#Requires -Version 5.1
<#
  BUG-55 -- a deploy that changes what the engine WANTS is a different act from a deploy that
  changes how the engine WORKS, and the tooling could not tell them apart.

  WHAT HAPPENED. v2.4.246 was built to ship a scheduler-lease fix. `Build-PimManagerImage` builds
  from `git archive HEAD`, so the image ALSO carried every desired-state change sitting in HEAD --
  including `templates/policy/*.json` edits that the handoff had explicitly marked as needing
  operator go-ahead and which had never been approved. Rolling it put that desired state into the
  runtime, the (now working) tick began applying it every 5 minutes, and by the next morning
  **217 of 325 production group policies** had been rewritten. Nothing alerted; it was found by a
  WhatIf run for an unrelated reason reporting `update=217` where `0` was expected.

  🪤 THE PRE-ROLL CHECK THAT MISSED IT LOOKED THOROUGH. The Job was diffed before and after and
  only the image field had changed. That answers *what did the deploy do to the JOB*. Nothing
  answered *what will this image do to the TENANT*, and only the second question mattered.

  WHAT THIS FILE IS. The desired-state half of a deploy, reduced to a fingerprint that can be
  compared across rolls: hash every shipped policy template, keep the per-template hashes so a
  change can be NAMED rather than just detected, and combine them into one value the roll path
  records on the deployed resource. The next roll compares against it and refuses to proceed
  silently when the answer changed.

  PURE. No Azure, no Graph, no git -- file reads only, so it is unit-testable offline and cannot
  behave differently on the deploy host than in the test.
#>

Set-StrictMode -Off

function Get-PimPolicyTemplateHash {
    <#
      PURE: a stable hash of ONE template's meaningful content.

      Normalised deliberately, because the fingerprint must answer "does the engine want something
      different" and not "did the bytes move":
        * parsed and re-serialised, so whitespace/key-order/line-ending churn is not a change
          (CRLF vs LF alone would otherwise flag every file on a Windows checkout);
        * `_`-prefixed annotation keys and `description` are DROPPED at every level -- they are
          commentary. Correcting a comment must not look like a baseline change, or the gate
          becomes noise and gets bypassed. This session edited exactly those fields on a shipped
          template and it must read as no-change.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json
    $stripped = Remove-PimTemplateAnnotation -Node $obj
    # Depth 30: the deepest shipped template nests rules -> Notification[] -> object.
    $canon = $stripped | ConvertTo-Json -Depth 30 -Compress
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($canon)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Remove-PimTemplateAnnotation {
    # PURE, recursive: drop `_*` keys and `description` so commentary is not desired state.
    [CmdletBinding()] param([object]$Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($p in ($Node.PSObject.Properties | Sort-Object Name)) {
            if ($p.Name -like '_*' -or $p.Name -eq 'description') { continue }
            $out[$p.Name] = Remove-PimTemplateAnnotation -Node $p.Value
        }
        return [pscustomobject]$out
    }
    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        # ASSIGN then wrap -- never `@(pipeline)`, the array-collapse trap recorded in BUG-26.
        $items = @()
        foreach ($i in $Node) { $items += ,(Remove-PimTemplateAnnotation -Node $i) }
        return ,$items
    }
    return $Node
}

function Get-PimPolicyBaselineFingerprint {
    <#
      PURE: the desired-state fingerprint of a whole templates/policy directory.

      Returns @{ hash = <combined>; templates = @{ <file> = <hash> }; count = n }.
      `templates` is what lets the gate say WHICH baseline moved instead of only THAT one did --
      the difference between a message someone acts on and one they click past.

      A missing/empty directory yields hash '' and count 0 rather than throwing: "no templates
      here" is a legitimate state for a non-hosted caller, and a gate that crashes gets disabled.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$TemplateDir)

    $result = @{ hash = ''; templates = @{}; count = 0 }
    if (-not (Test-Path -LiteralPath $TemplateDir)) { return $result }

    $files = @(Get-ChildItem -LiteralPath $TemplateDir -Filter '*.policytemplate.json' -File -ErrorAction SilentlyContinue |
               Sort-Object Name)
    if (-not $files.Count) { return $result }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $h = Get-PimPolicyTemplateHash -Path $f.FullName
        $result.templates[$f.Name] = $h
        [void]$parts.Add("$($f.Name):$h")
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($parts -join '|'))
        # Short form: this is carried as an Azure resource TAG value, and a full SHA-256 is
        # needlessly long there. 16 hex chars over a set this small is not a collision risk.
        $result.hash = ((($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')).Substring(0,16)
    } finally { $sha.Dispose() }
    $result.count = $files.Count
    return $result
}

function Compare-PimPolicyBaseline {
    <#
      PURE: decide whether a roll may proceed.

      Verdict shape: @{ changed; unknown; allowed; reason; added; removed; modified }

      THE THREE CASES, and the middle one is the design decision:
        * recorded == current            -> changed=$false, allowed=$true. The healthy answer.
        * NOTHING recorded (first roll)  -> unknown=$true, allowed=$true. A first deploy into an
          environment has no prior baseline to differ from, and blocking it would make the gate's
          own rollout impossible. It WARNS instead -- honest about not knowing.
        * recorded != current            -> changed=$true, allowed only with -AcceptBaselineChange.
          This is the 217-policy case: the roll is carrying desired state the operator did not ask
          for, and it must be an explicit act.
    #>
    [CmdletBinding()] param(
        [hashtable]$Current,
        [string]$RecordedHash,
        [hashtable]$RecordedTemplates,
        [switch]$Accept
    )
    $cur = if ($Current) { $Current } else { @{ hash=''; templates=@{}; count=0 } }
    $v = @{ changed=$false; unknown=$false; allowed=$true; reason=''; added=@(); removed=@(); modified=@() }

    if (-not "$RecordedHash".Trim()) {
        $v.unknown = $true
        $v.reason  = "no policy baseline recorded on the target yet -- cannot tell whether this image changes desired state (first roll after the BUG-55 gate shipped, or a resource deployed before it)"
        return $v
    }
    if ("$RecordedHash".Trim() -eq "$($cur.hash)".Trim()) {
        $v.reason = "policy baseline unchanged ($($cur.hash), $($cur.count) template(s))"
        return $v
    }

    $v.changed = $true
    $rec = if ($RecordedTemplates) { $RecordedTemplates } else { @{} }
    if ($rec.Count) {
        foreach ($k in @($cur.templates.Keys)) {
            if (-not $rec.ContainsKey($k)) { $v.added += $k }
            elseif ("$($rec[$k])" -ne "$($cur.templates[$k])") { $v.modified += $k }
        }
        foreach ($k in @($rec.Keys)) { if (-not $cur.templates.ContainsKey($k)) { $v.removed += $k } }
    }
    $v.allowed = [bool]$Accept
    $bits = @()
    if ($v.modified.Count) { $bits += "modified: $(($v.modified | Sort-Object) -join ', ')" }
    if ($v.added.Count)    { $bits += "added: $(($v.added    | Sort-Object) -join ', ')" }
    if ($v.removed.Count)  { $bits += "removed: $(($v.removed | Sort-Object) -join ', ')" }
    if (-not $bits.Count)  { $bits += "recorded $RecordedHash -> current $($cur.hash)" }
    $v.reason = "THIS IMAGE CHANGES THE POLICY BASELINE -- $($bits -join '; ')"
    return $v
}
