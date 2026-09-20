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

# ---- TEMPLATE ID ALIASES (operator 2026-09-19: "why dont we have 2 policy template for azure" / "and why not 2 for
# PIM4Groups") ----------------------------------------------------------------------------------------------------
# Every policy type ships ONE Standard + ONE RequireApproval template: Groups_*, EntraIDRoles_*, AzureRoles_*. The two
# PIM-for-Groups templates were called 'default' and 'approval-required' before; those ids stay ACCEPTED everywhere a
# template id is read (a row's PolicyTemplate, a template's 'extends', a stored template, the per-kind defaults) as
# ALIASES of the current ids. Defined HERE, in the most basic policy lib, because the BUG-55 hash below needs them
# (a template extending 'default' is the same desired state as one extending Groups_Standard) and this file is loaded
# on its own by the roll gate (Update-PimContainers.ps1). The resolver that uses them is Resolve-PimPolicyTemplateKey
# (PIM-PolicyTemplateStore.ps1).
function Get-PimPolicyTemplateAliases {
    <# PURE: former template id -> its current id. #>
    return [ordered]@{ 'default' = 'Groups_Standard'; 'approval-required' = 'Groups_RequireApproval' }
}

function Get-PimPolicyTemplateCanonicalId {
    <# PURE: a former id -> its current id; any other id unchanged (trimmed). #>
    param([AllowNull()][string]$Id)
    $t = "$Id".Trim()
    $a = Get-PimPolicyTemplateAliases
    foreach ($k in @($a.Keys)) { if ("$k" -ieq $t) { return "$($a[$k])" } }
    return $t
}

function Get-PimPolicyTemplateAliasNames {
    <# PURE: every OTHER id that means the same template as -Id ('Groups_Standard' -> 'default'; 'default' ->
       'Groups_Standard'). Empty for an id without aliases. #>
    param([AllowNull()][string]$Id)
    $t = "$Id".Trim(); if (-not $t) { return @() }
    $canon = Get-PimPolicyTemplateCanonicalId $t
    $a = Get-PimPolicyTemplateAliases
    $names = New-Object System.Collections.Generic.List[string]
    if ($canon -ine $t) { [void]$names.Add($canon) }
    foreach ($k in @($a.Keys)) { if ("$($a[$k])" -ieq $canon -and "$k" -ine $t) { [void]$names.Add("$k") } }
    return @($names.ToArray())
}

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
    [CmdletBinding(DefaultParameterSetName = 'Path')] param(
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
        # 2026-09-12: templates live in SQL -- hash an already-parsed template (the SQL copy) with the
        # SAME normalisation, so a stored template and the file it was seeded from hash identically.
        [Parameter(Mandatory, ParameterSetName = 'Object')][object]$Template
    )

    $obj = if ($PSCmdlet.ParameterSetName -eq 'Object') {
        # Round-trip through JSON so a hashtable, a PSCustomObject from ConvertFrom-Json and a value
        # hydrated from pim.Settings all normalise to the same PSCustomObject shape as a file read.
        ($Template | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json
    } else {
        (Get-Content -LiteralPath $Path -Raw -Encoding UTF8) | ConvertFrom-Json
    }
    $stripped = Remove-PimTemplateAnnotation -Node $obj
    # 2026-09-19 (operator: "give policies an id so we can rename them"): the template's IDENTITY and its display
    # NAME are not desired state either. `id` is carried by the per-file key of the fingerprint, and `name` is a
    # label the operator may now edit -- neither changes a single rule the engine applies, so neither may read as
    # a baseline change (a renamed template must stay "unmodified since shipped", and the roll gate must not fire
    # on a label). 'extends' is compared by the CURRENT id of what it names, so a template extending the old alias
    # 'default' hashes the same as one extending Groups_Standard. Top level only: rule bodies are untouched.
    if ($stripped -is [System.Management.Automation.PSCustomObject]) {
        foreach ($n in @('id', 'name')) { if ($stripped.PSObject.Properties[$n]) { $stripped.PSObject.Properties.Remove($n) } }
        if ($stripped.PSObject.Properties['extends']) { $stripped.extends = Get-PimPolicyTemplateCanonicalId -Id "$($stripped.extends)" }
    }
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
    [CmdletBinding(DefaultParameterSetName = 'Dir')] param(
        [Parameter(Mandatory, ParameterSetName = 'Dir')][string]$TemplateDir,
        # 2026-09-12 -- the SQL copy: id -> template object (pim.Settings['PolicyTemplates']). Each is
        # keyed '<id>.policytemplate.json' so the fingerprint of a store seeded from a directory EQUALS
        # the fingerprint of that directory -- one comparable value across files and SQL.
        [Parameter(Mandatory, ParameterSetName = 'Templates')][AllowEmptyCollection()][hashtable]$Templates
    )

    $result = @{ hash = ''; templates = @{}; count = 0 }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($PSCmdlet.ParameterSetName -eq 'Templates') {
        # A key that is already a file name is used as-is; a bare id gets the file suffix.
        $nameOf = @{}
        foreach ($k in @($Templates.Keys)) { $nameOf["$k"] = $(if ("$k" -like '*.policytemplate.json') { "$k" } else { "$k.policytemplate.json" }) }
        $names = @($nameOf.Keys | Sort-Object { $nameOf[$_] })
        if (-not $names.Count) { return $result }
        foreach ($id in $names) {
            $name = $nameOf[$id]
            $h = Get-PimPolicyTemplateHash -Template $Templates[$id]
            $result.templates[$name] = $h
            [void]$parts.Add("${name}:$h")
        }
        $count = $names.Count
    } else {
        if (-not (Test-Path -LiteralPath $TemplateDir)) { return $result }
        $files = @(Get-ChildItem -LiteralPath $TemplateDir -Filter '*.policytemplate.json' -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notmatch '\.custom\.' } | Sort-Object Name)
        if (-not $files.Count) { return $result }
        foreach ($f in $files) {
            $h = Get-PimPolicyTemplateHash -Path $f.FullName
            $result.templates[$f.Name] = $h
            [void]$parts.Add("$($f.Name):$h")
        }
        $count = $files.Count
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($parts -join '|'))
        # Short form: this is carried as an Azure resource TAG value, and a full SHA-256 is
        # needlessly long there. 16 hex chars over a set this small is not a collision risk.
        $result.hash = ((($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')).Substring(0,16)
    } finally { $sha.Dispose() }
    $result.count = $count
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

function Get-PimPolicyBaselineFromArchive {
    <#
      BUG-231 -- the desired-state fingerprint of the version an IN-CLOUD update is about to roll,
      read out of the source archive it builds from (`pim-src-<version>.tar.gz`).

      🔴 WHY THIS HAS TO EXIST. `Update-PimContainers` can fingerprint a tree because it HAS one.
      The in-cloud updater has only a tarball: it downloads the archive, hands it to ACR and never
      extracts it. Without this it cannot answer "what will the new image WANT?", and so the BUG-55
      desired-state gate -- the one that exists because 217 of 325 production group policies were
      rewritten overnight -- could not run on the path that actually runs overnight.

      Returns the SAME shape as Get-PimPolicyBaselineFingerprint (@{ hash; templates; count }), so
      Compare-PimPolicyBaseline judges a tarball and a directory by one rule, not two.

      🔒 NEVER THROWS, and an empty result means "could not tell", never "no templates". The caller
      must treat hash='' as UNKNOWN (warn, proceed) rather than as a baseline that differs -- a
      failed read must not look like a desired-state change and block a fleet at 03:00.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ArchivePath)

    $empty = @{ hash = ''; templates = @{}; count = 0 }
    if (-not (Test-Path -LiteralPath $ArchivePath)) { return $empty }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-bl-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    # 🪤 READ THE TAR WITH .NET, NOT THE `tar` BINARY. Two independent things bite the obvious
    # implementation, and both were measured 2026-09-20:
    #   1. GNU tar (the container image, powershell:7.4-ubuntu-22.04) needs `--wildcards` to match a
    #      pattern; bsdtar (Windows, mgmt1) matches by default and REFUSES the flag. One code path
    #      cannot satisfy both without probing.
    #   2. PowerShell 7.3+ turns a NON-ZERO NATIVE EXIT into a TERMINATING error when
    #      $ErrorActionPreference is 'Stop' ($PSNativeCommandUseErrorActionPreference). So the probe
    #      for (1) THROWS, the catch returns empty, and a perfectly good archive fingerprints as
    #      "could not tell" -- which reads as UNKNOWN and silently waves a roll through.
    # System.Formats.Tar (.NET 7+; the image has .NET 8, mgmt1 .NET 10) has no exit codes, no
    # pattern dialects and no child process. Entry names in a tar are ALWAYS forward-slashed,
    # whatever the host, so one regex is correct everywhere.
    try {
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $fs = $null; $gz = $null; $tr = $null
        try {
            $fs = [IO.File]::OpenRead($ArchivePath)
            $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
            $tr = New-Object System.Formats.Tar.TarReader($gz)
            while ($null -ne ($entry = $tr.GetNextEntry())) {
                # Anchored on the solution's own templates dir, so an archive that also carries
                # another solution's policy folder cannot contribute to PIM's fingerprint.
                if ("$($entry.Name)" -notmatch 'SOLUTIONS/PIM4EntraPS/templates/policy/[^/]+\.policytemplate\.json$') { continue }
                $leaf = [IO.Path]::GetFileName("$($entry.Name)")
                if (-not $leaf) { continue }
                $entry.ExtractToFile((Join-Path $tmp $leaf), $true)
            }
        } finally {
            if ($tr) { $tr.Dispose() }; if ($gz) { $gz.Dispose() }; if ($fs) { $fs.Dispose() }
        }
        if (-not @(Get-ChildItem -LiteralPath $tmp -Filter '*.policytemplate.json' -File -ErrorAction SilentlyContinue).Count) { return $empty }
        return (Get-PimPolicyBaselineFingerprint -TemplateDir $tmp)
    } catch {
        return $empty
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
