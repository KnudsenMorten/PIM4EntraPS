#Requires -Version 5.1
<#
.SYNOPSIS
    Build the STANDALONE support scripts Invardia publishes for download (https://invardia.com/support/pim/...), so a
    customer admin can run a PIM setup step without the repository (operator 2026-10-07: "like this Invoke-WebRequest
    https://invardia.com/support/New-InvardiaSupportApp.ps1 -OutFile New-InvardiaSupportApp.ps1").

.DESCRIPTION
    Each published script is ONE file: the script with every helper it dot-sources via
    `. (Join-Path $PSScriptRoot '<helper>.ps1')` inlined at the place it was loaded (resolved against the folder of the
    file that loads it, recursively, once each), plus a header naming the PIM version it was built from, and that version
    stamped into the inlined _PimScriptDoc.ps1 (its BUILD-VERSION line) so the script's first output line names it
    ("<Script> version <x.y.z> - documentation: <page>", REQUIREMENTS 100.52). Nothing else
    changes -- the script runs exactly as it does from the repository. The built file must parse; a script from
    outside tools\setup must also not dot-source anything. The output folder gets a SHA256SUMS.txt and a README.txt for Invardia.

    -Scripts entries: a bare file name is a script in tools\setup; a path with a folder ('pim-activator/X.ps1') is
    relative to tools\. The output always keeps the bare file name.

    Scripts built today:
      Initialize-PimSqlAdminGroup.ps1  -- make grp-pim-sql-admins the SQL server's admin, with PIM's identities and the
                                          Invardia Support app as members (gives Invardia support access to the store).
      Deploy-PimActivatorBackend.ps1   -- create / update the PIM Activator app registration in a tenant (browser
                                          sign-in, no PowerShell modules).
      Publish-PimActivatorRemediation.ps1 -- BUILD the Detect / Remediate pair for the tenant from its parameters (both
                                          shipped scripts embedded) and upload it to Intune as a Remediation (+ assign
                                          to a group when -AssignToGroupId is given; nobody otherwise).
      Deploy-PimActivatorClient.ps1    -- install the extension + its settings on a machine without Intune (servers).
      Grant-PimEnginePermissions.ps1   -- give the engine identity its missing application permissions + Azure roles
                                          (the command PIM Manager shows on Overview and in Get Started; no modules).
      Initialize-PimWorkloadPrereqs.ps1 -- fix a workload prerequisite PIM cannot fix itself (Power BI admin-API group,
                                          Fabric tenant setting, Sentinel on a dedicated workspace); browser sign-in, no
                                          modules (97.1: the command the prerequisite chips show; PIM records the result itself).
      Initialize-PimMailSender.ps1     -- MAIL-1 shared mailbox: create the sender mailbox + its send right scoped to that
                                          one mailbox (browser sign-in or the Support app's secret; Get Started > Mail sender).
      Set-PimSqlTier.ps1               -- 100.37: the SQL database to S0 minimum (never Basic) with a 250 GB max size, optional
                                          tier pin (pim-sql-tier-pin); the same plan as the installer and the updater.
      Set-PimSmtpRelayPassword.ps1     -- MAIL-1 SMTP relay: the relay password into the environment's Key Vault + read
                                          access on that one secret for the sending identities.

    SCRIPT-DOC-1 (framework 12.7) + framework 12.10 item 11 ("scripts are big concern"), 2026-10-09:
      * every script in $script:PimScriptDocScripts (tools\setup\_PimScriptDoc.ps1) must have its manifest
        tools\setup\script-docs\<Script>.doc.json; the build stamps version, docUrl, sha256 and the signature state into a
        copy next to the built script (<Script>.doc.json -- Invardia's renderer reads it from this folder) and lists it in
        SHA256SUMS.txt. A default-list build also hands over the manifests of the in-scope scripts that are part of the
        package rather than standalone (installers, operator routes), so every script has its page.
      * the built script's comment-based help gets .LINK <doc page> (from the ONE constant) and a .NOTES block with the
        permissions it needs and the changes it makes (from the manifest), so Get-Help -Full / -Online show them.
      * Authenticode: with -SigningCertThumbprint (or $env:PIM_CODESIGN_THUMBPRINT) each built .ps1 is signed with that
        code-signing certificate from Cert:\CurrentUser\My or Cert:\LocalMachine\My (never a file, never in the repo)
        BEFORE it is hashed. Without one the build says NOT SIGNED -- in its output, in each manifest ("signed": false)
        and in README.txt. A configured thumbprint that cannot be used fails the build (never a silent unsigned file).
      * README.txt: one line per script -- name, documentation page, SHA256 -- and the save / verify / run form.

.EXAMPLE
    .\tools\setup\Build-PimSupportScripts.ps1 -OutDir C:\ProgramData\Invardia\handover\support-scripts\pim-manager\2.4.522
.EXAMPLE
    .\tools\setup\Build-PimSupportScripts.ps1 -OutDir <handover folder> -SigningCertThumbprint <thumbprint> -TimestampServer http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutDir,
    [string[]]$Scripts = @('Initialize-PimSqlAdminGroup.ps1', 'pim-activator/Deploy-PimActivatorBackend.ps1', 'pim-activator/Publish-PimActivatorRemediation.ps1', 'pim-activator/Deploy-PimActivatorClient.ps1', 'Grant-PimEnginePermissions.ps1', 'Initialize-PimWorkloadPrereqs.ps1', 'Initialize-PimMailSender.ps1', 'Set-PimSmtpRelayPassword.ps1', 'Set-PimSqlTier.ps1'),
    # 12.10 item 11: the code-signing certificate (thumbprint of a certificate WITH its private key in CurrentUser\My or
    # LocalMachine\My). Empty = not signed, said loudly.
    [string]$SigningCertThumbprint = "$env:PIM_CODESIGN_THUMBPRINT",
    [string]$TimestampServer = "$env:PIM_CODESIGN_TIMESTAMP_URL",
    # Also hand over the manifests of the in-scope package scripts (default: only when -Scripts is the default list).
    [switch]$IncludePackageManifests
)
$ErrorActionPreference = 'Stop'
$setup = $PSScriptRoot
$tools = Split-Path $setup -Parent
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$version = "$(Get-Content -Raw -LiteralPath (Join-Path (Split-Path $tools -Parent) 'VERSION'))".Trim()
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$docDir = Join-Path $setup 'script-docs'
if (-not $PSBoundParameters.ContainsKey('Scripts')) { $IncludePackageManifests = $true }
$inScope = @{}
foreach ($e in $script:PimScriptDocScripts) { $inScope[(Get-PimScriptDocName -Script $e.Path).ToLowerInvariant()] = $e }

# ---- signing (12.10 item 11) -------------------------------------------------------------------------------------------
$signCert = $null
$tp = ("$SigningCertThumbprint" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
if ($tp) {
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $c = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1
        if ($c) { $signCert = $c; break }
    }
    if (-not $signCert) { throw "code-signing certificate $tp was not found in CurrentUser\My or LocalMachine\My -- nothing built (an unsigned file is never handed over in its place)" }
    if (-not $signCert.HasPrivateKey) { throw "code-signing certificate $tp has no private key here -- nothing built" }
    $eku = @($signCert.EnhancedKeyUsageList | ForEach-Object { "$($_.ObjectId)" })
    if ($eku -notcontains '1.3.6.1.5.5.7.3.3') { throw "certificate $tp is not a code-signing certificate (no Code Signing EKU) -- nothing built" }
    Write-Host "signing with: $($signCert.Subject) (thumbprint $tp, expires $($signCert.NotAfter.ToString('yyyy-MM-dd')))"
} else {
    Write-Warning 'NOT SIGNED: no code-signing certificate configured (-SigningCertThumbprint / PIM_CODESIGN_THUMBPRINT). The files are built and checksummed but carry no Authenticode signature; framework 12.10 item 11 says an unsigned script is not published.'
}

function Read-PimScriptDocManifest {
    # The source manifest for one in-scope script, or $null when the script is not in scope. In scope + missing = throw.
    param([string]$Name)
    $p = Join-Path $docDir "$Name.doc.json"
    if (-not $inScope.ContainsKey($Name.ToLowerInvariant())) { return $null }
    if (-not (Test-Path -LiteralPath $p)) { throw "12.7: $Name is in scope but has no manifest ($p)" }
    return ([IO.File]::ReadAllText($p) | ConvertFrom-Json)
}

function ConvertTo-PimScriptDocNotes {
    # The .NOTES text (help-safe: no comment terminators) listing what the person needs and what the script changes.
    param([object]$Manifest, [string]$DocUrl)
    $safe = { param($s) ("$s" -replace '#>', '# >' -replace '<#', '< #' -replace '\s+', ' ').Trim() }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("    PERMISSIONS AND CHANGES (from $(& $safe $Manifest.script) manifest, PIM Manager $version; full page: $DocUrl)")
    $l.Add('    The person running it needs:')
    $ra = @($Manifest.runAs)
    if (-not $ra.Count) { $l.Add('      (no directory or Azure role)') }
    foreach ($r in $ra) { $l.Add("      - $(& $safe $r.name) [$(& $safe $r.kind)$(if ("$($r.scope)") { ', ' + (& $safe $r.scope) })] -- $(& $safe $r.why)") }
    $l.Add('    What it creates, changes or grants:')
    $ch = @($Manifest.changes)
    if (-not $ch.Count) { $l.Add('      nothing (read-only)') }
    foreach ($c in $ch) {
        $perm = if ("$($c.permission)") { ': ' + (& $safe $c.permission) } else { '' }
        $sc = if ("$($c.scope)") { ' @ ' + (& $safe $c.scope) } else { '' }
        $l.Add("      - $(& $safe $c.action) $(& $safe $c.object) ($(& $safe $c.target))$perm$sc -- $(& $safe $c.why)$(if ("$($c.undo)") { ' Undo: ' + (& $safe $c.undo) })")
    }
    if ("$($Manifest.whatIf)") { $l.Add("    -WhatIf: $(& $safe $Manifest.whatIf)") }
    if ("$($Manifest.undo)") { $l.Add("    Undo: $(& $safe $Manifest.undo)") }
    return ($l -join "`r`n")
}

function Set-PimScriptDocHelp {
    # In the FIRST comment-help block (the one with .SYNOPSIS): drop any .LINK to the docs site, add the .NOTES
    # permissions (after an existing .NOTES line, else as a new .NOTES) and .LINK <doc page> at the end.
    param([string]$Text, [string]$Notes, [string]$DocUrl)
    $m = [regex]::Match($Text, '(?s)<#(?<body>.*?)#>')
    while ($m.Success -and $m.Groups['body'].Value -notmatch '(?m)^\s*\.SYNOPSIS') { $m = $m.NextMatch() }
    if (-not $m.Success) { throw 'no comment-based help block with .SYNOPSIS' }
    $body = $m.Groups['body'].Value
    $body = [regex]::Replace($body, '(?m)^[ \t]*\.LINK[ \t]*(\r?\n[ \t]*)?https://invardia\.com/docs/[^\s]*[ \t]*\r?\n?', '')
    $nl = [regex]::Match($body, '(?m)^[ \t]*\.NOTES[ \t]*\r?$')
    if ($nl.Success) {
        $at = $nl.Index + $nl.Length
        $body = $body.Substring(0, $at) + "`r`n" + $Notes + $body.Substring($at)
    } else {
        $body = $body.TrimEnd() + "`r`n`r`n.NOTES`r`n" + $Notes + "`r`n"
    }
    $body = $body.TrimEnd() + "`r`n`r`n.LINK`r`n    $DocUrl`r`n"
    return $Text.Substring(0, $m.Index) + '<#' + $body + '#>' + $Text.Substring($m.Index + $m.Length)
}

function Set-PimScriptBuildVersion {
    # PURE. 100.52: "$script:PimScriptDocVersion = ''   # BUILD-VERSION" (in _PimScriptDoc.ps1) -> the version, so the
    # standalone's banner names the version it was built from.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Version)
    if ($Version -notmatch '^[0-9A-Za-z.+-]+$') { throw "VERSION '$Version' is not a version string" }
    $rx = [regex]("(?m)^(?<indent>[ \t]*)\`$script:PimScriptDocVersion = ''[ \t]*# BUILD-VERSION[ \t]*(?=\r?$)")
    return $rx.Replace($Text, { param($m) "$($m.Groups['indent'].Value)`$script:PimScriptDocVersion = '$Version'   # BUILD-VERSION stamped by Build-PimSupportScripts" })
}

function Test-PimScriptBuildVersionStamped {
    # PURE. True when the text carries the stamped version line for -Version.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Version)
    return ($Text -match ("(?m)^[ \t]*\`$script:PimScriptDocVersion = '" + [regex]::Escape($Version) + "'[ \t]*# BUILD-VERSION stamped"))
}

function Expand-PimSupportScript {
    # Inline every `. (Join-Path $PSScriptRoot '<helper>.ps1')` line with that helper's content (recursively, once
    # each). -BaseDir is the folder of the file whose text this is: a helper resolves against it, and the helper's
    # own dot-sources against the helper's folder.
    param([string]$Text, [string]$BaseDir, [System.Collections.Generic.HashSet[string]]$Seen, [System.Collections.Generic.HashSet[string]]$SeenPaths)
    # 97.2 (owner 2026-10-08: "are all 3 files published at invardia"): a helper can carry DATA files too. A line
    #   $script:<Var> = @{}   # BUILD-EMBED: <file>, <file>
    # becomes a table <file name> -> base64 of that file's bytes (resolved against -BaseDir), so the standalone needs no
    # file next to it. In the repository the table stays empty and the helper reads the files themselves.
    $erx = [regex]('(?m)^(?<lhs>[ \t]*\$script:[A-Za-z0-9_]+) = @\{\}[ \t]*# BUILD-EMBED: (?<list>[^\r\n]+?)[ \t]*(?=\r?$)')
    $Text = $erx.Replace($Text, {
        param($m)
        $pairs = foreach ($f in @($m.Groups['list'].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            $p = [IO.Path]::GetFullPath((Join-Path $BaseDir ($f -replace '/', '\')))
            if (-not (Test-Path -LiteralPath $p)) { throw "embedded file not found: $f (looked in $BaseDir)" }
            "'$(Split-Path $p -Leaf)' = '$([Convert]::ToBase64String([IO.File]::ReadAllBytes($p)))'"
        }
        "$($m.Groups['lhs'].Value) = @{ $($pairs -join '; ') }   # embedded by Build-PimSupportScripts: $($m.Groups['list'].Value)"
    })
    $rx =[regex]('(?m)^(?<indent>[ \t]*)\.\s*\(Join-Path\s+\$PSScriptRoot\s+''(?<file>[^'']+\.ps1)''\)[^\r\n]*(?=\r?$)')
    return $rx.Replace($Text, {
        param($m)
        $f = $m.Groups['file'].Value
        $p = [IO.Path]::GetFullPath((Join-Path $BaseDir $f))
        if (-not (Test-Path -LiteralPath $p)) { throw "helper not found: $f (looked in $BaseDir)" }
        if (-not $SeenPaths.Add($p.ToLowerInvariant())) { return "# (helper $f already inlined above)" }
        [void]$Seen.Add($f.ToLowerInvariant())
        $inner = Expand-PimSupportScript -Text ([IO.File]::ReadAllText($p)) -BaseDir (Split-Path $p -Parent) -Seen $Seen -SeenPaths $SeenPaths
        $inner = [regex]::Replace($inner, '(?m)^#Requires[^\r\n]*\r?\n', '')
        "# ===== BEGIN inlined helper: $f =====`r`n$inner`r`n# ===== END inlined helper: $f ====="
    })
}

function Get-PimPublicScriptForbiddenNames {
    # MAIL-NAMING 100.14 item 3 (owner 2026-10-09): a published script never names a customer, a test environment or an
    # internal tool. Regexes (case as written; (?i) where any case counts). tests/Test-PimMailNaming.ps1 keeps its OWN copy
    # of this list on purpose -- a test must not trust the build's list. Real CUSTOMER names are never written here (this
    # file ships): they come from the internal denylist (Get-PimPublicScriptCustomerWords).
    @('(?i)\bEFIF', '\bRIDE\b', '(?i)\bmgmt1\b', '(?i)myfamilynetwork', '(?i)\bmfnpr\b',
      '(?i)\bf0fa27a0', '(?i)\b4ff34194', '(?i)\b9927fa1f', '(?i)\b7825c48b', '(?i)\big798\b', '(?i)automatit', '(?i)automateit',
      '(?i)ExpertsLive', '(?i)\bELDK', '(?i)2linkit', 'Setup-PimContainers', 'Initialize-PlatformEnvironment') +
    @(Get-PimPublicScriptCustomerWords | ForEach-Object { '(?i)\b' + [regex]::Escape($_) + '\b' })
}

function Get-PimPublicScriptCustomerWords {
    # The real customer names, from the internal denylist's `word:` entries (internal/REAL-IDENTIFIERS.md, SEC-19) -- the
    # same list Test-PimSourceSanitization scans shipped source for. No file (a public copy) = none.
    if (-not "$PSScriptRoot") { return @() }   # lifted out of this file (a test): no solution folder to read from
    $p = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'internal\REAL-IDENTIFIERS.md'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @([IO.File]::ReadAllLines($p) | ForEach-Object { $m = [regex]::Match($_, '^\s*word:\s*(?<v>[A-Za-z0-9][A-Za-z0-9._-]*)'); if ($m.Success) { $m.Groups['v'].Value } })
}

function ConvertTo-PimPublicScriptText {
    <#
      MAIL-NAMING 100.14 item 3: the comments of a published script are public too. The repository's comments keep their
      evidence ("measured on <test tenant>"); the PUBLISHED copy says it generically. Only COMMENT tokens are rewritten
      (the code runs unchanged); a forbidden name left anywhere after that -- in a string, in code -- FAILS the build,
      naming the line, so it is fixed in the source rather than shipped.
    #>
    param([Parameter(Mandatory)][string]$Text, [string]$Name = 'script')
    $rules = @(
        @('(?i)\b(?:EFIF|RIDE)\s*(?:/|\+|and|&)\s*(?:EFIF|RIDE)\b', 'two test tenants'),
        @("\bEFIF's\b", "a test tenant's"), @('(?i)admin-efif-', 'admin-<tenant>-'),
        @('\b(?:EFIF|RIDE)\b', 'a test tenant'), @('(?i)\befif\b', 'a test tenant'),
        @('(?i)\bmgmt1\b', 'a build machine'), @('(?i)\bmfnpr\b', 'an internal environment'),
        @('(?i)\bmyfamilynetwork\b', 'an internal tenant'), @('(?i)\b(?:f0fa27a0|4ff34194|9927fa1f|7825c48b)[0-9a-f-]*', '<tenant>'),
        @('(?i)\big798\b', 'a test environment'), @('(?i)kv-automatit-dev', 'the build key vault'), @('(?i)rg-automateit-', 'rg-pim-'),
        @('(?i)\bautomateit\b', 'the platform'), @('(?i)\bExpertsLive\w*', 'another tenant'), @('(?i)\bELDK\w*', 'another tenant'),
        @("(?i)\b2linkit's\b", "the vendor's"), @('(?i)\b2linkit\b', 'the vendor'),
        @('\bSetup-PimContainers(?:\.ps1)?', 'the deploy'), @('\bInitialize-PlatformEnvironment(?:\.ps1)?', 'the deploy'))
    foreach ($w in @(Get-PimPublicScriptCustomerWords)) { $rules += , @(('(?i)\b' + [regex]::Escape($w) + '\b'), 'a customer') }
    $tokens = $null; $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$perr)
    $sb = New-Object System.Text.StringBuilder $Text
    foreach ($t in @(@($tokens) | Where-Object { $_.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment } | Sort-Object { $_.Extent.StartOffset } -Descending)) {
        $c = $t.Text
        foreach ($r in $rules) { $c = [regex]::Replace($c, $r[0], $r[1]) }
        if ($c -ne $t.Text) { [void]$sb.Remove($t.Extent.StartOffset, $t.Extent.EndOffset - $t.Extent.StartOffset); [void]$sb.Insert($t.Extent.StartOffset, $c) }
    }
    $out = $sb.ToString()
    $lines = $out -split "`n"
    foreach ($rx in Get-PimPublicScriptForbiddenNames) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            # an embedded data table (BUILD-EMBED) is base64: letters in it are not names, a match there would be chance
            if ($lines[$i] -match '# embedded by Build-PimSupportScripts:') { continue }
            if ([regex]::IsMatch($lines[$i], $rx)) { throw "$Name line $($i + 1) names a customer / test environment / internal tool ($rx) outside a comment -- fix it in the source: $($lines[$i].Trim())" }
        }
    }
    return $out
}

$sums = New-Object System.Collections.Generic.List[string]
$built = New-Object System.Collections.Generic.List[string]
$lines = New-Object System.Collections.Generic.List[string]
$docs = New-Object System.Collections.Generic.List[object]
foreach ($s in $Scripts) {
    $rel = $s -replace '/', '\'
    $src = if ($rel -match '\\') { Join-Path $tools $rel } else { Join-Path $setup $rel }
    if (-not (Test-Path -LiteralPath $src)) { throw "script not found: $s" }
    $name = Split-Path $src -Leaf
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    $body = Expand-PimSupportScript -Text ([IO.File]::ReadAllText($src)) -BaseDir (Split-Path $src -Parent) -Seen $seen -SeenPaths $seenPaths
    if ($body -match '\.\s*\(Join-Path\s+\$PSScriptRoot') { throw "$name still loads a file next to it after inlining" }
    # the blank line after the header matters: a line comment directly above the help block makes PowerShell treat them
    # as one comment group, and the help is lost (Get-Help shows only the syntax).
    $hdr = "# PIM Manager $version -- $name, standalone (built by tools/setup/Build-PimSupportScripts.ps1; helpers inlined: $(@($seen) -join ', '))`r`n`r`n"
    # 12.7: .LINK + the permissions .NOTES from the manifest (in-scope scripts only)
    $docName = Get-PimScriptDocName -Script $name
    $manifest = Read-PimScriptDocManifest -Name $docName
    $docUrl = Get-PimScriptDocUrl -Script $docName
    if ($manifest) { $body = Set-PimScriptDocHelp -Text $body -Notes (ConvertTo-PimScriptDocNotes -Manifest $manifest -DocUrl $docUrl) -DocUrl $docUrl }
    # 100.52: the header names the version for a reader; the banner ("<Script> version <x.y.z> - documentation: <page>")
    # reads it from the inlined _PimScriptDoc.ps1, whose BUILD-VERSION line is stamped here (no repository, no VERSION
    # file next to a downloaded script). An in-scope script whose standalone carries no stamp fails the build.
    $body = Set-PimScriptBuildVersion -Text $body -Version $version
    if ($manifest -and -not (Test-PimScriptBuildVersionStamped -Text $body -Version $version)) { throw "$name`: the inlined _PimScriptDoc.ps1 has no stamped version (BUILD-VERSION line) -- its banner would not name the version" }
    $body = ConvertTo-PimPublicScriptText -Text $body -Name $name   # public: no customer / internal names (100.14)
    # keep '#Requires' first if the script starts with it
    if ($body -match '^(#Requires[^\r\n]*\r?\n)') { $body = $Matches[1] + $hdr + $body.Substring($Matches[1].Length) } else { $body = $hdr + $body }
    $out = Join-Path $OutDir $name
    [IO.File]::WriteAllText($out, $body, (New-Object System.Text.UTF8Encoding($true)))
    # must still parse
    $errs = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errs)
    if (@($errs).Count) { throw "$name does not parse after inlining: $($errs[0].Message)" }
    if ($manifest) {
        $help = $ast.GetHelpContent()
        if (-not $help -or -not @($help.Links | Where-Object { "$_".Trim() -eq $docUrl }).Count) { throw "$name`: the built help has no .LINK $docUrl (Get-Help would not find it)" }
    }
    # Scripts from outside tools\setup (e.g. pim-activator/Deploy-PimActivatorBackend.ps1) must not dot-source ANYTHING
    # (a standalone file has nothing next to it). tools\setup scripts keep the previous rule only: their helpers may
    # carry a guarded, optional dot-source (_PimSqlAdminGroup.ps1's PIM-Rest fallback) that must not fail the build.
    if ($rel -match '\\') {
        $dots = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot }, $true))
        if ($dots.Count) { throw "$name still dot-sources after inlining (line $($dots[0].Extent.StartLineNumber): $($dots[0].Extent.Text))" }
    }
    # 12.10 item 11: sign BEFORE hashing, then prove the signature is there and is ours
    $signer = ''
    if ($signCert) {
        $sa = @{ FilePath = $out; Certificate = $signCert; HashAlgorithm = 'SHA256' }
        if ("$TimestampServer".Trim()) { $sa['TimestampServer'] = "$TimestampServer".Trim() }
        $sig = Set-AuthenticodeSignature @sa
        $chk = Get-AuthenticodeSignature -FilePath $out
        if (-not $chk.SignerCertificate -or $chk.SignerCertificate.Thumbprint -ne $signCert.Thumbprint -or "$($chk.Status)" -in @('NotSigned', 'HashMismatch')) {
            throw "$name could not be signed ($($sig.Status): $($sig.StatusMessage)) -- nothing handed over unsigned in its place"
        }
        $signer = "$($signCert.Subject)"
    }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()
    $sums.Add("$h  $name")
    $built.Add($name)
    $lines.Add(('{0}  {1}  sha256 {2}' -f $name, $docUrl, $h))
    Write-Host "built $name ($((Get-Item $out).Length) bytes, sha256 $h, $(if ($signer) { 'signed' } else { 'NOT SIGNED' }))"
    if ($manifest) { $docs.Add(@{ Manifest = $manifest; Name = $docName; Sha = $h; Signer = $signer; Standalone = $true }) }
}
# 12.7: the package scripts' manifests (installers, operator routes) -- they have a page too, no download
if ($IncludePackageManifests) {
    foreach ($e in $script:PimScriptDocScripts) {
        $n = Get-PimScriptDocName -Script $e.Path
        if (@($docs | Where-Object { $_.Name -eq $n }).Count) { continue }
        $docs.Add(@{ Manifest = (Read-PimScriptDocManifest -Name $n); Name = $n; Sha = ''; Signer = ''; Standalone = $false })
        $lines.Add(('{0}.ps1  {1}  (part of the PIM Manager package: tools/{2})' -f $n, (Get-PimScriptDocUrl -Script $n), $e.Path))
    }
}
foreach ($d in $docs) {
    $m = $d.Manifest
    $o = [ordered]@{}
    foreach ($p in $m.PSObject.Properties) { $o[$p.Name] = $p.Value }
    $o['version'] = $version
    $o['docUrl'] = Get-PimScriptDocUrl -Script $d.Name
    $o['standalone'] = [bool]$d.Standalone
    if ($d.Standalone) {
        $o['download'] = Get-PimSupportScriptUrl -Script $d.Name
        $o['sha256'] = $d.Sha
        $o['signed'] = [bool]$d.Signer
        $o['signer'] = $d.Signer
    }
    $mf = Join-Path $OutDir "$($d.Name).doc.json"
    [IO.File]::WriteAllText($mf, ($o | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    $sums.Add("$((Get-FileHash -Algorithm SHA256 -LiteralPath $mf).Hash.ToLowerInvariant())  $($d.Name).doc.json")
}
[IO.File]::WriteAllLines((Join-Path $OutDir 'SHA256SUMS.txt'), $sums)
$first = if ($built.Count) { $built[0] } else { 'Initialize-PimSqlAdminGroup.ps1' }
$signLine = if ($signCert) { "SIGNED: every .ps1 carries an Authenticode signature by $($signCert.Subject) (thumbprint $($signCert.Thumbprint))." } else { 'NOT SIGNED: no code-signing certificate was configured for this build -- the .ps1 files carry NO Authenticode signature (framework 12.10 item 11: an unsigned script is not published).' }
@"
PIM Manager $version -- standalone support scripts for https://invardia.com/support/pim/<file>
Each file is self-contained (no other files needed). Documentation index: $($script:PimScriptDocBaseUrl)
$signLine

Save, verify, read, run -- never pipe to Invoke-Expression:
  Invoke-WebRequest https://invardia.com/support/pim/$first -OutFile $first
  Get-FileHash .\$first -Algorithm SHA256        # must equal its line in SHA256SUMS.txt
  Get-AuthenticodeSignature .\$first             # Windows: Status Valid when signed
  .\$first -WhatIf                               # preview: every change, none made

Scripts (name, documentation page, SHA256):
$($lines -join "`r`n")

Manifests: <Script>.doc.json next to each script (framework 12.7) -- the source of each documentation page.
Checksums: SHA256SUMS.txt (scripts + manifests). Rebuilt with every PIM release that changes them (tools/setup/Build-PimSupportScripts.ps1).
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'README.txt') -Encoding utf8
