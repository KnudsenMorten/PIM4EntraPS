#Requires -Version 5.1
<#
.SYNOPSIS
    Build the STANDALONE support scripts Invardia publishes for download (https://invardia.com/support/pim/...), so a
    customer admin can run a PIM setup step without the repository (operator 2026-10-07: "like this Invoke-WebRequest
    https://invardia.com/support/New-InvardiaSupportApp.ps1 -OutFile New-InvardiaSupportApp.ps1").

.DESCRIPTION
    Each published script is ONE file: the script with every helper it dot-sources via
    `. (Join-Path $PSScriptRoot '<helper>.ps1')` inlined at the place it was loaded (resolved against the folder of the
    file that loads it, recursively, once each), plus a header naming the PIM version it was built from. Nothing else
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

.EXAMPLE
    .\tools\setup\Build-PimSupportScripts.ps1 -OutDir C:\ProgramData\Invardia\handover\support-scripts\pim-manager\2.4.522
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutDir,
    [string[]]$Scripts = @('Initialize-PimSqlAdminGroup.ps1', 'pim-activator/Deploy-PimActivatorBackend.ps1', 'pim-activator/Publish-PimActivatorRemediation.ps1', 'pim-activator/Deploy-PimActivatorClient.ps1', 'Grant-PimEnginePermissions.ps1')
)
$ErrorActionPreference = 'Stop'
$setup = $PSScriptRoot
$tools = Split-Path $setup -Parent
$version = "$(Get-Content -Raw -LiteralPath (Join-Path (Split-Path $tools -Parent) 'VERSION'))".Trim()
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

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

$sums = New-Object System.Collections.Generic.List[string]
$built = New-Object System.Collections.Generic.List[string]
foreach ($s in $Scripts) {
    $rel = $s -replace '/', '\'
    $src = if ($rel -match '\\') { Join-Path $tools $rel } else { Join-Path $setup $rel }
    if (-not (Test-Path -LiteralPath $src)) { throw "script not found: $s" }
    $name = Split-Path $src -Leaf
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]'
    $body = Expand-PimSupportScript -Text ([IO.File]::ReadAllText($src)) -BaseDir (Split-Path $src -Parent) -Seen $seen -SeenPaths $seenPaths
    if ($body -match '\.\s*\(Join-Path\s+\$PSScriptRoot') { throw "$name still loads a file next to it after inlining" }
    $hdr = "# PIM Manager $version -- $name, standalone (built by tools/setup/Build-PimSupportScripts.ps1; helpers inlined: $(@($seen) -join ', '))`r`n"
    # keep '#Requires' first if the script starts with it
    if ($body -match '^(#Requires[^\r\n]*\r?\n)') { $body = $Matches[1] + $hdr + $body.Substring($Matches[1].Length) } else { $body = $hdr + $body }
    $out = Join-Path $OutDir $name
    [IO.File]::WriteAllText($out, $body, (New-Object System.Text.UTF8Encoding($true)))
    # must still parse
    $errs = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errs)
    if (@($errs).Count) { throw "$name does not parse after inlining: $($errs[0].Message)" }
    # Scripts from outside tools\setup (e.g. pim-activator/Deploy-PimActivatorBackend.ps1) must not dot-source ANYTHING
    # (a standalone file has nothing next to it). tools\setup scripts keep the previous rule only: their helpers may
    # carry a guarded, optional dot-source (_PimSqlAdminGroup.ps1's PIM-Rest fallback) that must not fail the build.
    if ($rel -match '\\') {
        $dots = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot }, $true))
        if ($dots.Count) { throw "$name still dot-sources after inlining (line $($dots[0].Extent.StartLineNumber): $($dots[0].Extent.Text))" }
    }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()
    $sums.Add("$h  $name")
    $built.Add($name)
    Write-Host "built $name ($((Get-Item $out).Length) bytes, sha256 $h)"
}
[IO.File]::WriteAllLines((Join-Path $OutDir 'SHA256SUMS.txt'), $sums)
$first = if ($built.Count) { $built[0] } else { 'Initialize-PimSqlAdminGroup.ps1' }
@"
PIM Manager $version -- standalone support scripts for https://invardia.com/support/pim/<file>
Each file is self-contained (no other files needed). Customers download and run it, e.g.:
  Invoke-WebRequest https://invardia.com/support/pim/$first -OutFile $first
Files: $($built -join ', ')
Checksums: SHA256SUMS.txt. Rebuilt with every PIM release that changes them (tools/setup/Build-PimSupportScripts.ps1).
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'README.txt') -Encoding utf8
