#Requires -Version 5.1
<#
.SYNOPSIS
    Build the STANDALONE support scripts Invardia publishes for download (https://invardia.com/support/pim/...), so a
    customer admin can run a PIM setup step without the repository (operator 2026-10-07: "like this Invoke-WebRequest
    https://invardia.com/support/New-InvardiaSupportApp.ps1 -OutFile New-InvardiaSupportApp.ps1").

.DESCRIPTION
    Each published script is ONE file: the setup script with every helper it dot-sources from tools\setup inlined at the
    place it was loaded, plus a header naming the PIM version it was built from. Nothing else changes -- the script runs
    exactly as it does from the repository. The output folder gets a SHA256SUMS.txt and a README.txt for Invardia.

    Scripts built today:
      Initialize-PimSqlAdminGroup.ps1  -- make grp-pim-sql-admins the SQL server's admin, with PIM's identities and the
                                          Invardia Support app as members (gives Invardia support access to the store).

.EXAMPLE
    .\tools\setup\Build-PimSupportScripts.ps1 -OutDir C:\ProgramData\Invardia\handover\support-scripts\pim-manager\2.4.522
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutDir,
    [string[]]$Scripts = @('Initialize-PimSqlAdminGroup.ps1')
)
$ErrorActionPreference = 'Stop'
$setup = $PSScriptRoot
$version = "$(Get-Content -Raw -LiteralPath (Join-Path (Split-Path (Split-Path $setup -Parent) -Parent) 'VERSION'))".Trim()
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Expand-PimSupportScript {
    # Inline every `. (Join-Path $PSScriptRoot '<helper>.ps1')` line with that helper's content (recursively, once each).
    param([string]$Text, [System.Collections.Generic.HashSet[string]]$Seen)
    $rx = [regex]('(?m)^(?<indent>[ \t]*)\.\s*\(Join-Path\s+\$PSScriptRoot\s+''(?<file>[^'']+\.ps1)''\)[^\r\n]*(?=\r?$)')
    return $rx.Replace($Text, {
        param($m)
        $f = $m.Groups['file'].Value
        $p = Join-Path $setup $f
        if (-not (Test-Path -LiteralPath $p)) { throw "helper not found: $f" }
        if (-not $Seen.Add($f.ToLowerInvariant())) { return "# (helper $f already inlined above)" }
        $inner = Expand-PimSupportScript -Text ([IO.File]::ReadAllText($p)) -Seen $Seen
        $inner = [regex]::Replace($inner, '(?m)^#Requires[^\r\n]*\r?\n', '')
        "# ===== BEGIN inlined helper: $f =====`r`n$inner`r`n# ===== END inlined helper: $f ====="
    })
}

$sums = New-Object System.Collections.Generic.List[string]
foreach ($s in $Scripts) {
    $src = Join-Path $setup $s
    if (-not (Test-Path -LiteralPath $src)) { throw "script not found: $s" }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $body = Expand-PimSupportScript -Text ([IO.File]::ReadAllText($src)) -Seen $seen
    if ($body -match '\.\s*\(Join-Path\s+\$PSScriptRoot') { throw "$s still loads a file next to it after inlining" }
    $hdr = "# PIM Manager $version -- $s, standalone (built by tools/setup/Build-PimSupportScripts.ps1; helpers inlined: $(@($seen) -join ', '))`r`n"
    # keep '#Requires' first if the script starts with it
    if ($body -match '^(#Requires[^\r\n]*\r?\n)') { $body = $Matches[1] + $hdr + $body.Substring($Matches[1].Length) } else { $body = $hdr + $body }
    $out = Join-Path $OutDir $s
    [IO.File]::WriteAllText($out, $body, (New-Object System.Text.UTF8Encoding($true)))
    # must still parse
    $errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errs)
    if (@($errs).Count) { throw "$s does not parse after inlining: $($errs[0].Message)" }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()
    $sums.Add("$h  $s")
    Write-Host "built $s ($((Get-Item $out).Length) bytes, sha256 $h)"
}
[IO.File]::WriteAllLines((Join-Path $OutDir 'SHA256SUMS.txt'), $sums)
@"
PIM Manager $version -- standalone support scripts for https://invardia.com/support/pim/<file>
Each file is self-contained (no other files needed). Customers download and run it, e.g.:
  Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimSqlAdminGroup.ps1 -OutFile Initialize-PimSqlAdminGroup.ps1
Checksums: SHA256SUMS.txt. Rebuilt with every PIM release that changes them (tools/setup/Build-PimSupportScripts.ps1).
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'README.txt') -Encoding utf8
