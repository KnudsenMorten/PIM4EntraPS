#Requires -Version 5.1
<#
.SYNOPSIS
    [H1] Read-PimRows header normalisation -- offline, in-proc Pester.

    Excel "CSV (semicolon)" exports wrap every header cell in double quotes, the
    FIRST cell can carry a UTF-8 BOM, and manual edits add whitespace after the
    delimiter. Before the fix, Read-PimRows split the header with -split ';' and
    only stripped a clean leading/trailing quote -- a BOM or whitespace BEFORE the
    quote left the column name as e.g. "<BOM>"UserName"" / ' "UserName"', so
    $r.PSObject.Properties[$col] never matched, every field read back blank, and
    the Delegation Map rendered EMPTY on a perfectly valid export.

    This suite extracts the REAL Read-PimRows (+ its header normaliser) from
    Open-PimManager.ps1, stubs only its tiny path/spec/scope deps, and drives it
    over real fixtures on disk:
      * clean unquoted header           (control -- proves no regression)
      * Excel quoted header             (quotes stripped)
      * quoted header + UTF-8 BOM       (BOM + quotes stripped on cell 1)
      * quoted header + whitespace      (' "Col"' trimmed then unquoted)
      * quoted DATA values w/ ; inside  (data quoting honoured, not corrupted)
    and asserts key columns (UserName / RoleDefinitionName) resolve to VALUES.

    Run:  Invoke-Pester -Path tests\PIM.ReadPimRows.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (drives this with the Pester job)
#>
# Invoke-Expression is intentional here: it loads the REAL Read-PimRows from the
# boot-laden Open-PimManager.ps1 by exact function name (no live tenant, no boot),
# the same technique the existing PIM safety suite uses. Stub params/verbs below
# mirror the real dependency signatures Read-PimRows calls.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

BeforeAll {
    $script:Root   = Split-Path -Parent $PSScriptRoot
    $script:SrvPath = Join-Path $Root 'tools\pim-manager\Open-PimManager.ps1'
    $script:Src    = [System.IO.File]::ReadAllText($script:SrvPath)

    # Extract the two real functions by name (same in-proc technique the safety
    # suite uses). We deliberately do NOT dot-source the whole file -- it has
    # top-level boot/HTTP code. Each function body ends at a line-start '}'.
    function Get-FunctionText([string]$name) {
        $m = [regex]::Match($script:Src, ("(?m)^function {0}\b[\s\S]*?^\}}" -f [regex]::Escape($name)))
        if (-not $m.Success) { throw "Could not extract function '$name' from Open-PimManager.ps1" }
        return $m.Value
    }

    # Minimal stubs for Read-PimRows' dependencies (CSV/local mode only).
    $script:configRoot = $null            # set per-test to the fixture dir
    $script:PimStorageMode = 'csv'        # force the CSV path (not SQL)
    $script:PimSqlCs = $null
    function Get-PimCsvSpec       { param([string]$BaseName) return $null }      # no default header -> use file's own
    function Resolve-PimCsvPath   {
        param([string]$BaseName)
        $custom = Join-Path $script:configRoot "$BaseName.custom.csv"
        if (Test-Path -LiteralPath $custom) { return [pscustomobject]@{ Path = $custom; Source = 'custom' } }
        return $null
    }
    function Limit-PimRowsToScope { param([hashtable]$Result, [string]$BaseName, [switch]$NoScope) return $Result }

    Invoke-Expression (Get-FunctionText 'ConvertTo-PimNormalizedHeaderToken')
    Invoke-Expression (Get-FunctionText 'Read-PimRows')

    $script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $script:Utf8Bom   = New-Object System.Text.UTF8Encoding($true)

    # Write a fixture file and return its config dir. $WithBom controls the BOM.
    function New-Fixture([string]$baseName, [string[]]$lines, [bool]$withBom) {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("pim-rpr-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0,8)))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $enc = if ($withBom) { $script:Utf8Bom } else { $script:Utf8NoBom }
        [System.IO.File]::WriteAllText((Join-Path $dir "$baseName.custom.csv"), (($lines -join "`r`n") + "`r`n"), $enc)
        return $dir
    }
}

Describe '[H1] Read-PimRows header normalisation (BOM / quotes / whitespace)' {

    It 'CONTROL: clean unquoted header parses and key columns resolve' {
        $script:configRoot = New-Fixture 'Admins' @(
            'UserName;RoleDefinitionName;GroupName'
            'alice;Reader;grp1'
            'bob;Contributor;grp2'
        ) $false
        $res = Read-PimRows -BaseName 'Admins'
        @($res.rows).Count        | Should -Be 2
        @($res.rows)[0].UserName  | Should -Be 'alice'
        @($res.rows)[0].RoleDefinitionName | Should -Be 'Reader'
        @($res.rows)[1].GroupName | Should -Be 'grp2'
        $res.header               | Should -Contain 'UserName'
        Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Excel quoted header parses identically to the clean control' {
        $script:configRoot = New-Fixture 'Admins' @(
            '"UserName";"RoleDefinitionName";"GroupName"'
            '"alice";"Reader";"grp1"'
            '"bob";"Contributor";"grp2"'
        ) $false
        $res = Read-PimRows -BaseName 'Admins'
        @($res.rows).Count        | Should -Be 2
        $res.header               | Should -Contain 'UserName'
        $res.header               | Should -Contain 'RoleDefinitionName'
        @($res.rows)[0].UserName  | Should -Be 'alice'
        @($res.rows)[0].RoleDefinitionName | Should -Be 'Reader'
        Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'quoted header + UTF-8 BOM: first column (UserName) still resolves' {
        # The BOM lands BEFORE the opening quote of the first cell -- the exact
        # case that left the Delegation Map empty.
        $script:configRoot = New-Fixture 'Admins' @(
            '"UserName";"RoleDefinitionName";"GroupName"'
            '"alice";"Reader";"grp1"'
        ) $true
        $res = Read-PimRows -BaseName 'Admins'
        # No header token may carry a stray BOM or quote.
        foreach ($h in $res.header) {
            ([int][char]("$h")[0]) | Should -Not -Be 0xFEFF
            "$h"                   | Should -Not -Match '"'
        }
        $res.header              | Should -Contain 'UserName'
        @($res.rows).Count       | Should -Be 1
        @($res.rows)[0].UserName | Should -Be 'alice'
        @($res.rows)[0].RoleDefinitionName | Should -Be 'Reader'
        Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'quoted header with whitespace after the delimiter still resolves' {
        $script:configRoot = New-Fixture 'Admins' @(
            '"UserName"; "RoleDefinitionName" ; "GroupName"'
            'alice;Reader;grp1'
        ) $false
        $res = Read-PimRows -BaseName 'Admins'
        $res.header              | Should -Contain 'RoleDefinitionName'
        @($res.rows)[0].RoleDefinitionName | Should -Be 'Reader'
        Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'quoted DATA values containing the delimiter are NOT corrupted' {
        # The header normaliser must not touch data values: a quoted value that
        # contains a ';' must survive intact (proves we only touched the header).
        $script:configRoot = New-Fixture 'Admins' @(
            '"UserName";"RoleDefinitionName";"GroupName"'
            '"alice";"Reader; Writer";"grp1"'
        ) $true
        $res = Read-PimRows -BaseName 'Admins'
        @($res.rows)[0].UserName           | Should -Be 'alice'
        @($res.rows)[0].RoleDefinitionName | Should -Be 'Reader; Writer'
        @($res.rows)[0].GroupName          | Should -Be 'grp1'
        Remove-Item -LiteralPath $script:configRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
