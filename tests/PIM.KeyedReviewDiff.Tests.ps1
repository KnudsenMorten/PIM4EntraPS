#Requires -Version 5.1
<#
.SYNOPSIS
    [M2] Review & Save diff is KEYED, not positional -- offline, in-proc Pester.

    The Manager's Review & Save (commit preview) diff used to compare the desired
    vs current row sets POSITIONALLY: if rows were merely reordered (very common
    after an Excel round-trip or an authoring move) the preview falsely reported
    modifies/removes/adds even though nothing changed, eroding trust in the diff.

    The fix matches rows by their STABLE per-entity natural key (the same key the
    store uses to identify a row -- Get-PimStoreRowKey -Base <entity>) instead of by
    position. A row present in both with the same key + same field values is
    UNCHANGED even if its position moved; same key + different values = a modify;
    key only in desired = an add; key only in current = a remove. Rows that have no
    derivable key, or that collide on a key, fall back gracefully to the legacy
    content/positional method (and never crash).

    This suite extracts the REAL Compare-PimRowSets from Open-PimManager.ps1 and the
    REAL Get-PimStoreRowKey from engine/_shared/PIM-SqlStore.ps1 (same in-proc
    name-extraction technique the Read-PimRows + safety suites use -- no live
    tenant, no boot), then drives the diff over real entity shapes.

    Cases proven:
      (a) pure REORDER of identical rows         -> ZERO adds/removes/modifies
      (b) one real value change                  -> exactly ONE modify (right cols)
      (c) an added row                           -> exactly ONE add
      (d) a removed row                          -> exactly ONE remove
      (e) reorder + one change mixed             -> only the real change shows
      + several entity shapes (Departments, AUs, composite-key assignments)
      + graceful fallback when no key is derivable / keys collide.

    Run:  Invoke-Pester -Path tests\PIM.KeyedReviewDiff.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (drives this with the Pester job)
#>
# Invoke-Expression is intentional: it loads the REAL functions by exact name from
# the boot-laden Open-PimManager.ps1 / PIM-SqlStore.ps1 (no live tenant, no boot),
# the same technique the existing Read-PimRows + safety suites use.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

BeforeAll {
    $script:Root    = Split-Path -Parent $PSScriptRoot
    $script:SrvPath = Join-Path $Root 'tools\pim-manager\Open-PimManager.ps1'
    $script:SqlPath = Join-Path $Root 'engine\_shared\PIM-SqlStore.ps1'

    function Get-FunctionTextFrom([string]$file, [string]$name) {
        $src = [System.IO.File]::ReadAllText($file)
        $m = [regex]::Match($src, ("(?m)^function {0}\b[\s\S]*?^\}}" -f [regex]::Escape($name)))
        if (-not $m.Success) { throw "Could not extract function '$name' from $file" }
        return $m.Value
    }

    # Load the REAL store key derivation, then the REAL keyed diff.
    Invoke-Expression (Get-FunctionTextFrom $script:SqlPath 'Get-PimStoreRowKey')
    Invoke-Expression (Get-FunctionTextFrom $script:SrvPath 'Compare-PimRowSets')

    # Helper: build an ordered row (matches what ConvertTo-OrderedRow produces).
    function New-Row([hashtable]$h) {
        $o = [ordered]@{}
        foreach ($k in $h.Keys) { $o[$k] = $h[$k] }
        return $o
    }
}

Describe '[M2] Compare-PimRowSets is keyed, not positional' {

    Context 'PIM-Definitions-* (keyed on GroupTag)' {
        BeforeAll {
            $script:Base = 'PIM-Definitions-Groups'
            $script:cur = @(
                (New-Row @{ GroupTag = 'GT-A'; Tier = '0'; GroupName = 'Group A' }),
                (New-Row @{ GroupTag = 'GT-B'; Tier = '1'; GroupName = 'Group B' }),
                (New-Row @{ GroupTag = 'GT-C'; Tier = '2'; GroupName = 'Group C' })
            )
        }

        It '(a) pure REORDER of identical rows -> ZERO adds/removes/modifies' {
            $reordered = @($script:cur[2], $script:cur[0], $script:cur[1])
            $d = Compare-PimRowSets -Before $script:cur -After $reordered -Base $script:Base
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 0
            $d.unchanged         | Should -Be 3
        }

        It '(b) one real value change -> exactly ONE modify on the right column' {
            $after = @(
                $script:cur[2],
                (New-Row @{ GroupTag = 'GT-A'; Tier = '0'; GroupName = 'Group A (renamed)' }),
                $script:cur[1]
            )
            $d = Compare-PimRowSets -Before $script:cur -After $after -Base $script:Base
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 1
            $d.unchanged         | Should -Be 2
            @($d.modifies[0].diffCols) | Should -Be @('GroupName')
            "$($d.modifies[0].after.GroupTag)" | Should -Be 'GT-A'
        }

        It '(c) an added row -> exactly ONE add (others unchanged despite reorder)' {
            $after = @(
                $script:cur[1],
                (New-Row @{ GroupTag = 'GT-D'; Tier = '0'; GroupName = 'Group D' }),
                $script:cur[2],
                $script:cur[0]
            )
            $d = Compare-PimRowSets -Before $script:cur -After $after -Base $script:Base
            @($d.adds).Count     | Should -Be 1
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 0
            $d.unchanged         | Should -Be 3
            "$($d.adds[0].GroupTag)" | Should -Be 'GT-D'
        }

        It '(d) a removed row -> exactly ONE remove (others unchanged despite reorder)' {
            $after = @($script:cur[2], $script:cur[0])   # GT-B dropped, rest reordered
            $d = Compare-PimRowSets -Before $script:cur -After $after -Base $script:Base
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 1
            @($d.modifies).Count | Should -Be 0
            $d.unchanged         | Should -Be 2
            "$($d.removes[0].GroupTag)" | Should -Be 'GT-B'
        }

        It '(e) reorder + one change mixed -> ONLY the real change shows' {
            $after = @(
                $script:cur[2],
                $script:cur[1],
                (New-Row @{ GroupTag = 'GT-A'; Tier = '5'; GroupName = 'Group A' })  # Tier changed
            )
            $d = Compare-PimRowSets -Before $script:cur -After $after -Base $script:Base
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 1
            $d.unchanged         | Should -Be 2
            @($d.modifies[0].diffCols) | Should -Be @('Tier')
        }
    }

    Context 'Per-entity key shapes' {
        It 'Departments key on Department name -> reorder is invisible' {
            $base = 'PIM-Definitions-Departments'
            $cur = @(
                (New-Row @{ Department = 'Finance'; Owners = 'a@x' }),
                (New-Row @{ Department = 'HR';      Owners = 'b@x' })
            )
            $after = @($cur[1], $cur[0])
            $d = Compare-PimRowSets -Before $cur -After $after -Base $base
            @($d.adds).Count + @($d.removes).Count + @($d.modifies).Count | Should -Be 0
            $d.unchanged | Should -Be 2
        }

        It 'AUs key on AdministrativeUnitTag -> reorder invisible, change = 1 modify' {
            $base = 'PIM-Definitions-AU'
            $cur = @(
                (New-Row @{ AdministrativeUnitTag = 'AU1'; DisplayName = 'Unit 1' }),
                (New-Row @{ AdministrativeUnitTag = 'AU2'; DisplayName = 'Unit 2' })
            )
            $after = @(
                (New-Row @{ AdministrativeUnitTag = 'AU2'; DisplayName = 'Unit 2 renamed' }),
                (New-Row @{ AdministrativeUnitTag = 'AU1'; DisplayName = 'Unit 1' })
            )
            $d = Compare-PimRowSets -Before $cur -After $after -Base $base
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 1
            "$($d.modifies[0].after.AdministrativeUnitTag)" | Should -Be 'AU2'
        }

        It 'composite-key assignment (GroupTag|RoleDefinitionName) -> reorder invisible' {
            $base = 'PIM-Assignments-Roles-Groups'
            $cur = @(
                (New-Row @{ GroupTag = 'GT-A'; RoleDefinitionName = 'Reader' }),
                (New-Row @{ GroupTag = 'GT-A'; RoleDefinitionName = 'Contributor' }),
                (New-Row @{ GroupTag = 'GT-B'; RoleDefinitionName = 'Reader' })
            )
            $after = @($cur[2], $cur[0], $cur[1])
            $d = Compare-PimRowSets -Before $cur -After $after -Base $base
            @($d.adds).Count + @($d.removes).Count + @($d.modifies).Count | Should -Be 0
            $d.unchanged | Should -Be 3
        }
    }

    Context 'Graceful fallback (no crash) when keys are unusable' {
        It 'no derivable key (no -Base) falls back to content match -> reorder invisible' {
            $cur = @(
                (New-Row @{ Foo = '1'; Bar = 'x' }),
                (New-Row @{ Foo = '2'; Bar = 'y' })
            )
            $after = @($cur[1], $cur[0])
            $d = Compare-PimRowSets -Before $cur -After $after   # no -Base
            @($d.adds).Count + @($d.removes).Count + @($d.modifies).Count | Should -Be 0
            $d.unchanged | Should -Be 2
        }

        It 'colliding key on one side does not crash; collided rows fall back to content' {
            $base = 'PIM-Definitions-Groups'
            # GT-DUP appears twice on BOTH sides (collision) -> legacy path.
            $cur = @(
                (New-Row @{ GroupTag = 'GT-DUP'; GroupName = 'one' }),
                (New-Row @{ GroupTag = 'GT-DUP'; GroupName = 'two' }),
                (New-Row @{ GroupTag = 'GT-UNIQ'; GroupName = 'solo' })
            )
            $after = @(
                (New-Row @{ GroupTag = 'GT-UNIQ'; GroupName = 'solo' }),       # reorder of the unique one
                (New-Row @{ GroupTag = 'GT-DUP'; GroupName = 'two' }),
                (New-Row @{ GroupTag = 'GT-DUP'; GroupName = 'one' })
            )
            { Compare-PimRowSets -Before $cur -After $after -Base $base } | Should -Not -Throw
            $d = Compare-PimRowSets -Before $cur -After $after -Base $base
            # Unique row resolved by key + the two collided rows matched by content
            # => everything unchanged, nothing falsely added/removed/modified.
            @($d.adds).Count     | Should -Be 0
            @($d.removes).Count  | Should -Be 0
            @($d.modifies).Count | Should -Be 0
            $d.unchanged         | Should -Be 3
        }

        It 'empty before -> all After rows are adds' {
            $base = 'PIM-Definitions-Groups'
            $after = @(
                (New-Row @{ GroupTag = 'GT-A'; GroupName = 'A' }),
                (New-Row @{ GroupTag = 'GT-B'; GroupName = 'B' })
            )
            $d = Compare-PimRowSets -Before @() -After $after -Base $base
            @($d.adds).Count    | Should -Be 2
            @($d.removes).Count | Should -Be 0
            $d.unchanged        | Should -Be 0
        }
    }
}
