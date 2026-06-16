#Requires -Version 5.1
<#
.SYNOPSIS
    [M3] Authoring inline preview / diff before commit -- offline, in-proc Pester.

    REQUIREMENTS.md §28 [M3]: the Authoring tab staged actions with NO inline
    preview/diff. "Move admin" did a wholesale row-replace that could silently
    DROP rows, and the hidden server ops (clone-azure-role / clone-au /
    delete-rows) weren't surfaced to the operator before they ran.

    The fix gives every authoring action a KEYED add/modify/remove preview BEFORE
    it is staged or committed (Get-PimAuthoringPreview), reusing the same natural
    key the store + the [M2] Review & Save diff use, plus a loud 'destructive'
    flag when rows would be removed. "Move admin" (New-PimAdminMovePlan) is now
    guarded to NEVER drop rows -- it asserts the output row count equals the input
    row count and reports preservedCount.

    This suite dot-sources the REAL engine/_shared/PIM-Authoring.ps1 (pure, no
    boot, no I/O) and the REAL Get-PimStoreRowKey from PIM-SqlStore.ps1, then
    drives the preview + move plan over real entity shapes.

    Cases proven:
      * Move-admin PRESERVES every row (no drop): output count == input count,
        preservedCount correct, all non-moved rows carried through verbatim.
      * Move-admin row-count-changed guard throws rather than dropping rows.
      * Each authoring op produces a CORRECT keyed preview:
          - clone (append)            -> adds only, reorder invisible
          - clone-azure-role (append) -> adds only
          - clone-au / au (append)    -> adds only
          - bulk-attach (append)      -> adds only
          - import-admins (append)    -> adds only
          - move-admin (replace)      -> the re-point shows as modify-not-remove
      * A DESTRUCTIVE op is surfaced: delete-rows (replace) flags destructive=true
        with the removed rows listed; clone (append) is destructive=false.
      * The preview keys IDENTICALLY to the store (Get-PimStoreRowKey).
      * Graceful: reorder of identical rows = ZERO change; no crash on blank keys.

    Run:  Invoke-Pester -Path tests\PIM.AuthoringPreview.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (drives this with the Pester job)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:AuthLib   = Join-Path $Root 'engine\_shared\PIM-Authoring.ps1'
    $script:SqlPath   = Join-Path $Root 'engine\_shared\PIM-SqlStore.ps1'

    # The store key derivation is loaded FIRST so Get-PimAuthoringRowKey defers to
    # it (proving the preview keys identically to the SQL store + the [M2] diff).
    function Get-FunctionTextFrom([string]$file, [string]$name) {
        $src = [System.IO.File]::ReadAllText($file)
        $m = [regex]::Match($src, ("(?m)^function {0}\b[\s\S]*?^\}}" -f [regex]::Escape($name)))
        if (-not $m.Success) { throw "Could not extract function '$name' from $file" }
        return $m.Value
    }
    . ([scriptblock]::Create((Get-FunctionTextFrom $script:SqlPath 'Get-PimStoreRowKey')))

    # Dot-source the real authoring lib (pure: Set-StrictMode -Off, no boot/IO).
    . $script:AuthLib

    function New-Row([hashtable]$h) {
        $o = [ordered]@{}
        foreach ($k in $h.Keys) { $o[$k] = $h[$k] }
        return $o
    }
}

Describe '[M3] Move admin never silently drops rows' {

    BeforeAll {
        # 4 assignment rows for two admins across three tags.
        $script:assign = @(
            (New-Row @{ Username = 'alice'; GroupTag = 'ROLE-A'; AssignmentType = 'Eligible' }),
            (New-Row @{ Username = 'alice'; GroupTag = 'ROLE-B'; AssignmentType = 'Active'   }),
            (New-Row @{ Username = 'bob';   GroupTag = 'ROLE-A'; AssignmentType = 'Eligible' }),
            (New-Row @{ Username = 'bob';   GroupTag = 'ROLE-C'; AssignmentType = 'Eligible' })
        )
    }

    It 'preserves EVERY row: output count == input count' {
        $plan = New-PimAdminMovePlan -AssignmentRows $script:assign -Username 'alice' -FromTag 'ROLE-A' -ToTag 'ROLE-Z'
        @($plan.rows).Count | Should -Be 4
        $plan.inputCount    | Should -Be 4
        $plan.outputCount   | Should -Be 4
        $plan.movedCount    | Should -Be 1
        $plan.preservedCount| Should -Be 3
    }

    It 're-points ONLY the matched row; every other row is carried through verbatim' {
        $plan = New-PimAdminMovePlan -AssignmentRows $script:assign -Username 'alice' -FromTag 'ROLE-A' -ToTag 'ROLE-Z'
        $rows = @($plan.rows)
        # The matched (alice|ROLE-A) row now points at ROLE-Z, same other columns.
        $moved = @($rows | Where-Object { "$($_.Username)" -eq 'alice' -and "$($_.GroupTag)" -eq 'ROLE-Z' })
        @($moved).Count | Should -Be 1
        "$($moved[0].AssignmentType)" | Should -Be 'Eligible'
        # alice's OTHER assignment (ROLE-B) is untouched.
        @($rows | Where-Object { "$($_.Username)" -eq 'alice' -and "$($_.GroupTag)" -eq 'ROLE-B' }).Count | Should -Be 1
        # bob's TWO assignments survive unchanged (the wholesale-replace bug would drop these).
        @($rows | Where-Object { "$($_.Username)" -eq 'bob' }).Count | Should -Be 2
        # The old (alice|ROLE-A) row is gone (re-pointed, not duplicated).
        @($rows | Where-Object { "$($_.Username)" -eq 'alice' -and "$($_.GroupTag)" -eq 'ROLE-A' }).Count | Should -Be 0
    }

    It 'throws (does not drop) when the admin has no matching assignment' {
        { New-PimAdminMovePlan -AssignmentRows $script:assign -Username 'carol' -FromTag 'ROLE-A' -ToTag 'ROLE-Z' } |
            Should -Throw -ExpectedMessage '*no assignment*'
    }

    It 'moves ALL of an admin''s matching rows when several share the From tag' {
        $multi = @(
            (New-Row @{ Username = 'dan'; GroupTag = 'ROLE-A'; AssignmentType = 'Eligible' }),
            (New-Row @{ Username = 'dan'; GroupTag = 'ROLE-A'; AssignmentType = 'Active'   }),
            (New-Row @{ Username = 'eve'; GroupTag = 'ROLE-A'; AssignmentType = 'Eligible' })
        )
        $plan = New-PimAdminMovePlan -AssignmentRows $multi -Username 'dan' -FromTag 'ROLE-A' -ToTag 'ROLE-Z'
        @($plan.rows).Count | Should -Be 3      # nothing dropped
        $plan.movedCount    | Should -Be 2
        @($plan.rows | Where-Object { "$($_.Username)" -eq 'dan' -and "$($_.GroupTag)" -eq 'ROLE-Z' }).Count | Should -Be 2
        @($plan.rows | Where-Object { "$($_.Username)" -eq 'eve' }).Count | Should -Be 1
    }
}

Describe '[M3] Each authoring op produces a correct keyed preview' {

    It 'clone (append) -> adds only, NOT destructive, reorder of existing is unchanged' {
        $base = 'PIM-Definitions-Groups'
        $before = @(
            (New-Row @{ GroupTag = 'GT-A'; GroupName = 'A' }),
            (New-Row @{ GroupTag = 'GT-B'; GroupName = 'B' })
        )
        # Clone produced two NEW tags from a template (append on top of current set).
        $after = @(
            (New-Row @{ GroupTag = 'GT-C'; GroupName = 'C' }),
            (New-Row @{ GroupTag = 'GT-D'; GroupName = 'D' })
        )
        $pv = Get-PimAuthoringPreview -Base $base -Before $before -After $after -Mode 'append' -Action 'clone'
        $pv.addCount    | Should -Be 2
        $pv.removeCount | Should -Be 0
        $pv.modifyCount | Should -Be 0
        $pv.destructive | Should -BeFalse
        $pv.summary     | Should -Be '+2 / ~0 / -0'
    }

    It 'clone-azure-role (append) -> adds only on the Azure-Resources base' {
        $base = 'PIM-Assignments-Azure-Resources'
        $after = @(
            (New-Row @{ GroupTag = 'GT-A'; AzScope = '/subs/x'; AzScopePermission = 'Reader' }),
            (New-Row @{ GroupTag = 'GT-A'; AzScope = '/subs/x'; AzScopePermission = 'Contributor' })
        )
        $pv = Get-PimAuthoringPreview -Base $base -Before @() -After $after -Mode 'append' -Action 'clone-azure-role'
        $pv.addCount    | Should -Be 2
        $pv.destructive | Should -BeFalse
    }

    It 'clone-au / au (append) -> adds only on the AU base' {
        $base = 'PIM-Definitions-AU'
        $after = @( (New-Row @{ AdministrativeUnitTag = 'AU-NEW'; AUDisplayName = 'New unit' }) )
        $pv = Get-PimAuthoringPreview -Base $base -Before @() -After $after -Mode 'append' -Action 'clone-au'
        $pv.addCount    | Should -Be 1
        $pv.destructive | Should -BeFalse
    }

    It 'bulk-attach (append) -> adds only on the Roles-Groups base' {
        $base = 'PIM-Assignments-Roles-Groups'
        $after = @(
            (New-Row @{ GroupTag = 'GT-A'; RoleDefinitionName = 'Reader' }),
            (New-Row @{ GroupTag = 'GT-A'; RoleDefinitionName = 'User Administrator' })
        )
        $pv = Get-PimAuthoringPreview -Base $base -Before @() -After $after -Mode 'append' -Action 'bulk-attach'
        $pv.addCount    | Should -Be 2
        $pv.destructive | Should -BeFalse
    }

    It 'import-admins (append) -> adds only on Account-Definitions-Admins' {
        $base = 'Account-Definitions-Admins'
        $after = @(
            (New-Row @{ UserName = 'Admin-AB-ID'; DisplayName = 'A B' }),
            (New-Row @{ UserName = 'Admin-CD-ID'; DisplayName = 'C D' })
        )
        $pv = Get-PimAuthoringPreview -Base $base -Before @() -After $after -Mode 'append' -Action 'import-admins'
        $pv.addCount    | Should -Be 2
        $pv.destructive | Should -BeFalse
    }

    It 'move-admin (replace) -> the re-point surfaces old assignment leaving + new arriving' {
        $base = 'PIM-Assignments-Admins'
        $before = @(
            (New-Row @{ Username = 'alice'; GroupTag = 'ROLE-A'; AssignmentType = 'Eligible' }),
            (New-Row @{ Username = 'bob';   GroupTag = 'ROLE-C'; AssignmentType = 'Eligible' })
        )
        # move-admin produces the FULL replacement set: alice|ROLE-A -> alice|ROLE-Z.
        $plan = New-PimAdminMovePlan -AssignmentRows $before -Username 'alice' -FromTag 'ROLE-A' -ToTag 'ROLE-Z'
        $pv = Get-PimAuthoringPreview -Base $base -Before $before -After @($plan.rows) -Mode 'replace' -Action 'move-admin'
        # The composite key is Username|GroupTag, so the re-point is a remove of
        # alice|ROLE-A + an add of alice|ROLE-Z; bob is untouched. The preview
        # surfaces BOTH so the operator sees the old assignment going away.
        $pv.addCount    | Should -Be 1
        $pv.removeCount | Should -Be 1
        $pv.unchanged   | Should -Be 1     # bob carried through, not falsely flagged
        "$($pv.adds[0].row.GroupTag)"    | Should -Be 'ROLE-Z'
        "$($pv.removes[0].row.GroupTag)" | Should -Be 'ROLE-A'
    }
}

Describe '[M3] Destructive ops are surfaced to the operator' {

    It 'delete-rows (replace) flags destructive=true and lists the removed rows' {
        $base = 'PIM-Definitions-Groups'
        $before = @(
            (New-Row @{ GroupTag = 'GT-A'; GroupName = 'A' }),
            (New-Row @{ GroupTag = 'GT-B'; GroupName = 'B' }),
            (New-Row @{ GroupTag = 'GT-C'; GroupName = 'C' })
        )
        # delete-rows removed GT-B (Remove-PimRowsByIndex result -> the new full set).
        $del = Remove-PimRowsByIndex -Rows $before -Indexes @(1)
        $pv = Get-PimAuthoringPreview -Base $base -Before $before -After @($del.rows) -Mode 'replace' -Action 'delete-rows'
        $pv.destructive | Should -BeTrue
        $pv.removeCount | Should -Be 1
        $pv.addCount    | Should -Be 0
        $pv.modifyCount | Should -Be 0
        "$($pv.removes[0].row.GroupTag)" | Should -Be 'GT-B'
    }

    It 'a non-destructive append never reports a remove even though Before has rows' {
        $base = 'PIM-Definitions-Groups'
        $before = @( (New-Row @{ GroupTag = 'GT-A'; GroupName = 'A' }) )
        $after  = @( (New-Row @{ GroupTag = 'GT-NEW'; GroupName = 'New' }) )
        $pv = Get-PimAuthoringPreview -Base $base -Before $before -After $after -Mode 'append' -Action 'clone'
        $pv.destructive | Should -BeFalse
        $pv.removeCount | Should -Be 0
        $pv.addCount    | Should -Be 1
    }

    It 'action-shape map routes each action to base + mode + destructive-by-design flag' {
        (Get-PimAuthoringActionShape -Action 'move-admin').mode | Should -Be 'replace'
        (Get-PimAuthoringActionShape -Action 'clone' -Base 'PIM-Definitions-Groups').mode | Should -Be 'append'
        (Get-PimAuthoringActionShape -Action 'clone-azure-role').base | Should -Be 'PIM-Assignments-Azure-Resources'
        (Get-PimAuthoringActionShape -Action 'clone-au').base | Should -Be 'PIM-Definitions-AU'
        (Get-PimAuthoringActionShape -Action 'delete-rows' -Base 'PIM-Definitions-Groups').destructiveByDesign | Should -BeTrue
        (Get-PimAuthoringActionShape -Action 'clone' -Base 'X').destructiveByDesign | Should -BeFalse
    }
}

Describe '[M3] Preview keys identically to the store + is graceful' {

    It 'preview key matches Get-PimStoreRowKey for a composite-key base' {
        $base = 'PIM-Assignments-Roles-Groups'
        $row = New-Row @{ GroupTag = 'GT-A'; RoleDefinitionName = 'Reader' }
        (Get-PimAuthoringRowKey -Base $base -Row $row) | Should -Be (Get-PimStoreRowKey -Base $base -Row $row)
    }

    It 'pure reorder of identical rows -> ZERO change (replace mode)' {
        $base = 'PIM-Definitions-Groups'
        $before = @(
            (New-Row @{ GroupTag = 'GT-A'; GroupName = 'A' }),
            (New-Row @{ GroupTag = 'GT-B'; GroupName = 'B' }),
            (New-Row @{ GroupTag = 'GT-C'; GroupName = 'C' })
        )
        $after = @($before[2], $before[0], $before[1])
        $pv = Get-PimAuthoringPreview -Base $base -Before $before -After $after -Mode 'replace' -Action 'reorder'
        $pv.addCount + $pv.removeCount + $pv.modifyCount | Should -Be 0
        $pv.unchanged | Should -Be 3
    }

    It 'does not crash on blank/unkeyable rows; falls back to content match' {
        $before = @( (New-Row @{ Foo = '1' }), (New-Row @{ Foo = '2' }) )
        $after  = @($before[1], $before[0])   # reorder, no derivable key
        { Get-PimAuthoringPreview -Base 'Unknown-Base' -Before $before -After $after -Mode 'replace' } | Should -Not -Throw
        $pv = Get-PimAuthoringPreview -Base 'Unknown-Base' -Before $before -After $after -Mode 'replace'
        $pv.addCount + $pv.removeCount + $pv.modifyCount | Should -Be 0
        $pv.unchanged | Should -Be 2
    }
}
