#Requires -Version 5.1
<#
.SYNOPSIS
    [H3] / REQUIREMENTS §28 -- APPROVAL-GATED BULK-REVOKE EXECUTOR (request ->
    approve -> EXECUTE), offline + in-proc Pester. Closes the Maintenance
    bulk-revoke "raw / immediate" gap: an over-threshold bulk revoke must flow
    through a maker/checker approval and only then execute through the EXISTING
    active-assignment revoke pipeline -- never a one-click immediate path.

    This suite dot-sources the REAL engine/_shared/PIM-DisableGuard.ps1 +
    PIM-ApprovalGate.ps1 (pure, no boot, no tenant) and exercises the new
    Invoke-PimRevokeExecution driver, the EXACT mirror of the [H4] offboard
    executor. The active-assignment revoke pipeline is INJECTED as a MOCK
    scriptblock that records the rows it was asked to revoke -- NO real
    assignment is ever revoked.

    Cases proven:
      * An over-threshold revoke does NOT execute until an Approved 'revoke'
        request for the batch label exists: with no approval, the run is refused
        (gate=no-approval) and the mock pipeline is never called.
      * SELF-APPROVAL is refused (maker != checker) -- the request stays Pending
        and an over-threshold execute is still blocked.
      * An at/below-threshold batch runs under the interim count-confirm guard
        (gate=interim-guard) -- no approval needed -- and revokes exactly the rows.
      * An APPROVED over-threshold batch executes EXACTLY the post-break-glass
        rows through the pipeline, latches once-only (a second execute is refused),
        and never re-runs.
      * BREAK-GLASS rows are ALWAYS excluded (reported in skipped), approval or not.
      * A blank justification is refused (every revoke must be attributed).

    Run:  Invoke-Pester -Path tests\PIM.RevokeExecution.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (drives this with the Pester job)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:GuardLib  = Join-Path $Root 'engine\_shared\PIM-DisableGuard.ps1'
    $script:GateLib   = Join-Path $Root 'engine\_shared\PIM-ApprovalGate.ps1'
    if (Test-Path -LiteralPath $script:GuardLib) { . $script:GuardLib }
    . $script:GateLib

    # Isolate the persistence store to a throwaway file; NO SQL, NO Set/Get-PimSetting.
    $global:PIM_ApprovalStatePath = Join-Path $env:TEMP ("pim-revoke-exec-test-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force }
    $global:PIM_BreakGlassAccounts     = $null
    $global:PIM_AllowSelfApprove       = $null
    $global:PIM_RevokeApprovalThreshold = 5    # explicit so the test is deterministic

    # Build N revoke rows -- distinct principals so none look like break-glass.
    function New-RevokeRows([int]$n, [string]$prefix = 'user') {
        $rows = New-Object System.Collections.ArrayList
        for ($i = 1; $i -le $n; $i++) {
            [void]$rows.Add([pscustomobject]@{
                id          = "row-$prefix-$i"
                principal   = "$prefix$i@contoso"
                principalId = "pid-$prefix-$i"
                type        = 'entra-role'
                role        = 'Some Role'
            })
        }
        return $rows.ToArray()
    }

    # MOCK revoke pipeline: records the rows it was asked to revoke, NEVER touches a
    # tenant. Returns a recording invoker + the call log.
    function New-MockRevokeInvoker {
        $log = New-Object System.Collections.ArrayList
        $invoker = {
            param($Rows, $Justification)
            $out = New-Object System.Collections.ArrayList
            foreach ($r in @($Rows)) {
                [void]$log.Add([pscustomobject]@{ id = "$($r.id)"; principal = "$($r.principal)"; justification = "$Justification" })
                [void]$out.Add([pscustomobject]@{ id = "$($r.id)"; ok = $true })
            }
            return $out.ToArray()
        }.GetNewClosure()
        return [pscustomobject]@{ invoker = $invoker; log = $log }
    }

    function New-RevokeRequest([string]$target, [string]$requestor = 'maker@contoso') {
        return Add-PimApprovalRequest -Requestor $requestor -Action 'revoke' -Target $target -Justification 'incident cleanup' -Ticket 'INC-700'
    }
}

AfterAll {
    if ($global:PIM_ApprovalStatePath -and (Test-Path -LiteralPath $global:PIM_ApprovalStatePath)) {
        Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force -ErrorAction SilentlyContinue
    }
    $global:PIM_ApprovalStatePath       = $null
    $global:PIM_BreakGlassAccounts      = $null
    $global:PIM_AllowSelfApprove        = $null
    $global:PIM_RevokeApprovalThreshold = $null
}

Describe 'Approval-gated bulk-revoke executor [H3]' {

    Context 'An over-threshold batch does NOT revoke until approved' {
        It 'refuses an over-threshold batch with no Approved request and never calls the pipeline' {
            $rows = New-RevokeRows 8 'a'   # 8 > threshold 5
            $mock = New-MockRevokeInvoker
            $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-A' -Justification 'cleanup' `
                     -RevokeInvoker $mock.invoker -Requests @()
            $res.ok        | Should -BeFalse
            $res.executed  | Should -BeFalse
            $res.gate      | Should -Be 'no-approval'
            $res.required  | Should -BeTrue
            $mock.log.Count | Should -Be 0
        }
    }

    Context 'Self-approval is refused (maker != checker)' {
        It 'leaves the request Pending and an over-threshold execute blocked when the requestor self-approves' {
            $req = New-RevokeRequest 'batch-self' 'solo@contoso'
            $dec = Set-PimApprovalDecision -Id $req.id -Approver 'solo@contoso' -Decision 'approve'
            $dec.ok | Should -BeFalse
            (@(Get-PimApprovalRequests -Target 'batch-self')[0]).status | Should -Be 'Pending'
            $rows = New-RevokeRows 8 'b'
            $mock = New-MockRevokeInvoker
            $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-self' -Justification 'cleanup' `
                     -RevokeInvoker $mock.invoker
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'no-approval'
            $mock.log.Count | Should -Be 0
        }
    }

    Context 'An at/below-threshold batch runs under the interim guard (no approval needed)' {
        It 'revokes exactly the rows and does not require an approval' {
            $rows = New-RevokeRows 3 'c'   # 3 <= threshold 5
            $mock = New-MockRevokeInvoker
            $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-small' -Justification 'cleanup' `
                     -RevokeInvoker $mock.invoker -Requests @()
            $res.executed | Should -BeTrue
            $res.ok       | Should -BeTrue
            $res.gate     | Should -Be 'interim-guard'
            $res.required | Should -BeFalse
            $mock.log.Count | Should -Be 3
        }
    }

    Context 'An approved over-threshold batch executes exactly the rows, once' {
        It 'runs the post-break-glass rows through the pipeline and latches once-only' {
            $req = New-RevokeRequest 'batch-big'
            $dec = Set-PimApprovalDecision -Id $req.id -Approver 'checker@contoso' -Decision 'approve'
            $dec.ok | Should -BeTrue

            $rows = New-RevokeRows 8 'd'
            $mock = New-MockRevokeInvoker
            $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-big' -Justification 'cleanup' `
                     -RevokeInvoker $mock.invoker
            $res.executed | Should -BeTrue
            $res.ok       | Should -BeTrue
            $res.gate     | Should -Be 'approved'
            $res.toRevokeCount | Should -Be 8
            $mock.log.Count    | Should -Be 8

            # Once-only latch: the request is now Executed and a SECOND execute is refused
            # (no longer approved-for) -- the mock is NOT called again.
            (@(Get-PimApprovalRequests -Target 'batch-big')[0]).status | Should -Be 'Executed'
            $mock2 = New-MockRevokeInvoker
            $res2 = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-big' -Justification 'cleanup' `
                      -RevokeInvoker $mock2.invoker
            $res2.executed   | Should -BeFalse
            $res2.gate       | Should -Be 'no-approval'
            $mock2.log.Count | Should -Be 0
        }
    }

    Context 'Break-glass rows are ALWAYS excluded (approval or not)' {
        It 'drops break-glass rows from the executed set and reports them skipped' {
            $global:PIM_BreakGlassAccounts = 'glass1@contoso;glass2@contoso'
            try {
                # 5 ordinary + 2 break-glass = 7 selected, 5 to-revoke (<= threshold 5)
                $ordinary = New-RevokeRows 5 'e'
                $bg = @(
                    [pscustomobject]@{ id = 'bg-1'; principal = 'glass1@contoso'; principalId = 'glass1@contoso'; type = 'entra-role' }
                    [pscustomobject]@{ id = 'bg-2'; principal = 'glass2@contoso'; principalId = 'glass2@contoso'; type = 'entra-role' }
                )
                $rows = @($ordinary) + $bg
                $mock = New-MockRevokeInvoker
                $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-bg' -Justification 'cleanup' `
                         -RevokeInvoker $mock.invoker -Requests @()
                $res.executed     | Should -BeTrue
                $res.skippedCount | Should -Be 2
                $res.toRevokeCount| Should -Be 5
                $mock.log.Count   | Should -Be 5
                # None of the revoked rows is a break-glass principal.
                (@($mock.log | Where-Object { $_.principal -like 'glass*' }).Count) | Should -Be 0
            } finally { $global:PIM_BreakGlassAccounts = $null }
        }
    }

    Context 'A revoke must be attributed' {
        It 'refuses a blank justification' {
            $rows = New-RevokeRows 3 'f'
            $mock = New-MockRevokeInvoker
            $res = Invoke-PimRevokeExecution -Rows $rows -Target 'batch-nojust' -Justification '   ' `
                     -RevokeInvoker $mock.invoker -Requests @()
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'no-justification'
            $mock.log.Count | Should -Be 0
        }
    }
}
