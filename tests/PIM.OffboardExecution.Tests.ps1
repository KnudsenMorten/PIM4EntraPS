#Requires -Version 5.1
<#
.SYNOPSIS
    [H4] / REQUIREMENTS §27 -- APPROVAL-GATED OFFBOARDING EXECUTOR (request ->
    approve -> EXECUTE), offline + in-proc Pester. Closes the incident gap: an
    offboard/disable must flow through a maker/checker approval and only then
    execute through the EXISTING account-status-change pipeline -- never a
    one-click/automatic path.

    This suite dot-sources the REAL engine/_shared/PIM-DisableGuard.ps1 +
    PIM-ApprovalGate.ps1 (pure, no boot, no tenant) and exercises the new
    Invoke-PimOffboardExecution driver. The account-status pipeline is INJECTED
    as a MOCK scriptblock that records calls -- NO real user is ever disabled.

    Cases proven:
      * An offboard REQUEST does NOT disable anything until it is approved: a
        Pending request, when run, is refused (gate=no-approval) and the mock
        pipeline is never called.
      * SELF-APPROVAL is refused (maker != checker) -- the request stays Pending
        and execution is still blocked.
      * An APPROVED request, when executed, drives EXACTLY the requested target
        through the account-status pipeline (disable + revoke-active steps,
        AccountStatus Disabled/Revoked), schedules-not-executes the delete, and
        latches once-only (a second execute is a no-op; the request is Executed).
      * An EMPTY target is blocked (never resolves a population), and a BULK /
        multi-principal target is blocked WITHOUT explicit confirmation -- never
        an auto path.
      * It reuses the account-status pipeline: the default invoker routes
        disable -> Invoke-PimAccountStatusChange Disabled and revoke-active ->
        ...Revoked (asserted against a stubbed pipeline, no tenant).
      * Automatic offboarding is refused outright even with an approval.

    Run:  Invoke-Pester -Path tests\PIM.OffboardExecution.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (drives this with the Pester job)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:GuardLib  = Join-Path $Root 'engine\_shared\PIM-DisableGuard.ps1'
    $script:GateLib   = Join-Path $Root 'engine\_shared\PIM-ApprovalGate.ps1'
    . $script:GuardLib
    . $script:GateLib

    # Isolate the persistence store to a throwaway file; NO SQL, NO Set/Get-PimSetting.
    $global:PIM_ApprovalStatePath = Join-Path $env:TEMP ("pim-offboard-exec-test-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    if (Test-Path -LiteralPath $global:PIM_ApprovalStatePath) { Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force }
    $global:PIM_BreakGlassAccounts   = $null
    $global:PIM_AllowSelfApprove     = $null
    $global:PIM_AccountDisableEnabled = $true   # feature ON so the DisableGuard composite is real, not short-circuited

    # A desired set that positively resolves (so the DisableGuard G1 "empty/unresolved
    # desired" abort does NOT fire -- we are testing the approval flow, not that guard).
    $script:Desired = @([pscustomobject]@{ UserName = 'someadmin' })

    # MOCK account-status pipeline: records every (step,target,status) it is asked to
    # run, NEVER touches a tenant. Returns a recording invoker + the call log.
    function New-MockInvoker {
        $log = New-Object System.Collections.ArrayList
        $invoker = {
            param($Step, $Target)
            $s = "$($Step.step)".Trim().ToLowerInvariant()
            $status = if ($s -eq 'disable') { 'Disabled' } elseif ($s -eq 'revoke-active') { 'Revoked' } else { '' }
            [void]$log.Add([pscustomobject]@{ step = $s; target = "$Target"; status = $status })
            if ($s -eq 'schedule-delete') { return [pscustomobject]@{ ok = $true; detail = 'scheduled (mock)' } }
            return [pscustomobject]@{ ok = $true; detail = "$s -> AccountStatus=$status (mock)" }
        }.GetNewClosure()
        return [pscustomobject]@{ invoker = $invoker; log = $log }
    }

    # Helper: raise + (optionally) approve an offboard request in the isolated store.
    function New-OffboardRequest([string]$target, [string]$requestor = 'maker@contoso') {
        return Add-PimApprovalRequest -Requestor $requestor -Action 'offboard' -Target $target -Justification 'left the company' -Ticket 'INC-900'
    }
}

AfterAll {
    if ($global:PIM_ApprovalStatePath -and (Test-Path -LiteralPath $global:PIM_ApprovalStatePath)) {
        Remove-Item -LiteralPath $global:PIM_ApprovalStatePath -Force -ErrorAction SilentlyContinue
    }
    $global:PIM_ApprovalStatePath     = $null
    $global:PIM_AccountDisableEnabled = $null
    $global:PIM_BreakGlassAccounts    = $null
    $global:PIM_AllowSelfApprove      = $null
}

Describe 'Approval-gated offboarding executor [H4]' {

    Context 'A request does NOT disable until approved' {
        It 'refuses to execute a Pending (un-approved) request and never calls the pipeline' {
            $req = New-OffboardRequest 'pending-user@contoso'
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $req.id -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.ok       | Should -BeFalse
            $res.executed | Should -BeFalse
            $res.gate     | Should -Be 'no-approval'
            $mock.log.Count | Should -Be 0          # nothing executed
            # And the request is still Pending in the store (not flipped to Executed).
            (@(Get-PimApprovalRequests -Target 'pending-user@contoso')[0]).status | Should -Be 'Pending'
        }
    }

    Context 'Self-approval is refused (maker != checker)' {
        It 'leaves the request Pending and execution blocked when the requestor self-approves' {
            $req = New-OffboardRequest 'self-user@contoso' 'solo@contoso'
            $dec = Set-PimApprovalDecision -Id $req.id -Approver 'solo@contoso' -Decision 'approve'
            $dec.ok | Should -BeFalse                                  # separation of duties
            (@(Get-PimApprovalRequests -Target 'self-user@contoso')[0]).status | Should -Be 'Pending'
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $req.id -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'no-approval'
            $mock.log.Count | Should -Be 0
        }
    }

    Context 'An approved request executes EXACTLY the requested targets, once' {
        It 'runs disable+revoke-active through the pipeline, schedules the delete, and latches once-only' {
            $req = New-OffboardRequest 'bob@contoso'
            $dec = Set-PimApprovalDecision -Id $req.id -Approver 'checker@contoso' -Decision 'approve'
            $dec.ok | Should -BeTrue

            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $req.id -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.ok       | Should -BeTrue
            $res.executed | Should -BeTrue
            $res.gate     | Should -Be 'executed'
            $res.target   | Should -Be 'bob@contoso'

            # EXACTLY the requested target was driven through the pipeline -- no other.
            ($mock.log | Where-Object { $_.target -ne 'bob@contoso' }).Count | Should -Be 0
            $disable = @($mock.log | Where-Object { $_.step -eq 'disable' })
            $revoke  = @($mock.log | Where-Object { $_.step -eq 'revoke-active' })
            $disable.Count | Should -Be 1
            $disable[0].status | Should -Be 'Disabled'
            $revoke.Count  | Should -Be 1
            $revoke[0].status  | Should -Be 'Revoked'
            # The delete is SCHEDULED, not executed.
            $del = @($mock.log | Where-Object { $_.step -eq 'schedule-delete' })
            $del.Count | Should -Be 1
            $del[0].status | Should -BeNullOrEmpty   # no AccountStatus -> not a disable/revoke

            # Once-only latch: the request is now Executed, no longer approved-for, and a
            # SECOND execute is a no-op (the mock is NOT called again).
            (@(Get-PimApprovalRequests -Target 'bob@contoso')[0]).status | Should -Be 'Executed'
            $mock2 = New-MockInvoker
            $res2 = Invoke-PimOffboardExecution -RequestId $req.id -ActionInvoker $mock2.invoker `
                      -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res2.executed   | Should -BeFalse
            # Refused on re-run: from the store the request is now Executed -> no longer
            # approved-for (gate=no-approval). It does NOT run again.
            $res2.gate       | Should -Be 'no-approval'
            $mock2.log.Count | Should -Be 0
            # The once-only LATCH itself is the last line of defence: replaying the
            # still-Approved record (e.g. a stale in-memory copy) against the store that
            # has already executed it is refused at the latch (gate=already-executed) and
            # still does not run.
            $res3 = Invoke-PimOffboardExecution -RequestId $req.id -Requests @($dec.request) -ActionInvoker $mock2.invoker `
                      -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res3.executed   | Should -BeFalse
            $res3.gate       | Should -Be 'already-executed'
            $mock2.log.Count | Should -Be 0
        }
    }

    Context 'Empty / bulk targets are blocked without explicit confirmation' {
        It 'blocks an EMPTY target (never resolves a population) even with -ConfirmBulk' {
            # Forge an Approved record with a blank target directly (Add- requires a target),
            # so we test the executor's empty-target guard in isolation.
            $rec = New-PimApprovalRequest -Requestor 'm@contoso' -Action 'offboard' -Target 'placeholder@contoso'
            $rec = ($rec.PSObject.Copy()); $rec.status = 'Approved'; $rec.approver = 'c@contoso'; $rec.decidedUtc = ([datetime]::UtcNow).ToString('o'); $rec.target = '   '
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $rec.id -Requests @($rec) -ConfirmBulk -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'empty-target'
            $mock.log.Count | Should -Be 0
        }
        It 'blocks a BULK / multi-principal target WITHOUT -ConfirmBulk' {
            $rec = New-PimApprovalRequest -Requestor 'm@contoso' -Action 'offboard' -Target 'a@contoso, b@contoso'
            $rec = ($rec.PSObject.Copy()); $rec.status = 'Approved'; $rec.approver = 'c@contoso'; $rec.decidedUtc = ([datetime]::UtcNow).ToString('o')
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $rec.id -Requests @($rec) -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'bulk-unconfirmed'
            $mock.log.Count | Should -Be 0
        }
        It 'classifies single vs bulk vs empty targets correctly (Test-PimOffboardTargetIsBulk)' {
            (Test-PimOffboardTargetIsBulk -Target 'bob@contoso').bulk  | Should -BeFalse
            (Test-PimOffboardTargetIsBulk -Target '').empty            | Should -BeTrue
            (Test-PimOffboardTargetIsBulk -Target 'a@x;b@x').bulk       | Should -BeTrue
            (Test-PimOffboardTargetIsBulk -Target 'all').bulk          | Should -BeTrue
            (Test-PimOffboardTargetIsBulk -Target '*').bulk            | Should -BeTrue
        }
    }

    Context 'Reuses the account-status pipeline (default invoker)' {
        It 'routes disable -> Invoke-PimAccountStatusChange Disabled and revoke-active -> Revoked' {
            # Stub the REAL pipeline cmdlet so the DEFAULT invoker (no -ActionInvoker) is
            # exercised without a tenant. Records the AccountStatus it is asked to apply.
            $script:psCalls = New-Object System.Collections.ArrayList
            function Invoke-PimAccountStatusChange {
                param([string]$UserPrincipalName, [string]$AccountStatus, [string]$StatusChangeCode)
                [void]$script:psCalls.Add([pscustomobject]@{ upn = $UserPrincipalName; status = $AccountStatus })
            }
            try {
                $req = New-OffboardRequest 'carol@contoso'
                Set-PimApprovalDecision -Id $req.id -Approver 'checker@contoso' -Decision 'approve' | Out-Null
                $res = Invoke-PimOffboardExecution -RequestId $req.id `
                         -Desired $script:Desired -DesiredResolved $true -Scanned 50   # no -ActionInvoker -> default
                $res.executed | Should -BeTrue
                $statuses = @($script:psCalls | Where-Object { $_.upn -eq 'carol@contoso' } | ForEach-Object { $_.status })
                $statuses | Should -Contain 'Disabled'
                $statuses | Should -Contain 'Revoked'
            } finally {
                Remove-Item Function:\Invoke-PimAccountStatusChange -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Automatic offboarding is never permitted' {
        It 'refuses -Automatic even with an Approved request' {
            $req = New-OffboardRequest 'auto-user@contoso'
            Set-PimApprovalDecision -Id $req.id -Approver 'checker@contoso' -Decision 'approve' | Out-Null
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $req.id -Automatic -ActionInvoker $mock.invoker `
                     -Desired $script:Desired -DesiredResolved $true -Scanned 50
            $res.executed   | Should -BeFalse
            $res.gate       | Should -Be 'automatic-prohibited'
            $mock.log.Count | Should -Be 0
            # Not latched -- the request is still Approved (never consumed by a refused run).
            (@(Get-PimApprovalRequests -Target 'auto-user@contoso')[0]).status | Should -Be 'Approved'
        }
    }

    Context 'DisableGuard circuit breaker is NOT bypassed by an approval' {
        It 'blocks when desired is unresolved (mass-disable safety net) even WITH approval' {
            $req = New-OffboardRequest 'guard-user@contoso'
            Set-PimApprovalDecision -Id $req.id -Approver 'checker@contoso' -Decision 'approve' | Out-Null
            $mock = New-MockInvoker
            $res = Invoke-PimOffboardExecution -RequestId $req.id -ActionInvoker $mock.invoker `
                     -Desired @() -DesiredResolved $false -Scanned 50
            $res.executed   | Should -BeFalse
            $res.gate       | Should -BeLike 'disable-guard:*'
            $mock.log.Count | Should -Be 0
        }
    }
}
