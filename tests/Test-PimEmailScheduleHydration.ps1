#Requires -Version 5.1
<#
  Offline tests for the EmailControls + JobSchedule hydration fix (GUI-state ==
  actual-behavior). Proves a COLD-booted send path / scheduler honours the GUI-saved
  pim.Settings, not just the Manager's in-process globals:
    (a) kill-switch=ON in the store BLOCKS the send even when the in-process global is
        unset (simulating a cold scheduled job / engine run);
    (b) redirect-all + allowlist from the store are applied to the send path;
    (c) a store-READ FAILURE does NOT fail-open (an armed kill switch stays armed; the
        send is never silently re-enabled);
    (d) the scheduler reads JobSchedule from the store at boot (Get-PimJobSchedule
        returns the persisted cadence, not the shipped default).
  Pure / offline: the SQL store reader is STUBBED -- no network, no live SQL.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
$shared = Resolve-Path "$here\..\engine\_shared"
. "$shared\PIM-Rest.ps1"
. "$shared\PIM-SqlStore.ps1"      # Import-PimSettingsFromStore + Get-PimSqlSettingsConnectionString
. "$shared\PIM-Notify.ps1"        # Send-PimNotifyMail + Set-PimEmailControlsGlobals + Initialize-PimEmailControlsFromStore
. "$shared\PIM-PortalAccess.ps1"  # Get-PimPolicySetting (engine/scheduler settings reader)
. "$shared\PIM-Scheduler.ps1"     # Get-PimJobSchedule + Import-PimSchedulerSettingsFromStore

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== EmailControls + JobSchedule hydration (GUI-state == behavior) ===" -ForegroundColor Cyan

# --- the stubbed store. $script:Store is the fake pim.Settings; $script:StoreUnreachable=$true makes
#     the reader throw (to prove fail-safe). Both helpers resolve a (fake) CS so the REAL
#     Import-PimSettingsFromStore runs end-to-end against the stub. -----------------------
$script:Store = @{}
$script:StoreUnreachable  = $false
function Get-PimSqlSettingsConnectionString { return 'Server=stub;Database=stub' }
function Get-PimAllSqlSettings { param([string]$ConnectionString) if ($script:StoreUnreachable) { throw 'stub: store unreachable' } ; return $script:Store }

function Reset-PimHydrationState {
    # Clear the once-per-process hydration latches + every global the helpers touch, so each
    # case starts from a true cold-boot (nothing mirrored in-process by a Manager).
    Set-Variable -Name PimEmailControlsHydrated -Scope Script -Value $false -ErrorAction SilentlyContinue
    Set-Variable -Name PimSchedSettingsHydrated -Scope Script -Value $false -ErrorAction SilentlyContinue
    $global:PIM_NamingConventions = @{}
    $global:PIM_MailKillSwitch    = $null
    $global:PIM_MailRedirectAllTo = $null
    $global:PIM_MailAllowlist     = $null
    $global:PIM_JobSchedule       = $null
    $global:PIM_MailSender        = 'sender@contoso.test'   # a sender so "no sender" never masks a kill-switch test
}

# ============================================================================
# (a) kill switch ON in the store blocks the send on a COLD process (global unset)
# ============================================================================
Reset-PimHydrationState
$script:Store = @{ EmailControls = @{ killSwitch = $true; redirectAllTo = ''; allowlist = @() } }
# Pre-condition: the in-process global is NOT set (a cold scheduled job never ran the Manager mirror).
Assert "pre: in-process kill-switch global is unset (cold process)" (-not $global:PIM_MailKillSwitch)
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'real-user@contoso.test'
Assert "(a) cold send is BLOCKED by store kill switch"        ($r.sent -eq $false -and $r.reason -eq 'email kill switch on')
Assert "(a) hydration armed the in-process kill-switch global" ($global:PIM_MailKillSwitch -eq $true)

# ============================================================================
# (b) redirect-all + allowlist from the store are applied to the send path
# ============================================================================
Reset-PimHydrationState
$script:Store = @{ EmailControls = @{ killSwitch = $false; redirectAllTo = 'lab@contoso.test'; allowlist = @('lab@contoso.test') } }
# Make the actual transport observable WITHOUT network: stub Invoke-PimGraph to capture the recipient.
$script:SentTo = $null
function Invoke-PimGraph { param($Method, $Path, $Body) $script:SentTo = $Body.message.toRecipients[0].emailAddress.address; return @{} }
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'someone-else@contoso.test'
Assert "(b) redirect-all from store rewrote the recipient"  ($global:PIM_MailRedirectAllTo -eq 'lab@contoso.test' -and $script:SentTo -eq 'lab@contoso.test')
Assert "(b) allowlist from store was applied (sent to allowed redirect target)" ($r.sent -eq $true -and @($global:PIM_MailAllowlist) -contains 'lab@contoso.test')
Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue

# (b2) allowlist DROPS a recipient that is not on it (after redirect resolution).
Reset-PimHydrationState
$script:Store = @{ EmailControls = @{ killSwitch = $false; redirectAllTo = ''; allowlist = @('only-this@contoso.test') } }
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'not-listed@contoso.test'
Assert "(b2) allowlist from store drops an off-list recipient" ($r.sent -eq $false -and $r.reason -eq 'recipient not on allowlist')

# ============================================================================
# (c) a store READ FAILURE does NOT fail-open
# ============================================================================
# (c1) kill switch already armed in-process + store read throws -> stays blocked.
Reset-PimHydrationState
$global:PIM_MailKillSwitch = $true          # e.g. armed by an earlier successful hydrate / the Manager
$script:StoreUnreachable = $true                        # the store is now unreachable
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'real-user@contoso.test'
Assert "(c1) read failure does NOT disarm an armed kill switch" ($r.sent -eq $false -and $r.reason -eq 'email kill switch on' -and $global:PIM_MailKillSwitch -eq $true)

# (c2) Import returns -1 (not a 0-count "all clear") when the store is unreachable, so a
#      malformed/blank record can never silently re-enable sending.
Reset-PimHydrationState
$script:StoreUnreachable = $true
$n = Import-PimSettingsFromStore
Assert "(c2) unreachable store reports -1 (couldn't read), not 0" ($n -eq -1)
$script:StoreUnreachable = $false

# (c3) Set-PimEmailControlsGlobals only ever ARMS the kill switch, never disarms it,
#      even from a malformed record (defence-in-depth fail-safe).
$global:PIM_MailKillSwitch = $true
[void](Set-PimEmailControlsGlobals -EmailControls @{ killSwitch = $false })
Assert "(c3) applying killSwitch=false does NOT disarm an armed kill switch" ($global:PIM_MailKillSwitch -eq $true)
[void](Set-PimEmailControlsGlobals -EmailControls 'not json {{')
Assert "(c3) a malformed record leaves the kill switch armed"                ($global:PIM_MailKillSwitch -eq $true)

# ============================================================================
# (d) the scheduler reads JobSchedule from the store at boot
# ============================================================================
Reset-PimHydrationState
$persisted = @(
    [pscustomobject]@{ name = 'delta-admins'; type = 'engine-delta'; scope = 'Admins'; intervalMinutes = 7; enabled = $true }
    [pscustomobject]@{ name = 'queue-apply';  type = 'queue-apply';  intervalMinutes = 3; enabled = $true }
)
$script:Store = @{ JobSchedule = $persisted }
# Pre-condition: a cold scheduler has nothing in-process -> default schedule.
Assert "pre: cold Get-PimJobSchedule returns the shipped default" ((@(Get-PimJobSchedule)[0].intervalMinutes) -ne 7)
# Boot hydration loads JobSchedule from the store into the engine/scheduler reader source.
$hydrated = Import-PimSchedulerSettingsFromStore
$sched = @(Get-PimJobSchedule)
Assert "(d) scheduler hydrate reported success"                 ($hydrated -eq $true)
Assert "(d) Get-PimJobSchedule now returns the PERSISTED cadence" (($sched | Where-Object { $_.name -eq 'delta-admins' }).intervalMinutes -eq 7)
Assert "(d) persisted schedule replaced the default (not merged)" ($sched.Count -eq 2)

# (d2) scheduler hydrate is fail-safe: an unreachable store keeps the default + does not throw.
Reset-PimHydrationState
$script:StoreUnreachable = $true
$threw = $false
try { [void](Import-PimSchedulerSettingsFromStore) } catch { $threw = $true }
$script:StoreUnreachable = $false
Assert "(d2) scheduler hydrate never throws on an unreachable store" (-not $threw)
Assert "(d2) unreachable store -> Get-PimJobSchedule keeps the default" ((@(Get-PimJobSchedule)[0].intervalMinutes) -ne 7)

# ============================================================================
# (e) IMP-06a -- the MailSender projection, and its fail-safe direction
# ============================================================================
# The sender is NOT part of the EmailControls record, so before IMP-06a nothing could carry it:
# no Use-Cfg entry, no container env var, no projection here. The result was silent -- an
# environment with no sender RENDERS notification mail and returns without sending, while
# account creation and TAP minting still report success. These cases pin the projection AND
# the fail-safe direction, which is the OPPOSITE of the kill switch's: the kill switch is safe
# when it stays ON, the sender is safe when it stays SET. Clearing a working sender from a blank
# or unreadable store would silently mute the environment -- the exact IMP-06 failure.

# (e1) a persisted MailSender reaches the send path on a COLD process.
Reset-PimHydrationState
$global:PIM_MailSender = $null                     # cold: nothing baked in, nothing mirrored
$script:Store = @{ MailSender = 'PIM-Engine@contoso.test' }
[void](Import-PimSettingsFromStore)
Assert "(e1) persisted MailSender hydrates onto the send path" ($global:PIM_MailSender -eq 'PIM-Engine@contoso.test')

# (e2) the store OVERRIDES a deploy-time env/global value (the Manager can change the sender
#      without a container redeploy -- that is the whole point of the runtime half).
Reset-PimHydrationState
$global:PIM_MailSender = 'baked-in@contoso.test'   # as Invoke-PimEngineCore's Use-Cfg would set it
$script:Store = @{ MailSender = 'gui-changed@contoso.test' }
[void](Import-PimSettingsFromStore)
Assert "(e2) store MailSender overrides the deploy-time value" ($global:PIM_MailSender -eq 'gui-changed@contoso.test')

# (e3) FAIL-SAFE: a BLANK stored value must NOT clear a working sender.
Reset-PimHydrationState
$global:PIM_MailSender = 'baked-in@contoso.test'
$script:Store = @{ MailSender = '   ' }
[void](Import-PimSettingsFromStore)
Assert "(e3) a blank stored MailSender does NOT mute a working sender" ($global:PIM_MailSender -eq 'baked-in@contoso.test')

# (e4) FAIL-SAFE: a store with no MailSender key at all leaves the sender alone.
Reset-PimHydrationState
$global:PIM_MailSender = 'baked-in@contoso.test'
$script:Store = @{ EmailControls = @{ killSwitch = $false } }
[void](Import-PimSettingsFromStore)
Assert "(e4) an absent MailSender key does NOT mute a working sender" ($global:PIM_MailSender -eq 'baked-in@contoso.test')

# (e5) FAIL-SAFE: an UNREACHABLE store leaves the sender alone (mail keeps working through an
#      outage -- the opposite call from the kill switch, which stays armed through the same outage).
Reset-PimHydrationState
$global:PIM_MailSender = 'baked-in@contoso.test'
$script:StoreUnreachable = $true
[void](Import-PimSettingsFromStore)
$script:StoreUnreachable = $false
Assert "(e5) an unreachable store does NOT mute a working sender" ($global:PIM_MailSender -eq 'baked-in@contoso.test')

# (e6) the whole point, end to end: with a hydrated sender the send actually happens, where the
#      same send with no sender is only RENDERED. This is the silent failure IMP-06 describes.
Reset-PimHydrationState
$global:PIM_MailSender = $null
$script:Store = @{}
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'real-user@contoso.test'
Assert "(e6) no sender -> rendered, NOT sent (the silent failure)" ($r.sent -eq $false -and $r.reason -eq 'no sender')
Reset-PimHydrationState
$global:PIM_MailSender = $null
$script:Store = @{ MailSender = 'PIM-Engine@contoso.test' }
$script:SentFrom = $null
function Invoke-PimGraph { param($Method, $Path, $Body) $script:SentFrom = $Path; return @{} }
$r = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{} -Recipient 'real-user@contoso.test'
Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
Assert "(e6) hydrated sender -> the mail is SENT"          ($r.sent -eq $true)
Assert "(e6) and it is sent AS the persisted mailbox"      ("$script:SentFrom" -like '*PIM-Engine@contoso.test*')

Write-Host ("`n  {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
