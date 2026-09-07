#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS's READINESS PROBE -- is this environment actually RUNNING, not merely deployed?

.DESCRIPTION
    The SOLUTION half of the framework readiness contract (DOCS/REQUIREMENTS.md DEPLOY-2 §7;
    framework half: sync/_AitReadiness.ps1). The framework declares nothing about what PIM needs
    -- it runs whatever this script is declared to be in solution.deploy.json and reads the
    result shape. Everything PIM-specific lives here, which is what keeps the framework generic.

    🔴 WHY THIS EXISTS -- every check below is a thing that was MEASURED BROKEN on a live managed
    tenant on 2026-08-13 while reporting success. The tenant had been deployed by the same code
    path as its healthy sibling and came up structurally fine and functionally inert:

      | what was wrong                        | how it reported |
      |---------------------------------------|-----------------|
      | every feature gate OFF                | a gate-skip logs ok=True |
      | no sender mailbox                     | Graph 404, never checked |
      | MailSender absent from pim.Settings   | sends return sent=$false into a swallowed catch |
      | no engine identity on the tick job    | 403s that looked like a permissions bug |
      | synced admins had no credential       | CreateTAP='FALSE', accounts enabled, nobody could sign in |

    NOT ONE of them raised an error. That is the entire argument for asserting the END STATE
    instead of trusting the step list.

.OUTPUTS
    The framework contract:  @{ ok = <bool>; checks = @( @{ name; ok; detail; required } ... ) }

    🪤 A check that could not be EVALUATED reports ok=$false with the reason -- never ok=$true and
    never silence. "I could not tell" is not "fine"; conflating them is the exact failure this
    probe exists to catch. Individual checks are wrapped so one unreachable dependency degrades
    that check rather than aborting the run and losing the other five verdicts.

.NOTES
    READ-ONLY. This probe never writes to the tenant or the store.
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$TickJobName = 'pim-tick',
    # The engine identity used to read Graph + the store. Resolved from the ambient engine
    # globals when omitted (the normal in-container case).
    [string]$EngineClientId,
    [string]$EngineClientSecret,
    [string]$EngineCertThumbprint,
    [string]$MailSenderExpected
)

$ErrorActionPreference = 'Continue'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')

$checks = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '', [bool]$Required = $true)
    $checks.Add([pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail; required = $Required }) | Out-Null
}
function Invoke-Check {
    # Run one check's body. An exception becomes a FAILED check carrying the error -- not a
    # crashed probe, because losing the other verdicts to one unreachable dependency is how a
    # partial answer turns into no answer.
    param([string]$Name, [scriptblock]$Body, [bool]$Required = $true)
    try {
        $r = & $Body
        Add-Check -Name $Name -Ok ([bool]$r.ok) -Detail "$($r.detail)" -Required $Required
    } catch {
        Add-Check -Name $Name -Ok $false -Detail "could not evaluate: $((("$($_.Exception.Message)") -split "`n")[0])" -Required $Required
    }
}

# --- identity ------------------------------------------------------------------------
if ($TenantId)             { $global:PIM_TenantId = $TenantId }
if ($EngineClientId)       { $global:PIM_ClientId = $EngineClientId }
if ($EngineClientSecret)   { $global:PIM_ClientSecret = $EngineClientSecret }
if ($EngineCertThumbprint) { $global:PIM_CertThumbprint = $EngineCertThumbprint }

$cs = $null
try {
    if ($SqlServerFqdn) { $cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $SqlDatabase }
    else                { $cs = Get-PimSqlConnectionString }
} catch { $cs = $null }

$settings = $null
try { if ($cs) { $settings = Get-PimAllSqlSettings -ConnectionString $cs } } catch { $settings = $null }

# =====================================================================================
# 1. THE STORE -- everything else reads through it, so it is checked first.
# =====================================================================================
Invoke-Check -Name 'store reachable + schema present' -Body {
    if (-not $cs) { return @{ ok = $false; detail = 'no SQL connection string could be resolved (pass -SqlServerFqdn)' } }
    # 🪤 ASSERT BY NAME, NEVER BY COUNT. A count threshold cannot tell "this store has fewer
    # tables because it is a SLAVE" from "the schema upgrade never applied", and an earlier
    # version of this check used `< 5` -- which measured 3 on a healthy managed tenant and would
    # have declared EVERY SLAVE IN THE ESTATE broken. A gate that cries wolf is a gate that gets
    # ignored, which is worse than no gate. Measured 2026-08-13: a master carries 9 tables
    # (incl. the CentralAdmins / TenantRoleProjection / platform.* registry, which are master-side
    # by design) and a healthy slave carries exactly these three.
    $required = @('Rows', 'Settings', 'ChangeQueue')
    $have = @(Invoke-PimSqlQuery -ConnectionString $cs -Sql "SELECT name FROM sys.tables WHERE SCHEMA_NAME(schema_id)='pim'" | ForEach-Object { "$($_.name)" })
    $missing = @($required | Where-Object { $have -notcontains $_ })
    if ($missing.Count) {
        # BUG-50's shape: the Manager and the tick both came up healthy against a database with no
        # schema, so nothing failed -- the engine simply could never do any work.
        return @{ ok = $false; detail = "schema 'pim' is missing $($missing -join ', ') -- the schema upgrade did not apply (BUG-50 shape); present: $($have -join ', ')" }
    }
    return @{ ok = $true; detail = "pim.$($required -join ', pim.') present ($($have.Count) table(s) total)" }
}

# =====================================================================================
# 2. FEATURE GATES (IMP-07) -- a disabled gate makes the engine a no-op that logs ok=True.
# =====================================================================================
Invoke-Check -Name 'feature gates enabled' -Body {
    if (-not $settings) { return @{ ok = $false; detail = 'pim.Settings could not be read' } }
    # 🪤 Get-PimAllSqlSettings returns values ALREADY DESERIALISED, so FeatureGates arrives as an
    # object, not JSON text. Stringifying it yields "System.Management.Automation.PSCustomObject"
    # and the parse then fails -- which read as "gates broken" against a tenant whose gates were
    # perfectly fine. Measured on the live master 2026-08-13. Both shapes are handled, because a
    # store written by an older path can still hold the raw string.
    $val = $settings['FeatureGates']
    if ($null -eq $val -or -not "$val".Trim()) { return @{ ok = $false; detail = 'no FeatureGates value -- every gate defaults OFF and the engine will do nothing while reporting success' } }
    $g = $null
    if ($val -is [string]) {
        try { $g = ($val | ConvertFrom-Json).gates } catch { return @{ ok = $false; detail = 'FeatureGates is not parseable JSON' } }
    } else {
        $g = $val.gates
    }
    if ($null -eq $g) { return @{ ok = $false; detail = 'FeatureGates carries no `gates` object' } }
    $want = @('scheduler.jobs', 'alerting.email')
    $off = @()
    foreach ($k in $want) { if (-not [bool]$g.$k) { $off += $k } }
    if ($off.Count) { return @{ ok = $false; detail = "gate(s) OFF: $($off -join ', ') -- run Set-PimFeatureBaseline (onboarding step 8)" } }
    return @{ ok = $true; detail = "on: $($want -join ', ')" }
}

# =====================================================================================
# 3. MAIL -- the persisted sender AND a mailbox that exists. Both halves fail silently.
# =====================================================================================
Invoke-Check -Name 'notification sender persisted' -Body {
    if (-not $settings) { return @{ ok = $false; detail = 'pim.Settings could not be read' } }
    $sender = "$($settings['MailSender'])".Trim().Trim('"')
    if (-not $sender) { return @{ ok = $false; detail = 'MailSender is not set in pim.Settings -- this environment is MAIL-MUTE: every send returns sent=$false and a minted TAP is delivered nowhere' } }
    if ($MailSenderExpected -and $sender -ne $MailSenderExpected) { return @{ ok = $false; detail = "MailSender is '$sender' but the deploy expected '$MailSenderExpected'" } }
    return @{ ok = $true; detail = $sender }
}

Invoke-Check -Name 'sender mailbox exists' -Body {
    if (-not $settings) { return @{ ok = $false; detail = 'pim.Settings could not be read' } }
    $sender = "$($settings['MailSender'])".Trim().Trim('"')
    if (-not $sender) { return @{ ok = $false; detail = 'no MailSender configured, so there is no mailbox to check' } }
    $u = Invoke-PimGraph -Path "/users/$sender`?`$select=id,userPrincipalName"
    if (-not $u.id) { return @{ ok = $false; detail = "Graph returned no user for '$sender'" } }
    return @{ ok = $true; detail = "$($u.userPrincipalName)" }
}

# =====================================================================================
# 4. THE ENGINE IDENTITY ON THE TICK JOB (IMP-08) -- deployed without it, the tick runs as a
#    permissionless managed identity and every scope dies on 403.
# =====================================================================================
Invoke-Check -Name 'tick job carries the engine identity' -Body {
    if (-not $SubscriptionId -or -not $ResourceGroup) { return @{ ok = $false; detail = 'pass -SubscriptionId and -ResourceGroup to evaluate the tick job' } }
    $arm = Get-PimRestToken -Resource arm
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$TickJobName`?api-version=2024-03-01"
    $job = Invoke-RestMethod -Headers @{ Authorization = "Bearer $arm" } -Uri $uri
    $env = @($job.properties.template.containers[0].env)
    $names = @($env | ForEach-Object { "$($_.name)" })
    if ($names -notcontains 'PIM_ClientId') {
        return @{ ok = $false; detail = "'$TickJobName' has no PIM_ClientId -- it runs as a permissionless identity and every engine scope will 403 (IMP-08). env: $($names -join ',')" }
    }
    return @{ ok = $true; detail = "PIM_ClientId present on '$TickJobName'" }
}

# =====================================================================================
# 5. CONTROL #1 -- every admin the store DESIRES exists and is enabled in the tenant.
# =====================================================================================
Invoke-Check -Name 'desired admin accounts exist and are enabled' -Body {
    if (-not $cs) { return @{ ok = $false; detail = 'store unreachable' } }
    $rows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    # A tenant with no admin definitions yet is a legitimate fresh state, not a failure.
    if (-not $rows.Count) { return @{ ok = $true; detail = 'no admin definitions in the store yet (nothing to verify)' } }
    $missing = @()
    foreach ($r in $rows) {
        $upn = "$($r.UserPrincipalName)".Trim()
        if (-not $upn) { continue }
        try {
            $u = Invoke-PimGraph -Path "/users/$upn`?`$select=id,accountEnabled"
            if (-not $u.id -or -not $u.accountEnabled) { $missing += $upn }
        } catch { $missing += $upn }
    }
    if ($missing.Count) { return @{ ok = $false; detail = "$($missing.Count)/$($rows.Count) desired admin(s) missing or disabled: $(($missing | Select-Object -First 5) -join ', ')" } }
    return @{ ok = $true; detail = "$($rows.Count)/$($rows.Count) present and enabled" }
}

# =====================================================================================
# 6. ...AND THEY CAN ACTUALLY SIGN IN. An account nobody can authenticate as is not a
#    delivered account -- the IMP-14 lesson. Checked as DELIVERABILITY of the credential
#    rather than "holds a TAP", because a TAP is consumed on first use: asserting its
#    presence would fail correctly-onboarded admins forever after.
# =====================================================================================
Invoke-Check -Name 'admins requesting a TAP can receive it' -Body {
    if (-not $cs) { return @{ ok = $false; detail = 'store unreachable' } }
    $rows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins' |
        Where-Object { "$($_.CreateTAP)" -match '(?i)^(true|1|yes)$' })
    if (-not $rows.Count) { return @{ ok = $true; detail = 'no admin requests a TAP' } }
    $noMgr = @($rows | Where-Object { -not "$($_.ManagerEmail)".Trim() })
    if ($noMgr.Count) {
        return @{ ok = $false; detail = "$($noMgr.Count)/$($rows.Count) admin(s) have CreateTAP=TRUE but NO ManagerEmail -- their TAP is minted and delivered NOWHERE, and the code is readable only at creation" }
    }
    $sender = ''
    if ($settings) { $sender = "$($settings['MailSender'])".Trim().Trim('"') }
    if (-not $sender) { return @{ ok = $false; detail = "$($rows.Count) admin(s) expect a TAP by mail, but this environment has no sender -- the credential cannot be delivered" } }
    return @{ ok = $true; detail = "$($rows.Count) admin(s) request a TAP; all have a recipient and a sender exists" }
}

# =====================================================================================
# 7. IMP-06 -- THE ENGINE MUST NOT HOLD *TENANT-WIDE* Graph Mail.Send.
#
# 🔴 This is a PRIVILEGE check wearing a readiness check's clothes, and it is here because the
# other two mail checks cannot see it. "MailSender is persisted" and "the mailbox exists" can both
# pass on an environment whose engine SPN can mail AS ANYONE IN THE TENANT.
#
# 🔑 Why absence is the correct state, measured both directions ~60 minutes apart during IMP-06:
#     WITH the tenant-wide consent    -- in-scope send ACCEPTED, out-of-scope send ACCEPTED
#     WITHOUT the tenant-wide consent -- in-scope send ACCEPTED, out-of-scope send DENIED
# Exchange RBAC does not RESTRICT a tenant-wide Graph consent -- it grants scoped access in its own
# right, and a tenant-wide consent alongside it keeps winning. So the scoped grant is only actually
# scoped while this permission is ABSENT.
#
# ⚠️ ADVISORY (Required=$false) ON PURPOSE, and this is a decision the operator should revisit.
# Required checks BLOCK a deploy, and the live state of the estate is not known here: promoting
# this to required without first measuring ~30 tenants could block deployments on a finding nobody
# has confirmed yet. It therefore REPORTS loudly and gates nothing. §33 → MSP-5 carries the
# promote-to-required decision.
# =====================================================================================
Invoke-Check -Name 'engine holds NO tenant-wide Graph Mail.Send' -Required $false -Body {
    $appId = if ($EngineClientId) { $EngineClientId } else { "$($global:PIM_ClientId)" }
    # 🪤 "Could not tell" is NOT "fine" -- the probe's own contract. An unknown engine identity
    # makes this unevaluable, which is a failed check with a reason, never a quiet pass.
    if (-not "$appId".Trim()) { return @{ ok = $false; detail = 'engine client id unknown -- cannot tell whether a tenant-wide send right is held (this is "did not look", not "it is fine")' } }
    $sp = Invoke-PimGraph -Path "/servicePrincipals(appId='$appId')?`$select=id,displayName"
    if (-not $sp.id) { return @{ ok = $false; detail = "no service principal found for engine appId '$appId'" } }
    # 🔒 Resolve the role BY NAME from Graph's own app-role list rather than hard-coding its GUID.
    # A wrong hard-coded id matches nothing and the check then passes on every tenant forever --
    # a guard that cannot fail, which this project has now shipped twice and caught twice.
    $graphSp = Invoke-PimGraph -Path "/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"
    $role = @(@($graphSp.appRoles) | Where-Object { "$($_.value)" -eq 'Mail.Send' })
    if (-not $role.Count) { return @{ ok = $false; detail = 'could not resolve the Graph Mail.Send app role -- unable to evaluate' } }
    $roleId = "$($role[0].id)"
    $asg = @((Invoke-PimGraph -Path "/servicePrincipals/$($sp.id)/appRoleAssignments").value)
    $hit = @($asg | Where-Object { "$($_.appRoleId)" -eq $roleId -and "$($_.resourceId)" -eq "$($graphSp.id)" })
    if ($hit.Count) {
        return @{ ok = $false; detail = "the engine SPN holds TENANT-WIDE Graph Mail.Send -- the per-mailbox Exchange RBAC scope is defeated by it (measured: with this consent an out-of-scope send is ACCEPTED). Revoke it; the scoped grant is what should carry sending." }
    }
    return @{ ok = $true; detail = 'no tenant-wide Graph Mail.Send on the engine SPN (sending is carried by the per-mailbox Exchange RBAC scope)' }
}

# =====================================================================================
$failedRequired = @($checks | Where-Object { $_.required -and -not $_.ok })
$result = @{ ok = ($failedRequired.Count -eq 0); checks = @($checks.ToArray()) }

foreach ($c in $checks) {
    $mark = if ($c.ok) { 'ok  ' } else { 'FAIL' }
    $col  = if ($c.ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0}  {1}{2}" -f $mark, $c.name, $(if ($c.detail) { " -- $($c.detail)" } else { '' })) -ForegroundColor $col
}
Write-Host ("[readiness] PIM4EntraPS: {0} ({1}/{2} checks passed)" -f `
    $(if ($result.ok) { 'READY' } else { 'NOT READY' }), @($checks | Where-Object { $_.ok }).Count, $checks.Count) `
    -ForegroundColor $(if ($result.ok) { 'Green' } else { 'Red' })

$result
