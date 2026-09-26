# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
# 🪤 PROBE EVERY FUNCTION THIS FILE NEEDS FROM THAT LIBRARY, NOT JUST THE FIRST ONE.
# The guard used to ask only for Get-PimUtcStamp. In a host where that name was already defined by
# some other load (PIM-Functions.psm1, an earlier dot-source), the guard short-circuited and
# PIM-DateSafe.ps1 was never sourced -- so 71.23's Get-PimAdminAutoDisableDate was missing and
# Test-PimAdminOffboarded threw CommandNotFoundException at runtime, in a host the offline suites
# actually use. A one-name probe for a multi-function library is a fail-OPEN.
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) -or
    -not (Get-Command Get-PimAdminAutoDisableDate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
<#
  PIM4EntraPS -- NEW engine scope providers (REST + SQL). Each provider plugs into
  PIM-EngineCore.ps1. Add a scope by registering a provider here.

  Implemented now:
    * Admins  -- ensure the admin accounts (Account-Definitions-Admins) exist + enabled
                 in Entra, fully over Graph REST.

  Contract for the remaining scopes (EntraRoles, AzRes, GroupsAssignment, GroupsPolicies,
  AdministrativeUnits, Workloads) is the same hashtable shape; they are added
  incrementally (their PIM REST apply workflows are larger). Until a provider is
  registered, Invoke-PimEngineScope returns "no provider" for that scope (handled
  gracefully by the scheduler).
#>

Set-StrictMode -Off

function Get-PimRowProp {
    param([object]$Row, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
    }
    return ''
}

# ===========================================================================
# ADMIN LIFECYCLE -- v1 parity (operator 2026-09-12: "fix 1-14. all are critical for pim v2 go
# live" / "we cannot leave customers on pim v1 in a worse situation going to pim v2").
# Private helpers for the Admins, AdminTap, AdminOffboarding and GroupRetirement providers.
# PURE unless the name says otherwise; time is injected so each decision is testable offline.
# v1 references are engine/_shared/PIM-Functions.psm1 line numbers as of 2026-09-12.
# ===========================================================================

# Date EXPRESSIONS (Now, FirstWorkdayNextMonth-3d@08:00, 2026-10-01@08:00) resolve through the one
# shared resolver. Neither the REST engine entry point nor the scheduler tick loads it, so without
# this every ProvisionDate / AutoDisableDate / TAPStartDate that is not a plain ISO stamp was
# unreadable to v2 -- and an unreadable AutoDisableDate never disables.
if (-not (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
    $__pimDateExprLib = Join-Path $PSScriptRoot 'PIM-DateExpression.ps1'
    if (Test-Path -LiteralPath $__pimDateExprLib) { . $__pimDateExprLib }
}
# TAP requests conformed to the tenant's TAP policy -- shared by AdminTap and the queued tap-reset.
if (-not (Get-Command Invoke-PimTapCreate -ErrorAction SilentlyContinue)) {
    $__pimTapPolicyLib = Join-Path $PSScriptRoot 'PIM-TapPolicy.ps1'
    if (Test-Path -LiteralPath $__pimTapPolicyLib) { . $__pimTapPolicyLib }
}

function Get-PimAdminLifecycleSetting {
    # One reader for the lifecycle knobs: $global:PIM_<Name> -> $env:PIM_<Name> -> pim.Settings
    # (hydrated into $global:PIM_NamingConventions by Import-PimSettingsFromStore) -> default.
    # v1 read these from a *.custom.ps1 FILE. v2 has no files, so an opt-in a v1 customer relied on
    # must be settable where v2 keeps its configuration, or it silently stops applying on migration.
    param([Parameter(Mandatory)][string]$Name, $Default = $null)
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $g -and "$g".Trim() -ne '') { return $g }
    $e = [Environment]::GetEnvironmentVariable("PIM_$Name", 'Process')
    if ($null -ne $e -and "$e".Trim() -ne '') { return $e }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        $s = $global:PIM_NamingConventions[$Name]
        if ($null -ne $s -and "$s".Trim() -ne '') { return $s }
    }
    return $Default
}

function ConvertTo-PimAdminLifecycleUtc {
    # PURE. A lifecycle cell -> @{ set; parsed; utc }. "set but not parsed" is its own answer:
    # callers decide what an unreadable value means for them (v1 did not treat them alike).
    param([AllowNull()][object]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return [pscustomobject]@{ set = $false; parsed = $false; utc = $null } }
    $d = $null
    if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) {
        try { $d = Resolve-PimDateExpression -Expression $v } catch { $d = $null }
    }
    if ($null -eq $d -and (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { $d = Get-PimUtcStamp $v }
    if ($null -ne $d) { try { $d = ([datetime]$d).ToUniversalTime() } catch { $d = $null } }
    return [pscustomobject]@{ set = $true; parsed = ($null -ne $d); utc = $d }
}

function Get-PimAdminRowKey {
    # PURE. The Admins diff key for a DESIRED row or a LIVE user -- the UPN local part (BUG-13).
    # One definition, so the providers that key on an admin cannot drift apart.
    param([object]$Row)
    if ($null -eq $Row) { return '' }
    $upn = Get-PimRowProp -Row $Row -Names @('userPrincipalName','UserPrincipalName','UPN','upn')
    if (-not $upn) { $upn = Get-PimRowProp -Row $Row -Names @('UserName','Username') }
    if (Get-Command Get-PimUpnLocalPart -ErrorAction SilentlyContinue) { return (Get-PimUpnLocalPart -Upn "$upn") }
    $s = "$upn".Trim(); $i = $s.IndexOf('@')
    if ($i -ge 0) { $s = $s.Substring(0, $i) }
    return $s.ToLowerInvariant()
}

function Test-PimAdminValueTrue {
    # PURE. accountEnabled from Graph is a bool; from a fixture or a JSON round-trip it can be a
    # string, and [bool]'False' is $true. Read it as text.
    param([AllowNull()][object]$Value)
    if ($Value -is [bool]) { return $Value }
    return ("$Value".Trim() -match '(?i)^(true|1|yes)$')
}

function Test-PimAdminProvisionDue {
    # #8 PURE. v1 created a row only once its ProvisionDate was due (v1 5568-5585). Blank = now.
    # An UNPARSEABLE value is treated as now with a warning, exactly as v1: "create rather than
    # silently never-create" -- the Manager's PIM-SCHED-001 catches a bad expression before commit.
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $raw = Get-PimRowProp -Row $Row -Names @('ProvisionDate','ProvisionUtc')
    $p = ConvertTo-PimAdminLifecycleUtc -Value $raw
    if (-not $p.set)    { return [pscustomobject]@{ due = $true; provisionUtc = $null; reason = 'no ProvisionDate' } }
    if (-not $p.parsed) { return [pscustomobject]@{ due = $true; provisionUtc = $null; reason = "ProvisionDate '$raw' is not a date expression -- treated as now (v1)" } }
    # 60 s of tolerance: 'Now' resolves a moment AFTER the caller captured its clock.
    if ($p.utc -gt $NowUtc.ToUniversalTime().AddSeconds(60)) {
        return [pscustomobject]@{ due = $false; provisionUtc = $p.utc; reason = ("scheduled -- provisions at {0:yyyy-MM-dd HH:mm} UTC" -f $p.utc) }
    }
    return [pscustomobject]@{ due = $true; provisionUtc = $p.utc; reason = 'ProvisionDate reached' }
}

function Get-PimAdminStatusDecision {
    # #1 PURE. WHAT STATE SHOULD THIS ADMIN ACCOUNT BE IN? v1 5587-5619 + 12366-12408.
    #   AccountStatus=Revoked   -> disabled, sign-in sessions revoked, never provisioned
    #   AccountStatus=Disabled  -> disabled, never provisioned
    #   AutoDisableDate passed  -> disabled, never provisioned (the auto-disable sweep does the
    #                              rest). 71.23: the column used to be called OffboardDate; the
    #                              old name is still READ (Get-PimAdminAutoDisableDate), and a row
    #                              carrying both names with DIFFERENT values is refused, not guessed.
    #   AccountStatus=Enabled   -> enabled; the ONLY value that may RE-enable a disabled account
    #   AccountStatus blank     -> created enabled, but a disabled account is left disabled
    #   anything else           -> v1 warned and skipped the row: nothing is changed or created
    # 🔴 THE DEFECT THIS REPLACES: Equal compared accountEnabled only and ApplyUpdate PATCHed
    # accountEnabled=$true, on a job that runs every 5 minutes -- so a Disabled or Revoked admin was
    # re-enabled within minutes of being switched off.
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = (Get-PimRowProp -Row $Row -Names @('AccountStatus')).Trim()
    $add = Get-PimAdminAutoDisableDate -Row $Row
    $od = ConvertTo-PimAdminLifecycleUtc -Value $add.value
    # A CONFLICT (both column names, different dates) never disables: value is '' above, so
    # $offDue is false and the row is left exactly as it is. The refusal is reported by the
    # sweep and by the validator -- silently picking one of the two dates is the one outcome
    # that must not happen.
    $offDue = ($od.parsed -and $od.utc -le $NowUtc.ToUniversalTime())
    $mk = {
        param($status, $enabled, $disable, $may, $sessions, $blocks, $reason, $statusDriven)
        [pscustomobject]@{ status = $status; desiredEnabled = $enabled; disable = [bool]$disable; mayEnable = [bool]$may
                           revokeSessions = [bool]$sessions; blocksCreate = [bool]$blocks; statusDriven = [bool]$statusDriven; reason = $reason }
    }
    if ($st -ieq 'Revoked')  { return (& $mk 'Revoked'  $false $true $false $true  $true 'AccountStatus=Revoked'  $true) }
    if ($st -ieq 'Disabled') { return (& $mk 'Disabled' $false $true $false $false $true 'AccountStatus=Disabled' $true) }
    if ($offDue) { return (& $mk 'AutoDisabled' $false $true $false $false $true ("AutoDisableDate {0:yyyy-MM-dd HH:mm} UTC reached" -f $od.utc) $false) }
    if (-not $st)            { return (& $mk ''        $true $false $false $false $false 'AccountStatus not set' $false) }
    if ($st -ieq 'Enabled')  { return (& $mk 'Enabled' $true $false $true  $false $false 'AccountStatus=Enabled' $false) }
    return (& $mk $st $null $false $false $false $true "unknown AccountStatus '$st' (expected Enabled / Disabled / Revoked) -- the account is left as it is" $false)
}

function Get-PimAdminAttributePlan {
    # #11 PURE. Which directory attributes differ? Returns an ordered hashtable of ONLY the fields
    # to PATCH. v1 set them on create (5698-5736) and on every update (5654-5662). Two rules stop
    # the engine from fighting the tenant:
    #   * a BLANK desired value is not managed -- the row said nothing about it;
    #   * a live object that does not CARRY a property was not observed, so it is not compared
    #     (Graph returns every $select-ed property, null included -- absence means "not read").
    param([Parameter(Mandatory)][object]$Desired, [Parameter(Mandatory)][object]$Live)
    $liveProp = {
        param($name)
        if ($Live -is [System.Collections.IDictionary]) { if ($Live.Contains($name)) { return @{ has = $true; v = $Live[$name] } }; return @{ has = $false } }
        $pp = $Live.PSObject.Properties[$name]
        if ($pp) { return @{ has = $true; v = $pp.Value } }
        return @{ has = $false }
    }
    $want = [ordered]@{
        givenName     = (Get-PimRowProp -Row $Desired -Names @('FirstName','GivenName','givenName'))
        surname       = (Get-PimRowProp -Row $Desired -Names @('LastName','Surname','surname'))
        displayName   = (Get-PimRowProp -Row $Desired -Names @('DisplayName','displayName'))
        jobTitle      = (Get-PimRowProp -Row $Desired -Names @('JobTitle','jobTitle'))
        usageLocation = (Get-PimRowProp -Row $Desired -Names @('UsageLocation','usageLocation'))
        companyName   = (Get-PimRowProp -Row $Desired -Names @('Company','CompanyName','companyName'))
    }
    # v1 wrote JobTitle = DisplayName for an Entra ID admin ($Description = $DisplayName, 5643).
    if (-not "$($want.jobTitle)".Trim()) { $want.jobTitle = $want.displayName }
    $plan = [ordered]@{}
    foreach ($k in @($want.Keys)) {
        $w = "$($want[$k])".Trim()
        if (-not $w) { continue }
        $lp = & $liveProp $k
        if (-not $lp.has) { continue }
        $have = "$($lp.v)".Trim()
        $differs = if ($k -eq 'usageLocation') { $w -ne $have } else { $w -cne $have }
        if ($differs) { $plan[$k] = $w }
    }
    $pp = & $liveProp 'passwordPolicies'
    if ($pp.has) {
        $cur = "$($pp.v)".Trim()
        if ($cur -notmatch '(?i)(^|[,\s])DisablePasswordExpiration($|[,\s])') {
            # Keep whatever else the tenant set (e.g. DisableStrongPassword) -- add, never replace.
            $plan['passwordPolicies'] = $(if ($cur) { "$cur, DisablePasswordExpiration" } else { 'DisablePasswordExpiration' })
        }
    }
    return $plan
}

function New-PimAdminInitialPassword {
    # #11. A strong random initial password that NOBODY is ever shown. v1 wrote the plaintext to
    # output/admin-passwords-<date>.txt (v1 5779); v2 stores nothing and logs nothing, because the
    # v2 onboarding route is the Temporary Access Pass (AdminTap, or the Manager's queued TAP reset)
    # and a password nobody knows cannot leak. forceChangePasswordNextSignIn stays on.
    param([int]$Length = 32)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^&*-_=+?')
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $pick = { param([string]$set) $b = New-Object byte[] 4; $rng.GetBytes($b); $set[[int]([BitConverter]::ToUInt32($b, 0) % [uint32]$set.Length)] }
        $chars = New-Object System.Collections.Generic.List[char]
        foreach ($s in $sets) { $chars.Add([char](& $pick $s)) }
        $all = -join $sets
        while ($chars.Count -lt $Length) { $chars.Add([char](& $pick $all)) }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $b = New-Object byte[] 4; $rng.GetBytes($b)
            $j = [int]([BitConverter]::ToUInt32($b, 0) % [uint32]($i + 1))
            $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
        }
        return (-join $chars.ToArray())
    } finally { $rng.Dispose() }
}

function Write-PimAdminLifecycleAudit {
    # Best-effort audit for lifecycle writes. Never throws: the directory change already happened.
    param([Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)][string]$Target, [object]$After = $null, [string]$Result = 'ok')
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action $Action -Target $Target -After $After -Result $Result | Out-Null
            return
        }
        $cs = Get-PimAdminLifecycleStoreCs
        if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            Write-PimSqlAuditEvent -ConnectionString $cs -Actor 'engine' -ActorSource 'engine' -Action $Action -Target $Target -After $After -Result $Result
        }
    } catch { Write-Warning ("  [audit] {0} for {1} was NOT recorded: {2}" -f $Action, $Target, $_.Exception.Message) }
}

function Get-PimAdminLifecycleStoreCs {
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { return (Get-PimSqlSettingsConnectionString) } catch { } }
    return $null
}

function ConvertTo-PimAdminLifecycleMap {
    # PURE. A stored JSON object / PSCustomObject / hashtable -> hashtable (one level, values too).
    param([AllowNull()][object]$Value)
    $h = @{}
    if ($null -eq $Value) { return $h }
    $o = $Value
    if ($o -is [string]) { if (-not $o.Trim()) { return $h }; $o = $o | ConvertFrom-Json }
    if ($o -is [System.Collections.IDictionary]) { foreach ($k in @($o.Keys)) { $h["$k"] = $o[$k] } }
    else { foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    return $h
}

function Get-PimAdminLifecycleStore {
    # SQL-only state for lifecycle steps that must happen ONCE (TAP issuance, offboarding progress).
    # Returns @{ ok; map; reason }. ok=$false = "no persistent store in this process", and every
    # caller FAILS CLOSED on it: a TAP that cannot be recorded as issued would be issued again by the
    # next process, and an offboarding whose revoke time is not kept cannot repeat its notice safely.
    param([Parameter(Mandatory)][string]$Name)
    $raw = $null; $ok = $false; $why = ''
    try {
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $raw = Get-PimSetting -Name $Name; $ok = $true }
        else {
            $cs = Get-PimAdminLifecycleStoreCs
            if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { $raw = Get-PimSqlSetting -ConnectionString $cs -Name $Name; $ok = $true }
            else { $why = 'no SQL settings store is wired in this process' }
        }
    } catch { $ok = $false; $why = "reading pim.Settings['$Name'] failed: $($_.Exception.Message)" }
    $map = @{}
    if ($ok) {
        try {
            $top = ConvertTo-PimAdminLifecycleMap -Value $raw
            foreach ($k in @($top.Keys)) { $map["$k".ToLowerInvariant()] = (ConvertTo-PimAdminLifecycleMap -Value $top[$k]) }
        } catch { return [pscustomobject]@{ ok = $false; map = @{}; reason = "pim.Settings['$Name'] is not a readable JSON object: $($_.Exception.Message)" } }
    }
    return [pscustomobject]@{ ok = $ok; map = $map; reason = $why }
}

function Save-PimAdminLifecycleStore {
    # Returns $true only when the write reached the store.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Map)
    try {
        if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name $Name -Value $Map | Out-Null; return $true }
        $cs = Get-PimAdminLifecycleStoreCs
        if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { Set-PimSqlSetting -ConnectionString $cs -Name $Name -Value $Map; return $true }
        Write-Warning "  [lifecycle] pim.Settings['$Name'] NOT saved -- no SQL settings store is wired in this process."
    } catch { Write-Warning "  [lifecycle] pim.Settings['$Name'] NOT saved: $($_.Exception.Message)" }
    return $false
}

function Test-PimAdminStatusChangeAuthorized {
    # #1 -- the MSP kill-switch code check, ported from v1 Test-PimAccountStatusChangeAuthorized
    # (12265-12364) + its call site (12399-12403). It applies to v2 too: v2 has the MSP variant
    # ($global:PIM_ConfigVariant='msp', set by Set-PimScenarioContext), central rows are downlinked
    # into a customer's store (PIM-Downlink.ps1) and a signed central-kill manifest emits
    # AccountStatus + StatusChangeCode rows (PIM-Substrate.ps1). So in the MSP variant a Disabled /
    # Revoked row is honoured ONLY when its StatusChangeCode equals the customer's Key Vault secret
    # pim-status-<upn with @ and . as ->. Default DENY. Outside the MSP variant the customer owns the
    # rows directly and no code is needed (v1: "local CSV = customer directly in control").
    # A refusal is an audit event -- v1 wrote a CSV file; v2 writes no files.
    param([Parameter(Mandatory)][string]$UserPrincipalName, [AllowEmptyString()][string]$ProvidedCode, [scriptblock]$SecretReader)
    $variant = "$(Get-PimAdminLifecycleSetting -Name 'ConfigVariant' -Default '')".Trim()
    if ($variant -ine 'msp') { return [pscustomobject]@{ authorized = $true; applies = $false; reason = 'not the MSP variant' } }
    $deny = {
        param($why)
        Write-Warning "  [SECURITY] central status change for $UserPrincipalName REFUSED: $why"
        Write-PimAdminLifecycleAudit -Action 'account.status.change.denied' -Target $UserPrincipalName -After @{ reason = $why; variant = 'msp' } -Result 'denied'
        [pscustomobject]@{ authorized = $false; applies = $true; reason = $why }
    }
    $vault = "$(Get-PimAdminLifecycleSetting -Name 'StatusChange_KeyVaultName' -Default '')".Trim()
    if (-not $vault) { return (& $deny 'no StatusChange_KeyVaultName is configured') }
    if (-not "$ProvidedCode".Trim()) { return (& $deny 'the row carries no StatusChangeCode') }
    $secretName = 'pim-status-' + ($UserPrincipalName.ToLowerInvariant() -replace '[@.]', '-')
    $reader = $SecretReader
    if (-not $reader -and ($global:PIM_StatusChangeSecretReader -is [scriptblock])) { $reader = $global:PIM_StatusChangeSecretReader }
    if (-not $reader) {
        $reader = {
            param($VaultName, $Name)
            $tok = Get-PimRestToken -Resource 'https://vault.azure.net'
            $uri = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $VaultName, $Name
            (Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop).value
        }
    }
    $expected = ''
    try { $expected = "$(& $reader $vault $secretName)" } catch { return (& $deny "Key Vault secret '$secretName' could not be read (the CISO has not opted in, or the engine cannot reach the vault)") }
    if (-not $expected.Trim()) { return (& $deny "Key Vault secret '$secretName' is empty") }
    # Constant-time-ish compare, as v1: length first, then OR of every XOR.
    if ($expected.Length -ne $ProvidedCode.Length) { return (& $deny 'StatusChangeCode mismatch') }
    $mismatch = 0
    for ($i = 0; $i -lt $expected.Length; $i++) { $mismatch = $mismatch -bor ([int][char]$expected[$i] -bxor [int][char]$ProvidedCode[$i]) }
    if ($mismatch -ne 0) { return (& $deny 'StatusChangeCode mismatch') }
    return [pscustomobject]@{ authorized = $true; applies = $true; reason = 'StatusChangeCode verified against Key Vault' }
}

function Update-PimAdminsDisableDecision {
    # #1. Decide the EXPLICIT disables of one Admins pass ONCE, before any handler runs, through the
    # account-disable circuit breaker (PIM-DisableGuard.ps1). Handlers only READ this decision.
    # 🔒 Why here and not in the core: the core's breaker gates the REMOVE bucket, and an explicit
    # AccountStatus disable is an UPDATE of a desired row -- it would bypass the breaker entirely.
    param([Parameter(Mandatory)][hashtable]$Context, [object[]]$Live = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $all = @($Context['adminsDesiredAll'] | Where-Object { $null -ne $_ })
    $liveByKey = @{}
    foreach ($l in @($Live)) { if ($null -ne $l) { $k = Get-PimAdminRowKey -Row $l; if ($k) { $liveByKey[$k] = $l } } }
    $bg = @(); if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) { $bg = @(Get-PimBreakGlassIdentifiers) }
    $cand = @{}; $unauth = @{}; $bgHit = New-Object System.Collections.Generic.List[string]; $leftOff = New-Object System.Collections.Generic.List[string]
    foreach ($d in $all) {
        if (-not (Test-PimAdminProvisionDue -Row $d -NowUtc $NowUtc).due) { continue }
        $k = Get-PimAdminRowKey -Row $d
        if (-not $k -or -not $liveByKey.ContainsKey($k)) { continue }
        $l = $liveByKey[$k]
        $dec = Get-PimAdminStatusDecision -Row $d -NowUtc $NowUtc
        $on = Test-PimAdminValueTrue $l.accountEnabled
        if ($dec.disable -and $on) {
            if ($bg.Count -gt 0 -and (Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue) -and (Test-PimRowIsBreakGlass -Row $l -Identifiers $bg)) { [void]$bgHit.Add($k); continue }
            # 68.6 row 35: a CENTRAL admin's status is decided by the MSP master and arrived in its signed
            # baseline -- that signature is the authorisation. The slave-side StatusChangeCode check
            # guards the slave's OWN rows only.
            if ($dec.statusDriven -and -not ((Get-Command Test-PimAdminRowIsCentral -ErrorAction SilentlyContinue) -and (Test-PimAdminRowIsCentral -Row $d))) {
                $auth = Test-PimAdminStatusChangeAuthorized -UserPrincipalName "$($l.userPrincipalName)" -ProvidedCode (Get-PimRowProp -Row $d -Names @('StatusChangeCode'))
                if (-not $auth.authorized) { $unauth[$k] = $auth.reason; continue }
            }
            $cand[$k] = $dec.reason
        } elseif ($dec.desiredEnabled -eq $true -and -not $on -and -not $dec.mayEnable) {
            [void]$leftOff.Add("$($l.userPrincipalName)")
        }
    }
    $decision = $null
    if ($cand.Count -gt 0) {
        $resolved = $null
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey('Account-Definitions-Admins')) { $resolved = [bool]$global:PIM_DesiredResolved['Account-Definitions-Admins'] }
        if (Get-Command Test-PimExplicitDisablePassAllowed -ErrorAction SilentlyContinue) {
            $decision = Test-PimExplicitDisablePassAllowed -ToDisable $cand.Count -Scanned @($Live).Count -Desired $all -DesiredResolved $resolved
        } else {
            # FAIL CLOSED: no breaker loaded means no disable, never an unguarded one.
            $decision = [pscustomobject]@{ allowed = $false; abort = $true; tripped = 'guard-not-loaded'; reason = 'PIM-DisableGuard.ps1 is not loaded in this process'; toDisable = $cand.Count; scanned = @($Live).Count }
        }
        if (-not $decision.allowed) {
            if (Get-Command Write-PimDisableAbortAlert -ErrorAction SilentlyContinue) { Write-PimDisableAbortAlert -Scope 'Admins (AccountStatus / AutoDisableDate)' -Decision $decision }
            else { Write-Host ("[engine] Admins: explicit disables ABORTED [{0}] -- {1}" -f $decision.tripped, $decision.reason) -ForegroundColor Red }
        } else {
            Write-Host ("    [admins] {0} account(s) to DISABLE as their row says: {1}" -f $cand.Count, (@($cand.Keys) -join ', ')) -ForegroundColor Yellow
        }
    }
    if ($bgHit.Count) { Write-Host ("    [admins] BREAK-GLASS never disabled, whatever its row says: {0}" -f ($bgHit -join ', ')) -ForegroundColor Yellow }
    if ($leftOff.Count) { Write-Host ("    [admins] {0} account(s) are DISABLED in the tenant and their AccountStatus is not explicitly 'Enabled' -- left disabled (set AccountStatus=Enabled to re-enable): {1}" -f $leftOff.Count, ($leftOff -join ', ')) -ForegroundColor DarkYellow }
    $Context['adminsDisable'] = [pscustomobject]@{ candidates = $cand; decision = $decision; unauthorized = $unauth; breakGlass = $bgHit.ToArray() }
    return $Context['adminsDisable']
}

function Get-PimScheduledAdminCreationReport {
    # #8 -- what the 'scheduled-creation' job reports, READ from SQL. It creates nothing: the
    # Admins provider (job delta-admins, 5 min) creates a row as soon as its ProvisionDate is due,
    # and AdminTap issues the TAP inside its lead window. The job used to read
    # $global:PIM_ScheduledAdminRows, which nothing ever set, and reported ran=true over nothing.
    # Returns @{ ok; reason; pending; next; tapDeferred }.
    param([datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ok = $false; reason = 'the engine core (Get-PimDesiredRows) is not loaded in this process'; pending = @(); next = $null; tapDeferred = @() }
    }
    $rows = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
    if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey('Account-Definitions-Admins') -and -not $global:PIM_DesiredResolved['Account-Definitions-Admins']) {
        return [pscustomobject]@{ ok = $false; reason = 'the admin rows could not be read from the desired store'; pending = @(); next = $null; tapDeferred = @() }
    }
    $pending = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $pd = Test-PimAdminProvisionDue -Row $r -NowUtc $NowUtc
        if (-not $pd.due) { [void]$pending.Add([pscustomobject]@{ upn = (Get-PimRowProp -Row $r -Names @('UserPrincipalName','UserName')); provisionUtc = $pd.provisionUtc }) }
    }
    $sorted = @($pending.ToArray() | Sort-Object provisionUtc)
    $tap = Select-PimAdminTapCandidates -Rows $rows -NowUtc $NowUtc
    $tapDeferred = @($tap.deferred | Where-Object { "$($_.reason)" -match '^TAP DEFERRED' })
    return [pscustomobject]@{ ok = $true; reason = ''; pending = $sorted; next = $(if ($sorted.Count) { $sorted[0] } else { $null }); tapDeferred = $tapDeferred }
}

function New-PimAdminsProvider {
    @{
        scope  = 'Admins'
        entity = 'Account-Definitions-Admins'
        order  = 30
        # ACCOUNT-DISABLE scope: its GetLive is the WHOLE tenant user population, so a
        # wrong/empty desired set could once have disabled everything it scans (incident
        # 2026-06-15). isAccountDisable routes its removals through PIM-DisableGuard
        # (feature opt-in + positively-resolved desired set + mass-disable circuit breaker)
        # in PIM-EngineCore before any disable runs.
        # 🔴 71.22 -- and its ApplyRemove now disables NOTHING at all: an account absent from
        # the desired set is REPORTED, never acted on. The disable paths that remain are the
        # row's own AccountStatus / AutoDisableDate (ApplyUpdate) and the auto-disable sweep.
        isAccountDisable = $true
        GetDesired = {
            param($ctx)
            # #8: a row whose ProvisionDate is still in the future is not created yet (v1 5568-5585).
            # The FULL set is kept for the circuit breaker's G1 input -- a pass of explicit disables
            # must be judged against the positively-resolved desired set, not a filtered view of it.
            $now = [datetime]::UtcNow
            $all = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
            $ctx['adminsDesiredAll'] = $all
            $deferred = @{}
            $adOnly = @{}
            $keep = New-Object System.Collections.Generic.List[object]
            foreach ($r in $all) {
                if ($null -eq $r) { continue }
                # AD-only admins do not exist in Entra: not created, updated or disabled here (hybrid-ad-apply owns them).
                if (Test-PimAdminIsAdOnly -Row $r) { $ak = Get-PimAdminRowKey -Row $r; if ($ak) { $adOnly[$ak] = $true }; continue }
                $pd = Test-PimAdminProvisionDue -Row $r -NowUtc $now
                if ($pd.due) { [void]$keep.Add($r); continue }
                $k = Get-PimAdminRowKey -Row $r
                if ($k) { $deferred[$k] = $pd }
                Write-Host ("    [admins] SCHEDULED {0}: {1}" -f (Get-PimRowProp -Row $r -Names @('UserPrincipalName','UserName')), $pd.reason) -ForegroundColor DarkCyan
            }
            $ctx['adminsDeferred'] = $deferred
            $ctx['adminsAdOnly'] = $adOnly
            $keep.ToArray()
        }
        GetLive    = {
            param($ctx)
            # BUG-12 (fixed 2026-08-06). This was `/users` with NO filter -- the WHOLE
            # tenant population -- compared against the ADMIN definitions, so every
            # ordinary user was a removal candidate. That is the mechanism of the
            # 2026-06-15 incident (53 users disabled): measured here on 2026-08-06 it
            # returned 79 users, only 13 of them admin accounts.
            #
            # The live set is now restricted to ADMIN ACCOUNTS by the configured naming
            # convention (s17), server-side, so desired and live are the same population
            # and an ordinary user CANNOT be classified as a removal by construction.
            #
            # FAILS CLOSED: with no prefix configured we throw rather than scanning
            # everything. An unfiltered fallback is precisely the defect being fixed --
            # do not "helpfully" restore one (the legacy Get-PimAdminsFiltered has such a
            # fallback; it must not be copied here).
            # Resolve the prefixes from the THREE legitimate sources, in order. These are
            # all the same configured value seen from different processes -- none of them
            # is a wildcard, so trying the next one is not a weakening. The REST engine
            # does not hydrate naming conventions the way the Manager does, so without
            # this the scope could not run at all.
            # UNION them, do not stop at the first non-empty source. Each source declares
            # "what an admin account looks like"; taking only the first found silently
            # DROPS admin shapes the others know about. Observed exactly that: the store
            # yielded only 'admin-', so 'x-Admin'/'g-Admin' accounts from the locked
            # config fell out of the live set -- they would then never be reconciled
            # (and, under -Prune, never removed either). Under-scoping is safer than
            # over-scoping but it is still wrong; the union is the correct semantic, and
            # it still cannot admit an ordinary user.
            $prefixes = @()
            if (Get-Command Get-PimAdminAccountPrefixes -ErrorAction SilentlyContinue) {
                $acc = New-Object System.Collections.Generic.List[string]
                $merge = { param($list) foreach ($x in @($list)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and -not $acc.Contains($s)) { [void]$acc.Add($s) } } }
                & $merge (Get-PimAdminAccountPrefixes)                                       # 1. already in-process
                if (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue) {
                    try { [void](Import-PimSettingsFromStore) } catch { }                    # 2. persisted pim.Settings
                    & $merge (Get-PimAdminAccountPrefixes)
                }
                try {                                                                        # 3. the shipped defaults (in code)
                    # 2026-09-20: was a dot-source of config\PIM4EntraPS.NamingConventions.locked.ps1 --
                    # a duplicate of the same defaults, now deleted. No file, and no clobbering of the
                    # live map: the shipped set is read directly and merged.
                    if (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue) {
                        $shipped = Get-PimShippedNamingConventions
                        if ($shipped -is [System.Collections.IDictionary] -and $shipped.Contains('AdminAccountPatterns')) {
                            & $merge @($shipped['AdminAccountPatterns'])
                        }
                    }
                } catch { }
                $prefixes = $acc.ToArray()
            }
            if ($prefixes.Count -eq 0) {
                throw ("Admins scope: no admin naming prefix is configured (`$global:PIM_NamingConventions.AdminAccountPatterns), " +
                       "so the live set cannot be limited to admin accounts. REFUSING to scan the whole user population -- " +
                       "that is what disabled 53 production users on 2026-06-15 (REQUIREMENTS s33 BUG-12).")
            }
            # Server-side filter, one startswith per configured prefix, unioned + deduped
            # by id. Also keeps the LEAN-context promise: never bulk-list a big tenant.
            $seen = @{}
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($p in $prefixes) {
                $esc = "$p".Replace("'", "''")
                # #11: the attributes the provider reconciles are read here, or drift is invisible.
                $q = "/users?`$select=id,userPrincipalName,displayName,accountEnabled,givenName,surname,jobTitle,usageLocation,companyName,passwordPolicies,onPremisesSyncEnabled&`$filter=startswith(userPrincipalName,'$esc')"
                foreach ($u in @(Invoke-PimGraph -Path $q -All)) {
                    if ($null -eq $u) { continue }
                    $k = "$($u.id)"
                    if ($k -and -not $seen.ContainsKey($k)) { $seen[$k] = $true; [void]$rows.Add($u) }
                }
            }
            # 🔴 AN ADMIN THIS TENANT ALREADY HAS A ROW FOR IS PART OF THE POPULATION, WHATEVER IT IS
            # CALLED (operator, 2026-09-22: "you can not block admins due to different name pattern").
            # The prefix filter above answers "which accounts in this tenant are admin accounts?" and
            # it must stay (BUG-12: without it the whole user population is a removal candidate). But
            # an account NAMED BY A DESIRED ROW is not a discovery question at all -- PIM is already
            # managing it, by its own store. On a managed tenant those rows arrive from the master
            # (Owner=MSP) and carry the MASTER's naming, so a slave whose prefixes differ could never
            # see them: the diff said "not present", every tick re-created the account, and the guard
            # that noticed this WITHHELD the admin instead -- naming deciding replication, which is
            # exactly what must not happen.
            # 🔑 This is a TARGETED read of named users (one lookup each), never a widening of the
            # filter: it cannot admit an account no row asks for, so the BUG-12 property holds.
            $desiredUpns = New-Object System.Collections.Generic.List[string]
            foreach ($d in @($ctx['adminsDesiredAll'])) {
                if ($null -eq $d) { continue }
                $u = "$(Get-PimRowProp -Row $d -Names @('UserPrincipalName','userPrincipalName','UPN','upn'))".Trim()
                if (-not $u) { continue }
                if ($u.IndexOf('@') -lt 0) { continue }          # a bare name cannot be read by UPN
                if (-not $desiredUpns.Contains($u)) { [void]$desiredUpns.Add($u) }
            }
            $addedByRow = New-Object System.Collections.Generic.List[string]
            # 🪤 BUG-138: NOT `@($rows)` -- the array subexpression over a List[object] throws
            # "Argument types do not match" at runtime (tests/Test-PimListWrapTrap.ps1). That is
            # exactly how 2.4.412 broke RIDE's delta-admins job: the scope threw before it read a
            # single account, so nine replicated admins were never created, and delta-admin-tap then
            # failed nine times with "user not found". Index the UPNs once instead -- correct AND O(1).
            $liveUpnSeen = @{}
            foreach ($lr in $rows) { $lu = "$($lr.userPrincipalName)".Trim().ToLowerInvariant(); if ($lu) { $liveUpnSeen[$lu] = $true } }
            foreach ($u in $desiredUpns) {
                if ($liveUpnSeen.ContainsKey($u.ToLowerInvariant())) { continue }
                $one = $null
                try { $one = Invoke-PimGraph -Path ("/users/{0}?`$select=id,userPrincipalName,displayName,accountEnabled,givenName,surname,jobTitle,usageLocation,companyName,passwordPolicies,onPremisesSyncEnabled" -f [uri]::EscapeDataString($u)) } catch { $one = $null }
                if ($null -eq $one -or -not "$($one.id)".Trim()) { continue }   # not created yet -- the create path owns that
                $k = "$($one.id)"
                if ($k -and -not $seen.ContainsKey($k)) {
                    $seen[$k] = $true; [void]$rows.Add($one); [void]$addedByRow.Add($u)
                    $nu = "$($one.userPrincipalName)".Trim().ToLowerInvariant(); if ($nu) { $liveUpnSeen[$nu] = $true }
                }
            }
            $live = $rows.ToArray()
            # Structural assertion: both sides of the diff must be the same population.
            # If anything non-admin slipped through (a server-side filter that silently
            # did nothing, say), stop -- do not diff a mixed population.
            # 🔑 The accounts a DESIRED ROW names are part of that population by definition, so they
            # are passed as allowed: without this the assertion would reject the very rows the store
            # asks for (a centrally-managed admin on a tenant with different naming).
            if (Get-Command Assert-PimAdminPopulationComparable -ErrorAction SilentlyContinue) {
                $chk = Assert-PimAdminPopulationComparable -Live $live -Prefixes $prefixes -AlsoAllowed @($desiredUpns)
                if (-not $chk.ok) { throw ("Admins scope: " + $chk.reason) }
            }
            Write-Host ("    [admins] live set limited to {0} admin account(s) by prefix: {1}" -f $live.Count, ($prefixes -join ', ')) -ForegroundColor DarkGray
            if ($addedByRow.Count) {
                Write-Host ("    [admins] + {0} account(s) named by a desired row whose name matches no prefix (managed by their row, not by naming): {1}" -f $addedByRow.Count, (($addedByRow | Select-Object -First 8) -join ', ')) -ForegroundColor DarkGray
            }
            # #8: a SCHEDULED admin's existing account (a re-hire, say) is not this run's business
            # either. Taken out of LIVE as well as desired, it can never become an unmanaged-admin
            # removal while its row waits for its ProvisionDate.
            $deferredKeys = if ($ctx['adminsDeferred'] -is [hashtable]) { $ctx['adminsDeferred'] } else { @{} }
            if ($deferredKeys.Count -gt 0) { $live = @($live | Where-Object { -not $deferredKeys.ContainsKey((Get-PimAdminRowKey -Row $_)) }) }
            # AD-only admins (TargetPlatform=AD rows) and any account synced from on-premises AD are not Entra
            # admins this scope manages: out of LIVE too, so they are never updated, disabled or pruned here.
            # Measured 2026-09-13: 2.4.338 PATCHed givenName/surname/jobTitle/passwordPolicies on three -AD accounts.
            $adKeys = if ($ctx['adminsAdOnly'] -is [hashtable]) { $ctx['adminsAdOnly'] } else { @{} }
            $adSkipped = @($live | Where-Object { $adKeys.ContainsKey((Get-PimAdminRowKey -Row $_)) -or "$($_.onPremisesSyncEnabled)" -ieq 'True' })
            if ($adSkipped.Count -gt 0) {
                $live = @($live | Where-Object { -not ($adKeys.ContainsKey((Get-PimAdminRowKey -Row $_)) -or "$($_.onPremisesSyncEnabled)" -ieq 'True') })
                Write-Host ("    [admins] {0} AD-only / on-premises-synced account(s) left to hybrid-ad-apply, not managed in Entra: {1}" -f $adSkipped.Count, (@($adSkipped | ForEach-Object { "$($_.userPrincipalName)" }) -join ', ')) -ForegroundColor DarkGray
            }
            # #1: the explicit disables of this pass, decided once through the circuit breaker.
            [void](Update-PimAdminsDisableDecision -Context $ctx -Live $live)
            $live
        }
        # BUG-13: key on the UPN's LOCAL PART, not the whole UPN. The desired UPN is
        # built as {UserName}@{DefaultDomainUPN} -- ONE default domain -- while a tenant
        # legitimately holds admin accounts across several verified domains. Keying on
        # the full UPN meant the SAME admin on a second domain could never match its
        # desired row and was classed as a removal. The account name is the identity;
        # the domain is a tenant detail.
        KeyOf = {
            param($r)
            $upn = Get-PimRowProp -Row $r -Names @('userPrincipalName','UserPrincipalName','UPN','upn')
            if (-not $upn) { $upn = Get-PimRowProp -Row $r -Names @('UserName','Username') }
            if (Get-Command Get-PimUpnLocalPart -ErrorAction SilentlyContinue) { return (Get-PimUpnLocalPart -Upn "$upn") }
            $s = "$upn".Trim(); $i = $s.IndexOf('@')
            if ($i -ge 0) { $s = $s.Substring(0, $i) }
            $s.ToLowerInvariant()
        }
        # #1 + #11: equal when the account is in the state its row asks for (enabled / disabled per
        # Get-PimAdminStatusDecision) AND no managed attribute differs. This used to be
        # `[bool]$l.accountEnabled` -- a disabled account was "unequal", so the update below
        # re-ENABLED every admin an operator had disabled or revoked, on a 5-minute job.
        Equal = {
            param($d,$l)
            $dec = Get-PimAdminStatusDecision -Row $d
            $on = Test-PimAdminValueTrue $l.accountEnabled
            if ($dec.disable -and $on) { return $false }
            if ($dec.desiredEnabled -eq $true -and -not $on -and $dec.mayEnable) { return $false }
            return (@((Get-PimAdminAttributePlan -Desired $d -Live $l).Keys).Count -eq 0)
        }
        ApplyCreate = {
            param($item,$ctx)
            # #1: a Disabled / Revoked / offboarded (or unknown-status) admin is never provisioned (v1
            # skipped the row entirely, 5594-5619). #8: nor is one whose ProvisionDate is ahead --
            # GetDesired already holds those back; this is the handler refusing on its own too.
            $__dec = Get-PimAdminStatusDecision -Row $item.desired
            if ($__dec.blocksCreate) {
                Write-Host ("    [skip] {0}: NOT created -- {1}" -f $item.key, $__dec.reason) -ForegroundColor DarkYellow
                return [pscustomobject]@{ pimApplied = $false; reason = "not created: $($__dec.reason) -- a disabled, revoked or offboarded admin is never provisioned (remove the row once it is finished)" }
            }
            $__due = Test-PimAdminProvisionDue -Row $item.desired
            if (-not $__due.due) { return [pscustomobject]@{ pimApplied = $false; reason = "not created: $($__due.reason)" } }
            # BUG-15. This read `$upn = "$($item.key)"`. That was correct while KeyOf returned
            # the whole UPN -- but the BUG-13 fix (rightly) changed KeyOf to the UPN LOCAL PART,
            # so the create started POSTing a userPrincipalName with NO DOMAIN and Entra rejected
            # every new admin with HTTP 400 "The domain portion of the userPrincipalName property
            # is invalid". The diff KEY is an identity, not an address: the address comes from the
            # desired row (as AdminTap.ApplyCreate already does), and only if the row carries none
            # do we compose it from the tenant's default verified domain.
            $upn = "$(Get-PimRowProp -Row $item.desired -Names @('UserPrincipalName','userPrincipalName','UPN','upn'))".Trim()
            if ($upn -notmatch '@') {
                $local = if ($upn) { $upn } else { "$($item.key)" }
                # REQ-T: pin -> this tenant's Admin account domain setting -> default domain (Get-PimAdminUpnDomain).
                $dom = "$(Get-PimAdminUpnDomain)".Trim()
                # BUG-20: this used to carry its OWN copy of the /organization lookup. It was
                # the CORRECT copy -- it unwrapped .value -- while Get-PimTargetDefaultDomain's
                # did not, so the two disagreed in every tenant: accounts were created at the
                # right domain while the assignment to those same accounts could not resolve
                # them. One resolver now serves both paths, so they cannot diverge again.
                # The $global: overrides above still win, on purpose: in an MSP fanout the
                # operator may pin the domain, and Get-PimTargetDefaultDomain deliberately
                # answers for the tenant the CURRENT token authenticates to.
                if (-not $dom) { $dom = "$(Get-PimTargetDefaultDomain)".Trim() }
                if (-not $dom) { throw "Admins: cannot create '$local' -- the desired row carries no UserPrincipalName and no default verified domain could be resolved. Refusing to POST a domainless UPN." }
                $upn = "$local@$dom"
            }
            $disp = Get-PimRowProp -Row $item.desired -Names @('DisplayName','displayName')
            if (-not $disp) { $disp = $upn }
            $nick = ($upn -split '@')[0]
            # #11: the attributes v1 sent on create (5698-5736) -- givenName, surname, jobTitle,
            # usageLocation, companyName -- plus passwordPolicies=DisablePasswordExpiration IN the
            # create body (v1 needed a separate PATCH with a replica-lag retry loop for it). Only
            # non-blank values are sent: Graph rejects an empty usageLocation.
            # 🔒 The password is random, long, never stored and never logged (see
            # New-PimAdminInitialPassword): v2 onboards through the TAP, not a handed-over password.
            $body = @{
                accountEnabled=$true; displayName=$disp; mailNickname=$nick; userPrincipalName=$upn
                passwordProfile=@{ forceChangePasswordNextSignIn=$true; password=(New-PimAdminInitialPassword) }
                passwordPolicies='DisablePasswordExpiration'
            }
            $__attrs = Get-PimAdminAttributePlan -Desired $item.desired -Live ([pscustomobject]@{ givenName=''; surname=''; displayName=''; jobTitle=''; usageLocation=''; companyName='' })
            foreach ($__k in @($__attrs.Keys)) { if ($__k -ne 'displayName') { $body[$__k] = $__attrs[$__k] } }
            $u = Invoke-PimGraph -Method POST -Path '/users' -Body $body
            $body = $null
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $u }   # incremental cache
            Write-PimAdminLifecycleAudit -Action 'account.create' -Target $upn -After @{ displayName = $disp; attributes = @($__attrs.Keys); platform = 'ID'; transport = 'rest' }
            # new-admin notification (best-effort) -> the ONE recipient rule (Get-PimAdminMailRecipient,
            # PIM-Rest.ps1): the owner's office user when forwarding is TRUE, else the manager. The Manager
            # shows the same rule as "Sends to", so screen and mail cannot disagree (operator, 2026-09-12).
            if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
                # 71.19: the sponsor DEPARTMENT's owners (all of them) -- see Get-PimAdminMailRecipientPlan.
                $__np = Get-PimAdminMailRecipientPlan -Row $item.desired -DepartmentOwners (Get-PimDepartmentOwnerIndex)
                $mgr = (@($__np.recipients) -join ';')
                if (-not "$mgr".Trim()) { Write-Host "  [Admins] $upn -- no new-admin notice: $($__np.reason)" -ForegroundColor DarkYellow }
                $toks = @{ UserPrincipalName=$upn; DisplayName=$disp; Date=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
                    TierLevel=(Get-PimRowProp -Row $item.desired -Names @('TargetUsage','Purpose')); Company=(Get-PimRowProp -Row $item.desired -Names @('Company')); ManagerEmail=(Get-PimRowProp -Row $item.desired -Names @('ManagerEmail')) }
                try { Send-PimNotifyMail -Type 'new-admin' -Tokens $toks -Recipient $mgr | Out-Null } catch { Write-Verbose "new-admin mail ($upn): $($_.Exception.Message)" }
            }
            # Mailbox forwarding where the account HAS a mailbox -- best-effort, gated OFF by default
            # ($global:PIM_AdminMailboxForwarding), never fails the create.
            if (Get-Command Invoke-PimAdminMailboxForwarding -ErrorAction SilentlyContinue) {
                $null = Invoke-PimAdminMailboxForwarding -Row $item.desired -UserPrincipalName $upn -UserId "$($u.id)"
            }
            $u
        }
        ApplyUpdate = {
            param($item,$ctx)
            # #1 + #11: PATCH ONLY what differs -- the attributes from Get-PimAdminAttributePlan, plus
            # accountEnabled when the row's status asks for a change:
            #   * disable  -> only when this pass's circuit-breaker decision allows it (decided once
            #                 in GetLive), never a break-glass account, never an MSP status change
            #                 whose StatusChangeCode did not verify; Revoked also revokes sessions.
            #   * enable   -> only when AccountStatus is explicitly 'Enabled'.
            $d = $item.desired; $l = $item.live
            $dec = Get-PimAdminStatusDecision -Row $d
            $on = Test-PimAdminValueTrue $l.accountEnabled
            $attrs = Get-PimAdminAttributePlan -Desired $d -Live $l
            $body = @{}
            foreach ($k in @($attrs.Keys)) { $body[$k] = $attrs[$k] }
            $disabling = $false; $enabling = $false; $blocked = ''
            $key = "$($item.key)".Trim().ToLowerInvariant()
            if ($dec.disable -and $on) {
                $st = $ctx['adminsDisable']
                if (-not $st) { $blocked = 'no circuit-breaker decision was made for this pass -- refusing to disable (fail closed)' }
                elseif (@($st.breakGlass) -contains $key) { $blocked = 'BREAK-GLASS account -- never disabled' }
                elseif ($st.unauthorized -is [hashtable] -and $st.unauthorized.ContainsKey($key)) { $blocked = "MSP status change NOT authorised: $($st.unauthorized[$key])" }
                elseif (-not $st.decision -or -not $st.decision.allowed) {
                    $tr = if ($st.decision) { "$($st.decision.tripped)" } else { 'no-decision' }
                    $rs = if ($st.decision) { "$($st.decision.reason)" } else { 'the account was not a disable candidate when the pass was decided' }
                    $blocked = "account-disable circuit breaker [$tr]: $rs"
                }
                else { $body['accountEnabled'] = $false; $disabling = $true }
            } elseif ($dec.desiredEnabled -eq $true -and -not $on -and $dec.mayEnable) {
                $body['accountEnabled'] = $true; $enabling = $true
            }
            # 🔴 71.20 -- A DISABLE THAT CAME FROM THE MSP MASTER MUST NEVER BE DROPPED QUIETLY (operator 2026-09-16:
            # "if an master admin is synced and he is disabled in master, then that state must also be synced out to
            # slaves"). A guard refusal on a CENTRAL row leaves the customer's directory with an account the MSP has
            # already decided to disable, so it is a FAILED ITEM (job red, alert raised by the guard above), naming the
            # admin and the guard. A LOCAL row keeps the previous report-only behaviour -- that is the slave's own data
            # and its own decision.
            $__central = (Get-Command Test-PimAdminRowIsCentral -ErrorAction SilentlyContinue) -and (Test-PimAdminRowIsCentral -Row $d)
            if ($blocked -and $__central) {
                throw ("MSP-DISABLE-BLOCKED: the MSP master has this admin as $($dec.reason), but this tenant did NOT disable " +
                       "$($item.key): $blocked. The account is still ENABLED here. Fix the guard condition (or approve the pass) " +
                       "and re-run; the master's decision is not applied until this succeeds.")
            }
            if ($body.Count -eq 0) {
                $why = if ($blocked) { "NOT disabled -- $blocked" } else { 'nothing to change' }
                Write-Host ("    [!] {0}: {1}" -f $item.key, $why) -ForegroundColor Yellow
                return [pscustomobject]@{ pimApplied = $false; reason = $why }
            }
            if ($blocked) { Write-Host ("    [!] {0}: NOT disabled -- {1} (attribute changes still applied)" -f $item.key, $blocked) -ForegroundColor Yellow }
            $r = Invoke-PimGraph -Method PATCH -Path "/users/$($l.id)" -Body $body
            $upnA = "$($l.userPrincipalName)"
            if ($disabling) {
                Write-Host ("    [-] {0}: accountEnabled=false ({1})" -f $item.key, $dec.reason) -ForegroundColor Yellow
                Write-PimAdminLifecycleAudit -Action 'account.disable' -Target $upnA -After @{ accountEnabled = $false; reason = $dec.reason; transport = 'rest' }
                if ($dec.revokeSessions) {
                    try {
                        Invoke-PimGraph -Method POST -Path "/users/$($l.id)/revokeSignInSessions" -Body @{} | Out-Null
                        Write-PimAdminLifecycleAudit -Action 'account.sessions.revoke' -Target $upnA -After @{ reason = $dec.reason }
                    } catch { Write-Warning ("  [admins] {0}: disabled, but revokeSignInSessions FAILED -- existing sessions may live until their tokens expire: {1}" -f $upnA, $_.Exception.Message) }
                }
            }
            if ($attrs.Count -gt 0) { Write-PimAdminLifecycleAudit -Action 'account.update' -Target $upnA -After @{ fields = @($attrs.Keys); transport = 'rest' } }
            if ($enabling) { Write-PimAdminLifecycleAudit -Action 'account.enable' -Target $upnA -After @{ accountEnabled = $true; reason = 'AccountStatus=Enabled' } }
            if ($disabling) { return $r }
            # Mailbox forwarding follows an enabled account only. Gated OFF by default.
            if (Get-Command Invoke-PimAdminMailboxForwarding -ErrorAction SilentlyContinue) {
                $fu = "$(Get-PimRowProp -Row $item.desired -Names @('UserPrincipalName','userPrincipalName'))".Trim()
                if (-not $fu) { $fu = "$($item.live.userPrincipalName)" }
                $null = Invoke-PimAdminMailboxForwarding -Row $item.desired -UserPrincipalName $fu -UserId "$($item.live.id)"
            }
            $r
        }
        ApplyRemove = {
            param($item,$ctx)
            # 🔴 71.22 -- THIS HANDLER NO LONGER DISABLES ANYTHING. Operator, 2026-09-16: "i dont
            # like flow 3 and that should be removed." An admin account being absent from the
            # desired set is a REPORT, never an instruction: Select-PimDisableRemovals now returns
            # an empty remove set, so the orchestrator never reaches here at all.
            # This refusal is the second half, and it is the important half -- the orchestrator's
            # filter is behind a `Get-Command Select-PimDisableRemovals` probe, so in a host where
            # the guard library failed to load, every "removal" would have flowed straight through
            # to this handler. That is a fail-OPEN, and it is exactly how a capability that was
            # "removed" comes back. Refusing here needs no library to be loaded.
            # Disabling an admin is still fully supported -- through its ROW (AccountStatus=Disabled
            # / Revoked, or an AutoDisableDate that has passed), which is ApplyUpdate, not this.
            Write-Host ("    [report] {0}: live admin account NOT in the desired set -- reported, NOT disabled (71.22: absence is never a disable instruction). Set AccountStatus=Disabled or an AutoDisableDate on its row to disable it." -f $item.key) -ForegroundColor Yellow
            return [pscustomobject]@{ pimApplied = $false; reason = 'not in the desired set -- reported only; PIM never disables an account because it is absent (71.22)' }
            # NOTE ON WHAT WAS DELETED HERE, so it is not "restored" by someone who thinks it was
            # lost: the old body ran the account-disable opt-in check, the break-glass check, and
            # then PATCHed accountEnabled=$false. Those two guards were the ONLY thing standing
            # between "absent from the desired set" and a disabled account. They are not needed
            # any more because nothing disables from absence at all -- and they still guard the
            # paths that DO disable (ApplyUpdate, the offboarding sweep, the MSP status change),
            # where they live in Test-PimDisablePassAllowed / Get-PimBreakGlassIdentifiers.
        }
    }
}

# ---------------------------------------------------------------------------
# EntraRoles scope -- PIM enablement/delegation of Entra DIRECTORY ROLES to the
# role-assignable PIM groups. Desired = PIM-Assignments-Roles-Groups (GroupTag +
# RoleDefinitionName + Eligible/Active + Permanent/expiry). Live + apply via the
# Graph PIM REST (roleEligibilityScheduleRequests / roleAssignmentScheduleRequests).
# ---------------------------------------------------------------------------

function New-PimRoleScheduleBody {
    # PURE: build the Graph PIM schedule-request body. Permanent (or Days<=0) ->
    # noExpiration; else afterDuration P{Days}D.
    param(
        [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefId,
        [switch]$Permanent, [int]$Days = 0, [string]$Action = 'adminAssign',
        [string]$Justification = 'PIM4EntraPS engine', [string]$StartUtc, [string]$DirectoryScopeId = '/'
    )
    $sched = @{ expiration = $(if ($Permanent -or $Days -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$Days" + 'D' } }) }
    if ($StartUtc) { $sched.startDateTime = $StartUtc }
    return @{ action=$Action; justification=$Justification; roleDefinitionId=$RoleDefId; principalId=$PrincipalId; directoryScopeId=$DirectoryScopeId; scheduleInfo=$sched }
}

function Get-PimEntraRoleKey {
    # PURE: uniform key for desired + live rows -> "<groupTag>|<roleName>|<type>".
    param([object]$Row)
    $tag  = Get-PimRowProp -Row $Row -Names @('GroupTag')
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName')
    $type = Get-PimRowProp -Row $Row -Names @('AssignmentType')
    return ("$tag|$role|$type").ToLowerInvariant()
}

# ===========================================================================
# v1 -> v2 ASSIGNMENT PARITY (REQUIREMENTS 68.6 rows 24-26), shared by the five assignment
# scopes (EntraRoles, RolesAUs, AdminMembers, GroupMembers, AzRes).
#
# What v1 (PIM-Functions.psm1, the *-From-file-CSV assigners + Assign-Roles-AdministrativeUnits-
# From-SQL) did per row, and v2 did not:
#   * Action=Remove      -> AdminRemove of exactly that assignment (v1:3541/3861/4257/4704/5178/6343)
#   * AutoExtend=TRUE    -> AdminExtend when <= 30 days remain       (v1:3505/3824/4224/4668/5143/6310)
#   * UpdateExisting=TRUE or Action=Update -> AdminUpdate            (v1:3465/3514/4198/4232/4626/4678/5098/5151/6274/6319)
# v2 differences, deliberate and safer:
#   * a write happens only when something is DUE (v1 re-issued AdminUpdate on EVERY run for an
#     UpdateExisting row). "Due" = permanence or duration differs, or <= 30 days remain (which
#     keeps v1's effect that an UpdateExisting assignment never lapsed).
#   * removals go through the engine's G4 removal budget (PIM-EngineCore / PIM-DisableGuard).
# All helpers below are PURE except the Invoke-* appliers.
# ===========================================================================
$script:PimAssignmentRenewWithinDays = 30   # v1's threshold, verbatim

function Test-PimRowIsRemove {
    param([object]$Row)
    return ("$(Get-PimRowProp -Row $Row -Names @('Action'))".Trim() -ieq 'Remove')
}

function Test-PimAssignmentFlag {
    # v1 compared the string to "TRUE"; also accept the usual truthy spellings from SQL/JSON.
    param([object]$Value)
    return ("$Value".Trim() -match '^(?i)(true|1|yes|y)$')
}

function Get-PimAssignmentIntent {
    # PURE: what the row asks for. Permanent when Permanent=TRUE or no positive day count -- the
    # SAME rule the create bodies use (New-PimRoleScheduleBody / New-PimGroupMembershipBody).
    param([object]$Row)
    $days = 0
    [void][int]::TryParse("$(Get-PimRowProp -Row $Row -Names @('NumOfDaysWhenExpire'))".Trim(), [ref]$days)
    $perm = Test-PimAssignmentFlag (Get-PimRowProp -Row $Row -Names @('Permanent'))
    $action = "$(Get-PimRowProp -Row $Row -Names @('Action'))".Trim()
    [pscustomobject]@{
        permanent      = ($perm -or $days -le 0)
        days           = $days
        autoExtend     = (Test-PimAssignmentFlag (Get-PimRowProp -Row $Row -Names @('AutoExtend')))
        updateExisting = ((Test-PimAssignmentFlag (Get-PimRowProp -Row $Row -Names @('UpdateExisting'))) -or ($action -ieq 'Update'))
        type           = "$(Get-PimRowProp -Row $Row -Names @('AssignmentType'))".Trim()
    }
}

function ConvertTo-PimAssignmentUtc {
    # PURE: a Graph/ARM date (string, or [datetime] after ConvertFrom-Json) -> UTC [datetime], or $null.
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-PimTypeNeutralKey {
    # PURE: "<...>|eligible" / "<...>|active" -> "<...>". A key whose type is neither returns ''
    # so an untyped row can never be paired with (and remove) a live assignment.
    param([string]$Key)
    $k = "$Key".Trim().ToLowerInvariant()
    if ($k -match '^(.+)\|(eligible|active)$') { return $Matches[1] }
    return ''
}

function Select-PimRemoveRows {
    # The Remove rows a scope can act on. Operator 2026-09-13: a Remove row REVOKES the delegation like
    # the Manager's revoke -- eligible AND active -- so AssignmentType does not narrow it (the core matches
    # both types). A type other than Eligible/Active/blank is a typo and is reported, never guessed at.
    param([object[]]$Rows = @(), [string]$Scope)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $t = "$(Get-PimRowProp -Row $r -Names @('AssignmentType'))".Trim()
        if (-not $t -or $t -ieq 'Eligible' -or $t -ieq 'Active') { $out.Add($r); continue }
        Write-Warning ("  [engine] {0}: a Remove row has AssignmentType '{1}' (not Eligible/Active/blank) -- skipped, nothing revoked; fix the row." -f $Scope, $t)
    }
    return $out.ToArray()
}

function Get-PimLiveScheduleWindow {
    # PURE: normalise a live assignment row's schedule. Rows built by the assignment GetLive blocks
    # carry scheduleKnown/startDateTime/endDateTime/expirationType; anything else is 'unknown' and
    # is never maintained (a maintenance write on a guess is worse than none).
    param([object]$Live)
    $unknown = [pscustomobject]@{ known = $false; permanent = $false; startUtc = $null; endUtc = $null; parseable = $false }
    if ($null -eq $Live -or -not $Live.PSObject.Properties['scheduleKnown'] -or -not $Live.scheduleKnown) { return $unknown }
    $start = ConvertTo-PimAssignmentUtc $Live.startDateTime
    $end   = ConvertTo-PimAssignmentUtc $Live.endDateTime
    $expType = "$($Live.expirationType)".Trim()
    $rawEnd = "$($Live.endDateTime)".Trim()
    $perm = ($expType -ieq 'noExpiration') -or (-not $rawEnd -and $expType -notmatch '(?i)afterDuration|afterDateTime')
    [pscustomobject]@{ known = $true; permanent = [bool]$perm; startUtc = $start; endUtc = $end; parseable = ($perm -or $null -ne $end) }
}

function Get-PimAssignmentMaintenance {
    <#
      PURE. Is an EXISTING assignment due for AdminExtend / AdminUpdate? Returns
      { action = none|extend|update; reason; daysLeft }.
      Order is v1's (e.g. v1:3463-3528): permanent live -> only UpdateExisting can change it; an
      expiring live -> AutoExtend first (<= 30 days), then UpdateExisting.
      A renewal is only "due" when it moves the end date by more than a day, so a short
      NumOfDaysWhenExpire (<= 30) cannot turn into a write on every engine tick.
    #>
    param([object]$Desired, [object]$Live, [datetime]$NowUtc = [datetime]::UtcNow, [int]$WithinDays = $script:PimAssignmentRenewWithinDays)
    $now = $NowUtc.ToUniversalTime()
    $intent = Get-PimAssignmentIntent -Row $Desired
    $w = Get-PimLiveScheduleWindow -Live $Live
    if (-not $w.known)     { return [pscustomobject]@{ action = 'none'; reason = 'live schedule not read'; daysLeft = $null } }
    if (-not $w.parseable) { return [pscustomobject]@{ action = 'none'; reason = 'live expiry unparseable (v1: NoAction)'; daysLeft = $null } }
    if ($w.permanent) {
        if ($intent.updateExisting -and -not $intent.permanent) {
            return [pscustomobject]@{ action = 'update'; reason = "permanence: live is permanent, the row asks for $($intent.days) day(s)"; daysLeft = $null }
        }
        return [pscustomobject]@{ action = 'none'; reason = 'permanent'; daysLeft = $null }
    }
    $daysLeft = [math]::Round(($w.endUtc - $now).TotalDays, 0)
    $gain = if ($intent.permanent) { [double]::MaxValue } else { ($now.AddDays($intent.days) - $w.endUtc).TotalDays }
    if ($daysLeft -le $WithinDays -and $intent.autoExtend -and $gain -gt 1) {
        return [pscustomobject]@{ action = 'extend'; reason = "AutoExtend: $daysLeft day(s) left"; daysLeft = $daysLeft }
    }
    if ($intent.updateExisting) {
        if ($intent.permanent) { return [pscustomobject]@{ action = 'update'; reason = 'permanence: the row asks for a permanent assignment'; daysLeft = $daysLeft } }
        if ($null -ne $w.startUtc) {
            $dur = [math]::Round(($w.endUtc - $w.startUtc).TotalDays, 0)
            if ([math]::Abs($dur - $intent.days) -gt 1) {
                return [pscustomobject]@{ action = 'update'; reason = "duration: live $dur day(s), the row asks for $($intent.days)"; daysLeft = $daysLeft }
            }
        }
        if ($daysLeft -le $WithinDays -and $gain -gt 1) {
            return [pscustomobject]@{ action = 'update'; reason = "UpdateExisting renewal: $daysLeft day(s) left (v1 re-applied UpdateExisting rows on every run, so they never lapsed)"; daysLeft = $daysLeft }
        }
    }
    return [pscustomobject]@{ action = 'none'; reason = "$daysLeft day(s) left"; daysLeft = $daysLeft }
}

function Test-PimAssignmentAbsentError {
    # PURE: does this removal failure mean "there was nothing to remove"? That is SUCCESS for a
    # removal (idempotence) -- v1 logged "Assignment already removed (not found) ... skipping".
    param([string]$Message)
    return ("$Message" -match '(?i)RoleAssignmentDoesNotExist|RoleEligibilityScheduleDoesNotExist|ScheduleNotFound|ResourceNotFound|Request_ResourceNotFound|\bHTTP\s*404\b|\b404\b.*not\s*found|does not exist')
}

function Test-PimAssignmentRetryableError {
    # PURE: failures a fallback must NOT paper over (permission, throttling, service errors).
    param([string]$Message)
    return ("$Message" -match '(?i)\b403\b|Forbidden|AuthorizationFailed|Authorization_RequestDenied|InsufficientPermissions|\b429\b|TooManyRequests|throttl|\bHTTP 5\d\d\b|InternalServerError|ServiceUnavailable')
}

function Test-PimAssignmentDurationRejected {
    param([string]$Message)
    return ("$Message" -match '(?i)greater than (the )?maximum allowed duration|ExpirationRule')
}

# §70.10 (2026-09-13): how long a group's membership read stays valid IN ONE PROCESS. It was 5 minutes, but a tick's
# batched read of every owned group takes 4-7 minutes on internal, so the SECOND scope that needs it (GroupMembers
# after AdminMembers, or a later job in the same tick) often re-read everything. Every write through the engine or the
# queue drops the affected group at once (Reset-PimAssignmentLiveCaches), and a long-lived host that needs a fresh view
# (the Manager's drift check) clears the caches explicitly (Clear-PimEngineReadCaches).
$script:PimGrpMemCacheTtlMinutes = 20
function Clear-PimEngineReadCaches {
    # Drop every per-process live-read cache so the next read comes from the tenant. For long-lived hosts (the Manager)
    # before a drift check; a tick is a fresh process and never needs it. The group POLICY-ID map is NOT cleared: a
    # group's policy id never changes, and a stale entry removes itself when its policy read fails (§70.10).
    $script:PimGrpMemCache = $null
    $script:PimDirSchedAt = $null
    $script:PimSolutionGroupsAt = $null
    # REQ-U wave 2: the workload role catalogs (Defender / Intune), so a drift check reads the live permissions.
    $script:__pimDefenderRoles = $null; $script:__pimIntuneRoles = $null
    if (Get-Command Clear-PimWorkloadRoleCaches -ErrorAction SilentlyContinue) { Clear-PimWorkloadRoleCaches }
}

function Reset-PimAssignmentLiveCaches {
    # After a write, the next read of THAT assignment must come from the tenant, not from the
    # 5-minute preload -- otherwise a just-extended assignment still looks expiring and is
    # extended again on the next tick, and a just-removed one is removed again.
    param([string]$GroupId)
    $script:PimDirSchedAt = $null
    if ($GroupId -and $script:PimGrpMemCache -is [hashtable]) { $script:PimGrpMemCache.Remove("$GroupId") }
}

function Invoke-PimAssignmentRemoval {
    # Run a removal; "already absent" is success (idempotent). Anything else rethrows so the core
    # records it through PIM-FailureCatalog.
    param([Parameter(Mandatory)][scriptblock]$Action, [string]$What)
    try {
        $r = & $Action
        return [pscustomobject]@{ removed = $true; alreadyAbsent = $false; response = $r }
    } catch {
        $m = "$($_.Exception.Message)"
        if ($_.ErrorDetails -and "$($_.ErrorDetails.Message)".Trim()) { $m = "$m $($_.ErrorDetails.Message)" }
        if (Test-PimAssignmentAbsentError $m) {
            Write-Host ("    [=] {0} (already absent -- nothing to remove)" -f $What) -ForegroundColor DarkGray
            return [pscustomobject]@{ removed = $false; alreadyAbsent = $true; response = $null }
        }
        throw
    }
}

function Invoke-PimGraphScheduleMaintenance {
    <#
      POST an adminExtend / adminUpdate schedule request (directory role or PIM-for-Groups).
        extend : duration ladder (lands at the policy max, like the create). If Graph refuses the
                 EXTEND itself (not a permission/throttle/service error), renew with adminUpdate --
                 same schedule, same end result, so an assignment is never left to lapse.
        update : NO ladder. A policy that caps the duration below the row would otherwise be
                 re-written every run; the refusal is reported (pimApplied=$false), nothing changes.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Body, [Parameter(Mandatory)][ValidateSet('adminExtend','adminUpdate')][string]$Verb, [string]$What)
    $Body['action'] = $Verb
    if ($Verb -eq 'adminExtend') {
        try { return (Invoke-PimScheduleCreate -Path $Path -Body $Body) }
        catch {
            $m = "$($_.Exception.Message)"
            if (Test-PimAssignmentRetryableError $m) { throw }
            Write-Host ("    [~] {0}: adminExtend refused ({1}) -- renewing with adminUpdate" -f $What, $m) -ForegroundColor DarkYellow
            $Body['action'] = 'adminUpdate'
            try { return (Invoke-PimScheduleCreate -Path $Path -Body $Body) }
            catch { throw ("AutoExtend of {0} failed: adminExtend: {1} | adminUpdate: {2}" -f $What, $m, $_.Exception.Message) }
        }
    }
    try { return (Invoke-PimGraph -Method POST -Path $Path -Body $Body) }
    catch {
        $m = "$($_.Exception.Message)"
        if (Test-PimAssignmentDurationRejected $m) {
            Write-Warning ("  [engine] {0}: adminUpdate refused by the PIM policy's maximum duration -- the live assignment is unchanged. Lower NumOfDaysWhenExpire or raise the policy maximum. ({1})" -f $What, $m)
            return [pscustomobject]@{ pimApplied = $false; reason = "the PIM policy caps the duration below NumOfDaysWhenExpire: $m" }
        }
        throw
    }
}

function Remove-PimDirRoleAssignment {
    # adminRemove of ONE directory-role assignment (tenant or AU scope), of the type the live row has.
    param([Parameter(Mandatory)][object]$Live, [string]$What)
    $scope = "$($Live.directoryScopeId)"; if (-not $scope) { $scope = '/' }
    $ep = if ("$($Live.AssignmentType)" -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
    $body = New-PimRoleScheduleBody -PrincipalId "$($Live.principalId)" -RoleDefId "$($Live.roleDefinitionId)" -Action 'adminRemove' -DirectoryScopeId $scope
    $r = Invoke-PimAssignmentRemoval -What $What -Action { Invoke-PimGraph -Method POST -Path "/roleManagement/directory/$ep" -Body $body }
    Reset-PimAssignmentLiveCaches
    return $r
}

function Remove-PimGroupScheduleAssignment {
    # adminRemove of ONE PIM-for-Groups membership (member principal in container group), of the type the live row has.
    param([Parameter(Mandatory)][object]$Live, [string]$What)
    $gid = "$($Live.groupId)"
    if (-not $gid) { throw "PIM-for-Groups removal of '$What': the live row carries no groupId -- refusing to guess the group" }
    $acc = "$($Live.accessId)"; if (-not $acc) { $acc = 'member' }
    $ep = if ("$($Live.AssignmentType)" -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
    $body = New-PimGroupMembershipBody -PrincipalId "$($Live.principalId)" -GroupId $gid -AccessId $acc -Action 'adminRemove'
    $r = Invoke-PimAssignmentRemoval -What $What -Action { Invoke-PimGraph -Method POST -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body }
    Reset-PimAssignmentLiveCaches -GroupId $gid
    return $r
}

function Remove-PimAzResScheduleAssignment {
    # ARM AdminRemove of ONE Azure PIM assignment at its scope (v1 PIM-Assignment-Revoker:676-703 shape).
    param([Parameter(Mandatory)][object]$Live, [string]$What)
    $scope = "$($Live.AzScope)"
    $rdef = "$($Live.roleDefinitionId)"
    if (-not $rdef -and "$($Live.RoleId)") { $rdef = "$scope/providers/Microsoft.Authorization/roleDefinitions/$($Live.RoleId)" }
    if (-not $scope -or -not $rdef -or -not "$($Live.principalId)") { throw "AzRes removal of '$What': the live row lacks scope/role/principal -- refusing to guess" }
    $ep = if ("$($Live.AssignmentType)" -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
    $body = @{ properties = @{ principalId = "$($Live.principalId)"; roleDefinitionId = $rdef; requestType = 'AdminRemove'; justification = 'PIM4EntraPS engine: Remove' } }
    $guid = [guid]::NewGuid().ToString()
    return (Invoke-PimAssignmentRemoval -What $What -Action { Invoke-PimArm -Method PUT -Path "$scope/providers/Microsoft.Authorization/$ep/$guid" -ApiVersion '2020-10-01-preview' -Body $body })
}

function Invoke-PimAssignmentMaintenanceApply {
    <#
      ApplyUpdate for the five assignment scopes: decide (Get-PimAssignmentMaintenance) and issue
      adminExtend / adminUpdate against the LIVE assignment, with the schedule the ROW asks for
      (v1 built the same start=now / end=now+NumOfDaysWhenExpire body for Assign, Extend and Update).
    #>
    param([Parameter(Mandatory)][ValidateSet('DirRole','GroupMember','AzRes')][string]$Kind, [Parameter(Mandatory)][object]$Item, [datetime]$NowUtc = [datetime]::UtcNow)
    $m = Get-PimAssignmentMaintenance -Desired $Item.desired -Live $Item.live -NowUtc $NowUtc
    if ($m.action -eq 'none') { return [pscustomobject]@{ pimApplied = $false; reason = "nothing due: $($m.reason)" } }
    $intent = Get-PimAssignmentIntent -Row $Item.desired
    $l = $Item.live
    $verb = if ($m.action -eq 'extend') { 'adminExtend' } else { 'adminUpdate' }
    Write-Host ("    [~] {0}: {1} ({2})" -f $Item.key, $verb, $m.reason) -ForegroundColor Yellow
    switch ($Kind) {
        'DirRole' {
            $scope = "$($l.directoryScopeId)"; if (-not $scope) { $scope = '/' }
            $body = New-PimRoleScheduleBody -PrincipalId "$($l.principalId)" -RoleDefId "$($l.roleDefinitionId)" -Permanent:$intent.permanent -Days $intent.days -Action $verb -StartUtc ($NowUtc.ToUniversalTime().ToString('o')) -DirectoryScopeId $scope
            $ep = if ("$($l.AssignmentType)" -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            $r = Invoke-PimGraphScheduleMaintenance -Path "/roleManagement/directory/$ep" -Body $body -Verb $verb -What "$($Item.key)"
            Reset-PimAssignmentLiveCaches
            return $r
        }
        'GroupMember' {
            $gid = "$($l.groupId)"; if (-not $gid) { throw "PIM-for-Groups $verb of '$($Item.key)': the live row carries no groupId" }
            $acc = "$($l.accessId)"; if (-not $acc) { $acc = 'member' }
            $body = New-PimGroupMembershipBody -PrincipalId "$($l.principalId)" -GroupId $gid -AccessId $acc -Permanent:$intent.permanent -Days $intent.days -Action $verb
            $ep = if ("$($l.AssignmentType)" -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            $r = Invoke-PimGraphScheduleMaintenance -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body -Verb $verb -What "$($Item.key)"
            Reset-PimAssignmentLiveCaches -GroupId $gid
            return $r
        }
        'AzRes' {
            $scope = "$($l.AzScope)"
            $rdef = "$($l.roleDefinitionId)"; if (-not $rdef) { $rdef = "$scope/providers/Microsoft.Authorization/roleDefinitions/$($l.RoleId)" }
            $start = $NowUtc.ToUniversalTime()
            $exp = if ($intent.permanent) { @{ type = 'noExpiration' } } else { @{ type = 'AfterDateTime'; endDateTime = $start.AddDays($intent.days).ToString('o') } }
            $ep = if ("$($l.AssignmentType)" -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            $mk = { param($rt) @{ properties = @{ principalId = "$($l.principalId)"; roleDefinitionId = $rdef; requestType = $rt; justification = "PIM4EntraPS engine: $rt"; scheduleInfo = @{ startDateTime = $start.ToString('o'); expiration = $exp } } } }
            $put = { param($b) Invoke-PimArm -Method PUT -Path "$scope/providers/Microsoft.Authorization/$ep/$([guid]::NewGuid().ToString())" -ApiVersion '2020-10-01-preview' -Body $b }
            if ($verb -eq 'adminExtend') {
                try { return (& $put (& $mk 'AdminExtend')) }
                catch {
                    $em = "$($_.Exception.Message)"
                    if (Test-PimAssignmentRetryableError $em) { throw }
                    Write-Host ("    [~] {0}: AdminExtend refused ({1}) -- renewing with AdminUpdate" -f $Item.key, $em) -ForegroundColor DarkYellow
                    try { return (& $put (& $mk 'AdminUpdate')) }
                    catch { throw ("AutoExtend of {0} failed: AdminExtend: {1} | AdminUpdate: {2}" -f $Item.key, $em, $_.Exception.Message) }
                }
            }
            try { return (& $put (& $mk 'AdminUpdate')) }
            catch {
                $em = "$($_.Exception.Message)"
                if (Test-PimAssignmentDurationRejected $em) {
                    Write-Warning ("  [engine] {0}: AdminUpdate refused by the PIM policy's maximum duration -- the live assignment is unchanged. ({1})" -f $Item.key, $em)
                    return [pscustomobject]@{ pimApplied = $false; reason = "the PIM policy caps the duration below NumOfDaysWhenExpire: $em" }
                }
                throw
            }
        }
    }
}

function Get-PimRolesGroupsAuScope {
    # SEC-30 (§33.28). PURE. The AU name when a PIM-Assignments-Roles-Groups row's PermissionScope says 'AU:<name>'
    # (what the Create-resource-delegation wizard used to stage), else ''. 'Global', 'Scoped' and blank are the
    # descriptive values this column otherwise carries and are unaffected.
    param([object]$Row)
    $s = "$(Get-PimRowProp -Row $Row -Names @('PermissionScope'))".Trim()
    if ($s -match '^(?i)AU\s*:\s*(.+)$') { return $Matches[1].Trim() }
    return ''
}

function Get-PimRolesGroupsAuScopeRefusal {
    param([object]$Row, [string]$Scope)
    $tag = Get-PimRowProp -Row $Row -Names @('GroupTag'); $rn = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName')
    return ("AU-SCOPE-REFUSED: PIM-Assignments-Roles-Groups row '{0} / {1}' is scoped to AU '{2}' (PermissionScope), but this entity assigns roles TENANT-WIDE. " +
            "NOT applied -- it would grant '{1}' over the whole tenant instead of the AU. Move it to PIM-Assignments-Roles-AUs (GroupTag, AdministrativeUnitTag='{2}', same role) and delete this row.") -f $tag, $rn, $Scope
}

function New-PimEntraRolesProvider {
    @{
        scope  = 'EntraRoles'
        entity = 'PIM-Assignments-Roles-Groups'
        order  = 40
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $all = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups')
            # 68.6 row 24: Remove rows are not desired -- they are TARGETED removals (GetRemoveRows).
            $ctx['removeRows:EntraRoles'] = @($all | Where-Object { Test-PimRowIsRemove $_ })
            @($all | Where-Object { -not (Test-PimRowIsRemove $_) })
        }
        GetRemoveRows = { param($ctx) @(Select-PimRemoveRows -Rows @($ctx['removeRows:EntraRoles']) -Scope 'EntraRoles') }
        TypeKeyOf = { param($r) $k = Get-PimTypeNeutralKey -Key (Get-PimEntraRoleKey -Row $r); $s = Get-PimRolesGroupsAuScope -Row $r; if ($s) { "$k|refused-scope=$s" } else { $k } }   # SEC-30: never pairs with a tenant-wide assignment
        GetLive = {
            param($ctx)
            # Was `try { Build-PimContext } catch {}` -- see Get-PimEntraRoleNameMap for why that hid
            # every EntraRoles failure in the scheduler as "unresolved group/role".
            $ctx['roleNameToId'] = Get-PimEntraRoleNameMap
            # BUG-17: this used to enumerate ONLY the group tags found in the desired rows,
            # so deleting a desired row also removed its live assignment from view and the
            # prune it should have caused did nothing -- the assignment stayed in the tenant
            # forever, unreported. The live universe is the groups the SOLUTION owns.
            # (This provider's keys already agreed across both sides -- GroupTag|role|type --
            # so unlike RolesAUs/GroupMembers it needed only the live-set half of the fix.)
            $owned = Get-PimSolutionOwnedGroups
            $ctx['tagToGroupId'] = @{}
            foreach ($t in @($owned.byTag.Keys)) { $ctx['tagToGroupId'][$t] = $owned.byTag[$t] }
            # 🔴 2026-09-20: an INCOMPLETE preload is not live state. Diffing against a short index turned
            # 9 present-and-correct Eligible assignments into TYPE CHANGES (which delete the live Active
            # one) on internal at 23:33 UTC. NOT CHECKED, nothing applied -- see Get-PimDirRoleSchedulePreload.
            Get-PimDirRoleSchedulePreload
            $__pe = Get-PimDirRoleScheduleReadError
            if ($__pe) { $ctx['__pimLiveReadError'] = "the directory role schedule preload was INCOMPLETE ($__pe)"; return @() }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"; if (-not $tag) { continue }
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $gid)) {
                    if ("$($s.directoryScopeId)" -ne '/') { continue }   # EntraRoles = tenant-scope only (AU-scoped handled by RolesAUs)
                    # An ACTIVATION of an eligible assignment is not an Active assignment: never key it
                    # as one (it would read as "Active exists", be extended, or be removed as a leftover).
                    if ("$($s.graphAssignmentType)" -ieq 'Activated') { continue }
                    $live.Add([pscustomobject]@{ GroupTag=$tag; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; principalId=$gid; roleDefinitionId=$s.roleDefinitionId
                                                 directoryScopeId='/'; scheduleKnown=$s.scheduleKnown; startDateTime=$s.startDateTime; endDateTime=$s.endDateTime })
                }
            }
            $live.ToArray()
        }
        # 🔴 SEC-30 (§33.28): a Roles-Groups row carrying PermissionScope 'AU:<name>' asks for an AU-SCOPED role, but
        # this provider only ever assigns at TENANT scope (directoryScopeId '/'). Applied as-is it became a TENANT-WIDE
        # grant. Such a row gets its own key (it can never match -- and so never 'confirm' -- a tenant-wide live
        # assignment) and ApplyCreate REFUSES it loudly; the AU-scoped form is a PIM-Assignments-Roles-AUs row.
        KeyOf = { param($r) $k = Get-PimEntraRoleKey -Row $r; $s = Get-PimRolesGroupsAuScope -Row $r; if ($s) { "$k|refused-scope=$s" } else { $k } }
        # 68.6 rows 25-26: an existing assignment is "different" when AutoExtend / UpdateExisting make
        # it due (Get-PimAssignmentMaintenance). Was `$true` -- every duration, permanence and
        # expiry change was ignored and AutoExtend assignments lapsed.
        Equal = { param($d,$l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item,$ctx) Invoke-PimAssignmentMaintenanceApply -Kind DirRole -Item $item }
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            # SEC-30 (ss33.28): never widen an AU-scoped grant to the whole tenant -- refuse it, loudly.
            $auScope = Get-PimRolesGroupsAuScope -Row $d
            if ($auScope) { throw (Get-PimRolesGroupsAuScopeRefusal -Row $d -Scope $auScope) }
            $tag = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['tagToGroupId'][$tag]
            $rn  = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['roleNameToId'][$rn.ToLowerInvariant()]
            if ($gid -and -not $rid) {
                # BUG-234 (77.3): say WHICH half is missing, and for a role, the closest real one.
                $cat = @($Global:Roles_All_ID | ForEach-Object { "$($_.DisplayName)" })
                throw (Get-PimEntraRoleNotFoundMessage -Scope 'EntraRoles' -RoleName $rn -Where "the Entra role assignment of group tag '$tag'" -Catalog $cat)
            }
            if (-not $gid -or -not $rid) { throw "EntraRoles: unresolved group/role ($tag / $rn)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimRoleScheduleBody -PrincipalId $gid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o'))
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            # Prune, targeted Remove row, or the old half of a type change -- one call, "already
            # absent" is success.
            Remove-PimDirRoleAssignment -Live $item.live -What "$($item.key)"
        }
    }
}

# ===========================================================================
# Shared resolvers (REST + SQL). Ported from PIM-Functions.psm1 (the most-updated
# CSV-engine logic) but module-free: all directory reads go through Build-PimContext
# ($Global:Groups_All_ID / Users_All_ID / AU_All_ID, filled via Invoke-PimGraph).
# ===========================================================================

function Get-PimMailNickname {
    # mailNickname allows no spaces/specials and is <=64. Legacy used the display name
    # verbatim (PIM names are already hyphen-cased); we sanitise defensively.
    param([string]$Name)
    $n = ($Name -replace '[^A-Za-z0-9._-]', '')
    if ($n.Length -gt 64) { $n = $n.Substring(0, 64) }
    if (-not $n) { $n = 'g' + ([guid]::NewGuid().ToString('N').Substring(0, 8)) }
    return $n
}

function Ensure-PimContextLoaded {
    if (-not $Global:PimContextBuiltAt -and (Get-Command Build-PimContext -ErrorAction SilentlyContinue)) {
        try { Build-PimContext | Out-Null } catch { Write-Warning "  [engine] Build-PimContext failed: $($_.Exception.Message)" }
    }
}

function Get-PimEntraRoleNameMap {
    <#
      role displayName (lower) -> role definition id, for every provider that resolves an Entra role
      by NAME. One place, and it FAILS LOUDLY on an empty catalog.
      🔴 Four providers built this map inline over $Global:Roles_All_ID after a context load that could
      fail silently (Build-PimContext absent from the scheduler, "command not found" swallowed). An
      empty map is not "no roles" -- every tenant has ~100 built-in roles -- so an empty catalog must
      stop the scope with the real reason, never turn into one "unresolved group/role" per item.
    #>
    # 🪤 NOT `@($Global:Roles_All_ID).Count`: an UNSET variable makes @($null), whose Count is 1, so
    # the load was skipped on exactly the cold tick this exists for. Count real items only.
    if (-not @(@($Global:Roles_All_ID) | Where-Object { $_ }).Count) {
        if (-not (Get-Command Build-PimContext -ErrorAction SilentlyContinue)) {
            throw 'the Entra role catalog cannot load: Build-PimContext is not defined in this host (PIM-ContextBuilder.ps1 is not dot-sourced). Every Entra role would resolve as "unresolved".'
        }
        Build-PimContext -Refresh:([bool]$Global:PimContextBuiltAt) | Out-Null   # throws with Graph's own reason
    }
    $map = @{}
    foreach ($r in @($Global:Roles_All_ID)) { $n = "$($r.DisplayName)"; if ($n) { $map[$n.ToLowerInvariant()] = "$($r.Id)" } }
    if ($map.Count -eq 0) {
        throw 'the Entra role catalog is EMPTY after loading (GET /roleManagement/directory/roleDefinitions returned nothing) -- check the runtime identity''s RoleManagement.Read.Directory permission.'
    }
    return $map
}

function Get-PimEntraRoleSuggestion {
    <#
      PURE. BUG-234 (77.3): the closest Entra role display name for a name the tenant does not have, or ''.
      Display names are not stable across tenants: measured 2026-09-21, EFIF calls template
      2af84b1e-32c8-42b7-82a3-daa748c1ce1b "Office Apps Administrator" while a row named it "Microsoft 365 Apps
      Administrator", and every run failed for two days as "Unrecognised failure". Known renames first, then the
      catalog name sharing the most words (ignoring 'administrator'/'admin', which every other role shares).
    #>
    param([string]$Name, [string[]]$Catalog)
    $n = "$Name".Trim(); if (-not $n) { return '' }
    $cat = @($Catalog | Where-Object { "$_".Trim() })
    $aliases = @{
        'microsoft 365 apps administrator' = 'Office Apps Administrator'; 'office apps administrator' = 'Microsoft 365 Apps Administrator'
        'microsoft entra joined device local administrator' = 'Azure AD Joined Device Local Administrator'; 'azure ad joined device local administrator' = 'Microsoft Entra Joined Device Local Administrator'
        'company administrator' = 'Global Administrator'
    }
    $a = $aliases[$n.ToLowerInvariant()]
    if ($a) { $hit = @($cat | Where-Object { "$_" -ieq $a }); if ($hit.Count) { return "$($hit[0])" } }
    $words = { param($s) @(("$s".ToLowerInvariant() -split '[^a-z0-9]+') | Where-Object { $_ -and $_ -notin @('administrator','admin','microsoft','365','the','of') } | Sort-Object -Unique) }
    $want = & $words $n
    if (-not $want.Count) { return '' }
    $best = ''; $bestScore = 0.0
    foreach ($c in $cat) {
        $have = & $words $c
        if (-not $have.Count) { continue }
        $common = @($want | Where-Object { $have -contains $_ }).Count
        if (-not $common) { continue }
        $score = $common / [double](@(@($want) + @($have) | Sort-Object -Unique).Count)
        if ($score -gt $bestScore) { $bestScore = $score; $best = "$c" }
    }
    if ($bestScore -ge 0.34) { return $best }
    ''
}

function Get-PimEntraRoleNotFoundMessage {
    # PURE. BUG-234: the sentence an operator can act on -- which role, which row, the closest real role.
    param([Parameter(Mandatory)][string]$Scope, [string]$RoleName, [string]$Where, [string[]]$Catalog)
    $s = Get-PimEntraRoleSuggestion -Name $RoleName -Catalog $Catalog
    "${Scope}: Entra has no role named '$RoleName' in this tenant" + $(if ($s) { " -- did you mean '$s'? (role display names differ between tenants)" } else { '' }) +
        $(if ("$Where".Trim()) { ". Used by: $Where" } else { '' }) + ". Fix: correct the role name on that row, or remove the row."
}

function Get-PimGroupDefinitionRows {
    # Every entity that DEFINES a group becomes one create candidate. All share the
    # GroupName/GroupTag/GroupDescription/IsRoleAssignable/AdministrativeUnitTag columns.
    #
    # 🔴 THE WIZARD OFFERED GROUP TYPES THE ENGINE NEVER CREATED (operator, 2026-09-12). The Manager's
    # direct-group wizard writes Department / Process rows to their own entities, but this list only
    # read Roles/Services/Organization/Tasks -- so those groups were authored, validated, shown on the
    # map, and never created. Operator decision: "wire them into engine". Project (PROJ-, AU
    # PIM-PROJECTS) and Cross-org (CORG-, AU PIM-CROSSORG) were added the same day.
    # 🔒 PIM-Definitions-Departments is ALSO the department/owner store (BUG-142: rows of
    # Department + Owners, no GroupName). Those rows are NOT groups, and the GroupName guard below is
    # what keeps them out -- do not loosen it.
    # ⛔ PIM-Definitions-Resources is DELIBERATELY NOT in this list. Discovery auto-create
    # (Invoke-PimDiscoveryAutoCreate, PIM-EngineCore.ps1) writes every discovered Azure/Power BI
    # resource into that entity, so reading it here would start creating every discovered group at
    # every customer with discovery switched on. The operator DROPPED "Resource" as a direct-group
    # type for now (2026-09-12: "drop the resources category for now"), so nothing authors a
    # direct group there any more; the entity remains discovery's.
    # 68.6 #31 -- Lifecycle=Retire rows are NOT group definitions by default: the Groups provider
    # would otherwise re-create (and re-describe) a group the GroupRetirement provider is deleting, and
    # GroupRetirement refuses to act while this function still returns the row. -IncludeRetired is for
    # the two resolvers that must keep SEEING the group until it is gone (the solution-owned set and
    # the tag map), so its live assignments are neither orphaned from view nor reported "unresolved".
    param([switch]$IncludeRetired)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
                     'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')) {
        foreach ($r in @(Get-PimDesiredRows -Entity $e)) {
            $gn = Get-PimRowProp -Row $r -Names @('GroupName'); if (-not $gn) { continue }
            $life = "$(Get-PimRowProp -Row $r -Names @('Lifecycle'))".Trim()
            if (-not $IncludeRetired -and $life -match '(?i)^retire') { continue }
            $list.Add([pscustomobject]@{
                GroupName             = $gn
                GroupTag              = (Get-PimRowProp -Row $r -Names @('GroupTag'))
                GroupDescription      = (Get-PimRowProp -Row $r -Names @('GroupDescription'))
                IsRoleAssignable      = (Get-PimRowProp -Row $r -Names @('IsRoleAssignable'))
                AdministrativeUnitTag = (Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag'))
                Owners                = (Get-PimRowProp -Row $r -Names @('Owners'))
                SponsorUpn            = (Get-PimRowProp -Row $r -Names @('SponsorUpn'))
                Department            = (Get-PimRowProp -Row $r -Names @('Department','DepartmentTag'))
                PolicyTemplate        = (Get-PimRowProp -Row $r -Names @('PolicyTemplate'))
                ReviewCycle           = (Get-PimRowProp -Row $r -Names @('ReviewCycle'))
                Workload              = (Get-PimRowProp -Row $r -Names @('Workload'))   # REQ-U: pairs the group with its workload binding
                # BUG-255: the former name(s) the Groups provider renames FROM. Dropped by this projection in 2.4.421, so the
                # released fix never saw it (live run 8 still made a second group) -- carried now, and pinned by the test.
                PreviousGroupName     = (Get-PimRowProp -Row $r -Names @('PreviousGroupName'))
                Lifecycle             = $life
                SourceEntity          = $e
            })
        }
    }
    $list.ToArray()
}

function Get-PimTagToGroupName {
    $h = @{}; foreach ($d in (Get-PimGroupDefinitionRows -IncludeRetired)) { $t = "$($d.GroupTag)"; if ($t) { $h[$t.ToLowerInvariant()] = $d.GroupName } }; $h
}
function Get-PimTagToAuName {
    $h = @{}; foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU')) {
        $t = Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag'); $n = Get-PimRowProp -Row $r -Names @('AUDisplayName')
        if ($t) { $h[$t.ToLowerInvariant()] = $n }
    }; $h
}

function Get-PimSolutionOwnedGroups {
    <#
      BUG-17. THE set of groups this solution owns, resolved to live ids.

      Why this exists: every assignment scope used to build its LIVE set out of the
      tags found in its own DESIRED rows. That makes desired and live the same
      universe, so an assignment whose desired row is DELETED stops being read -- and
      a prune, whose entire job is to remove exactly that, cannot see it. The orphan
      stays in the tenant forever and no report mentions it.

      The correct universe is not "what the assignment rows point at" but "the groups
      this solution manages", which comes from the group DEFINITIONS -- a different
      entity, owned by the Groups scope. Deleting an assignment row then leaves its
      live row plainly visible; deleting a GROUP is a separate operation with its own
      scope. That separation is what makes an assignment prune authoritative without
      making it able to reach anything the solution does not own.

      Returns @{ byId = @{ gid -> @{ id; name; tag } }; byTag = @{ tag -> gid } }.
      Cached with the same short TTL as the directory-role preload, so a long-running
      scheduler process picks up newly-created groups without re-resolving every scope.
    #>
    [CmdletBinding()] param([switch]$Force)
    if ($global:PIM_OwnedGroupsDirty) { $Force = $true; $global:PIM_OwnedGroupsDirty = $false }   # a group was created since (Add-PimContextObject)
    if (-not $Force -and $script:PimSolutionGroupsAt -and ((Get-Date) - $script:PimSolutionGroupsAt).TotalMinutes -lt 5) {
        return $script:PimSolutionGroups
    }
    $byId = @{}; $byTag = @{}
    foreach ($d in (Get-PimGroupDefinitionRows -IncludeRetired)) {
        $name = "$($d.GroupName)"; if (-not $name) { continue }
        $tag  = "$($d.GroupTag)"
        $gid  = Resolve-PimLiveGroupIdByName $name
        # No live id = the group has not been created yet (a first deploy, or the Groups
        # scope has not run). There is nothing live to reconcile for it, so it simply is
        # not in the live universe -- the assignment will be a create, which is right.
        if (-not $gid) { continue }
        $byId[$gid] = [pscustomobject]@{ id = $gid; name = $name; tag = $tag }
        if ($tag) { $byTag[$tag.ToLowerInvariant()] = $gid }
    }
    $script:PimSolutionGroups = [pscustomobject]@{ byId = $byId; byTag = $byTag }
    $script:PimSolutionGroupsAt = Get-Date
    Write-Host ("  [engine] solution-owned groups resolved: {0} of {1} defined" -f $byId.Count, @(Get-PimGroupDefinitionRows -IncludeRetired).Count) -ForegroundColor DarkGray
    return $script:PimSolutionGroups
}

function Test-PimNameAlreadyLive {
    <#
      BUG-18. Does an object with this displayName ALREADY exist? A DIRECT, freshly-read
      query -- never the context cache.

      Why: the engine decides create-vs-nochange from ONE bulk live LIST read, and Graph
      reads are not replica-pinned. A plan reported a scope fully converged and a real run
      four seconds later created the object AGAIN, because that call landed on a replica
      that had not caught up. Entra does not enforce unique displayName on AUs or groups,
      so the duplicate was accepted silently: no conflict, no error, errors=0. Observed
      three times in one session; the tenant then held two AUs with the same name, and
      since the engine KEYS on display name, every later run resolved that name to
      whichever copy a replica returned first.

      This is a CHECK, not a wait. A sleep or a retry delay would be guesswork about a
      window nobody can measure; one extra filtered read immediately before the POST is
      cheap, deterministic, and closes the case where the object demonstrably exists.
      It cannot close a window narrower than a single round-trip -- nothing can, short of
      a uniqueness constraint the directory does not offer -- so the caller treats a hit
      as validate-and-skip and carries on.

      Returns the existing object's id, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('group', 'administrativeUnit')][string]$Kind,
        [Parameter(Mandatory)][string]$DisplayName
    )
    $n = "$DisplayName".Trim(); if (-not $n) { return $null }
    $esc = $n -replace "'", "''"
    try {
        if ($Kind -eq 'group') {
            $r = @(Invoke-PimGraph -Headers @{ ConsistencyLevel = 'eventual' } -All `
                    -Path "/groups?`$filter=displayName eq '$esc'&`$count=true&`$select=id,displayName")
        } else {
            $r = @(Invoke-PimGraph -All -Path "/directory/administrativeUnits?`$filter=displayName eq '$esc'&`$select=id,displayName")
        }
        foreach ($o in $r) { if ($o -and "$($o.displayName)" -eq $n) { return "$($o.id)" } }
    } catch { Write-Verbose "existence probe ($Kind '$n'): $($_.Exception.Message)" }
    return $null
}

function Get-PimPreviousNames {
    <#
      PURE. The former display names a definition row carries (REQ-REN-1 / BUG-255): the Manager's rename action appends
      the old name to PreviousGroupName (groups) or PreviousAUDisplayName (AUs), '|'-separated, newest LAST. Returns them
      newest FIRST, trimmed, de-duplicated (case-insensitive), without the row's current name.
    #>
    param([object]$Row, [ValidateSet('group', 'administrativeUnit')][string]$Kind = 'group', [string]$CurrentName = '')
    $col = if ($Kind -eq 'group') { 'PreviousGroupName' } else { 'PreviousAUDisplayName' }
    $raw = "$(Get-PimRowProp -Row $Row -Names @($col))"
    $out = New-Object System.Collections.Generic.List[string]
    $parts = @($raw -split '\|' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    [array]::Reverse($parts)
    foreach ($p in $parts) {
        if ($CurrentName -and $p -ieq "$CurrentName".Trim()) { continue }
        if (@($out | Where-Object { $_ -ieq $p }).Count) { continue }
        $out.Add($p)
    }
    return $out.ToArray()   # unrolled on purpose: callers wrap in @() (a comma-return would nest the array)
}

function Invoke-PimRenameInPlace {
    <#
      🔴 BUG-255 (§78 live test, 2026-09-24) -- REQ-REN-1 says a rename is a RENAME, "not a delete+create". The engine keys
      groups and AUs on display name, so a renamed definition used to reach Entra as a NEW object while the old one kept
      every membership and role it held (scheduled runs never prune) -- privileged access left on an object nobody manages.
      Called by ApplyCreate AFTER the by-name check found nothing under the new name: if the row names a former name and
      an object with that name is live, PATCH its displayName (and a group's mailNickname) instead of creating. Newest
      former name first; the first one found wins. Returns the renamed object, or $null (then the caller creates).
    #>
    param([Parameter(Mandatory)][ValidateSet('group', 'administrativeUnit')][string]$Kind, [Parameter(Mandatory)][string]$NewName, [object]$Row)
    foreach ($old in @(Get-PimPreviousNames -Row $Row -Kind $Kind -CurrentName $NewName)) {
        $oid = Test-PimNameAlreadyLive -Kind $Kind -DisplayName $old
        if (-not $oid) { continue }
        if ($Kind -eq 'group') {
            [void](Invoke-PimGraph -Method PATCH -Path "/groups/$oid" -Body @{ displayName = $NewName; mailNickname = (Get-PimMailNickname $NewName) })
        } else {
            [void](Invoke-PimGraph -Method PATCH -Path "/directory/administrativeUnits/$oid" -Body @{ displayName = $NewName })
        }
        Write-Host ("    [~] {0} (RENAMED in place from '{1}' -- same object, memberships and roles kept)" -f $NewName, $old) -ForegroundColor Cyan
        $o = [pscustomobject]@{ id = $oid; displayName = $NewName; renamedFrom = $old }
        # The context cache de-duplicates by id (Merge-PimCacheItem), so the cached copy would keep the OLD name and every
        # later scope in this run would look the group up by a name it no longer has -- rename the cached copy itself.
        $var = if ($Kind -eq 'group') { 'Groups_All_ID' } else { 'AU_All_ID' }
        $hit = $false
        foreach ($c in @(Get-Variable -Scope Global -Name $var -ValueOnly -ErrorAction SilentlyContinue)) {
            foreach ($x in @($c)) {
                if ($x -and ("$($x.id)" -eq $oid -or "$($x.Id)" -eq $oid)) {
                    foreach ($pn in 'displayName', 'DisplayName') { if ($x.PSObject.Properties[$pn]) { $x.$pn = $NewName } }
                    $hit = $true
                }
            }
        }
        if (-not $hit -and (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue)) { Add-PimContextObject -Kind $(if ($Kind -eq 'group') { 'Group' } else { 'AU' }) -Object $o }
        if ($Kind -eq 'group') { $global:PIM_OwnedGroupsDirty = $true }
        return $o
    }
    return $null
}

function Resolve-PimLiveGroupIdByName {
    # Cache first (lean context holds only PIM-prefixed groups + engine-created ones); on a
    # miss, resolve ON-DEMAND by displayName (a 150k-group tenant is never bulk-listed) + cache.
    param([string]$Name)
    if (-not $Name) { return $null }
    $g = @($Global:Groups_All_ID) | Where-Object { "$($_.DisplayName)" -eq "$Name" } | Select-Object -First 1
    if ($g) { return "$($g.Id)" }
    try {
        $esc = $Name -replace "'", "''"
        $r = @(Invoke-PimGraph -Headers @{ ConsistencyLevel = 'eventual' } -All -Path "/groups?`$filter=displayName eq '$esc'&`$count=true&`$select=id,displayName,securityEnabled,mailNickname")
        if ($r.Count) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $r[0] }; return "$($r[0].id)" }
    } catch { Write-Verbose "group resolve ($Name): $($_.Exception.Message)" }
    return $null
}
function Get-PimAdminUpnDomain {
    # 🔑 REQ-T (2.4.377): THE DOMAIN AN ADMIN'S UPN IS BUILT AT, when the desired row carries only a bare UserName.
    # One resolver for every path that composes one (create, principal resolve, offboarding), in this order:
    #   1. $global:DefaultDomainUPN / $global:PIM_DefaultDomainUPN -- an explicit per-run pin (MSP fan-out, tests);
    #   2. THIS tenant's own "Admin account domain" setting -- the naming key AdminAccountUpnSuffix
    #      (Settings; blank = use the default domain, which is the v1 behaviour);
    #   3. the tenant's default verified domain (Get-PimTargetDefaultDomain).
    # Returns '' when none resolves; callers refuse rather than POST a domainless UPN.
    $dom = "$($global:DefaultDomainUPN)".Trim()
    if (-not $dom) { $dom = "$($global:PIM_DefaultDomainUPN)".Trim() }
    if (-not $dom -and (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue)) {
        try { $dom = "$(Get-PimNamingConvention -Key 'AdminAccountUpnSuffix')".Trim().TrimStart('@') } catch { $dom = '' }
    }
    if (-not $dom) { $dom = "$(Get-PimTargetDefaultDomain)".Trim() }
    return $dom
}
function Get-PimTargetDefaultDomain {
    # The TARGET tenant's default (primary) verified domain -- the tenant the engine
    # token currently authenticates to (Invoke-PimGraph always hits that tenant). Used
    # to build a UPN from a bare central UserName in the MSP master->slave flow, where
    # PIM-Assignments-Admins rows carry the bare UserName (e.g. PIMSCEN-Admin-...-ID),
    # not the per-tenant UPN. Resolved ONCE per run and cached (don't re-query per
    # principal). Returns $null on any failure (caller then falls through to unresolved).
    if ($script:__pimTargetDefaultDomain) { return $script:__pimTargetDefaultDomain }
    if ($script:__pimTargetDefaultDomainTried) { return $null }   # a REAL miss is cached; never re-query
    try {
        # BUG-20: this read `@($org) | Select-Object -First 1` and then $row.verifiedDomains.
        # Invoke-PimGraph (without -All) returns the RAW OData envelope -- @odata.context +
        # value -- so $row was the ENVELOPE, not the organization, and the isDefault lookup
        # found nothing. This function therefore returned $null in EVERY tenant, which meant
        # the MSP master->slave fallback it exists for (resolve a bare central UserName as
        # "{UserName}@{slave default domain}") had never once worked: every
        # PIM-Assignments-Admins row carrying a bare UserName failed "unresolved principal".
        # Admins.ApplyCreate already did the unwrap correctly -- the two had silently
        # diverged, which is why admin accounts got created at the right domain while the
        # assignment to them could not find them. Measured live: the old shape saw 1
        # "verifiedDomain" and no default; the unwrapped shape sees 3 and the real default.
        $org = Invoke-PimGraph -Path "/organization?`$select=verifiedDomains"
        $row = if ($org.value) { @($org.value)[0] } else { @($org) | Select-Object -First 1 }
        $def = @($row.verifiedDomains) | Where-Object { $_.isDefault } | Select-Object -First 1
        if (-not $def) { $def = @($row.verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1 }
        if ($def -and "$($def.name)") { $script:__pimTargetDefaultDomain = "$($def.name)"; return $script:__pimTargetDefaultDomain }
        # The query WORKED and the tenant genuinely has no default/initial domain: cache
        # that, it will not change mid-run.
        $script:__pimTargetDefaultDomainTried = $true
    } catch {
        # A THROWN query is transient (throttling, a dropped socket). Deliberately NOT
        # cached as a miss: with BUG-19 fixed the engine can run for the life of a
        # container, and one unlucky 429 must not disable admin resolution until restart.
        Write-Verbose "default-domain resolve: $($_.Exception.Message)"
    }
    return $null
}

function Reset-PimTargetDefaultDomainCache {
    # Test seam + the honest way for a caller that switches TARGET TENANT mid-process
    # (the MSP fanout does exactly that) to drop a domain resolved for the previous tenant.
    $script:__pimTargetDefaultDomain = $null
    $script:__pimTargetDefaultDomainTried = $false
}
function Resolve-PimPrincipalId {
    # Cache first; on a miss resolve ON-DEMAND by UPN (a 500k-user tenant is never bulk-listed)
    # + cache. GUIDs pass through. /users/{upn} returns a single object (not .value).
    # FALLBACK (MSP master->slave): when the value is a BARE username (no '@') and the
    # direct lookup yields nothing, retry once as "{UserName}@{targetTenantDefaultDomain}".
    # The fanout rewrites UserName->UPN when CREATING the slave account, but the desired
    # PIM-Assignments-Admins rows are not rewritten before engine-apply, so the assignment
    # carries the bare central UserName. The fallback ONLY triggers on a no-'@' value whose
    # primary resolution failed -- a real UPN or a value that resolves directly is unchanged.
    param([string]$UpnOrId)
    if (-not $UpnOrId) { return $null }
    if ($UpnOrId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return "$UpnOrId" }
    $u = @($Global:Users_All_ID) | Where-Object { "$($_.UserPrincipalName)" -eq "$UpnOrId" } | Select-Object -First 1
    if ($u) { return "$($u.Id)" }
    # NOTE (2026-08-09): a bare name can never match /users/{key}, so this first call always
    # 404s for the MSP master->slave case and writes a TerminatingError into the log of an
    # otherwise SUCCESSFUL run -- noise that caused a real misdiagnosis (see the retracted
    # BUG-35 in docs/REQUIREMENTS.md §33.9). Composing the UPN first was tried and REVERTED:
    # tests/Test-PimPrincipalResolveUpnFallback.ps1 deliberately pins this order
    # ("direct bare lookup tried first, then the UPN"), the behaviour is already correct, and
    # the only gain was tidier logs. Not worth overruling a deliberate assertion.
    try {
        $r = Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($UpnOrId))?`$select=id,userPrincipalName"
        if ($r.id) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $r }; return "$($r.id)" }
    } catch { Write-Verbose "user resolve ($UpnOrId): $($_.Exception.Message)" }
    # Fallback: bare username (no '@') that didn't resolve -> retry as UserName@defaultDomain.
    if ("$UpnOrId" -notmatch '@') {
        # REQ-T: an admin built at this tenant's Admin account domain is looked for THERE first, then at the
        # default domain (an account created before the setting was changed keeps its old UPN).
        foreach ($dom in @(@("$(Get-PimAdminUpnDomain)".Trim(), "$(Get-PimTargetDefaultDomain)".Trim()) | Where-Object { $_ } | Select-Object -Unique)) {
            $upn = "$UpnOrId@$dom"
            $cu = @($Global:Users_All_ID) | Where-Object { "$($_.UserPrincipalName)" -eq "$upn" } | Select-Object -First 1
            if ($cu) { return "$($cu.Id)" }
            try {
                $r2 = Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($upn))?`$select=id,userPrincipalName"
                if ($r2.id) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $r2 }; return "$($r2.id)" }
            } catch { Write-Verbose "user resolve fallback ($upn): $($_.Exception.Message)" }
        }
    }
    return $null
}

function Get-PimDepartmentOwnerIndex {
    # Department -> owner UPN list, from PIM-Definitions-Departments (Department + Owners),
    # so a group can inherit owners from its department when its own Owners column is blank.
    # Cached per run. Empty if the Departments table isn't present.
    if ($script:__pimDeptOwners) { return $script:__pimDeptOwners }
    $h = @{}
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Departments')) {
        $dept = Get-PimRowProp -Row $r -Names @('Department', 'DepartmentName', 'Name')
        $own  = Get-PimRowProp -Row $r -Names @('Owners', 'DeptOwner', 'DepartmentOwner', 'ManagerEmail')
        if ($dept) { $h[$dept.ToLowerInvariant()] = $own }
    }
    $script:__pimDeptOwners = $h; return $h
}

function Split-PimOwners {
    # Owners are pipe-joined UPNs per the Manager UX; also accept ; and , for safety.
    param([string]$Raw)
    @("$Raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Resolve-PimGroupOwnerIds {
    # Owner object-ids for a group definition row: Owners column -> SponsorUpn (Roles) ->
    # the group's Department contact (PIM-Definitions-Departments). UPN -> id; unresolved
    # owners are dropped. Returns @() when nothing resolves (caller enforces the rule).
    param([object]$Row, [hashtable]$Ctx = @{})
    $upns = @()
    $upns += Split-PimOwners (Get-PimRowProp -Row $Row -Names @('Owners'))
    if (-not $upns.Count) { $upns += Split-PimOwners (Get-PimRowProp -Row $Row -Names @('SponsorUpn')) }
    if (-not $upns.Count) {
        $dept = Get-PimRowProp -Row $Row -Names @('Department', 'DepartmentTag')
        if ($dept) { $di = Get-PimDepartmentOwnerIndex; if ($di.ContainsKey($dept.ToLowerInvariant())) { $upns += Split-PimOwners $di[$dept.ToLowerInvariant()] } }
    }
    $ids = New-Object System.Collections.Generic.List[object]
    foreach ($u in ($upns | Select-Object -Unique)) { $id = Resolve-PimPrincipalId $u; if ($id) { [void]$ids.Add($id) } }
    , $ids.ToArray()
}

function New-PimGroupMembershipBody {
    # PURE: PIM-for-Groups schedule-request body (accessId member/owner). Matches the
    # legacy Assign-User-PIM-PAG-Group shape; afterDuration instead of afterDateTime.
    param(
        [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
        [string]$AccessId = 'member', [switch]$Permanent, [int]$Days = 0,
        [string]$Action = 'adminAssign', [string]$Justification = 'PIM4EntraPS engine'
    )
    $exp = if ($Permanent -or $Days -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$Days" + 'D' } }
    @{ accessId = $AccessId; groupId = $GroupId; action = $Action; justification = $Justification; principalId = $PrincipalId
       scheduleInfo = @{ startDateTime = ([datetime]::UtcNow.ToString('o')); expiration = $exp } }
}

function Invoke-PimScheduleCreate {
    # POST a PIM schedule-request body, with a DURATION-LADDER fallback: PIM policies cap the
    # max eligible/active duration, and a request longer than the cap returns
    # RoleAssignmentRequestPolicyValidationFailed (ExpirationRule). On that specific error we
    # retry with progressively shorter afterDuration, then noExpiration -- so a data duration
    # that exceeds the tenant policy still lands at the policy max instead of failing.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Body)
    $sched = if ($Body.scheduleInfo) { $Body.scheduleInfo } elseif ($Body.properties) { $Body.properties.scheduleInfo } else { $null }
    try { return Invoke-PimGraph -Method POST -Path $Path -Body $Body }
    catch { if ("$($_.Exception.Message)" -notmatch '(?i)greater than maximum allowed duration|ExpirationRule') { throw } }
    foreach ($d in @(180, 90, 30, 0)) {
        if ($sched) { $sched.expiration = if ($d -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$d" + 'D' } } }
        try { return Invoke-PimGraph -Method POST -Path $Path -Body $Body }
        catch { if ("$($_.Exception.Message)" -notmatch '(?i)greater than maximum allowed duration|ExpirationRule') { throw } }
    }
    throw "schedule create still rejected after duration ladder ($Path)"
}

function Get-PimGroupSchedulePreload {
    # TENANT-WIDE preload of ALL PIM-for-Groups eligibility + assignment schedules, indexed
    # by groupId -- ported from Get-PimGroupSchedulesPreloaded (the func lib). One bulk read
    # (paged) instead of a per-group `$filter=groupId eq ...` round-trip. Cached 5 min.
    # 🔴 2026-09-20 -- SAME RULE AS Get-PimDirRoleSchedulePreload: a PARTIAL preload is not live state.
    # The catch used to warn and fall through to cache whatever had been collected, so an enumeration that
    # threw mid-paging left a SHORT index that AdminMembers / GroupMembers diffed as the tenant. A missing
    # live membership makes a targeted Action=Remove row look ALREADY GONE -- and an 'absent' Remove row is
    # completed and DELETED from pim.Rows, so the operator's committed revoke is silently thrown away and
    # never performed. Nothing is cached on failure, no time is stamped (the next call retries), and the
    # consumers turn the recorded reason into __pimLiveReadError (NOT CHECKED, nothing applied).
    param([switch]$Force)
    if (-not $Force -and $script:PimGrpSchedAt -and ((Get-Date) - $script:PimGrpSchedAt).TotalMinutes -lt 5) { return }
    $elig = @{}; $act = @{}
    $errs = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@{ ep = 'eligibilitySchedules'; idx = $elig }, @{ ep = 'assignmentSchedules'; idx = $act })) {
        try {
            foreach ($s in @(Invoke-PimGraph -Path "/identityGovernance/privilegedAccess/group/$($pair.ep)" -All)) {
                $gid = "$($s.groupId)"; if (-not $gid) { continue }
                if (-not $pair.idx.ContainsKey($gid)) { $pair.idx[$gid] = New-Object System.Collections.ArrayList }
                [void]$pair.idx[$gid].Add($s)
            }
        } catch { $errs.Add("$($pair.ep): $($_.Exception.Message)") }
    }
    if ($errs.Count) {
        $script:PimGrpSchedError = ($errs -join ' | ')
        $script:PimGrpElig = $null; $script:PimGrpAct = $null; $script:PimGrpSchedAt = $null
        Write-Warning ("  [engine] group schedule preload INCOMPLETE -- nothing is cached and the dependent scopes are NOT CHECKED this run: $($script:PimGrpSchedError)")
        return
    }
    $script:PimGrpSchedError = ''
    $script:PimGrpElig = $elig; $script:PimGrpAct = $act; $script:PimGrpSchedAt = Get-Date
    $ec = 0; foreach ($v in $elig.Values) { $ec += $v.Count }; $ac = 0; foreach ($v in $act.Values) { $ac += $v.Count }
    Write-Host ("  [perf] group schedules preloaded: $ec eligible + $ac active (tenant-wide)") -ForegroundColor DarkGray
}
function Get-PimLiveGroupMembership {
    # Eligible + Active PIM-for-Groups schedules for one group. NB: the group schedule list
    # endpoints REQUIRE a groupId/principalId filter (an unfiltered tenant-wide list now 400s
    # MissingParameters), so this is a per-group filtered query -- there is no valid bulk
    # preload for PIM-for-Groups (unlike directory roles). Cached per group per run.
    param([Parameter(Mandatory)][string]$GroupId, [string]$GroupTag)
    if (-not ($script:PimGrpMemCache -is [hashtable])) { $script:PimGrpMemCache = @{} }
    # Entries carry their read time. This cache had NO expiry: in the long-running scheduler a
    # group's membership was read once per container life, so a removal, an AutoExtend or a new
    # assignment was never seen again (68.6 rows 24/26 depend on a fresh read). Same 5-minute
    # bound as the directory-role preload; a write through this file drops the entry at once.
    $hit = $script:PimGrpMemCache[$GroupId]
    $ttl = if ($script:PimGrpMemCacheTtlMinutes -gt 0) { $script:PimGrpMemCacheTtlMinutes } else { 20 }
    if ($hit -is [hashtable] -and $hit.at -and ((Get-Date) - $hit.at).TotalMinutes -lt $ttl) {
        return @($hit.rows | ForEach-Object { $c = $_ | Select-Object *; $c.GroupTag = $GroupTag; $c })
    }
    # 🔴 2026-09-20 -- THIS WAS THE QUIETEST INSTANCE OF THE PARTIAL-READ BUG. The catch was
    # `Write-Verbose`, which is INVISIBLE by default: a failed read of a group's schedules became
    # "this group holds no memberships", was CACHED for 5 minutes, and was diffed as live state --
    # with nothing in the log at any level an operator sees. §70.21 already guards the NARROWED read
    # ("a narrowed answer that FAILED would hide live memberships -- a Remove row would read 'already
    # absent'"), and then falls back to THIS reader, which had the very defect the fallback exists to
    # avoid. A failure is now recorded, is NOT cached, and the scope reports NOT CHECKED.
    $out = New-Object System.Collections.Generic.List[object]
    $errs = New-Object System.Collections.Generic.List[string]
    foreach ($pair in $script:PimGroupSchedulePairs) {
        try {
            foreach ($s in @(Invoke-PimGraph -All -Path (Get-PimGroupSchedulePath -Endpoint $pair.ep -GroupId $GroupId))) {
                $out.Add((ConvertTo-PimLiveGroupMembershipRow -Schedule $s -GroupId $GroupId -GroupTag $GroupTag -AssignmentType $pair.type))
            }
        } catch { $errs.Add("$GroupTag/$($pair.type): $($_.Exception.Message)") }
    }
    if ($errs.Count) {
        $script:PimGrpMemError = (@(@("$($script:PimGrpMemError)".Trim()) + @($errs.ToArray())) | Where-Object { $_ }) -join ' | '
        Write-Warning ("  [engine] live membership read FAILED for group '$GroupTag' -- not cached, and its scope is NOT CHECKED this run: " + ($errs -join '; '))
        return @()      # never a partial list: an empty answer here would read as "no memberships"
    }
    $arr = $out.ToArray(); $script:PimGrpMemCache[$GroupId] = @{ at = (Get-Date); rows = $arr }; $arr
}

function Get-PimGroupScheduleReadError {
    <# '' when both group-schedule readers completed, else why not. Reset per scope by Clear-PimGroupScheduleReadError. #>
    return ((@("$($script:PimGrpSchedError)".Trim(), "$($script:PimGrpMemError)".Trim()) | Where-Object { $_ }) -join ' | ')
}
function Clear-PimGroupScheduleReadError {
    <# Called by a scope's GetLive BEFORE it reads, so one scope's failure cannot mark the next one NOT CHECKED. #>
    $script:PimGrpMemError = ''
}

$script:PimGroupSchedulePairs = @(@{ ep = 'eligibilitySchedules'; type = 'Eligible' }, @{ ep = 'assignmentSchedules'; type = 'Active' })
function Get-PimGroupSchedulePath {
    param([Parameter(Mandatory)][string]$Endpoint, [Parameter(Mandatory)][string]$GroupId)
    "/identityGovernance/privilegedAccess/group/$Endpoint`?`$filter=groupId eq '$GroupId'"
}
function ConvertTo-PimLiveGroupMembershipRow {
    # PURE: one PIM-for-Groups schedule -> the uniform live membership row both readers build.
    param([AllowNull()][object]$Schedule, [string]$GroupId, [string]$GroupTag, [string]$AssignmentType)
    $s = $Schedule
    # Schedule window (AutoExtend / UpdateExisting): scheduleInfo.startDateTime + expiration.
    $si = $s.scheduleInfo
    $known = ($null -ne $si -and "$($si.startDateTime)".Trim() -ne '')
    $expType = if ($si -and $si.expiration) { "$($si.expiration.type)" } else { '' }
    $end = if ($si -and $si.expiration) { $si.expiration.endDateTime } else { $null }
    if ($known -and -not "$end".Trim() -and $expType -ieq 'afterDuration' -and "$($si.expiration.duration)".Trim()) {
        try { $end = (ConvertTo-PimAssignmentUtc $si.startDateTime).Add([System.Xml.XmlConvert]::ToTimeSpan("$($si.expiration.duration)")).ToString('o') } catch { $end = $null }
    }
    [pscustomobject]@{ principalId = "$($s.principalId)"; accessId = "$($s.accessId)"; GroupTag = $GroupTag; AssignmentType = $AssignmentType
        groupId = $GroupId; graphAssignmentType = "$($s.assignmentType)"
        scheduleKnown = $known; startDateTime = $(if ($si) { $si.startDateTime } else { $null }); endDateTime = $end; expirationType = $expType }
}

function Initialize-PimGroupMembershipCache {
    <#
      PERFORMANCE (2026-09-13, internal): AdminMembers and GroupMembers each read every solution-owned group
      one filtered request at a time -- 342 groups x (eligibility + assignment) = 684 sequential calls, ~7 min
      per scope, which is most of why a tick took 25-50 minutes. The SAME filtered requests now go through
      Graph /$batch (20 per round-trip), and the answers land in the cache Get-PimLiveGroupMembership already
      reads, so its rows are built from identical responses by identical code. Only groups without a fresh
      entry are read. 'GraphBatchReads' = false restores the one-by-one loop.
    #>
    param([Parameter(Mandatory)][hashtable]$GroupTagById)
    if (-not ($script:PimGrpMemCache -is [hashtable])) { $script:PimGrpMemCache = @{} }
    if (-not (Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue) -or -not (Test-PimGraphBatchReadsEnabled)) { return 0 }
    $now = Get-Date
    $ttl = if ($script:PimGrpMemCacheTtlMinutes -gt 0) { $script:PimGrpMemCacheTtlMinutes } else { 20 }
    $need = New-Object System.Collections.Generic.List[string]
    foreach ($gid in @($GroupTagById.Keys)) {
        $hit = $script:PimGrpMemCache["$gid"]
        if ($hit -is [hashtable] -and $hit.at -and ($now - $hit.at).TotalMinutes -lt $ttl) { continue }
        $need.Add("$gid")
    }
    if ($need.Count -eq 0) { return 0 }
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($gid in $need) { foreach ($pair in $script:PimGroupSchedulePairs) { $paths.Add((Get-PimGroupSchedulePath -Endpoint $pair.ep -GroupId $gid)) } }
    $res = Invoke-PimGraphBatchGet -Paths $paths.ToArray()
    $i = 0
    foreach ($gid in $need) {
        $tag = "$($GroupTagById[$gid])"
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($pair in $script:PimGroupSchedulePairs) {
            $r = $res[$i]; $i++
            if (-not $r -or -not $r.ok) { if ($r) { Write-Verbose "group membership ($tag/$($pair.type)): $($r.error)" }; continue }
            foreach ($s in @($r.items)) { $rows.Add((ConvertTo-PimLiveGroupMembershipRow -Schedule $s -GroupId $gid -GroupTag $tag -AssignmentType $pair.type)) }
        }
        $script:PimGrpMemCache[$gid] = @{ at = (Get-Date); rows = $rows.ToArray() }
    }
    Write-Host ("  [perf] group memberships read in batches: {0} group(s), {1} request(s), {2} round-trip(s)" -f $need.Count, $paths.Count, [Math]::Ceiling($paths.Count / 20)) -ForegroundColor DarkGray
    return $need.Count
}

function Test-PimNarrowDeltaMembershipReadsEnabled {
    # Kill switch for the by-principal membership read (pim.Settings / $global:PIM_ / env 'NarrowDeltaMembershipReads').
    # ON by default; 'false' makes AdminMembers/GroupMembers read every solution-owned group again in every mode.
    $v = $null
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { try { $v = Get-PimPolicySetting -Name 'NarrowDeltaMembershipReads' -Default $null } catch { $v = $null } }
    elseif ($null -ne $global:PIM_NarrowDeltaMembershipReads) { $v = $global:PIM_NarrowDeltaMembershipReads }
    elseif ("$env:PIM_NarrowDeltaMembershipReads".Trim()) { $v = $env:PIM_NarrowDeltaMembershipReads }
    return -not ("$v".Trim() -match '^(?i)(false|0|no|off|disabled?)$')
}

function Get-PimGroupSchedulePrincipalPath {
    param([Parameter(Mandatory)][string]$Endpoint, [Parameter(Mandatory)][string]$PrincipalId)
    "/identityGovernance/privilegedAccess/group/$Endpoint`?`$filter=principalId eq '$PrincipalId'"
}

function Get-PimLiveGroupMembershipsByPrincipal {
    <#
      PERFORMANCE (2026-09-13, internal): a cold tick spent ~4.5 min in AdminMembers (and GroupMembers the same)
      reading the schedules of all 346 solution-owned groups -- 692 filtered requests, 1,262 of them throttled.
      That universe exists for BUG-17: a PRUNE must see live memberships whose desired row was deleted.
      When the scope CANNOT prune (Delta, or Full without -Prune -- Invoke-PimEngineScope sets
      $Context['__pimLiveNarrow']), every removal Compare-PimDesiredVsLive can produce (type change, type
      leftover, targeted Remove row) names a principal that a desired or Remove row names. Reading only those
      principals therefore gives the SAME diff for a fraction of the requests.

      Graph answers `$filter=principalId eq '<id>'` across ALL groups (multi-group filters 400), so this is one
      request per principal per endpoint. Rows are built by the same PURE ConvertTo-PimLiveGroupMembershipRow;
      schedules of groups the solution does not own are DROPPED; output is ordered like the per-group reader
      (owned-group order, Eligible then Active). Nothing is written to $script:PimGrpMemCache -- that cache is
      per GROUP and must stay complete for the prune path.
      Returns { rows; principals; requests }.
    #>
    param(
        [AllowEmptyCollection()][AllowNull()][string[]]$PrincipalIds = @(),
        [Parameter(Mandatory)][object]$Owned,
        [string]$Scope = '',
        [string]$Reason = 'no prune'
    )
    $ids = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($p in @($PrincipalIds)) {
        $v = "$p".Trim(); if (-not $v) { continue }
        $lk = $v.ToLowerInvariant(); if ($seen.ContainsKey($lk)) { continue }
        $seen[$lk] = $true; $ids.Add($v)
    }
    $ownedByLower = @{}
    foreach ($g in @($Owned.byId.Keys)) { $ownedByLower["$g".ToLowerInvariant()] = "$g" }
    $pathIdx = New-Object System.Collections.Generic.List[object]   # { path; principal; pair }
    foreach ($id in $ids) {
        foreach ($pair in $script:PimGroupSchedulePairs) {
            $pathIdx.Add([pscustomobject]@{ path = (Get-PimGroupSchedulePrincipalPath -Endpoint $pair.ep -PrincipalId $id); principal = $id; pair = $pair })
        }
    }
    $answers = New-Object object[] $pathIdx.Count
    if ($pathIdx.Count -gt 0) {
        if ((Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue) -and (Test-PimGraphBatchReadsEnabled)) {
            # Invoke-PimGraphBatchGet follows @odata.nextLink per sub-response, retries throttling, falls back to singles.
            $res = Invoke-PimGraphBatchGet -Paths @($pathIdx | ForEach-Object { $_.path })
            for ($i = 0; $i -lt $pathIdx.Count; $i++) { $answers[$i] = $res[$i] }
        } else {
            for ($i = 0; $i -lt $pathIdx.Count; $i++) {
                try { $answers[$i] = [pscustomobject]@{ ok = $true; items = @(Invoke-PimGraph -All -Path $pathIdx[$i].path); error = $null } }
                catch { $answers[$i] = [pscustomobject]@{ ok = $false; items = @(); error = "$($_.Exception.Message)" } }
            }
        }
    }
    $failedN = 0
    $bucket = @{}   # "<owned gid>|<type>" -> rows, in answer order
    for ($i = 0; $i -lt $pathIdx.Count; $i++) {
        $r = $answers[$i]; $x = $pathIdx[$i]
        if (-not $r -or -not $r.ok) { $failedN++; if ($r) { Write-Verbose "group membership by principal ($($x.principal)/$($x.pair.type)): $($r.error)" }; continue }
        foreach ($s in @($r.items)) {
            if ($null -eq $s) { continue }
            # Graph returns only this principal's schedules; checked anyway so a host that ignores the filter
            # cannot hand one principal's rows to another (or duplicate them across principals).
            $sp = "$($s.principalId)"
            if ($sp -and $sp -ine $x.principal) { continue }
            $gk = "$($s.groupId)".ToLowerInvariant()
            if (-not $gk -or -not $ownedByLower.ContainsKey($gk)) { continue }   # not a solution-owned group
            $gid = $ownedByLower[$gk]
            $bk = "$gid|$($x.pair.type)"
            if (-not $bucket.ContainsKey($bk)) { $bucket[$bk] = New-Object System.Collections.Generic.List[object] }
            $bucket[$bk].Add((ConvertTo-PimLiveGroupMembershipRow -Schedule $s -GroupId $gid -GroupTag "$($Owned.byId[$gid].tag)" -AssignmentType $x.pair.type))
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($gid in @($Owned.byId.Keys)) {
        foreach ($pair in $script:PimGroupSchedulePairs) {
            $bk = "$gid|$($pair.type)"
            if ($bucket.ContainsKey($bk)) { foreach ($row in $bucket[$bk]) { $rows.Add($row) } }
        }
    }
    Write-Host ("  [perf] {0} live read narrowed to {1} principal(s): {2} request(s) ({3})" -f $Scope, $ids.Count, $pathIdx.Count, $Reason) -ForegroundColor DarkGray
    return [pscustomobject]@{ rows = $rows.ToArray(); principals = $ids.Count; requests = $pathIdx.Count; failed = $failedN }
}

function Get-PimNarrowConfirmGroupIds {
    <#
      PURE. §70.21: which owned groups a narrowed (principal) read must CONFIRM with a per-group read.
      🔴 Measured on internal 2026-09-13: Graph's principalId-filtered PIM-for-Groups schedule list omits some schedules
      the groupId-filtered list returns (3 of 61 nestings of one role group, all created 2026-03-02) -- so "not in the
      principal read" does NOT mean "not live". A desired row the principal read did not answer, and EVERY Remove row
      (a removal must never read "already absent" from an incomplete list), names a group to re-read by group.
      -Pairs: { principal; tag; remove }. -LiveRows: the filtered principal-read rows. Returns owned group ids, in order.
    #>
    param([object[]]$Pairs = @(), [object[]]$LiveRows = @(), [Parameter(Mandatory)][object]$Owned)
    $have = @{}
    foreach ($m in @($LiveRows)) { if ($null -ne $m) { $have[("$($m.principalId)|$($m.groupId)").ToLowerInvariant()] = $true } }
    $out = New-Object System.Collections.Generic.List[string]; $seen = @{}
    foreach ($p in @($Pairs)) {
        if ($null -eq $p) { continue }
        $t = "$($p.tag)".Trim().ToLowerInvariant(); if (-not $t) { continue }
        $gid = $Owned.byTag[$t]; if (-not $gid) { continue }   # group not created yet: nothing live to confirm
        $hit = $have.ContainsKey(("$($p.principal)|$gid").ToLowerInvariant())
        if ($hit -and -not $p.remove) { continue }
        if (-not $seen.ContainsKey("$gid")) { $seen["$gid"] = $true; $out.Add("$gid") }
    }
    return $out.ToArray()   # callers wrap in @()
}

function Add-PimConfirmedGroupMemberships {
    <#
      §70.21: re-read the groups Get-PimNarrowConfirmGroupIds names BY GROUP (the complete list) and add the membership
      rows the principal read missed, filtered by the caller's -Keep. Goes through the per-group cache (a per-group read
      is complete, so caching it is correct). Returns the number of rows added; logs one [perf] line when it re-read.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Live, [object[]]$Pairs = @(), [Parameter(Mandatory)][object]$Owned,
          [Parameter(Mandatory)][scriptblock]$Keep, [string]$Scope = '')
    $gids = @(Get-PimNarrowConfirmGroupIds -Pairs @($Pairs) -LiveRows @($Live.ToArray()) -Owned $Owned)
    if (-not $gids.Count) { return 0 }
    $key = { param($m) ("$($m.principalId)|$($m.groupId)|$($m.AssignmentType)|$($m.accessId)|$($m.graphAssignmentType)").ToLowerInvariant() }
    $seen = @{}; foreach ($m in $Live) { $seen[(& $key $m)] = $true }
    $tagById = @{}; foreach ($g in $gids) { $tagById[$g] = "$($Owned.byId[$g].tag)" }
    [void](Initialize-PimGroupMembershipCache -GroupTagById $tagById)
    $added = 0
    foreach ($g in $gids) {
        foreach ($m in @(Get-PimLiveGroupMembership -GroupId $g -GroupTag "$($tagById[$g])")) {
            if ($null -eq $m) { continue }
            if (-not "$($m.groupId)") { Add-Member -InputObject $m -NotePropertyName groupId -NotePropertyValue $g -Force }
            if (-not (& $Keep $m)) { continue }
            $k = & $key $m
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true; $Live.Add($m); $added++
        }
    }
    Write-Host ("  [perf] {0} confirmed {1} group(s) by group read ({2} membership(s) the principal read did not return)" -f $Scope, $gids.Count, $added) -ForegroundColor DarkGray
    return $added
}

function Get-PimDirRoleSchedulePreload {
    # TENANT-WIDE preload of ALL directory role eligibility + assignment SCHEDULE INSTANCES,
    # indexed by principalId (the PIM group). One bulk read instead of per-group filters.
    #
    # 🔴 INSTANCES, NOT SCHEDULES -- and this is a correctness fix, not a preference.
    # This used to read /roleEligibilitySchedules + /roleAssignmentSchedules. An UNFILTERED
    # enumeration of those collections is INCOMPLETE: measured on myfamilynetwork 2026-08-10,
    #     roleAssignmentSchedules          total=613  AU-scoped=359  -> row ABSENT
    #     roleAssignmentScheduleInstances  total=602  AU-scoped=346  -> row PRESENT
    # for an assignment that a per-principal `$filter=principalId eq '<id>'` query on the SAME
    # schedules endpoint DID return. So the bulk read silently dropped rows that exist.
    # Consequence: RolesAUs re-planned 17 already-existing assignments as CREATEs on every single
    # run and skipped them at apply ("exists -- validated, skipped"). Harmless writes, but the scope
    # could never reach a steady state, so an operator could never tell "nothing to do" from
    # "17 things to do" -- on the scope that grants AU-scoped admin rights.
    # INSTANCES are also the semantically correct source for LIVE STATE: an instance is what is
    # currently in effect, whereas a schedule object can be expired or superseded (hence 602 < 613).
    # 🔴 2026-09-20 -- A PARTIAL PRELOAD IS NOT LIVE STATE, AND IT USED TO BE TREATED AS ONE.
    # The catch below only WARNED and then fell through to cache whatever had been collected so far,
    # so an enumeration that threw MID-PAGING (throttling, a transient 5xx, a dropped nextLink) left a
    # SHORT index that every consumer diffed as though it were the tenant.
    # MEASURED on internal 2026-09-19 23:33 UTC: EntraRoles read live=247 where the runs at 23:07 and at
    # 05:11/05:22/05:39 the next morning all read live=254 -- short by 7. Nine desired 'Eligible' rows on
    # Entra-ID-Bundle-GlobalRoles-L1 therefore lost their live match, paired instead with their live
    # 'Active' counterpart by the type-neutral key, and were planned as TYPE CHANGES -- each of which
    # DELETES the live Active assignment first. The per-scope removal budget (5) stopped all 9 and mailed
    # "REMOVAL BUDGET tripped -- 9 remove blocked". Nothing was removed, but only because 9 > 5: at 4 the
    # engine would have deleted four real assignments, silently, on a read that was simply incomplete.
    # 🔒 This is the rule Invoke-PimEngineScope already states for providers ("an empty live set is NOT
    # 'nothing there'"): a live read that FAILED must say so, never hand back what it managed to collect.
    # So a failure now caches NOTHING, stamps NO time (the next call retries) and records the reason; the
    # three consumers (EntraRoles, RolesAUs, EntraRolesDirect) turn that into __pimLiveReadError, i.e. the
    # scope is NOT CHECKED and applies nothing at all.
    param([switch]$Force)
    if (-not $Force -and $script:PimDirSchedAt -and ((Get-Date) - $script:PimDirSchedAt).TotalMinutes -lt 5) { return }
    $elig = @{}; $act = @{}
    $errs = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@{ ep = 'roleEligibilityScheduleInstances'; idx = $elig }, @{ ep = 'roleAssignmentScheduleInstances'; idx = $act })) {
        try {
            foreach ($s in @(Invoke-PimGraph -Path "/roleManagement/directory/$($pair.ep)?`$expand=roleDefinition" -All)) {
                $pp = "$($s.principalId)"; if (-not $pp) { continue }
                if (-not $pair.idx.ContainsKey($pp)) { $pair.idx[$pp] = New-Object System.Collections.ArrayList }
                [void]$pair.idx[$pp].Add($s)
            }
        } catch { $errs.Add("$($pair.ep): $($_.Exception.Message)") }
    }
    if ($errs.Count) {
        $script:PimDirSchedError = ($errs -join ' | ')
        # Drop any earlier cache too: a stale-but-complete index is still not THIS run's live state, and
        # silently diffing against it is the same class of mistake by a different route.
        $script:PimDirElig = $null; $script:PimDirAct = $null; $script:PimDirSchedAt = $null
        Write-Warning ("  [engine] directory role schedule preload INCOMPLETE -- nothing is cached and the dependent scopes are NOT CHECKED this run: $($script:PimDirSchedError)")
        return
    }
    $script:PimDirSchedError = ''
    $script:PimDirElig = $elig; $script:PimDirAct = $act; $script:PimDirSchedAt = Get-Date
    $ec = 0; foreach ($v in $elig.Values) { $ec += $v.Count }; $ac = 0; foreach ($v in $act.Values) { $ac += $v.Count }
    Write-Host ("  [perf] directory role schedules preloaded: $ec eligible + $ac active (tenant-wide)") -ForegroundColor DarkGray
}

function Get-PimDirRoleScheduleReadError {
    <#
      '' when the last directory role schedule preload completed, else why it did not. The scopes that
      diff against the preload (EntraRoles, RolesAUs, EntraRolesDirect) read this and refuse to compare
      rather than compare against a short index -- see Get-PimDirRoleSchedulePreload for the incident.
    #>
    return "$($script:PimDirSchedError)"
}
function Get-PimLiveDirRoleSchedules {
    # Directory role schedules for one principal (group) from the preload -> uniform rows.
    # 🔴 THROWS when the preload did not complete. Returning an empty list would say "this group holds no
    # role" to a caller that cannot tell that from "the read failed" -- and the diff turns that into
    # removals. The three engine consumers check Get-PimDirRoleScheduleReadError BEFORE they call this and
    # mark their scope NOT CHECKED; this throw is for every other caller, now and later.
    param([Parameter(Mandatory)][string]$PrincipalId)
    Get-PimDirRoleSchedulePreload
    $__pe = Get-PimDirRoleScheduleReadError
    if ($__pe) { throw "Get-PimLiveDirRoleSchedules: the directory role schedule preload is INCOMPLETE ($__pe) -- refusing to report live state for principal '$PrincipalId'." }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(@{ idx = $script:PimDirElig; type = 'Eligible' }, @{ idx = $script:PimDirAct; type = 'Active' })) {
        if ($pair.idx -and $pair.idx.ContainsKey($PrincipalId)) {
            # graphAssignmentType ('Assigned'|'Activated') and the start/end window are ADDITIVE fields
            # for the assignment scopes (68.6 rows 25-26): an activation is not an assignment, and
            # AutoExtend needs the live expiry.
            foreach ($s in $pair.idx[$PrincipalId]) { $out.Add([pscustomobject]@{ principalId = $PrincipalId; RoleDefinitionName = "$($s.roleDefinition.displayName)"; AssignmentType = $pair.type; roleDefinitionId = "$($s.roleDefinitionId)"; directoryScopeId = "$($s.directoryScopeId)"
                graphAssignmentType = "$($s.assignmentType)"; scheduleKnown = [bool]("$($s.startDateTime)".Trim()); startDateTime = $s.startDateTime; endDateTime = $s.endDateTime }) }
        }
    }
    $out.ToArray()
}

# ---------------------------------------------------------------------------
# AdministrativeUnits scope -- create the AUs (PIM-Definitions-AU) groups attach to.
# ---------------------------------------------------------------------------
function Get-PimLiveAdministrativeUnitsDetailed {
    # The AU live set WITH description + visibility (the directory cache selects neither
    # description nor a guaranteed visibility). One list read; on any failure fall back to the
    # cache, which still supports create -- only the update detection is skipped, and SAID so.
    $cache = @($Global:AU_All_ID | Where-Object { $_ })
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return $cache }
    try {
        $rows = @(Invoke-PimGraph -All -Path "/directory/administrativeUnits?`$select=id,displayName,description,visibility")
        return @($rows | Where-Object { $_ -and "$($_.displayName)" })
    } catch {
        Write-Warning "  [engine] AdministrativeUnits: detailed read failed ($($_.Exception.Message)) -- using the directory cache; description/visibility changes are NOT detected this run."
        return $cache
    }
}

function Get-PimAdministrativeUnitPatch {
    <#
      PURE. The PATCH body that brings a live AU to its definition -- description and visibility
      only; displayName is the key and is never written. A property the live row does not carry
      (not read) is never compared, and a blank desired value is "not managed" (never clears).
    #>
    param([object]$Desired, [object]$Live)
    $patch = @{}
    if ($null -eq $Desired -or $null -eq $Live) { return $patch }
    $dd = "$(Get-PimRowProp -Row $Desired -Names @('AUDescription'))".Trim()
    if ($dd -and $Live.PSObject.Properties['description'] -and ($dd -cne "$($Live.description)".Trim())) { $patch['description'] = $dd }
    $dv = "$(Get-PimRowProp -Row $Desired -Names @('Visibility'))".Trim()
    if ($dv -and $Live.PSObject.Properties['visibility']) {
        $norm = { param($v) $s = "$v".Trim(); if (-not $s -or $s -ieq 'Public') { 'public' } elseif ($s -match '(?i)^hidden') { 'hiddenmembership' } else { $s.ToLowerInvariant() } }
        if ((& $norm $dv) -ne (& $norm $Live.visibility)) { $patch['visibility'] = $(if ((& $norm $dv) -eq 'hiddenmembership') { 'HiddenMembership' } elseif ((& $norm $dv) -eq 'public') { 'Public' } else { $dv }) }
    }
    return $patch
}

function New-PimAdministrativeUnitsProvider {
    @{
        scope = 'AdministrativeUnits'; entity = 'PIM-Definitions-AU'; order = 10
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU' | Where-Object { Get-PimRowProp -Row $_ -Names @('AUDisplayName') }) }
        GetLive    = { param($ctx) Ensure-PimContextLoaded; @(Get-PimLiveAdministrativeUnitsDetailed) }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('AUDisplayName', 'DisplayName', 'displayName') }
        # 68.6 row 27 (b): was existence-only, so an edited AUDescription / Visibility never reached
        # Entra. The display name is the KEY and is never written by an update.
        Equal = { param($d, $l) (Get-PimAdministrativeUnitPatch -Desired $d -Live $l).Count -eq 0 }
        ApplyUpdate = {
            param($item, $ctx)
            $patch = Get-PimAdministrativeUnitPatch -Desired $item.desired -Live $item.live
            if ($patch.Count -eq 0) { return [pscustomobject]@{ pimApplied = $false; reason = 'nothing to update' } }
            $auId = "$($item.live.id)"; if (-not $auId) { $auId = "$($item.live.Id)" }
            if (-not $auId) { throw "AdministrativeUnits: cannot update '$($item.key)' -- the live AU has no id" }
            try { $r = Invoke-PimGraph -Method PATCH -Path "/directory/administrativeUnits/$auId" -Body $patch }
            catch {
                # If Entra refuses the VISIBILITY change, still apply the description rather than neither.
                if (-not ($patch.ContainsKey('visibility') -and "$($_.Exception.Message)" -match '(?i)visibility')) { throw }
                Write-Warning ("  [engine] AdministrativeUnits: '{0}' visibility change refused by Entra ({1}) -- applying the description only." -f $item.key, $_.Exception.Message)
                $patch.Remove('visibility')
                if ($patch.Count -eq 0) { return [pscustomobject]@{ pimApplied = $false; reason = "Entra refused the visibility change: $($_.Exception.Message)" } }
                $r = Invoke-PimGraph -Method PATCH -Path "/directory/administrativeUnits/$auId" -Body $patch
            }
            foreach ($k in @($patch.Keys)) { try { $item.live.$k = $patch[$k] } catch { Write-Verbose "AU cache refresh ($k): $($_.Exception.Message)" } }
            $r
        }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            # BUG-18: the diff said "create" from a bulk list read that may have been served
            # by a lagging replica. Re-check by name, directly, immediately before writing --
            # Entra does not enforce unique displayName, so without this a second run inside
            # the replication window silently makes a DUPLICATE and the engine (which keys on
            # display name) can never tell the two apart again.
            $existing = Test-PimNameAlreadyLive -Kind administrativeUnit -DisplayName "$($item.key)"
            if ($existing) {
                Write-Host ("    [=] {0} (already exists -- validated, skipped)" -f $item.key) -ForegroundColor DarkGray
                $au = [pscustomobject]@{ id = $existing; displayName = "$($item.key)" }
                if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind AU -Object $au }
                return $au
            }
            # BUG-255 / REQ-REN-1: a renamed AU renames the AU it already has (its members and scoped roles stay).
            $ren = Invoke-PimRenameInPlace -Kind administrativeUnit -NewName "$($item.key)" -Row $d
            if ($ren) { return $ren }
            $vis = Get-PimRowProp -Row $d -Names @('Visibility'); if (-not $vis) { $vis = 'Public' }
            $au = Invoke-PimGraph -Method POST -Path '/directory/administrativeUnits' -Body @{
                displayName = "$($item.key)"; description = (Get-PimRowProp -Row $d -Names @('AUDescription')); visibility = $vis
            }
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind AU -Object $au }   # incremental cache
            # TEST-16: remember that THIS pass created it, so AdministrativeUnitMembers (order 22)
            # can tell replication lag from a genuinely missing AU. Only here -- the already-exists
            # branch above returns early and deliberately does not register.
            Register-PimAuCreatedThisPass -Context $ctx -AuId "$($au.id)" -AuName "$($item.key)"
            $au
        }
    }
}

# ---------------------------------------------------------------------------
# TEST-16 -- a freshly-created AU 404s when the SAME pass attaches its members.
#
# Measured on the run that CREATED the two scenario AUs: `AdministrativeUnits` (order 10)
# reported `create=2 errors=0`, and `AdministrativeUnitMembers` (order 22) -- later in the SAME
# pass -- got `Request_ResourceNotFound` for both the read and the write of those brand-new AU
# ids. Entra had not yet made them servable.
#
# 🪤 THE DISTINCTION IS THE WHOLE FIX, and it is why this is not just "retry 404s". A 404 on an
# AU this pass created is REPLICATION LAG and will resolve on its own. A 404 on an AU it did NOT
# create is a REAL missing-object signal -- the object was deleted, or the id is wrong -- and
# retrying that one only delays an accurate error. So the retry is gated on provenance, not on
# the status code.
#
# Impact was already bounded (BUG-16's reconciling scope repairs it next run, and the failure is
# REPORTED, not swallowed) -- but a first-ever deploy into a new customer tenant ended with AU
# membership unapplied and a red count, which reads as a broken deploy.
# ---------------------------------------------------------------------------
function Register-PimAuCreatedThisPass {
    # Record an AU that THIS pass genuinely created. Deliberately NOT called for the
    # already-exists validate-skip path in ApplyCreate: that AU predates the run, so a later
    # 404 on it is a real signal and must not be retried away.
    param([hashtable]$Context, [string]$AuId, [string]$AuName)
    if ($null -eq $Context -or -not "$AuId".Trim()) { return }
    if (-not $Context.ContainsKey('auCreatedThisPass') -or $null -eq $Context['auCreatedThisPass']) {
        $Context['auCreatedThisPass'] = @{}
    }
    $Context['auCreatedThisPass']["$AuId"] = "$AuName"
}
function Test-PimAuCreatedThisPass {
    # PURE: did this pass create that AU?
    param([hashtable]$Context, [string]$AuId)
    if ($null -eq $Context -or -not "$AuId".Trim()) { return $false }
    $set = $Context['auCreatedThisPass']
    if ($null -eq $set) { return $false }
    return [bool]$set.ContainsKey("$AuId")
}
function Test-PimGraphNotFound {
    # PURE: is this failure a Graph 404? Matched on both the status and the error code, because
    # only one of the two is present depending on which layer surfaced it.
    param([string]$Message)
    return ("$Message" -match '(?i)HTTP\s*404|\bRequest_ResourceNotFound\b|ResourceNotFound')
}
function Invoke-PimAuReplicationRetry {
    <#
      Run $Action. If it fails with a 404 AND $AuId is an AU this pass created, wait and retry;
      otherwise rethrow immediately.

      -DelaySeconds is a parameter so the offline tests can drive the whole retry loop with 0 --
      a test that has to sleep to prove a backoff either takes seconds or gets deleted.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [hashtable]$Context,
        [string]$AuId,
        [string]$What = 'AU operation',
        [int]$MaxAttempts = 4,
        [int]$DelaySeconds = 5
    )
    for ($attempt = 1; ; $attempt++) {
        try { return (& $Action) }
        catch {
            $msg = "$($_.Exception.Message)"
            $retryable = (Test-PimGraphNotFound $msg) -and (Test-PimAuCreatedThisPass -Context $Context -AuId $AuId)
            if (-not $retryable -or $attempt -ge $MaxAttempts) { throw }
            Write-Host ("    [engine] {0}: AU {1} was created THIS pass and is not servable yet (404) -- retrying in {2}s ({3}/{4})." -f `
                        $What, $AuId, $DelaySeconds, $attempt, ($MaxAttempts - 1)) -ForegroundColor DarkGray
            if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }
        }
    }
}

# ---------------------------------------------------------------------------
# Groups scope -- create the delegation groups from ALL definition entities
# (Roles/Services/Organization/Tasks). isAssignableToRole from IsRoleAssignable;
# attach to its AU; add owners. Ported from Create-PIM-Group-Role / CreateUpdate-PIM-Group.
# ---------------------------------------------------------------------------
function Get-PimGroupDescriptionPatch {
    <#
      PURE. @{ description = ... } when the definition's GroupDescription differs from the live
      group, else @{}. Never displayName / mailNickname (a PIM group is never renamed). Only
      compared when the live object was READ with its description (objects cached from a
      by-name probe carry no description property and are never "different"); a blank desired
      description is not managed (Graph rejects an empty description, and blank never clears).
    #>
    param([object]$Desired, [object]$Live)
    $patch = @{}
    if ($null -eq $Desired -or $null -eq $Live) { return $patch }
    $dd = "$(Get-PimRowProp -Row $Desired -Names @('GroupDescription'))".Trim()
    if (-not $dd -or -not $Live.PSObject.Properties['description']) { return $patch }
    if ($dd -cne "$($Live.description)".Trim()) { $patch['description'] = $dd }
    return $patch
}

function Add-PimWorkloadGateWarnings {
    # REQ-U. Warn for every workload group whose workload role will not be assigned by this run -- REQ-W (2.4.380): the
    # binding provider (feature connectors.workload) is gated off, NO binding row names the group, or its workload's
    # prerequisites are not green (Get-PimWorkloadPrereqHeldReasons). The group itself is always created. Never throws:
    # a warning that cannot be computed must not stop the group deploy.
    param([object[]]$Rows = @(), [hashtable]$Context)
    try {
        if (-not (Get-Command Get-PimWorkloadGateWarnings -ErrorAction SilentlyContinue)) { return }
        $key = 'connectors.workload'
        $avail = $true; $reason = ''
        if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) {
            $avail = [bool](Test-PimFeatureAvailable -Key $key -Quiet)
            if (-not $avail) {
                $reason = if (Get-Command Get-PimFeatureSkipReason -ErrorAction SilentlyContinue) { Get-PimFeatureSkipReason -Key $key } else { "the feature '$key' is not available" }
            }
        }
        # Per binding kind present in the definitions: which tags have a binding row, and whether the kind's workload
        # assignment is held by its prerequisites. Computed once per kind, not per group.
        $bound = @{}; $held = @{}
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            $k = ConvertTo-PimWorkloadBindingKind -Workload "$(Get-PimRowProp -Row $r -Names @('Workload'))"
            if (-not $k -or $bound.ContainsKey($k)) { continue }
            $bound[$k] = if (Get-Command Get-PimWorkloadBoundTags -ErrorAction SilentlyContinue) { Get-PimWorkloadBoundTags -Kind $k } else { $null }
            $held[$k] = if (Get-Command Get-PimWorkloadPrereqHeldReasons -ErrorAction SilentlyContinue) { Get-PimWorkloadPrereqHeldReasons -Kind $k } else { $null }
        }
        foreach ($w in @(Get-PimWorkloadGateWarnings -Rows $Rows -BindingAvailable $avail -Reason $reason -BoundTagsByKind $bound -PrereqHeldByKind $held)) {
            Write-Warning "  [engine] Groups: $w"
            if ($Context -and $Context['__pimScopeWarnings'] -is [System.Collections.Generic.List[string]]) { $Context['__pimScopeWarnings'].Add("$w") }
        }
    } catch { Write-Warning "  [engine] Groups: the workload-binding check could not run: $($_.Exception.Message)" }
}

function New-PimGroupsProvider {
    @{
        scope = 'Groups'; entity = 'PIM-Definitions'; order = 20
        GetDesired = {
            param($ctx)
            $ctx['tagToAuName'] = Get-PimTagToAuName
            $rows = @(Get-PimGroupDefinitionRows)
            # REQ-U (2026-09-19): this provider is UNGATED, the workload binding providers (IntuneRoles,
            # DefenderXdrRoles, WorkloadConnectors) are gated by connectors.workload. A workload group is therefore
            # created (or kept) while its role binding is skipped -- an orphan nobody is told about. Warn per group
            # (Write-Warning reaches the job log; the scope result's `warnings` reaches the run's summary).
            # REQ-W (2.4.380): the group is ALWAYS created; the warning names why its workload role is not assigned yet
            # -- the feature is off, no binding row names it, or its workload's prerequisites are not green.
            Add-PimWorkloadGateWarnings -Rows $rows -Context $ctx
            $rows
        }
        GetLive    = { param($ctx) Ensure-PimContextLoaded; @($Global:Groups_All_ID) }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('GroupName', 'DisplayName', 'displayName') }
        # 68.6 row 27 (c): was existence-only, so an edited GroupDescription never reached Entra.
        # The ONLY property an update writes is description -- a group is NEVER renamed (the name is
        # the key, and REQUIREMENTS forbids renaming a PIM group).
        Equal = { param($d, $l) (Get-PimGroupDescriptionPatch -Desired $d -Live $l).Count -eq 0 }
        ApplyUpdate = {
            param($item, $ctx)
            $patch = Get-PimGroupDescriptionPatch -Desired $item.desired -Live $item.live
            if ($patch.Count -eq 0) { return [pscustomobject]@{ pimApplied = $false; reason = 'nothing to update' } }
            $gid = "$($item.live.id)"; if (-not $gid) { $gid = "$($item.live.Id)" }
            if (-not $gid) { throw "Groups: cannot update '$($item.key)' -- the live group has no id" }
            $r = Invoke-PimGraph -Method PATCH -Path "/groups/$gid" -Body $patch
            # Keep the in-process directory cache honest, so a second scope pass inside the cache
            # window does not PATCH the same description again.
            try { $item.live.description = $patch['description'] } catch { Write-Verbose "group cache refresh: $($_.Exception.Message)" }
            $r
        }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $gn = "$($item.key)"
            # BUG-18, same as the AU create: re-check by name directly before writing. The
            # diff's live set came from ONE bulk list read and Graph is not replica-pinned,
            # so "not there" can simply mean "not there YET". Entra allows duplicate group
            # display names, and the engine keys on display name -- a duplicate is therefore
            # permanent ambiguity, not a tidy-up job.
            $existingGid = Test-PimNameAlreadyLive -Kind group -DisplayName $gn
            if ($existingGid) {
                Write-Host ("    [=] {0} (already exists -- validated, skipped)" -f $gn) -ForegroundColor DarkGray
                $g0 = [pscustomobject]@{ id = $existingGid; displayName = $gn }
                if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $g0 }
                return $g0
            }
            # BUG-255 / REQ-REN-1: a renamed definition renames the group it already has -- never a second group.
            $ren = Invoke-PimRenameInPlace -Kind group -NewName $gn -Row $d
            if ($ren) { return $ren }
            # 🔴 REQ-W (operator 2026-09-19: "it should be possible to deploy groups"): the REQ-U wave-2 create hold that
            # stood here is GONE. A workload group is ALWAYS created -- binding gated off, no binding row, prerequisites
            # not green or a binding read refused. Measured on internal (tick 17:01Z, 2.4.378/379): with 0 binding rows
            # connectors.workload stayed off and 140 workload groups were never created. GetDesired's warning
            # (Add-PimWorkloadGateWarnings) says why the role is not assigned yet; only the ASSIGNMENT waits
            # (Get-PimWorkloadAssignmentHold, in the binding providers).
            $assignable = (Get-PimRowProp -Row $d -Names @('IsRoleAssignable')) -match '(?i)true'
            $body = @{
                displayName = $gn; mailNickname = (Get-PimMailNickname $gn)
                securityEnabled = $true; mailEnabled = $false; groupTypes = @()
                isAssignableToRole = $assignable
            }
            # Graph requires description 1-1024 chars when present -> only send if non-empty.
            $desc = Get-PimRowProp -Row $d -Names @('GroupDescription')
            if ("$desc".Trim()) { $body['description'] = $desc }
            # OWNERS: come from the definition's Owners column (pipe-joined UPNs per the Manager
            # UX; also accept ; or ,), Roles use SponsorUpn, falling back to the group's Department
            # contact (PIM-Definitions-Departments: Department -> Owners).
            #
            # 🔴 THIS NO LONGER REFUSES THE CREATE (operator, 2026-08-10):
            #   "it is important that the engine doesn't refuse to create an ownerless group.
            #    i acknowledge the purpose, but it must be support to add this later and should
            #    be optional."
            # It used to THROW, and that default was untenable in the real estate: 239 of the 259
            # authored service definitions carry a BLANK Owners column, so a strict engine would
            # refuse to (re)create the overwhelming majority of the estate's own groups -- measured
            # on myfamilynetwork while creating 4 legitimately-authored groups, all four refused.
            #
            # The purpose is kept, just not as a blocker: an ownerless create is WARNED about every
            # run, so the gap stays visible instead of silent, and OWNERSHIP IS ADDED LATER BY
            # DESIGN -- the GroupOwners scope reconciles owners on every run, so filling in the
            # Owners column at any point converges without touching the group.
            # Set $global:PIM_RequireGroupOwners = $true to restore the strict, refuse-to-create
            # behaviour; the knob now works in BOTH directions.
            $ownerIds = Resolve-PimGroupOwnerIds -Row $d -Ctx $ctx
            $require = $false; if ($null -ne $global:PIM_RequireGroupOwners) { $require = [bool]$global:PIM_RequireGroupOwners }
            if (-not $ownerIds.Count) {
                if ($require) {
                    throw "no owner resolves for group '$gn' and \$global:PIM_RequireGroupOwners is set -- set Owners/SponsorUpn on the definition, or a Department contact, or clear the flag to create it and assign the owner later."
                }
                Write-Warning ("  [engine] Groups: creating '$gn' with NO owner -- set Owners/SponsorUpn on the " +
                               "definition (or a Department contact) and the GroupOwners scope will attach it on a later run.")
            }
            $g = Invoke-PimGraph -Method POST -Path '/groups' -Body $body
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $g }   # incremental cache
            # Attach to its AU. This is an OPTIMISATION, not the guarantee: the
            # AdministrativeUnitMembers scope (order 22) reconciles AU membership on every
            # run and is what actually keeps it correct.
            #
            # BUG-16: this used to be the ONLY attach, it read the possibly-stale context
            # cache, and it swallowed every failure to Write-Verbose. When the AU had been
            # created moments earlier by the AdministrativeUnits scope and had not yet
            # replicated to the replica this process reads, the lookup missed, the attach
            # was skipped silently, and nothing ever repaired it -- the Groups provider's
            # Equal is existence-based, so the group is `nochange` forever. AU membership is
            # the SCOPE BOUNDARY for AU-scoped delegation, so the group quietly had a
            # different reach than the model said. Observed in 1 of 3 identical runs.
            # Now: a miss is a WARNING that names the repair, never silence.
            $auTag = Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag')
            if ($auTag -and $g.id) {
                $auName = $ctx['tagToAuName'][$auTag.ToLowerInvariant()]
                $au = @($Global:AU_All_ID) | Where-Object { "$($_.DisplayName)" -eq "$auName" } | Select-Object -First 1
                if ($au) {
                    # §70.19 (measured on internal 2026-09-13): the attach right after the create answered
                    # 404 Request_ResourceNotFound for BOTH new groups -- the group had not replicated yet --
                    # and each logged a WARNING although the AdministrativeUnitMembers pass attached them 9 s
                    # later. A 404 on a group created milliseconds ago is replication, not a fault: say so
                    # plainly. (No waiting here -- BUG-18 keeps the create paths free of sleep/retry; the
                    # reconcile pass right after this scope is the retry.)
                    try { Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($au.Id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null }
                    catch {
                        $auErr = "$($_.Exception.Message)"
                        if ($auErr -match '(?i)\b404\b|Request_ResourceNotFound') { Write-Host "    [engine] Groups: '$gn' is not replicated yet for the AU attach (404) -- the AdministrativeUnitMembers scope attaches it to '$auName' in this run." -ForegroundColor DarkGray }
                        elseif ($auErr -notmatch '(?i)already exist') { Write-Warning "  [engine] Groups: AU attach at create time failed for '$gn' -> '$auName' ($auErr). The AdministrativeUnitMembers scope will reconcile it." }
                    }
                } else {
                    Write-Warning "  [engine] Groups: AU '$auName' (tag '$auTag') is not visible yet, so '$gn' was NOT attached at create time. The AdministrativeUnitMembers scope will reconcile it."
                }
            }
            # owners are enforced above (refuse ownerless) but ATTACHED by the GroupOwners
            # scope (order 25) -- a separate, re-runnable pass that tolerates replication of
            # the just-created group and repairs missing owners on existing groups.
            $g
        }
    }
}

# ---------------------------------------------------------------------------
# AdministrativeUnitMembers scope (BUG-16) -- a PIM group belongs to the AU its
# definition names, and STAYS there.
#
# Why this is its own scope. The attach used to happen once, inside Groups.ApplyCreate,
# from a possibly-stale context cache, with the failure swallowed to Write-Verbose. Miss
# it and nothing ever repaired it: the Groups provider's Equal is existence-based, so on
# every later run the group is `nochange`. AU membership is the SCOPE BOUNDARY for
# AU-scoped delegation -- an L2 helpdesk role is granted AT the AU -- so a group that
# never joined its AU silently has a different reach than the delegation model says. A
# model that quietly disagrees with the directory is the thing this product exists to
# prevent, so the attach has to be RECONCILED, not attempted once.
#
# NB: create-only by design. There is deliberately no ApplyRemove -- pulling a group OUT
# of an AU changes the blast radius of every role scoped to that AU, and that belongs in
# the same approval conversation as wiring ApplyRemove on the other assignment scopes.
# A prune here therefore PLANS the removal and reports it; it does not execute it.
# ---------------------------------------------------------------------------
function New-PimAuMembersProvider {
    @{
        scope = 'AdministrativeUnitMembers'; entity = 'PIM-Definitions'; order = 22; refreshBefore = $true
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToAu = Get-PimTagToAuName
            $auByName = @{}; foreach ($a in @($Global:AU_All_ID)) { $n = "$($a.DisplayName)"; if ($n) { $auByName[$n.ToLowerInvariant()] = "$($a.Id)" } }
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($d in (Get-PimGroupDefinitionRows)) {
                $auTag = "$($d.AdministrativeUnitTag)"; if (-not $auTag) { continue }   # not an AU-scoped group
                $gn = "$($d.GroupName)"; if (-not $gn) { continue }
                $gid = Resolve-PimLiveGroupIdByName $gn
                $auName = $tagToAu[$auTag.ToLowerInvariant()]
                $auId = if ($auName) { $auByName["$auName".ToLowerInvariant()] } else { $null }
                # Group or AU not live yet -> nothing to reconcile this pass; the next run
                # picks it up. That is the self-healing the old create-time attach lacked.
                if (-not $gid -or -not $auId) { continue }
                $out.Add([pscustomobject]@{ auId = $auId; auName = $auName; groupId = $gid; GroupName = $gn })
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $owned = Get-PimSolutionOwnedGroups
            $out = New-Object System.Collections.Generic.List[object]
            # Only the AUs the SOLUTION defines, and only members that are groups it owns --
            # so this scope can never see, let alone plan against, anything else in the tenant.
            foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU')) {
                $auName = "$(Get-PimRowProp -Row $r -Names @('AUDisplayName'))"; if (-not $auName) { continue }
                $au = @($Global:AU_All_ID) | Where-Object { "$($_.DisplayName)" -eq $auName } | Select-Object -First 1
                if (-not $au) { continue }
                try {
                    # TEST-16: a 404 here on an AU this pass just created is replication lag, not a
                    # missing AU. Reading it as "no members" would make the diff plan a create that
                    # then 404s too -- which is exactly the reported failure.
                    $members = Invoke-PimAuReplicationRetry -Context $ctx -AuId "$($au.Id)" -What 'AdministrativeUnitMembers read' -Action {
                        @(Invoke-PimGraph -All -Path "/directory/administrativeUnits/$($au.Id)/members?`$select=id")
                    }
                    foreach ($m in @($members)) {
                        if (-not $m -or -not $m.id) { continue }
                        if (-not $owned.byId.ContainsKey("$($m.id)")) { continue }
                        $out.Add([pscustomobject]@{ auId = "$($au.Id)"; auName = $auName; groupId = "$($m.id)"; GroupName = "$($owned.byId["$($m.id)"].name)" })
                    }
                } catch {
                    # 2026-09-20: a partial live set must SAY it is partial. Without this the AU's members
                    # read as absent, and a committed Action=Remove row for one of them counts as "already
                    # done" and is DELETED from the desired state (Invoke-PimEngineScope, __pimLiveIncomplete).
                    $ctx['__pimLiveIncomplete'] = "AdministrativeUnitMembers: AU '$auName' members could not be read"
                    Write-Warning "  [engine] AdministrativeUnitMembers: could not read members of AU '$auName': $($_.Exception.Message)"
                }
            }
            $out.ToArray()
        }
        KeyOf = { param($r) "$(Get-PimRowProp -Row $r -Names @('auId'))|$(Get-PimRowProp -Row $r -Names @('groupId'))".ToLowerInvariant() }
        Equal = { param($d, $l) $true }   # membership exists -> nothing to change
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            # TEST-16: same provenance-gated retry as the read above. A 404 on an AU this pass did
            # NOT create still fails immediately -- that is a real missing object.
            Invoke-PimAuReplicationRetry -Context $ctx -AuId "$($d.auId)" -What 'AdministrativeUnitMembers attach' -Action {
                Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($d.auId)/members/`$ref" `
                    -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($d.groupId)" }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# AdminMembers scope -- admins (PIM-Assignments-Admins) become Eligible/Active
# members of their PIM group (PIM-for-Groups). This is "admins get access to the
# org groups". Ported from Assign-User-PIM-PAG-Group / Assign-Groups-Accounts.
# ---------------------------------------------------------------------------
function Test-PimAdminIsOut {
    <#
      68.6 #31 -- ONE predicate for "this admin is OUT": the membership scopes must not hand access
      back to an account the lifecycle has switched off. Without it AdminMembers re-added, on its next
      5-minute pass, every PIM-for-Groups membership the offboarding sweep had just removed.
      OUT when any of:
        * AccountStatus Disabled / Revoked, or OffboardDate reached (Get-PimAdminStatusDecision.disable)
        * Lifecycle=Retire or OffboardDate reached                  (Test-PimAdminOffboarded)
        * the offboarding sweep has a progress record for the account (pim.Settings['AdminOffboardState']:
          sessions revoked / memberships removed / deleted) -- UNLESS the row now says
          AccountStatus=Enabled, the only value that may bring an account back (the Admins rule).
      PURE given -OffboardState (the store's record for this account, or $null). Returns @{ out; reason }.
    #>
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow, [hashtable]$OffboardState)
    if (Get-Command Get-PimAdminStatusDecision -ErrorAction SilentlyContinue) {
        $dec = Get-PimAdminStatusDecision -Row $Row -NowUtc $NowUtc
        if ($dec.disable) { return [pscustomobject]@{ out = $true; reason = "$($dec.reason)" } }
    }
    if (Get-Command Test-PimAdminOffboarded -ErrorAction SilentlyContinue) {
        $f = Test-PimAdminOffboarded -Row $Row -NowUtc $NowUtc
        if ($f.offboard) { return [pscustomobject]@{ out = $true; reason = "$($f.reason)" } }
    }
    if ($OffboardState -is [hashtable] -and $OffboardState.Count) {
        $st = (Get-PimRowProp -Row $Row -Names @('AccountStatus')).Trim()
        $done = @(@('revokedAtUtc', 'membershipsRemovedUtc', 'deletedAtUtc') | Where-Object { "$($OffboardState[$_])".Trim() })
        if ($done.Count -and $st -ine 'Enabled') {
            return [pscustomobject]@{ out = $true; reason = "offboarding in progress/completed ($($done -join ', ') recorded)" }
        }
    }
    return [pscustomobject]@{ out = $false; reason = '' }
}

function Get-PimAdminMembersKey {
    # "<admin principal id>|<group tag>|<type>" -- one shape for desired, Remove and live rows.
    param([object]$Row)
    $prinId = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $prinId) { $prinId = Resolve-PimPrincipalId (Get-PimRowProp -Row $Row -Names @('Username')) }
    $tag = (Get-PimRowProp -Row $Row -Names @('GroupTag')).ToLowerInvariant()
    $type = (Get-PimRowProp -Row $Row -Names @('AssignmentType')).ToLowerInvariant()
    "$prinId|$tag|$type"
}

function New-PimAdminMembersProvider {
    @{
        scope = 'AdminMembers'; entity = 'PIM-Assignments-Admins'; order = 50; refreshBefore = $true
        GetDesired = {
            param($ctx)
            $all = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Admins')
            # 68.6 row 24: Remove rows are TARGETED removals (GetRemoveRows), never desired.
            $ctx['removeRows:AdminMembers'] = @($all | Where-Object { Test-PimRowIsRemove $_ })
            # 68.6 #31: an admin who is OUT (Test-PimAdminIsOut) gets no membership created, extended or
            # updated -- otherwise this scope re-adds what offboarding removed. Their rows simply leave
            # the desired set; their Remove rows still apply.
            $now = [datetime]::UtcNow
            $acct = @{}
            foreach ($a in @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')) { if ($a) { $ak = Get-PimAdminRowKey -Row $a; if ($ak) { $acct[$ak] = $a } } }
            $obMap = @{}
            if ($acct.Count -and (Get-Command Get-PimAdminLifecycleStore -ErrorAction SilentlyContinue)) {
                $st = Get-PimAdminLifecycleStore -Name 'AdminOffboardState'
                if ($st.ok) { foreach ($k in @($st.map.Keys)) { $obMap[(Get-PimAdminRowKey -Row ([pscustomobject]@{ UserPrincipalName = "$k" }))] = $st.map[$k] } }
            }
            $keep = New-Object System.Collections.Generic.List[object]
            $outSeen = @{}
            foreach ($d in @($all | Where-Object { -not (Test-PimRowIsRemove $_) })) {
                $ak = Get-PimAdminRowKey -Row ([pscustomobject]@{ UserName = (Get-PimRowProp -Row $d -Names @('Username','UserName','UserPrincipalName')) })
                $acctRow = if ($ak) { $acct[$ak] } else { $null }
                if ($acctRow -and (Test-PimAdminIsAdOnly -Row $acctRow)) {
                    if (-not $outSeen.ContainsKey($ak)) { $outSeen[$ak] = $true; Write-Host ("    [AdminMembers] {0}: AD-only admin -- no Entra group membership (it does not exist in Entra)." -f $ak) -ForegroundColor DarkGray }
                    continue
                }
                # Operator 2026-09-25 (verify-convergence FAIL, internal): an admin whose ProvisionDate is in the FUTURE has no
                # account yet, so its memberships were planned as creates for a principal that does not exist ("||role-...")
                # and, after the grace window, reported as a CONVERGENCE FAILURE for two days. They are not due until the
                # account is -- they leave the desired set until delta-admins creates it, then apply on the next run.
                if ($acctRow -and (Get-Command Test-PimAdminProvisionDue -ErrorAction SilentlyContinue)) {
                    $pd = Test-PimAdminProvisionDue -Row $acctRow
                    if (-not $pd.due) {
                        if (-not $outSeen.ContainsKey($ak)) { $outSeen[$ak] = $true; Write-Host ("    [AdminMembers] {0}: account is {1} -- memberships wait for it." -f $ak, $pd.reason) -ForegroundColor DarkGray }
                        continue
                    }
                }
                if ($acctRow) {
                    $o = Test-PimAdminIsOut -Row $acctRow -NowUtc $now -OffboardState $obMap[$ak]
                    if ($o.out) {
                        if (-not $outSeen.ContainsKey($ak)) { $outSeen[$ak] = $true; Write-Host ("    [AdminMembers] {0}: admin is OUT ({1}) -- memberships are NOT created, extended or updated." -f $ak, $o.reason) -ForegroundColor DarkYellow }
                        continue
                    }
                }
                $keep.Add($d)
            }
            # PERF: no prune possible -> GetLive reads only the admins these rows (and the Remove rows) name.
            # Resolved exactly like Get-PimAdminMembersKey; an unresolvable admin is skipped (its row is a create).
            [void]$ctx.Remove('livePrincipals:AdminMembers'); [void]$ctx.Remove('liveConfirm:AdminMembers')
            if ($ctx['__pimLiveNarrow']) {
                $__pids = New-Object System.Collections.Generic.List[string]; $__byUser = @{}
                $__pairs = New-Object System.Collections.Generic.List[object]
                $__nKeep = $keep.Count; $__i = -1
                foreach ($__r in @(@($keep.ToArray()) + @($ctx['removeRows:AdminMembers']))) {
                    $__i++
                    if ($null -eq $__r) { continue }
                    # The STAMPED live id (Get-PimRowProp would make it look like a settable column -- Test-PimEntityFieldCoverage).
                    $__p = if ($__r.PSObject.Properties['principalId']) { "$($__r.principalId)".Trim() } else { '' }
                    if (-not $__p) {
                        $__u = Get-PimRowProp -Row $__r -Names @('Username'); if (-not $__u) { continue }
                        $__uk = $__u.ToLowerInvariant()
                        if (-not $__byUser.ContainsKey($__uk)) { $__byUser[$__uk] = Resolve-PimPrincipalId $__u }
                        $__p = $__byUser[$__uk]
                    }
                    if ($__p) {
                        $__pids.Add("$__p")
                        $__pairs.Add([pscustomobject]@{ principal = "$__p"; tag = (Get-PimRowProp -Row $__r -Names @('GroupTag')); remove = ($__i -ge $__nKeep) })
                    }
                }
                $ctx['livePrincipals:AdminMembers'] = $__pids.ToArray()
                $ctx['liveConfirm:AdminMembers'] = $__pairs.ToArray()
            }
            $keep.ToArray()
        }
        GetRemoveRows = { param($ctx) @(Select-PimRemoveRows -Rows @($ctx['removeRows:AdminMembers']) -Scope 'AdminMembers') }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $ctx['admTagToGid'] = @{}
            # BUG-17: the live universe is every group the SOLUTION owns, not just the tags
            # that happen to appear in the desired rows. Reading only the desired tags meant
            # a deleted desired row took its live membership out of view with it, so the
            # prune that removal was supposed to trigger silently did nothing.
            $owned = Get-PimSolutionOwnedGroups
            foreach ($t in @($tagToName.Keys)) { $gid = $owned.byTag[$t]; if ($gid) { $ctx['admTagToGid'][$t] = $gid } }
            $live = New-Object System.Collections.Generic.List[object]
            # PERF: no prune possible -> read only the admins GetDesired named (Get-PimLiveGroupMembershipsByPrincipal),
            # then the SAME filters as the full read below.
            if ($ctx['__pimLiveNarrow'] -and $ctx.ContainsKey('livePrincipals:AdminMembers')) {
                $__nr = Get-PimLiveGroupMembershipsByPrincipal -PrincipalIds @($ctx['livePrincipals:AdminMembers']) -Owned $owned -Scope 'AdminMembers' -Reason "$($ctx['__pimLiveNarrowReason'])"
                # §70.21: a narrowed answer that FAILED would hide live memberships (a Remove row would read "already
                # absent") -- never plan from a partial read; take the full read below instead.
                if ([int]$__nr.failed -gt 0) { Write-Warning "  [AdminMembers] $($__nr.failed) narrowed read(s) failed -- using the full membership read" }
                else {
                    $__keepM = { param($m) (-not $owned.byId.ContainsKey("$($m.principalId)")) -and -not ("$($m.accessId)".Trim() -and "$($m.accessId)".Trim() -ine 'member') -and ("$($m.graphAssignmentType)" -ine 'activated') }
                    foreach ($m in @($__nr.rows)) { if (& $__keepM $m) { $live.Add($m) } }
                    # 🔴 §70.21: the principalId-filtered list OMITS some schedules (measured on internal: 3 of 61 nestings of
                    # one role group, all created 2026-03-02, returned only by the groupId-filtered list). Every desired or
                    # Remove row the principal read did not answer is CONFIRMED by a per-group read of its group.
                    [void](Add-PimConfirmedGroupMemberships -Live $live -Pairs @($ctx['liveConfirm:AdminMembers']) -Owned $owned -Keep $__keepM -Scope 'AdminMembers')
                    return $live.ToArray()
                }
            }
            # One batched read of every owned group's schedules into the membership cache (Initialize-PimGroupMembershipCache).
            Clear-PimGroupScheduleReadError
            $__tagById = @{}; foreach ($__g in @($owned.byId.Keys)) { $__tagById["$__g"] = "$($owned.byId[$__g].tag)" }
            [void](Initialize-PimGroupMembershipCache -GroupTagById $__tagById)
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) {
                    # Complement of the GroupMembers filter: a nested GROUP membership belongs
                    # to that scope, not this one. Without this split each scope would see the
                    # other's rows as unowned and, under -Prune, as removals.
                    if ($owned.byId.ContainsKey("$($m.principalId)")) { continue }
                    # 68.6 rows 24-26: this scope manages MEMBERSHIP. An OWNER schedule (accessId=owner)
                    # or an ACTIVATION of an eligible membership must not key as a membership -- it
                    # would be removed, extended or read as "exists" in place of the real one.
                    if ("$($m.accessId)".Trim() -and "$($m.accessId)".Trim() -ine 'member') { continue }
                    if ("$($m.graphAssignmentType)" -ieq 'activated') { continue }
                    if (-not "$($m.groupId)") { Add-Member -InputObject $m -NotePropertyName groupId -NotePropertyValue $gid -Force }
                    $live.Add($m)
                }
            }
            # 🔴 2026-09-20: if ANY group's read failed, this live set is short -- and a short set makes a
            # committed Action=Remove row look already-gone, which completes and DELETES it. NOT CHECKED.
            $__ge = Get-PimGroupScheduleReadError
            if ($__ge) { $ctx['__pimLiveReadError'] = "the live group membership read was INCOMPLETE ($__ge)"; return @() }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAdminMembersKey -Row $r }
        TypeKeyOf = { param($r) Get-PimTypeNeutralKey -Key (Get-PimAdminMembersKey -Row $r) }
        # 68.6 rows 25-26 (was `$true`: AutoExtend / UpdateExisting ignored).
        Equal = { param($d, $l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item, $ctx) Invoke-PimAssignmentMaintenanceApply -Kind GroupMember -Item $item }
        ApplyRemove = { param($item, $ctx) Remove-PimGroupScheduleAssignment -Live $item.live -What "$($item.key)" }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $prinId = Resolve-PimPrincipalId (Get-PimRowProp -Row $d -Names @('Username'))
            $tag = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['admTagToGid'][$tag]
            if (-not $prinId -or -not $gid) { throw "AdminMembers: unresolved principal/group ($(Get-PimRowProp -Row $d -Names @('Username')) / $tag)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimGroupMembershipBody -PrincipalId $prinId -GroupId $gid -AccessId 'member' -Permanent:$perm -Days $days
            $ep = if ($type -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupMembers scope -- nested PIM-for-Groups (PIM-Assignments-Groups): a SOURCE
# group becomes an Eligible/Active member of a TARGET group.
# ---------------------------------------------------------------------------
function Get-PimGroupMembersKey {
    # ONE shape both sides produce: <member principal id>|<container tag>|<type>.
    # The MEMBER is the TARGET group; the CONTAINER is the SOURCE group. On a live row the
    # container tag arrives as GroupTag (the group whose membership was enumerated).
    param([object]$Row)
    $r = $Row
    $container = (Get-PimRowProp -Row $r -Names @('SourceGroupTag', 'GroupTag')).ToLowerInvariant()
    $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
    $member = Get-PimRowProp -Row $r -Names @('principalId')   # live row, and the resolved desired row
    if (-not $member) { $member = "unresolved:" + (Get-PimRowProp -Row $r -Names @('TargetGroupTag')).ToLowerInvariant() }
    "$member|$container|$type"
}

function New-PimGroupMembersProvider {
    @{
        scope = 'GroupMembers'; entity = 'PIM-Assignments-Groups'; order = 55; refreshBefore = $true
        # BUG-11/BUG-17, same two fixes as RolesAUs: resolve the desired row's SOURCE group
        # to its live id so both sides key alike, and read live membership across every
        # group the solution owns rather than only the target tags found in desired.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['grpTagToGid']) { $ctx['grpTagToGid'] = @{} }
            $resolve = {
                param($tag)
                $t = "$tag".ToLowerInvariant(); if (-not $t) { return $null }
                if ($ctx['grpTagToGid'].ContainsKey($t)) { return $ctx['grpTagToGid'][$t] }
                $nm = $tagToName[$t]; if (-not $nm) { return $null }
                $gid = Resolve-PimLiveGroupIdByName $nm
                if ($gid) { $ctx['grpTagToGid'][$t] = $gid }
                return $gid
            }
            $out = New-Object System.Collections.Generic.List[object]
            # 68.6 row 24: Remove rows are resolved EXACTLY like desired rows (so they key like the
            # live membership they name) but kept apart -- they are targeted removals, never creates.
            $rmRows = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups')) {
                # 🔴 DIRECTION: the TARGET group is nested INTO the SOURCE group.
                # SourceGroupTag is where the permission comes FROM (the service group); the
                # TargetGroupTag group is the one that RECEIVES it and is therefore the MEMBER.
                # This was inverted -- principalId was stamped from the SOURCE -- so no desired key
                # could ever match a live one (measured: desired=206, live=199, nochange=0) and
                # ApplyCreate would have written 206 memberships the wrong way round, nesting
                # service groups inside role groups.
                # Verified against the live tenant: PIM-ROLE-Management-IT-OperationSecurity is a
                # MEMBER OF 50 service groups (Entra-ID-SecurityAdministrator-L1, ...) and contains
                # 1 member -- while its desired rows are all Target='ROLE-Mgmt-IT-OperationSecurity'
                # with Source='<service group>'.
                $tgtGid = & $resolve (Get-PimRowProp -Row $d -Names @('TargetGroupTag'))
                [void](& $resolve (Get-PimRowProp -Row $d -Names @('SourceGroupTag')))   # cache for ApplyCreate
                $row = $d | Select-Object *
                # The live row's principal IS the member, i.e. the TARGET group. Stamping its id
                # makes the desired key identical to the live one. Unresolved (target group not
                # created yet) keys as unresolved -> a create, which is right on a first deploy.
                if ($tgtGid) { Add-Member -InputObject $row -NotePropertyName principalId -NotePropertyValue $tgtGid -Force }
                if (Test-PimRowIsRemove $d) { $rmRows.Add($row) } else { $out.Add($row) }
            }
            $ctx['removeRows:GroupMembers'] = $rmRows.ToArray()
            # PERF: no prune possible -> GetLive reads only the MEMBER (TARGET) groups these rows and the Remove
            # rows resolved to. An unresolved target keys as unresolved (a create) and needs no live read.
            [void]$ctx.Remove('livePrincipals:GroupMembers'); [void]$ctx.Remove('liveConfirm:GroupMembers')
            if ($ctx['__pimLiveNarrow']) {
                $__pids = New-Object System.Collections.Generic.List[string]
                $__pairs = New-Object System.Collections.Generic.List[object]
                $__nKeep = $out.Count; $__i = -1
                foreach ($__r in @(@($out.ToArray()) + @($rmRows.ToArray()))) {
                    $__i++
                    if ($null -eq $__r) { continue }
                    $__p = if ($__r.PSObject.Properties['principalId']) { "$($__r.principalId)".Trim() } else { '' }
                    if ($__p) {
                        $__pids.Add("$__p")
                        # the CONTAINER is the source group: that is the group a confirming per-group read enumerates
                        $__pairs.Add([pscustomobject]@{ principal = "$__p"; tag = (Get-PimRowProp -Row $__r -Names @('SourceGroupTag')); remove = ($__i -ge $__nKeep) })
                    }
                }
                $ctx['livePrincipals:GroupMembers'] = $__pids.ToArray()
                $ctx['liveConfirm:GroupMembers'] = $__pairs.ToArray()
            }
            $out.ToArray()
        }
        GetRemoveRows = { param($ctx) @(Select-PimRemoveRows -Rows @($ctx['removeRows:GroupMembers']) -Scope 'GroupMembers') }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['grpTagToGid']) { $ctx['grpTagToGid'] = @{} }
            foreach ($t in @($tagToName.Keys)) {
                if ($ctx['grpTagToGid'].ContainsKey($t)) { continue }
                $gid = Resolve-PimLiveGroupIdByName $tagToName[$t]; if ($gid) { $ctx['grpTagToGid'][$t] = $gid }
            }
            # BUG-17: every solution-owned group is a potential TARGET, whether or not a
            # desired row currently points at it. Reading only the target tags in desired is
            # what made a deleted desired row invisible to prune.
            $owned = Get-PimSolutionOwnedGroups
            $live = New-Object System.Collections.Generic.List[object]
            # PERF: no prune possible -> read only the target groups GetDesired named (Get-PimLiveGroupMembershipsByPrincipal),
            # then the SAME filters as the full read below.
            # 🔴 §70.21 -- measured live on internal 2026-09-13 22:50Z (2.4.353, principal read only): live=171 where the
            # full read sees 208 -> 37 false creates (all skipped as "exists"); a Remove row naming an unseen nesting would
            # have read "already absent". Cause (probed read-only): the principalId-filtered list omits some schedules.
            # Fixed by the per-group CONFIRM below. 'NarrowDeltaGroupMembersReads' = false switches GroupMembers alone off.
            $__grpNarrowOn = $true
            if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { try { $__grpNarrowOn = -not ("$(Get-PimPolicySetting -Name 'NarrowDeltaGroupMembersReads' -Default $null)".Trim() -match '^(?i)(false|0|no|off|disabled?)$') } catch { $__grpNarrowOn = $true } }
            elseif ($null -ne $global:PIM_NarrowDeltaGroupMembersReads) { $__grpNarrowOn = -not ("$($global:PIM_NarrowDeltaGroupMembersReads)".Trim() -match '^(?i)(false|0|no|off|disabled?)$') }
            if ($__grpNarrowOn -and $ctx['__pimLiveNarrow'] -and $ctx.ContainsKey('livePrincipals:GroupMembers')) {
                $__nr = Get-PimLiveGroupMembershipsByPrincipal -PrincipalIds @($ctx['livePrincipals:GroupMembers']) -Owned $owned -Scope 'GroupMembers' -Reason "$($ctx['__pimLiveNarrowReason'])"
                if ([int]$__nr.failed -gt 0) { Write-Warning "  [GroupMembers] $($__nr.failed) narrowed read(s) failed -- using the full membership read" }
                else {
                    $__keepM = { param($m) $owned.byId.ContainsKey("$($m.principalId)") -and -not ("$($m.accessId)".Trim() -and "$($m.accessId)".Trim() -ine 'member') -and ("$($m.graphAssignmentType)" -ine 'activated') }
                    foreach ($m in @($__nr.rows)) { if (& $__keepM $m) { $live.Add($m) } }
                    # §70.21: confirm what the principal read did not answer (see AdminMembers) by a per-group read.
                    [void](Add-PimConfirmedGroupMemberships -Live $live -Pairs @($ctx['liveConfirm:GroupMembers']) -Owned $owned -Keep $__keepM -Scope 'GroupMembers')
                    return $live.ToArray()
                }
            }
            # One batched read of every owned group's schedules into the membership cache (Initialize-PimGroupMembershipCache).
            Clear-PimGroupScheduleReadError
            $__tagById = @{}; foreach ($__g in @($owned.byId.Keys)) { $__tagById["$__g"] = "$($owned.byId[$__g].tag)" }
            [void](Initialize-PimGroupMembershipCache -GroupTagById $__tagById)
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) {
                    # A PIM group's membership holds BOTH nested groups (this scope) and admin
                    # USERS (the AdminMembers scope) -- the same Graph endpoint serves both.
                    # Keep only the nested-GROUP rows here, or every admin membership would be
                    # an unmatched live row in this scope and a removal candidate under -Prune.
                    # This mattered only once the keys were fixed: before, nothing matched
                    # anything, so the overlap was invisible.
                    if (-not $owned.byId.ContainsKey("$($m.principalId)")) { continue }
                    # 68.6 rows 24-26: membership only (not owner schedules), assignments only (not activations).
                    if ("$($m.accessId)".Trim() -and "$($m.accessId)".Trim() -ine 'member') { continue }
                    if ("$($m.graphAssignmentType)" -ieq 'activated') { continue }
                    if (-not "$($m.groupId)") { Add-Member -InputObject $m -NotePropertyName groupId -NotePropertyValue $gid -Force }
                    $live.Add($m)
                }
            }
            # 🔴 2026-09-20: if ANY group's read failed, this live set is short -- and a short set makes a
            # committed Action=Remove row look already-gone, which completes and DELETES it. NOT CHECKED.
            $__ge = Get-PimGroupScheduleReadError
            if ($__ge) { $ctx['__pimLiveReadError'] = "the live group membership read was INCOMPLETE ($__ge)"; return @() }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimGroupMembersKey -Row $r }
        TypeKeyOf = { param($r) Get-PimTypeNeutralKey -Key (Get-PimGroupMembersKey -Row $r) }
        # 68.6 rows 25-26 (was `$true`: AutoExtend / UpdateExisting ignored).
        Equal = { param($d, $l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item, $ctx) Invoke-PimAssignmentMaintenanceApply -Kind GroupMember -Item $item }
        ApplyRemove = { param($item, $ctx) Remove-PimGroupScheduleAssignment -Live $item.live -What "$($item.key)" }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $tgt = (Get-PimRowProp -Row $d -Names @('TargetGroupTag')).ToLowerInvariant()
            $srcTag = (Get-PimRowProp -Row $d -Names @('SourceGroupTag')).ToLowerInvariant()
            $memberId    = $ctx['grpTagToGid'][$tgt]      # TARGET receives the access -> it is the MEMBER
            $containerId = $ctx['grpTagToGid'][$srcTag]   # SOURCE supplies the access -> it is the CONTAINER
            if (-not $memberId -or -not $containerId) { throw "GroupMembers: unresolved target/source ($tgt / $srcTag)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            # Was PrincipalId=$sid / GroupId=$gid, i.e. nesting the SOURCE into the TARGET -- the
            # exact inverse of what the tenant has, and of what v1 built.
            $body = New-PimGroupMembershipBody -PrincipalId $memberId -GroupId $containerId -AccessId 'member' -Permanent:$perm -Days $days
            $ep = if ($type -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# RolesAUs scope -- AU-SCOPED Entra directory roles to a PIM group
# (PIM-Assignments-Roles-AUs). Same PIM directory-role REST as EntraRoles but
# directoryScopeId = /administrativeUnits/<auId>. Ported from
# Assign-Roles-AdministrativeUnits-From-SQL.
# ---------------------------------------------------------------------------
function Get-PimRolesAUsKey {
    # ONE key shape for both sides: resolved principal + AU id + role + type.
    # GetDesired stamps principalId/directoryScopeId, so a desired row that
    # resolves keys identically to its live counterpart.
    param([object]$Row)
    $gid = Get-PimRowProp -Row $Row -Names @('principalId')
    if ($gid) {
        $scope = Get-PimRowProp -Row $Row -Names @('directoryScopeId'); $au = ($scope -split '/')[-1]
        $role = (Get-PimRowProp -Row $Row -Names @('RoleDefinitionName')).ToLowerInvariant()
        $type = (Get-PimRowProp -Row $Row -Names @('AssignmentType')).ToLowerInvariant()
        return "$gid|$($au.ToLowerInvariant())|$role|$type"
    }
    # UNRESOLVED desired row (group or AU not live yet) -> deliberately distinct, so
    # it becomes a create. It can never collide with a live key because a live row
    # always carries a principalId.
    $gt=(Get-PimRowProp -Row $Row -Names @('GroupTag')).ToLowerInvariant(); $at=(Get-PimRowProp -Row $Row -Names @('AdministrativeUnitTag')).ToLowerInvariant()
    $role=(Get-PimRowProp -Row $Row -Names @('RoleDefinitionName')).ToLowerInvariant(); $type=(Get-PimRowProp -Row $Row -Names @('AssignmentType')).ToLowerInvariant()
    "unresolved:$gt|autag:$at|$role|$type"
}

function New-PimRolesAUsProvider {
    @{
        scope = 'RolesAUs'; entity = 'PIM-Assignments-Roles-AUs'; order = 45; refreshBefore = $true
        # BUG-11: the desired row is RESOLVED here -- tag -> live group id, AU tag -> live
        # AU id -- and the resolved ids are stamped onto the row. KeyOf then produces the
        # SAME key shape for desired and live, instead of a `tag:` placeholder that could
        # never match a resolved live key. That mismatch meant desired rows were re-created
        # on every run (never `nochange`) and, under -Prune, every live row was classed as
        # a removal -- including rows the very same pass had just created.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $tagToAu = Get-PimTagToAuName
            $auByName = @{}; foreach ($a in @($Global:AU_All_ID)) { $n = "$($a.DisplayName)"; if ($n) { $auByName[$n.ToLowerInvariant()] = "$($a.Id)" } }
            $ctx['auTagToId'] = @{}; $ctx['rauGid'] = @{}
            $out = New-Object System.Collections.Generic.List[object]
            # 68.6 row 24: Remove rows are resolved like desired rows (same key as the live
            # assignment they name) and kept apart as targeted removals.
            $rmRows = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-AUs')) {
                $gt = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))"; $at = "$(Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag'))"
                $gid = $null; $aid = $null
                if ($gt) { $gn = $tagToName[$gt.ToLowerInvariant()]; if ($gn) { $gid = Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['rauGid'][$gt.ToLowerInvariant()] = $gid } } }
                if ($at) { $an = $tagToAu[$at.ToLowerInvariant()]; if ($an) { $aid = $auByName[$an.ToLowerInvariant()]; if ($aid) { $ctx['auTagToId'][$at.ToLowerInvariant()] = $aid } } }
                $row = $d | Select-Object *
                # Both must resolve for the key to be the live shape. If either does not,
                # the group/AU does not exist yet -- there is nothing live to match, the
                # row keys as unresolved and becomes a create. That is correct on a first
                # deploy and is NOT the old placeholder problem: an unresolvable row has
                # no live counterpart by definition.
                if ($gid -and $aid) {
                    Add-Member -InputObject $row -NotePropertyName principalId      -NotePropertyValue $gid -Force
                    Add-Member -InputObject $row -NotePropertyName directoryScopeId -NotePropertyValue "/administrativeUnits/$aid" -Force
                }
                if (Test-PimRowIsRemove $d) { $rmRows.Add($row) } else { $out.Add($row) }
            }
            $ctx['removeRows:RolesAUs'] = $rmRows.ToArray()
            $out.ToArray()
        }
        GetRemoveRows = { param($ctx) @(Select-PimRemoveRows -Rows @($ctx['removeRows:RolesAUs']) -Scope 'RolesAUs') }
        GetLive = {
            param($ctx)
            $ctx['rolesByName'] = Get-PimEntraRoleNameMap
            # BUG-17: read the AU-scoped role schedules of every group THIS SOLUTION OWNS,
            # not just the groups the desired rows happen to mention. Otherwise deleting a
            # desired row hides its live assignment and the prune it was meant to trigger
            # silently does nothing. Free here -- the schedules come from the tenant-wide
            # preload, so this is index lookups, not extra calls.
            $owned = Get-PimSolutionOwnedGroups
            # 🔴 2026-09-20: same rule as EntraRoles -- an INCOMPLETE preload is NOT CHECKED, never a diff.
            Get-PimDirRoleSchedulePreload
            $__pe = Get-PimDirRoleScheduleReadError
            if ($__pe) { $ctx['__pimLiveReadError'] = "the directory role schedule preload was INCOMPLETE ($__pe)"; return @() }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $gid)) {
                    if ("$($s.directoryScopeId)" -notmatch '(?i)/administrativeUnits/') { continue }   # RolesAUs = AU-scoped only
                    if ("$($s.graphAssignmentType)" -ieq 'Activated') { continue }                        # an activation is not an assignment
                    $live.Add([pscustomobject]@{ principalId=$gid; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; directoryScopeId=$s.directoryScopeId
                                                 roleDefinitionId=$s.roleDefinitionId; scheduleKnown=$s.scheduleKnown; startDateTime=$s.startDateTime; endDateTime=$s.endDateTime })
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimRolesAUsKey -Row $r }
        TypeKeyOf = { param($r) Get-PimTypeNeutralKey -Key (Get-PimRolesAUsKey -Row $r) }
        # 68.6 rows 25-26 (was `$true`: AutoExtend / UpdateExisting ignored).
        Equal = { param($d,$l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item,$ctx) Invoke-PimAssignmentMaintenanceApply -Kind DirRole -Item $item }
        ApplyRemove = { param($item,$ctx) Remove-PimDirRoleAssignment -Live $item.live -What "$($item.key)" }
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant(); $at=(Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag')).ToLowerInvariant()
            $gid=$ctx['rauGid'][$gt]; $aid=$ctx['auTagToId'][$at]
            $rn=Get-PimRowProp -Row $d -Names @('RoleDefinitionName'); $rid=$ctx['rolesByName'][$rn.ToLowerInvariant()]
            if (-not $gid -or -not $aid -or -not $rid) { throw "RolesAUs: unresolved group/AU/role ($gt / $at / $rn)" }
            $type=Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm=(Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days=[int]("0"+(Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body=New-PimRoleScheduleBody -PrincipalId $gid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o')) -DirectoryScopeId "/administrativeUnits/$aid"
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# AzRes scope -- Azure RBAC PIM role assignment to a PIM group at an ARM scope
# (PIM-Assignments-Azure-Resources). ARM REST (management.azure.com), api 2020-10-01-preview.
# Ported from Assign-AzResources-Groups-From-SQL. NB: the engine SPN needs Owner /
# User Access Administrator on the target scope (an Azure RBAC grant, separate from Graph).
# ---------------------------------------------------------------------------
function Resolve-PimArmRoleId {
    # ARM role NAME -> role definition GUID at a scope (cached per scope+name).
    param([string]$Scope, [string]$RoleName, [hashtable]$Cache)
    $k = "$Scope|$($RoleName.ToLowerInvariant())"
    if ($Cache.ContainsKey($k)) { return $Cache[$k] }
    $id = $null
    # 🔴 A FAILED LOOKUP IS NOT "ROLE NOT FOUND". This swallowed every ARM error and returned $null,
    # so the caller reported "ARM role 'Owner' not found at /subscriptions/0000..." -- when ARM had
    # actually answered 404 SubscriptionNotFound (a template placeholder scope; measured live
    # 2026-09-12, delta-pim-azure). The operator was sent looking for a role that exists. The ARM
    # error is now kept beside the cached id ("<key>|error") so the caller can say what really
    # happened; an EMPTY successful result is still the genuine "no role by that name here".
    try {
        $r = @(Invoke-PimArm -Path "$Scope/providers/Microsoft.Authorization/roleDefinitions?`$filter=roleName eq '$RoleName'" -ApiVersion '2022-04-01' -All)
        if ($r.Count) { $id = "$($r[0].name)" }
        $Cache.Remove("$k|error")
    } catch {
        $msg = "$($_.Exception.Message)"
        if ($_.ErrorDetails -and "$($_.ErrorDetails.Message)".Trim()) { $msg = "$($_.ErrorDetails.Message)" }
        if ($msg -match '(?i)SubscriptionNotFound') { $msg = "subscription not found (ARM SubscriptionNotFound): $msg" }
        $Cache["$k|error"] = $msg
        Write-Verbose "ARM roledef ($RoleName @ $Scope): $msg"
    }
    $Cache[$k] = $id; return $id
}
function Get-PimArmRoleLookupError {
    # The ARM error recorded by Resolve-PimArmRoleId for this scope+role, or '' when the lookup
    # succeeded (an empty result then genuinely means "no role by that name at this scope").
    param([string]$Scope, [string]$RoleName, [hashtable]$Cache)
    if (-not $Cache) { return '' }
    $k = "$Scope|$("$RoleName".ToLowerInvariant())|error"
    if ($Cache.ContainsKey($k)) { return "$($Cache[$k])" }
    return ''
}
function Get-PimAzResKey {
    # ONE shape both sides produce: principal id | scope | role definition guid | type.
    param([object]$Row)
    $gid = Get-PimRowProp -Row $Row -Names @('principalId')
    $scope = Get-PimRowProp -Row $Row -Names @('AzScope')
    $type = (Get-PimRowProp -Row $Row -Names @('AssignmentType')).ToLowerInvariant()
    $rid = "$(Get-PimRowProp -Row $Row -Names @('RoleId'))"
    if ($gid -and $rid) { return "$gid|$($scope.ToLowerInvariant())|rid:$($rid.ToLowerInvariant())|$type" }
    # UNRESOLVED desired row (group not live yet, or the ARM role name did not resolve
    # at this scope) -> distinct by construction, so it becomes a create and can never
    # collide with a live key.
    $gt=(Get-PimRowProp -Row $Row -Names @('GroupTag')).ToLowerInvariant(); $perm=(Get-PimRowProp -Row $Row -Names @('AzScopePermission')).ToLowerInvariant()
    "unresolved:$gt|$($scope.ToLowerInvariant())|perm:$perm|$type"
}

function New-PimAzResProvider {
    @{
        scope = 'AzRes'; entity = 'PIM-Assignments-Azure-Resources'; order = 60; refreshBefore = $true
        # BUG-11: resolve the desired row to the SAME shape the live row has -- the group's
        # live id and the ARM role DEFINITION GUID (the live side only ever reports the guid,
        # never the role name). Without this, `tag:…|perm:reader` could never equal
        # `<gid>|…|rid:<guid>`, so every run re-created assignments that already existed and
        # a -Prune classed every live assignment as a removal.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $ctx['armRoleCache'] = @{}
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['azGid']) { $ctx['azGid'] = @{} }
            $out = New-Object System.Collections.Generic.List[object]
            # 68.6 row 24: Remove rows resolve like desired rows and are kept apart as targeted removals.
            $rmRows = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources')) {
                $gt = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))".ToLowerInvariant()
                $scope = "$(Get-PimRowProp -Row $d -Names @('AzScope'))"
                $perm  = "$(Get-PimRowProp -Row $d -Names @('AzScopePermission'))"
                $gid = $null
                if ($gt) {
                    if ($ctx['azGid'].ContainsKey($gt)) { $gid = $ctx['azGid'][$gt] }
                    else { $gn = $tagToName[$gt]; if ($gn) { $gid = Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['azGid'][$gt] = $gid } } }
                }
                $rid = $null
                if ($scope -and $perm) { $rid = Resolve-PimArmRoleId -Scope $scope -RoleName $perm -Cache $ctx['armRoleCache'] }
                $row = $d | Select-Object *
                if ($gid -and $rid) {
                    Add-Member -InputObject $row -NotePropertyName principalId -NotePropertyValue $gid -Force
                    Add-Member -InputObject $row -NotePropertyName RoleId      -NotePropertyValue $rid -Force
                }
                if (Test-PimRowIsRemove $d) { $rmRows.Add($row) } else { $out.Add($row) }
            }
            $ctx['removeRows:AzRes'] = $rmRows.ToArray()
            $out.ToArray()
        }
        GetRemoveRows = {
            param($ctx)
            # A scope whose live read FAILED cannot prove a Remove row's assignment is absent: skip
            # those rows loudly rather than report "already absent" for something never read.
            $failed = $ctx['azLiveFailed']
            $ok = New-Object System.Collections.Generic.List[object]
            foreach ($r in @(Select-PimRemoveRows -Rows @($ctx['removeRows:AzRes']) -Scope 'AzRes')) {
                $s = "$(Get-PimRowProp -Row $r -Names @('AzScope'))".Trim()
                if ($failed -is [hashtable] -and $failed.ContainsKey($s)) {
                    Write-Warning ("  [engine] AzRes: Remove row at {0} NOT evaluated -- the live read of that scope failed ({1})." -f $s, $failed[$s])
                    continue
                }
                $ok.Add($r)
            }
            $ok.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['azGid']) { $ctx['azGid'] = @{} }
            foreach ($t in @($tagToName.Keys)) {
                if ($ctx['azGid'].ContainsKey($t)) { continue }
                $gid = Resolve-PimLiveGroupIdByName $tagToName[$t]; if ($gid) { $ctx['azGid'][$t] = $gid }
            }
            $owned = Get-PimSolutionOwnedGroups
            # BUG-17. Two changes, both about not letting DESIRED define the live universe:
            #   * the SCOPES come from the Azure resource DEFINITIONS (plus whatever the
            #     assignment rows mention), not from the assignment rows alone -- so deleting
            #     an assignment row leaves its scope in view and the orphan is visible;
            #   * at each scope we list ALL PIM schedule instances ONCE and keep the ones held
            #     by a solution-owned group, instead of one filtered call per (scope, group).
            #     That is bounded by the number of DEFINED SCOPES, not by scopes x groups.
            $scopes = @{}
            foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Resources')) {
                $s = "$(Get-PimRowProp -Row $r -Names @('AzScope','Scope','ResourceScope'))".Trim()
                if ($s -like '/subscriptions/*' -or $s -like '/providers/Microsoft.Management/*') { $scopes[$s] = $true }
            }
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources')) {
                $s = "$(Get-PimRowProp -Row $d -Names @('AzScope'))".Trim(); if ($s) { $scopes[$s] = $true }
            }
            $live = New-Object System.Collections.Generic.List[object]
            $ctx['azLiveFailed'] = @{}
            foreach ($scope in @($scopes.Keys)) {
                foreach ($pair in @(@{ ep='roleAssignmentScheduleInstances'; type='Active' }, @{ ep='roleEligibilityScheduleInstances'; type='Eligible' })) {
                    try {
                        foreach ($s in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/$($pair.ep)" -ApiVersion '2020-10-01-preview' -All)) {
                            # NB: NOT $pid -- that is a read-only PowerShell automatic variable
                            # (the process id) and assigning to it throws. The throw landed in
                            # the catch below, so the whole live read came back EMPTY and silent.
                            $prin = "$($s.properties.principalId)"
                            if (-not $owned.byId.ContainsKey($prin)) { continue }        # not ours -- never a removal candidate
                            $atScope = "$($s.properties.scope)"; if (-not $atScope) { $atScope = $scope }
                            if ($atScope -ne $scope) { continue }                        # inherited from an ancestor; owned there, not here
                            if ("$($s.properties.assignmentType)" -ieq 'Activated') { continue }   # an activation is not an assignment (68.6 rows 24-26)
                            $rid = ($s.properties.roleDefinitionId -split '/')[-1]
                            $live.Add([pscustomobject]@{ principalId=$prin; AzScope=$scope; RoleId=$rid; AssignmentType=$pair.type
                                                         roleDefinitionId="$($s.properties.roleDefinitionId)"
                                                         scheduleKnown=[bool]("$($s.properties.startDateTime)".Trim()); startDateTime=$s.properties.startDateTime; endDateTime=$s.properties.endDateTime })
                        }
                    } catch { $ctx['azLiveFailed'][$scope] = "$($_.Exception.Message)"; Write-Verbose "AzRes live ($scope/$($pair.ep)): $($_.Exception.Message)" }
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAzResKey -Row $r }
        TypeKeyOf = { param($r) Get-PimTypeNeutralKey -Key (Get-PimAzResKey -Row $r) }
        # 68.6 rows 25-26 (was `$true`: AutoExtend / UpdateExisting ignored).
        Equal = { param($d,$l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item,$ctx) Invoke-PimAssignmentMaintenanceApply -Kind AzRes -Item $item }
        ApplyRemove = { param($item,$ctx) Remove-PimAzResScheduleAssignment -Live $item.live -What "$($item.key)" }
        ApplyCreate = {
            param($item,$ctx)
            $d=$item.desired
            $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant(); $gid=$ctx['azGid'][$gt]
            $scope=Get-PimRowProp -Row $d -Names @('AzScope'); $perm=Get-PimRowProp -Row $d -Names @('AzScopePermission')
            # 🔴 REQ-W (2.4.380): a NEW Azure role assignment waits while the AzureRbac prerequisites are not green --
            # reported HELD, nothing written. A TYPE CHANGE's re-create is never held (its removal already ran);
            # extend / renew (ApplyUpdate) and removals are not gated.
            $__held = Get-PimWorkloadAssignmentHold -Workload 'AzureRbac' -Context $ctx -Item $item -Scope 'AzRes' -What ("Azure role '{0}' at {1} for group '{2}'" -f $perm, $scope, $gt)
            if ($__held) { return $__held }
            if (-not $gid -or -not $scope -or -not $perm) { throw "AzRes: unresolved group/scope/role ($gt / $scope / $perm)" }
            $rid = Resolve-PimArmRoleId -Scope $scope -RoleName $perm -Cache $ctx['armRoleCache']
            if (-not $rid) {
                $armErr = Get-PimArmRoleLookupError -Scope $scope -RoleName $perm -Cache $ctx['armRoleCache']
                if ($armErr) { throw "AzRes: could not look up ARM role '$perm' at ${scope}: $armErr" }
                throw "AzRes: ARM role '$perm' not found at $scope"
            }
            $type=Get-PimRowProp -Row $d -Names @('AssignmentType')
            $permFlag=(Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days=[int]("0"+(Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $start=[datetime]::UtcNow.ToString('o')
            $exp = if ($permFlag -or $days -le 0) { @{ type='noExpiration' } } else { @{ type='AfterDateTime'; endDateTime=([datetime]::UtcNow.AddDays($days).ToString('o')) } }
            $body=@{ properties=@{ principalId=$gid; roleDefinitionId="$scope/providers/Microsoft.Authorization/roleDefinitions/$rid"; requestType='AdminAssign'; justification='PIM4EntraPS engine'; scheduleInfo=@{ startDateTime=$start; expiration=$exp } } }
            $guid=[guid]::NewGuid().ToString()
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimArm -Method PUT -Path "$scope/providers/Microsoft.Authorization/$ep/$guid" -ApiVersion '2020-10-01-preview' -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupsPolicies scope -- PIM member-activation policy on a group, specifically the
# ACTIVATION-REQUIRES-APPROVAL rule (e.g. the GA delegation group must require
# approval). Driven by the definition's PolicyTemplate column: a value containing
# 'approval' marks the group as approval-required; approvers come from Owners.
# Ported from Set-PimGroupApprovalRule / CreateUpdate-Policies-PIM-Groups.
# ---------------------------------------------------------------------------
function Get-PimGroupPolicyAssignmentPath {
    param([Parameter(Mandatory)][string]$GroupId, [ValidateSet('member', 'owner')][string]$Role = 'member')
    "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq '$Role'"
}
function Get-PimGroupPolicyReadPath { param([Parameter(Mandatory)][string]$PolicyId) "/policies/roleManagementPolicies/$PolicyId`?`$expand=rules" }
# A group's member/owner policy id never changes for the life of the group, so a FOUND id is kept for
# 15 minutes (a miss is never cached: a group can be onboarded between reads). The batched GroupsPolicies
# live read fills it, so the apply that follows does not look the same id up again per item.
# 🔴 §70.10 (2026-09-13): 15 minutes was shorter than the read that fills it -- on internal the GroupsPolicies read
# took ~10 minutes, so by the next tick every one of the 706 ids was looked up AGAIN (706 of the 1,412 requests). An id
# is now kept for 12 hours in the process AND persisted in pim.Settings['GroupPolicyIdMap'], so a fresh tick process
# starts with every known id. A stale id (the policy read answers not-found) is dropped at once and looked up again.
$script:PimGrpPolicyIdTtlMinutes = 720
function Import-PimGroupPolicyIdMap {
    # Once per process: seed the in-memory cache from pim.Settings['GroupPolicyIdMap'] ({ "<groupId>|<role>": "<policyId>" }).
    if ($script:PimGrpPolicyIdMapLoaded) { return }
    $script:PimGrpPolicyIdMapLoaded = $true
    if (-not ($script:PimGrpPolicyIdCache -is [hashtable])) { $script:PimGrpPolicyIdCache = @{} }
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return }
    try {
        $v = Get-PimSetting -Name 'GroupPolicyIdMap'
        if ($v -is [string] -and "$v".Trim()) { $v = $v | ConvertFrom-Json }
        if ($null -eq $v) { return }
        $now = Get-Date; $n = 0
        foreach ($p in $v.PSObject.Properties) {
            if ("$($p.Name)" -match '^[^|]+\|(member|owner)$' -and "$($p.Value)".Trim() -and -not $script:PimGrpPolicyIdCache.ContainsKey("$($p.Name)")) {
                $script:PimGrpPolicyIdCache["$($p.Name)"] = @{ id = "$($p.Value)"; at = $now }; $n++
            }
        }
        if ($n) { Write-Host "  [perf] group policy ids: $n loaded from pim.Settings['GroupPolicyIdMap']" -ForegroundColor DarkGray }
    } catch { Write-Verbose "GroupPolicyIdMap load failed: $($_.Exception.Message)" }
}
function Save-PimGroupPolicyIdMap {
    # Persist the known ids when something changed (a new id, or a stale one dropped). The store writes nothing when the
    # value is identical (§70.8), so a steady-state tick costs no transaction log.
    if (-not $script:PimGrpPolicyIdMapDirty) { return }
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return }
    $map = [ordered]@{}
    foreach ($k in @($script:PimGrpPolicyIdCache.Keys | Sort-Object)) { $e = $script:PimGrpPolicyIdCache[$k]; if ($e -is [hashtable] -and "$($e.id)".Trim()) { $map["$k"] = "$($e.id)" } }
    try { Set-PimSetting -Name 'GroupPolicyIdMap' -Value ([pscustomobject]$map) | Out-Null; $script:PimGrpPolicyIdMapDirty = $false }
    catch { Write-Verbose "GroupPolicyIdMap save failed: $($_.Exception.Message)" }
}
function Remove-PimGroupPolicyIdCached {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$Role)
    if ($script:PimGrpPolicyIdCache -is [hashtable] -and $script:PimGrpPolicyIdCache.ContainsKey("$GroupId|$Role")) {
        $script:PimGrpPolicyIdCache.Remove("$GroupId|$Role"); $script:PimGrpPolicyIdMapDirty = $true
    }
}
function Get-PimGroupPolicyIdCached {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$Role)
    Import-PimGroupPolicyIdMap
    if (-not ($script:PimGrpPolicyIdCache -is [hashtable])) { $script:PimGrpPolicyIdCache = @{} }
    $ttl = if ($script:PimGrpPolicyIdTtlMinutes -gt 0) { $script:PimGrpPolicyIdTtlMinutes } else { 720 }
    $hit = $script:PimGrpPolicyIdCache["$GroupId|$Role"]
    if ($hit -is [hashtable] -and $hit.at -and ((Get-Date) - $hit.at).TotalMinutes -lt $ttl) { return "$($hit.id)" }
    return $null
}
function Set-PimGroupPolicyIdCached {
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$Role, [string]$PolicyId)
    if (-not "$PolicyId".Trim()) { return }
    if (-not ($script:PimGrpPolicyIdCache -is [hashtable])) { $script:PimGrpPolicyIdCache = @{} }
    $prev = $script:PimGrpPolicyIdCache["$GroupId|$Role"]
    if (-not ($prev -is [hashtable]) -or "$($prev.id)" -ne "$PolicyId") { $script:PimGrpPolicyIdMapDirty = $true }
    $script:PimGrpPolicyIdCache["$GroupId|$Role"] = @{ id = "$PolicyId"; at = (Get-Date) }
}
function Get-PimGroupMemberPolicyId {
    param([string]$GroupId)
    $c = Get-PimGroupPolicyIdCached -GroupId "$GroupId" -Role 'member'; if ($c) { return $c }
    try { $a = @(Invoke-PimGraph -All -Path (Get-PimGroupPolicyAssignmentPath -GroupId "$GroupId" -Role 'member')); if ($a.Count) { Set-PimGroupPolicyIdCached -GroupId "$GroupId" -Role 'member' -PolicyId "$($a[0].policyId)"; return "$($a[0].policyId)" } } catch { Set-PimGroupPolicyLookupError -GroupId "$GroupId" -Role 'member' -Message "$($_.Exception.Message)"; Write-Verbose "policyId ($GroupId): $($_.Exception.Message)" }
    return $null
}

# Why a group policy lookup returned nothing. Measured 2026-09-13 on four live environments: the engine
# identity lacked RoleManagementPolicy.ReadWrite.AzureADGroup, Graph refused the read, the refusal was
# swallowed, and the run reported "no member policy" for groups whose policies exist.
function Set-PimGroupPolicyLookupError {
    param([string]$GroupId, [string]$Role, [string]$Message)
    if (-not ($script:PimGrpPolicyLookupErr -is [hashtable])) { $script:PimGrpPolicyLookupErr = @{} }
    $script:PimGrpPolicyLookupErr["$GroupId|$Role"] = "$Message"
}
function Get-PimGroupPolicyMissingMessage {
    # PURE-ish. The error to throw when a group's policy id could not be resolved.
    param([string]$GroupName, [string]$GroupId, [string]$Role)
    $err = if ($script:PimGrpPolicyLookupErr -is [hashtable]) { "$($script:PimGrpPolicyLookupErr["$GroupId|$Role"])" } else { '' }
    if ($err -match '(?i)\b(401|403)\b|Forbidden|Authorization_RequestDenied|AccessDenied|insufficient privileges|Unauthorized') {
        return ("GroupsPolicies: PERMISSION DENIED reading the {0} policy of '{1}' -- the engine identity is missing Graph application role RoleManagementPolicy.ReadWrite.AzureADGroup (grant it: setup/Grant-PimGraphAppRoles.ps1 / Grant-PimMiGraph). The policy itself is not missing. Graph said: {2}" -f $Role, $GroupName, $err)
    }
    if ($err) { return ("GroupsPolicies: the {0} policy of '{1}' could not be looked up: {2}" -f $Role, $GroupName, $err) }
    return ("GroupsPolicies: no {0} policy for '{1}' (Graph returned no policy assignment for this group)" -f $Role, $GroupName)
}

# ---------------------------------------------------------------------------
# v1->v2 policy-rule parity: v1 PIM_Policy_Check_Update wrote FOUR rule families
# (Approval, Enablement, Expiration, Notification). v2 GroupsPolicies originally
# wrote only Approval + Enablement. These pure builders let a policy template also
# declare Expiration (max activation duration) and Notification recipients, kept as
# standalone functions so the rule-body shaping is unit-testable offline (no Graph).
# The PATCH plumbing is identical to the Approval/Enablement rule patches.
# ---------------------------------------------------------------------------
# Map the three v1 expiration targets to (rule id, caller, level). The group member
# policy carries exactly these three Expiration rules (v1 Custom-Policies.ps1 baseline).
$script:PimExpirationTargets = @(
    @{ Key='EndUser_Assignment';  Id='Expiration_EndUser_Assignment';  Caller='EndUser'; Level='Assignment'  }
    @{ Key='Admin_Assignment';    Id='Expiration_Admin_Assignment';    Caller='Admin';   Level='Assignment'  }
    @{ Key='Admin_Eligibility';   Id='Expiration_Admin_Eligibility';   Caller='Admin';   Level='Eligibility' }
)
function New-PimGroupExpirationRuleBody {
    # Build ONE unifiedRoleManagementPolicyExpirationRule for the given target.
    # $MaxDuration is an ISO-8601 duration (e.g. 'PT8H'/'P1D'/'P365D'); blank/absent -> $null (no rule).
    # Default target = EndUser/Assignment (member activation cap), so the legacy single-arg
    # call -MaxDuration 'PT8H' stays valid; pass -Caller/-Level (+ optional -Id) for the
    # Admin/Assignment and Admin/Eligibility rules that bring the policy to full v1 parity.
    param(
        [string]$MaxDuration,
        [ValidateSet('EndUser','Admin')][string]$Caller = 'EndUser',
        [ValidateSet('Assignment','Eligibility')][string]$Level = 'Assignment',
        [string]$Id,
        [bool]$IsExpirationRequired = $true
    )
    $dur = "$MaxDuration".Trim()
    if (-not $dur) { return $null }
    $rid = if ("$Id".Trim()) { "$Id".Trim() } else { "Expiration_${Caller}_${Level}" }
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
        id            = $rid
        target        = @{ caller=$Caller; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        isExpirationRequired = $IsExpirationRequired
        maximumDuration      = $dur
    }
}
function ConvertTo-PimExpirationRuleBodies {
    # Normalise a template's "Expiration" value into the FULL v1 expiration rule set.
    #   - a plain string ('P1D')         -> just the EndUser/Assignment cap (legacy shape)
    #   - an object keyed by target name  -> one rule per declared target, e.g.
    #       { "EndUser_Assignment": { "maximumDuration":"P1D",  "isExpirationRequired":true },
    #         "Admin_Assignment":   { "maximumDuration":"P365D","isExpirationRequired":true },
    #         "Admin_Eligibility":  { "maximumDuration":"P365D","isExpirationRequired":true } }
    #     (each value may also be a bare duration string).
    # Returns an array of rule bodies (possibly empty).
    param($Expiration)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Expiration) { return $out.ToArray() }
    if ($Expiration -is [string]) {
        $b = New-PimGroupExpirationRuleBody -MaxDuration "$Expiration"
        if ($b) { $out.Add($b) }
        return $out.ToArray()
    }
    foreach ($t in $script:PimExpirationTargets) {
        $val = $null
        if ($Expiration.PSObject -and $Expiration.PSObject.Properties[$t.Key]) { $val = $Expiration.$($t.Key) }
        elseif ($Expiration -is [hashtable] -and $Expiration.ContainsKey($t.Key)) { $val = $Expiration[$t.Key] }
        if ($null -eq $val) { continue }
        $dur = $null; $req = $true
        if ($val -is [string]) { $dur = "$val" }
        else {
            if ($val.PSObject -and $val.PSObject.Properties['maximumDuration']) { $dur = "$($val.maximumDuration)" }
            elseif ($val -is [hashtable] -and $val.ContainsKey('maximumDuration')) { $dur = "$($val['maximumDuration'])" }
            if ($val.PSObject -and $val.PSObject.Properties['isExpirationRequired']) { $req = [bool]$val.isExpirationRequired }
            elseif ($val -is [hashtable] -and $val.ContainsKey('isExpirationRequired')) { $req = [bool]$val['isExpirationRequired'] }
        }
        $b = New-PimGroupExpirationRuleBody -MaxDuration $dur -Caller $t.Caller -Level $t.Level -Id $t.Id -IsExpirationRequired $req
        if ($b) { $out.Add($b) }
    }
    $out.ToArray()
}
# Map the v1 enablement targets to (rule id, caller, level). The group member policy
# carries MFA+Justification on EndUser/Assignment AND Admin/Eligibility, and NONE on
# Admin/Assignment (v1 Custom-Policies.ps1 baseline).
$script:PimEnablementTargets = @(
    @{ Key='EndUser_Assignment'; Id='Enablement_EndUser_Assignment'; Caller='EndUser'; Level='Assignment'  }
    @{ Key='Admin_Eligibility';  Id='Enablement_Admin_Eligibility';  Caller='Admin';   Level='Eligibility' }
    @{ Key='Admin_Assignment';   Id='Enablement_Admin_Assignment';   Caller='Admin';   Level='Assignment'  }
)
function Assert-PimGroupPolicyPatchesApplied {
    <#
      BUG-52 -- turn collected rule-PATCH failures into a REAL failure for the item.

      The engine counts a provider's ApplyUpdate as applied unless it throws. So a swallowed
      PATCH error produced `applied=N errors=0` for work that never happened, and the scope
      printed its PLAN (`GroupsPolicies: c0/u112/r0`) as if it were the result. That is the
      condition that made a three-session non-convergence undiagnosable from the logs.

      Throwing here is deliberate over warning: "the policy is not what the template says" is not
      a degraded success, and the next run's diff will simply re-plan the item. Every failing rule
      is named in ONE message so a partially-applied policy is fully described rather than
      reported one rule at a time.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GroupName, $Failures)
    $f = @($Failures)
    if (-not $f.Count) { return }
    throw ("GroupsPolicies '$GroupName': $($f.Count) rule PATCH(es) FAILED, so the policy does NOT " +
           "match the template: " + ($f -join ' | '))
}

function New-PimGroupEnablementRuleBody {
    # Build ONE unifiedRoleManagementPolicyEnablementRule for the given target.
    # $EnabledRules = e.g. @('MultiFactorAuthentication','Justification') (empty = clear the rule).
    param(
        [string[]]$EnabledRules = @(),
        [ValidateSet('EndUser','Admin')][string]$Caller = 'EndUser',
        [ValidateSet('Assignment','Eligibility')][string]$Level = 'Assignment',
        [string]$Id
    )
    $rid = if ("$Id".Trim()) { "$Id".Trim() } else { "Enablement_${Caller}_${Level}" }
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
        id            = $rid
        target        = @{ caller=$Caller; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        enabledRules  = @($EnabledRules | Where-Object { $_ })
    }
}
function ConvertTo-PimEnablementRuleBodies {
    # Normalise a template's enablement declaration into the FULL v1 enablement rule set.
    # Accepts either the structured "Enablement" object:
    #   { "EndUser_Assignment": ["MultiFactorAuthentication","Justification"],
    #     "Admin_Eligibility":  ["MultiFactorAuthentication","Justification"],
    #     "Admin_Assignment":   [] }
    # OR the legacy single key value (Member_Enablement_EndUser_Assignment_enabledRules),
    # which maps to EndUser/Assignment only. Returns an array of rule bodies.
    param($Enablement, $LegacyEndUserAssignment)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Enablement) {
        foreach ($t in $script:PimEnablementTargets) {
            $val = $null; $present = $false
            if ($Enablement.PSObject -and $Enablement.PSObject.Properties[$t.Key]) { $val = $Enablement.$($t.Key); $present = $true }
            elseif ($Enablement -is [hashtable] -and $Enablement.ContainsKey($t.Key)) { $val = $Enablement[$t.Key]; $present = $true }
            if (-not $present) { continue }
            $out.Add((New-PimGroupEnablementRuleBody -EnabledRules @($val) -Caller $t.Caller -Level $t.Level -Id $t.Id))
        }
        return $out.ToArray()
    }
    if ($null -ne $LegacyEndUserAssignment) {
        $out.Add((New-PimGroupEnablementRuleBody -EnabledRules @($LegacyEndUserAssignment) -Caller 'EndUser' -Level 'Assignment'))
    }
    $out.ToArray()
}
function New-PimGroupNotificationRuleBody {
    # One notification rule (Graph requires one rule per recipient-type x event).
    # $RecipientType in Admin|Requestor|Approver; $Level in Eligibility|Assignment;
    # $NotificationLevel in All|Critical; $Recipients = extra email addresses.
    # $Caller (parity audit #5, 2026-09-13): v1 set NINE notification rules and six of them are on the
    # ADMIN caller -- Notification_{Admin,Requestor,Approver}_Admin_{Eligibility,Assignment} ("members are
    # assigned as eligible / active"). This builder always emitted caller=EndUser, so those six could not
    # be expressed at all. Default stays EndUser, so every existing call is unchanged.
    param(
        [Parameter(Mandatory)][ValidateSet('Admin','Requestor','Approver')][string]$RecipientType,
        [Parameter(Mandatory)][ValidateSet('Eligibility','Assignment')][string]$Level,
        [ValidateSet('All','Critical')][string]$NotificationLevel = 'All',
        [string[]]$Recipients = @(),
        [bool]$DefaultRecipientsEnabled = $true,
        [ValidateSet('EndUser','Admin')][string]$Caller = 'EndUser'
    )
    $id = "Notification_${RecipientType}_${Caller}_${Level}"
    @{
        '@odata.type'             = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'
        id                        = $id
        target                    = @{ caller=$Caller; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        notificationType          = 'Email'
        recipientType             = $RecipientType
        notificationLevel         = $NotificationLevel
        isDefaultRecipientsEnabled= $DefaultRecipientsEnabled
        notificationRecipients    = @($Recipients | Where-Object { $_ })
    }
}
function ConvertTo-PimNotificationRuleBody {
    # PURE: ONE template Notification entry -> its rule body, or $null when the entry is incomplete.
    # The single place an entry's fields are read, so every provider builds the same id for it
    # (recipientType, level, optional caller -- default EndUser -- notificationLevel, recipients,
    # defaultRecipientsEnabled).
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry) { return $null }
    $get = { param($n) if ($Entry -is [System.Collections.IDictionary]) { $Entry[$n] } elseif ($Entry.PSObject.Properties[$n]) { $Entry.$n } else { $null } }
    $rt = "$(& $get 'recipientType')"; $lvl = "$(& $get 'level')"
    if (-not $rt -or -not $lvl) { return $null }
    $caller = "$(& $get 'caller')".Trim(); if (-not $caller) { $caller = 'EndUser' }
    $recips = @(@(& $get 'recipients') | Where-Object { "$_".Trim() })
    $nlvl = "$(& $get 'notificationLevel')"; if (-not $nlvl) { $nlvl = 'All' }
    $defRaw = & $get 'defaultRecipientsEnabled'
    $defOn = if ($null -eq $defRaw) { $true } else { [bool]$defRaw }
    New-PimGroupNotificationRuleBody -RecipientType $rt -Level $lvl -NotificationLevel $nlvl -Recipients $recips -DefaultRecipientsEnabled $defOn -Caller $caller
}
function Resolve-PimTemplateNotifications {
    <#
      PURE-ish: a template's Notification entries resolved for ONE target, de-duplicated by rule id.
        * recipientsSource ApproverUpns / NotifyUpns is resolved from the target's row values;
        * an entry that REDIRECTS (has a recipientsSource) with defaults off and resolves to nobody is
          SKIPPED -- never silence a notification because a redirect is unconfigured (it is reported
          through -NoAudience) -- and whatever an EARLIER entry set for that rule id stays;
        * a plain entry with defaultRecipientsEnabled=false is a deliberate "off" (v1's values) and is kept;
        * later entries override earlier ones for the same rule id, so a template lists v1's baseline
          first and its redirects after.
    #>
    param([object[]]$Entries, [string]$ApproverUpns = '', [string]$NotifyUpns = '', [System.Collections.Generic.List[string]]$NoAudience, [string]$Label = '')
    $byId = [ordered]@{}
    foreach ($n in @($Entries)) {
        if ($null -eq $n) { continue }
        $entry = $n | Select-Object *
        $src = "$(if ($entry.PSObject.Properties['recipientsSource']) { $entry.recipientsSource } else { '' })".Trim()
        if ($src -eq 'ApproverUpns' -or $src -eq 'NotifyUpns') {
            $srcVal = if ($src -eq 'ApproverUpns') { $ApproverUpns } else { $NotifyUpns }
            $ups = @("$srcVal" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Add-Member -InputObject $entry -NotePropertyName recipients -NotePropertyValue $ups -Force
        }
        $defOn = if ($entry.PSObject.Properties['defaultRecipientsEnabled']) { [bool]$entry.defaultRecipientsEnabled } else { $true }
        $recipCount = @($entry.recipients | Where-Object { "$_".Trim() }).Count
        if ($src -and -not $defOn -and $recipCount -eq 0) {
            if ($null -ne $NoAudience -and $Label) { [void]$NoAudience.Add($Label) }
            continue
        }
        $b = ConvertTo-PimNotificationRuleBody -Entry $entry
        if (-not $b) { continue }
        $byId["$($b.id)"] = $entry
    }
    @($byId.Values)
}

# ---------------------------------------------------------------------------
# BUG-56 -- turning approval OFF, and getting out of a WRITE-LOCKED policy.
#
# Two facts, both measured live on throwaway roles in an isolated test tenant (2026-08-11).
# They are the whole reason these three helpers exist; do not "simplify" them away.
#
# 1. THE OFF BODY MUST BE COMPLETE. The obvious minimal merge -- setting.isApprovalRequired
#    = false on its own -- is rejected with `400 ArgumentNullException "Value cannot be null.
#    Parameter name: source"`. Entra wants the whole setting object, including an
#    approvalStages entry with an EMPTY primaryApprovers list. That reads like belt-and-braces
#    and is not: the short body simply does not work.
#
# 2. A POLICY CAN BE WRITE-LOCKED, AND THEN ONLY THE WHOLE-POLICY ROUTE WORKS. If a policy's
#    Notification_Approver_* rule ever ends up with isDefaultRecipientsEnabled=false AND a
#    non-empty recipient list, Entra treats that list as the policy's "activation custom
#    approvers" and refuses EVERY subsequent PATCH to /rules/{ruleId} with
#        400 ActivationCustomApproversNotEmpty "The activation custom approvers should be empty."
#    -- including rules that have nothing to do with approval (proven with an Expiration
#    rule), and including the PATCH that would clear the offending recipients. The poisoning
#    write itself is ACCEPTED, so nothing fails at the time it is done.
#    `PATCH /policies/roleManagementPolicies/{policyId}` with a `rules` COLLECTION stays open
#    in that state and is the only way back. It is also the only shape that can express
#    "approvers gone" and "approval not required" atomically, which is what the portal's
#    single Update does.
#
# The engine no longer ships that poisoning shape (guarded by
# tests/Test-PimPolicyTemplateSatisfiable.ps1), but a customer's policy can already be in the
# state -- set by hand in the portal, or by an older engine build -- so the recovery path has
# to exist rather than log the same refusal forever.
# ---------------------------------------------------------------------------
function New-PimApprovalOffRuleBody {
    # PURE: the approval rule body that turns approval OFF. Complete by necessity -- see (1).
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
        id            = 'Approval_EndUser_Assignment'
        target        = @{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
        setting       = @{
            isApprovalRequired               = $false
            isApprovalRequiredForExtension   = $false
            isRequestorJustificationRequired = $true
            approvalMode                     = 'NoApproval'
            approvalStages                   = @(@{
                approvalStageTimeOutInDays      = 1
                isApproverJustificationRequired = $true
                escalationTimeInMinutes         = 0
                isEscalationEnabled             = $false
                primaryApprovers                = @()
                escalationApprovers             = @()
            })
        }
    }
}
function Test-PimPolicyWriteLocked {
    # PURE: is this Graph failure the write-lock described in (2)? Matched on the error CODE
    # and on the message text, because the code is not always present in the surfaced string.
    param([string]$Message)
    return ("$Message" -match '(?i)ActivationCustomApproversNotEmpty|activation custom approvers should be empty')
}
function Set-PimPolicyRuleSet {
    # The whole-policy route. `rules` is a COLLECTION here, not a single rule.
    # A 1-element array survives as a JSON array because it is a hashtable PROPERTY -- the
    # ConvertTo-Json unwrap trap this codebase records applies to the PIPELINE form
    # (`@($x) | ConvertTo-Json`), not to this one. Verified before relying on it.
    param([Parameter(Mandatory)][string]$PolicyId, [Parameter(Mandatory)][object[]]$Rules)
    Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId" -Body @{ rules = @($Rules) } | Out-Null
}
function Repair-PimWriteLockedPolicy {
    <#
      Clear the POISON, not just the symptom.

      Working around a write-locked policy by routing one PATCH through the whole-policy
      endpoint leaves the offending Notification_Approver_* rule in place, so the NEXT run is
      locked again -- and the engine would quietly depend on the fallback forever. This flips
      the rule's isDefaultRecipientsEnabled back ON, which is the half that makes the pair
      poisonous, while KEEPING the recipient list: who gets told is a deliberate setting and
      losing it silently would be its own defect. `defaults=true` with explicit recipients is
      exactly what the shipped approval template uses and is measured safe.

      🪤 TWO THINGS ABOUT THE UNLOCK CALL, BOTH MEASURED LIVE AND BOTH COUNTER-INTUITIVE.
      1. IT MUST GO ALONE. The obvious version rode the caller's rule along in the same
         whole-policy PATCH so the unlock and the change would be atomic. That payload is
         REFUSED with the very error it is clearing; the identical PATCH carrying only the
         notification rule is ACCEPTED.
      2. THE RECIPIENTS CANNOT BE KEPT. The first version of this flipped
         isDefaultRecipientsEnabled back on and preserved the recipient list, on the theory that
         the FLAG was the poisonous half. It is not: on a clean policy, defaults=TRUE with two
         explicit Approver recipients locks it just as hard as defaults=false does, and
         defaults=false with an EMPTY list does not lock it at all. The RECIPIENT LIST ALONE is
         the trigger. So the list has to go, and it cannot be restored afterwards -- putting it
         back re-locks the policy immediately (observed: the unlock succeeded, the restore
         succeeded, and the very next per-rule PATCH was refused again).
         The removed addresses are therefore NAMED in a warning rather than dropped quietly.
         Approver notification then falls back to Entra's default routing, which is the only
         thing Entra actually supports for this rule.
      Returns $true when it sent something.
    #>
    param([Parameter(Mandatory)][string]$PolicyId)
    $rules = @()
    try { $rules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$PolicyId`?`$expand=rules").rules) }
    catch { Write-Verbose "write-lock repair: could not read policy ${PolicyId}: $($_.Exception.Message)" }

    $send = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rules)) {
        if ("$($r.id)" -notlike 'Notification_Approver_*') { continue }
        # The RECIPIENT LIST is the trigger, on its own. isDefaultRecipientsEnabled is NOT part
        # of the test -- see (2) in the header.
        # 🪤 Filter blanks BEFORE counting: @($null).Count is 1, so a rule with no
        # notificationRecipients property at all would otherwise look poisoned and be "repaired".
        $lost = @($r.notificationRecipients | Where-Object { "$_".Trim() })
        if (-not $lost.Count) { continue }
        $lvl = ("$($r.id)" -split '_')[-1]
        if ($lvl -notin @('Assignment','Eligibility')) { continue }
        # The caller is part of the rule id (Notification_Approver_<Caller>_<Level>): rebuild the SAME rule,
        # not its EndUser twin, now that the Admin-caller notification rules are managed too (#5).
        $cl = ("$($r.id)" -split '_')[-2]; if ($cl -notin @('EndUser','Admin')) { $cl = 'EndUser' }
        $nlvl = if ("$($r.notificationLevel)") { "$($r.notificationLevel)" } else { 'All' }
        $send.Add((New-PimGroupNotificationRuleBody -RecipientType 'Approver' -Level $lvl -NotificationLevel $nlvl `
                    -Recipients @() -DefaultRecipientsEnabled $true -Caller $cl)) | Out-Null
        # NAME the addresses being removed. They cannot be kept (restoring them re-locks the
        # policy), so this is the only record that the redirect existed at all.
        Write-Warning ("  [engine] policy $PolicyId was WRITE-LOCKED by $($r.id): Entra treats an explicit " +
                       "Approver-notification recipient list as the policy's 'activation custom approvers' and then " +
                       'refuses every per-rule PATCH. REMOVING those recipients (' + ($lost -join ', ') + ') is the only ' +
                       'way to unlock it, and they CANNOT be restored -- approver notification falls back to Entra default ' +
                       'routing. See BUG-56.')
    }
    if (-not $send.Count) { return $false }
    Set-PimPolicyRuleSet -PolicyId $PolicyId -Rules $send.ToArray()
    return $true
}
function Get-PimPolicyRulePatchDiagnostic {
    <#
      2026-09-21 (operator, on "HTTP 400 : InvalidPolicyRule -- The policy rule is invalid.": "can you provide graph or
      arm errors in here as i have nothing to work with"). Graph says only THAT the rule is invalid, never WHICH value.
      So the message carries what is needed to find it: the rule body the engine SENT, the rule as it is LIVE now
      (the difference is the offending value), and Graph's request-id + date for a Microsoft support case.
      Best-effort -- a failure here never hides the original error, which always comes first.
    #>
    param([string]$PolicyId, [object]$Body, [string]$Message)
    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add($Message)
    try {
        $le = $global:PimLastRestError
        if ($le -and "$($le.body)" -and "$($le.url)" -like "*$PolicyId/rules/$($Body.id)*") {   # only THIS call's error, never a stale one
            $e = ("$($le.body)" | ConvertFrom-Json -ErrorAction Stop).error
            $ie = if ($e) { $e.innerError } else { $null }
            if ($ie) { [void]$parts.Add("graph request-id=$($ie.'request-id') client-request-id=$($ie.'client-request-id') date=$(if ($ie.date -is [datetime]) { $ie.date.ToString('yyyy-MM-ddTHH:mm:ss') } else { $ie.date }) UTC") }
            if ($e -and $e.details) { [void]$parts.Add('graph details: ' + (($e.details | ConvertTo-Json -Depth 6 -Compress))) }
        }
    } catch { }
    $cut = { param($s) $s = "$s"; if ($s.Length -gt 1500) { $s.Substring(0, 1500) + '...' } else { $s } }
    try { [void]$parts.Add('sent: ' + (& $cut ($Body | ConvertTo-Json -Depth 12 -Compress))) } catch { }
    try {
        $live = Invoke-PimGraph -Method GET -Path "/policies/roleManagementPolicies/$PolicyId/rules/$($Body.id)"
        if ($live) { $live.PSObject.Properties.Remove('@odata.context'); [void]$parts.Add('live: ' + (& $cut ($live | ConvertTo-Json -Depth 12 -Compress))) }
    } catch { [void]$parts.Add("live: (could not read the rule: $($_.Exception.Message))") }
    return ($parts -join ' || ')
}

function Invoke-PimPolicyRulePatch {
    <#
      PATCH one rule, and if the policy turns out to be WRITE-LOCKED, unlock it and apply the
      same rule in one whole-policy PATCH.

      Deliberately NOT a blanket retry: the fallback fires ONLY on the write-lock signature.
      Any other failure is re-thrown unchanged, so a genuine bad-payload error still surfaces
      as itself instead of being retried into a second, more confusing error.
    #>
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][object]$Body,
        [ref]$Recovered
    )
    try {
        Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId/rules/$($Body.id)" -Body $Body | Out-Null
        return
    } catch {
        if (-not (Test-PimPolicyWriteLocked $_.Exception.Message)) { throw (Get-PimPolicyRulePatchDiagnostic -PolicyId $PolicyId -Body $Body -Message $_.Exception.Message) }
    }
    # Write-locked. Clear the poison first (its own call -- see Repair-PimWriteLockedPolicy),
    # then re-apply the caller's rule normally, now that the policy accepts writes again.
    if (Repair-PimWriteLockedPolicy -PolicyId $PolicyId) {
        Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId/rules/$($Body.id)" -Body $Body | Out-Null
    }
    else {
        # Locked, but no poisoned Notification_Approver_* rule to explain it. Last resort: the
        # whole-policy route, which is the only shape that can express "approvers gone AND
        # approval not required" atomically. NOT live-proven for this case -- no way was found
        # to produce a lock without the notification pair -- so it is a fallback, not the path.
        Set-PimPolicyRuleSet -PolicyId $PolicyId -Rules @($Body)
    }
    if ($Recovered) { $Recovered.Value = $true }
}

# ---------------------------------------------------------------------------
# GroupsCreateModifyPolicy -- full idempotent compare for a group's PIM member
# policy. The provider PATCHes FOUR rule families (Approval, Expiration x3,
# Enablement x3, Notification per recipient-type x event). To be genuinely
# create/modify + idempotent (no redundant PATCH when already matching, modify
# only when drifted), the diff must read back + compare EVERY rule it writes --
# not just the EndUser/Assignment subset. These PURE builders normalise the
# desired template + the live policy into the SAME comparable shape, so a single
# string compare per rule decides in-sync vs drift. No Graph here -> unit-testable.
# (The Approval/Expiration/Enablement/Notification rule BODIES are the existing
# New-PimGroup*RuleBody / ConvertTo-Pim*RuleBodies builders -- reused verbatim.)
# ---------------------------------------------------------------------------
function ConvertTo-PimSortedList {
    # PURE: a deterministic, case-insensitive, comma-joined string for an unordered
    # string set (enabledRules, recipient lists) so order never causes a false drift.
    param([object]$Values)
    @(@($Values) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique) -join ','
}
function Get-PimGroupPolicyDesiredFacets {
    # PURE: the comparable snapshot the engine WANTS for a group, derived from a desired
    # row (the object GetDesired emits: Approval/Expiration/Enablement/EnablementLegacy/
    # Notification + already-resolved ApproverIds). Returns a hashtable keyed by rule id;
    # each value is a normalised string. Only rules the provider would PATCH appear -- so a
    # facet absent from the template is absent here (the compare won't demand it live).
    param([Parameter(Mandatory)][object]$Desired)
    $f = @{}
    foreach ($b in @(ConvertTo-PimExpirationRuleBodies -Expiration $Desired.Expiration)) {
        $f[$b.id] = "exp|dur=$($b.maximumDuration)|req=$([bool]$b.isExpirationRequired)"
    }
    foreach ($b in @(ConvertTo-PimEnablementRuleBodies -Enablement $Desired.Enablement -LegacyEndUserAssignment $Desired.EnablementLegacy)) {
        $f[$b.id] = "en|rules=$(ConvertTo-PimSortedList $b.enabledRules)"
    }
    if ($Desired.Notification) {
        foreach ($n in @($Desired.Notification)) {
            $nb = ConvertTo-PimNotificationRuleBody -Entry $n   # honours the entry's caller (#5)
            if (-not $nb) { continue }
            $f[$nb.id] = "notify|lvl=$($nb.notificationLevel)|def=$($nb.isDefaultRecipientsEnabled)|recips=$(ConvertTo-PimSortedList $nb.notificationRecipients)"
        }
    }
    if ($Desired.PSObject -and $Desired.PSObject.Properties['ManageApproval'] -and -not $Desired.ManageApproval) {
        # #4/#5: a GROUP OWNER policy, or a BASELINE target no row names, is not the engine's to gate --
        # v1 never touched approval there. No approval facet at all, so live approval is neither
        # demanded nor turned off.
        return $f
    }
    if ($Desired.Approval) {
        # Approver identity set (already resolved upstream into ApproverIds) is part of the
        # facet so that adding/removing an owner is a detectable drift, not a silent nochange.
        $approverIds = ConvertTo-PimSortedList $Desired.ApproverIds
        $f['Approval_EndUser_Assignment'] = "appr|required=true|approvers=$approverIds"
    }
    else {
        # BUG-56: a template WITHOUT an Approval block means approval must be OFF -- it does not
        # mean "don't look". The old behaviour ("the engine never touches an approval rule it did
        # not itself apply") left a live approval stranded and unmanaged forever, so the product
        # could switch a role INTO approval and never back out. That is exactly what happened to a
        # production role: it was the ONLY drifting role of 96, because every write to its policy
        # was being refused and nothing converged it.
        #
        # Stating the OFF expectation here is what makes it a detectable drift instead of a silent
        # nochange. It is a desired-state change, so it was WhatIf'd against production before
        # shipping: both policy scopes stayed at update=0 (no managed role or group currently
        # carries an approval the engine did not itself apply), i.e. it converges nothing today and
        # arms the engine for the case that previously stranded.
        $f['Approval_EndUser_Assignment'] = 'appr|required=false|approvers='
    }
    $f
}
function Get-PimGroupPolicyLiveFacets {
    # PURE: the comparable snapshot a LIVE policy currently HAS, from its expanded rules
    # collection (the array under roleManagementPolicies/{id}?$expand=rules). Keyed by rule
    # id with the SAME normalised string shape as Get-PimGroupPolicyDesiredFacets, so the
    # two are directly comparable. A rule the policy doesn't carry simply isn't present.
    param([object[]]$Rules)
    $f = @{}
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $id = "$($r.id)"; if (-not $id) { continue }
        $type = "$($r.'@odata.type')"
        if ($id -like 'Expiration_*' -or $type -like '*ExpirationRule') {
            $f[$id] = "exp|dur=$($r.maximumDuration)|req=$([bool]$r.isExpirationRequired)"
        }
        elseif ($id -like 'Enablement_*' -or $type -like '*EnablementRule') {
            $f[$id] = "en|rules=$(ConvertTo-PimSortedList $r.enabledRules)"
        }
        elseif ($id -like 'Notification_*' -or $type -like '*NotificationRule') {
            $f[$id] = "notify|lvl=$($r.notificationLevel)|def=$([bool]$r.isDefaultRecipientsEnabled)|recips=$(ConvertTo-PimSortedList $r.notificationRecipients)"
        }
        elseif ($id -eq 'Approval_EndUser_Assignment' -or $type -like '*ApprovalRule') {
            $required = $false; $approverIds = @()
            if ($r.setting) {
                $required = [bool]$r.setting.isApprovalRequired
                foreach ($st in @($r.setting.approvalStages)) {
                    foreach ($a in @($st.primaryApprovers)) { if ($a.userId) { $approverIds += "$($a.userId)" } }
                }
            }
            $f[$id] = "appr|required=$($required.ToString().ToLowerInvariant())|approvers=$(ConvertTo-PimSortedList $approverIds)"
        }
    }
    $f
}
function Test-PimGroupPolicyInSync {
    # PURE: is the live policy already at the desired baseline? In-sync iff EVERY desired
    # facet exists live AND its normalised value matches. Live MAY carry extra rules the
    # engine doesn't manage -- those never force an update (the engine only owns what its
    # template declares). Returns $true (nochange) / $false (needs a modify PATCH).
    param([Parameter(Mandatory)][hashtable]$Desired, [hashtable]$Live = @{})
    foreach ($k in $Desired.Keys) {
        if (-not $Live.ContainsKey($k)) {
            # BUG-56: ONE exception to "a desired facet missing live means drift" -- a policy that
            # carries NO approval rule at all already satisfies "approval must be OFF". Absence and
            # required=false are the same state, so demanding a PATCH here would be a write that
            # changes nothing, forever, on every policy that simply has no approval rule.
            # Narrow on purpose: it applies ONLY to the approval facet and ONLY to the OFF value.
            # A missing rule can never satisfy required=TRUE.
            if ($k -eq 'Approval_EndUser_Assignment' -and "$($Desired[$k])" -eq 'appr|required=false|approvers=') { continue }
            return $false
        }
        if ("$($Live[$k])" -ne "$($Desired[$k])") { return $false }
    }
    return $true
}

# Policy templates -- SQL ONLY (operator, 2026-09-12: "move templates to sql"). The templates live in
# pim.Settings['PolicyTemplates'] (seeded from the shipped templates/policy/*.policytemplate.json by
# Update-PimPolicyTemplateStore at db-init / Manager boot: unmodified templates follow the shipped version,
# customised ones are kept and flagged TEMPLATE-UPGRADE-AVAILABLE -- BUG-55 semantics), hydrated into
# $global:PIM_NamingConventions like every other setting. There is NO file read here and NO
# *.policytemplate.custom.json override. Single-level 'extends' is merged exactly as before. A definition's
# PolicyTemplate column selects one; BLANK = the group default, Groups_Standard (formerly 'default'; pim.Settings['PolicyTemplateDefaults'].group) -- every group is linked.
# $global:PIM_PolicyTemplates is the in-memory injection seam (tests, or a host that has already read the
# setting) -- the same pattern as $global:PIM_DesiredRows for rows.
$script:PimEngineRoot = if ($PSScriptRoot) { (Resolve-Path "$PSScriptRoot\..\..").Path } else { $null }
# 2026-09-19 (operator: one Standard + RequireApproval pair per policy type; "give policies an id so we can rename
# them"; "set default in settings"): the template store lib is loaded HERE, with the providers, so every template
# lookup in the engine and the scheduler resolves the same way -- id, then current name, then former id
# (Resolve-PimPolicyTemplateKey) -- and a BLANK PolicyTemplate means the per-kind default from
# pim.Settings['PolicyTemplateDefaults'] (Get-PimEnginePolicyTemplateDefaultId). It also loads PIM-PolicyBaseline.ps1.
if ($PSScriptRoot -and -not (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-PolicyTemplateStore.ps1'))) {
    . (Join-Path $PSScriptRoot 'PIM-PolicyTemplateStore.ps1')
}
# REQ-WHATIF (77.1): the current -> new impact report every policy hold carries. Loaded UNCONDITIONALLY with the
# providers -- a Get-Command guard on a library nobody dot-sources is false forever (33.0 trap).
if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-PolicyImpact.ps1'))) {
    . (Join-Path $PSScriptRoot 'PIM-PolicyImpact.ps1')
}
# §79.14: the CAB workbook (.xlsx, no module) the policy-hold mail carries. Loaded unconditionally, like the impact report.
if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-Xlsx.ps1'))) {
    . (Join-Path $PSScriptRoot 'PIM-Xlsx.ps1')
}
function Get-PimEnginePolicyTemplates {
    $raw = $null
    if ($null -ne $global:PIM_PolicyTemplates) { $raw = $global:PIM_PolicyTemplates }
    elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PolicyTemplates')) { $raw = $global:PIM_NamingConventions['PolicyTemplates'] }
    elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $raw = Get-PimSetting -Name 'PolicyTemplates' } catch { $raw = $null } }
    if (-not (Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue) -and $PSScriptRoot) {
        $tsLib = Join-Path $PSScriptRoot 'PIM-PolicyTemplateStore.ps1'
        if (Test-Path -LiteralPath $tsLib) { . $tsLib }
    }
    $byId = @{}
    if (Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue) { $byId = ConvertTo-PimPolicyTemplateMap -Value $raw }
    if ($byId.Count -eq 0) {
        Write-Warning "  [policy] NO policy templates in the SQL store (pim.Settings 'PolicyTemplates') -- the policy providers have nothing to apply. Seed them with Initialize-PimPolicyTemplateStore (the Manager and the db-init job do this on a fresh store)."
    }
    $out = @{}
    $haveResolver = [bool](Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue)
    foreach ($id in @($byId.Keys)) {
        $j = $byId[$id]; $rules = @{}
        # 'extends' resolves like a row's PolicyTemplate: id, current name, former id ('default' -> Groups_Standard).
        $ext = "$($j.extends)".Trim()
        $extKey = if (-not $ext) { '' } elseif ($haveResolver) { Resolve-PimPolicyTemplateKey -Map $byId -Id $ext } elseif ($byId.ContainsKey($ext)) { $ext } else { '' }
        if ($extKey) { $base = $byId[$extKey]; if ($base.rules) { foreach ($p in $base.rules.PSObject.Properties) { $rules[$p.Name] = $p.Value } } }
        if ($j.rules) { foreach ($p in $j.rules.PSObject.Properties) { $rules[$p.Name] = $p.Value } }
        $out[$id] = [pscustomobject]@{ id = $id; name = "$($j.name)"; rules = $rules }
    }
    $out
}
function Get-PimEnginePolicyTemplateDefaultId {
    <#
      2026-09-19 (operator: "set default in settings"). The template a BLANK PolicyTemplate means for one kind of
      policy -- 'group' (a group definition row / the baseline sweep), 'directoryRole' (an Entra role row / the role
      baseline), 'azureRole' (an Azure-Resources row). Read from pim.Settings['PolicyTemplateDefaults'] (hydrated into
      $global:PIM_NamingConventions like every setting; $global:PIM_PolicyTemplateDefaults is the test seam) and
      resolved against the stored templates (Resolve-PimPolicyTemplateTypeDefaults). Unset = the built-in defaults
      Groups_Standard / EntraIDRoles_Standard / AzureRoles_Standard -- today's behaviour. A setting naming a template
      the store lacks is WARNED about and the built-in default used; never silent.
    #>
    param([Parameter(Mandatory)][ValidateSet('group', 'directoryRole', 'azureRole')][string]$Kind)
    $set = $null
    if ($null -ne $global:PIM_PolicyTemplateDefaults) { $set = $global:PIM_PolicyTemplateDefaults }
    elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PolicyTemplateDefaults')) { $set = $global:PIM_NamingConventions['PolicyTemplateDefaults'] }
    $all = if ($script:__pimTplCache) { $script:__pimTplCache } else { $script:__pimTplCache = Get-PimEnginePolicyTemplates; $script:__pimTplCache }
    if (-not (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue)) {
        return "$(@{ group = 'Groups_Standard'; directoryRole = 'EntraIDRoles_Standard'; azureRole = 'AzureRoles_Standard' }[$Kind])"
    }
    $r = Resolve-PimPolicyTemplateTypeDefaults -Setting $set -Map $all
    if (-not $script:__pimTplDefaultWarned) { $script:__pimTplDefaultWarned = @{} }
    foreach ($w in @($r.warnings)) { if (-not $script:__pimTplDefaultWarned.ContainsKey("$w")) { $script:__pimTplDefaultWarned["$w"] = $true; Write-Warning "  [policy] $w" } }
    return "$($r.defaults[$Kind])"
}
function Resolve-PimEnginePolicyTemplateId {
    <# The stored id a row's PolicyTemplate value resolves to (id, current name, former id); the value as given when
       nothing resolves, so the caller's "unknown template" report still names what the row says. #>
    param([string]$Id)
    $t = "$Id".Trim(); if (-not $t) { return '' }
    $all = if ($script:__pimTplCache) { $script:__pimTplCache } else { $script:__pimTplCache = Get-PimEnginePolicyTemplates; $script:__pimTplCache }
    if ($all.ContainsKey($t)) { return $t }
    if (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) { $k = Resolve-PimPolicyTemplateKey -Map $all -Id $t; if ($k) { return $k } }
    return $t
}
function Get-PimEnginePolicyTemplate {
    # Resolve ONE template: the id, then the current name, then a former id ('default' -> Groups_Standard);
    # BLANK -> the per-kind group default (Get-PimEnginePolicyTemplateDefaultId 'group'; Groups_Standard unless
    # pim.Settings['PolicyTemplateDefaults'] says otherwise -- formerly 'default', matches Get-PimDefinitionPolicyMap).
    param([string]$Id)
    $tid = if ("$Id".Trim()) { "$Id".Trim() } else { Get-PimEnginePolicyTemplateDefaultId -Kind 'group' }
    $all = if ($script:__pimTplCache) { $script:__pimTplCache } else { $script:__pimTplCache = Get-PimEnginePolicyTemplates; $script:__pimTplCache }
    if ($all.ContainsKey($tid)) { return $all[$tid] }
    if (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) {
        $k = Resolve-PimPolicyTemplateKey -Map $all -Id $tid
        if ($k) { return $all[$k] }
    }
    Write-Warning "  [policy] template '$tid' not found in the SQL store (pim.Settings 'PolicyTemplates')"; return $null
}

function Get-PimGroupOwnerPolicyId {
    # #4: the policy for the OWNER role of a PIM-for-Groups group (roleDefinitionId 'owner'). v1 set it on
    # every PIM-* group ($PIM_Policy[1], CSV L875-1022); v2 only ever read the member one.
    param([string]$GroupId)
    $c = Get-PimGroupPolicyIdCached -GroupId "$GroupId" -Role 'owner'; if ($c) { return $c }
    try { $a = @(Invoke-PimGraph -All -Path (Get-PimGroupPolicyAssignmentPath -GroupId "$GroupId" -Role 'owner')); if ($a.Count) { Set-PimGroupPolicyIdCached -GroupId "$GroupId" -Role 'owner' -PolicyId "$($a[0].policyId)"; return "$($a[0].policyId)" } } catch { Set-PimGroupPolicyLookupError -GroupId "$GroupId" -Role 'owner' -Message "$($_.Exception.Message)"; Write-Verbose "owner policyId ($GroupId): $($_.Exception.Message)" }
    return $null
}

function Test-PimPolicyBaselineEnabled {
    <#
      #5 COVERAGE. v1 set its policy baseline on EVERY directory role and EVERY PIM-* group, not only the
      ones a definition or assignment row names. ON by default (v1 parity); pim.Settings / $global: /
      env 'PolicyBaselineAllTargets' = false turns it off. A baseline target gets its type's default
      template and the engine never manages APPROVAL on it (nothing named it, so nothing decided it).
    #>
    # 🔒 §79.15 CRITICAL GATE (operator 2026-09-25) -- RETIRED, PERMANENTLY OFF: "we can NOT apply changes except if they
    # are managed (defined) inside database. engine must NOT touch anything which is NOT defined" / "unmanaged groups,
    # admins, delegations can NOT be touch by pim - only managed things". The v1-parity baseline put the default template
    # on EVERY directory role and EVERY PIM-* group no row names -- on a ring-2 customer that was 797 groups its v1 engine made, a
    # 1092-policy change the breaker held since the 2.4.416 roll. This rule OVERRIDES v1 parity. The setting
    # 'PolicyBaselineAllTargets' is no longer read: no value, env or global can turn the baseline back on.
    return $false
}

function Get-PimBaselineGroupTargets {
    # #5: live groups carrying the managed name prefix that no definition row names -- v1's target set
    # (CSV L705-711: security-enabled, not dynamic, not on-prem synced, DisplayName like 'PIM-*'). Read from
    # the directory cache the scope's refreshBefore loads (the lean context already filters by prefix);
    # it never forces a tenant read of its own.
    param([hashtable]$DefinedNames = @{})
    # REQ-U: the managed prefix is the TENANT's (GroupPrefix setting, else its PimGroupPattern), never a generic
    # 'PIM-' -- which, on a 'GRP-{Role}' tenant, put the policy baseline on groups the tenant does not manage.
    $prefix = @(Get-PimManagedGroupPrefixes) | Select-Object -First 1
    $prefix = "$prefix".Trim()
    if (-not $prefix) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Global:Groups_All_ID)) {
        if ($null -eq $g) { continue }
        $name = "$($g.DisplayName)"; if (-not $name) { $name = "$($g.displayName)" }
        if (-not $name -or -not $name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($DefinedNames.ContainsKey($name.ToLowerInvariant())) { continue }
        $sec = if ($g.PSObject.Properties['SecurityEnabled']) { $g.SecurityEnabled } else { $g.securityEnabled }
        if ($null -ne $sec -and -not [bool]$sec) { continue }
        $types = @($(if ($g.PSObject.Properties['GroupTypes']) { $g.GroupTypes } else { $g.groupTypes }))
        if ($types -contains 'DynamicMembership') { continue }
        $sync = if ($g.PSObject.Properties['OnPremisesSyncEnabled']) { $g.OnPremisesSyncEnabled } else { $g.onPremisesSyncEnabled }
        if ($null -ne $sync -and [bool]$sync) { continue }
        $id = "$($g.Id)"; if (-not $id) { $id = "$($g.id)" }
        $out.Add([pscustomobject]@{ GroupName = $name; GroupId = $id })
    }
    @($out.ToArray() | Sort-Object GroupName)
}

function Get-PimGroupsPolicyDesiredSet {
    <#
      DESIRED for GroupsPolicies: per managed group its MEMBER policy (as before) and -- when the template
      carries an Owner block (#4) -- its OWNER policy; plus, with the baseline on (#5), the member and owner
      policy of every managed-prefix group no definition row names, on the group default template (Groups_Standard, formerly 'default') with approval
      unmanaged. Notification entries are resolved per target (caller-aware, de-duplicated by rule id).
      BUG-185: an ACTIVE emergency override turns approval OFF on the approval-protected member policies in
      its scope (EmergencyOverride=$true on the row). -IgnoreEmergencyOverride returns the template view.
    #>
    [CmdletBinding()] param([switch]$IgnoreEmergencyOverride)
    $__ovRt = $null
    if (-not $IgnoreEmergencyOverride -and (Get-Command Get-PimEmergencyOverrideRuntime -ErrorAction SilentlyContinue)) {
        $__ovRt = Get-PimEmergencyOverrideRuntime
        if ($__ovRt.mode -ne 'active') { $__ovRt = $null }
    }
    $out = New-Object System.Collections.Generic.List[object]
    $defined = @{}
    $addOwner = {
        param($gn, $gid, $tpl, $isBaseline)
        if (-not $tpl.rules.ContainsKey('Owner') -or $null -eq $tpl.rules['Owner']) { return }
        $ob = $tpl.rules['Owner']
        $pick = { param($k) if ($ob -is [System.Collections.IDictionary]) { $ob[$k] } elseif ($ob.PSObject.Properties[$k]) { $ob.$k } else { $null } }
        $out.Add([pscustomobject]@{ GroupName=$gn; GroupId=$gid; PolicyRole='owner'; Baseline=[bool]$isBaseline; ManageApproval=$false; Owners=''; ApproverIds=@(); TemplateId=$tpl.id
            Approval=$null; Enablement=(& $pick 'Enablement'); EnablementLegacy=$null; Expiration=(& $pick 'Expiration')
            Notification=@(Resolve-PimTemplateNotifications -Entries @(& $pick 'Notification')) })
    }
    foreach ($g in (Get-PimGroupPolicyDefinitionRows)) {
        # blank PolicyTemplate -> the group default, Groups_Standard (formerly 'default'): every managed group gets the baseline
        $tplId = Get-PimRowProp -Row $g -Names @('PolicyTemplate')
        $tpl = Get-PimEnginePolicyTemplate -Id $tplId; if (-not $tpl) { continue }
        $defined["$($g.GroupName)".ToLowerInvariant()] = $true
        $hasApproval = $tpl.rules.ContainsKey('Approval')
        $expiration = if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null }
        $notify     = if ($tpl.rules.ContainsKey('Notification')) { @(Resolve-PimTemplateNotifications -Entries @($tpl.rules['Notification'])) } else { $null }
        # Enablement: prefer the structured 'Enablement' object (per-target MFA/Justification);
        # fall back to the legacy single EndUser/Assignment key for back-compat.
        $enablement = if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null }
        $enLegacy   = if ($tpl.rules.ContainsKey('Member_Enablement_EndUser_Assignment_enabledRules')) { $tpl.rules['Member_Enablement_EndUser_Assignment_enabledRules'] } else { $null }
        # Approver IDs follow the SAME resolution as group ownership: Owners column ->
        # SponsorUpn -> the group's Department contact. A service group usually has a BLANK
        # Owners column and inherits its department's owners; an approval rule with ZERO
        # approvers is rejected by Graph ('InvalidPolicy'), so resolve through the full chain.
        $approverIds = if ($hasApproval) { @(Resolve-PimGroupOwnerIds -Row $g | ForEach-Object { $_ }) } else { @() }
        $__mrow = [pscustomobject]@{ GroupName=$g.GroupName; GroupId=''; PolicyRole='member'; Baseline=$false; ManageApproval=$true; Owners=$g.Owners; ApproverIds=$approverIds; TemplateId=$tpl.id; Approval=$(if ($hasApproval) { $tpl.rules['Approval'] } else { $null }); Enablement=$enablement; EnablementLegacy=$enLegacy; Expiration=$expiration; Notification=$notify
            GroupTag=(Get-PimRowProp -Row $g -Names @('GroupTag')) }
        if ($__ovRt -and $hasApproval -and (Test-PimEmergencyOverrideRowInScope -Row $__mrow -Override $__ovRt.override)) { $__mrow = ConvertTo-PimEmergencyOverrideDesired -Row $__mrow }
        $out.Add($__mrow)
        & $addOwner $g.GroupName '' $tpl $false
    }
    if (Test-PimPolicyBaselineEnabled) {
        $base = @(Get-PimBaselineGroupTargets -DefinedNames $defined)
        if ($base.Count) {
            # The per-kind group default (Groups_Standard, formerly 'default', unless pim.Settings['PolicyTemplateDefaults'] sets another).
            $tpl = Get-PimEnginePolicyTemplate -Id (Get-PimEnginePolicyTemplateDefaultId -Kind 'group')
            if ($tpl) {
                foreach ($bg in $base) {
                    $out.Add([pscustomobject]@{ GroupName=$bg.GroupName; GroupId=$bg.GroupId; PolicyRole='member'; Baseline=$true; ManageApproval=$false; Owners=''; ApproverIds=@(); TemplateId=$tpl.id; Approval=$null
                        Enablement=$(if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null }); EnablementLegacy=$null
                        Expiration=$(if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null })
                        Notification=$(if ($tpl.rules.ContainsKey('Notification')) { @(Resolve-PimTemplateNotifications -Entries @($tpl.rules['Notification'])) } else { $null }) })
                    & $addOwner $bg.GroupName $bg.GroupId $tpl $true
                }
                Write-Host ("    [engine] GroupsPolicies: baseline covers {0} managed-prefix group(s) no definition row names (template '{1}', approval unmanaged)" -f $base.Count, $tpl.id) -ForegroundColor DarkGray
            }
        }
    }
    $out.ToArray()
}

function Get-PimGroupPolicyDefinitionRows {
    <#
      🔴 71.25 -- the rows whose `PolicyTemplate` the GROUPS-POLICY provider honours.
      Operator, 2026-09-16: *"i think we are missing the default policy for a permission (indirect)
      delegation in the wizards. I need to be able to select from the available templates for policies
      including Use default, approval policy template."*

      This is `Get-PimGroupDefinitionRows` PLUS `PIM-Definitions-Resources`, and the difference is
      deliberate and narrow. `Get-PimGroupDefinitionRows` is the GROUP-CREATION source, and Resources
      is excluded from it on purpose: discovery auto-create writes every discovered Azure/Power BI
      resource into that entity, so creating a group per row would create one at every customer with
      discovery on. That reason is about CREATING groups — it says nothing about POLICY.

      Reading Resources HERE changes behaviour for exactly one kind of row: a Resources row whose
      PolicyTemplate is set. A blank PolicyTemplate resolves to the group default (Groups_Standard, formerly 'default'), which is the
      same policy the baseline sweep (Get-PimBaselineGroupTargets) already applies to every managed
      group with no definition row — so every existing row keeps behaving byte-for-byte as before, and
      the only new outcome is the one the operator asked for: a Resource permission group can be given
      an approval template from the wizard.

      A row with no GroupName is not a group (the same guard the creation source uses).
    #>
    [CmdletBinding()] param()
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-PimGroupDefinitionRows)) { if ($r) { [void]$list.Add($r) } }
    $seen = @{}
    foreach ($r in $list) { $n = "$(Get-PimRowProp -Row $r -Names @('GroupName'))".Trim(); if ($n) { $seen[$n.ToLowerInvariant()] = $true } }
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Resources')) {
        if ($null -eq $r) { continue }
        $gn = "$(Get-PimRowProp -Row $r -Names @('GroupName'))".Trim(); if (-not $gn) { continue }
        $life = "$(Get-PimRowProp -Row $r -Names @('Lifecycle'))".Trim()
        if ($life -match '(?i)^retire') { continue }        # being deleted -- do not re-police it
        if ($seen.ContainsKey($gn.ToLowerInvariant())) { continue }
        [void]$list.Add($r)
    }
    return $list.ToArray()
}

function Get-PimResourceOwnerDefinitionRows {
    <#
      REQ-L (operator 2026-09-19, "what the Owner field is for"): the PIM-Definitions-Resources rows whose OWNERS the
      engine honours -- an Azure permission group's owners. Owners own the delegation group: the GroupOwners scope makes
      them its Entra group owners, they approve its activation when its template needs approval, and they are the Azure
      role policy's approver fallback. The Azure wizards used to put Owners on PIM-Assignments-Azure-Resources, which has
      no Owners column and no reader, so it did nothing; they now stage it on a Resources row, and this reads it.

      NARROW ON PURPOSE, for the same reason Get-PimGroupDefinitionRows leaves Resources out: discovery writes every
      discovered resource into that entity. Only a row that NAMES owners itself counts -- discovery never writes Owners,
      so a discovered resource is never given an owner, and no Department / SponsorUpn fallback is applied to a row that
      has not asked for ownership. A GroupName already defined by a group-definition entity is left to that row, and a
      row being retired is skipped. Returns the rows in Get-PimGroupDefinitionRows' shape.
    #>
    [CmdletBinding()] param()
    $seen = @{}
    foreach ($d in @(Get-PimGroupDefinitionRows -IncludeRetired)) { $n = "$($d.GroupName)".Trim(); if ($n) { $seen[$n.ToLowerInvariant()] = $true } }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Resources')) {
        if ($null -eq $r) { continue }
        $gn = "$(Get-PimRowProp -Row $r -Names @('GroupName'))".Trim(); if (-not $gn) { continue }
        $own = "$(Get-PimRowProp -Row $r -Names @('Owners'))".Trim(); if (-not $own) { continue }
        $life = "$(Get-PimRowProp -Row $r -Names @('Lifecycle'))".Trim()
        if ($life -match '(?i)^retire') { continue }
        if ($seen.ContainsKey($gn.ToLowerInvariant())) { continue }
        $seen[$gn.ToLowerInvariant()] = $true
        [void]$list.Add([pscustomobject]@{
            GroupName = $gn; GroupTag = (Get-PimRowProp -Row $r -Names @('GroupTag')); GroupDescription = (Get-PimRowProp -Row $r -Names @('GroupDescription'))
            IsRoleAssignable = (Get-PimRowProp -Row $r -Names @('IsRoleAssignable')); AdministrativeUnitTag = (Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag'))
            Owners = $own; SponsorUpn = ''; Department = ''
            PolicyTemplate = (Get-PimRowProp -Row $r -Names @('PolicyTemplate')); ReviewCycle = (Get-PimRowProp -Row $r -Names @('ReviewCycle'))
            Workload = (Get-PimRowProp -Row $r -Names @('Workload')); Lifecycle = $life; SourceEntity = 'PIM-Definitions-Resources'
        })
    }
    return $list.ToArray()
}

function Get-PimGroupsPolicyKey {
    param([object]$Row)
    $gn = (Get-PimRowProp -Row $Row -Names @('GroupName')).ToLowerInvariant()
    if ("$(Get-PimRowProp -Row $Row -Names @('PolicyRole'))" -eq 'owner') { return "$gn|owner" }
    $gn
}

function Invoke-PimGroupPolicyDriftUpdate {
    <#
      ApplyUpdate for an OWNER policy (#4) or a BASELINE group (#5): re-read the policy, PATCH ONLY the rules
      that drifted from the template (enablement, expiration, notification -- never approval), collect every
      refusal and fail the item naming all of them (BUG-52). An unreadable policy writes nothing.
    #>
    param([Parameter(Mandatory)][object]$Item)
    $d = $Item.desired; $gn = "$($d.GroupName)"; $role = if ("$($d.PolicyRole)" -eq 'owner') { 'owner' } else { 'member' }
    $gid = if ("$($d.GroupId)") { "$($d.GroupId)" } else { Resolve-PimLiveGroupIdByName $gn }
    if (-not $gid) { throw "GroupsPolicies: group '$gn' not found" }
    $polId = if ($role -eq 'owner') { Get-PimGroupOwnerPolicyId -GroupId $gid } else { Get-PimGroupMemberPolicyId -GroupId $gid }
    if (-not $polId) { throw (Get-PimGroupPolicyMissingMessage -GroupName $gn -GroupId $gid -Role $role) }
    $liveRules = $null
    try { $liveRules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules").rules) }
    catch { throw "GroupsPolicies: the $role policy of '$gn' could not be re-read, so NOTHING was written: $($_.Exception.Message)" }
    $have = Get-PimGroupPolicyLiveFacets -Rules $liveRules
    $want = Get-PimGroupPolicyDesiredFacets -Desired $d
    $drifted = @{}; foreach ($k in @($want.Keys)) { if (-not $have.ContainsKey($k) -or "$($have[$k])" -ne "$($want[$k])") { $drifted[$k] = $true } }
    if (-not $drifted.Count) { return [pscustomobject]@{ pimApplied = $false; note = 'already in sync on re-read' } }
    $failures = New-Object System.Collections.Generic.List[string]
    $bodies = New-Object System.Collections.Generic.List[object]
    foreach ($b in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement -LegacyEndUserAssignment $d.EnablementLegacy)) { if ($b) { $bodies.Add($b) } }
    foreach ($b in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) { if ($b) { $bodies.Add($b) } }
    foreach ($n in @($d.Notification)) { $b = ConvertTo-PimNotificationRuleBody -Entry $n; if ($b) { $bodies.Add($b) } }
    $sent = 0
    foreach ($b in $bodies.ToArray()) {
        if (-not $drifted.ContainsKey("$($b.id)")) { continue }
        $sent++
        try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $b } catch { $failures.Add("$($b.id): $($_.Exception.Message)") | Out-Null }
    }
    Assert-PimGroupPolicyPatchesApplied -GroupName "$gn ($role policy)" -Failures $failures
    [pscustomobject]@{ group = $gn; role = $role; policyId = $polId; template = "$($d.TemplateId)"; patched = $sent; baseline = [bool]$d.Baseline }
}

# =============================================================================
# 🔴 BUG-185 (§33.28) -- THE v2 CONSUMER OF THE BREAK-GLASS (EMERGENCY) OVERRIDE.
# POST /api/emergency records pim.Settings['EmergencyOverride'] and tells the operator the ENGINE will
# switch approval off on the scoped groups. The only reader was Invoke-PimEmergencyOverride in
# PIM-Functions.psm1 -- a v1 function (Graph SDK cmdlets, a policy-state FILE, a file write for
# appliedGroups) called only by the v1 CSV engine. In v2 nothing read the record, so break-glass did
# nothing at the one moment somebody relied on it, and the approval requirement was never restored
# either (DESIGN §17.9 promises both).
#
# The v2 consumer, SQL-only, three parts:
#   1. Get-PimGroupsPolicyDesiredSet folds an ACTIVE override into DESIRED state: an approval-protected
#      member policy in scope is desired with approval OFF (EmergencyOverride=$true). So the
#      GroupsPolicies provider does not switch approval back on every 30 minutes during the window,
#      and the mass-change breaker does not HOLD an authorised break-glass (such rows are left out of
#      the breaker plan -- a SuperAdmin + passcode already authorised exactly this change).
#   2. Invoke-PimEmergencyOverrideStep (job 'emergency-override', every tick) applies it at once:
#      approval rule OFF per scoped group, audited, owners notified, appliedGroups recorded in SQL.
#   3. At expiry the same step RE-APPLIES the linked policy template to every scoped group, audits the
#      restore and clears the record (active=false, restoredAtUtc). A restore that fails keeps the
#      record, so the next tick retries it -- approval is never left off silently.
# An override whose expiry cannot be read is treated as EXPIRED (restore): approval must never stay
# off because a date did not parse.
# =============================================================================
function Get-PimEmergencyOverrideSettingName { 'EmergencyOverride' }

function Get-PimEmergencyOverrideRecord {
    # The stored override, read from SQL. Returns @{ ok; override; error }. ok=$false = the store could
    # not be read (the caller must say so -- never read it as "no override").
    [CmdletBinding()] param([string]$ConnectionString)
    $cs = if ("$ConnectionString".Trim()) { $ConnectionString } else { Get-PimAdminLifecycleStoreCs }
    if (-not $cs) { return [pscustomobject]@{ ok = $false; override = $null; error = 'no SQL store is configured (the override lives in pim.Settings)' } }
    if (-not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ok = $false; override = $null; error = 'Get-PimSqlSetting is not loaded' } }
    try {
        $v = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimEmergencyOverrideSettingName)
        if ($v -is [string]) { if ("$v".Trim()) { $v = $v | ConvertFrom-Json } else { $v = $null } }
        return [pscustomobject]@{ ok = $true; override = $v; error = ''; cs = $cs }
    } catch {
        return [pscustomobject]@{ ok = $false; override = $null; error = "pim.Settings['$(Get-PimEmergencyOverrideSettingName)'] could not be read: $($_.Exception.Message)" }
    }
}

function Get-PimEmergencyOverrideMode {
    # PURE. 'none' | 'active' | 'restore'. An active record whose expiry is missing or unreadable is
    # 'restore' (fail safe: approval is never kept off on an unreadable date).
    [CmdletBinding()] param([AllowNull()][object]$Override, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Override) { return 'none' }
    $act = $false
    if ($Override.PSObject.Properties['active']) { $act = ("$($Override.active)".Trim().ToLowerInvariant() -in @('true','1','yes')) }
    if (-not $act) { return 'none' }
    $exp = $null
    $raw = $Override.expiresAtUtc
    try {
        # pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime] already; a string round-trip would
        # drop its Kind and shift it by the host's offset, so a [datetime] is used as it is.
        if ($raw -is [datetime]) { $exp = $raw.ToUniversalTime() }
        elseif ("$raw".Trim()) { $exp = [datetime]::Parse("$raw", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
    } catch { $exp = $null }
    if ($null -eq $exp) { return 'restore' }
    if ($NowUtc.ToUniversalTime() -ge $exp) { return 'restore' }
    return 'active'
}

function Test-PimEmergencyOverrideRowInScope {
    # PURE. An empty scope = every approval-protected group. Otherwise the row's GroupTag OR GroupName
    # must be listed (case-insensitive) -- the Manager's field is labelled GroupTags, operators type either.
    [CmdletBinding()] param([Parameter(Mandatory)][object]$Row, [AllowNull()][object]$Override)
    $scope = @()
    if ($Override -and $Override.PSObject.Properties['scopeGroupTags']) { $scope = @(@($Override.scopeGroupTags) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ }) }
    if (-not $scope.Count) { return $true }
    foreach ($n in 'GroupTag','GroupName') {
        $p = $Row.PSObject.Properties[$n]
        if ($p -and "$($p.Value)".Trim() -and ($scope -contains "$($p.Value)".Trim().ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-PimEmergencyOverrideRuntime {
    # What GetDesired needs: the mode + the record. A store that cannot be read yields mode 'unknown'
    # and a warning: desired state is then computed WITHOUT the override (the step job fails loudly).
    [CmdletBinding()] param([datetime]$NowUtc = [datetime]::UtcNow)
    $r = Get-PimEmergencyOverrideRecord
    if (-not $r.ok) {
        Write-Warning "  [emergency] the emergency override could not be read ($($r.error)) -- policies are planned WITHOUT it this run."
        return [pscustomobject]@{ mode = 'unknown'; override = $null; error = $r.error }
    }
    return [pscustomobject]@{ mode = (Get-PimEmergencyOverrideMode -Override $r.override -NowUtc $NowUtc); override = $r.override; error = '' }
}

function ConvertTo-PimEmergencyOverrideDesired {
    # PURE. A copy of one GroupsPolicies member row with approval OFF, flagged as the override's doing.
    [CmdletBinding()] param([Parameter(Mandatory)][object]$Row)
    $c = $Row.PSObject.Copy()
    $c.Approval = $null
    $c.ApproverIds = @()
    $c | Add-Member -NotePropertyName EmergencyOverride -NotePropertyValue $true -Force
    return $c
}

function Get-PimEmergencyOverrideScopedRows {
    # The approval-protected MEMBER policies the override covers (template approval on, engine-managed).
    [CmdletBinding()] param([AllowNull()][object]$Override)
    @(Get-PimGroupsPolicyDesiredSet -IgnoreEmergencyOverride | Where-Object {
        $_ -and "$($_.PolicyRole)" -ne 'owner' -and [bool]$_.ManageApproval -and $null -ne $_.Approval -and (Test-PimEmergencyOverrideRowInScope -Row $_ -Override $Override)
    })
}

function Invoke-PimEmergencyOverrideStep {
    <#
      The 'emergency-override' job. Returns @{ ran; detail; mode; applied; restored; failures }.
      THROWS when the record cannot be read, or when any scoped group could not be switched / restored
      (the job then FAILS and alerts; what did succeed is recorded first). -ApplyApprovalOff /
      -RestorePolicy / -Notify are injectable for the offline tests; the defaults do the Graph writes.
    #>
    [CmdletBinding()]
    param(
        [datetime]$NowUtc = [datetime]::UtcNow,
        [switch]$WhatIf,
        [scriptblock]$ApplyApprovalOff,
        [scriptblock]$RestorePolicy,
        [scriptblock]$Notify
    )
    $rec = Get-PimEmergencyOverrideRecord
    if (-not $rec.ok) { throw "[emergency] the emergency override could NOT be read, so it can be neither applied nor restored: $($rec.error)" }
    $ov = $rec.override
    $mode = Get-PimEmergencyOverrideMode -Override $ov -NowUtc $NowUtc
    if ($mode -eq 'none') { return [pscustomobject]@{ ran = $false; nothingDue = $true; mode = $mode; detail = 'no emergency override is active'; whatIf = [bool]$WhatIf } }
    if (-not $ApplyApprovalOff) {
        $ApplyApprovalOff = {
            param($row)
            $gid = if ("$($row.GroupId)") { "$($row.GroupId)" } else { Resolve-PimLiveGroupIdByName "$($row.GroupName)" }
            if (-not $gid) { throw "group '$($row.GroupName)' not found" }
            $polId = Get-PimGroupMemberPolicyId -GroupId $gid
            if (-not $polId) { throw (Get-PimGroupPolicyMissingMessage -GroupName "$($row.GroupName)" -GroupId $gid -Role 'member') }
            Invoke-PimPolicyRulePatch -PolicyId $polId -Body (New-PimApprovalOffRuleBody)
        }
    }
    if (-not $RestorePolicy) {
        # Re-apply the LINKED template in full (approval included) -- the same write the provider makes.
        $RestorePolicy = { param($row) Invoke-PimGroupsPolicyApply -item ([pscustomobject]@{ key = (Get-PimGroupsPolicyKey -Row $row); desired = $row; live = $null }) -ctx @{} }
    }
    if (-not $Notify) {
        $Notify = {
            param($row, $o)
            if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return 'mail sender not loaded' }
            $to = @("$($row.Owners)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '@' } | Select-Object -Unique)
            if (-not $to.Count) { return 'no owner address on the definition' }
            $miss = @()
            foreach ($t in $to) {
                $m = $null
                try { $m = Send-PimNotifyMail -Type 'emergency-override' -Recipient $t -Tokens @{ GroupName = "$($row.GroupName)"; ActivatedBy = "$($o.activatedBy)"; ExpiresAtUtc = "$($o.expiresAtUtc)"; Reason = "$($o.reason)" } } catch { $miss += "${t}: $($_.Exception.Message)"; continue }
                $ok = if ($m -is [hashtable]) { [bool]$m['sent'] } elseif ($m) { [bool]$m.sent } else { $false }
                if (-not $ok) { $miss += "${t}: $(if ($m -is [hashtable]) { $m['reason'] } elseif ($m) { $m.reason } else { 'not sent' })" }
            }
            if ($miss.Count) { return ('owner notice NOT sent to ' + ($miss -join '; ')) }
            return ''
        }
    }
    $scoped = @(Get-PimEmergencyOverrideScopedRows -Override $ov)
    $applied = @(@($ov.appliedGroups) | ForEach-Object { "$_" } | Where-Object { $_ })
    $failures = New-Object System.Collections.Generic.List[string]
    $scopeTxt = if (@($ov.scopeGroupTags | Where-Object { $_ }).Count) { (@($ov.scopeGroupTags) -join ', ') } else { 'ALL approval-protected groups' }

    if ($mode -eq 'active') {
        $todo = @($scoped | Where-Object { $applied -notcontains "$($_.GroupName)" })
        if ($WhatIf) { return [pscustomobject]@{ ran = $true; mode = $mode; whatIf = $true; detail = ("emergency override ACTIVE ({0}): would switch approval OFF on {1} group(s)" -f $scopeTxt, $todo.Count) } }
        $new = New-Object System.Collections.Generic.List[string]
        foreach ($row in $todo) {
            try { [void](& $ApplyApprovalOff $row) }
            catch { $failures.Add("$($row.GroupName): $($_.Exception.Message)"); continue }
            $new.Add("$($row.GroupName)")
            Write-Host ("  [emergency] APPROVAL DISABLED on '{0}' (override by {1}, expires {2} UTC)" -f $row.GroupName, $ov.activatedBy, $ov.expiresAtUtc) -ForegroundColor Red
            Write-PimAdminLifecycleAudit -Action 'emergency.apply' -Target "$($row.GroupName)" -After @{ activatedBy = "$($ov.activatedBy)"; expiresAtUtc = "$($ov.expiresAtUtc)"; reason = "$($ov.reason)" }
            $nw = ''
            try { $nw = "$(& $Notify $row $ov)" } catch { $nw = "owner notice failed: $($_.Exception.Message)" }
            if ($nw) { Write-Warning "  [emergency] '$($row.GroupName)': $nw" }
        }
        if ($new.Count) {
            $out = [ordered]@{}
            foreach ($p in $ov.PSObject.Properties) { $out[$p.Name] = $p.Value }
            $out['appliedGroups'] = @(@($applied) + @($new.ToArray()) | Select-Object -Unique)
            $out['appliedAtUtc'] = $NowUtc.ToUniversalTime().ToString('o')
            try { Set-PimSqlSetting -ConnectionString $rec.cs -Name (Get-PimEmergencyOverrideSettingName) -Value ([pscustomobject]$out) }
            catch { $failures.Add("the applied groups could NOT be recorded in SQL (approval IS off on: $($new -join ', ')): $($_.Exception.Message)") }
        }
        $detail = ("emergency override ACTIVE ({0}, expires {1}): approval OFF on {2} new + {3} earlier group(s) of {4} in scope" -f $scopeTxt, $ov.expiresAtUtc, $new.Count, $applied.Count, $scoped.Count)
        if ($failures.Count) { throw ("[emergency] $detail -- FAILED on: " + ($failures -join '; ')) }
        return [pscustomobject]@{ ran = $true; mode = $mode; applied = $new.Count; detail = $detail; whatIf = $false }
    }

    # mode 'restore' -- expired (or an unreadable expiry): re-apply the linked policy on every scoped group.
    # Every SCOPED group, not only appliedGroups: while the override was active the GroupsPolicies provider
    # may itself have switched approval off on a group this step had not yet recorded.
    if ($WhatIf) { return [pscustomobject]@{ ran = $true; mode = $mode; whatIf = $true; detail = ("emergency override EXPIRED: would restore the linked policy on {0} group(s)" -f $scoped.Count) } }
    $restored = New-Object System.Collections.Generic.List[string]
    foreach ($row in $scoped) {
        try { [void](& $RestorePolicy $row); $restored.Add("$($row.GroupName)") }
        catch { $failures.Add("$($row.GroupName): $($_.Exception.Message)") }
    }
    if ($failures.Count) {
        throw ("[emergency] emergency override EXPIRED, but the linked policy could NOT be restored on: " + ($failures -join '; ') +
               ". The override record is KEPT so the next run retries -- approval may still be OFF on those groups.")
    }
    $cleared = [ordered]@{
        active = $false; scopeGroupTags = @($ov.scopeGroupTags)
        activatedBy = "$($ov.activatedBy)"; activatedAtUtc = "$($ov.activatedAtUtc)"
        expiresAtUtc = "$($ov.expiresAtUtc)"; reason = "$($ov.reason)"
        appliedGroups = @(); restoredGroups = @($restored.ToArray()); restoredAtUtc = $NowUtc.ToUniversalTime().ToString('o')
    }
    Set-PimSqlSetting -ConnectionString $rec.cs -Name (Get-PimEmergencyOverrideSettingName) -Value ([pscustomobject]$cleared)
    Write-PimAdminLifecycleAudit -Action 'emergency.restore' -Target $scopeTxt -After @{ activatedBy = "$($ov.activatedBy)"; expiresAtUtc = "$($ov.expiresAtUtc)"; restoredGroups = @($restored.ToArray()) }
    Write-Host ("  [emergency] override EXPIRED -- the linked approval policy was re-applied on {0} group(s); the override is cleared" -f $restored.Count) -ForegroundColor Yellow
    return [pscustomobject]@{ ran = $true; mode = $mode; restored = $restored.Count; detail = ("emergency override EXPIRED: linked policy restored on {0} group(s), override cleared" -f $restored.Count); whatIf = $false }
}

function New-PimGroupsPoliciesProvider {
    @{
        scope = 'GroupsPolicies'; entity = 'PIM-Definitions'; order = 70; refreshBefore = $true
        # DESIRED = EVERY managed group's member policy brought to the v1 baseline. The
        # baseline (Expiration + Enablement + Notification) is applied to ALL linked groups
        # (blank PolicyTemplate = the group default, Groups_Standard -- formerly 'default'); the Approval rule is applied ONLY when the
        # template declares one (e.g. Groups_RequireApproval, formerly 'approval-required'). #4: plus each group's OWNER policy from the
        # template's Owner block. #5: plus every managed-prefix group no row names (baseline, default ON).
        GetDesired = {
            param($ctx)
            $d = @(Get-PimGroupsPolicyDesiredSet)
            if ($null -ne $ctx) { $ctx['groupsPolDesired'] = $d }
            $d
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $live = New-Object System.Collections.Generic.List[object]
            $desired = if ($null -ne $ctx -and $ctx.ContainsKey('groupsPolDesired')) { @($ctx['groupsPolDesired']) } else { @(Get-PimGroupsPolicyDesiredSet) }
            # PERFORMANCE (2026-09-13, internal: 706 policies = 1,412 sequential reads, ~11 min): the SAME two
            # reads per policy (assignment -> policy id, then the policy with its rules) go through Graph /$batch.
            if ((Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue) -and (Test-PimGraphBatchReadsEnabled)) {
                $targets = New-Object System.Collections.Generic.List[object]
                foreach ($g in $desired) {
                    $gid = if ("$($g.GroupId)") { "$($g.GroupId)" } else { Resolve-PimLiveGroupIdByName $g.GroupName }
                    if (-not $gid) { continue }
                    $role = if ("$($g.PolicyRole)" -eq 'owner') { 'owner' } else { 'member' }
                    $targets.Add([pscustomobject]@{ g = $g; gid = "$gid"; role = $role; polId = (Get-PimGroupPolicyIdCached -GroupId "$gid" -Role $role) })
                }
                $needId = @($targets | Where-Object { -not $_.polId })
                if ($needId.Count) {
                    $idRes = Invoke-PimGraphBatchGet -Paths @($needId | ForEach-Object { Get-PimGroupPolicyAssignmentPath -GroupId $_.gid -Role $_.role })
                    for ($i = 0; $i -lt $needId.Count; $i++) {
                        $r = $idRes[$i]
                        if (-not $r -or -not $r.ok) { if ($r) { Set-PimGroupPolicyLookupError -GroupId $needId[$i].gid -Role $needId[$i].role -Message "$($r.error)"; Write-Verbose "policyId ($($needId[$i].gid)/$($needId[$i].role)): $($r.error)" }; continue }
                        $a = @($r.items)
                        if ($a.Count) { $needId[$i].polId = "$($a[0].policyId)"; Set-PimGroupPolicyIdCached -GroupId $needId[$i].gid -Role $needId[$i].role -PolicyId $needId[$i].polId }
                    }
                }
                $withId = @($targets | Where-Object { $_.polId })
                $polRes = if ($withId.Count) { Invoke-PimGraphBatchGet -Paths @($withId | ForEach-Object { Get-PimGroupPolicyReadPath -PolicyId $_.polId }) } else { @() }
                for ($i = 0; $i -lt $withId.Count; $i++) {
                    $t = $withId[$i]; $r = $polRes[$i]
                    $rules = @(); $neverMod = $false
                    if ($r -and $r.ok -and $null -ne $r.body) { $rules = @($r.body.rules); $neverMod = Test-PimGraphPolicyNeverModified -Policy $r.body }
                    elseif ($r) {
                        Write-Verbose "policy read ($($t.g.GroupName)/$($t.role)): $($r.error)"
                        # §70.10: a cached/persisted id whose policy no longer exists must not be trusted again.
                        if ($r.status -eq 404 -or "$($r.error)" -match '(?i)HTTP 404|not ?found|ResourceNotFound') { Remove-PimGroupPolicyIdCached -GroupId $t.gid -Role $t.role }
                    }
                    $live.Add([pscustomobject]@{ GroupName=$t.g.GroupName; PolicyRole=$t.role; PolicyId=$t.polId; Rules=$rules; NeverModified=$neverMod })
                }
                Save-PimGroupPolicyIdMap
                Write-Host ("  [perf] group policies read in batches: {0} policy id lookup(s), {1} policy read(s)" -f $needId.Count, $withId.Count) -ForegroundColor DarkGray
                # 🔴 §70.6 (2026-09-13) -- THE BATCHED PATH SKIPPED THE MASS-CHANGE BREAKER. This `return` used to
                # come BEFORE the plan, and batched reads are ON by default, so Invoke-PimGraphPolicyGuardedApply
                # found no plan and applied every item directly. Measured on internal, 48 h of tick logs:
                # `[breaker] EntraRolePolicies` 7x, `[breaker] AzResPolicies` 30x, `[breaker] GroupsPolicies` 0x --
                # while GroupsPolicies applied 78 policy changes unguarded. PLAN FIRST on BOTH read paths.
                Set-PimGraphPolicyBreakerPlan -Provider 'GroupsPolicies' -Context $ctx -Desired $desired -Live $live.ToArray() `
                    -KeyOf { param($r) Get-PimGroupsPolicyKey -Row $r } -Label { param($r) if ("$($r.PolicyRole)" -eq 'owner') { "$($r.GroupName) (owner)" } else { "$($r.GroupName)" } }
                return $live.ToArray()
            }
            foreach ($g in $desired) {
                $gid = if ("$($g.GroupId)") { "$($g.GroupId)" } else { Resolve-PimLiveGroupIdByName $g.GroupName }
                if (-not $gid) { continue }
                $role = if ("$($g.PolicyRole)" -eq 'owner') { 'owner' } else { 'member' }
                $polId = if ($role -eq 'owner') { Get-PimGroupOwnerPolicyId -GroupId $gid } else { Get-PimGroupMemberPolicyId -GroupId $gid }
                if (-not $polId) { continue }
                # FULL read-back: the create/modify diff compares EVERY rule the provider
                # PATCHes (Approval + Expiration x3 + Enablement x3 + Notification), so the
                # live row carries the whole expanded rules collection (Get-PimGroupPolicyLiveFacets
                # normalises it in Equal). A group with no readable policy yet is simply absent
                # from live -> the diff classifies it as a create.
                $rules = @(); $neverMod = $false
                try {
                    $pol = Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules"
                    $rules = @($pol.rules); $neverMod = Test-PimGraphPolicyNeverModified -Policy $pol
                } catch {
                    Write-Verbose "policy read ($($g.GroupName)/$role): $($_.Exception.Message)"
                    if ("$($_.Exception.Message)" -match '(?i)HTTP 404|not ?found|ResourceNotFound') { Remove-PimGroupPolicyIdCached -GroupId "$gid" -Role $role }
                }
                $live.Add([pscustomobject]@{ GroupName=$g.GroupName; PolicyRole=$role; PolicyId=$polId; Rules=$rules; NeverModified=$neverMod })
            }
            Save-PimGroupPolicyIdMap
            # PLAN FIRST (mass-change circuit breaker, operator 2026-09-13): the whole change set and the
            # breaker decision exist before any ApplyUpdate runs.
            Set-PimGraphPolicyBreakerPlan -Provider 'GroupsPolicies' -Context $ctx -Desired $desired -Live $live.ToArray() `
                -KeyOf { param($r) Get-PimGroupsPolicyKey -Row $r } -Label { param($r) if ("$($r.PolicyRole)" -eq 'owner') { "$($r.GroupName) (owner)" } else { "$($r.GroupName)" } }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimGroupsPolicyKey -Row $r }
        # nochange ONLY when the live policy already matches the desired baseline across
        # the WHOLE managed rule set: Approval (when the template asks for it, incl. the
        # approver identity set), all three Expiration caps, all three Enablement rules,
        # and every declared Notification rule. Anything drifted -> modify (a single
        # idempotent string compare per rule via the pure facet builders).
        Equal = {
            param($d,$l)
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $have = Get-PimGroupPolicyLiveFacets -Rules $l.Rules
            Test-PimGroupPolicyInSync -Desired $want -Live $have
        }
        ApplyCreate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'GroupsPolicies').ApplyUpdate $item $ctx }
        ApplyUpdate = {
            param($item,$ctx)
            Invoke-PimGraphPolicyGuardedApply -Provider 'GroupsPolicies' -Item $item -Context $ctx -Apply { param($i, $c) Invoke-PimGroupsPolicyApply -item $i -ctx $c }
        }
    }
}

function Invoke-PimGroupsPolicyApply {
    # GroupsPolicies' write for ONE policy -- reached only through Invoke-PimGraphPolicyGuardedApply (breaker).
    param([object]$item, [hashtable]$ctx)
            $d=$item.desired; $gn=$d.GroupName
            if ("$($d.PolicyRole)" -eq 'owner' -or [bool]$d.Baseline) { return (Invoke-PimGroupPolicyDriftUpdate -Item $item) }
            $gid=Resolve-PimLiveGroupIdByName $gn; if (-not $gid) { throw "GroupsPolicies: group '$gn' not found" }
            $polId=Get-PimGroupMemberPolicyId -GroupId $gid; if (-not $polId) { throw (Get-PimGroupPolicyMissingMessage -GroupName $gn -GroupId $gid -Role 'member') }
            # 🔴 BUG-52 -- A SWALLOWED PATCH FAILURE IS WHY THIS SCOPE COULD NOT BE DIAGNOSED.
            # Every rule PATCH below used to be `try { ... } catch { Write-Verbose ... }`. Graph's
            # refusal therefore went to a stream nobody reads, the item still counted as APPLIED,
            # and the scope reported the PLAN as though it were the outcome -- `GroupsPolicies:
            # c0/u112/r0` with no indication that any of it failed. When the tenant then failed to
            # converge, the logs contained nothing to explain it, which sent a later session
            # chasing a non-existent security gap through the audit log instead (BUG-52's withdrawn
            # original text).
            # Failures are now COLLECTED and thrown together at the end of the item, so:
            #   * the engine counts the item as an ERROR, not an apply;
            #   * every failing rule is named in one message, instead of the first one aborting
            #     the rest -- a policy half-applied silently is worse than one that fails loudly;
            #   * a run that changes nothing can no longer look identical to one that worked.
            $ruleFailures = New-Object System.Collections.Generic.List[string]
            # 🔴 §70.7 (2026-09-13) -- PATCH ONLY THE RULES THAT DRIFTED. This path used to PATCH every
            # enablement, expiration and notification rule of the policy, one Graph call each (~15 per policy),
            # whether or not it differed: ~1,170 calls for 78 policies on internal, ~10 minutes of the tick.
            # The owner/baseline path (Invoke-PimGroupPolicyDriftUpdate) and EntraRolePolicies already sent only
            # drifted rules. The comparison is the SAME facet compare Equal uses, over the live rules this scope
            # run just read ($item.live). No live rules (a create, or an unreadable policy) => every rule is sent,
            # exactly as before -- the saving never costs a missed write.
            $wantFacets = Get-PimGroupPolicyDesiredFacets -Desired $d
            $liveRules = $null
            if ($item.live -and $item.live.PSObject.Properties['Rules'] -and @($item.live.Rules).Count) { $liveRules = @($item.live.Rules) }
            $haveFacets = if ($null -ne $liveRules) { Get-PimGroupPolicyLiveFacets -Rules $liveRules } else { $null }
            $ruleDrifted = {
                param([string]$RuleId)
                if ($null -eq $haveFacets) { return $true }
                if (-not $wantFacets.ContainsKey($RuleId)) { return $true }
                return (-not $haveFacets.ContainsKey($RuleId) -or "$($haveFacets[$RuleId])" -ne "$($wantFacets[$RuleId])")
            }
            $rulesSent = 0; $rulesSkipped = 0
            # --- v1 baseline: Enablement + Expiration + Notification on EVERY managed group ---
            # Member enablement (MFA / Justification) per target (EndUser/Assignment +
            # Admin/Eligibility get MFA+Justification; Admin/Assignment is cleared) from the template.
            foreach ($enBody in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement -LegacyEndUserAssignment $d.EnablementLegacy)) {
                if (-not (& $ruleDrifted "$($enBody.id)")) { $rulesSkipped++; continue }
                $rulesSent++
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $enBody } catch { $ruleFailures.Add("enablement/$($enBody.id): $($_.Exception.Message)") | Out-Null }
            }
            # Member expiration (v1 parity: EndUser/activation P1D, Admin/Assignment + Admin/Eligibility
            # P365D, all isExpirationRequired) from the template.
            foreach ($exBody in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) {
                if (-not (& $ruleDrifted "$($exBody.id)")) { $rulesSkipped++; continue }
                $rulesSent++
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $exBody } catch { $ruleFailures.Add("expiration/$($exBody.id): $($_.Exception.Message)") | Out-Null }
            }
            # Notification rules (v1 parity: the nine rules, caller-aware since #5) from the template
            if ($d.Notification) {
                foreach ($n in @($d.Notification)) {
                    try {
                        $nBody = ConvertTo-PimNotificationRuleBody -Entry $n
                        if (-not $nBody) { continue }
                        if (-not (& $ruleDrifted "$($nBody.id)")) { $rulesSkipped++; continue }
                        $rulesSent++
                        Invoke-PimPolicyRulePatch -PolicyId $polId -Body $nBody
                    } catch { $ruleFailures.Add("notification/$($n.recipientType)/$($n.level): $($_.Exception.Message)") | Out-Null }
                }
            }
            if ($rulesSkipped) { Write-Verbose "GroupsPolicies '$gn': $rulesSent drifted rule(s) sent, $rulesSkipped already in sync skipped" }
            # --- Approval rule: ONLY when the template declares one (default-linked groups skip) ---
            # 🪤 BUG-52: this early `return` is the DEFAULT path (every default-linked group takes
            # it), so the failure check has to happen HERE as well as at the end -- putting it only
            # after the approval block would leave the common case silent, which is the exact
            # defect being fixed.
            if (-not $d.Approval) {
                # BUG-56 -- the same one-way defect the directory-role provider had. A template
                # with no Approval block means approval must be OFF, not "leave whatever is
                # there". Only written when the live policy actually HAS approval on, so the
                # common default-linked group still takes the cheap path and sends nothing.
                $liveApprovalOn = $false
                foreach ($r in @($item.live.Rules)) {
                    if ("$($r.id)" -ne 'Approval_EndUser_Assignment') { continue }
                    if ($r.setting -and [bool]$r.setting.isApprovalRequired) { $liveApprovalOn = $true }
                }
                if ($liveApprovalOn) {
                    try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body (New-PimApprovalOffRuleBody) }
                    catch { $ruleFailures.Add("approval-off: $($_.Exception.Message)") | Out-Null }
                }
                Assert-PimGroupPolicyPatchesApplied -GroupName $gn -Failures $ruleFailures; return
            }
            # approvers: template approversSource=Owners -> the ALREADY-RESOLVED approver ids
            # (Owners -> SponsorUpn -> Department, computed in GetDesired). Build into a typed List
            # so a SINGLE approver still serialises as a JSON ARRAY (PS ConvertTo-Json unwraps a
            # 1-element @() to an object -> 'InvalidPolicy'). A singleUser approver carries ONLY
            # @odata.type + userId; a 'description' property also triggers 'InvalidPolicy'.
            $approversList = New-Object System.Collections.Generic.List[object]
            $approverIds = @($d.ApproverIds)
            if (-not $approverIds.Count) { foreach ($o in ("$($d.Owners)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $oid=Resolve-PimPrincipalId $o; if ($oid) { $approverIds += $oid } } }
            foreach ($oid in (@($approverIds) | Select-Object -Unique)) { if ($oid) { $approversList.Add(@{ '@odata.type'='#microsoft.graph.singleUser'; userId="$oid" }) } }
            $approvers = $approversList.ToArray()
            if (-not $approvers.Count) { throw "GroupsPolicies: approval-required for '$gn' but NO approver resolved (set Owners/SponsorUpn on the definition, or an Owners contact on its Department)" }
            $serial = ("$($d.Approval.mode)" -match '(?i)serial')
            $escMin = [int]("0" + "$($d.Approval.escalationHours)") * 60
            # Escalation approvers (optional template field 'escalationApprovers' = pipe/;/, UPN list).
            # Graph rejects a SingleStage approval rule with isEscalationEnabled=true but NO
            # escalationApprovers (InvalidPolicy). So escalation is ON only when both the template
            # asks for it (Serial) AND at least one escalation approver resolves.
            $escApprovers=@()
            foreach ($o in ("$($d.Approval.escalationApprovers)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $oid=Resolve-PimPrincipalId $o; if ($oid) { $escApprovers += @{ '@odata.type'='#microsoft.graph.singleUser'; userId=$oid } } }
            $escalationOn = ($serial -and $escApprovers.Count -gt 0)
            $body=@{ '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id='Approval_EndUser_Assignment'
                target=@{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
                setting=@{ isApprovalRequired=$true; isApprovalRequiredForExtension=$false; isRequestorJustificationRequired=$true; approvalMode='SingleStage'
                    approvalStages=@(@{ approvalStageTimeOutInDays=1; isApproverJustificationRequired=$true; escalationTimeInMinutes=$(if ($escalationOn) { $escMin } else { 0 }); isEscalationEnabled=$escalationOn; primaryApprovers=$approvers; escalationApprovers=$escApprovers }) } }
            # The approval PATCH is deliberately NOT wrapped: an approval rule that fails to apply
            # means the group is not actually approval-gated, which must stop the item outright.
            # §70.7: skipped only when the live approval facet (required + approver set) already equals the
            # desired one -- the same facet Equal compares, so this never skips a change Equal would detect.
            if (& $ruleDrifted 'Approval_EndUser_Assignment') { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $body }
            Assert-PimGroupPolicyPatchesApplied -GroupName $gn -Failures $ruleFailures
}

# ---------------------------------------------------------------------------
# EntraRolePolicies scope -- the PIM policy on an ENTRA DIRECTORY ROLE.
#
# WHY THIS EXISTS (operator, 2026-08-10): "we have a complete policy engine where we define
# explicitly how policies must be set, and it must verify it matches that at every run and set if
# not set. it is not ms standard." Until now the policy engine covered ONLY PIM-for-Groups member
# policies -- its single Graph filter was `scopeType eq 'Group' and roleDefinitionId eq 'member'`.
# Directory-role policies were never read and never written, so they sat at whatever Microsoft
# defaults to, unverified. Measured on the production tenant: Global Administrator, User
# Administrator and Helpdesk Administrator all carried Admin_Eligibility=[] / Admin_Assignment=[]
# purely because that is the Entra default -- not because anything had decided it.
#
# Directory-role policies are per-ROLE at TENANT scope (scopeId '/'); an AU-scoped assignment still
# activates through the role's tenant policy, so this manages one policy per managed role.
# ---------------------------------------------------------------------------
function Get-PimDirectoryRolePolicyId {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)
    try {
        $a = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'")
        if ($a.Count) { return "$($a[0].policyId)" }
    } catch { Write-Verbose "dir role policyId ($RoleDefinitionId): $($_.Exception.Message)" }
    return $null
}
function Get-PimManagedRolePolicyTargets {
    <#
      PURE-ish: the distinct set of directory ROLES the solution manages, with the policy template
      each one is linked to. Sources are the role-assignment entities, because a role the engine
      assigns is a role whose activation policy the engine is responsible for -- group-based, AU-scoped
      AND direct (#5: PIM-Assignments-Roles-Direct was missing, so a role assigned only directly never
      had its policy managed).

      Template selection: the row's PolicyTemplate column, resolved to the stored id (id, current name, former
      id); blank -> the per-kind Entra role default (Get-PimEnginePolicyTemplateDefaultId 'directoryRole':
      EntraIDRoles_Standard unless pim.Settings['PolicyTemplateDefaults'] sets another).
      CONFLICT RULE: if two rows name the same role with different templates, the one that requires
      APPROVAL wins and the conflict is reported. Silently picking either way would make a
      high-privilege role's approval requirement depend on row order.
    #>
    $byRole = @{}
    $roleDefault = $null
    foreach ($ent in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Roles-Direct')) {
        foreach ($r in @(Get-PimDesiredRows -Entity $ent | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
            $rn = "$(Get-PimRowProp -Row $r -Names @('RoleDefinitionName','RoleName'))".Trim()
            if (-not $rn) { continue }
            $tpl = Resolve-PimEnginePolicyTemplateId -Id "$(Get-PimRowProp -Row $r -Names @('PolicyTemplate'))"
            if (-not $tpl) { if ($null -eq $roleDefault) { $roleDefault = Get-PimEnginePolicyTemplateDefaultId -Kind 'directoryRole' }; $tpl = $roleDefault }
            $appr = "$(Get-PimRowProp -Row $r -Names @('ApproverUpns','Approvers'))".Trim()
            $noti = "$(Get-PimRowProp -Row $r -Names @('NotifyUpns'))".Trim()
            $k = $rn.ToLowerInvariant()
            if (-not $byRole.ContainsKey($k)) { $byRole[$k] = [pscustomobject]@{ RoleDefinitionName=$rn; TemplateId=$tpl; ApproverUpns=$appr; NotifyUpns=$noti } }
            elseif ($byRole[$k].TemplateId -ne $tpl) {
                $existing = $byRole[$k].TemplateId
                $wantsApproval = { param($t) "$t" -match '(?i)approval' }
                if ((& $wantsApproval $tpl) -and -not (& $wantsApproval $existing)) {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$tpl' (approval wins)."
                    $byRole[$k].TemplateId = $tpl
                    if ($appr) { $byRole[$k].ApproverUpns = $appr }
                } elseif (-not (& $wantsApproval $tpl) -and (& $wantsApproval $existing)) {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$existing' (approval wins)."
                } else {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$existing'."
                }
            }
            elseif ($appr -and -not $byRole[$k].ApproverUpns) { $byRole[$k].ApproverUpns = $appr }
            if ($noti -and -not $byRole[$k].NotifyUpns) { $byRole[$k].NotifyUpns = $noti }
        }
    }
    @($byRole.Values)
}

function Get-PimEntraRolePolicyDesiredSet {
    <#
      DESIRED for EntraRolePolicies: every role a row names (template per row), plus -- with the baseline on
      (#5, v1 parity: v1 set its rule set on EVERY directory role policy, CSV L510-695) -- every other
      directory role in the tenant on the Entra role default (EntraIDRoles_Standard unless
      pim.Settings['PolicyTemplateDefaults'] sets another) with approval unmanaged. Notifications are
      resolved per role (caller-aware, redirect-aware, de-duplicated). Returns @{ items; roleIds }.
    #>
    $out = New-Object System.Collections.Generic.List[object]
    $noAudience = New-Object System.Collections.Generic.List[string]
    $named = @{}
    $build = {
        param($rn, $tplId, $approverUpns, $notifyUpns, $isBaseline)
        $tpl = Get-PimEnginePolicyTemplate -Id $tplId
        if (-not $tpl) { Write-Warning "  [engine] EntraRolePolicies: unknown PolicyTemplate '$tplId' for role '$rn' -- skipped."; return }
        $hasApproval = (-not $isBaseline) -and $tpl.rules.ContainsKey('Approval')
        $approverIds = @()
        if ($hasApproval) {
            foreach ($u in ("$approverUpns" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $oid = Resolve-PimPrincipalId $u; if ($oid) { $approverIds += $oid }
            }
        }
        # Notification: resolve `recipientsSource` against the row. An approval rule whose approvers are
        # never NOTIFIED is an outage, not a control. NEVER SILENCE A NOTIFICATION: a redirect that
        # resolves to nobody is skipped (the earlier baseline entry for that rule id stays) and reported
        # once per scope. Real addresses come from the row, never from the template (templates ship publicly).
        $notify = $null
        if ($tpl.rules.ContainsKey('Notification')) {
            $notify = @(Resolve-PimTemplateNotifications -Entries @($tpl.rules['Notification']) -ApproverUpns "$approverUpns" -NotifyUpns "$notifyUpns" -NoAudience $noAudience -Label $rn)
        }
        $out.Add([pscustomobject]@{
            GroupName          = $rn          # reuse the facet builders' key field
            RoleDefinitionName = $rn
            TemplateId         = $tplId
            ApproverIds        = $approverIds
            Approval           = $(if ($hasApproval) { $tpl.rules['Approval'] } else { $null })
            Enablement         = $(if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null })
            Expiration         = $(if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null })
            Notification       = $notify
            ManageApproval     = (-not $isBaseline)
            Baseline           = [bool]$isBaseline
        })
    }
    foreach ($t in (Get-PimManagedRolePolicyTargets)) {
        $named[$t.RoleDefinitionName.ToLowerInvariant()] = $true
        & $build $t.RoleDefinitionName $t.TemplateId $t.ApproverUpns $t.NotifyUpns $false
    }
    $roleIds = $null
    if (Test-PimPolicyBaselineEnabled) {
        try { $roleIds = Get-PimEntraRoleNameMap } catch { Write-Warning "  [engine] EntraRolePolicies: baseline roles NOT covered this run -- the role catalog did not load: $($_.Exception.Message)" }
        if ($roleIds) {
            $extra = 0
            # The per-kind Entra role default (EntraIDRoles_Standard unless pim.Settings['PolicyTemplateDefaults'] sets another).
            $baseTpl = Get-PimEnginePolicyTemplateDefaultId -Kind 'directoryRole'
            foreach ($lk in @($roleIds.Keys | Sort-Object)) {
                if ($named.ContainsKey($lk)) { continue }
                $disp = @(@($Global:Roles_All_ID) | Where-Object { "$($_.DisplayName)".ToLowerInvariant() -eq $lk } | Select-Object -First 1)
                $rn = if ($disp.Count) { "$($disp[0].DisplayName)" } else { $lk }
                & $build $rn $baseTpl '' '' $true
                $extra++
            }
            if ($extra) { Write-Host ("    [engine] EntraRolePolicies: baseline covers {0} directory role(s) no row names (template '{1}', approval unmanaged)" -f $extra, $baseTpl) -ForegroundColor DarkGray }
        }
    }
    if ($noAudience.Count) {
        $n = $noAudience.Count
        $sample = ($noAudience | Select-Object -First 3) -join ', '
        Write-Host ("    [engine] EntraRolePolicies: {0} role(s) have no NotifyUpns, so their activation notices keep the template's baseline (Entra's default recipients). e.g. {1}{2}. Set NotifyUpns on the role's assignment row to redirect them." -f $n, $sample, $(if ($n -gt 3) { ', ...' } else { '' })) -ForegroundColor DarkGray
    }
    [pscustomobject]@{ items = $out.ToArray(); roleIds = $roleIds }
}

function Get-PimDirectoryRolePolicyIndex {
    # #5: with EVERY directory role in scope, one policy lookup + one policy read PER ROLE is ~260 Graph
    # calls a tick. v1 read them all in ONE call (CSV L510). Two list calls: the assignments (role id ->
    # policy id) and the policies with their rules. Returns @{ policyByRole; rulesByPolicy } or $null.
    try {
        $asg = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'")
        $pol = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=rules")
    } catch { Write-Verbose "directory role policy index: $($_.Exception.Message)"; return $null }
    $byRole = @{}; foreach ($a in $asg) { if ($a -and "$($a.roleDefinitionId)") { $byRole["$($a.roleDefinitionId)".ToLowerInvariant()] = "$($a.policyId)" } }
    $rules = @{}; foreach ($p in $pol) { if ($p -and "$($p.id)") { $rules["$($p.id)"] = @($p.rules) } }
    [pscustomobject]@{ policyByRole = $byRole; rulesByPolicy = $rules }
}

function New-PimEntraRolePoliciesProvider {
    @{
        scope = 'EntraRolePolicies'; entity = 'PIM-Assignments-Roles-Groups'; order = 75; refreshBefore = $true
        GetDesired = {
            param($ctx)
            $set = Get-PimEntraRolePolicyDesiredSet
            if ($null -ne $ctx) { $ctx['rolePolDesired'] = @($set.items); if ($set.roleIds) { $ctx['rolePolRoleIds'] = $set.roleIds } }
            @($set.items)
        }
        GetLive = {
            param($ctx)
            $ctx['rolePolRoleIds'] = Get-PimEntraRoleNameMap
            $live = New-Object System.Collections.Generic.List[object]
            $targets = if ($ctx.ContainsKey('rolePolDesired')) { @($ctx['rolePolDesired']) } else { @(Get-PimManagedRolePolicyTargets) }
            # Many roles (the baseline) -> read every directory-role policy in two list calls instead of two per role.
            $index = if (@($targets | Where-Object { $_.Baseline }).Count) { Get-PimDirectoryRolePolicyIndex } else { $null }
            foreach ($t in $targets) {
                # v2.4.336 regression: this read $rolesByName after the map moved to $ctx -- an empty
                # variable under ErrorActionPreference=Stop, so EntraRolePolicies failed every tick.
                $rid = $ctx['rolePolRoleIds'][$t.RoleDefinitionName.ToLowerInvariant()]
                if (-not $rid) { continue }   # role does not exist -> nothing live; the diff makes it a create and ApplyUpdate reports it
                $polId = $null; $rules = $null
                if ($index -and $index.policyByRole.ContainsKey("$rid".ToLowerInvariant())) {
                    $polId = $index.policyByRole["$rid".ToLowerInvariant()]
                    if ($index.rulesByPolicy.ContainsKey($polId)) { $rules = @($index.rulesByPolicy[$polId]) }
                }
                if (-not $polId) { $polId = Get-PimDirectoryRolePolicyId -RoleDefinitionId $rid }
                if (-not $polId) { continue }
                if ($null -eq $rules) {
                    $rules = @()
                    try { $rules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules").rules) }
                    catch { Write-Verbose "dir role policy read ($($t.RoleDefinitionName)): $($_.Exception.Message)" }
                }
                $live.Add([pscustomobject]@{ GroupName=$t.RoleDefinitionName; PolicyId=$polId; Rules=$rules })
            }
            # PLAN FIRST (mass-change circuit breaker, operator 2026-09-13).
            $planDesired = if ($ctx.ContainsKey('rolePolDesired')) { @($ctx['rolePolDesired']) } else { @((Get-PimEntraRolePolicyDesiredSet).items) }
            Set-PimGraphPolicyBreakerPlan -Provider 'EntraRolePolicies' -Context $ctx -Desired $planDesired -Live $live.ToArray() `
                -KeyOf { param($r) (Get-PimRowProp -Row $r -Names @('GroupName','RoleDefinitionName')).ToLowerInvariant() } -Label { param($r) "$($r.RoleDefinitionName)" }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('GroupName','RoleDefinitionName')).ToLowerInvariant() }
        # Same pure facet comparison the group policies use -- the builders are keyed by RULE ID,
        # which is identical for group and directory-role policies.
        Equal = {
            param($d,$l)
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $have = Get-PimGroupPolicyLiveFacets -Rules $l.Rules
            Test-PimGroupPolicyInSync -Desired $want -Live $have
        }
        ApplyCreate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'EntraRolePolicies').ApplyUpdate $item $ctx }
        ApplyUpdate = {
            param($item,$ctx)
            Invoke-PimGraphPolicyGuardedApply -Provider 'EntraRolePolicies' -Item $item -Context $ctx -Apply { param($i, $c) Invoke-PimEntraRolePolicyApply -item $i -ctx $c }
        }
    }
}

function Invoke-PimEntraRolePolicyApply {
    # EntraRolePolicies' write for ONE role policy -- reached only through Invoke-PimGraphPolicyGuardedApply (breaker).
    param([object]$item, [hashtable]$ctx)
            $d = $item.desired; $rn = "$($d.RoleDefinitionName)"
            $rid = $ctx['rolePolRoleIds'][$rn.ToLowerInvariant()]
            if (-not $rid) {
                $cat = @($Global:Roles_All_ID | ForEach-Object { "$($_.DisplayName)" })
                throw (Get-PimEntraRoleNotFoundMessage -Scope 'EntraRolePolicies' -RoleName $rn -Where 'an Entra role assignment row (its activation policy cannot be set)' -Catalog $cat)
            }
            $polId = Get-PimDirectoryRolePolicyId -RoleDefinitionId $rid
            if (-not $polId) { throw "EntraRolePolicies: no roleManagementPolicy for directory role '$rn'" }

            # PATCH ONLY THE RULES THAT ACTUALLY DRIFTED.
            # Re-sending every rule because ONE drifted is not merely wasteful -- Graph rejects a
            # re-PATCH of an already-correct approval rule with
            #   400 ActivationCustomApproversNotEmpty "The activation custom approvers should be empty."
            # so a notification-only drift failed the whole update and left the role reported as
            # broken while nothing was actually wrong with it. Re-read live here (rather than trust
            # the diff's snapshot) so the comparison is against the state we are about to write to.
            $liveRules = @()
            try { $liveRules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules").rules) }
            catch { Write-Verbose "role policy re-read ($rn): $($_.Exception.Message)" }
            $have = Get-PimGroupPolicyLiveFacets -Rules $liveRules
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $drifted = @{}
            foreach ($k in @($want.Keys)) {
                # Same BUG-56 exemption Test-PimGroupPolicyInSync makes, and for the same reason:
                # a policy carrying NO approval rule already satisfies "approval off". Without
                # this, any OTHER drift on such a policy would drag a pointless approval-off
                # PATCH along with it. Equal() and this loop must agree, or the item that Equal
                # called in-sync would be applied differently once something else drifted.
                if ($k -eq 'Approval_EndUser_Assignment' -and -not $have.ContainsKey($k) `
                    -and "$($want[$k])" -eq 'appr|required=false|approvers=') { continue }
                if (-not $have.ContainsKey($k) -or "$($have[$k])" -ne "$($want[$k])") { $drifted[$k] = $true }
            }
            if (-not $drifted.Count) { return [pscustomobject]@{ role=$rn; policyId=$polId; template=$d.TemplateId; note='already in sync' } }

            # #5 / BUG-52: a refused enablement or expiration PATCH used to go to Write-Verbose, so the role
            # counted as APPLIED while nothing changed. Every refusal is now COLLECTED and fails the item,
            # naming each rule -- the same contract GroupsPolicies has (Assert-PimGroupPolicyPatchesApplied).
            $ruleFailures = New-Object System.Collections.Generic.List[string]
            foreach ($enBody in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement)) {
                if (-not $drifted.ContainsKey($enBody.id)) { continue }
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $enBody }
                catch { $ruleFailures.Add("enablement/$($enBody.id): $($_.Exception.Message)") | Out-Null }
            }
            foreach ($exBody in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) {
                if (-not $drifted.ContainsKey($exBody.id)) { continue }
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $exBody }
                catch { $ruleFailures.Add("expiration/$($exBody.id): $($_.Exception.Message)") | Out-Null }
            }
            # Notification rules. NOT best-effort for the APPROVER rule: an approval whose approvers
            # are never told about the request is indistinguishable from a broken role.
            foreach ($n in @($d.Notification)) {
                $nBody = ConvertTo-PimNotificationRuleBody -Entry $n   # caller-aware (#5)
                if (-not $nBody) { continue }
                if (-not $drifted.ContainsKey("$($nBody.id)")) { continue }
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $nBody }
                catch {
                    if ("$($n.recipientType)" -eq 'Approver' -and $d.Approval) { throw "EntraRolePolicies: could not set the APPROVER notification rule on '$rn' ($($nBody.id)): $($_.Exception.Message). Refusing to leave an approval nobody is told about." }
                    $ruleFailures.Add("notification/$($nBody.id): $($_.Exception.Message)") | Out-Null
                }
            }
            $approvalOff = $false
            if ($drifted.ContainsKey('Approval_EndUser_Assignment')) {
                if ($d.Approval) {
                    # An approval rule with ZERO approvers is rejected by Graph (InvalidPolicy), and
                    # silently skipping it would leave a high-privilege role WITHOUT the approval its
                    # template demands -- so this is a hard failure, not a Write-Verbose.
                    $approvers = @(); foreach ($oid in @($d.ApproverIds)) { $approvers += @{ '@odata.type'='#microsoft.graph.singleUser'; userId=$oid } }
                    if (-not $approvers.Count) {
                        throw "EntraRolePolicies: template '$($d.TemplateId)' requires approval for '$rn' but NO approver resolved (set ApproverUpns on the role-assignment row)."
                    }
                    $serial = ("$($d.Approval.mode)" -match '(?i)serial')
                    $escMin = 240; if ($d.Approval.escalationHours) { $escMin = [int]$d.Approval.escalationHours * 60 }
                    $body = @{ '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id='Approval_EndUser_Assignment'
                        target=@{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
                        setting=@{ isApprovalRequired=$true; isApprovalRequiredForExtension=$false; isRequestorJustificationRequired=$true; approvalMode='SingleStage'
                            approvalStages=@(@{ approvalStageTimeOutInDays=1; isApproverJustificationRequired=$true; escalationTimeInMinutes=$(if ($serial) { $escMin } else { 0 }); isEscalationEnabled=$false; primaryApprovers=$approvers; escalationApprovers=@() }) } }
                    Invoke-PimPolicyRulePatch -PolicyId $polId -Body $body
                }
                else {
                    # BUG-56 -- SWITCHING A ROLE BACK OUT OF APPROVAL. This branch did not exist:
                    # the condition was `if ($d.Approval -and ...)`, so a role moved to a standard
                    # template kept its live approval forever and the product was one-way.
                    # Not best-effort. A role the operator has moved to a standard template but
                    # which still demands an approver is a role nobody can activate through the
                    # engine, so a failure here must stop the item rather than be logged and passed.
                    # (A BASELINE role carries no approval facet at all, so it never reaches here.)
                    Invoke-PimPolicyRulePatch -PolicyId $polId -Body (New-PimApprovalOffRuleBody)
                    $approvalOff = $true
                }
            }
            if ($ruleFailures.Count) {
                throw ("EntraRolePolicies '$rn': $($ruleFailures.Count) rule PATCH(es) FAILED, so the policy does NOT " +
                       "match template '$($d.TemplateId)': " + ($ruleFailures -join ' | '))
            }
            $res = [pscustomobject]@{ role=$rn; policyId=$polId; template=$d.TemplateId }
            if ($approvalOff) { $res | Add-Member -NotePropertyName note -NotePropertyValue 'approval turned OFF' }
            $res
}

# ---------------------------------------------------------------------------
# AzResPolicies scope -- the PIM policy on an AZURE RESOURCE ROLE at an ARM scope
# (Microsoft.Authorization/roleManagementPolicies, api 2020-10-01).
#
# WHY THIS EXISTS (operator, 2026-09-12: "pim v1 did that, you must fix immediately" / "they must
# match the template" / "azure policies must be on like entra and pim for groups. use same settings
# as current"). Until now v2 wrote PIM policies only through Graph (GroupsPolicies, EntraRolePolicies);
# nothing wrote the ARM policy, so an Azure role's policy sat at whatever was last saved -- including
# the partial 11-rule policies a v1 run left on internal on 2026-08-09, and the system default a
# scope falls back to when its custom policy is deleted (no MFA on activation).
#
# WHAT IS PORTED FROM v1, AND WHAT IS NOT.
#   * WHICH RULES + HOW (v1): v1's CSV engine checked each (scope, role) of
#     PIM-Assignments-Azure-Resources against the ARM policy the role's policy ASSIGNMENT names
#     (engine/PIM-Baseline-Management-CSV/PIM-Baseline-Management-CSV.ps1 L1161-1165), rule by rule,
#     via PIM_Policy_Check_Update -PIM_API AzureARM (engine/_shared/PIM-Functions.psm1 L8847-9657):
#     Expiration_EndUser_Assignment / _Admin_Eligibility / _Admin_Assignment, Enablement_EndUser_Assignment
#     and _Admin_Assignment (Admin_Eligibility commented out, L1177-1181), and nine Notification_* rules;
#     Approval and AuthenticationContext commented out (L1188-1207). THE RULES v1 COMPARED ARE THE
#     ASSIGNMENT'S `properties.effectiveRules` -- the merged set, including the defaults a partial custom
#     policy lacks -- and the policy id is `properties.policyId`'s last segment
#     (PIM-Functions.psm1 L9172-9178; the caller passes the assignment object, CSV L1161-1165). A rule id
#     NOT in effectiveRules was SKIPPED (L9651-9656); every differing rule was PATCHed ON ITS OWN as
#     { properties: { rules: [ <that one rule> ] } } to {scope}/providers/Microsoft.Authorization/
#     roleManagementPolicies/{policyId} (Invoke-AzPimPatch L9068; bodies L9252-9286, L9328-9358,
#     L9405-9437), with a write cooldown between PATCHes (Wait-PimWriteCooldown L9141). Patching a rule
#     that is in effectiveRules but missing from the custom policy is what puts it back.
#     The older SQL variant (CreateUpdate-Policies-PIM-AzResources-SQL, L7493-8027) blind-PATCHed ten rules
#     with values from config/policies.custom.sample.ps1 ($global:Azres_*, L87-127).
#   * VALUES (NOT v1): the CURRENT policy template, resolved exactly like EntraRolePolicies resolves a
#     role's template (Get-PimManagedRolePolicyTargets): the row's PolicyTemplate column (id, current name,
#     former id), blank -> the per-kind Azure role default, and approval wins a conflict. The Azure default
#     is 'AzureRoles_Standard' (2026-09-19, operator: "why dont we have 2 policy template for azure"; until
#     then Azure REUSED 'EntraIDRoles_Standard'), settable in pim.Settings['PolicyTemplateDefaults'].azureRole.
#     AzureRoles_Standard's rules are a byte-for-byte copy of EntraIDRoles_Standard's, so the switch changed
#     no Azure policy (tests/Test-PimAzResPolicies.ps1 compares the planned PATCH before/after). Those values
#     ARE v1's role values after BUG-21 (PT8H activation, P365D/P365D, MFA+Justification on activation,
#     nothing on the admin path) -- v1 applied the SAME values to Entra roles and Azure resource roles (CSV
#     engine L559-612 vs L1171-1225). AzureRoles_RequireApproval = the same + approval (approvers below).
#   * APPROVAL (operator, 2026-09-12: "i believe we have a template where it is [in the] template. that
#     must be supported"): a template that declares Approval is APPLIED, with the setting values the
#     EntraRolePolicies approval rule uses. Approvers: the row's ApproverUpns column when present (as
#     EntraRolePolicies), else the owners of the assigned groups (Owners -> SponsorUpn -> Department, as
#     GroupsPolicies). Approval is NEVER removed: a live approval the template does not declare is KEPT.
#
# MEASURED LIVE ON INTERNAL (2026-09-12), and each one shapes the code below:
#   * A PATCH carrying SIX rules was rejected as a whole (`HTTP 400 InvalidPolicyRuleId`) over one id.
#     So NEVER batch: one rule per request, each with its own result, exactly as v1 did; a rule that
#     fails is reported with ARM's raw error and does not stop the others.
#   * A read can return HTTP 500 for a scope/role -> recorded as UNREADABLE with the real error;
#     never guessed, never PATCHed.
#   * A deleted custom policy falls back to the system default (policy id == role definition GUID).
#     v1 PATCHed whatever policy id the assignment named (L9178), so this does too; a refusal is
#     reported with ARM's raw error.
#   * A managed identity's admin assignment is refused when an Admin_* enablement rule requires MFA
#     (MfaRule) -> a template asking for that is refused (BUG-21), never written.
#
# MASS-CHANGE CIRCUIT BREAKER (operator, 2026-09-12: "build the circuit breaker"). Modelled on the
# account-disable breaker (PIM-DisableGuard.ps1, Test-PimMassDisableSafe / Test-PimDisablePassAllowed):
# the WHOLE plan is computed before any PATCH; within thresholds the whole plan applies in this run;
# over ANY threshold the run writes NOTHING (never a partial mass-change) and records ONE
# AZ-POLICY-MASS-HOLD item. BUG-55 is why: a template change once rewrote 217 production group
# policies overnight with nothing to stop it. Release = an approval of that exact plan hash, stored in
# SQL (pim.Settings), never a file.
# ---------------------------------------------------------------------------
$script:PimAzResPolicyStandardRuleIds = @(
    # The 17 rule ids of a COMPLETE Azure resource PIM policy (v1's ValidateSet, PIM-Functions.psm1 L8864;
    # measured: complete policies carry these 17, a portal save adds 2 more).
    'Expiration_Admin_Eligibility','Enablement_Admin_Eligibility','Notification_Admin_Admin_Eligibility',
    'Notification_Requestor_Admin_Eligibility','Notification_Approver_Admin_Eligibility',
    'Expiration_Admin_Assignment','Enablement_Admin_Assignment','Notification_Admin_Admin_Assignment',
    'Notification_Requestor_Admin_Assignment','Notification_Approver_Admin_Assignment',
    'Expiration_EndUser_Assignment','Enablement_EndUser_Assignment','Approval_EndUser_Assignment',
    'AuthenticationContext_EndUser_Assignment','Notification_Admin_EndUser_Assignment',
    'Notification_Requestor_EndUser_Assignment','Notification_Approver_EndUser_Assignment'
)
# The BUILT-IN Azure default (2026-09-19: was 'EntraIDRoles_Standard', whose rules AzureRoles_Standard copies
# exactly). The engine reads the per-kind default from pim.Settings['PolicyTemplateDefaults'].azureRole through
# Get-PimEnginePolicyTemplateDefaultId, which falls back to this value (Get-PimPolicyTemplateCodeDefaults) -- and to
# EntraIDRoles_Standard while a store does not hold AzureRoles_Standard yet.
$script:PimAzResPolicyDefaultTemplate = 'AzureRoles_Standard'
# Breaker defaults (pim.Settings 'AzResPolicyBreaker' overrides each key). The percentage only applies
# once at least this many policies were checked, so a tiny estate is not blocked by a ratio.
$script:PimAzResPolicyBreakerDefaults = @{ MaxChanges = 25; MaxPercent = 25; MaxWeakening = 3 }
$script:PimAzResPolicyBreakerMinCheckedForPercent = 8
$script:PimAzResPolicyApprovalValidHours = 24

function Get-PimAzResPolicyTargets {
    <#
      The distinct (scope, role) pairs the solution assigns on Azure resources, each with the policy
      template it is linked to. Same selection rule as Get-PimManagedRolePolicyTargets: the row's
      PolicyTemplate column resolved to the stored id (id, current name, former id), blank -> the per-kind
      Azure role default (Get-PimEnginePolicyTemplateDefaultId 'azureRole': AzureRoles_Standard unless
      pim.Settings['PolicyTemplateDefaults'] sets another); two rows naming the same pair with different
      templates -> the one that requires APPROVAL wins and the conflict is reported. A row that still names
      EntraIDRoles_* keeps working (the same rules). GroupTags = every group assigned the pair (the approver
      fallback reads their owners).
    #>
    $byPair = @{}
    $azDefault = $null
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
        $scope = "$(Get-PimRowProp -Row $r -Names @('AzScope'))".Trim().TrimEnd('/')
        $role  = "$(Get-PimRowProp -Row $r -Names @('AzScopePermission'))".Trim()
        if (-not $scope -or -not $role) { continue }
        $tpl  = Resolve-PimEnginePolicyTemplateId -Id "$(Get-PimRowProp -Row $r -Names @('PolicyTemplate'))"
        if (-not $tpl) { if ($null -eq $azDefault) { $azDefault = Get-PimEnginePolicyTemplateDefaultId -Kind 'azureRole' }; $tpl = $azDefault }
        $appr = "$(Get-PimRowProp -Row $r -Names @('ApproverUpns','Approvers'))".Trim()
        $noti = "$(Get-PimRowProp -Row $r -Names @('NotifyUpns'))".Trim()
        $tag  = "$(Get-PimRowProp -Row $r -Names @('GroupTag'))".Trim()
        $k = "$($scope.ToLowerInvariant())|$($role.ToLowerInvariant())"
        if (-not $byPair.ContainsKey($k)) {
            $byPair[$k] = [pscustomobject]@{ AzScope=$scope; RoleName=$role; TemplateId=$tpl; ApproverUpns=$appr; NotifyUpns=$noti; GroupTags=@($(if ($tag) { $tag })) }
            continue
        }
        $t = $byPair[$k]
        if ($tag -and @($t.GroupTags) -notcontains $tag) { $t.GroupTags = @($t.GroupTags) + $tag }
        if ($t.TemplateId -ne $tpl) {
            $wantsApproval = { param($x) "$x" -match '(?i)approval' }
            if ((& $wantsApproval $tpl) -and -not (& $wantsApproval $t.TemplateId)) {
                Write-Warning "  [engine] AzResPolicies: '$role' @ $scope is linked to BOTH '$($t.TemplateId)' and '$tpl' -- using '$tpl' (approval wins)."
                $t.TemplateId = $tpl
                if ($appr) { $t.ApproverUpns = $appr }
            } else {
                Write-Warning "  [engine] AzResPolicies: '$role' @ $scope is linked to BOTH '$($t.TemplateId)' and '$tpl' -- using '$($t.TemplateId)'."
            }
        }
        elseif ($appr -and -not $t.ApproverUpns) { $t.ApproverUpns = $appr }
        if ($noti -and -not $t.NotifyUpns) { $t.NotifyUpns = $noti }
    }
    @($byPair.Values | Sort-Object AzScope, RoleName)
}

function Resolve-PimAzResPolicyApprovers {
    <#
      Approver object ids for an approval template on one (scope, role), resolved the way the existing
      providers resolve them:
        1. the row's ApproverUpns column (EntraRolePolicies) -- PIM-Assignments-Azure-Resources does not
           carry it today (Open-PimManager.ps1 defaultHeader), but a row that has it wins;
        2. otherwise the OWNERS of every group assigned the pair, through GroupsPolicies' chain
           (Resolve-PimGroupOwnerIds: Owners -> SponsorUpn -> Department owners).
      UPN -> id with Resolve-PimPrincipalId. Returns @{ ids; source } ; ids is empty when nothing resolves.
    #>
    param([Parameter(Mandatory)][object]$Target)
    $ids = New-Object System.Collections.Generic.List[string]
    $upns = @("$($Target.ApproverUpns)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($upns.Count) {
        foreach ($u in $upns) { $oid = Resolve-PimPrincipalId $u; if ($oid -and -not $ids.Contains("$oid")) { $ids.Add("$oid") } }
        return [pscustomobject]@{ ids = $ids.ToArray(); source = 'ApproverUpns' }
    }
    $tags = @(@($Target.GroupTags) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if ($tags.Count) {
        # REQ-L: an Azure permission group's owners live on its PIM-Definitions-Resources row (Get-PimResourceOwnerDefinitionRows).
        foreach ($g in @(@(Get-PimGroupDefinitionRows) + @(Get-PimResourceOwnerDefinitionRows))) {
            if ($null -eq $g) { continue }
            if ($tags -notcontains "$($g.GroupTag)".Trim().ToLowerInvariant()) { continue }
            foreach ($oid in @(Resolve-PimGroupOwnerIds -Row $g | ForEach-Object { $_ })) { if ($oid -and -not $ids.Contains("$oid")) { $ids.Add("$oid") } }
        }
    }
    [pscustomobject]@{ ids = $ids.ToArray(); source = 'GroupOwners' }
}

function Get-PimAzResPolicyDesiredSet {
    # DESIRED = one row per (scope, role) carrying the template's rule families in the SAME shape
    # EntraRolePolicies emits, so the shared facet builders (Get-PimGroupPolicyDesiredFacets) apply as-is.
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-PimAzResPolicyTargets)) {
        $tpl = Get-PimEnginePolicyTemplate -Id $t.TemplateId
        if (-not $tpl) { Write-Warning "  [engine] AzResPolicies: unknown PolicyTemplate '$($t.TemplateId)' for '$($t.RoleName)' @ $($t.AzScope) -- skipped."; continue }
        $hasApproval = $tpl.rules.ContainsKey('Approval')
        $approverIds = @(); $approverSource = ''
        if ($hasApproval) {
            $ar = Resolve-PimAzResPolicyApprovers -Target $t
            $approverIds = @($ar.ids); $approverSource = "$($ar.source)"
        }
        # Notification: the SAME resolution EntraRolePolicies applies (recipientsSource ApproverUpns /
        # NotifyUpns from the row; never silence a notification that has no resolved audience).
        $notify = $null
        if ($tpl.rules.ContainsKey('Notification')) {
            $notify = @(Resolve-PimTemplateNotifications -Entries @($tpl.rules['Notification']) -ApproverUpns "$($t.ApproverUpns)" -NotifyUpns "$($t.NotifyUpns)")
        }
        $out.Add([pscustomobject]@{
            AzScope        = $t.AzScope
            RoleName       = $t.RoleName
            TemplateId     = $t.TemplateId
            ApproverUpns   = $t.ApproverUpns
            NotifyUpns     = $t.NotifyUpns
            GroupTags      = @($t.GroupTags)
            ApproverIds    = $approverIds
            ApproverSource = $approverSource
            Approval       = $(if ($hasApproval) { $tpl.rules['Approval'] } else { $null })
            Enablement     = $(if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null })
            Expiration     = $(if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null })
            Notification   = $notify
        })
    }
    $out.ToArray()
}

function Get-PimAzResPolicyKey {
    param([object]$Row)
    $s = "$(Get-PimRowProp -Row $Row -Names @('AzScope'))".Trim().TrimEnd('/').ToLowerInvariant()
    $r = "$(Get-PimRowProp -Row $Row -Names @('RoleName'))".Trim().ToLowerInvariant()
    if (-not $s -or -not $r) { return '' }
    "$s|$r"
}

function Get-PimAzResPolicyLiveApproval {
    # PURE: an ARM approval rule -> @{ present; required; ids }. An ARM approver is { id, userType, ... }
    # where Graph's is { userId }.
    param([object[]]$Rules)
    foreach ($r in @($Rules)) {
        if ($null -eq $r -or "$($r.id)" -ne 'Approval_EndUser_Assignment') { continue }
        $required = $false; $ids = New-Object System.Collections.Generic.List[string]
        if ($r.setting) {
            $required = [bool]$r.setting.isApprovalRequired
            foreach ($st in @($r.setting.approvalStages)) {
                foreach ($a in @($st.primaryApprovers)) {
                    if ($null -eq $a) { continue }
                    $aid = if ("$($a.id)") { "$($a.id)" } else { "$($a.userId)" }
                    if ($aid -and -not $ids.Contains($aid.ToLowerInvariant())) { $ids.Add($aid.ToLowerInvariant()) }
                }
            }
        }
        return [pscustomobject]@{ present = $true; required = $required; ids = $ids.ToArray() }
    }
    [pscustomobject]@{ present = $false; required = $false; ids = @() }
}

function Get-PimAzResPolicyLiveFacets {
    # PURE: the shared live-facet builder, with the approval facet read from the ARM approver shape.
    param([object[]]$Rules)
    $f = Get-PimGroupPolicyLiveFacets -Rules $Rules
    $a = Get-PimAzResPolicyLiveApproval -Rules $Rules
    if ($a.present) { $f['Approval_EndUser_Assignment'] = "appr|required=$($a.required.ToString().ToLowerInvariant())|approvers=$(ConvertTo-PimSortedList $a.ids)" }
    $f
}

function Get-PimAzResPolicyVerdict {
    <#
      PURE. THE VERIFICATION: do the EFFECTIVE rules for one (scope, role) match its template?
        matches        -- every template rule present in effectiveRules holds the template's value
        kept           -- matches, and live carries an APPROVAL the template does not declare: kept on
                          purpose (approval is never removed) -- AZ-POLICY-APPROVAL, informational
        differs        -- some rules differ (diffs: live vs target); each is PATCHed on its own
        unreadable     -- a read failed (error carries ARM's own message); nothing is inferred
      A template rule id that is NOT in effectiveRules is SKIPPED (skippedRules), as v1 did -- never PATCHed.
        no-policy      -- ARM returned no policy assignment for the role at the scope
        role-not-found -- no ARM role by that name at the scope
      Each diff carries `target` -- the facet the rule will hold after the write (for approval that is
      live approvers UNION template approvers: an approver is never removed). A diff is `blocked` when it
      must not be written: 'no-approver' (the template requires approval and no approver resolved -- the
      policy is not written half-configured) or 'admin-mfa' (BUG-21: unsatisfiable by the engine).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Desired, [AllowNull()][object]$Live)
    $v = [ordered]@{
        key = (Get-PimAzResPolicyKey -Row $Desired); scope = "$($Desired.AzScope)"; role = "$($Desired.RoleName)"
        template = "$($Desired.TemplateId)"; state = ''; policyId = ''; isDefaultPolicy = $false
        skippedRules = @(); diffs = @(); lowersSecurity = @(); missingStandardRules = @(); approvalKept = $false; notes = @(); error = ''
    }
    if ($null -eq $Live) { $v.state = 'unreadable'; $v.error = 'no live read was taken for this pair'; return [pscustomobject]$v }
    $v.policyId = "$($Live.PolicyId)"; $v.isDefaultPolicy = [bool]$Live.IsDefaultPolicy
    $ls = "$($Live.State)"
    if ($ls -ne 'read') { $v.state = $(if ($ls) { $ls } else { 'unreadable' }); $v.error = "$($Live.Error)"; return [pscustomobject]$v }

    $want = Get-PimGroupPolicyDesiredFacets -Desired $Desired
    $have = Get-PimAzResPolicyLiveFacets -Rules @($Live.Rules)
    $liveAppr = Get-PimAzResPolicyLiveApproval -Rules @($Live.Rules)
    $liveIds = @{}; foreach ($r in @($Live.Rules)) { if ($r -and "$($r.id)") { $liveIds["$($r.id)"] = $true } }
    $v.missingStandardRules = @($script:PimAzResPolicyStandardRuleIds | Where-Object { -not $liveIds.ContainsKey($_) })

    $missing = New-Object System.Collections.Generic.List[string]
    $diffs = New-Object System.Collections.Generic.List[object]
    $lowers = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($want.Keys | Sort-Object)) {
        $w = "$($want[$k])"
        if ($k -eq 'Approval_EndUser_Assignment') {
            if (-not $Desired.Approval) {
                # Template declares no approval: never REMOVE one. No rule / not required = nothing to do;
                # required live = KEPT (reported, not written).
                if ($liveAppr.present -and $liveAppr.required) {
                    $v.approvalKept = $true
                    $notes.Add("AZ-POLICY-APPROVAL: approval is ON live but template '$($Desired.TemplateId)' has none -- KEPT (approval is never removed)")
                }
                continue
            }
            if (-not $liveAppr.present) { $missing.Add($k); $notes.Add("skipped $k -- not in effectiveRules (v1: 'rule not defined on this policy')"); continue }
            $tplIds = @(@($Desired.ApproverIds) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
            $absent = @($tplIds | Where-Object { @($liveAppr.ids) -notcontains $_ })
            if ($liveAppr.required -and $tplIds.Count -and -not $absent.Count) {
                $extra = @(@($liveAppr.ids) | Where-Object { $tplIds -notcontains $_ })
                if ($extra.Count) { $notes.Add("approval: $($extra.Count) approver(s) live beyond the template -- KEPT (an approver is never removed)") }
                continue
            }
            # The approvers the rule will hold: live UNION template when approval is already in force (never
            # remove an approver); only the template's when it is not (a not-in-force list grants nothing).
            $targetIds = New-Object System.Collections.Generic.List[string]
            if ($liveAppr.required) { foreach ($x in @($liveAppr.ids)) { if (-not $targetIds.Contains($x)) { $targetIds.Add($x) } } }
            foreach ($x in $tplIds) { if (-not $targetIds.Contains($x)) { $targetIds.Add($x) } }
            $blocked = if (-not $tplIds.Count) { 'no-approver' } else { '' }
            $diffs.Add([pscustomobject]@{ ruleId = $k; live = "$($have[$k])"; template = $w; target = "appr|required=true|approvers=$(ConvertTo-PimSortedList $targetIds.ToArray())"; blocked = $blocked; approverIds = $targetIds.ToArray() })
            continue
        }
        if (-not $have.ContainsKey($k)) { $missing.Add($k); $notes.Add("skipped $k -- not in effectiveRules (v1: 'rule not defined on this policy')"); continue }
        $h = "$($have[$k])"
        if ($h -eq $w) { continue }
        $blocked = ''
        if ($k -in @('Enablement_Admin_Assignment','Enablement_Admin_Eligibility') -and $w -match 'MultiFactorAuthentication') { $blocked = 'admin-mfa' }
        if ($k -like 'Enablement_*' -and $h -match 'MultiFactorAuthentication' -and $w -notmatch 'MultiFactorAuthentication') { $lowers.Add($k) }
        $diffs.Add([pscustomobject]@{ ruleId = $k; live = $h; template = $w; target = $w; blocked = $blocked; approverIds = @() })
    }
    $v.skippedRules = $missing.ToArray(); $v.diffs = $diffs.ToArray(); $v.lowersSecurity = $lowers.ToArray(); $v.notes = $notes.ToArray()
    $v.state = if ($diffs.Count) { 'differs' } elseif ($v.approvalKept) { 'kept' } else { 'matches' }
    [pscustomobject]$v
}

function Get-PimAzResPolicyDesiredRuleBodies {
    # PURE: rule id -> the template's rule body (the shared Graph-shaped builders). Only the VALUE
    # fields are taken from these; id/ruleType/target always come from the live ARM rule.
    param([Parameter(Mandatory)][object]$Desired)
    $m = @{}
    foreach ($b in @(ConvertTo-PimExpirationRuleBodies -Expiration $Desired.Expiration)) { if ($b) { $m["$($b.id)"] = $b } }
    foreach ($b in @(ConvertTo-PimEnablementRuleBodies -Enablement $Desired.Enablement)) { if ($b) { $m["$($b.id)"] = $b } }
    foreach ($n in @($Desired.Notification)) {
        $nb = ConvertTo-PimNotificationRuleBody -Entry $n   # caller-aware (#5)
        if ($nb) { $m["$($nb.id)"] = $nb }
    }
    if ($Desired.Approval) { $m['Approval_EndUser_Assignment'] = @{ id = 'Approval_EndUser_Assignment'; setting = (New-PimAzResPolicyApprovalSetting -Approval $Desired.Approval -ApproverIds @($Desired.ApproverIds)) } }
    $m
}

function New-PimAzResPolicyApprovalSetting {
    <#
      PURE: the approval `setting` for an ARM approval rule. The VALUES are the ones EntraRolePolicies'
      ApplyUpdate sends for a template with Approval (isApprovalRequired=true, not for extension,
      requestor justification, SingleStage, one stage of 1 day with approver justification, escalation
      minutes = escalationHours*60 when mode is Serial else 0, escalation disabled, no escalation
      approvers). The ONE shape difference is ARM's approver element: { id, userType, isBackup } where
      Graph's is { @odata.type: singleUser, userId }. Arrays stay arrays for a single approver.
    #>
    param([Parameter(Mandatory)][object]$Approval, [string[]]$ApproverIds = @())
    $serial = ("$($Approval.mode)" -match '(?i)serial')
    $escMin = 240; if ($Approval.escalationHours) { $escMin = [int]$Approval.escalationHours * 60 }
    $approvers = New-Object System.Collections.Generic.List[object]
    foreach ($oid in @($ApproverIds | Where-Object { "$_".Trim() })) { $approvers.Add([ordered]@{ id = "$oid"; userType = 'User'; isBackup = $false }) }
    [ordered]@{
        isApprovalRequired = $true; isApprovalRequiredForExtension = $false; isRequestorJustificationRequired = $true; approvalMode = 'SingleStage'
        approvalStages = @([ordered]@{ approvalStageTimeOutInDays = 1; isApproverJustificationRequired = $true; escalationTimeInMinutes = $(if ($serial) { $escMin } else { 0 }); isEscalationEnabled = $false; primaryApprovers = $approvers.ToArray(); escalationApprovers = @() })
    }
}

function New-PimAzResPolicyRulePatch {
    <#
      PURE: ONE rule for the ARM PATCH -- the LIVE rule, verbatim (id, ruleType, target and every field
      the engine does not manage), with only the template-managed VALUE fields replaced. Keeping target
      from live is deliberate: v1's SQL variant rebuilt target by hand and got it wrong
      (CreateUpdate-Policies-PIM-AzResources-SQL, PIM-Functions.psm1 L7653-7671: the activation rule
      Expiration_EndUser_Assignment sent with caller "Admin", and `level` outside `target`).
    #>
    param([Parameter(Mandatory)][object]$LiveRule, [Parameter(Mandatory)][object]$DesiredBody)
    $h = [ordered]@{}
    if ($LiveRule -is [System.Collections.IDictionary]) { foreach ($k in @($LiveRule.Keys)) { $h["$k"] = $LiveRule[$k] } }
    else { foreach ($p in $LiveRule.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $id = "$($h['id'])"
    if ($id -like 'Expiration_*') {
        $h['isExpirationRequired'] = [bool]$DesiredBody.isExpirationRequired
        $h['maximumDuration']      = "$($DesiredBody.maximumDuration)"
    }
    elseif ($id -like 'Enablement_*') {
        $h['enabledRules'] = @(@($DesiredBody.enabledRules) | Where-Object { "$_".Trim() })
    }
    elseif ($id -like 'Notification_*') {
        $h['notificationLevel']          = "$($DesiredBody.notificationLevel)"
        $h['isDefaultRecipientsEnabled'] = [bool]$DesiredBody.isDefaultRecipientsEnabled
        $h['notificationRecipients']     = @(@($DesiredBody.notificationRecipients) | Where-Object { "$_".Trim() })
    }
    elseif ($id -eq 'Approval_EndUser_Assignment') {
        $h['setting'] = $DesiredBody.setting
    }
    else { throw "AzResPolicies: rule '$id' is not a rule this provider writes" }
    $h
}

function Get-PimAzResPolicyWeakening {
    <#
      PURE: how applying ONE rule change would WEAKEN the policy. Returns plain sentences, empty when
      the change is not weakening. Weakening =
        * enabledRules loses MultiFactorAuthentication, Justification or Ticketing;
        * maximumDuration rises, or isExpirationRequired goes true -> false (an unparseable duration
          counts as weakening -- a breaker that cannot tell must not assume "safe");
        * a notification recipient is removed, or default recipients go on -> off.
      Approval is never weakening here: it is only ever added or widened, never removed.
    #>
    param([Parameter(Mandatory)][object]$LiveRule, [Parameter(Mandatory)][object]$DesiredBody)
    $out = New-Object System.Collections.Generic.List[string]
    $id = "$($LiveRule.id)"
    if ($id -like 'Enablement_*') {
        $liveSet = @(@($LiveRule.enabledRules) | ForEach-Object { "$_" })
        $desSet  = @(@($DesiredBody.enabledRules) | ForEach-Object { "$_" })
        foreach ($c in @('MultiFactorAuthentication','Justification','Ticketing')) {
            if ($liveSet -contains $c -and $desSet -notcontains $c) { $out.Add("removes $c") }
        }
    }
    elseif ($id -like 'Expiration_*') {
        if ([bool]$LiveRule.isExpirationRequired -and -not [bool]$DesiredBody.isExpirationRequired) { $out.Add('isExpirationRequired true -> false') }
        $ld = "$($LiveRule.maximumDuration)".Trim(); $dd = "$($DesiredBody.maximumDuration)".Trim()
        if ($ld -and $ld -ne $dd) {
            if (-not $dd) { $out.Add("removes maximumDuration $ld") }
            else {
                try {
                    if ([System.Xml.XmlConvert]::ToTimeSpan($dd) -gt [System.Xml.XmlConvert]::ToTimeSpan($ld)) { $out.Add("raises maximumDuration $ld -> $dd") }
                } catch { $out.Add("maximumDuration $ld -> $dd could not be compared (counted as weakening)") }
            }
        }
    }
    elseif ($id -like 'Notification_*') {
        $desR = @(@($DesiredBody.notificationRecipients) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        foreach ($x in @(@($LiveRule.notificationRecipients) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })) {
            if ($desR -notcontains $x) { $out.Add("removes notification recipient $x") }
        }
        if ([bool]$LiveRule.isDefaultRecipientsEnabled -and -not [bool]$DesiredBody.isDefaultRecipientsEnabled) { $out.Add('turns default recipients off') }
    }
    $out.ToArray()
}

function Read-PimAzResPolicyAssignment {
    <#
      GET the role's policy ASSIGNMENT at the scope and return { policyId; rules = properties.effectiveRules }.
      effectiveRules is what v1 compared (PIM-Functions.psm1 L9177): the MERGED rule set, including the
      default rules a partial custom policy lacks. The policy id is built as v1 built it: the scope plus
      the last segment of properties.policyId (L9178, L9279). THROWS on a failed read or on an assignment
      without effectiveRules (callers turn that into a state or an error -- never a guess).
    #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleId)
    $roleDefId = "$Scope/providers/Microsoft.Authorization/roleDefinitions/$RoleId"
    $asg = @(Invoke-PimArm -Path "$Scope/providers/Microsoft.Authorization/roleManagementPolicyAssignments?`$filter=roleDefinitionId eq '$roleDefId'" -ApiVersion '2020-10-01' -All)
    $asg = @($asg | Where-Object { $null -ne $_ -and "$($_.properties.policyId)" })
    if (-not $asg.Count) { return $null }
    $pick = @($asg | Where-Object { "$($_.properties.scope)".TrimEnd('/') -ieq $Scope } | Select-Object -First 1)
    $a = if ($pick.Count) { $pick[0] } else { $asg[0] }
    $polGuid = (("$($a.properties.policyId)").TrimEnd('/') -split '/')[-1]
    $rules = @(@($a.properties.effectiveRules) | Where-Object { $null -ne $_ })
    if (-not $rules.Count) { throw "the policy assignment for role $RoleId at $Scope returned no effectiveRules" }
    [pscustomobject]@{ policyId = "$Scope/providers/Microsoft.Authorization/roleManagementPolicies/$polGuid"; policyGuid = $polGuid; rules = $rules }
}

function Get-PimAzResPolicyLive {
    <#
      The live read for ONE (scope, role): the assignment's effectiveRules. Never throws: a failed read is
      a STATE carrying ARM's own message, so a 500 is reported as unreadable instead of being read as
      "no policy" or "no rules".
    #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$RoleName, [hashtable]$RoleCache = @{})
    $row = [pscustomobject]@{ AzScope=$Scope; RoleName=$RoleName; RoleId=''; State=''; Error=''; PolicyId=''; IsDefaultPolicy=$false; Rules=@() }
    $rid = Resolve-PimArmRoleId -Scope $Scope -RoleName $RoleName -Cache $RoleCache
    if (-not $rid) {
        $err = Get-PimArmRoleLookupError -Scope $Scope -RoleName $RoleName -Cache $RoleCache
        if ($err) { $row.State = 'unreadable'; $row.Error = "could not look up ARM role '$RoleName' at ${Scope}: $err" }
        else      { $row.State = 'role-not-found'; $row.Error = "AzResPolicies: ARM role '$RoleName' not found at $Scope" }
        return $row
    }
    $row.RoleId = $rid
    $a = $null
    try { $a = Read-PimAzResPolicyAssignment -Scope $Scope -RoleId $rid }
    catch { $row.State = 'unreadable'; $row.Error = "policy assignment read failed: $($_.Exception.Message)"; return $row }
    if (-not $a) { $row.State = 'no-policy'; $row.Error = "ARM returned no roleManagementPolicyAssignment for '$RoleName' at $Scope"; return $row }
    $row.PolicyId = $a.policyId
    $row.IsDefaultPolicy = ("$($a.policyGuid)" -ieq $rid)
    $row.Rules = @($a.rules)
    $row.State = 'read'
    $row
}

function Get-PimAzResPolicyChangePlan {
    <#
      PURE. PLAN FIRST, WRITE SECOND: everything this run would write, computed before any PATCH.
        checked (T)   = policies read successfully (matches / kept / differs)
        changes (N)   = POLICIES that would be PATCHed (each rule is its own PATCH; N counts policies)
        weakening (W) = RULE changes that weaken a policy (Get-PimAzResPolicyWeakening)
        planHash      = SHA-256 (lowercase hex) over the ordinally sorted lines
                        "<policyId lowercase>|<ruleId>|<target facet>" joined with LF -- the exact change
                        set; any different change set has a different hash.
      A policy is left out when nothing on it may be written (unreadable, or an approval template with no
      resolvable approver -- that one is never written half-configured).
    #>
    param([object[]]$Desired, [object[]]$Live, [object[]]$Verdicts)
    $desByKey = @{}; foreach ($x in @($Desired)) { if ($x) { $desByKey[(Get-PimAzResPolicyKey -Row $x)] = $x } }
    $liveByKey = @{}; foreach ($x in @($Live)) { if ($x) { $liveByKey[(Get-PimAzResPolicyKey -Row $x)] = $x } }
    $policies = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $weak = New-Object System.Collections.Generic.List[object]
    $adminAligned = New-Object System.Collections.Generic.List[object]
    $notifyAligned = New-Object System.Collections.Generic.List[object]
    $defaultAligned = New-Object System.Collections.Generic.List[object]
    $checked = 0
    foreach ($v in @($Verdicts)) {
        if ($null -eq $v) { continue }
        if ($v.state -in @('matches','kept','differs')) { $checked++ }
        if ($v.state -ne 'differs') { continue }
        if (@($v.diffs | Where-Object { $_.blocked -eq 'no-approver' }).Count) { continue }
        $d = $desByKey[$v.key]; $l = $liveByKey[$v.key]
        if (-not $d -or -not $l) { continue }
        $bodies = Get-PimAzResPolicyDesiredRuleBodies -Desired $d
        $liveById = @{}; foreach ($r in @($l.Rules)) { if ($r) { $liveById["$($r.id)"] = $r } }
        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($df in @($v.diffs)) {
            if ($df.blocked) { continue }
            if (-not $liveById.ContainsKey($df.ruleId) -or -not $bodies.ContainsKey($df.ruleId)) { continue }
            $w = @()
            if ($df.ruleId -ne 'Approval_EndUser_Assignment') { $w = @(Get-PimAzResPolicyWeakening -LiveRule $liveById[$df.ruleId] -DesiredBody $bodies[$df.ruleId]) }
            foreach ($s in $w) {
                $entry = [pscustomobject]@{ scope = $v.scope; role = $v.role; policyId = $v.policyId; ruleId = $df.ruleId; change = $s }
                # ADMIN-PATH ALIGNMENT IS NOT WEAKENING (decision 2026-09-13): Enablement_Admin_Assignment /
                # _Admin_Eligibility gate the ENGINE's own assignment writes; a managed identity can never
                # satisfy MFA (MfaRule, measured), and v1 cleared exactly these (BUG-21). Counted toward N,
                # reported as its own category -- visible, never hidden.
                if ($df.ruleId -in @('Enablement_Admin_Assignment','Enablement_Admin_Eligibility') -and $s -match '^removes (MultiFactorAuthentication|Justification)$') { $adminAligned.Add($entry) }
                # NOTIFICATION DEFAULTS aligned to the template (decision 2026-09-13) are not weakening either -- a
                # default-recipient switch; removing a NAMED recipient still is.
                elseif ($df.ruleId -like 'Notification_*' -and $s -eq 'turns default recipients off') { $notifyAligned.Add($entry) }
                # 2026-09-21 (operator: "it still shows pending approvals of policies, but i have approved long ago"): a SYSTEM
                # DEFAULT policy nobody ever changed has nothing to protect -- its first template application is not weakening.
                elseif ($v.PSObject.Properties['isDefaultPolicy'] -and $v.isDefaultPolicy) { $defaultAligned.Add($entry) }
                else { $weak.Add($entry) }
            }
            $rules.Add([pscustomobject]@{ ruleId = $df.ruleId; live = $df.live; target = $df.target; weakening = @($w) })
            $lines.Add(("{0}|{1}|{2}" -f "$($v.policyId)".ToLowerInvariant(), $df.ruleId, $df.target))
        }
        if ($rules.Count) { $policies.Add([pscustomobject]@{ key = $v.key; scope = $v.scope; role = $v.role; policyId = $v.policyId; template = $v.template; rules = $rules.ToArray()
                                                             neverModified = [bool]($v.PSObject.Properties['isDefaultPolicy'] -and $v.isDefaultPolicy) }) }
    }
    $sorted = $lines.ToArray(); [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))) } finally { $sha.Dispose() }
    $hash = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    $byKey = @{}; foreach ($p in $policies) { $byKey[$p.key] = $p }
    [pscustomobject]@{ planHash = $hash; checked = $checked; changes = $policies.Count; weakening = $weak.Count; ruleChanges = $sorted.Count
                       policies = $policies.ToArray(); weakenings = $weak.ToArray(); byKey = $byKey
                       adminPathAligned = $adminAligned.ToArray(); notificationDefaultsAligned = $notifyAligned.ToArray(); defaultPolicyAligned = $defaultAligned.ToArray() }
}

function ConvertFrom-PimAzResSettingValue {
    # A pim.Settings value may come back as a JSON string or an already-parsed object.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { $s = $Value.Trim(); if (-not $s) { return $null }; return ($s | ConvertFrom-Json) }
    $Value
}

function ConvertTo-PimAzResUtc {
    # A stamp as UTC [datetime], or $null. PS 7's ConvertFrom-Json already turns an ISO-8601 string into a
    # (local) [datetime], and "$value" would then render it in a culture format that does not parse back.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    try { return ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime() } catch { return $null }
}

# ---------------------------------------------------------------------------
# POLICY MASS-CHANGE CIRCUIT BREAKER -- ONE core, three providers (operator, 2026-09-13: "add breaker"
# to GroupsPolicies and EntraRolePolicies, the same design AzResPolicies has). Each provider has its OWN
# thresholds key, hold record, approval record and failure code, so an approval can never cover another
# provider's change set. Measured motivation for the Graph providers: the first 2.4.338 run on internal
# changed 293 of 706 group policies in one tick (owner + notification alignment) with nothing to hold it.
#   <prefix>Breaker            pim.Settings  {"MaxChanges":n,"MaxPercent":n,"MaxWeakening":n}
#   <prefix>MassHold           pim.Settings  the held plan (what an approval must match)
#   <prefix>MassChangeApproval pim.Settings  { planHash, approvedBy, approvedUtc, expiresUtc }
# ---------------------------------------------------------------------------
$script:PimPolicyBreakerSpecs = @{
    'azrespolicies'     = @{ Provider = 'AzResPolicies';     Prefix = 'AzResPolicy';     Code = 'AZ-POLICY-MASS-HOLD';     Audit = 'azres.policy.masschange'
                             ApproveFn = 'Approve-PimAzResPolicyMassChange'; Noun = 'Azure resource PIM policies'; MailSubject = 'PIM Azure policy mass-change circuit breaker held' }
    'groupspolicies'    = @{ Provider = 'GroupsPolicies';    Prefix = 'GroupsPolicy';    Code = 'GROUP-POLICY-MASS-HOLD';  Audit = 'groups.policy.masschange'
                             ApproveFn = 'Approve-PimPolicyMassChange';     Noun = 'PIM for Groups policies';      MailSubject = 'PIM for Groups policy mass-change circuit breaker held' }
    'entrarolepolicies' = @{ Provider = 'EntraRolePolicies'; Prefix = 'EntraRolePolicy'; Code = 'ENTRA-POLICY-MASS-HOLD';  Audit = 'entrarole.policy.masschange'
                             ApproveFn = 'Approve-PimPolicyMassChange';     Noun = 'Entra directory role PIM policies'; MailSubject = 'PIM Entra role policy mass-change circuit breaker held' }
}

function Get-PimPolicyBreakerSpec {
    param([Parameter(Mandatory)][string]$Provider)
    $s = $script:PimPolicyBreakerSpecs["$Provider".Trim().ToLowerInvariant()]
    if (-not $s) { throw "policy breaker: unknown provider '$Provider' (known: AzResPolicies, GroupsPolicies, EntraRolePolicies)" }
    $s
}

function Get-PimPolicyBreakerThresholds {
    <#
      The breaker thresholds for ONE provider: code defaults (MaxChanges 25, MaxPercent 25, MaxWeakening 3),
      each key overridable from SQL -- pim.Settings '<prefix>Breaker'. An unreadable or malformed setting
      falls back to the defaults, and says so.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Provider)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    $key = "$($spec.Prefix)Breaker"
    $t = [ordered]@{ MaxChanges = [int]$script:PimAzResPolicyBreakerDefaults.MaxChanges; MaxPercent = [double]$script:PimAzResPolicyBreakerDefaults.MaxPercent
                     MaxWeakening = [int]$script:PimAzResPolicyBreakerDefaults.MaxWeakening; MinCheckedForPercent = $script:PimAzResPolicyBreakerMinCheckedForPercent; source = 'default' }
    $hasStore = [bool](Get-Command Get-PimSetting -ErrorAction SilentlyContinue)
    $mirror = ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($key))
    if ($hasStore -or $mirror) {
        try {
            # pim.Settings through the store bridge, else the hydrated pim.Settings mirror (Import-PimSettingsFromStore)
            $raw = $null
            if ($hasStore) { $raw = Get-PimSetting -Name $key }
            if ($null -eq $raw -and $mirror) { $raw = $global:PIM_NamingConventions[$key] }
            $o = ConvertFrom-PimAzResSettingValue $raw
            if ($o) {
                foreach ($k in @('MaxChanges','MaxPercent','MaxWeakening')) {
                    $p = $o.PSObject.Properties[$k]
                    if ($p -and "$($p.Value)" -match '^\d+(\.\d+)?$') { $t[$k] = $(if ($k -eq 'MaxPercent') { [double]$p.Value } else { [int][double]$p.Value }); $t.source = "pim.Settings['$key']" }
                }
            }
        } catch { Write-Warning "  [engine] $($spec.Provider): pim.Settings['$key'] could not be read ($($_.Exception.Message)) -- using the default thresholds." }
    }
    [pscustomobject]$t
}

function Get-PimPolicyMassChangeApproval {
    # The recorded approval (pim.Settings '<prefix>MassChangeApproval') for ONE provider, or $null.
    param([Parameter(Mandatory)][string]$Provider)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return $null }
    try { $o = ConvertFrom-PimAzResSettingValue (Get-PimSetting -Name "$($spec.Prefix)MassChangeApproval") } catch { return $null }
    if (-not $o -or -not "$($o.planHash)".Trim()) { return $null }
    $o
}

function Get-PimPolicyMassHold {
    <#
      The CURRENT hold of ONE provider for a UI, or $null. The record lives in pim.Settings '<prefix>MassHold';
      it is current only while the failing set (pim.Settings 'EngineItemFailures') still carries that
      provider's hold item for this plan hash -- a later run that did not hold drops that item, so a stale
      record is never offered for approval.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Provider)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return $null }
    $h = $null
    try { $h = ConvertFrom-PimAzResSettingValue (Get-PimSetting -Name "$($spec.Prefix)MassHold") } catch { return $null }
    if (-not $h -or -not "$($h.planHash)".Trim()) { return $null }
    if (Get-Command Get-PimEngineItemFailures -ErrorAction SilentlyContinue) {
        $live = @(Get-PimEngineItemFailures | Where-Object { "$($_.code)" -eq $spec.Code -and "$($_.message)" -like "*$($h.planHash)*" })
        if (-not $live.Count) { return $null }
    }
    $h
}

function Get-PimPolicyWeakeningKey {
    # PURE. What identifies ONE weakening change for an approval: the policy, the rule and the change, lower-case.
    param([Parameter(Mandatory)][object]$Entry)
    ("{0}|{1}|{2}" -f "$($Entry.policyId)", "$($Entry.ruleId)", "$($Entry.change)").ToLowerInvariant()
}

function Approve-PimAllPolicyMassChanges {
    <#
      Approve EVERY standing policy hold (PIM for Groups, Entra role and Azure role policies) in one go -- operator 2026-09-21:
      "show me all changes and i can approve all in one go". Each is approved exactly as Approve-PimPolicyMassChange would
      (its own current plan hash, its own audit record). Returns one row per provider: @{ provider; approved; planHash; error }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$By, [ValidateRange(1, 168)][int]$ValidHours = 24, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($prov in 'GroupsPolicies', 'EntraRolePolicies', 'AzResPolicies') {
        $hold = $null
        try { $hold = Get-PimPolicyMassHold -Provider $prov } catch { $hold = $null }
        if (-not $hold) { continue }
        try {
            $r = Approve-PimPolicyMassChange -Provider $prov -PlanHash "$($hold.planHash)" -By $By -ValidHours $ValidHours -NowUtc $NowUtc
            $out.Add([pscustomobject]@{ provider = $prov; approved = $true; planHash = "$($r.planHash)"; changes = [int]$hold.changes; weakening = [int]$hold.weakening; error = '' }) | Out-Null
        } catch {
            $out.Add([pscustomobject]@{ provider = $prov; approved = $false; planHash = "$($hold.planHash)"; changes = [int]$hold.changes; weakening = [int]$hold.weakening; error = "$($_.Exception.Message)" }) | Out-Null
        }
    }
    return @($out.ToArray())
}

function Approve-PimPolicyMassChange {
    <#
      Approve ONE held plan of ONE provider. Refused unless -PlanHash equals the CURRENT recorded hold's hash
      FOR THAT PROVIDER. Writes pim.Settings '<prefix>MassChangeApproval' = { planHash, approvedBy,
      approvedUtc, expiresUtc } (default validity 24h). The next run of that provider applies the plan only
      if its hash is still exactly this one, then clears the approval.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][string]$PlanHash, [Parameter(Mandatory)][string]$By, [ValidateRange(1, 168)][int]$ValidHours = 24, [datetime]$NowUtc = [datetime]::UtcNow)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    $fn = $spec.ApproveFn
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw "${fn}: no SQL settings store (Set-PimSetting) -- an approval is a SQL record, never a file." }
    $h = "$PlanHash".Trim().ToLowerInvariant()
    if ($h -notmatch '^[0-9a-f]{64}$') { throw "${fn}: REFUSED -- '$PlanHash' is not a plan hash (64 hex characters)." }
    if (-not "$By".Trim()) { throw "${fn}: REFUSED -- -By (the approver) is required." }
    $hold = Get-PimPolicyMassHold -Provider $spec.Provider
    if (-not $hold) { throw "${fn}: REFUSED -- there is no current $($spec.Code) to approve." }
    if ("$($hold.planHash)".Trim().ToLowerInvariant() -ne $h) {
        throw "${fn}: REFUSED -- plan hash $h does not match the recorded hold ($($hold.planHash)). An approval never covers a different change set."
    }
    $now = $NowUtc.ToUniversalTime()
    # weakeningKeys: exactly which weakening changes the approver saw -- a later plan is covered while it adds none (Test-PimPolicyBreaker).
    $rec = [ordered]@{ planHash = $h; approvedBy = "$By".Trim(); approvedUtc = $now.ToString('o'); expiresUtc = $now.AddHours($ValidHours).ToString('o'); changes = [int]$hold.changes; weakening = [int]$hold.weakening
                       weakeningKeys = @(@($hold.weakenings) | Where-Object { $null -ne $_ } | ForEach-Object { Get-PimPolicyWeakeningKey -Entry $_ } | Select-Object -Unique) }
    Set-PimSetting -Name "$($spec.Prefix)MassChangeApproval" -Value (ConvertTo-Json -InputObject $rec -Compress)
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { Write-PimAuditEvent -Action "$($spec.Audit).approved" -Target $spec.Provider -After $rec | Out-Null }
    } catch { Write-Warning "  $($spec.Provider): the approval was recorded but NOT written to the audit trail: $($_.Exception.Message)" }
    [pscustomobject]$rec
}

function Write-PimPolicyMassHoldAlert {
    # Loud, best-effort -- same pattern as Write-PimDisableAbortAlert. NEVER throws: an alert failure must
    # not turn the hold (the safe outcome) into something else.
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Hold, [Parameter(Mandatory)][string]$Message,
          # One mail per hold, not per run (Set-PimPolicyHoldMailState): $false = this hold was already mailed and has not
          # grown weaker since -- log and audit, but no new mail (and the job's own "held" alert skips it too).
          [bool]$MailDue = $true)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    Write-Host ("[engine] {0}: mass-change circuit breaker HELD [{1}] -- N={2} T={3} W={4} planHash={5}. Wrote NOTHING this run." -f $spec.Provider, (@($Hold.tripped) -join ', '), $Hold.changes, $Hold.checked, $Hold.weakening, $Hold.planHash) -ForegroundColor Red
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action "$($spec.Audit).held" -Target $spec.Provider -After @{ planHash = $Hold.planHash; changes = $Hold.changes; checked = $Hold.checked; weakening = $Hold.weakening; tripped = @($Hold.tripped) } | Out-Null
        }
    } catch { Write-Warning "  [engine] $($spec.Provider): the mass-change hold was NOT written to the audit trail: $($_.Exception.Message)" }
    # 🔴 BUG-184 (§33.28): this sent Type 'alert' -- a template that does not exist -- with tokens the real
    # template does not use, and discarded the result, so the HOLD was never mailed and nothing said so.
    # Send-PimSafetyAlert (PIM-DisableGuard.ps1) uses 'alert-notice', READS the result, and reports a
    # failed or impossible send loudly. A runtime without it says so rather than pretending.
    if (-not $MailDue) {
        if (-not ($global:PimPolicyHoldAlerted -is [hashtable])) { $global:PimPolicyHoldAlerted = @{} }
        $global:PimPolicyHoldAlerted["$($Hold.planHash)".ToLowerInvariant()] = [datetime]::UtcNow
        Write-Host ("  [engine] {0}: this hold was already mailed at {1} and is not weaker than then -- no new mail (one mail per hold; the Approvals page shows the current change set)" -f $spec.Provider, "$($Hold.alertedUtc)") -ForegroundColor DarkGray
        return
    }
    try {
        if (Get-Command Send-PimSafetyAlert -ErrorAction SilentlyContinue) {
            # 2026-09-21 (operator: "this email is impossible to read" / "needs more details, which policies and what is
            # the change"): the mail carries the WhatIf -- which policies, each setting current -> new -- and what to
            # do, HTML-safe. The technical message stays in the job log. Falls back to the encoded message.
            $mail = $null
            if (Get-Command Format-PimPolicyHoldMail -ErrorAction SilentlyContinue) { try { $mail = Format-PimPolicyHoldMail -Hold $Hold -Provider $spec.Provider } catch { $mail = $null } }
            if ($mail) {
                # §79.14 (operator 2026-09-25): "i need this email to include a detailed excel file with all changes, policy
                # change (before, new) - i need to be able to get approval from their CAB / change board". Every policy x
                # setting, current -> new, in a workbook the change board can sort and sign. Best effort: a workbook that
                # cannot be built, or is over the ~3 MB a Graph sendMail can carry, never stops the alert itself.
                $att = @(); $attNote = ''
                if (Get-Command New-PimPolicyHoldWorkbook -ErrorAction SilentlyContinue) {
                    try {
                        $xb = New-PimPolicyHoldWorkbook -Hold $Hold -Provider $spec.Provider
                        $fn = "PIM-policy-change-{0}-{1}-{2}.xlsx" -f $spec.Provider, "$($Hold.planHash)".Substring(0, [Math]::Min(8, "$($Hold.planHash)".Length)), [datetime]::UtcNow.ToString('yyyyMMdd')
                        if ($xb.Length -le 3MB) { $att = @(@{ name = $fn; contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'; bytes = $xb }) }
                        else { $attNote = " The full change list ($([math]::Round($xb.Length / 1MB, 1)) MB) is too large to attach -- download it from Approvals." }
                    } catch { $attNote = ''; Write-Warning "  [engine] $($spec.Provider): the CAB workbook could not be built: $($_.Exception.Message)" }
                }
                $actionHtml = "$($mail.actionHtml)" + $(if ($att.Count) { ' <b>Attached:</b> the complete change list for your change board (every policy and setting, current &rarr; new).' } else { $attNote })
                [void](Send-PimSafetyAlert -Title "$($mail.subject)" -Headline "$($mail.headline)" -Detail "$($mail.detailHtml)" -Action $actionHtml -SwallowScope 'policy-mass-hold-alert-mail' -Tab 'jobs' -Attachments $att)
                # The job that ran this will raise its own "held" alert; it skips a plan mailed here (one mail per hold).
                if (-not ($global:PimPolicyHoldAlerted -is [hashtable])) { $global:PimPolicyHoldAlerted = @{} }
                $global:PimPolicyHoldAlerted["$($Hold.planHash)".ToLowerInvariant()] = [datetime]::UtcNow
            } else {
                [void](Send-PimSafetyAlert -Title "$($spec.MailSubject)" -Detail ([System.Net.WebUtility]::HtmlEncode($Message)) -SwallowScope 'policy-mass-hold-alert-mail' -Tab 'jobs')
            }
        } else {
            Write-Warning "  [engine] $($spec.Provider): the mass-change hold alert was NOT emailed -- the safety-alert sender (PIM-DisableGuard.ps1) is not loaded in this runtime."
        }
    } catch { Write-Warning "  [engine] $($spec.Provider): the mass-change hold alert mail was NOT sent: $($_.Exception.Message)" }
}

function Get-PimAzResPolicyBreakerThresholds {
    <#
      The breaker thresholds: code defaults (MaxChanges 25, MaxPercent 25, MaxWeakening 3), each key
      overridable from SQL -- pim.Settings 'AzResPolicyBreaker' = {"MaxChanges":n,"MaxPercent":n,"MaxWeakening":n}.
      An unreadable or malformed setting falls back to the defaults, and says so.
    #>
    [CmdletBinding()] param()
    Get-PimPolicyBreakerThresholds -Provider 'AzResPolicies'
}

function Get-PimAzResPolicyMassChangeApproval {
    # The recorded approval (pim.Settings 'AzResPolicyMassChangeApproval') or $null.
    Get-PimPolicyMassChangeApproval -Provider 'AzResPolicies'
}

function Test-PimAzResPolicyBreaker {
    # AzResPolicies' decision (thresholds default to pim.Settings 'AzResPolicyBreaker'). See Test-PimPolicyBreaker.
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan, [object]$Thresholds = $null, [object]$Approval = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Thresholds) { $Thresholds = Get-PimAzResPolicyBreakerThresholds }
    Test-PimPolicyBreaker -Plan $Plan -Thresholds $Thresholds -Approval $Approval -NowUtc $NowUtc
}

function Test-PimPolicyBreaker {
    <#
      PURE. The mass-change circuit breaker -- same decision shape as Test-PimDisablePassAllowed:
        { allowed; abort (= hold); tripped; reason; ... }
      Trips when N > MaxChanges, OR (T >= 8 and N/T > MaxPercent %), OR W > MaxWeakening. A trip is a
      HOLD (write nothing) unless an UNEXPIRED approval carries EXACTLY this plan's hash.
      -Provider only selects the default thresholds when -Thresholds is not given.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Plan, [object]$Thresholds = $null, [object]$Approval = $null, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Provider = 'AzResPolicies')
    if (-not $Thresholds) { $Thresholds = Get-PimPolicyBreakerThresholds -Provider $Provider }
    # 2026-09-21 (operator: "it still shows pending approvals of policies, but i have approved long ago"): 21 imported groups
    # = 42 new policies still at Entra's defaults held the whole set at the 25 cap. A policy NOBODY ever changed has no
    # setting to protect; its first template application is shown in the WhatIf but never counts toward the caps.
    $first = @(@($Plan.policies) | Where-Object { $null -ne $_ -and $_.PSObject.Properties['neverModified'] -and $_.neverModified }).Count
    $n = [Math]::Max(0, [int]$Plan.changes - $first); $t = [Math]::Max(0, [int]$Plan.checked - $first); $w = [int]$Plan.weakening
    $tripped = New-Object System.Collections.Generic.List[string]
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($n -gt [int]$Thresholds.MaxChanges) { $tripped.Add('max-changes'); $reasons.Add("would change $n policies (> cap $($Thresholds.MaxChanges))") }
    if ($t -ge [int]$Thresholds.MinCheckedForPercent -and $t -gt 0) {
        $pct = 100.0 * $n / $t
        if ($pct -gt [double]$Thresholds.MaxPercent) { $tripped.Add('max-percent'); $reasons.Add(("would change {0} of {1} checked policies ({2:N1}% > cap {3}%)" -f $n, $t, $pct, $Thresholds.MaxPercent)) }
    }
    if ($w -gt [int]$Thresholds.MaxWeakening) { $tripped.Add('max-weakening'); $reasons.Add("$w weakening change(s) (> cap $($Thresholds.MaxWeakening))") }
    $base = @{ changes = $n; checked = $t; weakening = $w; planHash = "$($Plan.planHash)"; thresholds = $Thresholds; tripped = $tripped.ToArray() }
    if (-not $tripped.Count) {
        return [pscustomobject](@{ allowed = $true; abort = $false; hold = $false; approved = $false; approvedBy = ''; reason = 'within the mass-change thresholds'; approvalNote = '' } + $base)
    }
    $why = "circuit breaker: " + ($reasons -join '; ')
    $note = 'no approval recorded'
    if ($Approval) {
        $exp = ConvertTo-PimAzResUtc $Approval.expiresUtc
        $sameHash = ("$($Approval.planHash)".Trim().ToLowerInvariant() -eq "$($Plan.planHash)".ToLowerInvariant())
        # 2026-09-21 (operator: "why is it that you cannot show me all changes and i can approve all in one go"): an approval
        # STICKS. It used to cover only the exact plan hash, so one new group between the click and the next run made it
        # void and the change was held again -- all day. Now it also covers a DIFFERENT plan as long as that plan adds no
        # WEAKENING the approver did not see: every weakening in it must be one the approval recorded (policy + rule +
        # change). Template alignment of further policies (a new group getting its template) is what the approver already
        # accepted. A weakening nobody approved -- a policy someone set by hand being loosened -- still holds.
        $newWeak = @()
        if (-not $sameHash) {
            $okKeys = @{}
            foreach ($k in @($(if ($Approval.PSObject.Properties['weakeningKeys']) { $Approval.weakeningKeys } else { @() }))) { $okKeys["$k".ToLowerInvariant()] = $true }
            $newWeak = @(@($Plan.weakenings) | Where-Object { $null -ne $_ } | Where-Object { -not $okKeys.ContainsKey((Get-PimPolicyWeakeningKey -Entry $_)) })
        }
        if (-not $exp -or $exp -le $NowUtc.ToUniversalTime()) { $note = "the approval EXPIRED ($($Approval.expiresUtc))" }
        elseif (-not $sameHash -and -not ($Approval.PSObject.Properties['weakeningKeys'])) { $note = "the recorded approval is for a DIFFERENT plan ($($Approval.planHash)) and predates approvals that carry over -- approve again" }
        elseif ($newWeak.Count) { $note = "the approval does not cover $($newWeak.Count) NEW weakening change(s) that appeared since it was given -- approve again after reviewing them" }
        else {
            $how = if ($sameHash) { 'this exact change set' } else { 'an earlier change set; this run adds no weakening it did not approve' }
            return [pscustomobject](@{ allowed = $true; abort = $false; hold = $false; approved = $true; approvedBy = "$($Approval.approvedBy)"; reason = "$why -- APPROVED by $($Approval.approvedBy) ($how) until $($Approval.expiresUtc)"; approvalNote = 'approved' } + $base)
        }
    }
    [pscustomobject](@{ allowed = $false; abort = $true; hold = $true; approved = $false; approvedBy = ''; reason = $why; approvalNote = $note } + $base)
}

function New-PimAzResPolicyMassHold {
    # PURE: the hold record (what the GUI shows and what an approval must match).
    param([Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][object]$Decision, [datetime]$NowUtc = [datetime]::UtcNow)
    $top = @($Plan.policies | Sort-Object @{ e = { @($_.rules).Count }; Descending = $true }, @{ e = { "$($_.key)" } } | Select-Object -First 10)
    [pscustomobject]@{
        code = 'AZ-POLICY-MASS-HOLD'; planHash = "$($Plan.planHash)"; heldUtc = $NowUtc.ToUniversalTime().ToString('o')
        changes = [int]$Plan.changes; checked = [int]$Plan.checked; weakening = [int]$Plan.weakening; ruleChanges = [int]$Plan.ruleChanges
        tripped = @($Decision.tripped); reason = "$($Decision.reason)"; approvalNote = "$($Decision.approvalNote)"
        thresholds = [pscustomobject]@{ MaxChanges = $Decision.thresholds.MaxChanges; MaxPercent = $Decision.thresholds.MaxPercent; MaxWeakening = $Decision.thresholds.MaxWeakening; MinCheckedForPercent = $Decision.thresholds.MinCheckedForPercent; source = $Decision.thresholds.source }
        policies = @($top | ForEach-Object { [pscustomobject]@{ scope = $_.scope; role = $_.role; policyId = $_.policyId; template = $_.template; rules = @($_.rules | ForEach-Object { [pscustomobject]@{ ruleId = $_.ruleId; live = $_.live; target = $_.target } }) } })
        morePolicies = [Math]::Max(0, [int]$Plan.changes - @($top).Count)
        weakenings = @($Plan.weakenings)
        adminPathAligned = @($Plan.adminPathAligned)
        notificationDefaultsAligned = @($Plan.notificationDefaultsAligned)
        impact = $(Get-PimPolicyImpactReportSafe -Plan $Plan)   # REQ-WHATIF 77.1: current -> new, grouped
        approveWith = "Approve-PimAzResPolicyMassChange -PlanHash $($Plan.planHash) -By <upn>"
        approvalValidHours = $script:PimAzResPolicyApprovalValidHours
    }
}

function Format-PimAzResPolicyMassHoldMessage {
    param([Parameter(Mandatory)][object]$Hold)
    $pol = @($Hold.policies | ForEach-Object { "$($_.role) @ $($_.scope) (" + (@($_.rules | ForEach-Object { $_.ruleId }) -join ', ') + ')' })
    $wk = @($Hold.weakenings | ForEach-Object { "$($_.role) @ $($_.scope) $($_.ruleId): $($_.change)" })
    $imp = if ($Hold.PSObject.Properties['impact']) { $Hold.impact } else { $null }
    ((Get-PimPolicyHoldLead -Noun 'Azure role policy' -Impact $imp -Changes ([int]$Hold.changes)) + ' ' +
     "AzResPolicies [AZ-POLICY-MASS-HOLD]: HELD by the mass-change circuit breaker [" + (@($Hold.tripped) -join ', ') + "] -- $($Hold.reason). " +
     "Wrote NOTHING this run. N=$($Hold.changes) policies to change, T=$($Hold.checked) checked, W=$($Hold.weakening) weakening. planHash=$($Hold.planHash). " +
     "Policies: " + ($pol -join '; ') + $(if ($Hold.morePolicies) { "; and $($Hold.morePolicies) more" } else { '' }) + ". " +
     "Weakening changes: " + $(if ($wk.Count) { $wk -join '; ' } else { 'none' }) + ". " +
     "Admin-path enablement aligned to template (engine requirement: its identity cannot present MFA; counted in N, not W): $(@($Hold.adminPathAligned).Count). Notification defaults aligned to template (counted in N, not W): $(@($Hold.notificationDefaultsAligned).Count). " +
     "Approval: $($Hold.approvalNote). Review the plan, then approve exactly this plan hash (Approve-PimAzResPolicyMassChange, valid $($Hold.approvalValidHours)h); " +
     "the next run applies it. If the plan changes first, the hash changes and the run holds again.")
}

function Write-PimAzResPolicyMassHoldAlert {
    # Loud, best-effort -- same pattern as Write-PimDisableAbortAlert. NEVER throws: an alert failure must
    # not turn the hold (the safe outcome) into something else.
    param([Parameter(Mandatory)][object]$Hold, [Parameter(Mandatory)][string]$Message, [bool]$MailDue = $true)
    Write-PimPolicyMassHoldAlert -Provider 'AzResPolicies' -Hold $Hold -Message $Message -MailDue:$MailDue
}

function Get-PimAzResPolicyMassHold {
    <#
      The CURRENT hold for a UI, or $null. The record lives in pim.Settings 'AzResPolicyMassHold'; it is
      current only while the failing set (pim.Settings 'EngineItemFailures') still carries its
      AZ-POLICY-MASS-HOLD item -- a later run that did not hold drops that item, so a stale record is
      never offered for approval.
    #>
    [CmdletBinding()] param()
    Get-PimPolicyMassHold -Provider 'AzResPolicies'
}

function Approve-PimAzResPolicyMassChange {
    <#
      Approve ONE held plan. Refused unless -PlanHash equals the CURRENT recorded hold's hash. Writes the
      SQL record pim.Settings 'AzResPolicyMassChangeApproval' = { planHash, approvedBy, approvedUtc,
      expiresUtc } (default validity 24h). The next run applies the plan only if its hash is still
      exactly this one, then clears the approval.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PlanHash, [Parameter(Mandatory)][string]$By, [ValidateRange(1, 168)][int]$ValidHours = 24, [datetime]$NowUtc = [datetime]::UtcNow)
    Approve-PimPolicyMassChange -Provider 'AzResPolicies' -PlanHash $PlanHash -By $By -ValidHours $ValidHours -NowUtc $NowUtc
}

# ---- the GRAPH policy providers (GroupsPolicies, EntraRolePolicies) on the same breaker ----------------

function Get-PimPolicyPlanHash {
    # PURE: SHA-256 (lowercase hex) over the ordinally sorted plan lines joined with LF.
    param([string[]]$Lines)
    $sorted = @($Lines); [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($sorted -join "`n"))) } finally { $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

function Get-PimGraphPolicyDesiredRuleBodies {
    # PURE: rule id -> the body the provider would send for a desired Graph policy item (no approval).
    param([Parameter(Mandatory)][object]$Desired)
    $b = @{}
    $legacy = if ($Desired.PSObject.Properties['EnablementLegacy']) { $Desired.EnablementLegacy } else { $null }
    foreach ($x in @(ConvertTo-PimEnablementRuleBodies -Enablement $Desired.Enablement -LegacyEndUserAssignment $legacy)) { if ($x) { $b["$($x.id)"] = $x } }
    foreach ($x in @(ConvertTo-PimExpirationRuleBodies -Expiration $Desired.Expiration)) { if ($x) { $b["$($x.id)"] = $x } }
    foreach ($n in @($Desired.Notification)) { if ($null -eq $n) { continue }; $x = ConvertTo-PimNotificationRuleBody -Entry $n; if ($x) { $b["$($x.id)"] = $x } }
    $b
}

function Test-PimGraphPolicyNeverModified {
    <#
      PURE. $true only when the policy object CARRIES lastModifiedDateTime and it is empty -- i.e. Microsoft's
      default policy that nobody (no person, not the engine) has ever changed. Measured on internal 2026-09-13:
      the brand-new PIM-ROLE-test1 policies read lastModifiedDateTime='' / lastModifiedBy {id:null}, while every
      policy the engine has written reads e.g. '2026-09-13T09:21:08Z' by ca-pim-tick. An object without the
      property (a trimmed $select) is NOT assumed pristine.
    #>
    param([AllowNull()][object]$Policy)
    if ($null -eq $Policy) { return $false }
    $p = $Policy.PSObject.Properties['lastModifiedDateTime']
    if (-not $p) { return $false }
    return (-not "$($p.Value)".Trim())
}

function Get-PimGraphPolicyChangePlan {
    <#
      PURE. PLAN FIRST for a GRAPH policy provider (GroupsPolicies / EntraRolePolicies): the same shape
      Get-PimAzResPolicyChangePlan returns, from the same facet compare the provider's Equal uses.
        checked (T)   = desired policies with a live policy read
        changes (N)   = policies whose facets drift (the ones ApplyUpdate would PATCH)
        weakening (W) = rule changes that weaken a policy: Get-PimAzResPolicyWeakening's rules (MFA /
                        Justification / Ticketing removed, a longer maximum duration, expiration no longer
                        required, a named notification recipient removed) plus APPROVAL TURNED OFF.
                        Admin-path enablement alignment and notification-default alignment count in N, not W.
        planHash      = SHA-256 over "<policyId lowercase>|<ruleId>|<target facet>" -- the exact change set.
      -Label names a policy for a human (group name + member/owner, or the role name).
    #>
    param([object[]]$Desired, [object[]]$Live, [Parameter(Mandatory)][scriptblock]$KeyOf, [scriptblock]$Label)
    $liveByKey = @{}; foreach ($x in @($Live)) { if ($x) { $liveByKey["$(& $KeyOf $x)".ToLowerInvariant()] = $x } }
    $policies = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $weak = New-Object System.Collections.Generic.List[object]
    $adminAligned = New-Object System.Collections.Generic.List[object]
    $notifyAligned = New-Object System.Collections.Generic.List[object]
    $defaultAligned = New-Object System.Collections.Generic.List[object]
    $checked = 0
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        # BUG-185: a row the ACTIVE emergency override switched to approval-off is an AUTHORISED change
        # (SuperAdmin + passcode, time-boxed, audited). It is left out of the breaker plan -- a HOLD here
        # would make break-glass do nothing at the moment it is needed. Such an item is "not in the plan",
        # so Invoke-PimGraphPolicyGuardedApply applies it directly.
        if ($d.PSObject.Properties['EmergencyOverride'] -and $d.EmergencyOverride) { continue }
        $key = "$(& $KeyOf $d)".ToLowerInvariant()
        $l = $liveByKey[$key]
        if (-not $l) { continue }
        $checked++
        $want = Get-PimGroupPolicyDesiredFacets -Desired $d
        $have = Get-PimGroupPolicyLiveFacets -Rules @($l.Rules)
        $name = if ($Label) { "$(& $Label $d)" } else { $key }
        $role = if ($d.PSObject.Properties['PolicyRole'] -and "$($d.PolicyRole)") { "$($d.PolicyRole)" } else { '' }
        $liveById = @{}; foreach ($r in @($l.Rules)) { if ($r -and "$($r.id)") { $liveById["$($r.id)"] = $r } }
        $bodies = $null
        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($rid in @($want.Keys | Sort-Object)) {
            # the SAME exemption Test-PimGroupPolicyInSync makes: no approval rule already means "approval off"
            if (-not $have.ContainsKey($rid)) {
                if ($rid -eq 'Approval_EndUser_Assignment' -and "$($want[$rid])" -eq 'appr|required=false|approvers=') { continue }
            } elseif ("$($have[$rid])" -eq "$($want[$rid])") { continue }
            $w = @()
            if ($rid -eq 'Approval_EndUser_Assignment') {
                if ("$($have[$rid])" -like 'appr|required=true*' -and "$($want[$rid])" -like 'appr|required=false*') { $w = @('turns approval off') }
            } else {
                if ($null -eq $bodies) { $bodies = Get-PimGraphPolicyDesiredRuleBodies -Desired $d }
                if ($bodies.ContainsKey($rid)) {
                    $lr = if ($liveById.ContainsKey($rid)) { $liveById[$rid] } else { [pscustomobject]@{ id = $rid } }
                    $w = @(Get-PimAzResPolicyWeakening -LiveRule $lr -DesiredBody $bodies[$rid])
                }
            }
            foreach ($s in $w) {
                $entry = [pscustomobject]@{ name = $name; role = $role; policyId = "$($l.PolicyId)"; ruleId = $rid; change = $s }
                if ($rid -in @('Enablement_Admin_Assignment','Enablement_Admin_Eligibility') -and $s -match '^removes (MultiFactorAuthentication|Justification)$') { $adminAligned.Add($entry) }
                elseif ($rid -like 'Notification_*' -and $s -eq 'turns default recipients off') { $notifyAligned.Add($entry) }
                # 🔴 §70.19 (2026-09-13, internal): the operator's two new delegations were HELD -- each new group's
                # member+owner policy is Microsoft's untouched default (P180D, owner expiration required), the
                # template says P365D / not required, so 2 new groups = 6 "weakening" changes > cap 3, and a new
                # delegation never got its activation policy. The breaker exists to stop a wrong template from
                # rewriting policies someone SET; the first template application to a never-modified default policy
                # is the baseline being established, not a weakening. Counted in N (the change caps still apply).
                elseif ($l.PSObject.Properties['NeverModified'] -and $l.NeverModified) { $defaultAligned.Add($entry) }
                else { $weak.Add($entry) }
            }
            $rules.Add([pscustomobject]@{ ruleId = $rid; live = $(if ($have.ContainsKey($rid)) { "$($have[$rid])" } else { '(absent)' }); target = "$($want[$rid])"; weakening = @($w) })
            $lines.Add(("{0}|{1}|{2}" -f "$($l.PolicyId)".ToLowerInvariant(), $rid, "$($want[$rid])"))
        }
        if ($rules.Count) { $policies.Add([pscustomobject]@{ key = $key; name = $name; role = $role; policyId = "$($l.PolicyId)"; template = "$($d.TemplateId)"; rules = $rules.ToArray()
                                                             neverModified = [bool]($l.PSObject.Properties['NeverModified'] -and $l.NeverModified) }) }
    }
    $byKey = @{}; foreach ($p in $policies) { $byKey[$p.key] = $p }
    [pscustomobject]@{ planHash = (Get-PimPolicyPlanHash -Lines $lines.ToArray()); checked = $checked; changes = $policies.Count; weakening = $weak.Count; ruleChanges = $lines.Count
                       policies = $policies.ToArray(); weakenings = $weak.ToArray(); byKey = $byKey
                       adminPathAligned = $adminAligned.ToArray(); notificationDefaultsAligned = $notifyAligned.ToArray()
                       defaultPolicyAligned = $defaultAligned.ToArray() }
}

function New-PimGraphPolicyMassHold {
    # PURE: the hold record of a GRAPH policy provider (what the GUI shows and what an approval must match).
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][object]$Decision, [datetime]$NowUtc = [datetime]::UtcNow)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    $top = @($Plan.policies | Sort-Object @{ e = { @($_.rules).Count }; Descending = $true }, @{ e = { "$($_.key)" } } | Select-Object -First 10)
    [pscustomobject]@{
        code = $spec.Code; provider = $spec.Provider; planHash = "$($Plan.planHash)"; heldUtc = $NowUtc.ToUniversalTime().ToString('o')
        changes = [int]$Plan.changes; checked = [int]$Plan.checked; weakening = [int]$Plan.weakening; ruleChanges = [int]$Plan.ruleChanges
        tripped = @($Decision.tripped); reason = "$($Decision.reason)"; approvalNote = "$($Decision.approvalNote)"
        thresholds = [pscustomobject]@{ MaxChanges = $Decision.thresholds.MaxChanges; MaxPercent = $Decision.thresholds.MaxPercent; MaxWeakening = $Decision.thresholds.MaxWeakening; MinCheckedForPercent = $Decision.thresholds.MinCheckedForPercent; source = $Decision.thresholds.source }
        policies = @($top | ForEach-Object { [pscustomobject]@{ name = $_.name; role = $_.role; policyId = $_.policyId; template = $_.template; rules = @($_.rules | ForEach-Object { [pscustomobject]@{ ruleId = $_.ruleId; live = $_.live; target = $_.target } }) } })
        morePolicies = [Math]::Max(0, [int]$Plan.changes - @($top).Count)
        weakenings = @($Plan.weakenings)
        adminPathAligned = @($Plan.adminPathAligned)
        notificationDefaultsAligned = @($Plan.notificationDefaultsAligned)
        defaultPolicyAligned = @($(if ($Plan.PSObject.Properties['defaultPolicyAligned']) { $Plan.defaultPolicyAligned } else { @() }))
        impact = $(Get-PimPolicyImpactReportSafe -Plan $Plan)   # REQ-WHATIF 77.1: current -> new, grouped
        approveWith = "Approve-PimPolicyMassChange -Provider $($spec.Provider) -PlanHash $($Plan.planHash) -By <upn>"
        approvalValidHours = $script:PimAzResPolicyApprovalValidHours
    }
}

function Format-PimGraphPolicyMassHoldMessage {
    param([Parameter(Mandatory)][object]$Hold)
    $spec = Get-PimPolicyBreakerSpec -Provider "$($Hold.provider)"
    $pol = @($Hold.policies | ForEach-Object { "$($_.name) (" + (@($_.rules | ForEach-Object { $_.ruleId }) -join ', ') + ')' })
    $wk = @($Hold.weakenings | ForEach-Object { "$($_.name) $($_.ruleId): $($_.change)" })
    $imp = if ($Hold.PSObject.Properties['impact']) { $Hold.impact } else { $null }
    ((Get-PimPolicyHoldLead -Noun $(if ($spec.Provider -eq 'GroupsPolicies') { 'PIM for Groups policy' } else { 'Entra role policy' }) -Impact $imp -Changes ([int]$Hold.changes)) + ' ' +
     "$($spec.Provider) [$($spec.Code)]: HELD by the mass-change circuit breaker [" + (@($Hold.tripped) -join ', ') + "] -- $($Hold.reason). " +
     "Wrote NOTHING this run. N=$($Hold.changes) policies to change, T=$($Hold.checked) checked, W=$($Hold.weakening) weakening. planHash=$($Hold.planHash). " +
     "Policies: " + ($pol -join '; ') + $(if ($Hold.morePolicies) { "; and $($Hold.morePolicies) more" } else { '' }) + ". " +
     "Weakening changes: " + $(if ($wk.Count) { $wk -join '; ' } else { 'none' }) + ". " +
     "Admin-path enablement aligned to template (engine requirement: its identity cannot present MFA; counted in N, not W): $(@($Hold.adminPathAligned).Count). Notification defaults aligned to template (counted in N, not W): $(@($Hold.notificationDefaultsAligned).Count). " +
     "First template application to never-modified default policies (counted in N, not W): $(@($(if ($Hold.PSObject.Properties['defaultPolicyAligned']) { $Hold.defaultPolicyAligned } else { @() })).Count). " +
     "Approval: $($Hold.approvalNote). Review the plan, then approve exactly this plan hash (Approve-PimPolicyMassChange -Provider $($spec.Provider), valid $($Hold.approvalValidHours)h); " +
     "the next run applies it. If the plan changes first, the hash changes and the run holds again.")
}

function Set-PimGraphPolicyBreakerPlan {
    <#
      Called at the end of a Graph policy provider's GetLive: PLAN FIRST -- the whole change set and the
      breaker decision exist before any ApplyUpdate runs (context keys '<provider>.plan' / '<provider>.breaker').
    #>
    param([Parameter(Mandatory)][string]$Provider, [hashtable]$Context, [object[]]$Desired, [object[]]$Live, [Parameter(Mandatory)][scriptblock]$KeyOf, [scriptblock]$Label)
    if ($null -eq $Context) { return }
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    $plan = Get-PimGraphPolicyChangePlan -Desired $Desired -Live $Live -KeyOf $KeyOf -Label $Label
    $dec = Test-PimPolicyBreaker -Plan $plan -Approval (Get-PimPolicyMassChangeApproval -Provider $spec.Provider) -Provider $spec.Provider
    $Context["$($spec.Provider).plan"] = $plan; $Context["$($spec.Provider).breaker"] = $dec
    $Context["$($spec.Provider).breakerState"] = @{ holdRecorded = $false; visited = @{}; approvalCleared = $false }
    $color = if ($dec.hold) { 'Red' } elseif ($dec.approved) { 'Yellow' } else { 'DarkCyan' }
    Write-Host ("    [breaker] {0}: N={1} change(s) of T={2} checked, W={3} weakening, planHash={4} -- {5}{6}" -f `
        $spec.Provider, $plan.changes, $plan.checked, $plan.weakening, $plan.planHash, $(if ($dec.hold) { 'HOLD: ' } elseif ($dec.approved) { 'APPROVED: ' } else { 'apply: ' }), $dec.reason) -ForegroundColor $color
    if (@($plan.notificationDefaultsAligned).Count) {
        Write-Host ("    [breaker] {0}: {1} notification default(s) aligned to template -- counted in N, not in W" -f $spec.Provider, @($plan.notificationDefaultsAligned).Count) -ForegroundColor DarkCyan
    }
    if (@($plan.adminPathAligned).Count) {
        Write-Host ("    [breaker] {0}: {1} admin-path enablement change(s) aligned to template -- counted in N, not in W" -f $spec.Provider, @($plan.adminPathAligned).Count) -ForegroundColor DarkCyan
    }
    if ($plan.PSObject.Properties['defaultPolicyAligned'] -and @($plan.defaultPolicyAligned).Count) {
        Write-Host ("    [breaker] {0}: {1} rule change(s) are the FIRST template application to never-modified default policies (new groups/roles) -- counted in N, not in W: {2}" -f $spec.Provider, @($plan.defaultPolicyAligned).Count, ((@($plan.defaultPolicyAligned) | ForEach-Object { $_.name } | Select-Object -Unique) -join ', ')) -ForegroundColor DarkCyan
    }
    if ($dec.hold -or ($Context["__pimWhatIf"] -and [int]$plan.changes -gt 0)) { Write-PimPolicyImpactLog -Provider $spec.Provider -Plan $plan }
}

function Invoke-PimGraphPolicyGuardedApply {
    <#
      ApplyUpdate gate for a GRAPH policy provider, the same contract Invoke-PimAzResPolicyUpdate has:
        * no plan/decision in the context -> the handler was called DIRECTLY for one item, not by
          Invoke-PimEngineScope (which always runs GetLive, and so the plan, first). One item is not a mass
          change, so it applies -- and says so. A scope run can never reach this branch;
        * HOLD and the item is in the plan -> the FIRST planned item records the hold (SQL), alerts and throws
          '<CODE>'; the rest are reported held; nothing is written;
        * otherwise the provider's own apply runs; after the last planned policy of an APPROVED run the
          approval is cleared.
      An item NOT in the plan (e.g. a create for a group whose policy could not be found) is unaffected.
    #>
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Item, [hashtable]$Context, [Parameter(Mandatory)][scriptblock]$Apply)
    $spec = Get-PimPolicyBreakerSpec -Provider $Provider
    if ($null -eq $Context) { $Context = @{} }
    $plan = $Context["$($spec.Provider).plan"]; $dec = $Context["$($spec.Provider).breaker"]
    if (-not $plan -or -not $dec) {
        Write-Verbose "$($spec.Provider): no breaker plan in the context (a direct single-item call, not a scope run) -- applying '$($Item.key)'"
        return (& $Apply $Item $Context)
    }
    if (-not $Context["$($spec.Provider).breakerState"]) { $Context["$($spec.Provider).breakerState"] = @{ holdRecorded = $false; visited = @{}; approvalCleared = $false } }
    $st = $Context["$($spec.Provider).breakerState"]
    $key = "$($Item.key)".Trim().ToLowerInvariant()
    $pp = if ($plan.byKey.ContainsKey($key)) { $plan.byKey[$key] } else { $null }
    if ($pp -and $dec.hold) {
        if (-not $st.holdRecorded) {
            $st.holdRecorded = $true
            $hold = New-PimGraphPolicyMassHold -Provider $spec.Provider -Plan $plan -Decision $dec
            $msg = Format-PimGraphPolicyMassHoldMessage -Hold $hold
            # One mail per hold, not per run: stamp the mail state carried from the hold still standing (Set-PimPolicyHoldMailState).
            $__prevHold = $null; try { $__prevHold = Get-PimPolicyMassHold -Provider $spec.Provider } catch { $__prevHold = $null }
            $__mailDue = $true; if (Get-Command Set-PimPolicyHoldMailState -ErrorAction SilentlyContinue) { $__mailDue = Set-PimPolicyHoldMailState -Previous $__prevHold -Hold $hold }
            if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
                try { Set-PimSetting -Name "$($spec.Prefix)MassHold" -Value (ConvertTo-Json -InputObject $hold -Depth 8 -Compress) }
                catch { Write-Warning "  [engine] $($spec.Provider): the hold record could NOT be saved (it cannot be approved until a run saves it): $($_.Exception.Message)" }
            }
            Write-PimPolicyMassHoldAlert -Provider $spec.Provider -Hold $hold -Message $msg -MailDue:$__mailDue
            throw $msg
        }
        return [pscustomobject]@{ pimApplied = $false; note = "held by the mass-change circuit breaker (planHash $($plan.planHash))" }
    }
    # §70.15 LOG-02: the audit of this policy change (Write-PimEngineChangeAudit, after the apply) records WHICH rules
    # changed from what to what -- the plan already computed it and used to discard it.
    if ($pp) {
        try {
            $Item | Add-Member -NotePropertyName pimAuditDetail -Force -NotePropertyValue ([ordered]@{
                policy = "$($pp.name)"; policyId = "$($pp.policyId)"; template = "$($pp.template)"; planHash = "$($plan.planHash)"
                approvedPlan = [bool]$dec.approved
                rules = @($pp.rules | ForEach-Object { [ordered]@{ ruleId = "$($_.ruleId)"; before = "$($_.live)"; after = "$($_.target)"; weakening = @($_.weakening) } })
            })
        } catch { }
    }
    try { & $Apply $Item $Context }
    finally {
        if ($pp) {
            $st.visited[$key] = $true
            if ($dec.approved -and -not $st.approvalCleared -and @($st.visited.Keys).Count -ge @($plan.policies).Count) {
                $st.approvalCleared = $true
                if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
                    try { Set-PimSetting -Name "$($spec.Prefix)MassChangeApproval" -Value ''; Write-Host "    [engine] $($spec.Provider): approved plan $($plan.planHash) applied -- approval cleared" -ForegroundColor Green }
                    catch { Write-Warning "  [engine] $($spec.Provider): the approval for plan $($plan.planHash) could NOT be cleared: $($_.Exception.Message)" }
                }
            }
        }
    }
}

function Write-PimAzResPolicyVerification {
    # Prints the verification for every pair (plan AND apply) and returns the verdicts.
    param([object[]]$Desired, [object[]]$Live)
    $byKey = @{}; foreach ($l in @($Live)) { if ($l) { $byKey[(Get-PimAzResPolicyKey -Row $l)] = $l } }
    $verdicts = @(foreach ($d in @($Desired)) { if ($d) { Get-PimAzResPolicyVerdict -Desired $d -Live $byKey[(Get-PimAzResPolicyKey -Row $d)] } })
    $count = { param($s) @($verdicts | Where-Object { $_.state -eq $s }).Count }
    Write-Host ("    [verify] AzResPolicies: {0} pair(s) -- matches={1} kept={2} differs={3} unreadable={4} no-policy={5} role-not-found={6}" -f `
        $verdicts.Count, (& $count 'matches'), (& $count 'kept'), (& $count 'differs'), (& $count 'unreadable'), (& $count 'no-policy'), (& $count 'role-not-found')) -ForegroundColor DarkCyan
    foreach ($v in $verdicts) {
        $label = "$($v.role) @ $($v.scope)"
        foreach ($n in @($v.notes)) { Write-Host ("    [verify] {0}: {1}" -f $label, $n) -ForegroundColor DarkYellow }
        if ($v.state -in @('matches','kept')) { continue }
        $dflt = if ($v.isDefaultPolicy) { ' [SYSTEM DEFAULT policy]' } else { '' }
        switch ($v.state) {
            'differs' {
                $parts = @($v.diffs | ForEach-Object { "$($_.ruleId) live[$($_.live)] target[$($_.target)]$(if ($_.blocked) { " (NOT written: $($_.blocked))" })" })
                Write-Host ("    [verify] {0}{1}: DIFFERS from '{2}' -- {3}" -f $label, $dflt, $v.template, ($parts -join '; ')) -ForegroundColor Yellow
                $adm = @(@($v.lowersSecurity) | Where-Object { $_ -like 'Enablement_Admin_*' })
                $act = @(@($v.lowersSecurity) | Where-Object { $_ -notlike 'Enablement_Admin_*' })
                if ($adm.Count) { Write-Host ("    [verify] {0}: admin-path enablement aligned to template (engine requirement: its identity cannot present MFA): MultiFactorAuthentication removed from {1}" -f $label, ($adm -join ', ')) -ForegroundColor DarkCyan }
                if ($act.Count) { Write-Host ("    [verify] {0}: applying the template REMOVES MultiFactorAuthentication from {1}" -f $label, ($act -join ', ')) -ForegroundColor Yellow }
                $nda = @(@($v.diffs) | Where-Object { $_.ruleId -like 'Notification_*' -and "$($_.live)" -match '\|def=True\|' -and "$($_.target)" -match '\|def=False\|' } | ForEach-Object { $_.ruleId })
                if ($nda.Count) { Write-Host ("    [verify] {0}: notification defaults aligned to template: {1}" -f $label, ($nda -join ', ')) -ForegroundColor DarkCyan }
            }
            default   { Write-Host ("    [verify] {0}: {1} -- {2}" -f $label, $v.state.ToUpperInvariant(), $v.error) -ForegroundColor Red }
        }
    }
    $verdicts
}

function Get-PimAzResPolicyConformance {
    <#
      READ-ONLY verification report: one verdict per (scope, role) -- matches / kept / differs (which rules,
      live vs target) / unreadable (the HTTP error) / no-policy / role-not-found, plus skippedRules (template
      rule ids not in effectiveRules).
      Uses the provider's own GetDesired + GetLive, so it reports exactly what a run would act on, and
      writes nothing.
    #>
    [CmdletBinding()]
    param([hashtable]$Context = @{})
    $p = New-PimAzResPoliciesProvider
    $d = @(& $p.GetDesired $Context)
    $l = @(& $p.GetLive $Context)
    if ($Context.ContainsKey('azResPolVerdicts')) { return @($Context['azResPolVerdicts']) }
    $byKey = @{}; foreach ($x in $l) { if ($x) { $byKey[(Get-PimAzResPolicyKey -Row $x)] = $x } }
    @(foreach ($x in $d) { Get-PimAzResPolicyVerdict -Desired $x -Live $byKey[(Get-PimAzResPolicyKey -Row $x)] })
}

function Invoke-PimAzResPolicyUpdate {
    <#
      ApplyUpdate for one (scope, role). In order, and each step refuses rather than guesses:
        1. a live state other than 'read' -> throw its real error; nothing written
        2. this run's breaker decision: HOLD -> the first planned policy throws AZ-POLICY-MASS-HOLD (and
           records the hold), the rest are reported held; nothing is written
        3. 3 consecutive policies whose every rule PATCH failed -> the rest of the run is deferred
        4. RE-READ the assignment's effectiveRules -> unreadable = throw, nothing written
        5. approval template without an approver -> AZ-POLICY-NO-APPROVER; nothing written
        6. ONE PATCH PER RULE (v1): each PLANNED rule that still differs goes in its own request
           { properties: { rules: [ <that rule> ] } }, target kept from the effective rule, with a write
           cooldown between requests. A refused rule is recorded with ARM's raw error and the others
           still go.
        7. pause, re-read effectiveRules, and fail unless every accepted rule now holds its target
        8. any refused rule -> throw AZ-POLICY-RULE-FAILED listing each rule id and its raw error
        9. a template demanding MFA on the admin path (BUG-21) -> throw, after the writable rules
      After the last planned policy of an APPROVED run, the approval is cleared.
    #>
    param([Parameter(Mandatory)][object]$Item, [hashtable]$Context = @{})
    if ($null -eq $Context) { $Context = @{} }
    $d = $Item.desired; $l = $Item.live
    $label = "$($d.RoleName) @ $($d.AzScope)"
    if (-not $Context['azResPol']) { $Context['azResPol'] = @{ failStreak = 0; holdRecorded = $false; visited = @{}; approvalCleared = $false } }
    $st = $Context['azResPol']

    if ($null -eq $l) { throw "AzResPolicies: no live read for $label -- nothing written" }
    switch ("$($l.State)") {
        'read'           { }
        'role-not-found' { throw "$($l.Error)" }
        'no-policy'      { throw "AzResPolicies: $($l.Error) -- nothing written." }
        default          { throw "AzResPolicies: policy for $label is UNREADABLE, so it was not verified and NOTHING was written: $($l.Error)" }
    }

    $plan = $Context['azResPolPlan']; $dec = $Context['azResPolBreaker']
    if (-not $plan -or -not $dec) { throw "AzResPolicies: no change plan was computed for this run, so NOTHING was written for $label" }
    $key = Get-PimAzResPolicyKey -Row $d
    $pp = if ($plan.byKey.ContainsKey($key)) { $plan.byKey[$key] } else { $null }

    if ($pp -and $dec.hold) {
        if (-not $st.holdRecorded) {
            $st.holdRecorded = $true
            $hold = New-PimAzResPolicyMassHold -Plan $plan -Decision $dec
            $msg = Format-PimAzResPolicyMassHoldMessage -Hold $hold
            $__prevHold = $null; try { $__prevHold = Get-PimPolicyMassHold -Provider 'AzResPolicies' } catch { $__prevHold = $null }
            $__mailDue = $true; if (Get-Command Set-PimPolicyHoldMailState -ErrorAction SilentlyContinue) { $__mailDue = Set-PimPolicyHoldMailState -Previous $__prevHold -Hold $hold }
            if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
                try { Set-PimSetting -Name 'AzResPolicyMassHold' -Value (ConvertTo-Json -InputObject $hold -Depth 8 -Compress) }
                catch { Write-Warning "  [engine] AzResPolicies: the hold record could NOT be saved (it cannot be approved until a run saves it): $($_.Exception.Message)" }
            }
            Write-PimAzResPolicyMassHoldAlert -Hold $hold -Message $msg -MailDue:$__mailDue
            throw $msg
        }
        return [pscustomobject]@{ pimApplied = $false; note = "held by the mass-change circuit breaker (planHash $($plan.planHash))" }
    }

    try {
        if ($pp -and [int]$st.failStreak -ge 3) {
            Write-Host ("    [engine] AzResPolicies: {0} consecutive policies failed every rule PATCH -- stopping writes for this run; {1} deferred" -f $st.failStreak, $label) -ForegroundColor Yellow
            return [pscustomobject]@{ pimApplied = $false; note = 'deferred: consecutive PATCH failures' }
        }

        $fresh = $null
        try { $fresh = Read-PimAzResPolicyAssignment -Scope "$($d.AzScope)" -RoleId "$($l.RoleId)" }
        catch { throw "AzResPolicies: policy for $label is UNREADABLE on re-read, so NOTHING was written: $($_.Exception.Message)" }
        if (-not $fresh) { throw "AzResPolicies: the policy assignment for $label disappeared before the write -- nothing written." }
        $l2 = $l.PSObject.Copy(); $l2.Rules = @($fresh.rules); $l2.PolicyId = $fresh.policyId
        $v = Get-PimAzResPolicyVerdict -Desired $d -Live $l2

        if ($v.state -in @('matches','kept')) { return [pscustomobject]@{ pimApplied = $false; note = "already $($v.state) on re-read" } }
        if (@($v.diffs | Where-Object { $_.blocked -eq 'no-approver' }).Count) {
            $where = if ("$($d.ApproverUpns)".Trim()) { 'the ApproverUpns on its assignment row resolve to no user' } else { "set Owners (or SponsorUpn, or the Department's owners) on the group definition(s) of GroupTag $((@($d.GroupTags) -join ', '))" }
            throw ("AzResPolicies [AZ-POLICY-NO-APPROVER]: template '$($d.TemplateId)' requires APPROVAL for $label but NO approver resolved, so NOTHING was written " +
                   "(a policy is never left half-configured). To fix: $where.")
        }

        $bodies = Get-PimAzResPolicyDesiredRuleBodies -Desired $d
        $liveById = @{}; foreach ($r in @($fresh.rules)) { $liveById["$($r.id)"] = $r }
        $planned = @{}; if ($pp) { foreach ($pr in @($pp.rules)) { $planned[$pr.ruleId] = $pr } }
        $todo = New-Object System.Collections.Generic.List[object]
        foreach ($df in @($v.diffs)) {
            if ($df.blocked) { continue }
            # Only what the PLAN (and therefore the breaker, and any approval) covered: a rule that started
            # to differ between the plan and this re-read waits for the next run's plan.
            if (-not $planned.ContainsKey($df.ruleId) -or "$($planned[$df.ruleId].target)" -ne "$($df.target)") { continue }
            if (-not $liveById.ContainsKey($df.ruleId) -or -not $bodies.ContainsKey($df.ruleId)) { continue }
            $todo.Add($df)
        }
        foreach ($rid in @($v.lowersSecurity)) {
            if (-not @($todo | Where-Object { $_.ruleId -eq $rid }).Count) { continue }
            Write-Warning ("  [engine] AzResPolicies: {0}: {1} -- REMOVING MultiFactorAuthentication (live has it, template '{2}' does not){3}" -f `
                $label, $rid, $d.TemplateId, $(if ($rid -like 'Enablement_Admin_*') { '. The engine''s own assignments are refused (MfaRule) while it is set.' } else { '' }))
        }

        $cool = 3
        if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $cool = Get-PimPolicySetting -Name 'AzResPolicyPatchCooldownSeconds' -Default 3 }
        $cs = 3; if (-not [int]::TryParse("$cool", [ref]$cs)) { $cs = 3 }
        $accepted = New-Object System.Collections.Generic.List[object]
        $refused = New-Object System.Collections.Generic.List[string]
        $n = 0
        foreach ($df in $todo) {
            if ($n -gt 0 -and $cs -gt 0) { Start-Sleep -Seconds $cs }   # v1 Wait-PimWriteCooldown between PATCHes
            $n++
            $body = $bodies[$df.ruleId]
            if ($df.ruleId -eq 'Approval_EndUser_Assignment') { $body = @{ id = $df.ruleId; setting = (New-PimAzResPolicyApprovalSetting -Approval $d.Approval -ApproverIds @($df.approverIds)) } }
            $one = New-PimAzResPolicyRulePatch -LiveRule $liveById[$df.ruleId] -DesiredBody $body
            try {
                # ONE rule per request -- never batch (a six-rule PATCH was rejected whole over one id).
                Invoke-PimArm -Method PATCH -Path $fresh.policyId -ApiVersion '2020-10-01' -Body @{ properties = @{ rules = @($one) } } | Out-Null
                $accepted.Add($df)
            } catch {
                $refused.Add(("{0}: {1}" -f $df.ruleId, "$($_.Exception.Message)"))
            }
        }
        if ($todo.Count) {
            if ($accepted.Count) { $st.failStreak = 0 } else { $st.failStreak = [int]$st.failStreak + 1 }
        }

        if ($accepted.Count) {
            $delay = 5
            if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $delay = Get-PimPolicySetting -Name 'AzResPolicyVerifyDelaySeconds' -Default 5 }
            $ds = 5; if (-not [int]::TryParse("$delay", [ref]$ds)) { $ds = 5 }
            if ($ds -gt 0) { Start-Sleep -Seconds $ds }
            $after = $null
            try { $after = Read-PimAzResPolicyAssignment -Scope "$($d.AzScope)" -RoleId "$($l.RoleId)" }
            catch { throw "AzResPolicies: $($accepted.Count) rule PATCH(es) on $label were accepted but the verification re-read of effectiveRules failed, so they are NOT counted as applied: $($_.Exception.Message)" }
            $have = if ($after) { Get-PimAzResPolicyLiveFacets -Rules @($after.rules) } else { @{} }
            foreach ($df in $accepted.ToArray()) {
                if ("$($have[$df.ruleId])" -ne "$($df.target)") { $refused.Add(("{0}: PATCH accepted but the re-read effectiveRules still show [{1}], not [{2}]" -f $df.ruleId, "$($have[$df.ruleId])", $df.target)) }
            }
        }
        $okIds = @($accepted | Where-Object { $id = $_.ruleId; -not @($refused | Where-Object { $_ -like "${id}:*" }).Count } | ForEach-Object { $_.ruleId })

        if ($refused.Count) {
            throw ("AzResPolicies [AZ-POLICY-RULE-FAILED]: $($refused.Count) of $($todo.Count) rule(s) on $label (policy $($fresh.policyId)$(if ($l.IsDefaultPolicy) { ', the system default policy' })) did not apply" +
                   $(if ($okIds.Count) { "; applied: $($okIds -join ', ')" } else { '' }) + '. Per rule, ARM said: ' + ($refused -join ' | '))
        }
        $mfa = @($v.diffs | Where-Object { $_.blocked -eq 'admin-mfa' })
        if ($mfa.Count) {
            $done = if ($okIds.Count) { "Patched $($okIds -join ', '); but " } else { 'Nothing written; ' }
            throw ("AzResPolicies: ${done}template '$($d.TemplateId)' asks for MultiFactorAuthentication on " + (@($mfa | ForEach-Object { $_.ruleId }) -join ', ') +
                   " for $label. Refused: the admin making those requests is the engine's own identity, which can never present MFA, so every engine assignment would be rejected.")
        }
        if (-not $todo.Count) { return [pscustomobject]@{ pimApplied = $false; note = 'nothing planned for this policy in this run' } }
        [pscustomobject]@{ scope = "$($d.AzScope)"; role = "$($d.RoleName)"; policyId = "$($fresh.policyId)"; template = "$($d.TemplateId)"; patched = $okIds; isDefaultPolicy = [bool]$l.IsDefaultPolicy; skipped = @($v.skippedRules) }
    }
    finally {
        if ($pp) {
            $st.visited[$key] = $true
            if ($dec.approved -and -not $st.approvalCleared -and @($st.visited.Keys).Count -ge @($plan.policies).Count) {
                $st.approvalCleared = $true
                if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
                    try { Set-PimSetting -Name 'AzResPolicyMassChangeApproval' -Value ''; Write-Host "    [engine] AzResPolicies: approved plan $($plan.planHash) applied -- approval cleared" -ForegroundColor Green }
                    catch { Write-Warning "  [engine] AzResPolicies: the approval for plan $($plan.planHash) could NOT be cleared: $($_.Exception.Message)" }
                }
            }
        }
    }
}

function New-PimAzResPoliciesProvider {
    # Enabled exactly like GroupsPolicies / EntraRolePolicies: no `feature` key (they carry none), always
    # registered, reached by its own sub-daily engine-delta job (delta-pim-azure-policies).
    @{
        scope = 'AzResPolicies'; entity = 'PIM-Assignments-Azure-Resources'; order = 58; refreshBefore = $false
        GetDesired = {
            param($ctx)
            if ($null -eq $ctx) { $ctx = @{} }
            $ctx['azResPol'] = @{ failStreak = 0; holdRecorded = $false; visited = @{}; approvalCleared = $false }
            $d = @(Get-PimAzResPolicyDesiredSet)
            $ctx['azResPolDesired'] = $d
            $d
        }
        GetLive = {
            param($ctx)
            if ($null -eq $ctx) { $ctx = @{} }
            $desired = if ($ctx.ContainsKey('azResPolDesired')) { @($ctx['azResPolDesired']) } else { @(Get-PimAzResPolicyDesiredSet) }
            if (-not $ctx['azResPolArmRoleCache']) { $ctx['azResPolArmRoleCache'] = @{} }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($d in $desired) { $live.Add((Get-PimAzResPolicyLive -Scope "$($d.AzScope)" -RoleName "$($d.RoleName)" -RoleCache $ctx['azResPolArmRoleCache'])) }
            $verdicts = @(Write-PimAzResPolicyVerification -Desired $desired -Live $live.ToArray())
            $ctx['azResPolVerdicts'] = $verdicts
            # PLAN FIRST: the whole change set and the breaker decision exist before any ApplyUpdate runs.
            $plan = Get-PimAzResPolicyChangePlan -Desired $desired -Live $live.ToArray() -Verdicts $verdicts
            $dec = Test-PimAzResPolicyBreaker -Plan $plan -Approval (Get-PimAzResPolicyMassChangeApproval)
            $ctx['azResPolPlan'] = $plan; $ctx['azResPolBreaker'] = $dec
            $color = if ($dec.hold) { 'Red' } elseif ($dec.approved) { 'Yellow' } else { 'DarkCyan' }
            Write-Host ("    [breaker] AzResPolicies: N={0} change(s) of T={1} checked, W={2} weakening, planHash={3} -- {4}{5}" -f `
                $plan.changes, $plan.checked, $plan.weakening, $plan.planHash, $(if ($dec.hold) { 'HOLD: ' } elseif ($dec.approved) { 'APPROVED: ' } else { 'apply: ' }), $dec.reason) -ForegroundColor $color
            if (@($plan.notificationDefaultsAligned).Count) {
                Write-Host ("    [breaker] AzResPolicies: {0} notification default(s) aligned to template -- counted in N, not in W" -f @($plan.notificationDefaultsAligned).Count) -ForegroundColor DarkCyan
            }
            if (@($plan.adminPathAligned).Count) {
                Write-Host ("    [breaker] AzResPolicies: {0} admin-path enablement change(s) aligned to template (engine requirement: its identity cannot present MFA) -- counted in N, not in W: {1}" -f `
                    @($plan.adminPathAligned).Count, ((@($plan.adminPathAligned | Select-Object -First 5 | ForEach-Object { "$($_.role) @ $($_.scope) $($_.ruleId) $($_.change)" })) -join '; ')) -ForegroundColor DarkCyan
            }
            if ($dec.hold -or ($ctx["__pimWhatIf"] -and [int]$plan.changes -gt 0)) { Write-PimPolicyImpactLog -Provider 'AzResPolicies' -Plan $plan }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAzResPolicyKey -Row $r }
        Equal = { param($d,$l) (Get-PimAzResPolicyVerdict -Desired $d -Live $l).state -in @('matches','kept') }
        ApplyCreate = { param($item,$ctx) throw "AzResPolicies: no live policy read for '$($item.key)' -- nothing written" }
        ApplyUpdate = { param($item,$ctx) Invoke-PimAzResPolicyUpdate -Item $item -Context $ctx }
    }
}

# ---------------------------------------------------------------------------
# AdminTap scope -- issue a Temporary Access Pass for admin accounts flagged
# CreateTAP=TRUE (Account-Definitions-Admins). Ported from New-PimTemporaryAccessPass.
# ---------------------------------------------------------------------------

function Get-PimAdminTapLeadHours {
    # #10 -- v1 $global:PIM_TapCreateLeadHours, default 48 (v1 11395). Global, env or pim.Settings.
    $v = "$(Get-PimAdminLifecycleSetting -Name 'TapCreateLeadHours' -Default '')".Trim()
    $n = 0
    if ($v -and [int]::TryParse($v, [ref]$n) -and $n -ge 0) { return $n }
    return 48
}

function Test-PimAdminIsAdOnly {
    # PURE. Operator 2026-09-13: "admins with -ad dont exist in entra, ad only ... password only".
    # A TargetPlatform=AD row is provisioned on-premises by hybrid-ad-apply and is NEVER handled by an
    # Entra provider (Admins, AdminMembers, AdminTap) and never warned about as if it were an Entra admin.
    param([object]$Row)
    if ($null -eq $Row) { return $false }
    return ("$(Get-PimRowProp -Row $Row -Names @('TargetPlatform','Platform'))".Trim() -ieq 'AD')
}

function Test-PimAdminTapWanted {
    # PURE. Operator 2026-09-13: "enforce tap to true" -- every admin is issued a TAP, whatever the
    # stored CreateTAP says. The one exception is an AD-only admin (TargetPlatform=AD): a TAP is an
    # Entra credential and cannot exist there. The Manager mirrors this in Test-PimManagerAdminTapWanted
    # (tests/Test-PimAdminLifecycle.ps1 keeps the two identical).
    param([object]$Row)
    if ($null -eq $Row) { return $false }
    return -not (Test-PimAdminIsAdOnly -Row $Row)
}

function Select-PimAdminTapCandidates {
    # #10 + #8 PURE. Which CreateTAP rows may be issued a TAP on THIS run? v1 11384-11400:
    #   * the account must be due (ProvisionDate) and not Disabled / Revoked / offboarded;
    #   * TAPStartDate further out than the lead window (default 48 h) is DEFERRED -- "a
    #     long-pending TAP is a standing credential, and some tenants reject far-future
    #     startDateTime". A later run inside the window issues it.
    # Returns @{ issue; deferred; blocked } -- deferred/blocked carry @{ upn; reason }.
    param([object[]]$Rows = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$LeadHours = -1)
    if ($LeadHours -lt 0) { $LeadHours = Get-PimAdminTapLeadHours }
    $issue = New-Object System.Collections.Generic.List[object]
    $deferred = New-Object System.Collections.Generic.List[object]
    $blocked = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if (-not (Test-PimAdminTapWanted -Row $r)) { continue }   # enforced for every admin; AD-only cannot hold a TAP
        $upn = Get-PimRowProp -Row $r -Names @('UserPrincipalName')
        $pd = Test-PimAdminProvisionDue -Row $r -NowUtc $NowUtc
        if (-not $pd.due) { [void]$deferred.Add([pscustomobject]@{ upn = $upn; reason = "account $($pd.reason)"; startUtc = $pd.provisionUtc }); continue }
        $dec = Get-PimAdminStatusDecision -Row $r -NowUtc $NowUtc
        if ($dec.blocksCreate) { [void]$blocked.Add([pscustomobject]@{ upn = $upn; reason = $dec.reason }); continue }
        $s = ConvertTo-PimAdminLifecycleUtc -Value (Get-PimRowProp -Row $r -Names @('TAPStartDate','TapStartDate'))
        if ($s.parsed -and $s.utc -gt $NowUtc.ToUniversalTime().AddHours($LeadHours)) {
            [void]$deferred.Add([pscustomobject]@{ upn = $upn; reason = ("TAP DEFERRED -- starts {0:yyyy-MM-dd HH:mm} UTC, more than {1} h out; a later run inside the lead window issues it" -f $s.utc, $LeadHours); startUtc = $s.utc })
            continue
        }
        [void]$issue.Add($r)
    }
    return [pscustomobject]@{ issue = $issue.ToArray(); deferred = $deferred.ToArray(); blocked = $blocked.ToArray() }
}

function Get-PimAdminTapStartDateTime {
    # #10 PURE. The startDateTime to send for a row's TAPStartDate, or '' to start immediately.
    # v2 sent none, so every TAP started the moment it was minted. A start that is not meaningfully
    # in the future is omitted (Graph rejects a start in the past); an unreadable one is omitted with
    # the reason, as v1 did ("TAP will start immediately").
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $raw = Get-PimRowProp -Row $Row -Names @('TAPStartDate','TapStartDate')
    $s = ConvertTo-PimAdminLifecycleUtc -Value $raw
    if (-not $s.set) { return [pscustomobject]@{ value = ''; reason = 'no TAPStartDate' } }
    if (-not $s.parsed) { return [pscustomobject]@{ value = ''; reason = "TAPStartDate '$raw' is not a date expression -- the TAP starts immediately" } }
    if ($s.utc -le $NowUtc.ToUniversalTime().AddMinutes(2)) { return [pscustomobject]@{ value = ''; reason = 'TAPStartDate is now or past -- starts immediately' } }
    return [pscustomobject]@{ value = $s.utc.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); reason = 'TAPStartDate' }
}

function Get-PimAdminTapChatChannels {
    # #10 -- v1 also delivered the TAP to every configured Teams / Slack incoming webhook
    # (Send-PimAdminTap, v1 11774-12095), from $global:PIM_NotificationChannels in a config FILE.
    # v2 reads the SAME shape from pim.Settings['TapDeliveryChannels'] (or the in-process global):
    #   { "Teams": { "WebhookUrl": "https://..." }, "Slack": { "WebhookUrl": "https://..." } }
    # 🔒 Deliberately NOT the alerting webhook (PIM-AlertChannels.ps1): that channel carries
    # operational alerts to a wide audience and must never carry a credential.
    $cfg = Get-PimAdminLifecycleSetting -Name 'TapDeliveryChannels'
    if ($null -eq $cfg -and $global:PIM_NotificationChannels) { $cfg = $global:PIM_NotificationChannels }
    if ($cfg -is [string]) { try { $cfg = $cfg | ConvertFrom-Json } catch { $cfg = $null } }
    $out = @()
    if ($null -eq $cfg) { return $out }
    foreach ($ch in @('Teams', 'Slack')) {
        $c = $null
        if ($cfg -is [System.Collections.IDictionary]) { if ($cfg.Contains($ch)) { $c = $cfg[$ch] } }
        else { $p = $cfg.PSObject.Properties[$ch]; if ($p) { $c = $p.Value } }
        if ($null -eq $c) { continue }
        $url = if ($c -is [System.Collections.IDictionary]) { "$($c['WebhookUrl'])" } else { "$($c.WebhookUrl)" }
        if ($url.Trim()) { $out += [pscustomobject]@{ channel = $ch; url = $url.Trim() } }
    }
    return $out
}

function Test-PimAdminTapWebhookUrl {
    # PURE. Only an https URL on a public, dotted host name -- never an IP literal or an intranet
    # name. Uses the shared SSRF rule when PIM-AlertChannels.ps1 is loaded.
    param([string]$Url)
    if (Get-Command Test-PimWebhookUrlAllowed -ErrorAction SilentlyContinue) { return [bool](Test-PimWebhookUrlAllowed -Url $Url).allowed }
    $u = $null
    if (-not [System.Uri]::TryCreate("$Url", [System.UriKind]::Absolute, [ref]$u)) { return $false }
    if ($u.Scheme -ne 'https') { return $false }
    $h = "$($u.Host)"; $ip = $null
    if ([System.Net.IPAddress]::TryParse($h, [ref]$ip)) { return $false }
    return ($h.IndexOf('.') -gt 0 -and $h -notmatch '(?i)(^|\.)localhost$')
}

function Send-PimAdminTapChatDelivery {
    # #10 -- best effort, never blocks provisioning, never logs the code. Returns
    # @{ configured; sent; failed }. -Poster is the test seam ($url, $json).
    param([Parameter(Mandatory)][string]$UserPrincipalName, [Parameter(Mandatory)][object]$Tap, [string]$ExpiresUtc, [scriptblock]$Poster)
    $res = [pscustomobject]@{ configured = $false; sent = @(); failed = @() }
    $chans = @(Get-PimAdminTapChatChannels)
    if (-not $chans.Count) {
        Write-Host "  [AdminTap] chat delivery: no Teams/Slack channel is configured (pim.Settings 'TapDeliveryChannels') -- the TAP went by mail only." -ForegroundColor DarkGray
        return $res
    }
    $res.configured = $true
    if ($global:WhatIfMode) { return $res }
    $post = $Poster
    if (-not $post -and ($global:PIM_TapWebhookPoster -is [scriptblock])) { $post = $global:PIM_TapWebhookPoster }
    if (-not $post) { $post = { param($Url, $Json) Invoke-RestMethod -Uri $Url -Method Post -ContentType 'application/json' -Body $Json -ErrorAction Stop | Out-Null } }
    $code = "$($Tap.temporaryAccessPass)"; $start = "$($Tap.startDateTime)"; $mins = "$($Tap.lifetimeInMinutes)"
    $subject = "Your initial PIM admin TAP for $UserPrincipalName"
    $bt = [string][char]96
    foreach ($c in $chans) {
        if (-not (Test-PimAdminTapWebhookUrl -Url $c.url)) {
            $res.failed += $c.channel
            Write-Warning "  [AdminTap] $($c.channel) TAP delivery REFUSED for ${UserPrincipalName}: the configured webhook is not an https URL on a public host."
            continue
        }
        try {
            if ($c.channel -eq 'Teams') {
                $card = @{ type = 'AdaptiveCard'; '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'; version = '1.4'
                    body = @(
                        @{ type = 'TextBlock'; size = 'Medium'; weight = 'Bolder'; text = $subject; wrap = $true },
                        @{ type = 'FactSet'; facts = @(
                            @{ title = 'Admin UPN'; value = $UserPrincipalName }, @{ title = 'TAP code'; value = $code },
                            @{ title = 'Valid from'; value = $start }, @{ title = 'Lifetime'; value = "$mins minute(s)" }, @{ title = 'Expires at'; value = $ExpiresUtc }) },
                        @{ type = 'TextBlock'; wrap = $true; text = 'Use the TAP at https://mysignins.microsoft.com/security-info to register strong credentials (Passkey / Authenticator).' }) }
                $json = @{ type = 'message'; attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; contentUrl = $null; content = $card }) } | ConvertTo-Json -Depth 12 -Compress
            } else {
                $text = @("*$subject*", "Admin UPN: $bt$UserPrincipalName$bt", "TAP code: $bt$code$bt", "Valid from: $start", "Lifetime: $mins minute(s); expires $ExpiresUtc",
                          'Register strong credentials at https://mysignins.microsoft.com/security-info.') -join "`n"
                $json = @{ text = $text } | ConvertTo-Json -Depth 4 -Compress
            }
            & $post $c.url $json
            $res.sent += $c.channel
        } catch {
            $res.failed += $c.channel
            Write-Warning "  [AdminTap] $($c.channel) TAP delivery FAILED for ${UserPrincipalName} (provisioning NOT blocked): $($_.Exception.Message)"
        }
    }
    return $res
}

function New-PimAdminTapProvider {
    @{
        scope = 'AdminTap'; entity = 'Account-Definitions-Admins'; order = 35; refreshBefore = $true
        GetDesired = {
            param($ctx)
            # #8 + #10: only rows whose account is due, not disabled/revoked/offboarded, and whose
            # TAPStartDate is inside the lead window (Select-PimAdminTapCandidates). The rest wait.
            $sel = Select-PimAdminTapCandidates -Rows @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins') -NowUtc ([datetime]::UtcNow)
            foreach ($x in @($sel.deferred)) { Write-Host ("    [AdminTap] {0}: {1}" -f $x.upn, $x.reason) -ForegroundColor DarkCyan }
            foreach ($x in @($sel.blocked))  { Write-Host ("    [AdminTap] {0}: no TAP -- {1}" -f $x.upn, $x.reason) -ForegroundColor DarkYellow }
            $ctx['adminTapDesired'] = @($sel.issue)
            @($sel.issue)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            # @( if ... ) -- an `if` expression unrolls a one-element array, and on PS 5.1 a lone
            # PSCustomObject has no .Count, which silently skipped the refusal warning below.
            $desired = @(if ($ctx.ContainsKey('adminTapDesired')) { $ctx['adminTapDesired'] } else { (Select-PimAdminTapCandidates -Rows @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')).issue })
            $live = New-Object System.Collections.Generic.List[object]
            # 🔑 #10 ISSUE ONCE (v1 11386-11387 + 11418-11421, tap-state.json -> pim.Settings['AdminTapIssuance']).
            # An account with an issuance record is SATISFIED for ever: an expired pass is NOT re-issued
            # automatically. Re-issue is the Manager's queued tap-reset (PIM-QueueActions.ps1), a human
            # decision. This replaces BUG-66's "mint again whenever the last pass is unusable", which
            # minted a fresh credential every time one expired for as long as CreateTAP=TRUE.
            $store = Get-PimAdminLifecycleStore -Name 'AdminTapIssuance'
            $ctx['adminTapStore'] = $store
            if (-not $store.ok -and $desired.Count -gt 0) {
                Write-Warning "  [AdminTap] REFUSING to issue any TAP this run: issuance cannot be recorded ($($store.reason)), so issue-once could not be guaranteed."
            }
            $backfill = $false
            # 2026-09-23 (operator: "disable the automatic tap sending every day"): the 2026-09-21 re-issue below minted and
            # mailed a new pass every time the last one expired. It is OFF unless pim.Settings 'TapReissueUntilOnboarded'
            # is TRUE -- issue once again; a new pass is the Manager's Reset TAP.
            $__reissue = "$(Get-PimAdminLifecycleSetting -Name 'TapReissueUntilOnboarded' -Default '')" -match '^(?i)(true|1|yes)$'
            foreach ($d in $desired) {
                $upn = Get-PimRowProp -Row $d -Names @('UserPrincipalName')
                $upnL = "$upn".Trim().ToLowerInvariant()
                if (-not $store.ok) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue }        # fail closed
                if ($store.map.ContainsKey($upnL) -and -not $__reissue) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue }   # issued once = satisfied
                if ($store.map.ContainsKey($upnL)) {
                    # 2026-09-21 (operator: "keep sending a tap until logged in"): ISSUE-ONCE becomes ISSUE-UNTIL-ONBOARDED. An
                    # account that was issued a TAP stays satisfied while that pass is still usable, or once the admin has
                    # registered a sign-in method of their own (then recorded as onboarded and never probed again). An
                    # expired or used-up pass on an account with NO own method gets a NEW one. Any read that fails keeps it
                    # satisfied (fail closed: a delayed pass, never a loop of credentials).
                    $__rec = $store.map[$upnL]
                    $__onb = ($__rec -is [System.Collections.IDictionary] -and $__rec.Contains('onboarded') -and $__rec['onboarded']) -or ("$($__rec.source)" -like 'already onboarded*')
                    if ($__onb) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue }
                    $__uid = Resolve-PimPrincipalId $upn
                    if (-not $__uid) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue }
                    try {
                        $__usable = @(@(Invoke-PimGraph -All -Path "/users/$__uid/authentication/temporaryAccessPassMethods") | Where-Object { "$($_.isUsable)" -match '(?i)true' })
                        if ($__usable.Count) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue }
                        $__own = @(Invoke-PimGraph -All -Path "/users/$__uid/authentication/methods" | Where-Object {
                            "$($_.'@odata.type')" -match '(?i)fido2|microsoftAuthenticator|windowsHelloForBusiness|softwareOath|platformCredential|x509Certificate|passkey|phoneAuthentication' })
                        if ($__own.Count) {
                            $store.map[$upnL] = @{ issuedAtUtc = "$($__rec.issuedAtUtc)"; recordedAtUtc = [datetime]::UtcNow.ToString('o'); source = 'already onboarded: registered a sign-in method of their own'; onboarded = $true }
                            $backfill = $true
                            $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue
                        }
                        Write-Host "  [AdminTap] $upn -- the last TAP is no longer usable and the admin has not registered a method of their own yet -- issuing a NEW TAP (keep sending until signed in)." -ForegroundColor Yellow
                        continue   # NOT in the live set -> ApplyCreate issues a fresh pass (and replaces the dead one)
                    } catch {
                        $live.Add([pscustomobject]@{ UserPrincipalName=$upn }); continue   # unreadable -> satisfied (fail closed)
                    }
                }
                $uid = Resolve-PimPrincipalId $upn; if (-not $uid) { continue }
                # 🔴 -All IS LOAD-BEARING, and its absence made this scope a no-op.
                # Invoke-PimRest returns the RAW RESPONSE unless -All is passed (`if (-not $All)
                # { return $resp }`), so without it $taps was the response WRAPPER object, not the
                # TAP collection -- and @(wrapper).Count is 1 even when the user has NO TAP.
                # Every resolvable account was therefore classified as "already has a TAP", Equal
                # returned $true, and the scope reported c0/u0/r0 while minting nothing.
                # MEASURED in EFIF: four accounts with CreateTAP=TRUE sat at TAP=none across
                # repeated runs, each reporting AdminTap:c0/u0/r0 with no error. The only TAP that
                # ever appeared did so by ACCIDENT -- a freshly-created account is briefly
                # unresolvable, so it fell out of the live set and became a create candidate.
                # With -All the aggregated .value is returned, so an account with no TAP yields 0.
                # 🔴 BUG-66 -- "HAS A TAP" IS NOT "HAS A USABLE TAP", and the difference is whether
                # the admin can ever sign in again. This counted ANY temporaryAccessPassMethods
                # entry as satisfied, so an EXPIRED pass classified the account as done: the scope
                # reported ok=True on six consecutive runs against the live master while minting
                # nothing, and the admin had no route to a credential. Deleting the dead method by
                # hand re-armed it and the next tick minted one within seconds.
                # Entra reports usability directly (isUsable / methodUsabilityReason), so filter on
                # it: a dead pass now leaves the account OUT of the live set, which makes it a
                # create candidate and ApplyCreate replaces it.
                # 📌 SUPERSEDED 2026-09-12 by #10 ISSUE ONCE (operator): an unusable pass is now
                # RECORDED as the one issuance and left alone; re-issue is the Manager's queued
                # tap-reset. isUsable is still read, to say WHY in the log and the record.
                # 🪤 An UNREADABLE probe must count as SATISFIED, not as missing. If Graph errors
                # here, treating the account as "no TAP" would mint a fresh credential on every
                # tick for as long as the read keeps failing -- the runaway this scope must never
                # become. Failing closed costs a delayed re-issue; failing open mails credentials
                # in a loop.
                try {
                    $taps = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")
                    $usable = @($taps | Where-Object { "$($_.isUsable)" -match '(?i)true' })
                    if ($taps.Count) {
                        # A pass PIM has no record of: issued before issue-once tracking existed (or by
                        # hand). It COUNTS as the one issuance -- recorded, never replaced automatically.
                        $why = if ($usable.Count) { 'pre-existing usable TAP' } else { "pre-existing TAP, not usable ($($taps[0].methodUsabilityReason))" }
                        if (-not $usable.Count -and $__reissue) {
                            # 2026-09-21 ("keep sending a tap until logged in"): a dead pass on an account with no method of its
                            # own is replaced -- not left for a person to notice.
                            $__own0 = @()
                            try { $__own0 = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/methods" | Where-Object { "$($_.'@odata.type')" -match '(?i)fido2|microsoftAuthenticator|windowsHelloForBusiness|softwareOath|platformCredential|x509Certificate|passkey|phoneAuthentication' }) } catch { $__own0 = @('unreadable') }
                            if (-not $__own0.Count) {
                                Write-Host "  [AdminTap] $upn holds a TAP that is NOT usable ($($taps[0].methodUsabilityReason)) and has no sign-in method of its own -- issuing a NEW TAP." -ForegroundColor Yellow
                                continue
                            }
                        }
                        $store.map[$upnL] = @{ issuedAtUtc = ''; recordedAtUtc = [datetime]::UtcNow.ToString('o'); source = $why }
                        $backfill = $true
                        $live.Add([pscustomobject]@{ UserPrincipalName=$upn })
                        continue
                    }
                    # No pass at all. An account that already has a strong sign-in method registered was
                    # onboarded long ago (a v1 migration: v1 kept its tap-state in a FILE v2 never reads),
                    # so it must not be handed a fresh credential now. A failed read of the methods is
                    # not fatal here: the worst case is ONE issuance, which is then recorded.
                    $strong = @()
                    try {
                        $strong = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/methods" | Where-Object {
                            "$($_.'@odata.type')" -match '(?i)fido2|microsoftAuthenticator|windowsHelloForBusiness|softwareOath|platformCredential|x509Certificate|passkey' })
                    } catch { Write-Verbose "TAP onboarding probe ($upn): $($_.Exception.Message)" }
                    if ($strong.Count) {
                        $store.map[$upnL] = @{ issuedAtUtc = ''; recordedAtUtc = [datetime]::UtcNow.ToString('o'); source = 'already onboarded: a strong sign-in method is registered' }
                        $backfill = $true
                        $live.Add([pscustomobject]@{ UserPrincipalName=$upn })
                    }
                } catch {
                    # fail CLOSED (see above): unreadable => leave it in the live set => no mint.
                    $live.Add([pscustomobject]@{ UserPrincipalName=$upn })
                    Write-Verbose "TAP live ($upn): $($_.Exception.Message) -- treating as satisfied (fail-closed)"
                }
            }
            if ($backfill -and -not (Save-PimAdminLifecycleStore -Name 'AdminTapIssuance' -Map $store.map)) {
                Write-Warning '  [AdminTap] pre-existing TAPs were found but could not be recorded -- they are still NOT re-issued this run.'
            }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('UserPrincipalName')).ToLowerInvariant() }
        Equal = { param($d,$l) $true }   # has a TAP already -> nochange
        ApplyCreate = {
            param($item,$ctx)
            $d=$item.desired; $upn=Get-PimRowProp -Row $d -Names @('UserPrincipalName'); $uid=Resolve-PimPrincipalId $upn
            if (-not $uid) { throw "AdminTap: user '$upn' not found" }
            # 2026-09-21: no TAPLifetimeHours on the row = as long as the tenant's TAP policy allows (New-PimTapRequestBody -1).
            $hrs=[int]("0"+(Get-PimRowProp -Row $d -Names @('TAPLifetimeHours'))); $__tapMins = if ($hrs -gt 0) { $hrs*60 } else { -1 }

            # 🔴 BUG-66 -- REFUSE BEFORE MINTING when the mail cannot be delivered.
            # Now that GetLive replaces an EXPIRED pass, this scope re-mints on expiry -- which is
            # the behaviour that made the fix an operator decision in the first place: on a tenant
            # that cannot send mail, a self-healing scope mints a fresh UNDELIVERABLE credential
            # every cycle. Refusing first turns that runaway into one honest warning per run.
            # The guard is the SAME one the Manager's re-issue button uses (PIM-Notify.ps1), so the
            # two paths cannot disagree about whether a credential may be issued.
            # The recipient is the ONE rule the Manager also displays (Get-PimAdminMailRecipient): the
            # owner's office user (ForwardMailsToContact=TRUE + MailForwardAddress), else ManagerEmail.
            # It read ManagerEmail directly, while the Manager said the TAP went to the office user --
            # the screen and the mail disagreed (operator, 2026-09-12).
            # 71.19: ALL the sponsor department's owners (';'-joined -> one mail, several toRecipients).
            $__tp = Get-PimAdminMailRecipientPlan -Row $d -DepartmentOwners (Get-PimDepartmentOwnerIndex)
            $mgr = (@($__tp.recipients) -join ';')
            if (Get-Command Test-PimTapMailReady -ErrorAction SilentlyContinue) {
                $mailChk = Test-PimTapMailReady -Recipient $mgr -Reason "$($__tp.reason)"
                if (-not $mailChk.ok) {
                    # Not a throw: one unreachable admin must not fail the whole scope. Reported
                    # loudly, and NOTHING is created -- the existing (dead) pass is left untouched,
                    # which is strictly better than a live credential nobody received.
                    Write-Warning "  [AdminTap] $upn -- no TAP issued (nothing changed): $($mailChk.reason)"
                    # 🔴 `return $null` HERE WAS COUNTED AS APPLIED. Measured live on EFIF 2026-08-25:
                    # the guard refused all six admins, printed "Nothing was changed" six times, and
                    # the run still summarised `applied=6 errors=0 ok=True`. Six dead accounts, a
                    # perfect green, on a 15-minute job -- the failure would never have surfaced.
                    # BUG-35a already built the convention for exactly this ("a handler that RETURNS
                    # WITHOUT ACTING must not be counted as applied") but its default is
                    # anything-that-is-not-pimApplied-false counts as applied, and **$null is
                    # 'anything'**. The refusal was written before that convention and never adopted
                    # it, so the loudest possible warning was reported as a success.
                    # 🪤 A refusal that reports success is worse than no guard at all: without the
                    # guard you get a bad credential you can see, with it you get a green you trust.
                    return [pscustomobject]@{ pimApplied = $false; reason = "$($mailChk.reason)" }
                }
            }

            # #10 ISSUE ONCE needs somewhere to write the issuance. No store => no mint (fail closed),
            # and this refusal sits BEFORE the delete below: never destroy what cannot be replaced.
            $__store = $ctx['adminTapStore']
            if (-not $__store) { $__store = Get-PimAdminLifecycleStore -Name 'AdminTapIssuance' }
            if (-not $__store.ok) {
                Write-Warning "  [AdminTap] $upn -- REFUSING to issue: the issuance cannot be recorded ($($__store.reason)). Nothing was changed."
                return [pscustomobject]@{ pimApplied = $false; reason = "issuance cannot be recorded: $($__store.reason)" }
            }

            # Entra allows exactly ONE TAP per user, so a dead pass must be REMOVED before a new
            # one can be created. This is the step that was done by hand to recover the master.
            try {
                foreach ($old in @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")) {
                    if (-not "$($old.id)".Trim()) { continue }
                    Invoke-PimGraph -Method DELETE -Path "/users/$uid/authentication/temporaryAccessPassMethods/$($old.id)" | Out-Null
                    Write-Host "  [AdminTap] $upn -- removed the previous TAP ($($old.methodUsabilityReason))." -ForegroundColor DarkGray
                }
            } catch { Write-Verbose "TAP delete ($upn): $($_.Exception.Message)" }

            # #10: TAPStartDate -> startDateTime (v1 11403 + New-PimTemporaryAccessPass 11505-11527).
            # v2 sent none, so a TAP planned for an admin's first day started -- and began expiring --
            # the moment it was minted.
            $__start = Get-PimAdminTapStartDateTime -Row $d
            # 🔴 The body is built from the TENANT'S TAP POLICY (PIM-TapPolicy.ps1). This sent
            # a MULTI-use request unconditionally, and a tenant that only allows one-time passes
            # answered 400 "Tenant Policy does not allow multiple use temporary access pass method"
            # for every admin (measured live on internal 2026-09-12). The POST itself stays here.
            $tap = Invoke-PimTapCreate -LifetimeMinutes $__tapMins -StartDateTime $__start.value -UserLabel $upn -Poster {
                param($b) Invoke-PimGraph -Method POST -Path "/users/$uid/authentication/temporaryAccessPassMethods" -Body $b
            }
            # Record the issuance BEFORE delivery, as v1 did (11418): a delivery failure must never
            # cause a second TAP on the next run. The CODE is never stored.
            $__store.map["$upn".Trim().ToLowerInvariant()] = @{ issuedAtUtc = [datetime]::UtcNow.ToString('o'); startDateTime = "$($tap.startDateTime)"; lifetimeInMinutes = "$($tap.lifetimeInMinutes)"; methodId = "$($tap.id)"; source = 'engine' }
            if (-not (Save-PimAdminLifecycleStore -Name 'AdminTapIssuance' -Map $__store.map)) {
                Write-Warning "  [AdminTap] $upn -- a TAP WAS MINTED but its issuance could NOT be recorded; a later run could issue another. Check pim.Settings['AdminTapIssuance']."
            }
            Write-PimAdminLifecycleAudit -Action 'tap.create' -Target $upn -After @{ startDateTime = "$($tap.startDateTime)"; lifetimeInMinutes = "$($tap.lifetimeInMinutes)" }
            # deliver the TAP by mail (best-effort) -- to the admin's manager
            if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
                # $mgr is already resolved above -- the refuse-before-minting guard needs it BEFORE
                # anything is created, so re-reading it here would be a second source of truth.
                # {{TapExpiresUtc}} is IN the shipped tap-delivery template, and this used to pass
                # it as a hardcoded '' -- so every TAP mail ever sent rendered an EMPTY "expires at".
                # The recipient got a code with no deadline, which is the one fact a time-boxed
                # credential has to carry. Reported by the operator on the first mail that actually
                # arrived, 2026-08-12. Computed from the values Graph returns on the TAP itself.
                $__tapMins = 0; [void][int]::TryParse("$($tap.lifetimeInMinutes)", [ref]$__tapMins)
                $__tapStart = $null
                if ("$($tap.startDateTime)".Trim()) {
                    try { $__tapStart = [datetime]::Parse("$($tap.startDateTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { $__tapStart = $null }
                }
                # Fall back to "now" only when Graph gave no parseable start: the TAP was minted
                # moments ago, so now+lifetime is accurate to seconds -- and a near-exact deadline
                # is far more useful to the recipient than the blank this replaces.
                if (-not $__tapStart) { $__tapStart = [datetime]::UtcNow }
                $__tapExpires = if ($__tapMins -gt 0) { $__tapStart.AddMinutes($__tapMins).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '' }
                $toks = @{ UserPrincipalName=$upn; TapCode="$($tap.temporaryAccessPass)"; TapStartLocal="$($tap.startDateTime)"; TapStartUtc="$($tap.startDateTime)"; TapLifetimeMinutes="$($tap.lifetimeInMinutes)"; TapExpiresUtc=$__tapExpires }
                # THE RESULT IS NOT OPTIONAL INFORMATION, and piping it to Out-Null hid the one
                # failure this scope must never hide. Send-PimNotifyMail NEVER throws for a
                # refused send -- an allowlist miss, a kill switch flipped between the pre-check
                # and the send, a template that vanished, or a Graph 4xx all come back as
                # sent=$false in the RETURN VALUE. Discarding it meant the scope reported
                # applied=1 / ok=True over a live credential nobody received, with the previous
                # pass already deleted -- the exact outcome BUG-66's refuse-before-minting guard
                # exists to prevent, arriving one step later than the guard can see. The guard
                # answers "may we issue?"; nothing answered "did it actually get there?".
                # This cannot be undone here (the old pass is gone by now), so the only correct
                # action is to say so LOUDLY, naming the account, the recipient and the reason.
                # Measured 2026-08-21 on the live master: the happy path returns sent=True.
                $mailRes = $null
                try { $mailRes = Send-PimNotifyMail -Type 'tap-delivery' -Tokens $toks -Recipient $mgr } catch { Write-Verbose "tap mail ($upn): $($_.Exception.Message)" }
                if ("$($mailRes.sent)" -notmatch '(?i)true') {
                    $why = if ("$($mailRes.reason)".Trim()) { "$($mailRes.reason)" } else { 'the send threw' }
                    Write-Warning "  [AdminTap] $upn -- a TAP WAS MINTED but the mail to '$mgr' did NOT go out: $why. A live credential now exists that nobody received -- delete it, or re-issue from the Manager's Accounts & TAP tab once mail works."
                }
            }
            # #10: Teams / Slack as well, when a TAP delivery channel is configured (v1 11426-11452).
            # Best effort; says plainly when none is configured.
            $__chatExp = ''
            $__cm = 0; [void][int]::TryParse("$($tap.lifetimeInMinutes)", [ref]$__cm)
            $__cs = $null
            if ("$($tap.startDateTime)".Trim()) { try { $__cs = [datetime]::Parse("$($tap.startDateTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { $__cs = $null } }
            if (-not $__cs) { $__cs = [datetime]::UtcNow }
            if ($__cm -gt 0) { $__chatExp = $__cs.AddMinutes($__cm).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
            try { [void](Send-PimAdminTapChatDelivery -UserPrincipalName $upn -Tap $tap -ExpiresUtc $__chatExp) } catch { Write-Warning "  [AdminTap] $upn -- chat delivery threw (provisioning NOT blocked): $($_.Exception.Message)" }
            $tap
        }
    }
}

# ---------------------------------------------------------------------------
# AccessReviews scope -- create an access-review schedule for groups that opt in via a
# ReviewCycle column. Reviewers = the group's Owners; auto-apply is OFF (the engine never
# auto-applies decisions on an engine-managed group -- matches LIFECYCLE-GOVERNANCE).
# Needs AccessReview.ReadWrite.All on the engine SPN; built REST-only.
# ---------------------------------------------------------------------------
function Get-PimReviewRecurrence {
    # ReviewCycle text -> Graph accessReview recurrence pattern + a sensible instance duration.
    param([string]$Cycle)
    switch -Regex ("$Cycle") {
        '(?i)week'                 { return @{ pattern = @{ type = 'weekly';        interval = 1 }; days = 3  } }
        '(?i)month'                { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 1 }; days = 7  } }
        '(?i)quarter'              { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 }; days = 14 } }
        '(?i)semi|half'            { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 6 }; days = 21 } }
        '(?i)ann|year'             { return @{ pattern = @{ type = 'absoluteYearly';  interval = 1 }; days = 30 } }
        default                    { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 }; days = 14 } }
    }
}
function New-PimAccessReviewsProvider {
    @{
        scope = 'AccessReviews'; entity = 'PIM-Definitions'; order = 80; refreshBefore = $true
        # REQ-Y (operator 2026-09-19): access review campaigns are Pro -- without a Pro licence this scope no-ops with the
        # licence reason (Invoke-PimEngineScope's feature gate -> Test-PimFeatureAvailable -> Test-PimFeatureProLicence).
        feature = 'reviews.campaigns'
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            @(Get-PimGroupDefinitionRows | Where-Object { "$(Get-PimRowProp -Row $_ -Names @('ReviewCycle'))".Trim() } |
                ForEach-Object { [pscustomobject]@{ GroupName = $_.GroupName; Owners = $_.Owners; SponsorUpn = $_.SponsorUpn; Department = $_.Department; ReviewCycle = (Get-PimRowProp -Row $_ -Names @('ReviewCycle')) } })
        }
        GetLive = {
            param($ctx)
            $live = New-Object System.Collections.Generic.List[object]
            try { foreach ($d in @(Invoke-PimGraph -All -Path "/identityGovernance/accessReviews/definitions?`$select=id,displayName")) { if ("$($d.displayName)" -like 'PIM4EntraPS review - *') { $live.Add([pscustomobject]@{ GroupName = ("$($d.displayName)" -replace '^PIM4EntraPS review - ', '') }) } } }
            catch {
                $ctx['__pimLiveIncomplete'] = 'AccessReviews: the review definitions could not be listed'   # 2026-09-20, see AdministrativeUnitMembers
                Write-Warning "  [AccessReviews] list failed: $($_.Exception.Message)"
            }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('GroupName')).ToLowerInvariant() }
        Equal = { param($d, $l) $true }   # one review schedule per group (existence-based)
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired; $gn = $d.GroupName
            $gid = Resolve-PimLiveGroupIdByName $gn; if (-not $gid) { throw "AccessReviews: group '$gn' not found" }
            $reviewerIds = Resolve-PimGroupOwnerIds -Row $d -Ctx $ctx
            if (-not $reviewerIds.Count) { throw "AccessReviews: no reviewer (owner) resolves for '$gn'" }
            $rev = @($reviewerIds | ForEach-Object { @{ query = "/users/$_"; queryType = 'MicrosoftGraph' } })
            $rc = Get-PimReviewRecurrence -Cycle $d.ReviewCycle
            $body = @{
                displayName = "PIM4EntraPS review - $gn"
                descriptionForAdmins = "Engine-managed access review for PIM group $gn (reviewers = owners; auto-apply OFF)."
                scope = @{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = "/groups/$gid/transitiveMembers"; queryType = 'MicrosoftGraph' }
                reviewers = $rev
                settings = @{
                    mailNotificationsEnabled = $true; reminderNotificationsEnabled = $true
                    justificationRequiredOnApproval = $true; recommendationsEnabled = $true
                    defaultDecisionEnabled = $false; defaultDecision = 'None'
                    autoApplyDecisionsEnabled = $false            # engine never auto-applies
                    instanceDurationInDays = $rc.days
                    recurrence = @{ pattern = $rc.pattern; range = @{ type = 'noEnd'; startDate = ([datetime]::UtcNow.ToString('yyyy-MM-dd')) } }
                }
            }
            Invoke-PimGraph -Method POST -Path '/identityGovernance/accessReviews/definitions' -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupOwners scope -- attach each group's resolved owners (Owners/SponsorUpn/Department).
# Separate from Groups create so it (a) tolerates replication of a just-created group
# (retry), (b) is re-runnable -- repairs missing owners on EXISTING groups (Groups itself
# is existence-based nochange and would never re-add them). Proper diff via $expand=owners.
# ---------------------------------------------------------------------------
function New-PimGroupOwnersProvider {
    @{
        scope = 'GroupOwners'; entity = 'PIM-Definitions'; order = 25; refreshBefore = $true
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $out = New-Object System.Collections.Generic.List[object]
            # REQ-L: plus an Azure permission group's owners, from the PIM-Definitions-Resources row the Azure wizards stage
            # (only rows that name Owners -- see Get-PimResourceOwnerDefinitionRows).
            foreach ($g in @(@(Get-PimGroupDefinitionRows) + @(Get-PimResourceOwnerDefinitionRows))) {
                if ($null -eq $g) { continue }
                foreach ($oid in (Resolve-PimGroupOwnerIds -Row $g -Ctx $ctx)) {
                    $out.Add([pscustomobject]@{ GroupName = $g.GroupName; OwnerId = "$oid" })
                }
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $live = New-Object System.Collections.Generic.List[object]
            try {
                foreach ($grp in @(Invoke-PimGraph -Path "/groups?`$select=id,displayName&`$expand=owners" -All)) {
                    $gn = "$($grp.displayName)"; if (-not $gn) { continue }
                    foreach ($o in @($grp.owners)) { if ($o.id) { $live.Add([pscustomobject]@{ GroupName = $gn; OwnerId = "$($o.id)" }) } }
                }
            } catch {
                $ctx['__pimLiveIncomplete'] = "GroupOwners: the owners preload failed"   # 2026-09-20, see AdministrativeUnitMembers
                Write-Warning "  [GroupOwners] owners preload failed: $($_.Exception.Message)"
            }
            $live.ToArray()
        }
        KeyOf = { param($r) ("$(Get-PimRowProp -Row $r -Names @('GroupName'))").ToLowerInvariant() + '|' + "$(Get-PimRowProp -Row $r -Names @('OwnerId'))" }
        Equal = { param($d, $l) $true }
        ApplyCreate = {
            param($item, $ctx)
            $gn = Get-PimRowProp -Row $item.desired -Names @('GroupName'); $oid = Get-PimRowProp -Row $item.desired -Names @('OwnerId')
            $gid = Resolve-PimLiveGroupIdByName $gn
            if (-not $gid) { throw "GroupOwners: group '$gn' not found" }
            $ok = $false
            for ($t = 0; $t -lt 4 -and -not $ok; $t++) {
                try { Invoke-PimGraph -Method POST -Path "/groups/$gid/owners/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$oid" } | Out-Null; $ok = $true }
                catch { $em = "$($_.Exception.Message)"; if ($em -match '(?i)already exist|references already exist') { throw }  else { Start-Sleep -Seconds 3 } }   # exists -> let core validate-skip; else replication, retry
            }
            if (-not $ok) { throw "GroupOwners: owner add failed after retries ($oid -> $gn)" }
        }
    }
}

# ---------------------------------------------------------------------------
# EntraRolesDirect scope -- PIM v1-style DIRECT directory-role assignment to an
# ADMIN PRINCIPAL (a user), as opposed to the group-centric v2 model where the
# principal is always a PIM group. Some tenants still carry roles assigned
# directly to the admin (eligible or active) -- e.g. break-glass accounts that
# must not depend on the group fabric. Desired = PIM-Assignments-Roles-Direct
# (UserPrincipalName + RoleDefinitionName + AssignmentType[Eligible|Active] +
# Permanent/NumOfDaysWhenExpire). Same Graph PIM directory-role REST as
# EntraRoles, but principalId is the USER's id, tenant scope ('/'). The group
# model is preferred; the engine emits a deprecation note once per run so the
# data owner is nudged toward a group. Ported intent from the legacy v1 direct
# role path; module-free, REST-only, PS 5.1-safe.
# ---------------------------------------------------------------------------
function Get-PimDirectRoleKey {
    # PURE: uniform key for desired + live direct-role rows -> "<principalId|upn>|<role>|<type>".
    param([object]$Row)
    $prin = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $prin) { $prin = Get-PimRowProp -Row $Row -Names @('UserPrincipalName','Username','UPN','upn') }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName')
    $type = Get-PimRowProp -Row $Row -Names @('AssignmentType')
    return ("$prin|$role|$type").ToLowerInvariant()
}
function New-PimEntraRolesDirectProvider {
    @{
        scope  = 'EntraRolesDirect'
        entity = 'PIM-Assignments-Roles-Direct'
        order  = 48   # after group-centric EntraRoles(40)/RolesAUs(45), before AdminMembers(50)
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            # 68.6 rows 24-26 (direct): rows are resolved UPN -> user object id and the id is STAMPED, so a
            # desired row keys like its live assignment (live carries only the id). Before this the two
            # never matched ("upn|role|type" vs "<id>|role|type"): nothing was ever nochange, and a Remove
            # row could not have named a live item. Remove rows are resolved the same way and kept apart.
            $all = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Direct' | Where-Object { Get-PimRowProp -Row $_ -Names @('UserPrincipalName','Username','UPN','upn') })
            $stamp = {
                param($row)
                $c = $row | Select-Object *
                $uid = Resolve-PimPrincipalId (Get-PimRowProp -Row $row -Names @('UserPrincipalName','Username','UPN','upn'))
                if ($uid) { Add-Member -InputObject $c -NotePropertyName principalId -NotePropertyValue $uid -Force }
                $c
            }
            $ctx['removeRows:EntraRolesDirect'] = @($all | Where-Object { Test-PimRowIsRemove $_ } | ForEach-Object { & $stamp $_ })
            $rows = @($all | Where-Object { -not (Test-PimRowIsRemove $_) } | ForEach-Object { & $stamp $_ })
            if (@($rows).Count) {
                # DEPRECATION nudge: v2 is group-centric; direct role assignment to a user is a v1 holdover.
                Write-Host ("  [EntraRolesDirect] {0} DIRECT (v1-style) role assignment(s) to user principals -- supported, but the group model is preferred (assign the role to a PIM group + make the admin a member). See DESIGN 'PIM v1 direct assignments'." -f @($rows).Count) -ForegroundColor DarkYellow
            }
            @($rows)
        }
        GetLive = {
            param($ctx)
            $ctx['directRoleNameToId'] = Get-PimEntraRoleNameMap; $ctx['directUpnToId'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Direct')
            $upns = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('UserPrincipalName','Username','UPN','upn') } | Where-Object { $_ } | Select-Object -Unique)
            # 🔴 2026-09-20: same rule as EntraRoles -- an INCOMPLETE preload is NOT CHECKED, never a diff.
            Get-PimDirRoleSchedulePreload
            $__pe = Get-PimDirRoleScheduleReadError
            if ($__pe) { $ctx['__pimLiveReadError'] = "the directory role schedule preload was INCOMPLETE ($__pe)"; return @() }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($upn in $upns) {
                $uid = Resolve-PimPrincipalId $upn; if (-not $uid) { continue }
                $ctx['directUpnToId'][$upn.ToLowerInvariant()] = $uid
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $uid)) {
                    if ("$($s.directoryScopeId)" -ne '/') { continue }   # tenant-scope direct roles only
                    if ("$($s.graphAssignmentType)" -ieq 'Activated') { continue }   # an activation is not an assignment (68.6 rows 24-26)
                    $live.Add([pscustomobject]@{ principalId=$uid; UserPrincipalName=$upn; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; roleDefinitionId=$s.roleDefinitionId
                                                 directoryScopeId='/'; scheduleKnown=$s.scheduleKnown; startDateTime=$s.startDateTime; endDateTime=$s.endDateTime })
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimDirectRoleKey -Row $r }
        GetRemoveRows = { param($ctx) @(Select-PimRemoveRows -Rows @($ctx['removeRows:EntraRolesDirect']) -Scope 'EntraRolesDirect') }
        TypeKeyOf = { param($r) Get-PimTypeNeutralKey -Key (Get-PimDirectRoleKey -Row $r) }
        # 68.6 rows 25-26 (was `$true`: AutoExtend / UpdateExisting ignored, a type switch kept both types).
        Equal = { param($d,$l) (Get-PimAssignmentMaintenance -Desired $d -Live $l).action -eq 'none' }
        ApplyUpdate = { param($item,$ctx) Invoke-PimAssignmentMaintenanceApply -Kind DirRole -Item $item }
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $upn = Get-PimRowProp -Row $d -Names @('UserPrincipalName','Username','UPN','upn')
            $uid = $ctx['directUpnToId'][$upn.ToLowerInvariant()]; if (-not $uid) { $uid = Get-PimRowProp -Row $d -Names @('principalId') }; if (-not $uid) { $uid = Resolve-PimPrincipalId $upn }
            $rn  = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['directRoleNameToId'][$rn.ToLowerInvariant()]
            if (-not $uid -or -not $rid) { throw "EntraRolesDirect: unresolved user/role ($upn / $rn)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimRoleScheduleBody -PrincipalId $uid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o'))
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            # Prune, targeted Remove row, or the old half of a type change; "already absent" is success.
            Remove-PimDirRoleAssignment -Live $item.live -What "$($item.key)"
        }
    }
}

# ---------------------------------------------------------------------------
# Offboarding -- remove an admin principal's DELEGATIONS cleanly. The legacy CSV
# engine (PIM-Functions.psm1 Invoke-PimAdminOffboarding) handled account revoke +
# delete; the REST engine needs the delegation-removal half: when an admin is
# retired (Account-Definitions-Admins Lifecycle=Retire OR a past OffboardDate),
# strip every PIM-for-Groups membership (eligible + active) they hold across the
# managed groups -- so no lingering privileged reach survives the offboarding.
#
# Pure planner (Get-PimOffboardingPlan) decides WHO is to be offboarded + which
# live memberships to remove (fully testable, no Graph). The provider wraps it as
# a real REST-applying scope, GATED like every destructive path:
#   * runs only under -Mode Full -Prune (the engine's standard destructive gate), AND
#   * $global:PIM_OffboardCleanupMode controls intent: Off (skip) | Report
#     (plan only, the default) | Enforce (apply removals). Report/Off never write.
# 📌 SUPERSEDED 2026-09-12 (#12, v1 parity): the provider is per ADMIN and does v1's whole
# sequence without -Prune -- see New-PimOffboardingProvider. Test-PimAdminOffboarded and
# Get-PimOffboardingPlan remain as pure helpers.
# An admin NOT flagged for offboarding is never touched (only flagged principals
# contribute live memberships, so the diff can only ever remove their rows).
# ---------------------------------------------------------------------------
function Test-PimAdminOffboarded {
    # PURE: is this admin row due for AUTO-DISABLE as of $NowUtc?
    #   Lifecycle=Retire     -> yes (immediate)
    #   AutoDisableDate (a date expression / ISO) at or before NowUtc -> yes
    # 🔴 71.23 -- "Retire" here means the SAME disable-only path as a date that has passed:
    # disable, revoke sessions, remove memberships/eligibilities, notice, audit, stop. It has
    # never meant "delete the account", and since 71.21 nothing in the product does.
    # The legacy column name OffboardDate is still read (Get-PimAdminAutoDisableDate); a row
    # carrying both names with different values is REFUSED (reason returned, offboard=$false).
    # Returns @{ offboard=[bool]; reason=<text>; conflict=[bool] }.
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $life = (Get-PimRowProp -Row $Row -Names @('Lifecycle')).Trim()
    if ($life -match '(?i)^retire') { return @{ offboard = $true; reason = 'Lifecycle=Retire'; conflict = $false } }
    $add = Get-PimAdminAutoDisableDate -Row $Row
    if ($add.conflict) { return @{ offboard = $false; reason = "AutoDisableDate CONFLICT -- $($add.reason)"; conflict = $true } }
    $od = "$($add.value)".Trim()
    if ($od) {
        $when = $null
        if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) { try { $when = Resolve-PimDateExpression -Expression $od } catch { $when = $null } }
        if (-not $when) { $when = Get-PimUtcStamp $od }   # IMP-02: unreadable -> no auto-disable
        $lbl = if ($add.source -eq 'legacy') { 'OffboardDate (legacy name for AutoDisableDate)' } else { 'AutoDisableDate' }
        if ($when -and $when -le $NowUtc) { return @{ offboard = $true; reason = "$lbl $($when.ToString('yyyy-MM-dd')) reached"; conflict = $false } }
    }
    return @{ offboard = $false; reason = ''; conflict = $false }
}
function Get-PimOffboardingPlan {
    # PURE: given the admin definition rows + a (principalId -> live memberships)
    # map, return the removal plan -- one entry per live membership held by an
    # offboarded admin. $LiveByPrincipal[$pid] = @( @{ principalId; accessId;
    # GroupTag; AssignmentType }, ... ) (the shape Get-PimLiveGroupMembership
    # returns). Non-offboarded admins contribute nothing.
    param(
        [object[]]$AdminRows = @(),
        [Parameter(Mandatory)][hashtable]$LiveByPrincipal,
        [hashtable]$UpnToId = @{},
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($AdminRows)) {
        $flag = Test-PimAdminOffboarded -Row $a -NowUtc $NowUtc
        if (-not $flag.offboard) { continue }
        $upn = Get-PimRowProp -Row $a -Names @('UserPrincipalName','Username','UPN','upn')
        $prinId = Get-PimRowProp -Row $a -Names @('principalId')
        if (-not $prinId -and $upn) { $prinId = $UpnToId["$upn".ToLowerInvariant()] }
        if (-not $prinId) { continue }
        foreach ($m in @($LiveByPrincipal[$prinId])) {
            if ($null -eq $m) { continue }
            $plan.Add([pscustomobject]@{
                principalId       = $prinId
                UserPrincipalName = $upn
                GroupTag          = "$($m.GroupTag)"
                accessId          = $(if ("$($m.accessId)") { "$($m.accessId)" } else { 'member' })
                AssignmentType    = "$($m.AssignmentType)"
                Reason            = $flag.reason
            })
        }
    }
    return $plan.ToArray()
}

# OPERATOR POLICY (mass-disable incident, env-aware refinement): automatic offboarding
# (removing an offboarded admin's PIM-group memberships across the whole managed set) is
# ENVIRONMENT-AWARE -- it DEFAULTS ON in a test tenant and OFF in a protected one, and an
# explicit $global:PIM_EnableAutomaticOffboarding (true/false) always overrides that
# default in either direction. This is in addition to the existing -Mode Full -Prune +
# OffboardCleanupMode=Enforce gates. Self-contained here because the REST engine does not
# load PIM-Functions.psm1. Automatic offboarding stays prohibited in production until an
# approval flow exists (docs/REQUIREMENTS.md) -- protected env keeps it off by default.
#
# 📌 2026-09-12 (#12): the flag is ALSO read from the environment and from pim.Settings
# (Get-PimAdminLifecycleSetting). v1 took it from a *.custom.ps1 FILE, which v2 never loads -- so a
# v1 customer who had opted in would have silently lost offboarding on migration. The
# -Prune + OffboardCleanupMode=Enforce double gate is gone: offboarding is per ADMIN now, runs from
# its own job, and Enforce is the default once the feature is on (v1 had no second gate).
function Test-PimAutoOffboardingEnabled {
    $val = Get-PimAdminLifecycleSetting -Name 'EnableAutomaticOffboarding'
    # Explicit operator setting (true/false) always wins.
    if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
        $explicit = Test-PimExplicitFlagValue -Value $val
        if ($null -ne $explicit) { return [bool]$explicit }
        if (Get-Command Resolve-PimDestructiveFeatureDefault -ErrorAction SilentlyContinue) {
            return [bool](Resolve-PimDestructiveFeatureDefault)
        }
    }
    # Fallback (DisableGuard not loaded): preserve the post-incident OFF-by-default.
    return ("$val".Trim().ToLowerInvariant() -in @('true','1','yes','y','on','enable','enabled'))
}

function Get-PimOffboardMode {
    # Off | Report | Enforce. UNSET = Enforce: the opt-in is Test-PimAutoOffboardingEnabled, as in
    # v1 (which had no second gate). An explicit Report still plans without writing.
    $m = "$(Get-PimAdminLifecycleSetting -Name 'OffboardCleanupMode' -Default '')".Trim()
    if (-not $m) { return 'Enforce' }
    return $m
}

function Get-PimAdminOffboardCandidate {
    # #12 PURE. Does the offboarding sweep act on this admin row, and how?
    #   'offboard' -- past OffboardDate or Lifecycle=Retire (Test-PimAdminOffboarded): v1's full
    #                 sequence (v1 10977-11097): disable, revoke sessions, remove memberships,
    #                 notice mail. 71.21: NO delete -- the account is KEPT, disabled, for ever.
    #   'revoke'   -- AccountStatus=Revoked without offboarding: v1 Invoke-PimAccountRevoke also
    #                 cancelled PIM-for-Groups schedules and removed direct group memberships
    #                 (12451-12628). The Admins provider disables + revokes sessions; this adds the
    #                 membership half.
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $f = Test-PimAdminOffboarded -Row $Row -NowUtc $NowUtc
    if ($f.offboard) { return [pscustomobject]@{ kind = 'offboard'; reason = $f.reason } }
    if ((Get-PimRowProp -Row $Row -Names @('AccountStatus')).Trim() -ieq 'Revoked') { return [pscustomobject]@{ kind = 'revoke'; reason = 'AccountStatus=Revoked' } }
    return $null
}

function Get-PimAdminOffboardSteps {
    # #12 PURE. The steps still OWED for one admin, in v1's order. $State is the admin's record in
    # pim.Settings['AdminOffboardState'] (v1: output/state/offboard-state.json).
    #   disable      account still enabled
    #   sessions     not yet recorded as revoked
    #   memberships  not yet recorded as removed (retried on the next run if a removal failed)
    #   notice       offboarding-notice mail not yet sent ('offboard' only)
    # A missing account owes nothing: a human deleted it by hand in Entra.
    #
    # 🔴 71.21 -- THERE IS NO 'delete' STEP. PIM NEVER DELETES A USER ACCOUNT (operator, 2026-09-16:
    # "we will newer delete an accounnt, if that is in the code, then turn if off in the code, as I
    # will not allow that"). This used to add a 'delete' step once DeleteAfterDays had elapsed, and
    # Invoke-PimAdminOffboardSteps then issued DELETE /users/<id>. Both are GONE -- not gated behind
    # a flag, removed: an offboarded account stays in the tenant, disabled, sessions revoked,
    # memberships and eligibilities removed, for ever, unless a human deletes it by hand in Entra.
    # The retention field went with it (operator: "nobody uses it yet, so dont worry about
    # deleteafterdays, as i dont want it to be shown as it confuses") -- there is no -DeleteAfterDays
    # parameter, no column and no warning. A stored row that still carries the value is ignored in
    # silence. tests/Test-PimNoAccountDelete.ps1 fails the suite if either comes back.
    param([Parameter(Mandatory)][string]$Kind, [hashtable]$State = @{}, [bool]$Found = $true, [bool]$AccountEnabled = $false,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $steps = New-Object System.Collections.Generic.List[string]
    $note = ''; $dueUtc = $null
    if (-not $Found) { return [pscustomobject]@{ steps = @(); note = 'the account is not in the tenant'; deleteDueUtc = $null } }
    $has = { param($k) [bool]("$($State[$k])".Trim()) }
    if ($Kind -eq 'revoke') {
        if (-not (& $has 'membershipsRemovedUtc')) { [void]$steps.Add('memberships') }
        return [pscustomobject]@{ steps = $steps.ToArray(); note = ''; deleteDueUtc = $null }
    }
    if ($AccountEnabled) { [void]$steps.Add('disable') }
    if (-not (& $has 'revokedAtUtc')) { [void]$steps.Add('sessions') }
    if (-not (& $has 'membershipsRemovedUtc')) { [void]$steps.Add('memberships') }
    if (-not (& $has 'noticeSentUtc')) { [void]$steps.Add('notice') }
    return [pscustomobject]@{ steps = $steps.ToArray(); note = $note; deleteDueUtc = $dueUtc }
}

function Remove-PimAdminGroupMemberships {
    # #12 -- v1 Invoke-PimAccountRevoke steps 1, 2 and 5 (12509-12587): cancel every eligible and
    # active PIM-for-Groups schedule the principal holds DIRECTLY, then remove it from the groups it
    # is a direct member of. Per-principal filters -- never a tenant-wide scan. The filter result is
    # re-checked, not trusted. Returns @{ removed; errors }.
    param([Parameter(Mandatory)][string]$PrincipalId)
    $removed = 0
    $errors = New-Object System.Collections.Generic.List[string]
    $gone = '(?i)NotFound|does not exist|ResourceNotFound|404'
    foreach ($pair in @(@{ list = 'eligibilitySchedules'; req = 'eligibilityScheduleRequests' }, @{ list = 'assignmentSchedules'; req = 'assignmentScheduleRequests' })) {
        $rows = @()
        try { $rows = @(Invoke-PimGraph -All -Path ("/identityGovernance/privilegedAccess/group/{0}?`$filter=principalId eq '{1}'" -f $pair.list, $PrincipalId)) }
        catch { [void]$errors.Add("read $($pair.list): $($_.Exception.Message)"); continue }
        foreach ($s in $rows) {
            if ($null -eq $s -or "$($s.principalId)" -ne $PrincipalId) { continue }
            if ("$($s.memberType)" -match '(?i)^group$') { continue }   # inherited through a nested group
            $gid = "$($s.groupId)"; if (-not $gid) { continue }
            $acc = if ("$($s.accessId)".Trim()) { "$($s.accessId)" } else { 'member' }
            $body = New-PimGroupMembershipBody -PrincipalId $PrincipalId -GroupId $gid -AccessId $acc -Action 'adminRemove' -Justification 'PIM4EntraPS offboarding'
            try { Invoke-PimGraph -Method POST -Path "/identityGovernance/privilegedAccess/group/$($pair.req)" -Body $body | Out-Null; $removed++ }
            catch { if ("$($_.Exception.Message)" -notmatch $gone) { [void]$errors.Add("$($pair.req) $gid/$($acc): $($_.Exception.Message)") } }
        }
    }
    try {
        foreach ($g in @(Invoke-PimGraph -All -Path "/users/$PrincipalId/memberOf/microsoft.graph.group?`$select=id,displayName,groupTypes")) {
            if ($null -eq $g -or -not "$($g.id)".Trim()) { continue }
            if (@($g.groupTypes) -contains 'DynamicMembership') { continue }   # a rule decides; nothing to remove
            try { Invoke-PimGraph -Method DELETE -Path "/groups/$($g.id)/members/$PrincipalId/`$ref" | Out-Null; $removed++ }
            catch { if ("$($_.Exception.Message)" -notmatch $gone) { [void]$errors.Add("member of $($g.displayName) ($($g.id)): $($_.Exception.Message)") } }
        }
    } catch { [void]$errors.Add("read memberOf: $($_.Exception.Message)") }
    return [pscustomobject]@{ removed = $removed; errors = $errors.ToArray() }
}

function Invoke-PimAdminOffboardSteps {
    # #12 -- execute the owed steps for ONE admin, in order, recording progress in SQL after each so
    # a failure part-way resumes instead of repeating or skipping. Every step is idempotent.
    # The GATES (feature opt-in, removal budget, circuit breaker, break-glass) were decided for the
    # whole pass in the provider's GetLive and checked by ApplyUpdate before this is called.
    param([Parameter(Mandatory)][object]$Live, [object]$Desired, [hashtable]$Context = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $upn = "$($Live.UserPrincipalName)"; $uid = "$($Live.principalId)"; $upnL = $upn.Trim().ToLowerInvariant()
    $store = $Context['offboardStore']
    if (-not $store) { $store = Get-PimAdminLifecycleStore -Name 'AdminOffboardState' }
    if (-not $store.ok) { return [pscustomobject]@{ pimApplied = $false; reason = "offboarding state cannot be kept: $($store.reason)" } }
    $st = if ($store.map.ContainsKey($upnL)) { $store.map[$upnL] } else { @{} }
    if (-not ($st -is [hashtable])) { $st = ConvertTo-PimAdminLifecycleMap -Value $st }
    $now = { [datetime]::UtcNow.ToString('o') }
    $save = {
        $st['kind'] = "$($Live.kind)"
        $store.map[$upnL] = $st
        if (-not (Save-PimAdminLifecycleStore -Name 'AdminOffboardState' -Map $store.map)) {
            throw "offboarding state for $upn could not be saved -- stopping here so the next run resumes from what is recorded"
        }
    }
    $steps = @($Live.steps)
    $done = New-Object System.Collections.Generic.List[string]
    if ($steps -contains 'disable') {
        Invoke-PimGraph -Method PATCH -Path "/users/$uid" -Body @{ accountEnabled = $false } | Out-Null   # a failure THROWS: nothing else runs
        [void]$done.Add('disabled')
        Write-PimAdminLifecycleAudit -Action 'account.offboard.disable' -Target $upn -After @{ accountEnabled = $false; reason = "$($Live.reason)" }
    }
    if ($steps -contains 'sessions') {
        try { Invoke-PimGraph -Method POST -Path "/users/$uid/revokeSignInSessions" -Body @{} | Out-Null; [void]$done.Add('sessions revoked') }
        catch { Write-Warning "  [Offboard] $upn -- revokeSignInSessions failed (offboarding continues, as v1): $($_.Exception.Message)" }
    }
    if ($steps -contains 'memberships') {
        $m = Remove-PimAdminGroupMemberships -PrincipalId $uid
        if (@($m.errors).Count -eq 0) {
            $st['membershipsRemovedUtc'] = & $now; [void]$done.Add("memberships removed ($($m.removed))")
        } else {
            $tries = 0; [void][int]::TryParse("$($st['membershipAttempts'])", [ref]$tries); $tries++
            $st['membershipAttempts'] = $tries
            Write-Warning ("  [Offboard] {0} -- {1} membership removal(s) FAILED (attempt {2}): {3}" -f $upn, @($m.errors).Count, $tries, (@($m.errors) -join ' | '))
            if ($tries -ge 3) {
                # Stop retrying for ever; the account is disabled and the failures are recorded.
                $st['membershipsRemovedUtc'] = & $now; $st['membershipErrors'] = (@($m.errors) -join ' | ')
                Write-Warning "  [Offboard] $upn -- giving up on the remaining memberships after 3 attempts; review them by hand."
            }
            if ($m.removed -gt 0) { [void]$done.Add("memberships removed ($($m.removed), with errors)") }
        }
    }
    if ($Live.kind -eq 'offboard' -and -not "$($st['revokedAtUtc'])".Trim() -and ($steps -contains 'sessions' -or $steps -contains 'disable')) {
        $st['revokedAtUtc'] = & $now
        $st['offboardDate'] = "$((Get-PimAdminAutoDisableDate -Row $Desired).value)"   # 71.23: AutoDisableDate (legacy OffboardDate still read)
        Write-PimAdminLifecycleAudit -Action 'account.offboard.revoke' -Target $upn -After @{ offboardDate = $st['offboardDate']; accountKept = $true }
    }
    if ($steps -contains 'disable' -or $steps -contains 'sessions' -or $steps -contains 'memberships') { & $save }
    if ($steps -contains 'notice') {
        $rcpt = ''; $rcptWhy = ''
        if (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue) {
            # 71.19: sponsor department owners (ManagerEmail only as the legacy fallback, inside the plan).
            $__op = Get-PimAdminMailRecipientPlan -Row $Desired -DepartmentOwners (Get-PimDepartmentOwnerIndex)
            $rcpt = (@($__op.recipients) -join ';'); $rcptWhy = "$($__op.reason)"
        }
        if (-not $rcpt) {
            $st['noticeSentUtc'] = 'skipped: no recipient resolved'
            Write-Host "  [Offboard] $upn -- no offboarding notice: $rcptWhy" -ForegroundColor DarkYellow
        } elseif (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
            $st['noticeSentUtc'] = 'skipped: the mail library is not loaded in this process'
        } else {
            $toks = @{ DisplayName = (Get-PimRowProp -Row $Desired -Names @('DisplayName')); UserPrincipalName = $upn
                       OffboardDate = "$((Get-PimAdminAutoDisableDate -Row $Desired).value)"   # 71.23: the mail token keeps its name; the value is AutoDisableDate
                       AutoDisableDate = "$((Get-PimAdminAutoDisableDate -Row $Desired).value)"
                       # 71.21: no "deletion scheduled" sentence -- PIM never deletes the account.
                       Steps = 'PIM schedules cancelled, group memberships removed, account disabled, sessions revoked. The account itself is KEPT (disabled); PIM never deletes an account -- delete it by hand in Entra if that is wanted.'
                       Date = [datetime]::UtcNow.ToString('yyyy-MM-dd') }
            $res = $null
            try { $res = Send-PimNotifyMail -Type 'offboarding-notice' -Tokens $toks -Recipient $rcpt } catch { $res = @{ sent = $false; reason = "send threw: $($_.Exception.Message)" } }
            if ("$($res.sent)" -match '(?i)true') { $st['noticeSentUtc'] = & $now; [void]$done.Add("notice mailed to $rcpt") }
            elseif ("$($res.reason)" -match '(?i)threw|timeout|429|50\d|temporar') { Write-Warning "  [Offboard] $upn -- offboarding notice to '$rcpt' did NOT go out ($($res.reason)); retried next run." }
            else {
                # A refusal that will not change by retrying (kill switch, allowlist, no sender,
                # no template) is recorded once instead of warned about every hour.
                $st['noticeSentUtc'] = "skipped: $($res.reason)"
                Write-Warning "  [Offboard] $upn -- offboarding notice to '$rcpt' NOT sent: $($res.reason)."
            }
        }
        & $save
    }
    # 🔴 71.21 -- THE ACCOUNT-DELETE STEP IS GONE. There is no branch here that deletes a user, and
    # no setting that can bring one back (operator, 2026-09-16). An offboarded admin ends as a
    # disabled account with no sessions, no memberships and no eligibilities, and stays that way.
    if ($done.Count -eq 0) { return [pscustomobject]@{ pimApplied = $false; reason = 'no offboarding step completed this run (see the warnings above)' } }
    Write-Host ("    [offboard] {0}: {1}" -f $upn, ($done -join '; ')) -ForegroundColor Yellow
    return [pscustomobject]@{ pimApplied = $true; steps = $done.ToArray() }
}

function New-PimOffboardingProvider {
    # #12 -- per ADMIN, not per membership, and no -Prune. v2's first version diffed memberships
    # and removed them only under -Mode Full -Prune plus OffboardCleanupMode=Enforce: no scheduled
    # job ever passed -Prune, so it never ran; it never disabled, revoked sessions, mailed or
    # deleted; and a single admin holding six memberships tripped the 5-item removal budget.
    #   desired = the admin rows the sweep acts on (Get-PimAdminOffboardCandidate)
    #   live    = one record per such admin: what the tenant + the SQL progress record say is owed
    #   equal   = nothing owed
    #   update  = do the owed steps (Invoke-PimAdminOffboardSteps)
    # GATES, all decided in GetLive for the whole pass: automatic offboarding enabled (env-aware,
    # v1's gate) -> OffboardCleanupMode (Off / Report / Enforce, default Enforce) -> the offboarding
    # state store is reachable (else fail closed) -> break-glass excluded -> G4 removal budget over
    # the admins with destructive steps -> the account-disable circuit breaker over the disables.
    @{
        scope = 'AdminOffboarding'; entity = 'Account-Definitions-Admins'; order = 90; refreshBefore = $true
        GetDesired = {
            param($ctx)
            $now = [datetime]::UtcNow
            $all = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
            $ctx['offboardAll'] = $all
            $cands = New-Object System.Collections.Generic.List[object]
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($a in $all) {
                if ($null -eq $a) { continue }
                # 🔴 71.23 -- a row that carries BOTH AutoDisableDate and the legacy OffboardDate with
                # DIFFERENT dates is REFUSED, loudly, and never guessed. It is reported here (once per
                # run, naming the admin and both values) rather than in the candidate test, because a
                # conflicting row is not a candidate at all and would otherwise vanish silently.
                $__add = Get-PimAdminAutoDisableDate -Row $a
                if ($__add.conflict) {
                    $__who = (Get-PimRowProp -Row $a -Names @('UserPrincipalName','UserName','Username')).Trim()
                    Write-Warning ("  [AdminOffboarding] {0}: NOT auto-disabled -- {1}" -f $__who, $__add.reason)
                    continue
                }
                $c = Get-PimAdminOffboardCandidate -Row $a -NowUtc $now
                if (-not $c) { continue }
                $upn = (Get-PimRowProp -Row $a -Names @('UserPrincipalName','UPN','upn')).Trim()
                if ($upn -notmatch '@') {
                    $local = if ($upn) { $upn } else { (Get-PimRowProp -Row $a -Names @('UserName','Username')).Trim() }
                    $dom = if ($local) { "$(Get-PimAdminUpnDomain)".Trim() } else { '' }   # REQ-T: pin -> Admin account domain -> default
                    if ($local -and $dom) { $upn = "$local@$dom" }
                }
                if ($upn -notmatch '@') { Write-Host "    [AdminOffboarding] a row flagged for offboarding has no resolvable UPN -- skipped." -ForegroundColor Yellow; continue }
                [void]$cands.Add([pscustomobject]@{ upn = $upn; kind = $c.kind; reason = $c.reason; key = (Get-PimAdminRowKey -Row ([pscustomobject]@{ UserPrincipalName = $upn })) })
                [void]$rows.Add($a)
            }
            $ctx['offboardCandidates'] = $cands.ToArray()
            $rows.ToArray()
        }
        GetLive = {
            param($ctx)
            $cands = @($ctx['offboardCandidates'] | Where-Object { $null -ne $_ })
            if (-not $cands.Count) { return @() }
            $rec = { param($c, $complete, $note) [pscustomobject]@{ UserPrincipalName = $c.upn; kind = $c.kind; reason = $c.reason; complete = [bool]$complete; steps = @(); note = $note; blocked = '' } }
            # OPERATOR POLICY: automatic offboarding is env-aware OFF in a protected tenant. One loud
            # line, no Graph read, nothing owed.
            if (-not (Test-PimAutoOffboardingEnabled)) {
                Write-Host ("    [AdminOffboarding] SKIPPED -- automatic offboarding is DISABLED (operator policy): {0} admin row(s) flagged for offboarding/revoke are NOT processed. Set PIM_EnableAutomaticOffboarding=true (global, env or pim.Settings 'EnableAutomaticOffboarding') to opt in." -f $cands.Count) -ForegroundColor DarkYellow
                return @($cands | ForEach-Object { & $rec $_ $true 'automatic offboarding disabled' })
            }
            $mode = Get-PimOffboardMode
            $ctx['offboardMode'] = $mode
            if ($mode -match '(?i)^off') {
                Write-Host "    [AdminOffboarding] SKIPPED -- OffboardCleanupMode=Off." -ForegroundColor DarkYellow
                return @($cands | ForEach-Object { & $rec $_ $true 'OffboardCleanupMode=Off' })
            }
            Ensure-PimContextLoaded
            $now = [datetime]::UtcNow
            $store = Get-PimAdminLifecycleStore -Name 'AdminOffboardState'
            $ctx['offboardStore'] = $store
            $ctx['offboardBlocked'] = ''
            if (-not $store.ok) {
                $ctx['offboardBlocked'] = "offboarding progress cannot be kept in SQL ($($store.reason)) -- without it the revoke time is lost and the notice would repeat every run"
                Write-Warning "  [AdminOffboarding] REFUSING to offboard: $($ctx['offboardBlocked'])"
            }
            $bg = @(); if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) { $bg = @(Get-PimBreakGlassIdentifiers) }
            $rowByKey = @{}; foreach ($a in @($ctx['offboardAll'])) { if ($a) { $rowByKey[(Get-PimAdminRowKey -Row $a)] = $a } }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($c in $cands) {
                $r = & $rec $c $false ''
                $u = $null; $found = $false
                try {
                    $u = Invoke-PimGraph -Path ("/users/{0}?`$select=id,userPrincipalName,displayName,accountEnabled" -f [uri]::EscapeDataString($c.upn))
                    $found = [bool]("$($u.id)".Trim())
                } catch {
                    if ("$($_.Exception.Message)" -notmatch '(?i)404|ResourceNotFound|does not exist|not found') {
                        $r.blocked = "the account could not be read: $($_.Exception.Message)"
                        [void]$live.Add($r); continue
                    }
                }
                $probe = [pscustomobject]@{ userPrincipalName = $c.upn; id = "$($u.id)" }
                if ($bg.Count -gt 0 -and (Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue) -and (Test-PimRowIsBreakGlass -Row $probe -Identifiers $bg)) {
                    # IMP-39: an UNREADABLE break-glass list protects every account THIS RUN -- it must not
                    # latch the offboard as complete, or the account would never be offboarded once the
                    # store is back. Blocked (retried next run), not done.
                    if ($bg -contains '<break-glass-list-unreadable>') {
                        $r.blocked = 'the break-glass account list could not be read, so this account cannot be confirmed as NOT break-glass -- not offboarded this run'
                        [void]$live.Add($r); continue
                    }
                    Write-Host "    [AdminOffboarding] $($c.upn) is a BREAK-GLASS account -- never offboarded, whatever its row says." -ForegroundColor Yellow
                    $r.complete = $true; $r.note = 'break-glass'; [void]$live.Add($r); continue
                }
                $stRec = @{}
                if ($store.ok -and $store.map.ContainsKey($c.upn.ToLowerInvariant())) { $stRec = $store.map[$c.upn.ToLowerInvariant()] }
                $row = $rowByKey[$c.key]
                $s = Get-PimAdminOffboardSteps -Kind $c.kind -State $stRec -Found $found -AccountEnabled (Test-PimAdminValueTrue $u.accountEnabled) -NowUtc $now
                if ($s.note) { Write-Host "    [AdminOffboarding] $($c.upn): $($s.note)" -ForegroundColor DarkYellow }
                $r | Add-Member -NotePropertyName principalId -NotePropertyValue "$($u.id)" -Force
                $r | Add-Member -NotePropertyName deleteDueUtc -NotePropertyValue $s.deleteDueUtc -Force
                $r.steps = @($s.steps); $r.complete = (@($s.steps).Count -eq 0); $r.note = $s.note
                [void]$live.Add($r)
            }
            # BLAST RADIUS, decided once for the whole pass (v1 10997-11009 budgeted the sweep).
            $destructive = @($live | Where-Object { -not $_.complete -and -not $_.blocked -and (@($_.steps | Where-Object { $_ -ne 'notice' }).Count -gt 0) })
            $toDisable = @($destructive | Where-Object { $_.steps -contains 'disable' }).Count
            if (-not $ctx['offboardBlocked'] -and $destructive.Count -gt 0) {
                if (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue) {
                    $rb = Test-PimRemoveBudgetAllowed -ToRemove $destructive.Count -Scope 'AdminOffboarding' -Scanned @($ctx['offboardAll']).Count -Operation 'auto-disable'
                    if (-not $rb.allowed) {
                        if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { Write-PimRemoveBudgetAlert -Decision $rb }
                        $ctx['offboardBlocked'] = "removal budget: $($rb.reason)"
                    }
                } else { $ctx['offboardBlocked'] = 'the removal budget (PIM-DisableGuard.ps1) is not loaded -- refusing to offboard (fail closed)' }
            }
            if (-not $ctx['offboardBlocked'] -and $toDisable -gt 0) {
                $resolved = $null
                if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey('Account-Definitions-Admins')) { $resolved = [bool]$global:PIM_DesiredResolved['Account-Definitions-Admins'] }
                if (Get-Command Test-PimExplicitDisablePassAllowed -ErrorAction SilentlyContinue) {
                    $dec = Test-PimExplicitDisablePassAllowed -ToDisable $toDisable -Scanned @($ctx['offboardAll']).Count -Desired @($ctx['offboardAll']) -DesiredResolved $resolved
                    if (-not $dec.allowed) {
                        if (Get-Command Write-PimDisableAbortAlert -ErrorAction SilentlyContinue) { Write-PimDisableAbortAlert -Scope 'AdminOffboarding' -Decision $dec }
                        $ctx['offboardBlocked'] = "account-disable circuit breaker [$($dec.tripped)]: $($dec.reason)"
                    }
                } else { $ctx['offboardBlocked'] = 'the account-disable circuit breaker (PIM-DisableGuard.ps1) is not loaded -- refusing to offboard (fail closed)' }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAdminRowKey -Row $r }
        Equal = { param($d,$l) [bool]$l.complete }
        ApplyUpdate = {
            param($item,$ctx)
            # Defense in depth: the same gates GetLive decided, re-checked where the writes happen.
            if (-not (Test-PimAutoOffboardingEnabled)) {
                Write-Host "    [AdminOffboarding] SKIPPED -- automatic offboarding is DISABLED (operator policy)." -ForegroundColor DarkYellow
                # BUG-35a: tell the core this was NOT applied.
                return [pscustomobject]@{ pimApplied = $false; reason = 'auto-offboarding disabled' }
            }
            $l = $item.live
            $blocked = "$($ctx['offboardBlocked'])".Trim(); if (-not $blocked) { $blocked = "$($l.blocked)".Trim() }
            if ($blocked) {
                Write-Host ("    [!] {0}: offboarding NOT run -- {1}" -f $l.UserPrincipalName, $blocked) -ForegroundColor Yellow
                return [pscustomobject]@{ pimApplied = $false; reason = $blocked }
            }
            $mode = "$($ctx['offboardMode'])"; if (-not $mode) { $mode = Get-PimOffboardMode }
            if ($mode -notmatch '(?i)^enforce') {
                Write-Host ("    [report] would offboard: {0} -> {1} ({2})" -f $l.UserPrincipalName, (@($l.steps) -join ', '), $l.reason) -ForegroundColor DarkYellow
                # BUG-35a: REPORT mode changes nothing, so it must not be counted as applied.
                return [pscustomobject]@{ pimApplied = $false; reason = "offboardMode=$mode (report only)" }
            }
            Invoke-PimAdminOffboardSteps -Live $l -Desired $item.desired -Context $ctx
        }
    }
}

# ---------------------------------------------------------------------------
# GroupRetirement (#12) -- Lifecycle=Retire on a GROUP definition row, ported from v1
# Invoke-PimGroupRetirement (v1 11099-11198): remove the directory role assignments the group
# holds, remove its members, delete the group. v1's gates, kept as they were:
#   * automatic group retirement is env-aware OFF in a protected tenant (PIM_EnableGroupRetirement;
#     global, env or pim.Settings 'EnableGroupRetirement' -- v1 read a file);
#   * only a group matching the engine naming prefix (PIM_GroupPrefix, else the literal prefix of the
#     tenant's PimGroupPattern -- REQ-U, no generic 'PIM-' default) is retired,
#     so a hand-made group with the same name is never deleted;
#   * G4 removal budget over the groups in the batch, aborted whole, never part-way.
# One v2 guard on top: a group the Groups provider still lists as desired would be RE-CREATED by
# the next groups deploy, so retiring it would flap -- that is refused until Get-PimGroupDefinitionRows
# stops returning Lifecycle=Retire rows.
# ---------------------------------------------------------------------------
function Test-PimGroupRetirementEnabled {
    $val = Get-PimAdminLifecycleSetting -Name 'EnableGroupRetirement'
    if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
        $explicit = Test-PimExplicitFlagValue -Value $val
        if ($null -ne $explicit) { return [bool]$explicit }
        if (Get-Command Resolve-PimDestructiveFeatureDefault -ErrorAction SilentlyContinue) { return [bool](Resolve-PimDestructiveFeatureDefault) }
    }
    return ("$val".Trim().ToLowerInvariant() -in @('true','1','yes','y','on','enable','enabled'))
}

function Get-PimManagedGroupPrefixes {
    <#
      REQ-U (2026-09-19) -- the name prefix(es) of the groups this TENANT's engine manages. Operator: "customer can
      have different naming convention so you must make sure code uses the actual naming per tenant and not
      generic". Both callers (the policy baseline's target set, the retirement guard) used to default to a
      hard-coded 'PIM-'. Order:
        1. an explicit GroupPrefix setting ($global:/env/pim.Settings, comma- or semicolon-separated) -- v1's knob;
        2. the literal prefix of the tenant's PimGroupPattern (Get-PimGroupNamePrefix, the same rule the tenant
           cache and the active-assignments snapshot use);
        3. NOTHING. A pattern with no literal prefix (e.g. '{Role}') cannot tell ours from anyone's by name, so a
           prefix-selected action selects nothing -- it must never widen to a generic 'PIM-'.
    #>
    $raw = "$(Get-PimAdminLifecycleSetting -Name 'GroupPrefix')".Trim()
    if ($raw) { return @($raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $p = ''
    if (Get-Command Get-PimGroupNamePrefix -ErrorAction SilentlyContinue) { $p = "$(Get-PimGroupNamePrefix)" }
    else {
        $pat = ''
        if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PimGroupPattern')) { $pat = "$($global:PIM_NamingConventions['PimGroupPattern'])" }
        if (-not $pat.Trim()) { $pat = 'PIM-{Role}-{Department}' }
        $i = $pat.IndexOf('{'); $p = if ($i -lt 0) { $pat } else { $pat.Substring(0, $i) }
        if ($p.Length -lt 3) { $p = '' }
    }
    if ($p) { return @($p) }
    return @()
}

function Get-PimGroupRetirementPrefixes {
    return @(Get-PimManagedGroupPrefixes)
}

function Get-PimRetireGroupRows {
    # PURE over the desired store: every group DEFINITION row flagged Lifecycle=Retire. The same
    # entities Get-PimGroupDefinitionRows reads (v1 read the seven definition CSVs).
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
                     'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')) {
        foreach ($r in @(Get-PimDesiredRows -Entity $e)) {
            if ($null -eq $r) { continue }
            $gn = (Get-PimRowProp -Row $r -Names @('GroupName')).Trim()
            if (-not $gn) { continue }
            if ((Get-PimRowProp -Row $r -Names @('Lifecycle')).Trim() -notmatch '(?i)^retire') { continue }
            [void]$out.Add([pscustomobject]@{ GroupName = $gn; Entity = $e })
        }
    }
    return $out.ToArray()
}

function New-PimGroupRetirementProvider {
    @{
        scope = 'GroupRetirement'; entity = 'PIM-Definitions'; order = 92; refreshBefore = $true
        GetDesired = { param($ctx) $rows = @(Get-PimRetireGroupRows); $ctx['retireRows'] = $rows; $rows }
        GetLive = {
            param($ctx)
            $rows = @($ctx['retireRows'] | Where-Object { $null -ne $_ })
            if (-not $rows.Count) { return @() }
            $rec = { param($r, $complete, $note) [pscustomobject]@{ GroupName = $r.GroupName; groupId = ''; complete = [bool]$complete; blocked = ''; note = $note } }
            if (-not (Test-PimGroupRetirementEnabled)) {
                Write-Host ("    [GroupRetirement] SKIPPED -- automatic group retirement is DISABLED (operator policy): {0} Lifecycle=Retire row(s) not processed. Set PIM_EnableGroupRetirement=true (global, env or pim.Settings 'EnableGroupRetirement') to opt in." -f $rows.Count) -ForegroundColor DarkYellow
                return @($rows | ForEach-Object { & $rec $_ $true 'group retirement disabled' })
            }
            Ensure-PimContextLoaded
            $prefixes = @(Get-PimGroupRetirementPrefixes)
            $stillDesired = @{}
            if (Get-Command Get-PimGroupDefinitionRows -ErrorAction SilentlyContinue) {
                foreach ($g in @(Get-PimGroupDefinitionRows)) { $n = "$($g.GroupName)".Trim().ToLowerInvariant(); if ($n) { $stillDesired[$n] = $true } }
            }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($r in $rows) {
                $x = & $rec $r $false ''
                $okPrefix = @($prefixes | Where-Object { $r.GroupName.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
                if (-not $okPrefix) {
                    if (-not $prefixes.Count) {
                        Write-Warning "  [GroupRetirement] '$($r.GroupName)': the tenant's group naming pattern has no literal prefix, so the engine cannot prove by name that it owns this group -- refusing to retire it. Set GroupPrefix (pim.Settings) to the prefix your groups carry to allow retirement."
                    } else {
                        Write-Warning "  [GroupRetirement] '$($r.GroupName)' does not match the engine naming prefix ($($prefixes -join ', ')) -- refusing to retire a group the engine may not own."
                    }
                    $x.complete = $true; $x.note = 'not engine-owned (prefix)'; [void]$live.Add($x); continue
                }
                $gid = Resolve-PimLiveGroupIdByName $r.GroupName
                if (-not $gid) { $x.complete = $true; $x.note = 'already gone -- remove the row (or its Retire flag) to finish'; [void]$live.Add($x); continue }
                $x.groupId = "$gid"
                if ($stillDesired.ContainsKey($r.GroupName.ToLowerInvariant())) {
                    $x.blocked = 'the Groups provider still lists this group as desired, so the next groups deploy would re-create it -- retirement refused until Lifecycle=Retire rows are excluded from Get-PimGroupDefinitionRows'
                }
                [void]$live.Add($x)
            }
            $ctx['retireBlocked'] = ''
            $pending = @($live | Where-Object { -not $_.complete -and -not $_.blocked })
            if ($pending.Count -gt 0) {
                if (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue) {
                    $rb = Test-PimRemoveBudgetAllowed -ToRemove $pending.Count -Scope 'GroupRetirement' -Scanned $rows.Count -Operation 'delete group'
                    if (-not $rb.allowed) {
                        if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { Write-PimRemoveBudgetAlert -Decision $rb }
                        $ctx['retireBlocked'] = "removal budget: $($rb.reason)"
                    }
                } else { $ctx['retireBlocked'] = 'the removal budget (PIM-DisableGuard.ps1) is not loaded -- refusing to delete groups (fail closed)' }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) "$($r.GroupName)".Trim().ToLowerInvariant() }
        Equal = { param($d,$l) [bool]$l.complete }
        ApplyUpdate = {
            param($item,$ctx)
            if (-not (Test-PimGroupRetirementEnabled)) { return [pscustomobject]@{ pimApplied = $false; reason = 'group retirement disabled' } }
            $l = $item.live
            $blocked = "$($ctx['retireBlocked'])".Trim(); if (-not $blocked) { $blocked = "$($l.blocked)".Trim() }
            if ($blocked) {
                Write-Host ("    [!] {0}: NOT retired -- {1}" -f $l.GroupName, $blocked) -ForegroundColor Yellow
                return [pscustomobject]@{ pimApplied = $false; reason = $blocked }
            }
            $gid = "$($l.groupId)"; $gn = "$($l.GroupName)"
            $warn = New-Object System.Collections.Generic.List[string]
            # 1. directory role assignments held BY the group (v1 11161-11171)
            try {
                foreach ($ra in @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$gid'")) {
                    if ($null -eq $ra -or "$($ra.principalId)" -ne $gid -or -not "$($ra.id)") { continue }
                    try { Invoke-PimGraph -Method DELETE -Path "/roleManagement/directory/roleAssignments/$($ra.id)" | Out-Null }
                    catch { [void]$warn.Add("role assignment $($ra.id): $($_.Exception.Message)") }
                }
            } catch { [void]$warn.Add("role assignment read: $($_.Exception.Message)") }
            # 2. members out (v1 11173-11180)
            try {
                foreach ($m in @(Invoke-PimGraph -All -Path "/groups/$gid/members?`$select=id")) {
                    if ($null -eq $m -or -not "$($m.id)") { continue }
                    try { Invoke-PimGraph -Method DELETE -Path "/groups/$gid/members/$($m.id)/`$ref" | Out-Null }
                    catch { [void]$warn.Add("member $($m.id): $($_.Exception.Message)") }
                }
            } catch { [void]$warn.Add("member read: $($_.Exception.Message)") }
            foreach ($w in $warn) { Write-Warning "  [GroupRetirement] $gn -- $w" }
            # 3. the group itself (v1 11182-11195). Azure RBAC held by the group dies with the object.
            Invoke-PimGraph -Method DELETE -Path "/groups/$gid" | Out-Null
            Write-Host "  [GroupRetirement] '$gn' DELETED. Remove the definition row to finish." -ForegroundColor Red
            Write-PimAdminLifecycleAudit -Action 'group.retire' -Target $gn -After @{ groupId = $gid; deleted = $true; warnings = $warn.Count }
            return [pscustomobject]@{ pimApplied = $true; groupId = $gid }
        }
    }
}

# ===========================================================================
# Workload-RBAC providers: Defender XDR + Intune (REQUIREMENTS §7). Group-centric,
# existence-based, idempotent, REST-only over Microsoft Graph (cert app-only).
#
# Both delegate a NATIVE workload RBAC role to a PIM GROUP (the principal is always
# a group, per the v2 model -- the admin gets the workload role by being a member of
# the group). They follow the same provider contract as EntraRoles/AzRes:
#   GetDesired -> the PIM-Assignments-* rows (Action!=Remove)
#   GetLive    -> the live role assignments the managed groups already hold
#   KeyOf      -> stable "<groupId>|<roleId>|..." key on BOTH desired + live
#   Equal      -> existence-based ($true: the group already holds the role => nochange)
#   ApplyCreate-> POST the workload role assignment for the group
#   ApplyRemove-> DELETE it (Full reconcile / -Prune only)
#
# READ-ONLY at collection: GetDesired/GetLive only read; nothing is written unless
# a create/remove is applied. -Mode Full reconciles create/update only; removal of a
# live-not-desired assignment needs -Prune (the engine's standard destructive gate).
#
# Each provider's RBAC prerequisite (REQUIREMENTS §7 "each connector enables its RBAC
# prerequisite"): Defender XDR needs Microsoft 365 Defender Unified RBAC activated and
# the engine SPN granted the Graph role-management.defender scope; Intune RBAC is on by
# default and needs DeviceManagementRBAC.ReadWrite.All.
# ===========================================================================

# Shared resolver: GroupTag -> live PIM group object id, via the tenant-wide tag map.
# (Same chain as the other assignment providers: a tag defined in any definition entity
# resolves to a GroupName, then to a live group id -- cache-first, on-demand fallback.)
function Resolve-PimGroupIdByTag {
    param([string]$Tag, [hashtable]$TagToName)
    if (-not $Tag) { return $null }
    $nm = $TagToName[$Tag.ToLowerInvariant()]; if (-not $nm) { return $null }
    return Resolve-PimLiveGroupIdByName $nm
}

# ---------------------------------------------------------------------------
# DefenderXdrRoles scope -- delegate a Microsoft Defender XDR (Microsoft 365
# Defender Unified RBAC) role to a PIM GROUP. Desired = PIM-Assignments-Defender
# (GroupTag + RoleDefinitionName + optional DataSources/UnitTag). Live + apply via
# the Graph Defender RBAC REST (roleManagement/defender/roleDefinitions +
# roleAssignments). Defender RBAC is a beta surface; the principal is the PIM group.
#
# NB: Defender Unified RBAC must be ACTIVATED in the security portal first (this is
# the connector's RBAC prerequisite); until it is, the role-definition list is empty
# and a clear "not activated / no roles" message is surfaced rather than a crash.
# ---------------------------------------------------------------------------
function Get-PimDefenderRoleKey {
    # PURE: uniform key for desired + live Defender rows -> "<groupId-or-tag>|<role>".
    param([object]$Row)
    $gid  = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName','RoleDefinitionId','roleDefinitionId')
    return ("$gid|$role").ToLowerInvariant()
}
function Get-PimDefenderRoleNameToId {
    # Live Defender role-definition NAME -> id map (cached per run). Empty when Unified
    # RBAC isn't activated -> caller surfaces a clear message.
    # REQ-U: a FAILED read is recorded (Get-PimDefenderRoleReadError) and NOT cached, so it is never remembered
    # as "this tenant has no Defender roles" and the provider can report the area as not checked.
    # 🔴 REQ-U wave 2: built from the ONE catalog read (Get-PimDefenderRoleCatalog, PIM-WorkloadRoles.ps1), which keeps
    # every role's actions. The map used to COLLAPSE duplicate names (last id wins -- internal has two "Microsoft Defender
    # for Identity Administrator"); an AMBIGUOUS name is now left OUT of this map and refused by name
    # (Get-PimDefenderAmbiguousRoleNames), never resolved to whichever id came last.
    if ($script:__pimDefenderRoles) { return $script:__pimDefenderRoles }
    $h = @{}
    $cat = Get-PimDefenderRoleCatalog
    if (-not $cat.ok) {
        $script:__pimDefenderRolesError = "$($cat.error)"
        Write-Warning "  [DefenderXdrRoles] role-definition list failed (Unified RBAC activated? engine SPN granted?): $($cat.error)"
        return $h
    }
    foreach ($k in @($cat.byName.Keys)) { $l = @($cat.byName[$k]); if ($l.Count -eq 1) { $h[$k] = "$($l[0].id)" } }
    $script:__pimDefenderRolesError = $null
    $script:__pimDefenderRoles = $h; return $h
}
function Get-PimDefenderRoleReadError { "$($script:__pimDefenderRolesError)" }
function New-PimDefenderXdrRolesProvider {
    @{
        scope  = 'DefenderXdrRoles'
        entity = 'PIM-Assignments-Defender'
        order  = 62   # after AzRes(60), a workload-RBAC delegation surface
        feature = 'connectors.workload'   # s29: advanced workload connector (kill switch); FREE since REQ-Y 2026-09-19
        refreshBefore = $true
        # 🔴 REQ-U wave 2 (design point 3). Desired = normalised copies (Get-PimDefenderDesiredBindings,
        # PIM-WorkloadRoles.ps1): every PIM-Assignments-Defender row PLUS every PIM-Assignments-Workloads Defender row
        # that carries a role SPEC (Permissions + DataSources). A spec row makes this provider OWN the custom role named
        # like the group: create it, keep its actions equal to the spec, assign it with the spec's data sources. A row
        # without a spec binds an existing role by name, as before.
        GetDesired = {
            param($ctx)
            $ctx['defTagToName'] = Get-PimTagToGroupName
            $rows = @(Get-PimDefenderDesiredBindings -TagToName $ctx['defTagToName'])
            $ctx['defDesired'] = $rows
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['defTagToName']) { $ctx['defTagToName'] } else { Get-PimTagToGroupName }
            $roleNameToId = Get-PimDefenderRoleNameToId
            $cat = Get-PimDefenderRoleCatalog
            $ctx['defRoleNameToId'] = $roleNameToId; $ctx['defGid'] = @{}; $ctx['defRoleCatalog'] = $cat
            $ctx['defRoleAmbiguous'] = Get-PimDefenderAmbiguousRoleNames -Catalog $cat
            $desired = if ($null -ne $ctx['defDesired']) { @($ctx['defDesired']) } else { @(Get-PimDefenderDesiredBindings -TagToName $tagToName) }
            # REQ-U wave 2: the Defender workload groups PIM defines. The orphan check reads live even before any
            # binding row exists -- a group with no binding at all is exactly the orphan to report.
            $wlDefs = @(Get-PimWorkloadDefinitionsOfKind -Kind 'defender')
            # REQ-U: with anything to compare, a failed role read makes this area NOT CHECKED (never "all missing").
            $__rre = "$(Get-PimDefenderRoleReadError)".Trim()
            if ($__rre -and ($desired.Count -or $wlDefs.Count)) { $ctx['__pimLiveReadError'] = "Defender XDR role definitions (Graph beta roleManagement/defender): $__rre"; return @() }
            # which group ids do we care about (the desired tags)? A live row is stamped with its group's TAG(s), so
            # desired and live share one key (Get-PimWorkloadRoleBindingKey).
            $wantGids = @{}; $gidTags = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if (-not $gid) { continue }
                $ctx['defGid'][$gt.ToLowerInvariant()] = $gid
                $gk = "$gid".ToLowerInvariant(); $wantGids[$gk] = $true
                if (-not $gidTags.ContainsKey($gk)) { $gidTags[$gk] = New-Object System.Collections.Generic.List[string] }
                if (-not $gidTags[$gk].Contains($gt)) { $gidTags[$gk].Add($gt) }
            }
            if (-not $wantGids.Count -and -not $wlDefs.Count) { return @() }
            $la = Get-PimDefenderLiveAssignments
            if (-not $la.ok) {
                Write-Warning "  [DefenderXdrRoles] assignment list failed: $($la.error)"
                $ctx['__pimLiveReadError'] = "Defender XDR role assignments (Graph beta roleManagement/defender): $($la.error)"
                return @()
            }
            $live = New-Object System.Collections.Generic.List[object]
            $asg = New-Object System.Collections.Generic.List[object]
            foreach ($a in @($la.items)) {
                $role = $cat.byId["$($a.roleDefinitionId)".ToLowerInvariant()]
                $rn = if ($role) { "$($role.name)" } else { '' }
                $asg.Add([pscustomobject]@{ id = "$($a.id)"; displayName = "$($a.displayName)"; roleName = $rn; roleDefinitionId = "$($a.roleDefinitionId)"; principals = @($a.principals); appScopeIds = @($a.appScopeIds) })
                foreach ($pp in @($a.principals)) {
                    $pk = "$pp".ToLowerInvariant(); if (-not $wantGids.ContainsKey($pk)) { continue }
                    foreach ($gt in @($gidTags[$pk])) {
                        $live.Add([pscustomobject]@{ principalId = "$pp"; GroupTag = $gt; GroupName = "$($tagToName[$gt.ToLowerInvariant()])"; Workload = 'Defender XDR'
                            RoleDefinitionName = $rn; roleDefinitionId = "$($a.roleDefinitionId)"; assignmentId = "$($a.id)"
                            appScopeIds = @($a.appScopeIds); principalCount = @($a.principals).Count; roleActions = @(if ($role) { $role.actions }) })
                    }
                }
            }
            # REQ-U wave 2 (design point 8): the live orphan warnings of this area (orphan group / unmanaged binding /
            # wrong permissions / ambiguous role). A warning that cannot be computed never fails the scope.
            try {
                $owned = Get-PimSolutionOwnedGroups
                $rel = @{}
                foreach ($d in $desired) { $t = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))".ToLowerInvariant(); if ($t) { if (-not $rel.ContainsKey($t)) { $rel[$t] = @() }; $rel[$t] += (Get-PimWorkloadRoleBindingKey -Row $d) } }
                $names = @{}; foreach ($g in @($Global:Groups_All_ID)) { if ($g -and "$($g.Id)") { $names["$($g.Id)".ToLowerInvariant()] = "$($g.DisplayName)" } }
                # REQ-W: a group whose Defender assignment is HELD by its prerequisites is "waiting", not an orphan.
                $fnd = Get-PimWorkloadLiveOrphanFindings -Kind 'defender' -Definitions $wlDefs -OwnedById $(if ($owned -and $owned.byId) { $owned.byId } else { @{} }) `
                    -Assignments @($asg.ToArray()) -SpecBindings @($desired | Where-Object { Get-PimDefenderRoleSpec -Row $_ }) -SpecGidByTag $ctx['defGid'] `
                    -Catalog $cat -NameById $names -RelatedKeysByTag $rel -HeldGate (Get-PimEngineWorkloadAssignmentGate -Workload 'DefenderXdr') -BoundTags (Get-PimWorkloadBoundTags -Kind 'defender')
                Add-PimWorkloadLiveFindings -Context $ctx -Findings @($fnd) -Scope 'DefenderXdrRoles'
            } catch { Write-Warning "  [DefenderXdrRoles] the live orphan check could not run: $($_.Exception.Message)" }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimWorkloadRoleBindingKey -Row $r }
        # A row without a spec is existence-based (the group already holds the role => nochange). A row WITH a spec
        # also compares the role's live actions and the assignment's data sources; a difference is an UPDATE.
        Equal = { param($d,$l) Test-PimDefenderBindingEqual -Desired $d -Live $l }
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['defGid'][$gt]
            $rn = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            # 🔴 REQ-W (2.4.380): a NEW Defender XDR assignment (and the custom role it would create) waits while the
            # DefenderXdr prerequisites are not green -- reported HELD, nothing written. Updates / removals are not gated.
            $__held = Get-PimWorkloadAssignmentHold -Workload 'DefenderXdr' -Context $ctx -Item $item -Scope 'DefenderXdrRoles' `
                -What ("Defender XDR role '{0}' for group '{1}'" -f $rn, $(if ("$($d.GroupName)".Trim()) { "$($d.GroupName)" } else { $gt }))
            if ($__held) { return $__held }
            if (-not $gid) { throw "DefenderXdrRoles: group for tag '$gt' not found" }
            # REQ-U wave 2: an AMBIGUOUS role name (two live roles share it) is refused -- never resolved to one of them.
            $amb = $ctx['defRoleAmbiguous']
            if ($amb -is [hashtable] -and $rn -and $amb.ContainsKey($rn.ToLowerInvariant())) {
                throw ("DEFENDER-ROLE-AMBIGUOUS: {0} live Defender XDR roles are named '{1}' (ids {2}) -- PIM will not pick one. Rename or delete the extra role in the Defender portal, then the next run binds the one that is left." -f @($amb[$rn.ToLowerInvariant()]).Count, $rn, (@($amb[$rn.ToLowerInvariant()]) -join ', '))
            }
            $spec = Get-PimDefenderRoleSpec -Row $d
            if ($spec) {
                # The custom role named like the group: created when missing, its actions PATCHed to the spec.
                $rid = Resolve-PimDefenderSpecRole -Name $rn -Actions @($spec.actions) -Catalog $ctx['defRoleCatalog']
            } else {
                $rid = $ctx['defRoleNameToId'][$rn.ToLowerInvariant()]
                if (-not $rid) { throw "DefenderXdrRoles: Defender role '$rn' not found (Unified RBAC activated? role spelled correctly?)" }
            }
            $disp = Get-PimRowProp -Row $d -Names @('AssignmentName'); if (-not $disp) { $disp = "PIM4EntraPS - $rn" }
            # BUG-222 (§33.28): this once sent '#microsoft.graph.unifiedRbacResourceNamespace' (a NAMESPACE type). The
            # 2.4.370 fix replaced it with the Graph beta example's '#microsoft.graph.unifiedRoleAssignmentMultiple' --
            # and the LIVE service refuses ANY '@odata.type' on this POST (proven 2026-09-19, see
            # New-PimDefenderAssignmentBody), so the body now carries none. appScopeIds '/' = "all and future workloads".
            # REQ-U wave 2: a spec row assigns with ITS data sources (DataSources, blank = '/'), not a hardcoded '/'.
            $scopes = if ($spec) { @($spec.dataSources) } else { @('/') }
            # 🔴 LIVE 2026-09-19: Graph answered 400 "roleAssignment: The roleAssignment field is required." to every
            # create while the body carried '@odata.type' (2.4.379 + 2.4.380, all three ring-1 tenants); without it the
            # assignment is created and answered with an insecure redirect. Body: New-PimDefenderAssignmentBody (no type,
            # directoryScopeIds ['/']); the POST + read-back: Invoke-PimDefenderAssignmentCreate.
            $body = New-PimDefenderAssignmentBody -DisplayName $disp -RoleDefinitionId $rid -PrincipalId $gid -AppScopeIds @($scopes)
            Invoke-PimDefenderAssignmentCreate -Body $body
        }
        # REQ-U wave 2: a spec'd binding whose live role or assignment differs from the spec. The role's actions are
        # PATCHed; a data-source difference is a RE-ASSIGN, removal first (never wider than asked, even for a moment).
        # An assignment shared with other principals is refused -- deleting it would take their access too.
        ApplyUpdate = {
            param($item,$ctx)
            $d = $item.desired; $l = $item.live
            $spec = Get-PimDefenderRoleSpec -Row $d
            if (-not $spec) { return [pscustomobject]@{ pimApplied = $false; reason = 'nothing to update (the row carries no role spec)' } }
            $rn = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $amb = $ctx['defRoleAmbiguous']
            if ($amb -is [hashtable] -and $rn -and $amb.ContainsKey($rn.ToLowerInvariant())) {
                throw ("DEFENDER-ROLE-AMBIGUOUS: {0} live Defender XDR roles are named '{1}' -- PIM will not pick one; rename or delete the extra role in the Defender portal." -f @($amb[$rn.ToLowerInvariant()]).Count, $rn)
            }
            $rid = Resolve-PimDefenderSpecRole -Name $rn -Actions @($spec.actions) -Catalog $ctx['defRoleCatalog']
            $out = [pscustomobject]@{ roleId = $rid; reassigned = $false }
            if (-not (Test-PimWorkloadStringSetEqual -A @($l.appScopeIds) -B @($spec.dataSources))) {
                if ([int]$l.principalCount -gt 1) {
                    throw ("DEFENDER-ASSIGNMENT-SHARED: the assignment of role '{0}' (id {1}) also holds {2} other principal(s), so it cannot be re-created with the data sources [{3}] without taking their access. Split it in the Defender portal (or give the group its own assignment), then the next run corrects it." -f $rn, $l.assignmentId, ([int]$l.principalCount - 1), (@($spec.dataSources) -join '; '))
                }
                # 🔴 OPERATOR 2026-09-20: "we can NOT have removes except if coming from operator" /
                # "any tings that maybe should be deleted must come in as warning for operator to decide,
                # newer automatic." This branch used to DELETE the live Defender assignment and re-create
                # it with the new data sources, because Graph offers no way to change appScopeIds in place.
                # It was the worst remaining case of the automatic-removal class:
                #   * nobody asked for a removal -- it was inferred from a data field differing, exactly
                #     like the withdrawn type change; and
                #   * it sits in ApplyUpdate, so the item NEVER enters $diff.remove. The per-scope removal
                #     budget could not count it, cap it or alert on it. A delete the safety ceiling cannot
                #     even see is the one an operator finds out about last.
                # It now WARNS and changes nothing. The decision is the operator's: stage an Action=Remove
                # row for this assignment and commit it, and the next run creates it with the data sources
                # the row names -- the same committed path every other removal goes through.
                $__dsMsg = ("DEFENDER-DATASOURCES-CHANGED: '{0}' is assigned for data source(s) [{1}] and the row asks for [{2}]. " +
                            "Graph cannot change them in place, so applying this would DELETE the live assignment and re-create it. " +
                            "NOTHING was changed -- PIM never removes an assignment nobody asked to remove. To apply it, stage an " +
                            "Action=Remove row for this assignment and commit it; the next run then creates it with your data sources.") -f `
                            $rn, (@($l.appScopeIds) -join '; '), (@($spec.dataSources) -join '; ')
                Write-Warning ("  [DefenderXdrRoles] " + $__dsMsg)
                if ($ctx -is [hashtable]) {
                    if (-not ($ctx['__pimScopeWarnings'] -is [System.Collections.IList])) { $ctx['__pimScopeWarnings'] = New-Object System.Collections.Generic.List[string] }
                    [void]$ctx['__pimScopeWarnings'].Add($__dsMsg)
                }
                $out.reassigned = $false
                $out | Add-Member -NotePropertyName pimApplied -NotePropertyValue $false -Force
                $out | Add-Member -NotePropertyName reason -NotePropertyValue $__dsMsg -Force
            }
            $out
        }
        ApplyRemove = {
            param($item,$ctx)
            $aid = "$($item.live.assignmentId)"
            if (-not $aid) { throw "DefenderXdrRoles: no assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Beta -Method DELETE -Path "/roleManagement/defender/roleAssignments/$aid"
        }
    }
}

# ---------------------------------------------------------------------------
# IntuneRoles scope -- delegate an Intune (Microsoft Intune / deviceManagement)
# RBAC role to a PIM GROUP, optionally bounded by Intune SCOPE TAGS. Desired =
# PIM-Assignments-Intune (GroupTag + RoleDefinitionName + optional ScopeTags
# pipe/;/,-joined names + optional MemberScope All|Tagged). Live + apply via the
# Graph Intune RBAC REST (deviceManagement/roleDefinitions + roleAssignments +
# roleScopeTags). The principal (members) is the PIM group; scope tags name the
# resource-scope boundary. Intune RBAC needs DeviceManagementRBAC.ReadWrite.All.
# ---------------------------------------------------------------------------
function Get-PimIntuneRoleKey {
    # PURE: uniform key for desired + live Intune rows -> "<groupId-or-tag>|<role>".
    param([object]$Row)
    $gid  = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName','RoleDefinitionId','roleDefinitionId')
    return ("$gid|$role").ToLowerInvariant()
}
function Get-PimIntuneRoleNameToId {
    # Live Intune role-definition NAME -> id (built-in + custom), cached per run.
    # REQ-U: a FAILED read (e.g. 403, no DeviceManagementRBAC) is recorded and NOT cached -- see Get-PimDefenderRoleNameToId.
    if ($script:__pimIntuneRoles) { return $script:__pimIntuneRoles }
    $h = @{}
    try {
        foreach ($r in @(Invoke-PimGraph -All -Path "/deviceManagement/roleDefinitions?`$select=id,displayName")) {
            $n = "$($r.displayName)"; if ($n) { $h[$n.ToLowerInvariant()] = "$($r.id)" }
        }
    } catch {
        $script:__pimIntuneRolesError = "$($_.Exception.Message)"
        Write-Warning "  [IntuneRoles] role-definition list failed (engine SPN granted DeviceManagementRBAC?): $($_.Exception.Message)"
        return $h
    }
    $script:__pimIntuneRolesError = $null
    $script:__pimIntuneRoles = $h; return $h
}
function Get-PimIntuneRoleReadError { "$($script:__pimIntuneRolesError)" }
function Get-PimIntuneScopeTagNameToId {
    # Live Intune scope-tag NAME -> id, cached per run. Used to translate the desired
    # ScopeTags (names) into the roleScopeTags ids the assignment carries.
    if ($script:__pimIntuneScopeTags) { return $script:__pimIntuneScopeTags }
    $h = @{}
    try {
        foreach ($t in @(Invoke-PimGraph -All -Path "/deviceManagement/roleScopeTags?`$select=id,displayName")) {
            $n = "$($t.displayName)"; if ($n) { $h[$n.ToLowerInvariant()] = "$($t.id)" }
        }
    } catch { Write-Verbose "Intune scope-tag list: $($_.Exception.Message)" }
    $script:__pimIntuneScopeTags = $h; return $h
}
function Resolve-PimIntuneScopeTagIds {
    # PURE-ish: desired ScopeTags (pipe/;/,-joined NAMES, or numeric ids) -> id list.
    # A name that doesn't resolve is dropped (warned). Blank -> @() (the default scope tag
    # '0' is applied by the create body so an untagged assignment still validates).
    param([string]$Raw, [hashtable]$NameToId)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @("$Raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($s -match '^\d+$') { [void]$out.Add($s); continue }
        $id = $NameToId[$s.ToLowerInvariant()]
        if ($id) { [void]$out.Add("$id") } else { Write-Warning "  [IntuneRoles] scope tag '$s' not found -- dropped" }
    }
    return $out.ToArray()
}
function New-PimIntuneRolesProvider {
    @{
        scope  = 'IntuneRoles'
        entity = 'PIM-Assignments-Intune'
        order  = 64   # after AzRes(60)/DefenderXdrRoles(62), a workload-RBAC delegation surface
        feature = 'connectors.workload'   # s29: advanced workload connector (kill switch); FREE since REQ-Y 2026-09-19
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $ctx['intTagToName'] = Get-PimTagToGroupName
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Intune' | Where-Object {
                (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and
                (Get-PimRowProp -Row $_ -Names @('GroupTag')) -and
                (Get-PimRowProp -Row $_ -Names @('RoleDefinitionName','RoleName')) })
            # REQ-U wave 2: COPIES stamped with the group's name + the workload, so a drift / failure label reads
            # "group X -> Intune role 'Y'" (the store's rows are never mutated).
            $rows = @(foreach ($r in $rows) {
                $c = [ordered]@{}
                if ($r -is [System.Collections.IDictionary]) { foreach ($k in @($r.Keys)) { $c["$k"] = $r[$k] } } else { foreach ($p in $r.PSObject.Properties) { $c[$p.Name] = $p.Value } }
                $gt0 = "$(Get-PimRowProp -Row $r -Names @('GroupTag'))"
                if (-not "$($c['GroupName'])".Trim() -and $ctx['intTagToName'] -and $ctx['intTagToName'].ContainsKey($gt0.ToLowerInvariant())) { $c['GroupName'] = "$($ctx['intTagToName'][$gt0.ToLowerInvariant()])" }
                if (-not "$($c['Workload'])".Trim()) { $c['Workload'] = 'Intune' }
                [pscustomobject]$c
            })
            $ctx['intDesired'] = $rows
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['intTagToName']) { $ctx['intTagToName'] } else { Get-PimTagToGroupName }
            $roleNameToId = Get-PimIntuneRoleNameToId
            $roleIdToName = @{}; foreach ($k in @($roleNameToId.Keys)) { $roleIdToName[$roleNameToId[$k].ToLowerInvariant()] = $k }
            $ctx['intRoleNameToId'] = $roleNameToId; $ctx['intGid'] = @{}; $ctx['intScopeTagNameToId'] = Get-PimIntuneScopeTagNameToId
            $desired = if ($null -ne $ctx['intDesired']) { @($ctx['intDesired']) } else { @(Get-PimDesiredRows -Entity 'PIM-Assignments-Intune') }
            # REQ-U wave 2: the Intune workload groups PIM defines (their bindings may live in PIM-Assignments-Workloads,
            # another scope). The orphan check needs this area's live read even when no Intune row is desired here.
            $wlDefs = @(Get-PimWorkloadDefinitionsOfKind -Kind 'intune')
            # REQ-U: with anything to compare, a failed role read (403 without DeviceManagementRBAC) is NOT CHECKED.
            $__rre = "$(Get-PimIntuneRoleReadError)".Trim()
            if ($__rre -and ($desired.Count -or $wlDefs.Count)) { $ctx['__pimLiveReadError'] = "Intune role definitions (Graph deviceManagement/roleDefinitions): $__rre"; return @() }
            # A live row is stamped with its group's TAG(s), so desired and live share one key (Get-PimWorkloadRoleBindingKey).
            $wantGids = @{}; $gidTags = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if (-not $gid) { continue }
                $ctx['intGid'][$gt.ToLowerInvariant()] = $gid
                $gk = "$gid".ToLowerInvariant(); $wantGids[$gk] = $true
                if (-not $gidTags.ContainsKey($gk)) { $gidTags[$gk] = New-Object System.Collections.Generic.List[string] }
                if (-not $gidTags[$gk].Contains($gt)) { $gidTags[$gk].Add($gt) }
            }
            if (-not $wantGids.Count -and -not $wlDefs.Count) { return @() }
            $live = New-Object System.Collections.Generic.List[object]
            $asg = New-Object System.Collections.Generic.List[object]
            try {
                # roleAssignments expand members; an Intune RBAC assignment carries the member
                # group ids in 'members' (a deviceAndAppManagementRoleAssignment).
                foreach ($a in @(Invoke-PimGraph -All -Path "/deviceManagement/roleAssignments?`$select=id,displayName,members,roleDefinition&`$expand=roleDefinition")) {
                    if ($null -eq $a) { continue }
                    $rid = "$($a.roleDefinition.id)"
                    $rn = $roleIdToName[$rid.ToLowerInvariant()]
                    if (-not $rn) { $rn = "$($a.roleDefinition.displayName)" }
                    $asg.Add([pscustomobject]@{ id = "$($a.id)"; displayName = "$($a.displayName)"; roleName = $rn; roleDefinitionId = $rid; principals = @(@($a.members) | ForEach-Object { "$_" } | Where-Object { $_ }); appScopeIds = @() })
                    foreach ($m in @($a.members)) {
                        $pk = "$m".ToLowerInvariant(); if (-not $wantGids.ContainsKey($pk)) { continue }
                        foreach ($gt in @($gidTags[$pk])) {
                            $live.Add([pscustomobject]@{ principalId = "$m"; GroupTag = $gt; GroupName = "$($tagToName[$gt.ToLowerInvariant()])"; Workload = 'Intune'
                                RoleDefinitionName = $rn; roleDefinitionId = $rid; assignmentId = "$($a.id)" })
                        }
                    }
                }
            } catch {
                Write-Warning "  [IntuneRoles] assignment list failed: $($_.Exception.Message)"
                $ctx['__pimLiveReadError'] = "Intune role assignments (Graph deviceManagement/roleAssignments): $($_.Exception.Message)"
                return @()
            }
            # REQ-U wave 2 (design point 8): the live orphan warnings of this area. Never fails the scope.
            try {
                $owned = Get-PimSolutionOwnedGroups
                $rel = @{}
                foreach ($d in $desired) { $t = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))".ToLowerInvariant(); if ($t) { if (-not $rel.ContainsKey($t)) { $rel[$t] = @() }; $rel[$t] += (Get-PimWorkloadRoleBindingKey -Row $d) } }
                $names = @{}; foreach ($g in @($Global:Groups_All_ID)) { if ($g -and "$($g.Id)") { $names["$($g.Id)".ToLowerInvariant()] = "$($g.DisplayName)" } }
                # REQ-W: a group whose Intune assignment is HELD by its prerequisites is "waiting", not an orphan.
                $fnd = Get-PimWorkloadLiveOrphanFindings -Kind 'intune' -Definitions $wlDefs -OwnedById $(if ($owned -and $owned.byId) { $owned.byId } else { @{} }) `
                    -Assignments @($asg.ToArray()) -NameById $names -RelatedKeysByTag $rel -HeldGate (Get-PimEngineWorkloadAssignmentGate -Workload 'Intune') -BoundTags (Get-PimWorkloadBoundTags -Kind 'intune')
                Add-PimWorkloadLiveFindings -Context $ctx -Findings @($fnd) -Scope 'IntuneRoles'
            } catch { Write-Warning "  [IntuneRoles] the live orphan check could not run: $($_.Exception.Message)" }
            $live.ToArray()
        }
        # REQ-U wave 2: ONE key for desired and live (the tag), so a bound role is 'nochange' instead of a create every run.
        KeyOf = { param($r) Get-PimWorkloadRoleBindingKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the Intune role)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['intGid'][$gt]
            $rn = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            # 🔴 REQ-W (2.4.380): a NEW Intune assignment waits while the Intune prerequisites are not green -- reported
            # HELD, nothing written. Removals are not gated.
            $__held = Get-PimWorkloadAssignmentHold -Workload 'Intune' -Context $ctx -Item $item -Scope 'IntuneRoles' `
                -What ("Intune role '{0}' for group '{1}'" -f $rn, $(if ("$($d.GroupName)".Trim()) { "$($d.GroupName)" } else { $gt }))
            if ($__held) { return $__held }
            $rid = $ctx['intRoleNameToId'][$rn.ToLowerInvariant()]
            if (-not $gid) { throw "IntuneRoles: group for tag '$gt' not found" }
            if (-not $rid) { throw "IntuneRoles: Intune role '$rn' not found (role spelled correctly? custom role created?)" }
            $disp = Get-PimRowProp -Row $d -Names @('AssignmentName'); if (-not $disp) { $disp = "PIM4EntraPS - $rn" }
            $scopeTags = @(Resolve-PimIntuneScopeTagIds -Raw (Get-PimRowProp -Row $d -Names @('ScopeTags','ScopeTagNames')) -NameToId $ctx['intScopeTagNameToId'])
            if (-not $scopeTags.Count) { $scopeTags = @('0') }   # default scope tag so the body validates
            # MemberScope: 'All' -> scopeType allDevicesAndLicensedUsers (org-wide); else 'resourceScope'
            # (the scope tags bound the resources). Default = Tagged when scope tags are given, else All.
            $memberScope = Get-PimRowProp -Row $d -Names @('MemberScope')
            $allScope = if ($memberScope) { $memberScope -match '(?i)all' } else { -not (Get-PimRowProp -Row $d -Names @('ScopeTags','ScopeTagNames')) }
            $body = @{
                '@odata.type'    = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
                displayName      = $disp
                description      = 'PIM4EntraPS engine'
                members          = @($gid)
                roleDefinition   = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions/$rid" }
                roleScopeTagIds  = $scopeTags
            }
            if ($allScope) { $body['scopeType'] = 'allDevicesAndLicensedUsers' } else { $body['scopeType'] = 'resourceScope'; $body['resourceScopes'] = @() }
            Invoke-PimGraph -Method POST -Path "/deviceManagement/roleDefinitions/$rid/roleAssignments" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $aid = "$($item.live.assignmentId)"
            if (-not $aid) { throw "IntuneRoles: no assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Method DELETE -Path "/deviceManagement/roleAssignments/$aid"
        }
    }
}

# ---------------------------------------------------------------------------
# EntraAppRole scope -- GENERIC enterprise-app app-role delegation. ONE pattern
# assigns a PIM GROUP to ANY enterprise application's app role via the Graph
# servicePrincipals/{resourceSpId}/appRoleAssignedTo relationship -- so every
# gallery / line-of-business app is covered without a per-app connector. Desired =
# PIM-Assignments-AppRole (GroupTag + the target app (servicePrincipal) identified
# by AppDisplayName | AppId(application id) | ServicePrincipalId | ResourceSpId,
# + AppRole value/displayName, OR the special value 'Default Access' / blank for
# the implicit no-role app-role id all-zeros GUID). The app-role VALUE is resolved
# to its id from the resource SP's appRoles collection (fail loud on an unknown
# value, like every other connector). Live + apply via Graph appRoleAssignedTo
# (POST/DELETE). Existence-based + idempotent (group already holds the app role ->
# nochange; a live assignment not desired is pruned under -Mode Full -Prune).
# RBAC: the engine SPN needs AppRoleAssignment.ReadWrite.All (or be an owner of
# each target app) to read/POST/DELETE appRoleAssignedTo.
# ---------------------------------------------------------------------------
# The implicit "default access" app role -- Graph uses an all-zeros GUID when an
# app exposes no app roles (or the assignment targets the app generally).
$script:PimAppRoleDefaultId = '00000000-0000-0000-0000-000000000000'

function Get-PimAppRoleTargetKey {
    # PURE: stable key for the TARGET app across desired (names/appId) + the cached
    # resolved id. Prefer the resolved resource SP id; else fall back to the most
    # specific identifier present (ResourceSpId/ServicePrincipalId -> AppId ->
    # AppDisplayName), so an unresolved desired row never collides with a live row.
    param([object]$Row)
    $sp = Get-PimRowProp -Row $Row -Names @('resourceSpId','ResourceSpId','ServicePrincipalId','servicePrincipalId')
    if ($sp) { return "$sp".ToLowerInvariant() }
    $appId = Get-PimRowProp -Row $Row -Names @('AppId','ApplicationId','appId')
    if ($appId) { return ('appid:' + "$appId".ToLowerInvariant()) }
    return ('app:' + (Get-PimRowProp -Row $Row -Names @('AppDisplayName','AppName','ResourceDisplayName')).ToLowerInvariant())
}
function Get-PimAppRoleKey {
    # PURE: uniform key for desired + live app-role rows -> "<group-or-tag>|<app>|<approle>".
    # Group: resolved principalId if present, else 'tag:<GroupTag>'. App: per
    # Get-PimAppRoleTargetKey. App-role: the resolved appRoleId if present, else the
    # declared value (case-insensitive) -- blank/'default access' normalise to the
    # all-zeros default id so a "default access" assignment is existence-matched.
    param([object]$Row)
    $gid = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $app = Get-PimAppRoleTargetKey -Row $Row
    $rid = Get-PimRowProp -Row $Row -Names @('appRoleId','AppRoleId')
    if ($rid) { $role = "$rid" }
    else {
        $rv = (Get-PimRowProp -Row $Row -Names @('AppRole','AppRoleValue','AppRoleName','AppRoleDisplayName')).Trim()
        if (-not $rv -or $rv -match '(?i)^default access$') { $role = $script:PimAppRoleDefaultId } else { $role = $rv }
    }
    return ("$gid|$app|$role").ToLowerInvariant()
}
function Resolve-PimAppRoleId {
    # PURE: resolve a desired app-role VALUE (or displayName) to the app-role id from
    # the resource SP's appRoles array. Blank or 'Default Access' -> the all-zeros
    # default app-role id (Graph's implicit role). A non-blank value that matches no
    # appRole.value AND no appRole.displayName THROWS -- fail loud, like the other
    # connectors (Defender/Intune role-not-found). Match is case-insensitive.
    param([string]$Value, [object[]]$AppRoles)
    $v = "$Value".Trim()
    if (-not $v -or $v -match '(?i)^default access$') { return $script:PimAppRoleDefaultId }
    foreach ($r in @($AppRoles)) {
        if ("$($r.value)" -and "$($r.value)".ToLowerInvariant() -eq $v.ToLowerInvariant()) { return "$($r.id)" }
    }
    foreach ($r in @($AppRoles)) {
        if ("$($r.displayName)" -and "$($r.displayName)".ToLowerInvariant() -eq $v.ToLowerInvariant()) { return "$($r.id)" }
    }
    throw "EntraAppRole: app role '$Value' not found on the target application (check the value/displayName against the app's exposed app roles)"
}
function New-PimAppRoleAssignmentBody {
    # PURE: the appRoleAssignedTo POST body -- principalId = the PIM group, resourceId
    # = the target app's service-principal id, appRoleId = the resolved app-role id.
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$ResourceSpId,
        [Parameter(Mandatory)][string]$AppRoleId
    )
    @{ principalId = $PrincipalId; resourceId = $ResourceSpId; appRoleId = $AppRoleId }
}
function Resolve-PimAppServicePrincipal {
    # Resolve the TARGET enterprise app's service principal (id + appRoles) from any of
    # ServicePrincipalId/ResourceSpId (object id), AppId (application id), or
    # AppDisplayName. Cached per-run by the identifier used. Returns $null on a miss
    # (caller fails loud). Module-free REST.
    param([object]$Row)
    if (-not $script:__pimAppSpCache) { $script:__pimAppSpCache = @{} }
    $spId  = Get-PimRowProp -Row $Row -Names @('resourceSpId','ResourceSpId','ServicePrincipalId','servicePrincipalId')
    $appId = Get-PimRowProp -Row $Row -Names @('AppId','ApplicationId','appId')
    $disp  = Get-PimRowProp -Row $Row -Names @('AppDisplayName','AppName','ResourceDisplayName')
    $ck = ("$spId|$appId|$disp").ToLowerInvariant()
    if ($script:__pimAppSpCache.ContainsKey($ck)) { return $script:__pimAppSpCache[$ck] }
    $sp = $null
    try {
        if ($spId) {
            $sp = Invoke-PimGraph -Path "/servicePrincipals/$spId`?`$select=id,appId,displayName,appRoles"
        } elseif ($appId) {
            $r = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appId,displayName,appRoles")
            if ($r.Count) { $sp = $r[0] }
        } elseif ($disp) {
            $esc = $disp -replace "'", "''"
            $r = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=displayName eq '$esc'&`$select=id,appId,displayName,appRoles")
            if ($r.Count) { $sp = $r[0] }
        }
    } catch { Write-Verbose "EntraAppRole SP resolve ($spId/$appId/$disp): $($_.Exception.Message)" }
    $script:__pimAppSpCache[$ck] = $sp; return $sp
}
function New-PimEntraAppRoleProvider {
    @{
        scope  = 'EntraAppRole'
        entity = 'PIM-Assignments-AppRole'
        order  = 66   # after AzRes(60)/DefenderXdrRoles(62)/IntuneRoles(64), a workload-RBAC delegation surface
        feature = 'connectors.apps'   # REQ-Y 2026-09-19: the generic app-role connector is Pro (Intune / Defender stay free)
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $ctx['appRoleTagToName'] = Get-PimTagToGroupName
            # A row is valid when it names a GROUP (GroupTag) AND a TARGET APP (one of
            # ServicePrincipalId / AppId / AppDisplayName). The app-role value may be
            # blank (-> default access). Action=Remove rows are dropped (prune handles
            # removal of live-only rows under -Mode Full -Prune).
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-AppRole' | Where-Object {
                (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and
                (Get-PimRowProp -Row $_ -Names @('GroupTag')) -and
                ( (Get-PimRowProp -Row $_ -Names @('ServicePrincipalId','servicePrincipalId','resourceSpId','ResourceSpId')) -or
                  (Get-PimRowProp -Row $_ -Names @('AppId','ApplicationId','appId')) -or
                  (Get-PimRowProp -Row $_ -Names @('AppDisplayName','AppName','ResourceDisplayName')) ) })
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['appRoleTagToName']) { $ctx['appRoleTagToName'] } else { Get-PimTagToGroupName }
            $ctx['appRoleGid'] = @{}; $ctx['appRoleSp'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-AppRole')
            # which (group, app) pairs do we care about?
            $wantGids = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if ($gid) { $ctx['appRoleGid'][$gt.ToLowerInvariant()] = $gid; $wantGids[$gid] = $true }
            }
            # resolve every distinct target app once + index its appRoles (id->value/displayName)
            $appsByKey = @{}
            foreach ($d in $desired) {
                $ak = Get-PimAppRoleTargetKey -Row $d
                if ($appsByKey.ContainsKey($ak)) { continue }
                $sp = Resolve-PimAppServicePrincipal -Row $d
                $appsByKey[$ak] = $sp
                if ($sp) { $ctx['appRoleSp'][$ak] = $sp }
            }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($ak in $appsByKey.Keys) {
                $sp = $appsByKey[$ak]; if (-not $sp -or -not $sp.id) { continue }
                try {
                    foreach ($a in @(Invoke-PimGraph -All -Path "/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=id,principalId,appRoleId,principalType")) {
                        $pp = "$($a.principalId)"; if (-not $wantGids.ContainsKey($pp)) { continue }
                        $live.Add([pscustomobject]@{ principalId=$pp; resourceSpId="$($sp.id)"; appRoleId="$($a.appRoleId)"; assignmentId="$($a.id)" })
                    }
                } catch {
                    $ctx['__pimLiveIncomplete'] = "EntraAppRole: appRoleAssignedTo could not be read for '$($sp.displayName)'"   # 2026-09-20, see AdministrativeUnitMembers
                    Write-Warning "  [EntraAppRole] appRoleAssignedTo list failed for '$($sp.displayName)' (engine SPN granted AppRoleAssignment.ReadWrite.All / app owner?): $($_.Exception.Message)"
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAppRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the app role)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['appRoleGid'][$gt]
            if (-not $gid) { throw "EntraAppRole: group for tag '$gt' not found" }
            $ak = Get-PimAppRoleTargetKey -Row $d
            $sp = $ctx['appRoleSp'][$ak]; if (-not $sp) { $sp = Resolve-PimAppServicePrincipal -Row $d }
            if (-not $sp -or -not $sp.id) { throw "EntraAppRole: target application not found ($ak) -- check AppDisplayName / AppId / ServicePrincipalId" }
            $rv = Get-PimRowProp -Row $d -Names @('AppRole','AppRoleValue','AppRoleName','AppRoleDisplayName')
            $rid = Resolve-PimAppRoleId -Value $rv -AppRoles @($sp.appRoles)
            $body = New-PimAppRoleAssignmentBody -PrincipalId $gid -ResourceSpId "$($sp.id)" -AppRoleId $rid
            Invoke-PimGraph -Method POST -Path "/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $l = $item.live
            $sp = "$($l.resourceSpId)"; $aid = "$($l.assignmentId)"
            if (-not $sp -or -not $aid) { throw "EntraAppRole: no resource SP / assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Method DELETE -Path "/servicePrincipals/$sp/appRoleAssignedTo/$aid"
        }
    }
}

# ===========================================================================
# WorkloadConnectors scope (order 67) -- PIM-Assignments-Workloads, applied the way v1 applied it.
#
# 🔴 v2 PARITY GAP (operator, 2026-09-12: "we cannot leave customers on pim v1 in a worse situation
# going to pim v2"). v1 dispatched every PIM-Assignments-Workloads row by its Workload column to a
# declarative connector (Apply-PimWorkloadAssignments, PIM-Functions.psm1 ~L2825-3004) and the CSV
# engine ran it whenever the file existed (PIM-Baseline-Management-CSV.ps1 L1426-1436). v2 shipped
# three hand-written providers over OTHER entities (Defender / Intune / AppRole, above) and nothing
# that read PIM-Assignments-Workloads -- so every row the migration imported was never applied.
#
# This provider is that dispatcher: one row -> the connector named by Workload -> resolve group, role
# and (nested-membership connectors) the container -> Assign or Remove. Runtime:
# PIM-WorkloadConnectors.ps1. Behaviour kept from v1:
#   * Action=Assign creates the binding when it is absent (idempotent).
#   * Action=Remove removes it when present: a nested-membership role is detached; a FLAT assignment
#     is deleted only when this tool created it, otherwise it is reported and left for a human.
#     Remove rows go through the core's TARGETED removal (GetRemoveRows), so they count against the
#     universal per-run removal budget like every other removal, and an absent binding is "already gone".
#   * No prune. The live set is built only from desired rows, so -Mode Full -Prune cannot reach an
#     assignment nobody wrote a row for -- v1 had no prune either.
# Changed from v1, deliberately:
#   * A row that cannot be applied (unknown connector, unresolved group, unknown role, no container,
#     a listing that failed) is a FAILURE ITEM with a catalogued code, not a red console line that
#     skipped the row. v1 printed "Skipping" and the run looked successful.
#   * An ACTIVE workload exemption (pim.Settings['WorkloadExemptions'], PIM-WorkloadMap.ps1) excuses a
#     missing Assign binding: reported, not created. An expired one no longer excuses it.
# Gate: feature 'connectors.workload', which is effectively ON whenever workload rows exist
# (PIM-FeatureCatalog.ps1 autoEnableWhenData) -- v1 was on whenever its file existed.
# ===========================================================================
# REQ-U wave 2: PIM-WorkloadRoles.ps1 = the Defender role spec, the Groups hold, live orphan warnings, workload role discovery.
# REQ-W (2.4.380): PIM-WorkloadPrereqs.ps1 carries the ONE assignment-gate rule (Get-PimWorkloadAssignmentGate) the
# workload providers apply before they create an assignment (Get-PimWorkloadAssignmentHold, PIM-WorkloadRoles.ps1).
foreach ($__pimWlFile in @('PIM-WorkloadConnectors.ps1', 'PIM-WorkloadMap.ps1', 'PIM-WorkloadRoles.ps1', 'PIM-WorkloadPrereqs.ps1')) {
    if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot $__pimWlFile))) { . (Join-Path $PSScriptRoot $__pimWlFile) }
}

function Get-PimWorkloadDesiredBindings {
    # Desired rows -> normalised bindings, split by Action: 'assign' (the desired set) and 'remove'
    # (the engine's targeted-removal rows, GetRemoveRows). One row per key within each set. A key in
    # BOTH sets is left to the engine core, which reports the conflict and removes nothing.
    # 'rows' = every normalised row (assign + remove + unsupported actions), for live resolution.
    param([object[]]$Rows = @())
    $assign = [ordered]@{}; $remove = [ordered]@{}; $other = [ordered]@{}
    $skipped = 0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $n = ConvertTo-PimWorkloadRow -Row $r
        if (-not $n) { $skipped++; continue }
        $k = Get-PimWorkloadConnectorKey -Row $n
        $bucket = if ("$($n.Action)" -ieq 'Assign') { $assign } elseif ("$($n.Action)" -ieq 'Remove') { $remove } else { $other }
        if (-not $bucket.Contains($k)) { $bucket[$k] = $n }
    }
    $toArr = { param($d) foreach ($v in $d.Values) { $v } }
    # An unsupported Action cannot be applied: it rides in the DESIRED set so it surfaces as a failure
    # item (its binding carries WORKLOAD-ACTION-UNKNOWN), instead of vanishing.
    $desired = @(& $toArr $assign) + @(& $toArr $other)
    $removeRows = @(& $toArr $remove)
    return [pscustomobject]@{ assign = $desired; remove = $removeRows; rows = @($desired + $removeRows); skipped = $skipped }
}

function New-PimWorkloadConnectorsProvider {
    @{
        scope   = 'WorkloadConnectors'
        entity  = 'PIM-Assignments-Workloads'
        order   = 67   # after the three dedicated workload providers (62/64/66)
        feature = 'connectors.workload'
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            # REQ-U wave 2: a Defender row carrying a role SPEC (Permissions) is DefenderXdrRoles' (it creates the custom
            # role this dispatcher cannot) -- Get-PimWorkloadConnectorDesiredRows leaves it out here, so it is never applied twice.
            $d = Get-PimWorkloadDesiredBindings -Rows @(Get-PimWorkloadConnectorDesiredRows -Warnings $ctx['__pimScopeWarnings'])
            if ($d.skipped) { Write-Host ("  [WorkloadConnectors] {0} row(s) lack Workload / RoleName / GroupTag and are not bindings -- ignored" -f $d.skipped) -ForegroundColor DarkGray }
            $ctx['wlcSets'] = $d
            @($d.assign)
        }
        # Action=Remove rows: the engine core removes EXACTLY the live item each one keys to, in every
        # mode, through the universal removal budget; an absent item is reported as already gone.
        GetRemoveRows = {
            param($ctx)
            $d = if ($ctx['wlcSets']) { $ctx['wlcSets'] } else { Get-PimWorkloadDesiredBindings -Rows @(Get-PimWorkloadConnectorDesiredRows) }
            @($d.remove)
        }
        GetLive = {
            param($ctx)
            $d = if ($ctx['wlcSets']) { $ctx['wlcSets'] } else { Get-PimWorkloadDesiredBindings -Rows @(Get-PimWorkloadConnectorDesiredRows) }
            $ctx['wlcSets'] = $d
            $rows = @($d.rows)
            $ctx['wlcBind'] = @{}
            if (-not $rows.Count) { return @() }
            Ensure-PimContextLoaded
            $connectors = Get-PimWorkloadConnectorCatalog
            $tagToName = @{}
            try { $tagToName = Get-PimTagToGroupName } catch { Write-Warning ("  [WorkloadConnectors] tag map unavailable, resolving GroupTag by name only: {0}" -f $_.Exception.Message) }
            $exemptions = @()
            if (Get-Command Read-PimWorkloadExemptions -ErrorAction SilentlyContinue) {
                try { $exemptions = @(Read-PimWorkloadExemptions) } catch { Write-Warning ("  [WorkloadConnectors] workload exemptions could not be read -- none applied this run: {0}" -f $_.Exception.Message) }
            }
            $cache = @{}
            $live = New-Object System.Collections.Generic.List[object]
            $seen = @{}
            $assignKeys = @{}; foreach ($a in @($d.assign)) { $assignKeys[(Get-PimWorkloadConnectorKey -Row $a)] = $true }
            foreach ($r in $rows) {
                $b = Resolve-PimWorkloadBinding -Row $r -Connectors $connectors -TagToName $tagToName -Cache $cache
                $isRemove = ("$($r.Action)" -ieq 'Remove')
                $bk = if ($isRemove) { 'remove|' } else { 'assign|' }
                $ctx['wlcBind'][$bk + $b.key] = $b
                $o = [ordered]@{ Workload = $r.Workload; GroupTag = $r.GroupTag; Resource = $r.Resource; Scope = $r.Scope; RoleName = $r.RoleName; wlcState = '' }
                if ($b.error) {
                    # Assign: no live item -> Create -> ApplyCreate raises the error as a failure item.
                    # Remove: an 'error' live item -> targeted removal -> ApplyRemove raises it the same
                    # way. Without it the core would read the row as "already absent" and succeed.
                    if ($isRemove -and -not $seen.ContainsKey($b.key) -and -not $assignKeys.ContainsKey($b.key)) { $o.wlcState = 'error'; $o['wlcError'] = $b.error; $live.Add([pscustomobject]$o); $seen[$b.key] = $true }
                    continue
                }
                if ($b.present) {
                    if ($seen.ContainsKey($b.key)) { continue }
                    $o.wlcState = 'present'
                    if ($b.existing) { $o['assignmentId'] = "$($b.existing.id)"; $o['displayName'] = "$($b.existing.displayName)" }
                    if ($b.container) { $o['container'] = "$($b.container)" }
                    $live.Add([pscustomobject]$o); $seen[$b.key] = $true
                    continue
                }
                if ($isRemove) { continue }   # nothing live: the core reports it as already absent
                foreach ($e in $exemptions) {
                    if ((Test-PimWorkloadExemptionMatches -Exemption $e -Row $r) -and (Test-PimWorkloadExemptionActive -Exemption $e)) {
                        $o.wlcState = 'exempted'; $o['exemptionReason'] = "$($e.reason)"
                        Write-Host ("    [workloads] exempted -- {0} (not created: {1})" -f $b.key, $e.reason) -ForegroundColor DarkYellow
                        if (-not $seen.ContainsKey($b.key)) { $live.Add([pscustomobject]$o); $seen[$b.key] = $true }
                        break
                    }
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimWorkloadConnectorKey -Row $r }
        # Existence-based: the binding is in place (or excused by an active exemption).
        Equal = { param($d, $l) ("$($l.wlcState)" -eq 'present' -or "$($l.wlcState)" -eq 'exempted') }
        ApplyCreate = {
            param($item, $ctx)
            # 🔴 REQ-W (2.4.380): a NEW binding waits while its connector's workload prerequisites are not green
            # (defender-xdr / intune / powerbi / azure-rbac; entra-roles and connectors with no prerequisite definition
            # are never held). Checked before the binding's own errors: an unprepared workload is the cause to report.
            $__wl = Get-PimWorkloadPrereqForConnector -Connector "$($item.desired.Workload)"
            $__held = Get-PimWorkloadAssignmentHold -Workload $__wl -Context $ctx -Item $item -Scope 'WorkloadConnectors' `
                -What ("{0} role '{1}' for group '{2}'" -f $item.desired.Workload, $item.desired.RoleName, $item.desired.GroupTag)
            if ($__held) { return $__held }
            $b = $null; if ($ctx['wlcBind']) { $b = $ctx['wlcBind']['assign|' + (Get-PimWorkloadConnectorKey -Row $item.desired)] }
            if (-not $b) { throw ("WorkloadConnectors: binding '{0}' was not resolved in this run" -f $item.key) }
            if ($b.error) { throw $b.error }
            Invoke-PimWorkloadBindingAssign -Binding $b
        }
        ApplyRemove = {
            param($item, $ctx)
            if ("$($item.live.wlcError)".Trim()) { throw "$($item.live.wlcError)" }
            $b = $null; if ($ctx['wlcBind']) { $b = $ctx['wlcBind']['remove|' + (Get-PimWorkloadConnectorKey -Row $item.live)] }
            # Only a Remove ROW removes. The live set is built from rows alone, so a prune has nothing
            # else to reach -- but if one ever did, it is refused rather than acted on.
            if (-not $b) { return [pscustomobject]@{ pimApplied = $false; reason = 'no Action=Remove row names this binding -- workload bindings are removed only by an explicit Remove row' } }
            if ($b.error) { throw $b.error }
            Invoke-PimWorkloadBindingRemove -Binding $b
        }
    }
}

# ===========================================================================
# HybridAdProvisioning scope (order 95) -- on-prem AD account + gMSA/sMSA support
# (REQUIREMENTS § 6). CLOUD-ONLY ENGINE CONSTRAINT: this provider is a PLANNER. It
# computes WHAT on-prem AD objects should exist for the AD-platform admin rows and
# emits a work package -- it NEVER imports the ActiveDirectory module or writes to a
# DC from the cloud engine. The actual on-prem write is a HYBRID-WORKER step
# (Invoke-PimHybridAdApply -Apply on a domain-joined host), flagged [ ] in DESIGN.
#
# It is read-only at collection time: GetLive returns @() (the cloud engine has no DC
# line-of-sight), so the diff is always "all desired AD rows = create-or-update intent",
# materialised as the plan + a work package the worker consumes. ApplyCreate/ApplyUpdate
# only LOG the planned on-prem action + (best-effort) write the work package; they do not
# touch AD. Gated by $global:PIM_HybridAdMode = Off (default) | Plan -- never auto-applies.
# ===========================================================================
function New-PimHybridAdProvider {
    @{
        scope  = 'HybridAdProvisioning'
        entity = 'Account-Definitions-Admins'
        order  = 95
        GetDesired = {
            param($ctx)
            $mode = "$($global:PIM_HybridAdMode)"; if (-not $mode) { $mode = 'Off' }
            $ctx['hybridAdMode'] = $mode
            if ($mode -match '(?i)^off') { return @() }
            if (-not (Get-Command Get-PimHybridAdPlan -ErrorAction SilentlyContinue)) {
                Write-Warning '  [HybridAdProvisioning] PIM-HybridAd.ps1 not loaded; skipping.'
                return @()
            }
            $admins = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
            $nc = $global:PIM_NamingConventions
            $pa  = if ($nc) { "$($nc.PathAdmins)" } else { '' }
            $pal = if ($nc) { "$($nc.PathAdminsL0T0)" } else { '' }
            $dom = "$($global:PIM_AdDomain)"
            # CLOUD-ONLY: no DC access here -> Live = @(); the plan is pure desired intent.
            $plan = Get-PimHybridAdPlan -AdminRows $admins -Live @() -PathAdmins $pa -PathAdminsL0T0 $pal -Domain $dom
            $ctx['hybridAdPlan'] = $plan
            @($plan.desired)
        }
        # No DC line-of-sight from the cloud engine -- live AD is read on the worker.
        GetLive = { param($ctx) @() }
        KeyOf = { param($r) Get-PimHybridAdDesiredKey -Record $r }
        Equal = { param($d,$l) $true }
        ApplyCreate = {
            param($item,$ctx)
            # [ ] On-prem write is HYBRID-WORKER-ONLY. The cloud engine only PLANS + logs.
            $d = $item.desired
            $kind = "$($d.accountKind)"
            Write-Host ("    [hybrid-ad/plan] would provision on worker: {0} (kind={1}, ou={2}) -- on-prem write deferred to hybrid worker" -f $d.samAccountName, $kind, $(if ($d.targetOu) { $d.targetOu } else { '<unset>' })) -ForegroundColor DarkCyan
            # Best-effort: publish the work package once per run so a worker can see the plan.
            # 🔒 #12 (2026-09-12): into SQL pim.Settings['HybridAdWorkPackage'], NOT a file under
            # output/state -- v2 is SQL-only, and a file written inside a container is gone with the
            # replica. The worker does not need it to apply: the 'hybrid-ad-apply' job plans from
            # pim.Rows itself (Invoke-PimHybridAdWorkerJob).
            if (-not $ctx['hybridAdPackageWritten'] -and $ctx['hybridAdPlan'] -and (Get-Command ConvertTo-PimHybridAdWorkPackage -ErrorAction SilentlyContinue)) {
                try {
                    $pkg = ConvertTo-PimHybridAdWorkPackage -Plan $ctx['hybridAdPlan']
                    if (Save-PimAdminLifecycleStore -Name 'HybridAdWorkPackage' -Map $pkg) {
                        Write-Host "    [hybrid-ad/plan] work package published to pim.Settings['HybridAdWorkPackage'] (the hybrid-ad-apply job on a hybrid worker applies the plan)" -ForegroundColor DarkGray
                    }
                    $ctx['hybridAdPackageWritten'] = $true
                } catch { Write-Verbose "hybrid-ad work package publish failed: $($_.Exception.Message)" }
            }
            # BUG-70 residue. THIS HANDLER NEVER PROVISIONS ANYTHING -- the on-prem write is the hybrid
            # worker's job (see the header comment), and this scope only plans + logs. It used to end on
            # the `if` above, returning nothing, and the core counted every planned account as APPLIED:
            # a run that provisioned ZERO on-prem accounts reported `applied=N`. Worse than the offboard
            # Report-mode case it mirrors, because there is no Enforce mode here to make it true later.
            # The work package is written once per RUN, so items 2..N did literally nothing at all.
            [pscustomobject]@{ pimApplied = $false; reason = 'planned only -- the on-prem write is deferred to the hybrid worker' }
        }
        ApplyUpdate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'HybridAdProvisioning').ApplyCreate $item $ctx }
    }
}

function Register-PimDefaultEngineProviders {
    if (-not (Get-Command Register-PimEngineProvider -ErrorAction SilentlyContinue)) { throw 'PIM-EngineCore.ps1 not loaded.' }
    Register-PimEngineProvider -Provider (New-PimAdministrativeUnitsProvider)   # order 10
    Register-PimEngineProvider -Provider (New-PimGroupsProvider)                # order 20
    Register-PimEngineProvider -Provider (New-PimAuMembersProvider)             # order 22 (BUG-16: AU membership is RECONCILED, not create-time-only)
    Register-PimEngineProvider -Provider (New-PimGroupOwnersProvider)           # order 25
    Register-PimEngineProvider -Provider (New-PimAdminsProvider)                # order 30
    Register-PimEngineProvider -Provider (New-PimAdminTapProvider)              # order 35
    Register-PimEngineProvider -Provider (New-PimEntraRolesProvider)            # order 40
    Register-PimEngineProvider -Provider (New-PimRolesAUsProvider)              # order 45
    Register-PimEngineProvider -Provider (New-PimEntraRolePoliciesProvider)     # order 75 -- Entra ROLE policies
    Register-PimEngineProvider -Provider (New-PimEntraRolesDirectProvider)      # order 48 (PIM v1 direct)
    Register-PimEngineProvider -Provider (New-PimAdminMembersProvider)          # order 50
    Register-PimEngineProvider -Provider (New-PimGroupMembersProvider)          # order 55
    Register-PimEngineProvider -Provider (New-PimAzResPoliciesProvider)         # order 58 -- Azure resource role policies (ARM), before AzRes assigns
    Register-PimEngineProvider -Provider (New-PimAzResProvider)                 # order 60
    Register-PimEngineProvider -Provider (New-PimDefenderXdrRolesProvider)      # order 62 (workload RBAC: Defender XDR)
    Register-PimEngineProvider -Provider (New-PimIntuneRolesProvider)           # order 64 (workload RBAC: Intune + scope tags)
    Register-PimEngineProvider -Provider (New-PimEntraAppRoleProvider)          # order 66 (generic enterprise-app app-role)
    Register-PimEngineProvider -Provider (New-PimWorkloadConnectorsProvider)    # order 67 (PIM-Assignments-Workloads, v1 connector dispatch)
    Register-PimEngineProvider -Provider (New-PimGroupsPoliciesProvider)        # order 70
    Register-PimEngineProvider -Provider (New-PimAccessReviewsProvider)         # order 80
    Register-PimEngineProvider -Provider (New-PimOffboardingProvider)           # order 90 (per-admin offboarding: disable, sessions, memberships, notice -- gated; job admin-offboarding. 71.21: PIM never deletes an account)
    Register-PimEngineProvider -Provider (New-PimGroupRetirementProvider)       # order 92 (Lifecycle=Retire groups -- gated OFF in protected tenants, as v1)
    if (Get-Command New-PimHybridAdProvider -ErrorAction SilentlyContinue) {
        Register-PimEngineProvider -Provider (New-PimHybridAdProvider)          # order 95 (on-prem AD/gMSA PLANNER; on-prem write = hybrid worker [ ])
    }
    # Notifications wired into Admins/AdminTap (new-admin/tap-delivery). Remaining for full
    # parity: admin lifecycle schedules/reminders into the REST engine -- tracked separately.
}
