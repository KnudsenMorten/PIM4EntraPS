<#
  PIM4EntraPS -- Hybrid on-prem AD provisioning + gMSA/sMSA support (REQUIREMENTS § 6).

  WHY THIS IS A PLANNER, NOT AN APPLIER
  -------------------------------------
  The new REST + SQL engine is CLOUD-ONLY at runtime: it runs headless on a Linux
  container / serverless host with NO line-of-sight to a domain controller and NO
  ActiveDirectory module. On-prem AD writes (New-ADUser / Set-ADUser, gMSA managed-
  password retrieval) can only run on a HYBRID WORKER -- a domain-joined Windows host
  with RSAT-AD and the right credential -- never from the cloud engine.

  So this module is split into two halves with a clean seam between them:

    * PLAN  (pure, offline-unit-testable, runs ANYWHERE -- cloud engine included):
        - Get-PimHybridAdAccountName  -- desired sAMAccountName (gMSA/sMSA append '$')
        - Get-PimHybridAdRowKind      -- classify a row: standard | gmsa | smsa
        - Resolve-PimHybridAdTargetOu -- OU routing from Purpose / L0-T0 name markers
        - Get-PimHybridAdSearchRoot   -- derive default LDAP searchroot/domain
        - ConvertTo-PimHybridAdDesired-- one normalised desired-state record per AD row
        - Compare-PimHybridAdState    -- idempotent diff desired vs a supplied live set
        - Get-PimHybridAdPlan         -- the full plan (create / update / nochange + skips)
        - New-PimHybridAdWorkItem     -- one serialisable work item the hybrid worker applies

    * EXECUTE (the SEAM -- an interface a HYBRID WORKER calls; the ActiveDirectory-module
      execution itself is FLAGGED [ ] -- it cannot run from the cloud engine):
        - Export-PimHybridAdWorkPackage / Import-PimHybridAdWorkPackage  -- hand-off file
        - Invoke-PimHybridAdApply  -- the worker entry point. PURE-PLANS by default;
          the real AD writes live behind -Apply + an injectable -ActiveDirectoryAdapter
          so the seam is testable with a fake adapter and the live path is the ONLY
          on-prem-bound code. Get-PimDefaultActiveDirectoryAdapter returns the real
          ActiveDirectory-module adapter (the [ ] flagged, hybrid-worker-only part).

  HYBRID-WORKER CONTRACT (documented; see DESIGN § 21.x):
    1. The cloud engine (or the Manager) produces a WORK PACKAGE with Get-PimHybridAdPlan
       + Export-PimHybridAdWorkPackage. It contains ONLY desired-state intent and the
       computed plan -- NO passwords, NO secrets, NO live AD data.
    2. A hybrid worker (domain-joined, RSAT-AD, explicit high-priv credential or gMSA)
       imports the package, reads LIVE AD, and calls Invoke-PimHybridAdApply -Apply with
       the real adapter. gMSA/sMSA managed passwords are resolved ON THE WORKER from the
       DC (msDS-ManagedPassword), never carried in the package.
    3. The worker returns a result set (created / updated / skipped / failed) that flows
       back as audit + LastApplied. The worker -- not the cloud engine -- is the only AD
       writer; the cloud engine never imports the ActiveDirectory module.

  PS 5.1-safe (no ?./??/ternary, no RSA.ImportFromPem). No new cloud-module deps.
#>

Set-StrictMode -Off

# Reuse Get-PimRowProp from PIM-EngineProviders.ps1 when present; define a local
# fallback so this module is usable / testable standalone (offline unit tests).
if (-not (Get-Command Get-PimRowProp -ErrorAction SilentlyContinue)) {
    function Get-PimRowProp {
        param([object]$Row, [string[]]$Names)
        foreach ($n in $Names) {
            if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } }
            else { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
        }
        return ''
    }
}

# ---------------------------------------------------------------------------
# PLAN layer -- pure, offline-testable, NO I/O, runs anywhere.
# ---------------------------------------------------------------------------

# Marker regex shared with the legacy CSV engine (v2.4.122): a high-priv account
# carries an -L0- / -T0- marker in the UserName, bounded by - _ . so 'Admin-SKR-L0-T0-AD'
# matches but 'L01' / 'LT0' do not.
$script:PimHybridAdHighPrivRegex = '(?i)(^|[-_.])(L0|T0)([-_.]|$)'

function Get-PimHybridAdRowKind {
    # PURE: classify an admin row -> 'gmsa' | 'smsa' | 'standard'.
    # Detection mirrors REQUIREMENTS § 6: a name containing *gMSA* / *sMSA*
    # (case-insensitive) is a managed service account. An explicit AccountKind /
    # AdAccountKind column wins over the name heuristic.
    param([Parameter(Mandatory)][object]$Row)
    $explicit = (Get-PimRowProp -Row $Row -Names @('AdAccountKind','AccountKind')).Trim()
    if ($explicit) {
        switch -regex ($explicit) {
            '(?i)^gmsa' { return 'gmsa' }
            '(?i)^smsa' { return 'smsa' }
            '(?i)^(standard|user|normal)' { return 'standard' }
        }
    }
    $name = (Get-PimRowProp -Row $Row -Names @('UserName','SamAccountName','Username','Name')).Trim()
    if ($name -match '(?i)gmsa') { return 'gmsa' }
    if ($name -match '(?i)smsa') { return 'smsa' }
    return 'standard'
}

function Get-PimHybridAdAccountName {
    # PURE: desired sAMAccountName for an AD row. gMSA/sMSA accounts MUST end in '$'
    # (REQUIREMENTS § 6 "append $"); the trailing '$' is appended idempotently so an
    # already-suffixed source name is not double-suffixed.
    param([Parameter(Mandatory)][object]$Row)
    $name = (Get-PimRowProp -Row $Row -Names @('SamAccountName','UserName','Username','Name')).Trim()
    if (-not $name) { return '' }
    $kind = Get-PimHybridAdRowKind -Row $Row
    if ($kind -eq 'gmsa' -or $kind -eq 'smsa') {
        if (-not $name.EndsWith('$')) { $name = $name + '$' }
    }
    return $name
}

function Test-PimHybridAdHighPriv {
    # PURE: does this row route to the high-priv OU? Purpose=HighPriv wins; blank
    # Purpose falls back to the L0/T0 UserName-marker check (legacy v2.4.171 contract).
    param([Parameter(Mandatory)][object]$Row)
    $purpose = (Get-PimRowProp -Row $Row -Names @('Purpose')).Trim()
    if ($purpose) { return ($purpose -ieq 'HighPriv') }
    $name = (Get-PimRowProp -Row $Row -Names @('UserName','SamAccountName','Username','Name'))
    return [bool]($name -match $script:PimHybridAdHighPrivRegex)
}

function Resolve-PimHybridAdTargetOu {
    # PURE: OU distinguished-name for a CREATE. HighPriv -> PathAdminsL0T0,
    # else PathAdmins. Returns '' when the corresponding path wasn't supplied
    # (the caller surfaces a skip -- never invents an OU).
    param(
        [Parameter(Mandatory)][object]$Row,
        [string]$PathAdmins,
        [string]$PathAdminsL0T0
    )
    if (Test-PimHybridAdHighPriv -Row $Row) { return "$PathAdminsL0T0".Trim() }
    return "$PathAdmins".Trim()
}

function Get-PimHybridAdSearchRoot {
    # PURE: derive the LDAP searchroot + domain for a gMSA/sMSA lookup. Priority:
    # an explicit SearchRoot/Domain column on the row, else the supplied -Domain,
    # else the row's UPN domain suffix. Returns @{ domain; searchRoot }.
    # (The cloud engine can COMPUTE this; only the DC read happens on the worker.)
    param(
        [object]$Row,
        [string]$Domain
    )
    $dom = ''
    if ($Row) { $dom = (Get-PimRowProp -Row $Row -Names @('Domain','AdDomain')).Trim() }
    if (-not $dom -and $Domain) { $dom = "$Domain".Trim() }
    if (-not $dom -and $Row) {
        $upn = (Get-PimRowProp -Row $Row -Names @('UserPrincipalName','UPN','upn')).Trim()
        if ($upn -match '@(.+)$') { $dom = $Matches[1] }
    }
    $explicitRoot = ''
    if ($Row) { $explicitRoot = (Get-PimRowProp -Row $Row -Names @('SearchRoot')).Trim() }
    if ($explicitRoot) { return @{ domain = $dom; searchRoot = $explicitRoot } }
    if (-not $dom) { return @{ domain = ''; searchRoot = '' } }
    $rootDn = (($dom -split '\.') | ForEach-Object { "DC=$_" }) -join ','
    return @{ domain = $dom; searchRoot = "LDAP://$rootDn" }
}

function ConvertTo-PimHybridAdDesired {
    # PURE: normalise ONE Account-Definitions-Admins row into a desired-state AD record.
    # Only rows whose TargetPlatform = AD (and not Action=Remove) are AD-provisioned;
    # everything else returns $null so the cloud engine skips it. The record is
    # serialisable (hashtable of strings) so it survives the work-package round-trip.
    param(
        [Parameter(Mandatory)][object]$Row,
        [string]$PathAdmins,
        [string]$PathAdminsL0T0,
        [string]$Domain
    )
    $platform = (Get-PimRowProp -Row $Row -Names @('TargetPlatform','Platform')).Trim()
    if ($platform -and $platform -notmatch '(?i)^ad$') { return $null }
    $action = (Get-PimRowProp -Row $Row -Names @('Action')).Trim()
    if ($action -match '(?i)^remove') { return $null }

    $sam  = Get-PimHybridAdAccountName -Row $Row
    if (-not $sam) { return $null }
    $kind = Get-PimHybridAdRowKind -Row $Row
    $upn  = (Get-PimRowProp -Row $Row -Names @('UserPrincipalName','UPN','upn')).Trim()
    $disp = (Get-PimRowProp -Row $Row -Names @('DisplayName','displayName')).Trim()
    if (-not $disp) { $disp = $sam }
    $sr   = Get-PimHybridAdSearchRoot -Row $Row -Domain $Domain

    return @{
        samAccountName    = $sam
        accountKind       = $kind                                   # standard | gmsa | smsa
        userPrincipalName = $upn
        displayName       = $disp
        givenName         = (Get-PimRowProp -Row $Row -Names @('FirstName','GivenName')).Trim()
        surname           = (Get-PimRowProp -Row $Row -Names @('LastName','Surname')).Trim()
        description       = (Get-PimRowProp -Row $Row -Names @('Description')).Trim()
        purpose           = (Get-PimRowProp -Row $Row -Names @('Purpose')).Trim()
        isHighPriv        = [bool](Test-PimHybridAdHighPriv -Row $Row)
        targetOu          = (Resolve-PimHybridAdTargetOu -Row $Row -PathAdmins $PathAdmins -PathAdminsL0T0 $PathAdminsL0T0)
        domain            = $sr.domain
        searchRoot        = $sr.searchRoot                          # used by the worker for the gMSA managed-password read
        requiresManagedPassword = ($kind -eq 'gmsa' -or $kind -eq 'smsa')
    }
}

function Get-PimHybridAdDesiredKey {
    # PURE: stable comparison key for desired + live records -> lower-cased sAMAccountName.
    param([Parameter(Mandatory)][object]$Record)
    $sam = ''
    if ($Record -is [System.Collections.IDictionary]) {
        if ($Record.Contains('samAccountName')) { $sam = "$($Record['samAccountName'])" }
        elseif ($Record.Contains('SamAccountName')) { $sam = "$($Record['SamAccountName'])" }
    } else {
        $p = $Record.PSObject.Properties['samAccountName']; if (-not $p) { $p = $Record.PSObject.Properties['SamAccountName'] }
        if ($p) { $sam = "$($p.Value)" }
    }
    return $sam.Trim().ToLowerInvariant()
}

function Test-PimHybridAdRecordEqual {
    # PURE: is the live AD object already at the desired state for the mutable
    # attributes the engine manages (DisplayName / Description / UPN / Given / Surname)?
    # gMSA/sMSA accounts are existence-only (their attributes aren't engine-managed).
    param([Parameter(Mandatory)][hashtable]$Desired, [Parameter(Mandatory)][object]$Live)
    if ($Desired.accountKind -eq 'gmsa' -or $Desired.accountKind -eq 'smsa') { return $true }
    $get = {
        param($o,$names)
        foreach ($n in $names) {
            if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return "$($o[$n])" } }
            else { $p = $o.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
        }
        return ''
    }
    $pairs = @(
        @('displayName', @('DisplayName','displayName')),
        @('description', @('Description','description')),
        @('userPrincipalName', @('UserPrincipalName','userPrincipalName')),
        @('givenName', @('GivenName','givenName')),
        @('surname', @('Surname','surname'))
    )
    foreach ($pair in $pairs) {
        $want = "$($Desired[$pair[0]])".Trim()
        $have = (& $get $Live $pair[1]).Trim()
        if ($want -ne $have) { return $false }
    }
    return $true
}

function Compare-PimHybridAdState {
    # PURE: idempotent diff -- desired AD records vs a supplied live set. Live is
    # whatever the WORKER read from AD (array of objects with at least SamAccountName).
    # Returns { create; update; nochange } (no destructive removal here -- AD account
    # deletion is a higher-priv, explicit, worker-side step, see DESIGN § 21.x).
    param(
        [hashtable[]]$Desired = @(),
        [object[]]$Live = @()
    )
    $liveMap = @{}
    foreach ($l in @($Live)) {
        if ($null -eq $l) { continue }
        $k = Get-PimHybridAdDesiredKey -Record $l
        if ($k) { $liveMap[$k] = $l }
    }
    $create = New-Object System.Collections.Generic.List[object]
    $update = New-Object System.Collections.Generic.List[object]
    $nochange = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        $k = Get-PimHybridAdDesiredKey -Record $d
        if (-not $k) { continue }
        if (-not $liveMap.ContainsKey($k)) {
            $create.Add([pscustomobject]@{ key = $k; desired = $d })
        } else {
            $l = $liveMap[$k]
            if (Test-PimHybridAdRecordEqual -Desired $d -Live $l) { $nochange.Add([pscustomobject]@{ key=$k; desired=$d; live=$l }) }
            else { $update.Add([pscustomobject]@{ key=$k; desired=$d; live=$l }) }
        }
    }
    return [pscustomobject]@{ create = $create.ToArray(); update = $update.ToArray(); nochange = $nochange.ToArray() }
}

function New-PimHybridAdWorkItem {
    # PURE: one serialisable instruction the hybrid worker applies. Op = Create | Update.
    # A Create with an empty targetOu becomes a Skip with a clear reason (mirrors the
    # legacy engine's "target OU empty" guard) -- the worker never invents an OU.
    param(
        [Parameter(Mandatory)][ValidateSet('Create','Update')][string]$Op,
        [Parameter(Mandatory)][hashtable]$Desired
    )
    $reasonSkip = ''
    if ($Op -eq 'Create' -and [string]::IsNullOrWhiteSpace("$($Desired.targetOu)")) {
        $whichPath = if ($Desired.isHighPriv) { 'PathAdminsL0T0' } else { 'PathAdmins' }
        $reasonSkip = "target OU empty (high-priv=$($Desired.isHighPriv); supply $whichPath in NamingConventions.custom.ps1)"
    }
    return [pscustomobject]@{
        op             = $(if ($reasonSkip) { 'Skip' } else { $Op })
        samAccountName = "$($Desired.samAccountName)"
        accountKind    = "$($Desired.accountKind)"
        requiresManagedPassword = [bool]$Desired.requiresManagedPassword
        targetOu       = "$($Desired.targetOu)"
        searchRoot     = "$($Desired.searchRoot)"
        domain         = "$($Desired.domain)"
        desired        = $Desired
        skipReason     = $reasonSkip
    }
}

function Get-PimHybridAdPlan {
    # PURE: the full hybrid-AD plan from definition rows + the live AD set the worker
    # read. Returns desired records, the diff, and the ordered work items (Create then
    # Update; OU-less creates demoted to Skip). Live defaults to @() so the CLOUD engine
    # can produce a "what we WANT" preview with no AD access at all.
    param(
        [object[]]$AdminRows = @(),
        [object[]]$Live = @(),
        [string]$PathAdmins,
        [string]$PathAdminsL0T0,
        [string]$Domain
    )
    $desired = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($AdminRows)) {
        if ($null -eq $r) { continue }
        $rec = ConvertTo-PimHybridAdDesired -Row $r -PathAdmins $PathAdmins -PathAdminsL0T0 $PathAdminsL0T0 -Domain $Domain
        if ($rec) { $desired.Add($rec) }
    }
    $diff = Compare-PimHybridAdState -Desired ($desired.ToArray()) -Live $Live
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($diff.create)) { $items.Add((New-PimHybridAdWorkItem -Op 'Create' -Desired $c.desired)) }
    foreach ($u in @($diff.update)) { $items.Add((New-PimHybridAdWorkItem -Op 'Update' -Desired $u.desired)) }
    return [pscustomobject]@{
        desired   = $desired.ToArray()
        diff      = $diff
        workItems = $items.ToArray()
        summary   = [pscustomobject]@{
            desired  = $desired.Count
            create   = @($items | Where-Object { $_.op -eq 'Create' }).Count
            update   = @($items | Where-Object { $_.op -eq 'Update' }).Count
            nochange = @($diff.nochange).Count
            skip     = @($items | Where-Object { $_.op -eq 'Skip' }).Count
            gmsa     = @($desired.ToArray() | Where-Object { $_.accountKind -eq 'gmsa' }).Count
            smsa     = @($desired.ToArray() | Where-Object { $_.accountKind -eq 'smsa' }).Count
        }
    }
}

# ---------------------------------------------------------------------------
# EXECUTION SEAM -- the interface a HYBRID WORKER calls. The actual on-prem
# ActiveDirectory-module writes are FLAGGED [ ] (hybrid-worker-only, cannot run
# from the cloud engine) and isolated behind an injectable adapter.
# ---------------------------------------------------------------------------

function Export-PimHybridAdWorkPackage {
    # Serialise a plan (the cloud-engine "what we want" preview) to a hand-off file the
    # hybrid worker imports. Contains ONLY desired-state intent + the plan -- NO live AD
    # data, NO passwords, NO secrets (the gMSA managed password is read on the worker).
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$Path
    )
    $pkg = [ordered]@{
        kind        = 'PimHybridAdWorkPackage'
        version     = 1
        createdUtc  = ([datetime]::UtcNow.ToString('o'))
        summary     = $Plan.summary
        workItems   = $Plan.workItems
    }
    $json = $pkg | ConvertTo-Json -Depth 12
    # PS 5.1 Set-Content defaults to UTF-16; force UTF8 so the worker reads it cleanly.
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

function Import-PimHybridAdWorkPackage {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Hybrid-AD work package not found: $Path" }
    $raw = [System.IO.File]::ReadAllText($Path)
    $pkg = $raw | ConvertFrom-Json
    if ("$($pkg.kind)" -ne 'PimHybridAdWorkPackage') { throw "Not a PimHybridAdWorkPackage: $Path" }
    return $pkg
}

function Get-PimDefaultActiveDirectoryAdapter {
    <#
      [ ] HYBRID-WORKER-ONLY -- NOT runnable from the cloud engine.

      Returns the REAL adapter the worker uses: a hashtable of scriptblocks that wrap the
      ActiveDirectory module (Get-ADUser / New-ADUser / Set-ADUser) + gMSA managed-password
      retrieval. This is the ONLY on-prem-bound code; everything above is pure + testable.
      The cloud engine never calls this (no ActiveDirectory module, no DC line-of-sight) --
      it produces the work package; the worker supplies this adapter to Invoke-PimHybridAdApply.

      The adapter is intentionally thin so Invoke-PimHybridAdApply (the orchestration) stays
      testable with a FAKE adapter; only these scriptblocks touch AD.
    #>
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        throw 'ActiveDirectory module not available -- Get-PimDefaultActiveDirectoryAdapter is hybrid-worker-only (domain-joined host with RSAT-AD). The cloud engine must export a work package instead.'
    }
    return @{
        # Read live AD users by sAMAccountName (explicit -Credential, NOT ambient SYSTEM).
        GetUser = {
            param($Sam, $Credential)
            $p = @{ Filter = "SamAccountName -eq '$Sam'"; Properties = @('DisplayName','Description','UserPrincipalName','GivenName','Surname') }
            if ($Credential) { $p['Credential'] = $Credential }
            Get-ADUser @p -ErrorAction Stop
        }
        # Create a standard AD user account in the routed OU with an explicit credential.
        NewUser = {
            param($Item, $Credential, $AccountPassword)
            $d = $Item.desired
            $p = @{
                Name = $d.samAccountName; SamAccountName = $d.samAccountName
                GivenName = $d.givenName; Surname = $d.surname; DisplayName = $d.displayName
                Description = $d.description; EmailAddress = $d.userPrincipalName
                UserPrincipalName = $d.userPrincipalName; Path = $d.targetOu
                AccountPassword = $AccountPassword; Enabled = $true; ErrorAction = 'Stop'
            }
            if ($Credential) { $p['Credential'] = $Credential }
            New-ADUser @p
        }
        # Update mutable attributes on an existing account.
        SetUser = {
            param($Item, $Live, $Credential)
            $d = $Item.desired
            $p = @{
                Identity = $Live; GivenName = $d.givenName; Surname = $d.surname
                DisplayName = $d.displayName; Description = $d.description
                EmailAddress = $d.userPrincipalName; UserPrincipalName = $d.userPrincipalName; ErrorAction = 'Stop'
            }
            if ($Credential) { $p['Credential'] = $Credential }
            Set-ADUser @p
        }
        # Resolve a gMSA/sMSA managed password from the DC (msDS-ManagedPassword). On the
        # worker this would delegate to AutomateITPS.AD\Get-GMSACredential. gMSA/sMSA
        # accounts are not created via New-ADUser by this engine -- they are pre-created
        # (New-ADServiceAccount) and this resolves the credential for downstream use.
        GetManagedCredential = {
            param($Item, $Context)
            if (Get-Command Get-GMSACredential -ErrorAction SilentlyContinue) {
                return Get-GMSACredential -Context $Context -GMSAName $Item.samAccountName -Domain $Item.domain -SearchRoot $Item.searchRoot
            }
            throw 'Get-GMSACredential (AutomateITPS.AD) not loaded on this worker; cannot resolve managed password.'
        }
    }
}

function Invoke-PimHybridAdApply {
    <#
      The hybrid-worker entry point + the execution seam.

      WHEN -Apply IS NOT SET (default): PURE plan/preview -- returns the result rows
      with status 'plan' and writes NOTHING. Safe to run from the cloud engine, in CI,
      and in offline unit tests. This is what the cloud engine uses to log intent.

      WHEN -Apply IS SET: the worker applies via the supplied -ActiveDirectoryAdapter:
        * Create (standard)  -> adapter.NewUser   (explicit -Credential, real error surfaced)
        * Update             -> adapter.SetUser
        * gMSA/sMSA          -> existence-only; managed password resolved via
                                adapter.GetManagedCredential (NOT created by New-ADUser)
        * Skip               -> reported, never applied
      A row whose live read fails surfaces the REAL error (no false "Updating AD user")
      and is reported as 'failed' -- it does not cascade into a create.

      If -Apply is set WITHOUT an adapter, the real adapter is fetched with
      Get-PimDefaultActiveDirectoryAdapter -- which THROWS off a non-domain-joined host.
      This is the [ ] flagged boundary: the cloud engine can never accidentally write AD.
    #>
    param(
        [Parameter(Mandatory)][object]$Plan,                 # from Get-PimHybridAdPlan / Import-PimHybridAdWorkPackage
        [switch]$Apply,
        [hashtable]$ActiveDirectoryAdapter,                  # injected on the worker; fake in tests
        [System.Management.Automation.PSCredential]$Credential,
        [object]$Context,                                    # for gMSA credential resolution on the worker
        [scriptblock]$NewPassword                            # () -> SecureString for standard-account create
    )
    $items = @($Plan.workItems)
    $results = New-Object System.Collections.Generic.List[object]

    if ($Apply) {
        if (-not $ActiveDirectoryAdapter) { $ActiveDirectoryAdapter = Get-PimDefaultActiveDirectoryAdapter }
        if (-not $Credential) {
            # Mirror the legacy contract: without an explicit AD credential, skip the AD
            # branch and SAY SO (never fall back to ambient SYSTEM silently).
            foreach ($it in $items) {
                $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op=$it.op; status='skipped'; reason='no explicit AD credential supplied -- AD branch skipped (never runs as ambient SYSTEM)' })
            }
            return [pscustomobject]@{ applied=$false; results=$results.ToArray() }
        }
    }

    foreach ($it in $items) {
        if ($it.op -eq 'Skip') {
            $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Skip'; status='skipped'; reason=$it.skipReason })
            continue
        }
        if (-not $Apply) {
            $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op=$it.op; status='plan'; reason='' })
            continue
        }
        try {
            if ($it.requiresManagedPassword) {
                # gMSA/sMSA: existence-only here. Resolve the managed credential from the DC
                # (the [ ] flagged read) so downstream consumers can use it; never New-ADUser.
                $cred = & $ActiveDirectoryAdapter.GetManagedCredential $it $Context
                $ok = [bool]$cred
                $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op=$it.op; status=$(if ($ok) {'resolved'} else {'failed'}); reason='gMSA/sMSA managed credential resolved from DC (existence-only; not created by New-ADUser)' })
                continue
            }
            # Standard account: read live first; a failed read does NOT cascade to create.
            $live = $null
            try { $live = & $ActiveDirectoryAdapter.GetUser $it.samAccountName $Credential } catch { throw "Get-ADUser failed for $($it.samAccountName) with credential '$($Credential.UserName)': $($_.Exception.Message)" }
            if ($live) {
                & $ActiveDirectoryAdapter.SetUser $it $live $Credential | Out-Null
                $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Update'; status='updated'; reason='' })
            } else {
                $pw = $null
                if ($NewPassword) { $pw = & $NewPassword }
                & $ActiveDirectoryAdapter.NewUser $it $Credential $pw | Out-Null
                $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Create'; status='created'; reason="OU: $($it.targetOu)" })
            }
        } catch {
            # Surface the REAL error (no false "Updating AD user").
            $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op=$it.op; status='failed'; reason=$_.Exception.Message })
        }
    }
    return [pscustomobject]@{ applied=[bool]$Apply; results=$results.ToArray() }
}
