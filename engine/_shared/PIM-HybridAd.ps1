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

# Customer naming (operator 2026-09-13: "remember to use naming as customer can choose their own
# naming"). Every admin-name shape on the AD path comes from the naming conventions in pim.Settings
# (hydrated into $global:PIM_NamingConventions) through the SAME helpers the Entra path and the
# Manager use -- nothing here hard-codes a '-AD' suffix, an 'Admin-' prefix or a level/tier marker.
if (-not (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue)) {
    $__pimNamingLib = Join-Path $PSScriptRoot 'PIM-Naming.ps1'
    if (Test-Path -LiteralPath $__pimNamingLib) { . $__pimNamingLib }
}

# ---------------------------------------------------------------------------
# PLAN layer -- pure, offline-testable, NO I/O, runs anywhere.
# ---------------------------------------------------------------------------

function Test-PimHybridAdRowIsAd {
    # PURE. An on-premises AD admin is identified by its row: TargetPlatform = AD (v1: `$TargetPlatform
    # -eq "AD"`, PIM-Functions.psm1 5824). Never by a name shape. A blank platform is NOT AD.
    param([Parameter(Mandatory)][object]$Row)
    return ((Get-PimRowProp -Row $Row -Names @('TargetPlatform','Platform')).Trim() -ieq 'AD')
}

function Get-PimHybridAdNamingValue {
    # One reader for an AD naming setting (PathAdmins, PathAdminsL0T0, ...): the naming conventions
    # (pim.Settings, hydrated) first, then v1's $global:<Name> back-compat (PIM-Baseline-Management-CSV.ps1
    # 341-364 used exactly this order). Returns '' when unset.
    param([Parameter(Mandatory)][string]$Name)
    $v = $null
    if (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { $v = Get-PimNamingConvention -Key $Name }
    elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) { $v = $global:PIM_NamingConventions[$Name] }
    if (-not "$v".Trim()) { $v = Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    return "$v".Trim()
}

function Resolve-PimHybridAdIdentity {
    # PURE. The names an AD admin row is created/maintained under. v1 took UserName / UserPrincipalName /
    # DisplayName from the row (New-ADUser -Name $UserName, PIM-Functions.psm1 5911), so the ROW wins.
    # A value the row leaves blank is DERIVED from the customer's naming conventions with the Manager's
    # own generator (Resolve-PimAdminName -Environment ad), never from a hard-coded shape.
    param([Parameter(Mandatory)][object]$Row)
    $userName = (Get-PimRowProp -Row $Row -Names @('UserName','SamAccountName','Username','Name')).Trim()
    $upn      = (Get-PimRowProp -Row $Row -Names @('UserPrincipalName','UPN','upn')).Trim()
    $disp     = (Get-PimRowProp -Row $Row -Names @('DisplayName','displayName')).Trim()
    $derived  = @()
    if ((-not $userName -or -not $upn) -and (Get-Command Resolve-PimAdminName -ErrorAction SilentlyContinue)) {
        $owner = (Get-PimRowProp -Row $Row -Names @('Initials','Owner','Initial')).Trim()
        if ($owner) {
            $hp = ((Get-PimRowProp -Row $Row -Names @('Purpose')).Trim() -ieq 'HighPriv')
            $gen = Resolve-PimAdminName -Owner $owner -AdminType (Get-PimRowProp -Row $Row -Names @('AdminType')) -Environment 'ad' -HighPriv:$hp `
                                        -Company (Get-PimRowProp -Row $Row -Names @('Company'))   # {Company} (2026-09-21)
            $local = "$gen"; $suffixed = ''
            if ($local -match '^([^@]+)@(.+)$') { $local = $Matches[1]; $suffixed = "$gen" }
            if (-not $userName) { $userName = $local; $derived += 'UserName' }
            if (-not $upn -and $suffixed) { $upn = $suffixed; $derived += 'UserPrincipalName' }
        }
    }
    if (-not $disp) {
        $fn = (Get-PimRowProp -Row $Row -Names @('FirstName','GivenName')).Trim()
        $ln = (Get-PimRowProp -Row $Row -Names @('LastName','Surname')).Trim()
        $suffix = if (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue) { "$(Get-PimNamingConvention -Key 'AdminAccountDisplayNameSuffix')" } else { '' }
        $person = (@($fn, $ln) | Where-Object { $_ }) -join ' '
        $disp = if ($person) { "$person$suffix" } else { $userName }
        if ($disp) { $derived += 'DisplayName' }
    }
    return [pscustomobject]@{ userName = $userName; userPrincipalName = $upn; displayName = $disp; derived = $derived }
}

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
    if (-not $name) { $name = "$((Resolve-PimHybridAdIdentity -Row $Row).userName)".Trim() }
    if (-not $name) { return '' }
    $kind = Get-PimHybridAdRowKind -Row $Row
    if ($kind -eq 'gmsa' -or $kind -eq 'smsa') {
        if (-not $name.EndsWith('$')) { $name = $name + '$' }
    }
    return $name
}

function Test-PimHybridAdHighPriv {
    # PURE: does this row route to the high-priv OU? v1 (PIM-Functions.psm1 5900-5903): Purpose=HighPriv
    # is the selector; a blank Purpose falls back to "does the UserName look like the high-priv admin
    # convention". v1 hard-coded that look as an L0/T0 marker regex; here it is the CUSTOMER's high-priv
    # pattern (AdminAccountPatternHighPriv), so a tenant that names its tier-0 admins differently routes
    # correctly. With the shipped default pattern ('{AdminWord}-{Initial}-L0-T0{Platform}') the result is
    # the same as v1's marker check. When the high-priv and day-2-day patterns are identical the name
    # cannot tell them apart, so only Purpose can.
    param([Parameter(Mandatory)][object]$Row)
    $purpose = (Get-PimRowProp -Row $Row -Names @('Purpose')).Trim()
    if ($purpose) { return ($purpose -ieq 'HighPriv') }
    $name = "$((Resolve-PimHybridAdIdentity -Row $Row).userName)".Trim()
    if (-not $name) { return $false }
    if ($name -match '@') { $name = $name.Split('@')[0] }
    if (-not (Get-Command ConvertTo-PimAdminNameRegex -ErrorAction SilentlyContinue)) { return $false }
    $hpPat  = "$(Get-PimNamingConvention -Key 'AdminAccountPatternHighPriv')".Trim()
    $d2dPat = "$(Get-PimNamingConvention -Key 'AdminAccountPattern')".Trim()
    if (-not $hpPat -or $hpPat -ieq $d2dPat) { return $false }
    return [bool]((ConvertTo-PimAdminNameRegex -Pattern $hpPat).IsMatch($name))
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
    # Only TargetPlatform=AD rows are AD-provisioned. A BLANK platform used to count as AD here (the
    # planner would have handed an Entra admin to the hybrid worker); v1 required "AD" exactly.
    if (-not (Test-PimHybridAdRowIsAd -Row $Row)) { return $null }
    $action = (Get-PimRowProp -Row $Row -Names @('Action')).Trim()
    if ($action -match '(?i)^remove') { return $null }

    $sam  = Get-PimHybridAdAccountName -Row $Row
    if (-not $sam) { return $null }
    $kind = Get-PimHybridAdRowKind -Row $Row
    $id   = Resolve-PimHybridAdIdentity -Row $Row
    $upn  = "$($id.userPrincipalName)".Trim()
    $disp = "$($id.displayName)".Trim()
    if (-not $disp) { $disp = $sam }
    $sr   = Get-PimHybridAdSearchRoot -Row $Row -Domain $Domain
    # v1: -Description $Description where $Description = $DisplayName (PIM-Functions.psm1 5643, 5881, 5915).
    # An explicit Description column still wins.
    $descr = (Get-PimRowProp -Row $Row -Names @('Description')).Trim()
    if (-not $descr) { $descr = $disp }
    # Where the initial password is mailed -- the ONE admin-mail recipient rule (office user email,
    # else manager). An address, not a secret, so it may travel in the work package.
    $rcpt = ''
    if (Get-Command Get-PimAdminMailRecipient -ErrorAction SilentlyContinue) { try { $rcpt = "$(Get-PimAdminMailRecipient -Row $Row)".Trim() } catch { $rcpt = '' } }

    return @{
        samAccountName    = $sam
        accountKind       = $kind                                   # standard | gmsa | smsa
        userPrincipalName = $upn
        emailAddress      = $upn                                    # v1: -EmailAddress $UserPrincipalName
        displayName       = $disp
        mailRecipient     = $rcpt
        givenName         = (Get-PimRowProp -Row $Row -Names @('FirstName','GivenName')).Trim()
        surname           = (Get-PimRowProp -Row $Row -Names @('LastName','Surname')).Trim()
        description       = $descr
        purpose           = (Get-PimRowProp -Row $Row -Names @('Purpose')).Trim()
        isHighPriv        = [bool](Test-PimHybridAdHighPriv -Row $Row)
        targetOu          = (Resolve-PimHybridAdTargetOu -Row $Row -PathAdmins $PathAdmins -PathAdminsL0T0 $PathAdminsL0T0)
        domain            = $sr.domain
        searchRoot        = $sr.searchRoot                          # used by the worker for the gMSA managed-password read
        requiresManagedPassword = ($kind -eq 'gmsa' -or $kind -eq 'smsa')
    }
}

function Get-PimHybridAdDesiredValue {
    # PURE: one field of a desired record, whether it is a hashtable (fresh plan) or a PSCustomObject
    # (a work package round-tripped through JSON / SQL).
    param([object]$Desired, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Desired) { return '' }
    if ($Desired -is [System.Collections.IDictionary]) { if ($Desired.Contains($Name)) { return "$($Desired[$Name])" }; return '' }
    $p = $Desired.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)" }
    return ''
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
    # PURE: is the live AD object already at the desired state for the attributes v1 wrote on every
    # update (Set-ADUser -GivenName -Surname -DisplayName -Description -EmailAddress -UserPrincipalName,
    # PIM-Functions.psm1 5878-5884)? gMSA/sMSA accounts are existence-only.
    # Two rules, the same the Entra attribute plan uses (Get-PimAdminAttributePlan):
    #   * a BLANK desired value is not managed -- the row said nothing about it (v1 cleared the
    #     attribute; v2 never erases directory data the row did not name);
    #   * a property the live object does not CARRY was not observed. For a PLAN it is not compared;
    #     before a WRITE (-UnobservedIsDifferent) "cannot prove equal" means write.
    param([Parameter(Mandatory)][object]$Desired, [Parameter(Mandatory)][object]$Live, [switch]$UnobservedIsDifferent)
    $kind = Get-PimHybridAdDesiredValue -Desired $Desired -Name 'accountKind'
    if ($kind -eq 'gmsa' -or $kind -eq 'smsa') { return $true }
    $get = {
        param($o,$names)
        foreach ($n in $names) {
            if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return @{ has = $true; v = "$($o[$n])" } } }
            else { $p = $o.PSObject.Properties[$n]; if ($p) { return @{ has = $true; v = "$($p.Value)" } } }
        }
        return @{ has = $false; v = '' }
    }
    $pairs = @(
        @('displayName', @('DisplayName','displayName')),
        @('description', @('Description','description')),
        @('userPrincipalName', @('UserPrincipalName','userPrincipalName')),
        @('emailAddress', @('EmailAddress','emailAddress','mail')),
        @('givenName', @('GivenName','givenName')),
        @('surname', @('Surname','surname'))
    )
    foreach ($pair in $pairs) {
        $want = (Get-PimHybridAdDesiredValue -Desired $Desired -Name $pair[0]).Trim()
        if (-not $want) { continue }
        $have = & $get $Live $pair[1]
        if (-not $have.has) { if ($UnobservedIsDifferent) { return $false } else { continue } }
        if ($want -cne "$($have.v)".Trim()) { return $false }
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
        $reasonSkip = "target OU empty (high-priv=$($Desired.isHighPriv); set $whichPath in the naming settings)"
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

function ConvertTo-PimHybridAdWorkPackage {
    # PURE. The same package Export-PimHybridAdWorkPackage writes, as a hashtable -- so the engine
    # can publish it into SQL (pim.Settings['HybridAdWorkPackage']) instead of a file. v2 is
    # SQL-only (operator, 2026-09-12); the file functions remain for a worker that is handed one.
    param([Parameter(Mandatory)][object]$Plan)
    return @{
        kind       = 'PimHybridAdWorkPackage'
        version    = 1
        createdUtc = ([datetime]::UtcNow.ToString('o'))
        summary    = $Plan.summary
        workItems  = @($Plan.workItems)
    }
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
        # Read the live AD user. v1 looked the account up by UPN (Get-ADUser -Filter
        # 'UserPrincipalName -eq $UserPrincipalName', PIM-Functions.psm1 5849); a row without a UPN
        # falls back to the sAMAccountName. Explicit -Credential, NOT ambient SYSTEM; -ErrorAction Stop
        # so an auth/DC fault is an error, never "not found" (v1's hard-fail, 5840-5870).
        GetUser = {
            param($Sam, $Credential, $Upn)
            $props = @('DisplayName','Description','UserPrincipalName','GivenName','Surname','EmailAddress','Enabled')
            $p = if ("$Upn".Trim()) { @{ Filter = "UserPrincipalName -eq '$("$Upn".Trim().Replace("'", "''"))'"; Properties = $props } }
                 else { @{ Filter = "SamAccountName -eq '$("$Sam".Replace("'", "''"))'"; Properties = $props } }
            if ($Credential) { $p['Credential'] = $Credential }
            Get-ADUser @p -ErrorAction Stop
        }
        # Create a standard AD user in the routed OU (v1 New-ADUser, 5911-5922): -Name = the account name,
        # given/surname/display/description, -AccountPassword, -EmailAddress = UPN, -UserPrincipalName,
        # -Path, -Enabled. v1 set no PasswordNeverExpires and no ChangePasswordAtLogon; neither does this.
        # A blank attribute is omitted (New-ADUser rejects an empty string for most of them).
        NewUser = {
            param($Item, $Credential, $AccountPassword)
            $d = $Item.desired
            $p = @{ Name = $d.samAccountName; SamAccountName = $d.samAccountName; Path = $d.targetOu; AccountPassword = $AccountPassword; Enabled = $true; ErrorAction = 'Stop' }
            foreach ($pair in @(@('GivenName','givenName'), @('Surname','surname'), @('DisplayName','displayName'), @('Description','description'), @('EmailAddress','emailAddress'), @('UserPrincipalName','userPrincipalName'))) {
                $v = "$(Get-PimHybridAdDesiredValue -Desired $d -Name $pair[1])".Trim(); if ($v) { $p[$pair[0]] = $v }
            }
            if ($Credential) { $p['Credential'] = $Credential }
            New-ADUser @p
        }
        # Update the attributes v1 updated (Set-ADUser, 5878-5884). A blank desired value is not written.
        SetUser = {
            param($Item, $Live, $Credential)
            $d = $Item.desired
            $p = @{ Identity = $Live; ErrorAction = 'Stop' }
            foreach ($pair in @(@('GivenName','givenName'), @('Surname','surname'), @('DisplayName','displayName'), @('Description','description'), @('EmailAddress','emailAddress'), @('UserPrincipalName','userPrincipalName'))) {
                $v = "$(Get-PimHybridAdDesiredValue -Desired $d -Name $pair[1])".Trim(); if ($v) { $p[$pair[0]] = $v }
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
        [scriptblock]$NewPassword,                           # () -> SecureString for standard-account create (no delivery)
        # v1 parity for the initial password (AD admins have no TAP -- "password only"). v1 generated a
        # random password per new account and handed it to the operator (PIM-Functions.psm1 5639-5641,
        # 5935-5937). v2 stores and logs NOTHING, so the password is MAILED to the admin-mail recipient:
        #   -DeliverPassword       ($Item, [string]$PlainPassword) -> @{ sent; reason }
        #   -PasswordDeliveryReady ($Item) -> @{ ok; reason }   checked BEFORE the account is created
        #   -NewPlainPassword      () -> [string]               default New-PimAdminInitialPassword -Length 24 (v1's length)
        # When -DeliverPassword is given, a create that cannot deliver its password is HELD (skipped), and a
        # create whose delivery then fails is reported FAILED -- an account nobody can sign in to is never
        # reported as a success.
        [scriptblock]$DeliverPassword,
        [scriptblock]$PasswordDeliveryReady,
        [scriptblock]$NewPlainPassword
    )
    $items = @($Plan.workItems)
    $results = New-Object System.Collections.Generic.List[object]
    $upnOf = { param($it) Get-PimHybridAdDesiredValue -Desired $it.desired -Name 'userPrincipalName' }
    # Read -> compare -> write only when different (v1 wrote every run; the result is the same state).
    $maintain = {
        param($it, $live)
        if (Test-PimHybridAdRecordEqual -Desired $it.desired -Live $live -UnobservedIsDifferent) {
            return [pscustomobject]@{ samAccountName=$it.samAccountName; op='Update'; status='nochange'; reason='' }
        }
        & $ActiveDirectoryAdapter.SetUser $it $live $Credential | Out-Null
        return [pscustomobject]@{ samAccountName=$it.samAccountName; op='Update'; status='updated'; reason='' }
    }

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
            # v1 (PIM-Baseline-Management-CSV.ps1 373-380): with no OU configured "updates still go
            # through; only Create needs the OU". A Skip for a missing OU therefore still UPDATES an
            # account that already exists -- only the create is skipped.
            if ($Apply -and "$($it.skipReason)" -match '^target OU empty' -and -not $it.requiresManagedPassword) {
                try {
                    $liveS = & $ActiveDirectoryAdapter.GetUser $it.samAccountName $Credential (& $upnOf $it)
                    if ($liveS) {
                        $rS = & $maintain $it $liveS
                        $rS.reason = 'no OU configured -- existing account maintained, create skipped'
                        $results.Add($rS)
                        continue
                    }
                } catch {
                    $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Update'; status='failed'; reason=$_.Exception.Message })
                    continue
                }
            }
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
            try { $live = & $ActiveDirectoryAdapter.GetUser $it.samAccountName $Credential (& $upnOf $it) } catch { throw "Get-ADUser failed for $($it.samAccountName) with credential '$($Credential.UserName)': $($_.Exception.Message)" }
            if ($live) {
                $results.Add((& $maintain $it $live))
            } elseif ($DeliverPassword) {
                if ($PasswordDeliveryReady) {
                    $ready = & $PasswordDeliveryReady $it
                    if (-not $ready -or -not $ready.ok) {
                        $why = if ($ready) { "$($ready.reason)" } else { 'no answer from the delivery check' }
                        $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Create'; status='skipped'; reason="create HELD: its initial password could not be delivered -- $why" })
                        continue
                    }
                }
                $plain = if ($NewPlainPassword) { "$(& $NewPlainPassword)" } elseif (Get-Command New-PimAdminInitialPassword -ErrorAction SilentlyContinue) { New-PimAdminInitialPassword -Length 24 } else { [guid]::NewGuid().ToString('N').Substring(0, 20) + 'Aa9!' }
                $sec = New-Object System.Security.SecureString
                foreach ($ch in $plain.ToCharArray()) { $sec.AppendChar($ch) }
                $sec.MakeReadOnly()
                try {
                    & $ActiveDirectoryAdapter.NewUser $it $Credential $sec | Out-Null
                } catch { $plain = $null; throw }
                $sent = $null
                try { $sent = & $DeliverPassword $it $plain } catch { $sent = @{ sent = $false; reason = "$($_.Exception.Message)" } }
                $plain = $null
                if ($sent -and "$($sent.sent)" -match '(?i)^true$') {
                    $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Create'; status='created'; reason="OU: $($it.targetOu); initial password mailed to the admin-mail recipient" })
                } else {
                    $why = if ($sent) { "$($sent.reason)" } else { 'no answer from the delivery' }
                    $results.Add([pscustomobject]@{ samAccountName=$it.samAccountName; op='Create'; status='failed'; reason="account CREATED in $($it.targetOu), but its initial password could NOT be delivered ($why) -- reset the password in AD" })
                }
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

# ---------------------------------------------------------------------------
# THE SCHEDULED HYBRID WORKER JOB (#12, 2026-09-12). Until now nothing ever called
# Invoke-PimHybridAdApply -Apply: the cloud provider planned, and on-prem AD accounts -- which v1
# created and updated on every CSV-engine run (PIM-Functions.psm1 5824-5938, launcher condition
# PIM-Baseline-Management-CSV.ps1 367-389) -- were silently never provisioned.
#
# The job 'hybrid-ad-apply' runs this on every scheduler worker. v1's condition is kept exactly:
# it applies only where the ActiveDirectory module AND an AD credential exist. Anywhere else (every
# container) it does not plan quietly -- it reports that a HYBRID WORKER is required, naming how
# many AD rows are waiting, so the gap is visible in the Jobs list instead of looking like success.
# A hybrid worker is a domain-joined Windows host running the scheduler scoped to this job
# (Start-PimScheduler.ps1 -Jobs hybrid-ad-apply), with its SQL coordinates.
# ---------------------------------------------------------------------------
function Resolve-PimHybridAdCredential {
    # The explicit AD credential, never ambient SYSTEM. Sources, in order:
    #   1. $global:PIM_HybridAdCredential                     (a PSCredential the worker launcher set)
    #   2. $global:Context.Identity.Legacy.Internal.Prod      (v1's platform identity on the same host)
    #   3. Key Vault: settings HybridAdCredentialVault + HybridAdCredentialUserSecret +
    #      HybridAdCredentialPasswordSecret (v1: Legacy-UserName-Internal-Prod / -Password-), read
    #      through -SecretReader, $global:PIM_HybridAdSecretReader, or Get-PimSqlSecretFromKeyVault.
    # Returns @{ credential; source } -- credential $null when none. Never logs a secret.
    param([scriptblock]$SecretReader)
    if ($global:PIM_HybridAdCredential -is [System.Management.Automation.PSCredential]) {
        return [pscustomobject]@{ credential = $global:PIM_HybridAdCredential; source = 'PIM_HybridAdCredential' }
    }
    try {
        $legacy = $global:Context.Identity.Legacy.Internal.Prod
        if ($legacy -is [System.Management.Automation.PSCredential]) { return [pscustomobject]@{ credential = $legacy; source = 'Context.Identity.Legacy.Internal.Prod' } }
    } catch { }
    $get = { param($n) $v = $null; if (Get-Command Get-PimAdminLifecycleSetting -ErrorAction SilentlyContinue) { $v = Get-PimAdminLifecycleSetting -Name $n } else { $v = Get-Variable -Name "PIM_$n" -Scope Global -ValueOnly -ErrorAction SilentlyContinue }; "$v".Trim() }
    $vault = & $get 'HybridAdCredentialVault'
    $uSec  = & $get 'HybridAdCredentialUserSecret'
    $pSec  = & $get 'HybridAdCredentialPasswordSecret'
    if (-not ($vault -and $uSec -and $pSec)) { return [pscustomobject]@{ credential = $null; source = '' } }
    $reader = $SecretReader
    if (-not $reader -and ($global:PIM_HybridAdSecretReader -is [scriptblock])) { $reader = $global:PIM_HybridAdSecretReader }
    if (-not $reader -and (Get-Command Get-PimSqlSecretFromKeyVault -ErrorAction SilentlyContinue)) { $reader = { param($v, $n) Get-PimSqlSecretFromKeyVault -VaultName $v -SecretName $n } }
    if (-not $reader) { return [pscustomobject]@{ credential = $null; source = '' } }
    try {
        $user = "$(& $reader $vault $uSec)".Trim()
        $pw   = "$(& $reader $vault $pSec)"
        if (-not $user -or -not $pw) { return [pscustomobject]@{ credential = $null; source = '' } }
        $sec = New-Object System.Security.SecureString
        foreach ($ch in $pw.ToCharArray()) { $sec.AppendChar($ch) }
        $sec.MakeReadOnly()
        return [pscustomobject]@{ credential = (New-Object System.Management.Automation.PSCredential($user, $sec)); source = "Key Vault $vault" }
    } catch {
        Write-Warning "  [hybrid-ad] the AD credential could not be read from Key Vault '$vault': $($_.Exception.Message)"
        return [pscustomobject]@{ credential = $null; source = '' }
    }
}

function Test-PimHybridAdWorkerCapability {
    # v1's condition (PIM-Baseline-Management-CSV.ps1 367-372): the ActiveDirectory module AND an
    # AD credential. -AdModulePresent is the test seam.
    param([object]$AdModulePresent = $null, [object]$Credential = $null, [scriptblock]$SecretReader)
    $ad = if ($null -ne $AdModulePresent) { [bool]$AdModulePresent } else { [bool](Get-Command Get-ADUser -ErrorAction SilentlyContinue) }
    $cred = $Credential; $src = 'supplied'
    if (-not $cred) { $r = Resolve-PimHybridAdCredential -SecretReader $SecretReader; $cred = $r.credential; $src = $r.source }
    $reason = ''
    if (-not $ad) { $reason = 'this host has no ActiveDirectory module (RSAT-AD) -- a container cannot write on-premises AD' }
    elseif (-not $cred) { $reason = 'no AD credential is available (set PIM_HybridAdCredential on the worker, or the HybridAdCredentialVault / -UserSecret / -PasswordSecret settings)' }
    return [pscustomobject]@{ ok = ($ad -and [bool]$cred); adModule = $ad; hasCredential = [bool]$cred; credential = $cred; credentialSource = $src; reason = $reason }
}

function New-PimHybridAdSecurePassword {
    # A random initial password for a NEW standard AD account, as a SecureString. Never stored,
    # never logged (v1 wrote it to output/admin-passwords-<date>.txt, 5935-5937).
    $plain = if (Get-Command New-PimAdminInitialPassword -ErrorAction SilentlyContinue) { New-PimAdminInitialPassword -Length 32 } else { [guid]::NewGuid().ToString('N') + 'Aa9!' + [guid]::NewGuid().ToString('N') }
    $sec = New-Object System.Security.SecureString
    foreach ($ch in $plain.ToCharArray()) { $sec.AppendChar($ch) }
    $plain = $null
    $sec.MakeReadOnly()
    return $sec
}

function Test-PimHybridAdPasswordMailReady {
    # Can the initial password of a NEW AD admin be mailed right now? Checked BEFORE New-ADUser, so an
    # account is never created with a password nobody receives. Same checks as the TAP delivery guard
    # (Test-PimTapMailReady): a recipient, a sender (hydrated from pim.Settings first), the send path and
    # the template -- asked explicitly, because a -WhatIf probe cannot see a missing sender.
    param([string]$Recipient)
    if (-not "$Recipient".Trim()) {
        return @{ ok = $false; reason = 'no recipient resolved for this admin -- its mail goes to the owners of its SPONSOR DEPARTMENT (set Department on the admin and Owners on that department), or to an office user email (MailForwardAddress with ForwardMailsToContact=TRUE) -- so there is nowhere to send the initial password' }
    }
    if ((-not "$($global:PIM_MailSender)".Trim()) -and (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue)) {
        try { [void](Initialize-PimEmailControlsFromStore) } catch { }
    }
    if (-not "$($global:PIM_MailSender)".Trim()) { return @{ ok = $false; reason = 'no notification sender is configured (MailSender) -- the tenant cannot send mail' } }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return @{ ok = $false; reason = 'the notification path (PIM-Notify.ps1) is not loaded on this worker' } }
    try {
        $probe = Send-PimNotifyMail -Type 'ad-password-delivery' -Tokens @{ UserPrincipalName = 'probe'; SamAccountName = 'probe'; InitialPassword = '' } -Recipient $Recipient -WhatIf
        if ("$($probe.reason)" -and "$($probe.reason)" -ne 'whatif') { return @{ ok = $false; reason = "$($probe.reason)" } }
    } catch { return @{ ok = $false; reason = "mail pre-check failed: $($_.Exception.Message)" } }
    return @{ ok = $true; reason = '' }
}

function Send-PimHybridAdPasswordMail {
    # Mail a new AD admin's initial password (template ad-password-delivery) to the admin-mail recipient.
    # Returns @{ sent; reason } ONLY -- the rendered message (which contains the password) is dropped here
    # and never returned, logged or stored.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$PlainPassword)
    $rcpt = Get-PimHybridAdDesiredValue -Desired $Item.desired -Name 'mailRecipient'
    if (-not "$rcpt".Trim()) { return @{ sent = $false; reason = 'no recipient' } }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return @{ sent = $false; reason = 'PIM-Notify.ps1 not loaded' } }
    $toks = @{
        UserPrincipalName = (Get-PimHybridAdDesiredValue -Desired $Item.desired -Name 'userPrincipalName')
        SamAccountName    = "$($Item.samAccountName)"
        InitialPassword   = $PlainPassword
    }
    $r = $null
    try { $r = Send-PimNotifyMail -Type 'ad-password-delivery' -Tokens $toks -Recipient $rcpt } catch { $r = @{ sent = $false; reason = "$($_.Exception.Message)" } }
    $toks = $null
    return @{ sent = ("$($r.sent)" -match '(?i)^true$'); reason = "$($r.reason)" }
}

function Invoke-PimHybridAdWorkerJob {
    <#
      The 'hybrid-ad-apply' job. Reads the admin rows from SQL (or -Rows), keeps TargetPlatform=AD
      rows that are due (ProvisionDate) and not Disabled / Revoked / offboarded, plans, and -- only
      on a capable host -- applies through Invoke-PimHybridAdApply -Apply.
      Returns the scheduler handler shape: @{ ran; detail; ...; unimplemented; requiresHybridWorker }.
      THROWS when an apply failed, so the tick records a failed run.
    #>
    param(
        [datetime]$NowUtc = [datetime]::UtcNow,
        [switch]$WhatIf,
        [object[]]$Rows = $null,
        [hashtable]$ActiveDirectoryAdapter,
        [System.Management.Automation.PSCredential]$Credential,
        [object]$AdModulePresent = $null,
        [scriptblock]$SecretReader,
        [scriptblock]$DeliverPassword = { param($Item, $PlainPassword) Send-PimHybridAdPasswordMail -Item $Item -PlainPassword $PlainPassword },
        [scriptblock]$PasswordDeliveryReady = { param($Item) Test-PimHybridAdPasswordMailReady -Recipient (Get-PimHybridAdDesiredValue -Desired $Item.desired -Name 'mailRecipient') }
    )
    if ($null -eq $Rows) {
        if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ ran = $false; unimplemented = $true; detail = 'unimplemented:hybrid-ad-apply -- the engine core (Get-PimDesiredRows) is not loaded on this worker'; whatIf = [bool]$WhatIf }
        }
        $Rows = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey('Account-Definitions-Admins') -and -not $global:PIM_DesiredResolved['Account-Definitions-Admins']) {
            throw '[hybrid-ad-apply] the admin rows could not be read from the desired store -- nothing was planned'
        }
    }
    $ad = New-Object System.Collections.Generic.List[object]
    $held = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if (-not (Test-PimHybridAdRowIsAd -Row $r)) { continue }
        $name = (Get-PimRowProp -Row $r -Names @('UserName','SamAccountName','UserPrincipalName')).Trim()
        if (Get-Command Test-PimAdminProvisionDue -ErrorAction SilentlyContinue) {
            $pd = Test-PimAdminProvisionDue -Row $r -NowUtc $NowUtc
            if (-not $pd.due) { [void]$held.Add("$name ($($pd.reason))"); continue }
        }
        if (Get-Command Get-PimAdminStatusDecision -ErrorAction SilentlyContinue) {
            $dec = Get-PimAdminStatusDecision -Row $r -NowUtc $NowUtc
            if ($dec.blocksCreate) { [void]$held.Add("$name ($($dec.reason))"); continue }
        }
        [void]$ad.Add($r)
    }
    $heldText = if ($held.Count) { "; held back: " + ($held -join ', ') } else { '' }
    if ($ad.Count -eq 0) {
        return [pscustomobject]@{ ran = $true; detail = "hybrid-ad-apply: no due TargetPlatform=AD admin rows -- nothing for a hybrid worker to do$heldText"; adRows = 0; whatIf = [bool]$WhatIf }
    }
    $cap = Test-PimHybridAdWorkerCapability -AdModulePresent $AdModulePresent -Credential $Credential -SecretReader $SecretReader
    if (-not $cap.ok) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; requiresHybridWorker = $true; adRows = $ad.Count
            detail = ("hybrid worker required: {0} TargetPlatform=AD admin row(s) are waiting for on-premises AD, and {1}. Run the scheduler on a domain-joined host scoped to this job (Start-PimScheduler.ps1 -Jobs hybrid-ad-apply){2}" -f $ad.Count, $cap.reason, $heldText)
            whatIf = [bool]$WhatIf }
    }
    # The OU paths and every derived name come from the customer's naming conventions in pim.Settings.
    # A cold worker has not hydrated them yet (the scheduler tick normally has): read them once, fail-safe.
    if (-not (Get-PimHybridAdNamingValue -Name 'PathAdmins') -and -not (Get-PimHybridAdNamingValue -Name 'PathAdminsL0T0') -and (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue)) {
        try { [void](Import-PimSettingsFromStore) } catch { Write-Warning "  [hybrid-ad] naming settings could not be read from the store: $($_.Exception.Message)" }
    }
    $plan = Get-PimHybridAdPlan -AdminRows $ad.ToArray() -Live @() -PathAdmins (Get-PimHybridAdNamingValue -Name 'PathAdmins') -PathAdminsL0T0 (Get-PimHybridAdNamingValue -Name 'PathAdminsL0T0') -Domain "$($global:PIM_AdDomain)"
    if ($WhatIf) {
        $pr = Invoke-PimHybridAdApply -Plan $plan
        return [pscustomobject]@{ ran = $true; whatIf = $true; adRows = $ad.Count; results = $pr.results
            detail = ("hybrid-ad-apply (whatif): {0} AD row(s) planned, {1} skipped{2}" -f @($pr.results | Where-Object { $_.status -eq 'plan' }).Count, @($pr.results | Where-Object { $_.status -eq 'skipped' }).Count, $heldText) }
    }
    $applyArgs = @{ Plan = $plan; Apply = $true; Credential = $cap.credential }
    if ($DeliverPassword) { $applyArgs['DeliverPassword'] = $DeliverPassword; if ($PasswordDeliveryReady) { $applyArgs['PasswordDeliveryReady'] = $PasswordDeliveryReady } }
    else { $applyArgs['NewPassword'] = { New-PimHybridAdSecurePassword } }
    if ($ActiveDirectoryAdapter) { $applyArgs['ActiveDirectoryAdapter'] = $ActiveDirectoryAdapter }
    $res = Invoke-PimHybridAdApply @applyArgs
    $count = { param($s) @($res.results | Where-Object { $_.status -eq $s }).Count }
    $failed = @($res.results | Where-Object { $_.status -eq 'failed' })
    $heldCreates = @($res.results | Where-Object { $_.status -eq 'skipped' -and "$($_.reason)" -match '^create HELD' })
    $heldCreateText = if ($heldCreates.Count) { "; create held: " + (@($heldCreates | ForEach-Object { "$($_.samAccountName) ($($_.reason -replace '^create HELD: ', ''))" }) -join ', ') } else { '' }
    $detail = ("hybrid-ad-apply: created={0} updated={1} nochange={2} resolved={3} skipped={4} failed={5} (credential: {6}){7}{8}" -f (& $count 'created'), (& $count 'updated'), (& $count 'nochange'), (& $count 'resolved'), (& $count 'skipped'), $failed.Count, $cap.credentialSource, $heldText, $heldCreateText)
    foreach ($x in @($res.results | Where-Object { $_.status -eq 'created' -or $_.status -eq 'updated' -or ($_.status -eq 'failed' -and $_.op -eq 'Create' -and "$($_.reason)" -match '^account CREATED') })) {
        $act = if ($x.status -eq 'failed') { 'account.ad.created' } else { "account.ad.$($x.status)" }
        $res2 = if ($x.status -eq 'failed') { 'partial' } else { 'ok' }
        if (Get-Command Write-PimAdminLifecycleAudit -ErrorAction SilentlyContinue) { Write-PimAdminLifecycleAudit -Action $act -Target "$($x.samAccountName)" -After @{ platform = 'AD'; reason = "$($x.reason)" } -Result $res2 }
    }
    if ($failed.Count) {
        throw ("[hybrid-ad-apply] " + $detail + " -- " + (@($failed | ForEach-Object { "$($_.samAccountName): $($_.reason)" }) -join ' | '))
    }
    return [pscustomobject]@{ ran = $true; detail = $detail; adRows = $ad.Count; results = $res.results; whatIf = $false }
}
