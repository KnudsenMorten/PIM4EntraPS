# PIM4EntraPS -- permission-wizard auto-derivation (reversed create flow).
# Dot-sourced by PIM-Functions.psm1 and standalone by the pim-manager.
#
# The NEW create flow is target-first: pick the delegation TARGET (entra / azure /
# workload), pick the SOURCE/scope, pick the desired ROLES in scope -- then the
# engine AUTO-DERIVES groupKind (permission-service vs permission-bundle), name,
# roleScope, role, level, tier, plane. These functions are the pure brain of that
# wizard (no I/O, fully testable). Naming grammar:
#   PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}
#   (+ -AU-{AU} segment after {Name} for AU-scoped entra)

Set-StrictMode -Off

# Entra roles that are tier-0 / L0 (control of identity). Overridable.
function Get-PimPrivilegedEntraRoles {
    if ($global:PIM_PrivilegedEntraRoles) { return @($global:PIM_PrivilegedEntraRoles) }
    return @('Global Administrator','Privileged Role Administrator','Privileged Authentication Administrator')
}
function Test-PimRolePrivileged {
    param([Parameter(Mandatory)][string]$RoleName)
    $p = @(Get-PimPrivilegedEntraRoles | ForEach-Object { "$_".ToLowerInvariant() })
    return ($p -contains "$RoleName".Trim().ToLowerInvariant())
}

# Entra roles that support AU (administrative unit) scoping. Overridable; the
# wizard shows the AU step ONLY when every selected role is AU-scopable.
function Get-PimAuScopableRoles {
    if ($global:PIM_AuScopableRoles) { return @($global:PIM_AuScopableRoles) }
    return @(
        'User Administrator','Groups Administrator','Helpdesk Administrator',
        'Password Administrator','Authentication Administrator','License Administrator',
        'Cloud Device Administrator','Printer Administrator','Knowledge Administrator',
        'Knowledge Manager','Teams Devices Administrator','Tenant Creator'
    )
}
function Test-PimRoleAuScopable {
    param([Parameter(Mandatory)][string]$RoleName)
    $a = @(Get-PimAuScopableRoles | ForEach-Object { "$_".ToLowerInvariant() })
    return ($a -contains "$RoleName".Trim().ToLowerInvariant())
}
function Test-PimRolesAuScopable {
    # The AU step is offered only when ALL selected roles are AU-scopable.
    param([string[]]$Roles = @())
    $r = @(@($Roles) | Where-Object { "$_".Trim() })
    if ($r.Count -eq 0) { return $false }
    foreach ($x in $r) { if (-not (Test-PimRoleAuScopable -RoleName $x)) { return $false } }
    return $true
}

function Get-PimGroupKindFromRoleCount {
    # 1 role -> permission-service ; 2+ -> permission-bundle.
    param([int]$RoleCount)
    if ($RoleCount -le 1) { return 'permission-service' }
    return 'permission-bundle'
}

function ConvertTo-PimNameSegment {
    # Compress a role / scope label into a name segment (CamelCase-ish, no spaces).
    param([AllowNull()][string]$Text)
    $t = "$Text".Trim()
    if (-not $t) { return '' }
    $t = ($t -replace '[^A-Za-z0-9 ]', ' ')
    $parts = @($t -split '\s+' | Where-Object { $_ })
    return (($parts | ForEach-Object { if ($_.Length -gt 1) { $_.Substring(0,1).ToUpper() + $_.Substring(1) } else { $_.ToUpper() } }) -join '')
}

function New-PimPermissionGroupName {
    # Assemble a name from the grammar. AU segment inserted after {Name} when set.
    param(
        [Parameter(Mandatory)][string]$Service,   # Entra-ID / Azure / Defender ...
        [Parameter(Mandatory)][string]$Name,      # capability / role segment
        [Parameter(Mandatory)][int]$Level,
        [Parameter(Mandatory)][int]$Tier,
        [Parameter(Mandatory)][string]$Code,      # CP / MP / WDP / DP / APP / USER
        [Parameter(Mandatory)][string]$Domain,    # ID / RES / DAT
        [string]$Au
    )
    $auSeg = if ("$Au".Trim()) { "-AU-$($Au.Trim())" } else { '' }
    return ("PIM-{0}-{1}{2}-L{3}-T{4}-{5}-{6}" -f $Service, $Name, $auSeg, $Level, $Tier, $Code, $Domain)
}

# --- ENTRA derivation -----------------------------------------------------------
function Get-PimEntraDerivation {
    # Roles (1=service, 2+=bundle); AuScope optional (only honoured if all roles
    # are AU-scopable). Returns the full auto-fill: kind, level, tier, plane(CP),
    # domain(ID), name, groupName, auOffered.
    param(
        [Parameter(Mandatory)][string[]]$Roles,
        [string]$AuScope,
        [string]$BundleName
    )
    $roles = @(@($Roles) | Where-Object { "$_".Trim() })
    if ($roles.Count -eq 0) { throw "Get-PimEntraDerivation: at least one role is required." }
    $kind  = Get-PimGroupKindFromRoleCount -RoleCount $roles.Count
    $tier  = 0                                  # entra permission groups are tier 0
    $code  = 'CP'                               # control plane
    $domain = 'ID'                              # identity domain
    $auOffered = Test-PimRolesAuScopable -Roles $roles
    $au = ''
    $anyPriv = $false
    foreach ($r in $roles) { if (Test-PimRolePrivileged -RoleName $r) { $anyPriv = $true } }
    if ($anyPriv) {
        $level = 0                              # GA + privileged -> L0
    } elseif ($auOffered -and "$AuScope".Trim()) {
        $level = 2; $au = "$AuScope".Trim()     # AU-scoped -> L2
    } else {
        $level = 1                              # other entra roles -> L1
    }
    $nameSeg = if ($kind -eq 'permission-bundle') {
        if ("$BundleName".Trim()) { ConvertTo-PimNameSegment $BundleName } else { 'Bundle-' + (ConvertTo-PimNameSegment ($roles[0])) }
    } else { ConvertTo-PimNameSegment $roles[0] }
    $name = New-PimPermissionGroupName -Service 'Entra-ID' -Name $nameSeg -Level $level -Tier $tier -Code $code -Domain $domain -Au $au
    return [pscustomobject]@{
        target = 'entra'; kind = $kind; roles = $roles; roleCount = $roles.Count
        level = $level; tier = $tier; plane = $code; domain = $domain
        roleScope = $(if ($au) { "AU:$au" } else { 'Tenant' })
        auOffered = $auOffered; au = $au
        nameSegment = $nameSeg; groupName = $name
    }
}

# --- AZURE derivation -----------------------------------------------------------
function Get-PimAzureScopeDepth {
    # Level by ARM scope depth: tenant root = 0; subscription = 1; resource group
    # = 2; resource = 3. Management groups carry no depth in their id -> pass
    # -ManagementGroupDepth (the connector knows the hierarchy; default 1, root 0).
    param(
        [Parameter(Mandatory)][ValidateSet('tenantRoot','managementGroup','subscription','resourceGroup','resource')][string]$ScopeType,
        [string]$ScopePath,
        [int]$ManagementGroupDepth = 1
    )
    switch ($ScopeType) {
        'tenantRoot'      { return 0 }
        'managementGroup' { return [math]::Max(0, $ManagementGroupDepth) }
        'subscription'    { return 1 }
        'resourceGroup'   { return 2 }
        'resource'        { return 3 }
    }
    return 1
}

function Get-PimAzurePlane {
    # CAF-aware plane: tenant root -> CP; platform/management/connectivity/identity
    # names -> MP; landing-zone (lz) / data (storage/sql/data) -> WDP; else default
    # MP for management groups, WDP for subs/rgs/resources.
    param(
        [Parameter(Mandatory)][string]$ScopeType,
        [string]$ScopePath,
        [string]$ScopeName
    )
    if ($ScopeType -eq 'tenantRoot') { return 'CP' }
    $hay = ("$ScopePath $ScopeName").ToLowerInvariant()
    if ($hay -match '(^|[^a-z])(platform|management|connectivity|identity|mgmt)([^a-z]|$)') { return 'MP' }
    if ($hay -match '(^|[^a-z])(lz|landingzone|landing-zone|workload|storage|sql|data)([^a-z]|$)') { return 'WDP' }
    if ($ScopeType -eq 'managementGroup') { return 'MP' }
    return 'WDP'
}

function Get-PimAzureDerivation {
    # Scope (sub/mg/rg/resource) + roles -> kind, level (depth), tier (root=0 else
    # 1), plane (CAF), domain (RES, or DAT for data planes), name.
    param(
        [Parameter(Mandatory)][ValidateSet('tenantRoot','managementGroup','subscription','resourceGroup','resource')][string]$ScopeType,
        [Parameter(Mandatory)][string[]]$Roles,
        [string]$ScopePath,
        [string]$ScopeName,
        [int]$ManagementGroupDepth = 1,
        [string]$BundleName
    )
    $roles = @(@($Roles) | Where-Object { "$_".Trim() })
    if ($roles.Count -eq 0) { throw "Get-PimAzureDerivation: at least one role is required." }
    $kind  = Get-PimGroupKindFromRoleCount -RoleCount $roles.Count
    $level = Get-PimAzureScopeDepth -ScopeType $ScopeType -ScopePath $ScopePath -ManagementGroupDepth $ManagementGroupDepth
    $tier  = if ($ScopeType -eq 'tenantRoot') { 0 } else { 1 }   # only tenant root is tier 0
    $plane = Get-PimAzurePlane -ScopeType $ScopeType -ScopePath $ScopePath -ScopeName $ScopeName
    $hay   = ("$ScopePath $ScopeName").ToLowerInvariant()
    $domain = if ($plane -eq 'WDP' -and ($hay -match '(storage|sql|data)')) { 'DAT' } else { 'RES' }
    $scopeSeg = if ("$ScopeName".Trim()) { ConvertTo-PimNameSegment $ScopeName } else { ConvertTo-PimNameSegment $ScopeType }
    $roleSeg  = if ($kind -eq 'permission-bundle') {
        if ("$BundleName".Trim()) { ConvertTo-PimNameSegment $BundleName } else { 'Bundle' }
    } else { ConvertTo-PimNameSegment $roles[0] }
    $nameSeg = (@($scopeSeg, $roleSeg) | Where-Object { $_ }) -join '-'
    $name = New-PimPermissionGroupName -Service 'Azure' -Name $nameSeg -Level $level -Tier $tier -Code $plane -Domain $domain
    return [pscustomobject]@{
        target = 'azure'; kind = $kind; roles = $roles; roleCount = $roles.Count
        level = $level; tier = $tier; plane = $plane; domain = $domain
        roleScope = "$ScopeType`:$ScopePath"; scopeType = $ScopeType
        nameSegment = $nameSeg; groupName = $name
    }
}

# --- WORKLOAD derivation (defender xdr, power bi, ...) ---------------------------
function Get-PimWorkloadDerivation {
    # Generic workload connector target. tier 1 / WDP by default (overridable per
    # workload); level from the supplied default (the connector/UI sets it).
    param(
        [Parameter(Mandatory)][string]$Workload,      # Defender / PowerBI / Intune ...
        [Parameter(Mandatory)][string[]]$Roles,
        [int]$Level = 3,
        [int]$Tier = 1,
        [string]$Plane = 'WDP',
        [string]$Domain = 'ID',
        [string]$Scope,
        [string]$BundleName
    )
    $roles = @(@($Roles) | Where-Object { "$_".Trim() })
    if ($roles.Count -eq 0) { throw "Get-PimWorkloadDerivation: at least one role is required." }
    $kind = Get-PimGroupKindFromRoleCount -RoleCount $roles.Count
    $svc  = ConvertTo-PimNameSegment $Workload
    $roleSeg = if ($kind -eq 'permission-bundle') { if ("$BundleName".Trim()) { ConvertTo-PimNameSegment $BundleName } else { 'Bundle' } } else { ConvertTo-PimNameSegment $roles[0] }
    $name = New-PimPermissionGroupName -Service $svc -Name $roleSeg -Level $Level -Tier $Tier -Code $Plane -Domain $Domain
    return [pscustomobject]@{
        target = 'workload'; workload = $Workload; kind = $kind; roles = $roles; roleCount = $roles.Count
        level = $Level; tier = $Tier; plane = $Plane; domain = $Domain
        roleScope = $(if ("$Scope".Trim()) { "$Scope" } else { 'Service' })
        nameSegment = $roleSeg; groupName = $name
    }
}

# --- ADMIN derivation (admin-account name) --------------------------------------
function Get-PimAdminDerivation {
    # Derive the admin ACCOUNT name from owner + admin-type (prefix) + environment
    # (suffix), using the §17 naming helpers in PIM-Naming.ps1 (Resolve-PimAdminName).
    # This is the live name derivation the Create-admin wizard / Advanced grid / guest
    # invite drive so GUI and engine resolve the SAME name. -HighPriv = the dedicated
    # L0-T0 form. Returns the resolved UserName plus the inputs that drove it.
    param(
        [Parameter(Mandatory)][string]$Owner,
        [string]$AdminType   = 'internal-adminuser',
        [string]$Environment = 'entra',
        [switch]$HighPriv
    )
    if (-not (Get-Command Resolve-PimAdminName -ErrorAction SilentlyContinue)) {
        throw "Get-PimAdminDerivation: PIM-Naming.ps1 is not loaded (Resolve-PimAdminName missing)."
    }
    $userName = Resolve-PimAdminName -Owner $Owner -AdminType $AdminType -Environment $Environment -HighPriv:$HighPriv
    $prefix   = Get-PimAdminTypePrefix  -AdminType   $AdminType
    $suffix   = Get-PimEnvironmentSuffix -Environment $Environment
    return [pscustomobject]@{
        target      = 'admin'
        owner       = $Owner
        adminType   = (Resolve-PimAdminTypeKey $AdminType)
        environment = (Resolve-PimEnvironmentKey $Environment)
        highPriv    = [bool]$HighPriv
        prefix      = $prefix
        suffix      = $suffix
        userName    = $userName
        groupName   = $userName   # alias so the GUI's generic "derived name" field works
        valid       = [bool](Test-PimAdminName -Name $userName -Purpose ($(if ($HighPriv) { 'HighPriv' } else { 'Day2Day' })))
    }
}

# --- UNIFIED DISPATCH -----------------------------------------------------------
function Get-PimWizardDerivation {
    # The ONE entry-point for the reversed (target-first) wizard: target -> source
    # -> roles-in-scope, then auto-derive everything. Dispatches to the per-target
    # brain above so the Manager endpoint (and tests) drive a single function.
    #   target=entra    : -Roles [-AuScope] [-BundleName]
    #   target=azure    : -ScopeType -Roles [-ScopePath] [-ScopeName] [-ManagementGroupDepth] [-BundleName]
    #   target=workload : -Workload -Roles [-Scope] [-Level] [-Tier] [-Plane] [-Domain] [-BundleName]
    #   target=admin    : -Owner [-AdminType] [-Environment] [-HighPriv]   (admin account name)
    param(
        [Parameter(Mandatory)][ValidateSet('entra','azure','workload','admin')][string]$Target,
        [string[]]$Roles,
        [string]$AuScope,
        [string]$ScopeType,
        [string]$ScopePath,
        [string]$ScopeName,
        [int]$ManagementGroupDepth = 1,
        [string]$Workload,
        [string]$Scope,
        [Nullable[int]]$Level,
        [Nullable[int]]$Tier,
        [string]$Plane,
        [string]$Domain,
        [string]$BundleName,
        [string]$Owner,
        [string]$AdminType,
        [string]$Environment,
        [switch]$HighPriv
    )
    if ($Target -ne 'admin' -and (-not $Roles -or @($Roles).Count -eq 0)) {
        throw "Get-PimWizardDerivation: at least one role is required for target '$Target'."
    }
    switch ($Target) {
        'admin' {
            if (-not "$Owner".Trim()) { throw "Get-PimWizardDerivation: -Owner is required for target 'admin'." }
            $at = if ("$AdminType".Trim())   { $AdminType }   else { 'internal-adminuser' }
            $ev = if ("$Environment".Trim()) { $Environment } else { 'entra' }
            return Get-PimAdminDerivation -Owner $Owner -AdminType $at -Environment $ev -HighPriv:$HighPriv
        }
        'entra' { return Get-PimEntraDerivation -Roles $Roles -AuScope $AuScope -BundleName $BundleName }
        'azure' {
            if (-not "$ScopeType".Trim()) { throw "Get-PimWizardDerivation: -ScopeType is required for target 'azure'." }
            return Get-PimAzureDerivation -ScopeType $ScopeType -Roles $Roles -ScopePath $ScopePath -ScopeName $ScopeName -ManagementGroupDepth $ManagementGroupDepth -BundleName $BundleName
        }
        'workload' {
            if (-not "$Workload".Trim()) { throw "Get-PimWizardDerivation: -Workload is required for target 'workload'." }
            $p = @{ Workload = $Workload; Roles = $Roles; Scope = $Scope; BundleName = $BundleName }
            if ($null -ne $Level)  { $p['Level']  = [int]$Level }
            if ($null -ne $Tier)   { $p['Tier']   = [int]$Tier }
            if ("$Plane".Trim())   { $p['Plane']  = $Plane }
            if ("$Domain".Trim())  { $p['Domain'] = $Domain }
            return Get-PimWorkloadDerivation @p
        }
    }
    throw "Get-PimWizardDerivation: unknown target '$Target' (expected entra | azure | workload | admin)."
}
