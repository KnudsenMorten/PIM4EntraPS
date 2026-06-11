#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-flight validator for PIM Manager.

.DESCRIPTION
    Dot-sourced from Open-PimManager.ps1. Exposes:

      Invoke-PimPreflightValidation   -> returns @{ violations = [...]; ranAt = <iso>;
                                                    cacheFreshness = @{ entraRoles=...; aus=...; azureScopes=... } }

    Each violation is a [pscustomobject] with:
      Severity   : 'error' | 'warning' | 'info'
      Code       : stable rule id (e.g. 'PIM-FK-001')
      Csv        : the CSV base name where the issue lives (or '<global>')
      Row        : 0-based row index, or $null for whole-file issues
      Column     : optional column name
      Message    : human-readable explanation
      Suggestion : actionable hint (may be $null)

    Reads all 14 CSVs via the existing Read-PimCsvRows helper (so this works
    against either .custom.csv or .locked.csv, whichever wins).

    All rules degrade gracefully when source data is missing: a CSV that does
    not exist becomes a single PIM-IO-001 info violation, and dependent FK
    checks for that CSV are skipped.

.NOTES
    Caches nothing on disk; the 14 CSVs are small enough that a fresh read
    on every call is well under 1s. The HTTP endpoint re-runs on demand.
#>

# ---------------------------------------------------------------------------
# Levenshtein (for the "did you mean" suggestion in PIM-FK-001)
# ---------------------------------------------------------------------------

# Compiled Levenshtein. The original pure-PS char-by-char DP loop cost the
# /api/preflight endpoint ~10 of its 12 seconds (each "did you mean"
# suggestion = full haystack scan; PS loop iterations are ~1000x slower than
# compiled code) -- and the server is single-threaded, so every page load
# (which auto-runs preflight) froze ALL other API calls for that long.
if (-not ('PimManager.Levenshtein' -as [type])) {
    Add-Type -TypeDefinition @'
namespace PimManager {
    public static class Levenshtein {
        public static int Distance(string a, string b) {
            if (string.IsNullOrEmpty(a)) return string.IsNullOrEmpty(b) ? 0 : b.Length;
            if (string.IsNullOrEmpty(b)) return a.Length;
            int la = a.Length, lb = b.Length;
            int[] prev = new int[lb + 1];
            int[] curr = new int[lb + 1];
            for (int j = 0; j <= lb; j++) prev[j] = j;
            for (int i = 1; i <= la; i++) {
                curr[0] = i;
                for (int j = 1; j <= lb; j++) {
                    int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
                    int m = curr[j - 1] + 1;
                    if (prev[j] + 1 < m) m = prev[j] + 1;
                    if (prev[j - 1] + cost < m) m = prev[j - 1] + cost;
                    curr[j] = m;
                }
                int[] tmp = prev; prev = curr; curr = tmp;
            }
            return prev[lb];
        }
    }
}
'@ -ErrorAction Stop
}

function Get-PimLevenshteinDistance {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$A,
        [Parameter(Mandatory)][AllowEmptyString()][string]$B
    )
    return [PimManager.Levenshtein]::Distance($A, $B)
}

function Get-PimClosestMatches {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Needle,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Haystack,
        [int]$MaxDistance = 4,
        [int]$Top = 3
    )
    if (-not $Needle -or -not $Haystack -or $Haystack.Count -eq 0) { return @() }
    $scored = foreach ($h in $Haystack) {
        if (-not $h) { continue }
        $d = Get-PimLevenshteinDistance -A $Needle -B $h
        if ($d -le $MaxDistance) { [pscustomobject]@{ Value = $h; Distance = $d } }
    }
    if (-not $scored) { return @() }
    return @($scored | Sort-Object Distance, Value | Select-Object -First $Top)
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-PimViolation {
    param(
        [Parameter(Mandatory)][ValidateSet('error','warning','info')][string]$Severity,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Csv,
        [AllowNull()][object]$Row = $null,
        [string]$Column,
        [Parameter(Mandatory)][string]$Message,
        [string]$Suggestion
    )
    [pscustomobject]@{
        Severity   = $Severity
        Code       = $Code
        Csv        = $Csv
        Row        = $Row
        Column     = $Column
        Message    = $Message
        Suggestion = $Suggestion
    }
}

function Get-PimRowValue {
    # Safe lookup that handles both OrderedDictionary (Read-PimCsvRows output)
    # and PSCustomObject (older paths). Returns '' if column missing.
    param([Parameter(Mandatory)][AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Column)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Column)) { return [string]$Row[$Column] }
        return ''
    }
    $p = $Row.PSObject.Properties[$Column]
    if ($p) { return [string]$p.Value }
    return ''
}

function Test-PimRowIsBlank {
    # Treats a row with every column null/empty as a separator (matches
    # how the engines read these CSVs).
    param([Parameter(Mandatory)][AllowNull()][object]$Row)
    if ($null -eq $Row) { return $true }
    $keys = @()
    if ($Row -is [System.Collections.IDictionary]) { $keys = @($Row.Keys) }
    else { $keys = @($Row.PSObject.Properties.Name) }
    foreach ($k in $keys) {
        $v = Get-PimRowValue -Row $Row -Column $k
        if ($null -ne $v -and "$v".Length -gt 0) { return $false }
    }
    return $true
}

function Get-PimCacheFreshness {
    # Maps the on-disk cache files to 'live' / 'stale' / 'none' so the UI
    # can decide whether to surface PIM-STALE-* rules.
    $now = (Get-Date).ToUniversalTime()
    $staleAfterHours = 24
    $out = [ordered]@{}
    $kinds = @(
        @{ k = 'entra-roles';  key = 'entraRoles' },
        @{ k = 'aus';          key = 'aus' },
        @{ k = 'pim-groups';   key = 'pimGroups' },
        @{ k = 'azure-scopes'; key = 'azureScopes' }
    )
    foreach ($kind in $kinds) {
        $state = 'none'
        if (Get-Command Get-PimTenantCacheFile -ErrorAction SilentlyContinue) {
            $f = Get-PimTenantCacheFile -Kind $kind.k
            if (Test-Path -LiteralPath $f) {
                try {
                    $raw = [System.IO.File]::ReadAllText($f, [System.Text.UTF8Encoding]::new($false))
                    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                    $parsed = $raw | ConvertFrom-Json
                    if ($parsed -and $parsed.refreshedUtc) {
                        $t = [datetime]::Parse($parsed.refreshedUtc).ToUniversalTime()
                        $ageH = ($now - $t).TotalHours
                        $state = if ($ageH -lt $staleAfterHours) { 'live' } else { 'stale' }
                    } else {
                        $state = 'stale'
                    }
                } catch { $state = 'stale' }
            }
        }
        $out[$kind.key] = $state
    }
    return $out
}

# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------

function Invoke-PimPreflightValidation {
    [CmdletBinding()]
    param()

    $violations = New-Object System.Collections.ArrayList
    $cacheFreshness = Get-PimCacheFreshness

    # Naming convention overrides (regex + admin pattern).
    $naming = $null
    try { $naming = Get-PimNamingConventions } catch { $naming = @{} }
    # The PowerShell side uses the same documented shape the JS side defaults to.
    $groupTagRegex = $null
    if ($naming -and $naming.ContainsKey('PimGroupTagRegex') -and $naming.PimGroupTagRegex) {
        try { $groupTagRegex = [regex]::new([string]$naming.PimGroupTagRegex) } catch { $groupTagRegex = $null }
    }
    if (-not $groupTagRegex) {
        $groupTagRegex = [regex]::new('^[A-Za-z0-9][A-Za-z0-9._-]*-L[0-9]-T[0-2]-(CP|WDP|MP|APP|USER)-(ID|RES|DAT)(-S_AD)?$')
    }
    # Admin UPN pattern: customer-overridable token-style ('adm_{Owner}'), turned into a permissive regex.
    $adminPatternRegex = $null
    if ($naming -and $naming.ContainsKey('AdminAccountPattern') -and $naming.AdminAccountPattern) {
        try {
            $tplate = [string]$naming.AdminAccountPattern
            # Tokens like {Owner} -> .+ ; escape the rest.
            # NB: [regex]::Escape escapes '{' but NOT '}' (.NET asymmetry), so
            # the closing brace must be matched optionally-escaped -- the old
            # pattern ('\\\}') never matched, the token survived as a literal,
            # and EVERY legitimate UPN got a false PIM-NAME-002 warning.
            $reSrc = [regex]::Escape($tplate)
            $reSrc = $reSrc -replace '\\\{[A-Za-z][A-Za-z0-9]*\\?\}', '.+'
            $adminPatternRegex = [regex]::new('^' + $reSrc + '($|@)')
        } catch { $adminPatternRegex = $null }
    }

    # ------------------------------------------------------------------
    # Load every CSV up-front so we can cross-reference without re-reading.
    # ------------------------------------------------------------------
    $bases = Get-PimCsvBases
    $loaded = @{}
    foreach ($spec in $bases) {
        $base = $spec.base
        $resolved = Resolve-PimCsvPath -BaseName $base
        if (-not $resolved) {
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-IO-001' -Csv $base -Message "CSV not present on disk (neither .custom.csv nor .locked.csv exists)." -Suggestion "Copy $base.custom.sample.csv -> $base.custom.csv if this tenant uses this CSV; otherwise ignore."))
            $loaded[$base] = @{ header = @(); rows = @(); source = 'none'; path = $null }
            continue
        }
        try {
            $loaded[$base] = Read-PimCsvRows -BaseName $base
        } catch {
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-IO-001' -Csv $base -Message "Failed to read CSV: $($_.Exception.Message)"))
            $loaded[$base] = @{ header = @(); rows = @(); source = 'none'; path = $null }
        }
    }

    # ------------------------------------------------------------------
    # Build cross-reference indexes.
    # ------------------------------------------------------------------
    # All known GroupTags + which CSV they live in + IsRoleAssignable flag + TierLevel.
    $defGroupBases = @(
        'PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services',
        'PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments',
        'PIM-Definitions-Organization'
    )
    $groupTagIndex = @{} # GroupTag (lower) -> @{ Tag, Csv, Row, IsRoleAssignable, TierLevel, Kind }
    $allGroupTags  = New-Object System.Collections.ArrayList
    foreach ($db in $defGroupBases) {
        if (-not $loaded.ContainsKey($db)) { continue }
        $rows = $loaded[$db].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $tag) { continue }
            $key = $tag.ToLowerInvariant()
            $kind = if ($db -eq 'PIM-Definitions-Roles') { 'role-group' } else { 'permission-group' }
            $ira = (Get-PimRowValue -Row $r -Column 'IsRoleAssignable').ToUpperInvariant()
            $tier = Get-PimRowValue -Row $r -Column 'TierLevel'
            if (-not $groupTagIndex.ContainsKey($key)) {
                $groupTagIndex[$key] = @{
                    Tag = $tag; Csv = $db; Row = $i; Kind = $kind
                    IsRoleAssignable = ($ira -eq 'TRUE')
                    TierLevel = $tier
                }
                [void]$allGroupTags.Add($tag)
            }
        }
    }

    # AU tags from PIM-Definitions-AU.
    $auTagIndex = @{}
    if ($loaded.ContainsKey('PIM-Definitions-AU')) {
        $auRows = $loaded['PIM-Definitions-AU'].rows
        for ($i = 0; $i -lt $auRows.Count; $i++) {
            $tag = Get-PimRowValue -Row $auRows[$i] -Column 'AdministrativeUnitTag'
            if (-not $tag) { continue }
            $key = $tag.ToLowerInvariant()
            if (-not $auTagIndex.ContainsKey($key)) {
                $auTagIndex[$key] = @{ Tag = $tag; Row = $i }
            }
        }
    }

    # Admin UPNs (auto-derive if missing per the engine pattern).
    $adminIndex = @{} # upn-lower -> @{ Row, TierLevel, TargetPlatform, CreateTAP, AccountStatus, StatusChangeCode, ForwardMailsToContact, MailForwardAddress, UserName, Upn }
    $defaultDomain = if ($global:DefaultDomainUPN) { [string]$global:DefaultDomainUPN } else { $null }
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $adminRows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $adminRows.Count; $i++) {
            $r = $adminRows[$i]
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            if (-not $upn) {
                $un = Get-PimRowValue -Row $r -Column 'UserName'
                if ($un -and $defaultDomain) { $upn = "$un@$defaultDomain" }
            }
            if (-not $upn) { continue }
            $key = $upn.ToLowerInvariant()
            if (-not $adminIndex.ContainsKey($key)) {
                $adminIndex[$key] = @{
                    Row = $i; Upn = $upn
                    UserName        = Get-PimRowValue -Row $r -Column 'UserName'
                    TierLevel       = Get-PimRowValue -Row $r -Column 'TierLevel'
                    TargetPlatform  = Get-PimRowValue -Row $r -Column 'TargetPlatform'
                    CreateTAP       = (Get-PimRowValue -Row $r -Column 'CreateTAP').ToUpperInvariant()
                    AccountStatus   = Get-PimRowValue -Row $r -Column 'AccountStatus'
                    StatusChangeCode= Get-PimRowValue -Row $r -Column 'StatusChangeCode'
                    ForwardMailsToContact = (Get-PimRowValue -Row $r -Column 'ForwardMailsToContact').ToUpperInvariant()
                    MailForwardAddress    = Get-PimRowValue -Row $r -Column 'MailForwardAddress'
                }
            }
        }
    }

    # Tenant cache (entra-roles, aus) for stale checks.
    $cachedEntraRoleNames = @{}  # lower -> displayName
    $cachedAuNames        = @{}  # lower -> displayName / id
    if (Get-Command Read-PimTenantListCache -ErrorAction SilentlyContinue) {
        try {
            $cache = Read-PimTenantListCache
            if ($cache.entraRoles -and $cache.entraRoles.items) {
                foreach ($it in $cache.entraRoles.items) {
                    if ($it.displayName) { $cachedEntraRoleNames[([string]$it.displayName).ToLowerInvariant()] = [string]$it.displayName }
                }
            }
            if ($cache.aus -and $cache.aus.items) {
                foreach ($it in $cache.aus.items) {
                    if ($it.displayName) { $cachedAuNames[([string]$it.displayName).ToLowerInvariant()] = [string]$it.displayName }
                    if ($it.id) { $cachedAuNames[([string]$it.id).ToLowerInvariant()] = [string]$it.id }
                }
            }
        } catch { }
    }
    $cacheRolesPresent = $cachedEntraRoleNames.Count -gt 0
    $cacheAUsPresent   = $cachedAuNames.Count -gt 0

    # ------------------------------------------------------------------
    # PIM-FK-001: every GroupTag in every assignment CSV must be defined.
    # ------------------------------------------------------------------
    $tagRefs = @(
        @{ Csv = 'PIM-Assignments-Admins';          Cols = @('GroupTag') }
        @{ Csv = 'PIM-Assignments-Groups';          Cols = @('TargetGroupTag','SourceGroupTag') }
        @{ Csv = 'PIM-Assignments-Roles-Groups';    Cols = @('GroupTag') }
        @{ Csv = 'PIM-Assignments-Roles-AUs';       Cols = @('GroupTag') }
        @{ Csv = 'PIM-Assignments-Azure-Resources'; Cols = @('GroupTag') }
        @{ Csv = 'PIM-Assignments-Workloads';       Cols = @('GroupTag') }
    )
    $knownTagList = @($allGroupTags)
    foreach ($ref in $tagRefs) {
        if (-not $loaded.ContainsKey($ref.Csv)) { continue }
        $rows = $loaded[$ref.Csv].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            foreach ($col in $ref.Cols) {
                $val = Get-PimRowValue -Row $r -Column $col
                if (-not $val) { continue }
                if (-not $groupTagIndex.ContainsKey($val.ToLowerInvariant())) {
                    $suggestion = $null
                    $matches = Get-PimClosestMatches -Needle $val -Haystack $knownTagList -MaxDistance 5 -Top 3
                    if ($matches -and $matches.Count -gt 0) {
                        $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                        $suggestion = "Add '$val' to one of $(($defGroupBases | Where-Object { $_ -ne 'PIM-Definitions-Roles' }) -join ', '), or change this row to one of: $list."
                    } else {
                        $suggestion = "Add '$val' to one of the PIM-Definitions-* CSVs, or delete this row."
                    }
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-001' -Csv $ref.Csv -Row $i -Column $col `
                        -Message "$col '$val' referenced here is not defined in any PIM-Definitions-* CSV" -Suggestion $suggestion))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-FK-002: every Username in PIM-Assignments-Admins exists as a UPN
    # in Account-Definitions-Admins (auto-deriving UPN where needed).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        $rows = $loaded['PIM-Assignments-Admins'].rows
        $knownUpns = @($adminIndex.Values | ForEach-Object { $_.Upn })
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            if (-not $u) { continue }
            $key = $u.ToLowerInvariant()
            if ($adminIndex.ContainsKey($key)) { continue }
            # Try UPN-derivation match too (raw UserName -> UserName@defaultDomain).
            $derivedHit = $false
            if ($defaultDomain) {
                $derived = "$u@$defaultDomain"
                if ($adminIndex.ContainsKey($derived.ToLowerInvariant())) { $derivedHit = $true }
            }
            if ($derivedHit) { continue }
            $suggestion = $null
            $matches = Get-PimClosestMatches -Needle $u -Haystack $knownUpns -MaxDistance 5 -Top 3
            if ($matches -and $matches.Count -gt 0) {
                $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                $suggestion = "Add '$u' to Account-Definitions-Admins, or change this row to one of: $list."
            } else {
                $suggestion = "Add '$u' to Account-Definitions-Admins, or delete this row."
            }
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-002' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'Username' `
                -Message "Username '$u' is not defined in Account-Definitions-Admins (UserPrincipalName)." -Suggestion $suggestion))
        }
    }

    # ------------------------------------------------------------------
    # PIM-FK-003: every AdministrativeUnitTag in PIM-Assignments-Roles-AUs
    # exists in PIM-Definitions-AU.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Roles-AUs')) {
        $rows = $loaded['PIM-Assignments-Roles-AUs'].rows
        $knownAuTags = @($auTagIndex.Values | ForEach-Object { $_.Tag })
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $t = Get-PimRowValue -Row $r -Column 'AdministrativeUnitTag'
            if (-not $t) { continue }
            if ($auTagIndex.ContainsKey($t.ToLowerInvariant())) { continue }
            $suggestion = $null
            $matches = Get-PimClosestMatches -Needle $t -Haystack $knownAuTags -MaxDistance 5 -Top 3
            if ($matches -and $matches.Count -gt 0) {
                $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                $suggestion = "Add '$t' to PIM-Definitions-AU, or change this row to one of: $list."
            } else {
                $suggestion = "Add '$t' to PIM-Definitions-AU, or delete this row."
            }
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-003' -Csv 'PIM-Assignments-Roles-AUs' -Row $i -Column 'AdministrativeUnitTag' `
                -Message "AdministrativeUnitTag '$t' is not defined in PIM-Definitions-AU." -Suggestion $suggestion))
        }
    }

    # ------------------------------------------------------------------
    # PIM-RA-001: when an assignment binds a permission group to an Entra
    # ID role, the permission group must be IsRoleAssignable=TRUE.
    # ------------------------------------------------------------------
    foreach ($csv in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs')) {
        if (-not $loaded.ContainsKey($csv)) { continue }
        $rows = $loaded[$csv].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $tag) { continue }
            $k = $tag.ToLowerInvariant()
            if (-not $groupTagIndex.ContainsKey($k)) { continue }  # already flagged by PIM-FK-001
            $g = $groupTagIndex[$k]
            if (-not $g.IsRoleAssignable) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-RA-001' -Csv $csv -Row $i -Column 'GroupTag' `
                    -Message "GroupTag '$tag' is bound to an Entra ID role but the definition in $($g.Csv) has IsRoleAssignable=FALSE. Entra refuses role assignment to non-role-assignable groups." `
                    -Suggestion "Set IsRoleAssignable=TRUE in $($g.Csv) row $($g.Row + 1). The Entra group must be RECREATED with isAssignableToRole=true; the flag cannot be added in place."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-RA-002: when an admin is assigned DIRECTLY to a role-assignable
    # group, AssignmentType must be Eligible (Active is not supported by Entra).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        $rows = $loaded['PIM-Assignments-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            $at  = Get-PimRowValue -Row $r -Column 'AssignmentType'
            if (-not $tag -or -not $at) { continue }
            $k = $tag.ToLowerInvariant()
            if (-not $groupTagIndex.ContainsKey($k)) { continue }
            $g = $groupTagIndex[$k]
            if ($g.IsRoleAssignable -and $at -ieq 'Active') {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-RA-002' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'AssignmentType' `
                    -Message "AssignmentType=Active is not supported for direct admin assignment to role-assignable group '$tag'. Entra requires Eligible." `
                    -Suggestion "Change AssignmentType to 'Eligible' (admin activates JIT). See DESIGN.md section 2 for the structural rule."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-TIER-001: T2 admin nested into a path that reaches a T0 asset.
    # Conservative: only flag the direct admin->group hop where the admin's
    # tier is numerically higher than the target group's tier (T2 -> T0/T1).
    # ------------------------------------------------------------------
    function _PimTierNum([string]$v) {
        if (-not $v) { return $null }
        $m = [regex]::Match($v, '(?i)T(\d+)')
        if ($m.Success) { return [int]$m.Groups[1].Value }
        return $null
    }
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        $rows = $loaded['PIM-Assignments-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $u -or -not $tag) { continue }
            $admin = $adminIndex[$u.ToLowerInvariant()]
            $grp   = $groupTagIndex[$tag.ToLowerInvariant()]
            if (-not $admin -or -not $grp) { continue }
            $adminT = _PimTierNum $admin.TierLevel
            $grpT   = _PimTierNum $grp.TierLevel
            if ($adminT -ne $null -and $grpT -ne $null -and $adminT -gt $grpT) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-TIER-001' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'GroupTag' `
                    -Message "T$adminT admin '$u' is assigned to a T$grpT role-group '$tag'. Lower-tier admins reaching higher-tier assets is a privilege-escalation path." `
                    -Suggestion "Either raise the admin's TierLevel to T$grpT (matches the role), or split the role-group so the T$grpT capabilities live in a T$adminT-appropriate variant."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-TIER-002: admin's TierLevel != tier of the role-group they hit.
    # (Distinct from PIM-TIER-001 by treating exact mismatch as a warning,
    # not just direction-of-escalation.)
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        $rows = $loaded['PIM-Assignments-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $u -or -not $tag) { continue }
            $admin = $adminIndex[$u.ToLowerInvariant()]
            $grp   = $groupTagIndex[$tag.ToLowerInvariant()]
            if (-not $admin -or -not $grp) { continue }
            if (-not $admin.TierLevel -or -not $grp.TierLevel) { continue }
            if ($admin.TierLevel -ine $grp.TierLevel -and (_PimTierNum $admin.TierLevel) -le (_PimTierNum $grp.TierLevel)) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-TIER-002' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'GroupTag' `
                    -Message "Admin '$u' is TierLevel=$($admin.TierLevel) but role-group '$tag' is TierLevel=$($grp.TierLevel). Tier-mixing is allowed but confusing in audits." `
                    -Suggestion "Align tiers if intentional (preferred), otherwise document why this row crosses tiers."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-NAME-001: GroupTag doesn't match the naming-convention regex.
    # ------------------------------------------------------------------
    foreach ($db in $defGroupBases) {
        if (-not $loaded.ContainsKey($db)) { continue }
        $rows = $loaded[$db].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $tag = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $tag) { continue }
            if (-not $groupTagRegex.IsMatch($tag)) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-NAME-001' -Csv $db -Row $i -Column 'GroupTag' `
                    -Message "GroupTag '$tag' doesn't match the naming-convention regex." `
                    -Suggestion "Expected shape: <Name>-L<0-9>-T<0-2>-<CP|WDP|MP|APP|USER>-<ID|RES|DAT>[-S_AD] (overridable via PIM_NAMING.PimGroupTagRegex)."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-NAME-002: admin UPN doesn't match AdminAccountPattern.
    # ------------------------------------------------------------------
    if ($adminPatternRegex -and $loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            if (-not $upn) { continue }
            if (-not $adminPatternRegex.IsMatch($upn)) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-NAME-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'UserPrincipalName' `
                    -Message "UPN '$upn' doesn't match AdminAccountPattern '$($naming.AdminAccountPattern)'." `
                    -Suggestion "Either rename to fit the pattern, or override PIM_NAMING.AdminAccountPattern in your .custom.ps1."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-ORPHAN-001: admin row with zero PIM-Assignments-Admins references.
    # ------------------------------------------------------------------
    if ($adminIndex.Count -gt 0 -and $loaded.ContainsKey('PIM-Assignments-Admins')) {
        $usedAdmins = @{}
        foreach ($r in $loaded['PIM-Assignments-Admins'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            if ($u) { $usedAdmins[$u.ToLowerInvariant()] = $true }
        }
        foreach ($key in $adminIndex.Keys) {
            if (-not $usedAdmins.ContainsKey($key)) {
                $a = $adminIndex[$key]
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-ORPHAN-001' -Csv 'Account-Definitions-Admins' -Row $a.Row -Column 'UserPrincipalName' `
                    -Message "Admin '$($a.Upn)' has zero rows in PIM-Assignments-Admins -- the account exists but has no PIM reach." `
                    -Suggestion "Either add an admin->role-group assignment, or remove this row from Account-Definitions-Admins."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-ORPHAN-002: permission group with zero outbound assignment rows.
    # "Outbound" = appears as SourceGroupTag in PIM-Assignments-Groups OR
    # as GroupTag in any PIM-Assignments-Roles-* / Azure CSV.
    # ------------------------------------------------------------------
    $outboundTags = @{}
    if ($loaded.ContainsKey('PIM-Assignments-Groups')) {
        foreach ($r in $loaded['PIM-Assignments-Groups'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $s = Get-PimRowValue -Row $r -Column 'SourceGroupTag'
            if ($s) { $outboundTags[$s.ToLowerInvariant()] = $true }
        }
    }
    foreach ($csv in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources')) {
        if (-not $loaded.ContainsKey($csv)) { continue }
        foreach ($r in $loaded[$csv].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $t = Get-PimRowValue -Row $r -Column 'GroupTag'
            if ($t) { $outboundTags[$t.ToLowerInvariant()] = $true }
        }
    }
    foreach ($key in $groupTagIndex.Keys) {
        $g = $groupTagIndex[$key]
        if ($g.Kind -ne 'permission-group') { continue }
        if (-not $outboundTags.ContainsKey($key)) {
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-ORPHAN-002' -Csv $g.Csv -Row $g.Row -Column 'GroupTag' `
                -Message "Permission group '$($g.Tag)' has no outbound assignments (nothing targets it via PIM-Assignments-Groups SourceGroupTag, and it isn't bound to an Entra/Azure target)." `
                -Suggestion "Either bind it to a target (PIM-Assignments-Roles-*/Azure-Resources) and/or nest it under a role group, or remove the definition."))
        }
    }

    # ------------------------------------------------------------------
    # PIM-ORPHAN-003: role group with zero PIM-Assignments-Groups rows
    # nesting permission groups into it.
    # ------------------------------------------------------------------
    $rolesWithNested = @{}
    if ($loaded.ContainsKey('PIM-Assignments-Groups')) {
        foreach ($r in $loaded['PIM-Assignments-Groups'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $t = Get-PimRowValue -Row $r -Column 'TargetGroupTag'
            if ($t) { $rolesWithNested[$t.ToLowerInvariant()] = $true }
        }
    }
    foreach ($key in $groupTagIndex.Keys) {
        $g = $groupTagIndex[$key]
        if ($g.Kind -ne 'role-group') { continue }
        if (-not $rolesWithNested.ContainsKey($key)) {
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-ORPHAN-003' -Csv $g.Csv -Row $g.Row -Column 'GroupTag' `
                -Message "Role group '$($g.Tag)' has no permission groups nested into it via PIM-Assignments-Groups." `
                -Suggestion "Either nest one or more permission groups (TargetGroupTag = this tag) so admins assigned to this role group actually gain permissions, or remove the role definition."))
        }
    }

    # ------------------------------------------------------------------
    # PIM-DUP-001: same admin reaches the same target via 2+ role-group paths.
    # We compute path closure: admin --> role-group --> permission-group --> target.
    # ------------------------------------------------------------------
    # Build adjacency: roleGroupTag(lower) -> @(permissionGroupTag-lower)
    $roleToPerms = @{}
    if ($loaded.ContainsKey('PIM-Assignments-Groups')) {
        foreach ($r in $loaded['PIM-Assignments-Groups'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $t = Get-PimRowValue -Row $r -Column 'TargetGroupTag'
            $s = Get-PimRowValue -Row $r -Column 'SourceGroupTag'
            if (-not $t -or -not $s) { continue }
            $tk = $t.ToLowerInvariant()
            if (-not $roleToPerms.ContainsKey($tk)) { $roleToPerms[$tk] = New-Object System.Collections.ArrayList }
            [void]$roleToPerms[$tk].Add($s.ToLowerInvariant())
        }
    }
    # permissionGroupTag(lower) -> @( targetKey )
    $permToTargets = @{}
    function _AddTarget([hashtable]$map, [string]$pTagLower, [string]$targetKey) {
        if (-not $map.ContainsKey($pTagLower)) { $map[$pTagLower] = New-Object System.Collections.ArrayList }
        [void]$map[$pTagLower].Add($targetKey)
    }
    if ($loaded.ContainsKey('PIM-Assignments-Roles-Groups')) {
        foreach ($r in $loaded['PIM-Assignments-Roles-Groups'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $g = Get-PimRowValue -Row $r -Column 'GroupTag'
            $rn = Get-PimRowValue -Row $r -Column 'RoleDefinitionName'
            if (-not $g -or -not $rn) { continue }
            _AddTarget $permToTargets $g.ToLowerInvariant() "entra:$($rn.ToLowerInvariant())"
        }
    }
    if ($loaded.ContainsKey('PIM-Assignments-Roles-AUs')) {
        foreach ($r in $loaded['PIM-Assignments-Roles-AUs'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $g  = Get-PimRowValue -Row $r -Column 'GroupTag'
            $au = Get-PimRowValue -Row $r -Column 'AdministrativeUnitTag'
            $rn = Get-PimRowValue -Row $r -Column 'RoleDefinitionName'
            if (-not $g -or -not $au -or -not $rn) { continue }
            _AddTarget $permToTargets $g.ToLowerInvariant() "au:$($au.ToLowerInvariant()):$($rn.ToLowerInvariant())"
        }
    }
    if ($loaded.ContainsKey('PIM-Assignments-Azure-Resources')) {
        foreach ($r in $loaded['PIM-Assignments-Azure-Resources'].rows) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            $g = Get-PimRowValue -Row $r -Column 'GroupTag'
            $sc = Get-PimRowValue -Row $r -Column 'AzScope'
            $sp = Get-PimRowValue -Row $r -Column 'AzScopePermission'
            if (-not $g -or -not $sc -or -not $sp) { continue }
            _AddTarget $permToTargets $g.ToLowerInvariant() "az:$($sc.ToLowerInvariant()):$($sp.ToLowerInvariant())"
        }
    }
    # For each admin, walk admin -> role-group -> permission-group -> target,
    # collect per-target the set of role-group paths that reach it; flag dups.
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        # admin (lower) -> list of (roleGroupLower, assignmentRowIdx)
        $adminToRoleGroups = @{}
        $rows = $loaded['PIM-Assignments-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            $g = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $u -or -not $g) { continue }
            $uk = $u.ToLowerInvariant()
            if (-not $adminToRoleGroups.ContainsKey($uk)) { $adminToRoleGroups[$uk] = New-Object System.Collections.ArrayList }
            [void]$adminToRoleGroups[$uk].Add(@{ RoleGroup = $g; Row = $i })
        }
        foreach ($admin in $adminToRoleGroups.Keys) {
            # target -> @(roleGroup names) hit via this admin
            $targetMap = @{}
            $rowsHit = @{}  # target -> first row idx that introduced it
            foreach ($e in $adminToRoleGroups[$admin]) {
                $rg = $e.RoleGroup
                $rgKey = $rg.ToLowerInvariant()
                # BFS perm groups reachable from this role group (1-2 hops usually; depth cap = 5).
                $visited = @{ $rgKey = $true }
                $queue = New-Object System.Collections.Queue
                $queue.Enqueue($rgKey)
                $depth = 0
                while ($queue.Count -gt 0 -and $depth -lt 5) {
                    $depth++
                    $sizeSnap = $queue.Count
                    for ($q = 0; $q -lt $sizeSnap; $q++) {
                        $cur = $queue.Dequeue()
                        # Targets directly bound to this group:
                        if ($permToTargets.ContainsKey($cur)) {
                            foreach ($t in $permToTargets[$cur]) {
                                if (-not $targetMap.ContainsKey($t)) { $targetMap[$t] = New-Object System.Collections.ArrayList }
                                if (-not ($targetMap[$t] -contains $rg)) { [void]$targetMap[$t].Add($rg) }
                                if (-not $rowsHit.ContainsKey($t)) { $rowsHit[$t] = $e.Row }
                            }
                        }
                        # Walk nested:
                        if ($roleToPerms.ContainsKey($cur)) {
                            foreach ($child in $roleToPerms[$cur]) {
                                if (-not $visited.ContainsKey($child)) { $visited[$child] = $true; $queue.Enqueue($child) }
                            }
                        }
                    }
                }
            }
            foreach ($t in $targetMap.Keys) {
                $paths = @($targetMap[$t])
                if ($paths.Count -ge 2) {
                    $upn = ($adminIndex[$admin] | Select-Object -ExpandProperty Upn -ErrorAction SilentlyContinue)
                    if (-not $upn) { $upn = $admin }
                    [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-DUP-001' -Csv 'PIM-Assignments-Admins' -Row $rowsHit[$t] -Column 'GroupTag' `
                        -Message "Admin '$upn' reaches target '$t' via $($paths.Count) role-group paths: $($paths -join ', ')." `
                        -Suggestion "Pick the canonical role group and drop the others; duplicate paths cause audit confusion and complicate offboarding."))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-STALE-001/002: cache-relative stale checks.
    # ------------------------------------------------------------------
    if (-not $cacheRolesPresent) {
        [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-STALE-001' -Csv '<global>' `
            -Message "Tenant cache 'entra-roles' is missing or empty. Role-name freshness checks are skipped." `
            -Suggestion "Run: Open-PimManager.ps1 -RefreshTenantLists  (or click the 'no cache' badge in the UI)."))
    } else {
        foreach ($csv in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs')) {
            if (-not $loaded.ContainsKey($csv)) { continue }
            $rows = $loaded[$csv].rows
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                $rn = Get-PimRowValue -Row $r -Column 'RoleDefinitionName'
                if (-not $rn) { continue }
                if (-not $cachedEntraRoleNames.ContainsKey($rn.ToLowerInvariant())) {
                    $matches = Get-PimClosestMatches -Needle $rn -Haystack @($cachedEntraRoleNames.Values) -MaxDistance 6 -Top 3
                    $suggestion = if ($matches -and $matches.Count -gt 0) {
                        "Did you mean: $((($matches | ForEach-Object { $_.Value }) -join ', '))?"
                    } else {
                        "Verify the role name is spelled correctly and the tenant cache is up to date (click the cache badge to refresh)."
                    }
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-STALE-001' -Csv $csv -Row $i -Column 'RoleDefinitionName' `
                        -Message "RoleDefinitionName '$rn' is not in the entra-roles tenant cache. Either the role was renamed/removed or the cache is out of date." `
                        -Suggestion $suggestion))
                }
            }
        }
    }
    if ($cacheAUsPresent) {
        foreach ($csv in @('PIM-Assignments-Roles-AUs','PIM-Definitions-AU')) {
            if (-not $loaded.ContainsKey($csv)) { continue }
            $rows = $loaded[$csv].rows
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                $au = Get-PimRowValue -Row $r -Column 'AdministrativeUnitTag'
                if (-not $au) { continue }
                # Try both displayName + id forms.
                if ($cachedAuNames.ContainsKey($au.ToLowerInvariant())) { continue }
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-STALE-002' -Csv $csv -Row $i -Column 'AdministrativeUnitTag' `
                    -Message "AdministrativeUnitTag '$au' is not in the aus tenant cache. Either the AU was renamed/removed or the cache is out of date." `
                    -Suggestion "Verify the AU exists, or refresh the cache (click the 'aus' cache badge in the UI)."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-STATUS-001: AccountStatus Disabled/Revoked but no StatusChangeCode
    # in MSP variant.
    # ------------------------------------------------------------------
    $variant = $global:PIM_ConfigVariant
    if ($variant -eq 'msp' -and $loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $st = (Get-PimRowValue -Row $r -Column 'AccountStatus')
            if ($st -ieq 'Disabled' -or $st -ieq 'Revoked') {
                $code = Get-PimRowValue -Row $r -Column 'StatusChangeCode'
                if (-not $code) {
                    $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-STATUS-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'StatusChangeCode' `
                        -Message "AccountStatus='$st' for '$upn' but StatusChangeCode is empty. MSP variant refuses status changes without the CISO-issued code." `
                        -Suggestion "Get the per-admin code from the customer's pim-status-* Key Vault secret and paste into StatusChangeCode."))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-DOMAIN-001: MailForwardAddress set but ForwardMailsToContact=FALSE.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $addr = Get-PimRowValue -Row $r -Column 'MailForwardAddress'
            $fwd  = (Get-PimRowValue -Row $r -Column 'ForwardMailsToContact').ToUpperInvariant()
            if ($addr -and $fwd -ne 'TRUE') {
                $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-DOMAIN-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'MailForwardAddress' `
                    -Message "MailForwardAddress='$addr' is set for '$upn' but ForwardMailsToContact='$fwd' -- engine will ignore the forward address." `
                    -Suggestion "Either set ForwardMailsToContact=TRUE to activate the forward, or clear MailForwardAddress to remove the misleading config."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-RING-001: Ring column (deployment-ring rollout staging) must be
    # blank, 0, 1, or 2. Anything else is treated as 0 by the engine (full
    # reach) -- a typo like 'Ring=22' silently grants ALL tenants. Severity
    # is WARNING by design (never blocks Save); the Validate tab's Fix-all
    # repairs it to Ring=2 (least privilege).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $ringVal = (Get-PimRowValue -Row $r -Column 'Ring').Trim()
            if (-not $ringVal) { continue }
            if ($ringVal -notin @('0','1','2')) {
                $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-RING-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Ring' `
                    -Message "Ring '$ringVal' for '$upn' is not a valid deployment ring (blank, 0, 1, or 2). The engine treats invalid values as 0 = ALL tenants -- a typo here silently over-grants." `
                    -Suggestion "Use Fix-all (sets Ring=2, least privilege), or set Ring to 2 / 1 / 0 manually."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-TAP-001: CreateTAP=TRUE but TargetPlatform=AD (TAP is Entra-only).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $tap = (Get-PimRowValue -Row $r -Column 'CreateTAP').ToUpperInvariant()
            $plat = (Get-PimRowValue -Row $r -Column 'TargetPlatform').ToUpperInvariant()
            if ($tap -eq 'TRUE' -and $plat -eq 'AD') {
                $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
                [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-TAP-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'CreateTAP' `
                    -Message "CreateTAP=TRUE for '$upn' but TargetPlatform=AD. Temporary Access Pass is an Entra-ID-only feature; AD-only admins cannot have a TAP." `
                    -Suggestion "Set CreateTAP=FALSE for AD-only admins, or change TargetPlatform to ID/Both if the admin should also exist in Entra."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-WL-*: workload RBAC rows (PIM-Assignments-Workloads). The engine
    # applies these via workloads/connectors/<id>.connector.json, so a row
    # whose Workload has no connector file is silently unappliable -- catch
    # it here. GroupTag FK coverage comes from PIM-FK-001 (tagRefs above).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Workloads')) {
        $connectorIds = @()
        try {
            $connDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'workloads\connectors'
            if (Test-Path -LiteralPath $connDir) {
                $connectorIds = @(Get-ChildItem -LiteralPath $connDir -Filter '*.connector.json' |
                    ForEach-Object { $_.Name -replace '\.connector\.json$', '' })
            }
        } catch { $connectorIds = @() }

        $rows = $loaded['PIM-Assignments-Workloads'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }

            # PIM-WL-001: Workload must have a connector definition.
            $wl = (Get-PimRowValue -Row $r -Column 'Workload').Trim()
            if (-not $wl) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-WL-001' -Csv 'PIM-Assignments-Workloads' -Row $i -Column 'Workload' `
                    -Message "Workload is empty -- the engine cannot pick a connector for this row." `
                    -Suggestion ("Set Workload to one of: " + ($(if ($connectorIds.Count) { $connectorIds -join ', ' } else { '(no connectors found under workloads\connectors)' })) + ".")))
            } elseif ($connectorIds.Count -gt 0 -and ($connectorIds -notcontains $wl)) {
                $suggestion = "Available connectors: $($connectorIds -join ', '). Add workloads\connectors\$wl.connector.json or fix the Workload value."
                $near = Get-PimClosestMatches -Needle $wl -Haystack $connectorIds -MaxDistance 5 -Top 2
                if ($near -and $near.Count -gt 0) {
                    $suggestion = "Did you mean: $(($near | ForEach-Object { $_.Value }) -join ', ')? Available connectors: $($connectorIds -join ', ')."
                }
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-WL-001' -Csv 'PIM-Assignments-Workloads' -Row $i -Column 'Workload' `
                    -Message "Workload '$wl' has no connector (workloads\connectors\$wl.connector.json not found) -- the engine skips this row with an error." `
                    -Suggestion $suggestion))
            }

            # PIM-WL-002: RoleName is required (it is matched against the
            # connector's live role list at apply time).
            $roleName = (Get-PimRowValue -Row $r -Column 'RoleName').Trim()
            if (-not $roleName) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-WL-002' -Csv 'PIM-Assignments-Workloads' -Row $i -Column 'RoleName' `
                    -Message "RoleName is empty -- the engine cannot resolve which workload role to assign." `
                    -Suggestion "Use the Workload delegation panel on the Delegation Map tab to pick a live role name, or copy it from the workload's admin portal."))
            }

            # PIM-WL-003: Action must be blank (= Assign), Assign, or Remove.
            $action = (Get-PimRowValue -Row $r -Column 'Action').Trim()
            if ($action -and $action -notin @('Assign','Remove')) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-WL-003' -Csv 'PIM-Assignments-Workloads' -Row $i -Column 'Action' `
                    -Message "Action '$action' is not recognised (valid: Assign, Remove, or blank = Assign). The engine treats unknown actions as errors at apply time." `
                    -Suggestion "Change Action to Assign or Remove (or clear it for the Assign default)."))
            }
        }
    }

    return [ordered]@{
        violations     = @($violations.ToArray())
        ranAt          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        cacheFreshness = $cacheFreshness
        summary        = [ordered]@{
            errors   = @($violations | Where-Object { $_.Severity -eq 'error'   }).Count
            warnings = @($violations | Where-Object { $_.Severity -eq 'warning' }).Count
            infos    = @($violations | Where-Object { $_.Severity -eq 'info'    }).Count
            total    = $violations.Count
        }
    }
}
