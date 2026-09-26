#Requires -Version 5.1
# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when it is dot-sourced without the full PIM-Functions module.
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-DateSafe.ps1')
}
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

    Reads all 14 entities from the SQL store via Read-PimRows (SQL-only since
    2026-09-12 -- there is no file store).

    All rules degrade gracefully when source data is missing: an entity whose
    read FAILS becomes a single PIM-STORE-001 warning, and dependent FK checks
    for it are skipped. An entity with no rows is simply empty.

.NOTES
    Caches nothing on disk; the 14 CSVs are small enough that a fresh read
    on every call is well under 1s. The HTTP endpoint re-runs on demand.
#>

# ---------------------------------------------------------------------------
# Shared date-expression resolver (PIM-SCHED-* rules + /api/resolve-date).
# Same file the engine dot-sources -- GUI, validator and engine must resolve
# identically. Guarded: if the layout is unusual and the file is missing, the
# SCHED rules skip instead of breaking the whole validator.
# ---------------------------------------------------------------------------
$_dateExprLib = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-DateExpression.ps1'
if (Test-Path -LiteralPath $_dateExprLib) { . $_dateExprLib }

# Warning override / acknowledgement POST-FILTER (REQUIREMENTS §11). Loaded
# here so the single hook below (one call before the validator returns) can
# downgrade operator-acknowledged warnings to 'acknowledged' without touching
# any rule's emit logic. Guarded: missing file -> no overrides applied.
$_warnOverrideLib = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-WarningOverrides.ps1'
if (Test-Path -LiteralPath $_warnOverrideLib) { . $_warnOverrideLib }

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
        [string]$Suggestion,
        # Stable per-instance identity for the warning-override post-filter
        # (REQUIREMENTS §11): the override key is Code + Subject + Target. The
        # rules an operator most often overrules (PIM-DUP-001, PIM-ORPHAN-001)
        # stamp these; other rules leave them blank and scope by Csv/Row.
        [string]$Subject,
        [string]$Target,
        # 🔴 B7 (2026-09-10) -- WHERE THE REMEDY LIVES, when it is NOT on the row that is wrong.
        # PIM-RA-001 is reported against the ASSIGNMENT row, but the field to change
        # (IsRoleAssignable) is on the DEFINITION row in a different CSV. The GUI's quick-fix
        # registry only ever had the finding's own Csv/Row, so it could not offer a button at all
        # -- the operator got "Open in Grid" and nothing else, and reported "bug: cannot fix this".
        # Any rule whose fix is elsewhere can now say so, instead of leaving the GUI to guess.
        [string]$FixCsv,
        [AllowNull()][object]$FixRow = $null,
        [string]$FixColumn,
        [string]$FixValue
    )
    [pscustomobject]@{
        Severity   = $Severity
        Code       = $Code
        Csv        = $Csv
        Row        = $Row
        Column     = $Column
        Message    = $Message
        Suggestion = $Suggestion
        Subject    = $Subject
        Target     = $Target
        FixCsv     = $FixCsv
        FixRow     = $FixRow
        FixColumn  = $FixColumn
        FixValue   = $FixValue
    }
}

function Get-PimRowValue {
    # Safe lookup that handles both OrderedDictionary (Read-PimRows output)
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

function Test-PimMailForwardAddressIsReal {
    # Decides whether a MailForwardAddress column value is a REAL forwarding
    # address or just a "no address" sentinel. The schema reuses the literal
    # string 'FALSE' (and blanks / 'no' / '0') to mean "no forwarding address",
    # so an address column of 'FALSE' must NOT be treated as a configured
    # address. Returns $true ONLY for something that looks like an email
    # address (contains '@' with text either side).
    #
    # The engine apply path (PIM-Functions.psm1) calls the same predicate before
    # invoking Set-PimMailboxForwarding, so validator + engine agree: a sentinel
    # is never forwarded to, and a real address with forwarding off is the only
    # genuine misconfiguration.
    param([AllowNull()][object]$Value)
    $s = ([string]$Value).Trim()
    if (-not $s) { return $false }
    switch ($s.ToUpperInvariant()) {
        'FALSE' { return $false }
        'NO'    { return $false }
        '0'     { return $false }
        'NONE'  { return $false }
        'N/A'   { return $false }
        default {
            # A real address: text @ text . text (no spaces).
            return ($s -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
        }
    }
}

function Get-PimCacheFreshness {
    # Maps the stored tenant caches (SQL pim.TenantCache) to 'live' / 'stale' / 'none' so the UI
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
        # SQL pim.TenantCache (Get-PimTenantCacheEntry, _tenantSync.ps1) -- no cache files (SQL-only).
        if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
            $parsed = $null
            try { $parsed = Get-PimTenantCacheEntry -Kind $kind.k } catch { $parsed = $null }
            if ($null -ne $parsed) {
                try {
                    # IMP-02: was an unguarded [datetime]::Parse -- a malformed stamp threw
                    # instead of reporting 'stale'. Unreadable now means stale, which is the
                    # safe reading of "we cannot prove this cache is fresh".
                    $t = if ($parsed) { Get-PimUtcStamp $parsed.refreshedUtc } else { $null }
                    if ($null -ne $t) {
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
    <#
      🔴 BUG-106 -- -PendingRows.

      This validation BLOCKS the commit ("13 validation error(s) -- Save is blocked"). It read
      only the SAVED store, so it could only ever describe the state BEFORE the change. The
      operator staged every available fix, re-ran, and got the same 13 errors:

          errors are in the saved store
        -> commit is blocked while errors > 0
        -> the fixes live in pendingChanges, which this function never saw
        -> the only thing that would clear the errors is the commit they block.

      Reported as "i have tried everything fix all but i cannot commit" -- and clicking every
      "Set to Eligible" and "Fix all auto-fixable errors" was exactly right and could never
      have worked.

      🔑 A PRE-FLIGHT CHECK MUST VALIDATE THE STATE THE COMMIT WOULD PRODUCE, not the state it
      is replacing. Otherwise the gate can only ever refuse the fix.

      -PendingRows is @{ '<entity base>' = @(<row objects>) } and REPLACES that entity's rows
      for this run. Entities absent from the hashtable are read from the store as before, so an
      empty/omitted overlay reproduces the old behaviour exactly.
    #>
    [CmdletBinding()]
    param([hashtable]$PendingRows)

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
    # 🔴 BUG-145 -- THE VALIDATOR AND THE ENGINE DISAGREED ABOUT WHAT A VALID GROUP NAME IS, and the
    # validator was the stricter of the two, so it warned about names the engine considers correct.
    # `Test-PimGroupName` (engine/_shared/PIM-Naming.ps1) accepts TWO shapes:
    #     (a) the canonical  [PIM-]<...>-L<n>-T<0-2>-<CP|WDP|MP|APP|USER>-<ID|RES|DAT>[-S_*]
    #     (b) the SIMPLE     PIM-{Role}[-{Department}]   e.g. 'PIM-Helpdesk-IT', 'PIM-ROLE-ciooffice'
    # This fallback regex only ever accepted (a). Every group named with the simple convention --
    # which is the convention the Manager's own wizards produce -- therefore drew a false
    # PIM-NAME-001 warning. Measured 2026-09-12: the operator's internal environment reported
    # 755 warnings, the great majority of them this rule firing on correctly-named groups.
    # 🔑 ONE PREDICATE, NOT TWO. The same lesson is already written into REQUIREMENTS §1188 for the
    # mail-forward sentinel -- "Keep validator + engine on the ONE shared predicate
    # (Test-PimMailForwardAddressIsReal)". A second, privately-maintained copy of a rule does not
    # stay in step; it just decides which of the two is wrong. So when the engine's predicate is
    # loaded we CALL it, and the regex below survives only as the no-engine fallback.
    # 🪤 An explicitly-configured PimGroupTagRegex still wins over both -- that is the customer
    # deliberately narrowing the convention, and it must not be silently widened by this change.
    $groupTagTest = $null
    if (-not $groupTagRegex -and (Get-Command Test-PimGroupName -ErrorAction SilentlyContinue)) {
        $groupTagTest = { param($t) try { [bool](Test-PimGroupName -Name "$t") } catch { $true } }
    }
    if (-not $groupTagRegex -and -not $groupTagTest) {
        $groupTagRegex = [regex]::new('^(PIM-)?.+-L[0-9]+-T[0-2]-(CP|WDP|MP|APP|USER)-(ID|RES|DAT)(-S_[A-Za-z0-9]+)?$', 'IgnoreCase')
    }
    # Admin UPN patterns: customer-overridable token-style ('adm_{Owner}'), turned into permissive regexes.
    # v2.4.171: TWO conventions -- AdminAccountPattern (day-2-day, no level/tier
    # markers) and AdminAccountPatternHighPriv (dedicated high-priv accounts,
    # -L0-T0- markers). A row's Purpose column picks which one applies; blank
    # Purpose accepts either.
    function ConvertTo-PimPatternRegex([string]$tplate, [string]$adminWord = 'Admin') {
        if (-not $tplate) { return $null }
        try {
            # 🔴 {AdminWord} (v2.4.333) is ONE configured literal, not a wildcard. As `.*` it let 'Adm-MK-AD'
            # and any other near-miss satisfy the admin convention -- the rule lost its teeth the day
            # the word became configurable. Substitute the word BEFORE the generic token pass.
            $aw = if ("$adminWord".Trim()) { "$adminWord".Trim() } else { 'Admin' }
            $tplate = $tplate -replace '\{AdminWord\}', $aw.Replace('$', '$$')
            # Tokens like {Owner} -> .* ; escape the rest.
            $reSrc = [regex]::Escape($tplate)
            # 🔴 BUG-144 -- `.+` PUNISHED THE DEFAULT ADMIN TYPE. A token became `.+` (ONE-or-more),
            # but `{AdminTypePrefix}` is legitimately EMPTY: PIM-Naming.ps1's AdminTypePrefixes maps
            # 'internal-adminuser' -> '' and 'external-guest' -> '', and only 'external-adminuser'
            # carries 'x-'. So `{AdminTypePrefix}Admin-{Initial}{Platform}` compiled to
            # `^.+Admin-.+.+($|@)`, which REQUIRES at least one character before "Admin-" --
            # and therefore every ordinary internal admin and every guest got a false
            # PIM-NAME-002 warning, while an external `x-Admin-...` passed.
            # Measured 2026-09-12 on the operator's internal environment: 'Admin-Helpdesk-AD@...'
            # and 'Admin-Helpdesk-ID@...' both flagged, both correct.
            # 🪤 THIS IS THE SECOND TIME THIS ONE LINE HAS MADE EVERY LEGITIMATE UPN WARN. The
            # previous round was the `}`-escaping asymmetry noted below; the fix changed how the
            # token was MATCHED and left the quantifier it expands to unexamined. A rule that can
            # only ever fire is indistinguishable from a rule that is working, which is why this
            # now has a regression test over the SHIPPED pattern and all three admin types
            # (tests/Test-PimNamingConventionRule.ps1).
            # `.*` keeps this a permissive SHAPE check -- the literal 'Admin-' is still required --
            # without demanding that an optional token be non-empty.
            # NB: [regex]::Escape escapes '{' but NOT '}' (.NET asymmetry), so the closing brace
            # must be matched optionally-escaped -- the old pattern ('\\\}') never matched, the
            # token survived as a literal, and EVERY legitimate UPN got a false warning then too.
            $reSrc = $reSrc -replace '\\\{[A-Za-z][A-Za-z0-9]*\\?\}', '.*'
            # 2026-09-21 (operator, EFIF: "i dont see the problem here" -- 'adm-e-chau-t0-c' vs '...-T0-...'): a UPN is
            # case-INsensitive in Entra, so the convention is too. Case-sensitive, every lower-case 't0'/'t1' warned.
            [regex]::new('^' + $reSrc + '($|@)', 'IgnoreCase')
        } catch { $null }
    }
    $adminPatternRegex = $null
    $adminPatternHighPrivRegex = $null
    if ($naming -and $naming.ContainsKey('AdminAccountPattern') -and $naming.AdminAccountPattern) {
        $adminPatternRegex = ConvertTo-PimPatternRegex ([string]$naming.AdminAccountPattern) ([string]$naming.AdminWord)
    }
    if ($naming -and $naming.ContainsKey('AdminAccountPatternHighPriv') -and $naming.AdminAccountPatternHighPriv) {
        $adminPatternHighPrivRegex = ConvertTo-PimPatternRegex ([string]$naming.AdminAccountPatternHighPriv) ([string]$naming.AdminWord)
    }

    # ------------------------------------------------------------------
    # Load every CSV up-front so we can cross-reference without re-reading.
    # ------------------------------------------------------------------
    $bases = Get-PimCsvBases
    $loaded = @{}
    # SQL-only (2026-09-12): data lives in pim.Rows. Read-PimRows is the single chokepoint; there is
    # no on-disk presence check any more (PIM-IO-001 "file not present" is gone with the file store).
    foreach ($spec in $bases) {
        $base = $spec.base
        try {
            $loaded[$base] = Read-PimRows -BaseName $base
        } catch {
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-STORE-001' -Csv $base -Message "Failed to read rows from the SQL store: $($_.Exception.Message)"))
            $loaded[$base] = @{ header = @(); rows = @(); source = 'none'; path = $null }
        }
        # BUG-106: overlay the operator's UNCOMMITTED rows for this entity, so what is validated
        # is the state the commit WOULD produce. Done here, at the single load seam, so every
        # rule below cross-references the pending world consistently -- a partial overlay would
        # report phantom foreign-key breaks between pending and saved rows, which is worse than
        # the deadlock it replaces.
        if ($PendingRows -and $PendingRows.ContainsKey($base)) {
            $pend = @($PendingRows[$base])
            $hdr  = @($loaded[$base].header)
            if (-not $hdr -or $hdr.Count -eq 0) {
                # No saved header (a brand-new entity): derive it from the pending rows.
                $hdr = @()
                foreach ($r in $pend) { foreach ($p in $r.PSObject.Properties.Name) { if ($hdr -notcontains $p) { $hdr += $p } } }
            }
            $loaded[$base] = @{ header = $hdr; rows = $pend; source = 'pending'; path = $loaded[$base].path }
        }
    }

    # ------------------------------------------------------------------
    # Build cross-reference indexes.
    # ------------------------------------------------------------------
    # All known GroupTags + which CSV they live in + IsRoleAssignable flag + TierLevel.
    $defGroupBases = @(
        'PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services',
        'PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments',
        'PIM-Definitions-Organization','PIM-Definitions-Projects','PIM-Definitions-CrossOrg'
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
                    # B7: the DISPLAY NAME is what an operator has to find in Entra ID to act on a
                    # finding. Without it PIM-RA-001 could only say "the group must be recreated"
                    # without saying WHICH group -- which is a description of a problem, not a remedy.
                    GroupName = (Get-PimRowValue -Row $r -Column 'GroupName')
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
    $adminIndex = @{} # upn-lower (or UserName-lower when the row carries no UPN) -> @{ Row, TierLevel, TargetPlatform, CreateTAP, AccountStatus, StatusChangeCode, UserName, Upn }
    $adminUserNames = New-Object System.Collections.Generic.HashSet[string]   # every admin UserName (lower) -- the identity
    $defaultDomain = if ($global:DefaultDomainUPN) { [string]$global:DefaultDomainUPN } else { $null }
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $adminRows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $adminRows.Count; $i++) {
            $r = $adminRows[$i]
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            $un0 = Get-PimRowValue -Row $r -Column 'UserName'
            if ($un0) { [void]$adminUserNames.Add($un0.Trim().ToLowerInvariant()) }
            if (-not $upn) {
                if ($un0 -and $defaultDomain) { $upn = "$un0@$defaultDomain" }
            }
            # 🔴 (2.4.377, operator 2026-09-19: "remember we need to separate the username and upn from each other, as we in
            # pim v1 used username and then used domain pairing when creating"). The admin's IDENTITY is its UserName -- the
            # store key (Get-PimStoreRowKey) and the engine's KeyOf -- and the UPN is only COMPOSED at create
            # (UserName@<Admin account domain>, Get-PimAdminUpnDomain). A v1 row carries NO UserPrincipalName, and in the
            # hosted Manager no domain is pinned, so this index skipped every such admin: all 15 EFIF memberships were
            # refused as PIM-FK-002 "not defined" while the 6 admins were in the store. Index them by UserName instead.
            $key = if ($upn) { $upn.ToLowerInvariant() } elseif ($un0) { $un0.Trim().ToLowerInvariant() } else { $null }
            if (-not $key) { continue }
            if (-not $upn) { $upn = $un0 }
            if (-not $adminIndex.ContainsKey($key)) {
                $adminIndex[$key] = @{
                    Row = $i; Upn = $upn
                    UserName        = Get-PimRowValue -Row $r -Column 'UserName'
                    TierLevel       = Get-PimRowValue -Row $r -Column 'TierLevel'
                    TargetPlatform  = Get-PimRowValue -Row $r -Column 'TargetPlatform'
                    CreateTAP       = (Get-PimRowValue -Row $r -Column 'CreateTAP').ToUpperInvariant()
                    AccountStatus   = Get-PimRowValue -Row $r -Column 'AccountStatus'
                    StatusChangeCode= Get-PimRowValue -Row $r -Column 'StatusChangeCode'
                }
            }
        }
    }

    # 🔴 THE REPLICATED ADMINS ARE ADMINS TOO (RIDE, 2026-09-22: "tons of errors here" -- 11x PIM-FK-002
    # on a managed tenant whose admins had just arrived from the master).
    # On an MSP slave the downlink writes the master's admins into their OWN entity,
    # 'Account-Definitions-Admins-Central' (PIM-Downlink.ps1 Invoke-PimDownlinkAdminApply), because they
    # are governed by the master and must never be edited locally. The slave's own
    # 'Account-Definitions-Admins' holds only its LOCAL admins. The memberships arrive in the same pull
    # and name those central accounts -- so an index built from the local entity alone declares every
    # replicated membership an orphan, with a "Remove this assignment" button that would undo the
    # replication and a "Add ... to admins" button that would fork a local copy of a master-owned
    # account. Measured on RIDE: 18 central admins, 3 local, 11 errors, all of them false.
    # Kept as a SEPARATE set rather than merged into $adminIndex on purpose: every other admin rule
    # below reports by ROW INDEX into Account-Definitions-Admins, so a central row in that index would
    # point findings at the wrong row -- and these rows are read-only anyway, so none of those rules
    # (naming, TAP, orphan, status, ring/target) has anything actionable to say about them.
    $centralAdminNames = New-Object System.Collections.Generic.HashSet[string]   # UserName AND UPN, lower
    $centralAdminList  = New-Object System.Collections.Generic.List[string]      # for the did-you-mean haystack
    if (Get-Command Read-PimRows -ErrorAction SilentlyContinue) {
        try {
            foreach ($cr in @((Read-PimRows -BaseName 'Account-Definitions-Admins-Central').rows)) {
                foreach ($col in @('UserName', 'UserPrincipalName')) {
                    $cv = "$(Get-PimRowValue -Row $cr -Column $col)".Trim()
                    if (-not $cv) { continue }
                    if ($centralAdminNames.Add($cv.ToLowerInvariant())) { $centralAdminList.Add($cv) }
                }
            }
        } catch {
            # No such entity (single tenant, or a master) -- not a finding. Only a slave has one.
        }
    }
    $isKnownAdminName = {
        param([string]$Name)
        $k = "$Name".Trim().ToLowerInvariant()
        if (-not $k) { return $false }
        if ($centralAdminNames.Contains($k)) { return $true }
        # a full UPN whose local part is a central admin's UserName is a reference to that admin
        if ($k.Contains('@') -and $centralAdminNames.Contains($k.Substring(0, $k.IndexOf('@')))) { return $true }
        return $false
    }

    # Tenant cache (entra-roles, aus, azure-scopes) for stale / orphan checks.
    $cachedEntraRoleNames = @{}  # lower -> displayName
    $cachedAuNames        = @{}  # lower -> displayName / id
    $cachedAzureScopes    = @{}  # lower(scopePath|id) -> displayName
    $cachedAzureScopesPresent = $false
    # 🔴 CERTAINTY, NOT A HEDGE (operator, 2026-09-12: "the stale-002 looks wrong as it must be 100%
    # sure if it exist in cache or not"). Every cache-driven finding used to say "either it was
    # removed OR the cache is out of date" -- which tells the operator nothing they can act on. So
    # each cache now carries WHEN it was read and HOW MANY items it holds:
    #   * fresh (read within $cacheFreshHours)  -> the rule speaks DEFINITIVELY, naming the time + count;
    #   * stale / unstamped / absent             -> the rule makes NO per-row claim at all, and emits ONE
    #                                              info finding saying the check could not run and why.
    # Same 24h threshold as Get-PimCacheFreshness, so the UI badge and the findings agree.
    $cacheFreshHours = 24
    $cacheInfo = @{}   # key (entraRoles|aus|azureScopes) -> @{ fresh; stamp; count; ageText; present }
    $describeCache = {
        param($entry)
        $info = @{ present = $false; fresh = $false; stamp = $null; count = 0; ageText = 'absent' }
        if ($null -eq $entry) { return $info }
        $info.present = $true
        $info.count = @($entry.items | Where-Object { $_ }).Count
        $t = $null
        try { $t = Get-PimUtcStamp $entry.refreshedUtc } catch { $t = $null }
        if ($null -eq $t) { $info.ageText = 'of unknown age (no readable refreshedUtc)'; return $info }
        $info.stamp = $t
        $ageH = ((Get-Date).ToUniversalTime() - $t).TotalHours
        $info.ageText = if ($ageH -lt 1) { '{0:N0} minute(s) old' -f ($ageH * 60) } else { '{0:N1} hour(s) old' -f $ageH }
        $info.fresh = ($ageH -lt $cacheFreshHours -and $info.count -gt 0)
        return $info
    }
    if (Get-Command Read-PimTenantListCache -ErrorAction SilentlyContinue) {
        try {
            $cache = Read-PimTenantListCache
            $cacheInfo['entraRoles']  = & $describeCache $cache.entraRoles
            $cacheInfo['aus']         = & $describeCache $cache.aus
            $cacheInfo['azureScopes'] = & $describeCache $cache.azureScopes
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
            if ($cache.azureScopes -and $cache.azureScopes.items) {
                foreach ($it in $cache.azureScopes.items) {
                    $cachedAzureScopesPresent = $true
                    if ($it.scopePath) { $cachedAzureScopes[([string]$it.scopePath).ToLowerInvariant()] = [string]$it.displayName }
                    if ($it.id)        { $cachedAzureScopes[([string]$it.id).ToLowerInvariant()]        = [string]$it.displayName }
                }
            }
        } catch {
            # 🔴 §49. THIS CATCH USED TO BE EMPTY, AND THAT IS HOW A RULE DISAPPEARS.
            # Every cache-driven rule below (PIM-ORPHAN-AZ-001, PIM-STALE-*, the AU/role staleness
            # checks) is gated on "is the cache present?", so a cache read that THROWS is
            # indistinguishable from a tenant that has no cache: the rules quietly stop running and
            # the preflight still reports clean. Measured 2026-09-08 -- a broken test stub threw in
            # here, PIM-ORPHAN-AZ-001 never ran, and the failure looked like a validator defect.
            # 🪤 An empty catch turns a loud failure into a silent loss of coverage. Keep the
            # tolerance (a missing cache must never fail a preflight) but never keep the silence.
            Write-Warning ("tenant-list cache could not be read, so the cache-driven rules " +
                           "(orphaned Azure scope, stale role/AU) DID NOT RUN: $($_.Exception.Message)")
        }
    }
    $cacheRolesPresent = $cachedEntraRoleNames.Count -gt 0
    $cacheAUsPresent   = $cachedAuNames.Count -gt 0
    foreach ($ck in @('entraRoles','aus','azureScopes')) {
        if (-not $cacheInfo.ContainsKey($ck)) { $cacheInfo[$ck] = @{ present = $false; fresh = $false; stamp = $null; count = 0; ageText = 'absent' } }
    }
    $cacheReadAt = { param($ci) if ($ci.stamp) { $ci.stamp.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'an unknown time' } }

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
                    if (@($matches).Count -gt 0) {
                        $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                        $suggestion = "Define '$val' in one of $(($defGroupBases | Where-Object { $_ -ne 'PIM-Definitions-Roles' }) -join ', '), or change this row to one of: $list."
                    } else {
                        $suggestion = "Define '$val' in the matching Definitions entity, or delete this row."
                    }
                    # BUG-90: stamp the BUSINESS KEY so the GUI can identify this finding by the
                    # thing it is about instead of by a row index (a position the user never sees
                    # and which shifts whenever a row above it is inserted or deleted).
                    # BUG-91: Target also gives the quick-fix its tag directly, so the action no
                    # longer regex-parses the Message -- a coupling that silently breaks the
                    # buttons the moment anyone rewords the message.
                    $subj = ''
                    foreach ($idCol in @('Username', 'SourceGroupTag', 'GroupTag', 'AdminUnitTag')) {
                        $sv = Get-PimRowValue -Row $r -Column $idCol
                        if ($sv -and $sv -ne $val) { $subj = $sv; break }
                    }
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-001' -Csv $ref.Csv -Row $i -Column $col `
                        -Subject $subj -Target $val `
                        -Message "$col '$val' is referenced here but is not defined in any Definitions entity" -Suggestion $suggestion))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-FK-005 (2.4.378): a group defined ONLY by a PIM-Definitions-Resources row. PIM-FK-001 accepts it (the tag IS
    # defined), but the engine never CREATES a group from that entity -- it is discovery's (Get-PimGroupDefinitionRows) --
    # so an Azure binding on such a tag resolves to nothing and the delegation silently never lands. A WARNING, not an
    # error: an existing environment may hold such rows, and blocking every commit over them would be worse than saying so.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Definitions-Resources') -and $loaded.ContainsKey('PIM-Assignments-Azure-Resources')) {
        $creatable = New-Object System.Collections.Generic.HashSet[string]
        foreach ($db in @($defGroupBases | Where-Object { $_ -ne 'PIM-Definitions-Resources' })) {
            if (-not $loaded.ContainsKey($db)) { continue }
            foreach ($r in $loaded[$db].rows) { $t = Get-PimRowValue -Row $r -Column 'GroupTag'; if ($t) { [void]$creatable.Add($t.ToLowerInvariant()) } }
        }
        $resOnly = New-Object System.Collections.Generic.HashSet[string]
        foreach ($r in $loaded['PIM-Definitions-Resources'].rows) { $t = Get-PimRowValue -Row $r -Column 'GroupTag'; if ($t -and -not $creatable.Contains($t.ToLowerInvariant())) { [void]$resOnly.Add($t.ToLowerInvariant()) } }
        $azRows = $loaded['PIM-Assignments-Azure-Resources'].rows
        $warnedFk5 = New-Object System.Collections.Generic.HashSet[string]
        for ($i = 0; $i -lt $azRows.Count; $i++) {
            $r = $azRows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'Action') -ieq 'Remove') { continue }
            $t = Get-PimRowValue -Row $r -Column 'GroupTag'
            if (-not $t -or -not $resOnly.Contains($t.ToLowerInvariant()) -or -not $warnedFk5.Add($t.ToLowerInvariant())) { continue }
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-FK-005' -Csv 'PIM-Assignments-Azure-Resources' -Row $i -Column 'GroupTag' `
                -Subject $t -Target $t `
                -Message "Group '$t' is defined only in PIM-Definitions-Resources (the discovery entity). The engine never creates a group from it, so this Azure delegation cannot land." `
                -Suggestion "Define '$t' in PIM-Definitions-Services (as the Azure wizards now do), or remove this binding."))
        }
    }

    # ------------------------------------------------------------------
    # PIM-FK-002: every Username in PIM-Assignments-Admins exists as a UPN
    # in Account-Definitions-Admins (auto-deriving UPN where needed).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('PIM-Assignments-Admins')) {
        $rows = $loaded['PIM-Assignments-Admins'].rows
        $knownUpns = @(@($adminIndex.Values | ForEach-Object { $_.Upn }) + @($centralAdminList)) | Where-Object { $_ }
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $u = Get-PimRowValue -Row $r -Column 'Username'
            if (-not $u) { continue }
            $key = $u.ToLowerInvariant()
            if ($adminIndex.ContainsKey($key)) { continue }
            # A membership naming the admin by UserName, or by a full UPN whose local part is an admin's UserName, is a
            # reference to that admin: the UPN is composed from the UserName at create (UserName vs UPN, 2.4.377).
            if ($adminUserNames.Contains($key) -or ($key.Contains('@') -and $adminUserNames.Contains($key.Substring(0, $key.IndexOf('@'))))) { continue }
            # ...and an admin REPLICATED from the master is defined, just not here (see $centralAdminNames above).
            if (& $isKnownAdminName $u) { continue }
            # Try UPN-derivation match too (raw UserName -> UserName@defaultDomain).
            $derivedHit = $false
            if ($defaultDomain) {
                $derived = "$u@$defaultDomain"
                if ($adminIndex.ContainsKey($derived.ToLowerInvariant())) { $derivedHit = $true }
            }
            if ($derivedHit) { continue }
            $suggestion = $null
            $matches = Get-PimClosestMatches -Needle $u -Haystack $knownUpns -MaxDistance 5 -Top 3
            # 🪤 `@($matches).Count`, not `$matches.Count` -- and it is not cosmetic. On WINDOWS
            # POWERSHELL 5.1 a ONE-element result unwraps to a bare PSCustomObject, which has no
            # .Count there (pwsh 7 gives it one), so `$matches.Count -gt 0` was FALSE and the
            # did-you-mean list was dropped for exactly the case it is most useful in: a single
            # near-miss, e.g. one character wrong in an admin's UserName. Four rules had it.
            if (@($matches).Count -gt 0) {
                $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                $suggestion = "Add '$u' to Account-Definitions-Admins, or change this row to one of: $list."
            } else {
                $suggestion = "Add '$u' to Account-Definitions-Admins, or delete this row."
            }
            # 🔴 §58 -- WITHOUT -Target THIS FINDING HAS NO FIX BUTTONS AT ALL.
            # The GUI's quick-fix registry is keyed on the code and reads v.Target; FK-001 passed
            # Subject/Target and got "Remove this assignment" + "Define ...", while FK-002 passed
            # neither and got prose telling the operator to go and do it by hand. Worse, "Fix all
            # auto-fixable errors" filtered on FK-001 alone, so clicking it left every FK-002
            # untouched -- reported as "i have chosen autofix to remove these assignment ... but
            # they dont dissapear". The finding was right; there was simply nothing behind it.
            # Target = the principal that is missing a definition, which is what both remedies act
            # on: remove THIS assignment row, or define THAT principal.
            $subj = "$(Get-PimRowValue -Row $r -Column 'GroupTag')"
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-002' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'Username' `
                -Subject $subj -Target $u `
                -Message "Username '$u' is not defined in Account-Definitions-Admins (no admin has this UserName or UserPrincipalName)." -Suggestion $suggestion))
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
            if (@($matches).Count -gt 0) {
                $list = ($matches | ForEach-Object { "$($_.Value) (distance $($_.Distance))" }) -join ', '
                $suggestion = "Add '$t' to PIM-Definitions-AU, or change this row to one of: $list."
            } else {
                $suggestion = "Add '$t' to PIM-Definitions-AU, or delete this row."
            }
            # 🔴 §58.2 -- THE THIRD MEMBER OF THE SAME FAMILY, AND IT SHIPPED WITHOUT REMEDIES.
            # FK-001 and FK-002 are "an assignment names something no definition declares", and
            # both offer the two deterministic fixes: remove THIS row, or define THAT thing.
            # FK-003 is the identical shape for AU tags and passed NEITHER -Subject NOR -Target,
            # so the GUI's quick-fix registry (keyed on the code, reading v.Target) had nothing to
            # render -- exactly the state FK-002 was in when the operator reported that autofix
            # "left them". Found by the audit's GUI-FINDING-NO-FIX rule.
            $subj = "$(Get-PimRowValue -Row $r -Column 'GroupTag')"
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-FK-003' -Csv 'PIM-Assignments-Roles-AUs' -Row $i -Column 'AdministrativeUnitTag' `
                -Subject $subj -Target $t `
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
                # 🔴 B7 -- this finding used to offer NO remedy at all: no Subject/Target for the
                # GUI to key on, and the field to change lives on the DEFINITION row, not this one.
                # Stamping both makes the quick-fix registry able to stage the real edit.
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-RA-001' -Csv $csv -Row $i -Column 'GroupTag' `
                    -Subject $tag -Target $(if ("$($g.GroupName)".Trim()) { "$($g.GroupName)" } else { $tag }) `
                    -FixCsv "$($g.Csv)" -FixRow $g.Row -FixColumn 'IsRoleAssignable' -FixValue 'TRUE' `
                    -Message "The group '$(if ("$($g.GroupName)".Trim()) { "$($g.GroupName)" } else { $tag })' is bound to an Entra ID role but is not role-assignable. Entra refuses role assignment to non-role-assignable groups." `
                    -Suggestion "Set IsRoleAssignable=TRUE in $($g.Csv) row $($g.Row + 1). Entra CANNOT add this flag to an existing group: delete the group '$($g.GroupName)' in Entra ID and the engine recreates it correctly on the next run (group creation is existence-based)."))
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
                # BUG-90: the admin and the group ARE the identity of this finding -- "row 5"
                # is not. BUG-91: Subject/Target also feed the per-finding quick-fix.
                $ra2Admin = Get-PimRowValue -Row $r -Column 'Username'
                # R14 (operator, 2026-09-10): *"no refs to grouptags. use reel groups."* Where a
                # definition exists, name the REAL group -- the thing the operator can actually find
                # in Entra ID -- and fall back to the tag only when no GroupName is authored.
                # 🪤 An FK finding is the OPPOSITE case: nothing defines the tag, so there the tag is
                # the only identifier that exists and naming it is correct, not a violation of R14.
                $ra2Group = $(if ("$($g.GroupName)".Trim()) { "$($g.GroupName)" } else { $tag })
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-RA-002' -Csv 'PIM-Assignments-Admins' -Row $i -Column 'AssignmentType' `
                    -Subject $ra2Admin -Target $ra2Group `
                    -Message "AssignmentType=Active is not supported for direct admin assignment to the role-assignable group '$ra2Group'. Entra requires Eligible." `
                    -Suggestion "Change AssignmentType to 'Eligible' (admin activates JIT). Entra will not honour an Active assignment to a role-assignable group -- the admin must activate it just-in-time."))
            }
        }
    }
    # 🔴 §70.19 (2026-09-13) -- THE SAME RULE FOR A GROUP NESTED INTO A ROLE-ASSIGNABLE GROUP.
    # PIM-Assignments-Groups: TargetGroupTag becomes a MEMBER of SourceGroupTag (the container).
    # When the container is role-assignable, Entra refuses an Active membership ("Nesting is currently
    # not supported"); the engine skipped it silently, so the operator's delegation (made Eligible in
    # the wizard, written Active by the wizard) never deployed and nothing here said why. Reported as
    # PIM-RA-002 on this CSV so the existing "Set to Eligible" fix and the Fix-all bucket apply as-is:
    # both edit AssignmentType on the finding's own Csv/Row.
    if ($loaded.ContainsKey('PIM-Assignments-Groups')) {
        $rows = $loaded['PIM-Assignments-Groups'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $src = Get-PimRowValue -Row $r -Column 'SourceGroupTag'
            $tgt = Get-PimRowValue -Row $r -Column 'TargetGroupTag'
            $at  = Get-PimRowValue -Row $r -Column 'AssignmentType'
            if (-not $src -or -not $at) { continue }
            $k = $src.ToLowerInvariant()
            if (-not $groupTagIndex.ContainsKey($k)) { continue }  # FK rules own an undefined tag
            $g = $groupTagIndex[$k]
            if ($g.IsRoleAssignable -and $at -ieq 'Active') {
                $ra2Container = $(if ("$($g.GroupName)".Trim()) { "$($g.GroupName)" } else { $src })
                $tk = "$tgt".ToLowerInvariant()
                $ra2Member = $(if ($tgt -and $groupTagIndex.ContainsKey($tk) -and "$($groupTagIndex[$tk].GroupName)".Trim()) { "$($groupTagIndex[$tk].GroupName)" } elseif ($tgt) { $tgt } else { '(no target group)' })
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-RA-002' -Csv 'PIM-Assignments-Groups' -Row $i -Column 'AssignmentType' `
                    -Subject $ra2Member -Target $ra2Container `
                    -Message "AssignmentType=Active is not supported for nesting the group '$ra2Member' into the role-assignable group '$ra2Container'. Entra refuses it, so this delegation can never deploy; Entra requires Eligible." `
                    -Suggestion "Change AssignmentType to 'Eligible' (members of '$ra2Member' activate '$ra2Container' just-in-time). An Active nesting into a role-assignable group is rejected by Entra on every engine run."))
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
            # BUG-145: ask the ENGINE's predicate when it is loaded, so the validator cannot be
            # stricter than the thing that actually applies the convention.
            # 🔴 A TAG IS NOT A GROUP NAME (operator, 2026-09-12: "this is wrong" -- every ROLE-/ORG- tag
            # warned). The group NAME is '<prefix>-<tag>' (GroupName 'PIM-ROLE-CloudEngineer' carries tag
            # 'ROLE-CloudEngineer'), and the name predicate requires the prefix -- so testing the bare tag
            # flagged every correctly named direct group. Judge the tag as the name it produces; a tag
            # that already carries the prefix (tiered names) still passes as itself.
            $gnPrefix = if ($naming -and "$($naming.PimGroupNamePrefix)".Trim()) { "$($naming.PimGroupNamePrefix)".Trim().TrimEnd('-') } else { 'PIM' }
            $asName   = if ($tag -match "^(?i)$([regex]::Escape($gnPrefix))-") { $tag } else { "$gnPrefix-$tag" }
            $tagOk = if ($groupTagTest) { [bool](& $groupTagTest $tag) -or [bool](& $groupTagTest $asName) } else { $groupTagRegex.IsMatch($tag) -or $groupTagRegex.IsMatch($asName) }
            if (-not $tagOk) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-NAME-001' -Csv $db -Row $i -Column 'GroupTag' `
                    -Message "GroupTag '$tag' doesn't match the naming convention." `
                    -Suggestion "Expected either the simple shape PIM-<Role>[-<Department>] (e.g. PIM-Helpdesk-IT) or the tiered shape <Name>-L<0-9>-T<0-2>-<CP|WDP|MP|APP|USER>-<ID|RES|DAT>[-S_AD] (override both via PIM_NAMING.PimGroupTagRegex)."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-NAME-002: admin UPN doesn't match the convention its Purpose selects.
    # Purpose=HighPriv -> AdminAccountPatternHighPriv; Purpose=Day2Day ->
    # AdminAccountPattern; blank/unknown Purpose -> either pattern passes.
    # ------------------------------------------------------------------
    if (($adminPatternRegex -or $adminPatternHighPrivRegex) -and $loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            if (-not $upn) { continue }
            $purpose = "$(Get-PimRowValue -Row $r -Column 'Purpose')".Trim()
            $applicable = if ($purpose -ieq 'HighPriv' -and $adminPatternHighPrivRegex) { @($adminPatternHighPrivRegex) }
                          elseif ($purpose -ieq 'Day2Day' -and $adminPatternRegex)      { @($adminPatternRegex) }
                          else { @($adminPatternRegex, $adminPatternHighPrivRegex | Where-Object { $_ }) }
            $matched = $false
            foreach ($rx in $applicable) { if ($rx.IsMatch($upn)) { $matched = $true; break } }
            if (-not $matched) {
                # Say what the name SHOULD look like for THIS row -- the pattern with its values filled in -- not only
                # the raw template, which the operator cannot check by eye ("i dont see the problem here").
                $fill = {
                    param([string]$tpl)
                    $prefixes = $naming.AdminTypePrefixes; $suffixes = $naming.EnvironmentSuffixes
                    $at = "$(Get-PimRowValue -Row $r -Column 'AdminType')".Trim(); if (-not $at) { $at = "$($naming.AdminTypeDefault)".Trim() }
                    $en = "$(Get-PimRowValue -Row $r -Column 'Environment')".Trim(); if (-not $en) { $en = "$($naming.EnvironmentDefault)".Trim() }
                    $pick = { param($map, $k) if ($null -eq $map -or -not $k) { return $null }; if ($map -is [System.Collections.IDictionary]) { if ($map.Contains($k)) { return "$($map[$k])" } } elseif ($map.PSObject.Properties[$k]) { return "$($map.$k)" }; $null }
                    $co = "$(Get-PimRowValue -Row $r -Column 'Company')".Trim(); if (-not $co) { $co = "$($naming.Company)".Trim() }
                    $ini = "$(Get-PimRowValue -Row $r -Column 'Initials')".Trim()
                    $vals = @{ AdminTypePrefix = (& $pick $prefixes $at); Platform = (& $pick $suffixes $en); Company = $co; Initial = $ini; Initials = $ini; AdminWord = "$($naming.AdminWord)".Trim() }
                    $out = "$tpl"
                    for ($pass = 0; $pass -lt 3; $pass++) {
                        $out = [regex]::Replace($out, '\{([A-Za-z][A-Za-z0-9]*)\}',{ param($m) $v = $vals[$m.Groups[1].Value]; if ("$v".Trim()) { "$v" } else { '<' + $m.Groups[1].Value.ToLowerInvariant() + '>' } })
                    }
                    $out
                }
                $patLabel = if ($purpose -ieq 'HighPriv') { "the high-privilege pattern, i.e. '$(& $fill $naming.AdminAccountPatternHighPriv)' ($($naming.AdminAccountPatternHighPriv))" }
                            elseif ($purpose -ieq 'Day2Day') { "the day-to-day pattern, i.e. '$(& $fill $naming.AdminAccountPattern)' ($($naming.AdminAccountPattern))" }
                            else { "either pattern: '$(& $fill $naming.AdminAccountPattern)' or '$(& $fill $naming.AdminAccountPatternHighPriv)'" }
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-NAME-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'UserPrincipalName' `
                    -Message "UPN '$upn' (Purpose='$purpose') doesn't match $patLabel -- upper and lower case are the same." `
                    -Suggestion "Either rename to fit the convention, fix the row's Purpose, or change the pattern in Settings > Naming (stored in SQL)."))
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
            if ("$($adminIndex[$key].TargetPlatform)".Trim() -ieq 'AD') { continue }   # AD-only admins get no PIM (Entra) reach by design
            # REQ-G (2.4.376): a v1 assignment names the admin by bare UserName (PIM-FK-002 accepts that), so the UPN alone
            # reported every imported admin as orphaned. Either spelling is a reference.
            $un = "$($adminIndex[$key].UserName)".Trim().ToLowerInvariant()
            if (-not $usedAdmins.ContainsKey($key) -and -not ($un -and $usedAdmins.ContainsKey($un))) {
                $a = $adminIndex[$key]
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-ORPHAN-001' -Csv 'Account-Definitions-Admins' -Row $a.Row -Column 'UserPrincipalName' `
                    -Subject $a.Upn `
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
    # REQ-U (2026-09-19): the WORKLOAD binding entities. PIM-Assignments-Intune / -Defender are engine entities the
    # Manager grid does not list (Get-PimCsvBases), so they are read here on their own; an entity that cannot be read
    # is remembered, and every rule that needs it says "not checked" instead of guessing.
    $wlBindUnread = @{}
    foreach ($wb in @('PIM-Assignments-Intune', 'PIM-Assignments-Defender')) {
        if ($loaded.ContainsKey($wb)) { continue }
        if ($PendingRows -and $PendingRows.ContainsKey($wb)) {
            $loaded[$wb] = @{ header = @(); rows = @($PendingRows[$wb]); source = 'pending'; path = $null }
            continue
        }
        try { $loaded[$wb] = Read-PimRows -BaseName $wb }
        catch { $wlBindUnread[$wb] = "$($_.Exception.Message)"; $loaded[$wb] = @{ header = @(); rows = @(); source = 'none'; path = $null } }
    }
    # The Workload -> binding-kind map (ONE definition: ConvertTo-PimWorkloadBindingKind, PIM-WorkloadConnectors.ps1).
    # A host that has not loaded the engine runtime gets the same map inline.
    $wlKindOf = {
        param([string]$w)
        if (Get-Command ConvertTo-PimWorkloadBindingKind -ErrorAction SilentlyContinue) { return (ConvertTo-PimWorkloadBindingKind -Workload $w) }
        $n = ("$w".Trim().ToLowerInvariant()) -replace '[^a-z0-9]', ''
        if (-not $n) { return '' }
        if ($n -in @('intune', 'microsoftintune', 'endpointmanager', 'mem', 'intunerbac')) { return 'intune' }
        if ($n -in @('defender', 'defenderxdr', 'microsoftdefender', 'microsoftdefenderxdr', 'm365defender', 'microsoft365defender', 'mde', 'defenderforendpoint')) { return 'defender' }
        $gen = @{ powerbi = 'powerbi'; azuredevops = 'azure-devops'; azdevops = 'azure-devops'; dataverse = 'dataverse'; businesscentral = 'business-central'; powerplatform = 'power-platform'; entraapprole = 'entra-approle' }
        if ($gen.ContainsKey($n)) { return $gen[$n] }
        return ''
    }
    # kind -> { lower(GroupTag or group name) -> $true }, from every non-Remove binding row.
    $wlBound = @{}
    $wlAddBound = { param($kind, $val) if (-not $kind -or -not "$val".Trim()) { return }; if (-not $wlBound.ContainsKey($kind)) { $wlBound[$kind] = @{} }; $wlBound[$kind]["$val".Trim().ToLowerInvariant()] = $true }
    foreach ($pair in @(@('PIM-Assignments-Intune', 'intune'), @('PIM-Assignments-Defender', 'defender'))) {
        foreach ($r in @($loaded[$pair[0]].rows)) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'Action').Trim() -ieq 'Remove') { continue }
            & $wlAddBound $pair[1] (Get-PimRowValue -Row $r -Column 'GroupTag')
        }
    }
    if ($loaded.ContainsKey('PIM-Assignments-Workloads')) {
        foreach ($r in @($loaded['PIM-Assignments-Workloads'].rows)) {
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'Action').Trim() -ieq 'Remove') { continue }
            & $wlAddBound (& $wlKindOf (Get-PimRowValue -Row $r -Column 'Workload')) (Get-PimRowValue -Row $r -Column 'GroupTag')
        }
    }
    # A binding row may name the group by its tag OR by its full name (the shipped Workloads sample does the latter).
    $defNameToTag = @{}
    foreach ($k in $groupTagIndex.Keys) { $gnm = "$($groupTagIndex[$k].GroupName)".Trim(); if ($gnm) { $defNameToTag[$gnm.ToLowerInvariant()] = $k } }

    $outboundTags = @{}
    # REQ-U: a group bound by a WORKLOAD binding row (Intune / Defender / generic connector) has an outbound
    # assignment -- PIM-ORPHAN-002 used to call every such workload group orphaned.
    foreach ($kb in @($wlBound.Keys)) {
        foreach ($v in @($wlBound[$kb].Keys)) {
            $outboundTags[$v] = $true
            if ($defNameToTag.ContainsKey($v)) { $outboundTags[$defNameToTag[$v]] = $true }
        }
    }
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
                -Message "Permission group '$($g.Tag)' has no outbound assignments (nothing targets it via PIM-Assignments-Groups SourceGroupTag, and it isn't bound to an Entra/Azure target or a workload role)." `
                -Suggestion "Either bind it to a target (PIM-Assignments-Roles-*/Azure-Resources, or a workload binding: PIM-Assignments-Intune/-Defender/-Workloads) and/or nest it under a role group, or remove the definition."))
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
                    [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-DUP-001' -Csv 'PIM-Assignments-Admins' -Row $rowsHit[$t] -Column 'GroupTag' `
                        -Subject $upn -Target $t `
                        -Message "Admin '$upn' reaches target '$t' via $($paths.Count) role-group paths: $($paths -join ', ')." `
                        -Suggestion "Pick the canonical role group and drop the others; duplicate paths cause audit confusion and complicate offboarding."))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-STALE-001/002: cache-relative stale checks.
    # ------------------------------------------------------------------
    # 🔑 A cache that cannot PROVE the answer produces ONE info finding, never per-row claims.
    $refreshHint = "The scheduler's tenant-cache job refreshes it automatically; to refresh now click the cache badge in the UI, or run Open-PimManager.ps1 -RefreshTenantLists."
    $ciRoles = $cacheInfo['entraRoles']
    if (-not $ciRoles.fresh) {
        $why = if (-not $cacheRolesPresent) { 'is missing or empty' } else { "is $($ciRoles.ageText)" }
        [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-STALE-001' -Csv '<global>' `
            -Message "Entra role names were NOT checked: the 'entra-roles' tenant cache $why, so it cannot prove whether a role exists. No role row has been judged either way." `
            -Suggestion $refreshHint))
    } else {
        $rolesAt = & $cacheReadAt $ciRoles
        foreach ($csv in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs')) {
            if (-not $loaded.ContainsKey($csv)) { continue }
            $rows = $loaded[$csv].rows
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                $rn = Get-PimRowValue -Row $r -Column 'RoleDefinitionName'
                if (-not $rn) { continue }
                if (-not $cachedEntraRoleNames.ContainsKey($rn.ToLowerInvariant())) {
                    # @() -- on Windows PowerShell 5.1 a SINGLE match unwraps to a bare object with no
                    # .Count, so the did-you-mean (which the Fix-all uses) silently disappeared there.
                    $matches = @(Get-PimClosestMatches -Needle $rn -Haystack @($cachedEntraRoleNames.Values) -MaxDistance 6 -Top 3)
                    $suggestion = if (@($matches).Count -gt 0) {
                        "Did you mean: $((($matches | ForEach-Object { $_.Value }) -join ', '))?"
                    } else {
                        "Correct the role name to an existing Entra role, or delete this row."
                    }
                    # ERROR: the engine resolves the role BY NAME; a name the tenant does not have can
                    # never be applied as written.
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-STALE-001' -Csv $csv -Row $i -Column 'RoleDefinitionName' `
                        -Message "Entra role '$rn' does not exist in the tenant -- checked against the $($ciRoles.count) role definitions read at $rolesAt. This row can never be applied as written." `
                        -Suggestion $suggestion))
                }
            }
        }
    }

    # PIM-STALE-002 -- ADMINISTRATIVE UNITS.
    # 🔴 THE OLD RULE COMPARED THE WRONG THING. It looked the raw AdministrativeUnitTag up among the
    # cached AU DISPLAY NAMES -- but a tag is not a display name. The engine resolves
    # tag -> PIM-Definitions-AU.AUDisplayName -> live AU (Get-PimTagToAuName, PIM-EngineProviders.ps1),
    # so every AU whose display name differs from its tag drew a false warning: 178 on the operator's
    # internal environment, 2026-09-12. Now the validator walks the SAME chain the engine walks:
    #   * assignment row, tag with no PIM-Definitions-AU row -> PIM-FK-003 (error) already says so;
    #   * definition row with no AUDisplayName               -> ERROR: the engine can neither create nor
    #                                                          resolve an AU without a name;
    #   * definition row whose AU is absent (fresh cache)    -> INFO: the AdministrativeUnits scope
    #                                                          creates it on the next engine run;
    #   * stale / absent cache                               -> ONE info, no per-row claim.
    # An assignment row whose tag IS defined never needs its own finding: its AU either exists or is
    # about to be created, and the definition row carries that finding once, not once per assignment.
    if ($loaded.ContainsKey('PIM-Definitions-AU')) {
        $ciAus = $cacheInfo['aus']
        $defAuRows = $loaded['PIM-Definitions-AU'].rows
        $ausAt = & $cacheReadAt $ciAus
        $auNotChecked = $false
        for ($i = 0; $i -lt $defAuRows.Count; $i++) {
            $r = $defAuRows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $tag  = (Get-PimRowValue -Row $r -Column 'AdministrativeUnitTag').Trim()
            $name = (Get-PimRowValue -Row $r -Column 'AUDisplayName').Trim()
            if (-not $tag -and -not $name) { continue }
            if (-not $name) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-STALE-002' -Csv 'PIM-Definitions-AU' -Row $i -Column 'AUDisplayName' `
                    -Subject $tag `
                    -Message "AU definition '$tag' has no AUDisplayName. The engine creates and finds an AU by its display name, so this AU -- and every role assignment scoped to tag '$tag' -- can never be applied as written." `
                    -Suggestion "Set AUDisplayName to the AU's name in Entra ID (or the name it should be created with)."))
                continue
            }
            if (-not $ciAus.fresh) { $auNotChecked = $true; continue }
            if ($cachedAuNames.ContainsKey($name.ToLowerInvariant())) { continue }
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-STALE-002' -Csv 'PIM-Definitions-AU' -Row $i -Column 'AUDisplayName' `
                -Subject $tag `
                -Message "AU '$name' (tag '$tag') does not exist in the tenant yet -- checked against the $($ciAus.count) AUs read at $ausAt. The engine creates it on the next engine run." `
                -Suggestion "Nothing to do if this AU is new. If it should already exist, check the spelling of AUDisplayName against Entra ID."))
        }
        if ($auNotChecked) {
            $why = if (-not $ciAus.present -or $ciAus.count -eq 0) { 'is missing or empty' } else { "is $($ciAus.ageText)" }
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-STALE-002' -Csv '<global>' `
                -Message "Administrative units were NOT checked: the 'aus' tenant cache $why, so it cannot prove whether an AU exists. No AU row has been judged either way." `
                -Suggestion $refreshHint))
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
    # PIM-DOMAIN-001: the office-user mail pair is HALF configured.
    # ------------------------------------------------------------------
    # UN-RETIRED 2026-09-12 (operator, "Both"). ForwardMailsToContact + MailForwardAddress
    # name the admin owner's OFFICE USER: PIM mail about the admin goes there
    # (Get-PimAdminMailRecipient, ManagerEmail fallback) and, where the account has a
    # mailbox, Exchange forwarding is set to it (gated). The engine USES the pair again, so
    # the 2026-08-12 wording ("the engine ignores it") is gone.
    # What is still misleading is a pair that is half set:
    #   * a real address with the flag not TRUE -> the address is stored and never used
    #   * the flag TRUE with no real address    -> mail silently falls back to ManagerEmail
    # Both-set and both-off are consistent and stay silent. A sentinel ('FALSE'/'no'/'0'/
    # blank, or a flag value like 'true') is not an address -- Test-PimMailForwardAddressIsReal.
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'TargetPlatform').Trim() -ieq 'AD') { continue }   # AD-only: no Entra mailbox forwarding
            $addr   = Get-PimRowValue -Row $r -Column 'MailForwardAddress'
            $flagOn = ("$(Get-PimRowValue -Row $r -Column 'ForwardMailsToContact')".Trim() -match '(?i)^(true|yes|1)$')
            $real   = (Test-PimMailForwardAddressIsReal -Value $addr) -and ("$addr".Trim() -notmatch '(?i)^(true|yes|1)$')
            if ($real -eq $flagOn) { continue }   # both set, or both off -- consistent
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            $mgr = Get-PimRowValue -Row $r -Column 'ManagerEmail'
            if ($real) {
                $msg = "MailForwardAddress='$addr' is set for '$upn' but ForwardMailsToContact is not TRUE -- the office-user address is stored and never used."
                $sug = "Set ForwardMailsToContact=TRUE to send this admin's mail to '$addr', or clear MailForwardAddress."
            } else {
                $msg = "ForwardMailsToContact=TRUE for '$upn' but MailForwardAddress='$addr' is not an email address -- the per-admin override does nothing, so mail falls back to the sponsor department's owners."
                $sug = "Enter the owner's office user email in MailForwardAddress, or set ForwardMailsToContact=FALSE and let the admin's sponsor department own the mail."
            }
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-DOMAIN-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'MailForwardAddress' `
                -Message $msg -Suggestion $sug))
        }
    }

    # ------------------------------------------------------------------
    # PIM-UPN-001 -- AN ADMIN ROW MUST CARRY ITS UserPrincipalName (operator 2026-09-21: "we can not have a admin
    # without a upn. that makes no sense, then it is not compatible"). Measured on EFIF: six rows imported with a
    # UserName only never showed on Admin accounts, and every UPN-keyed path (TAP, forwarding, sign-in) passed them
    # by. The UPN is this tenant's; a replicated admin gets its slave's UPN built at staging (UserName@slave domain).
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ("$(Get-PimRowValue -Row $r -Column 'UserPrincipalName')".Trim()) { continue }
            $un = "$(Get-PimRowValue -Row $r -Column 'UserName')".Trim()
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-UPN-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'UserPrincipalName' `
                -Message "admin '$un' has no UserPrincipalName -- an admin without a UPN is not a valid admin: it cannot sign in, get a TAP or be managed." `
                -Suggestion "Set UserPrincipalName to '$un@<the tenant's domain>'."))
        }
    }

    # ------------------------------------------------------------------
    # PIM-MAIL-001 (71.19) -- WHO RECEIVES AN ADMIN'S MAIL IS THE SPONSOR DEPARTMENT, NOT A PERSON.
    # Operator 2026-09-16: "the logic is that an admin is linked to a dept (sponsor) and the dept has owners";
    # REQUIREMENTS §62: "we dont add a manager on the person ... whoever is the actual manager of the dept gets the
    # emails ... otherwise you are vulnerable for org changes". The engine resolves an admin's recipient as
    # per-admin override -> sponsor department owners -> ManagerEmail (legacy), and REFUSES to issue a TAP it cannot
    # deliver. Everything this rule reports is therefore an admin who will end up without a credential, or one whose
    # mail rides on a person's address that no org change will update.
    #   no recipient at all                        -> WARNING (the TAP is refused; the account cannot be used)
    #   only ManagerEmail (legacy)                 -> WARNING (works today; move it to the department)
    # 🔑 SEVERITY IS WARNING, NOT ERROR, DELIBERATELY. An error blocks Commit in the Manager, and every environment that
    # has not yet moved to sponsor departments would be unable to save ANY change until it had -- a migration gate
    # disguised as a validation rule. The gap is already loud where it matters: the engine REFUSES the TAP and says why,
    # Test-PimTenantReady FAILS the environment, and the Accounts screen shows the admin's recipient as "none".
    # AD-only admins are skipped (they hold no TAP).
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins') -and (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) {
        $deptIdx = @{}
        if ($loaded.ContainsKey('PIM-Definitions-Departments')) {
            foreach ($dr in @($loaded['PIM-Definitions-Departments'].rows)) {
                $dn = ''; foreach ($k in @('Department', 'DepartmentName', 'Name')) { $v = (Get-PimRowValue -Row $dr -Column $k).Trim(); if ($v) { $dn = $v; break } }
                if (-not $dn) { continue }
                $dow = ''; foreach ($k in @('Owners', 'DeptOwner', 'DepartmentOwner', 'ManagerEmail')) { $v = (Get-PimRowValue -Row $dr -Column $k).Trim(); if ($v) { $dow = $v; break } }
                $deptIdx[$dn.ToLowerInvariant()] = $dow
            }
        }
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'TargetPlatform').Trim() -ieq 'AD') { continue }
            $who = (Get-PimRowValue -Row $r -Column 'UserPrincipalName').Trim(); if (-not $who) { $who = (Get-PimRowValue -Row $r -Column 'UserName').Trim() }
            $plan = Get-PimAdminMailRecipientPlan -Row $r -DepartmentOwners $deptIdx
            if ("$($plan.source)" -eq 'none') {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MAIL-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Department' `
                    -Message "'$who' has no mail recipient: $($plan.reason). A Temporary Access Pass is enforced for every Entra admin and the engine REFUSES to issue one it cannot deliver, so this admin would never be able to sign in." `
                    -Suggestion "Set the admin's Department to its sponsor department and give that department Owners (Definitions > Departments). A per-admin override is ForwardMailsToContact=TRUE + MailForwardAddress."))
            } elseif ("$($plan.source)" -eq 'manager-legacy') {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MAIL-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Department' `
                    -Message "'$who' still receives its mail through ManagerEmail. The rule is the SPONSOR DEPARTMENT's owners -- a person on the row is not updated when the organisation changes." `
                    -Suggestion "Set the admin's Department to its sponsor department and give that department Owners; ManagerEmail then stops being used."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-RING-001: Ring column (deployment-ring rollout staging) must be
    # blank, 0 (dev), 1 (test) or 2 (broad) -- §77.20 (operator 2026-09-21), the
    # same order as the update rings. DOC-16 a (§33.28): an invalid value
    # UNDER-grants, it does not over-grant: the admin reaches NO managed tenant.
    # Each slave's ring is set locally in the slave. Severity is WARNING by
    # design (never blocks Save); the Validate tab's Fix-all offers Ring=0
    # (dev tenants only, the narrowest) or blank.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'TargetPlatform').Trim() -ieq 'AD') { continue }   # AD-only: no Entra tenant rollout
            $ringVal = (Get-PimRowValue -Row $r -Column 'Ring').Trim()
            if (-not $ringVal) { continue }
            if ($ringVal -notmatch '^[0-2]$') {
                $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-RING-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Ring' `
                    -Message "Ring '$ringVal' for '$upn' is not a deployment ring (0 = dev, 1 = test, 2 = broad), so this admin reaches NO managed tenant -- it UNDER-grants: the admin is silently NOT deployed (it is never widened to all tenants)." `
                    -Suggestion "Set Ring to 0 (dev tenants only), 1 (dev + test) or 2 (every tenant) -- an admin on ring N reaches the managed tenants whose own ring is N or lower -- or use Fix-all (Ring=0 or blank)."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-MSP-001 / PIM-MSP-002 (REQUIREMENTS 68.6 row 35): the per-admin MSP downlink definition.
    #   001 = ManagementMode=msp but no valid Ring -> the admin reaches NO slave (the downlink
    #         treats a missing ring as not eligible), which is almost never the intent.
    #   002 = Target is malformed, or names a tag no managed tenant carries. The unknown-tag half is
    #         only raised when the MSP registry's tag list was actually READ -- never on a guess.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        $mspTags = @{ known = $false; tags = @() }
        if ($global:PIM_ValidatorKnownTenantTags -is [hashtable]) { $mspTags = $global:PIM_ValidatorKnownTenantTags }
        elseif (Get-Command Get-PimManagerKnownTenantTags -ErrorAction SilentlyContinue) { try { $mspTags = Get-PimManagerKnownTenantTags } catch { } }
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'
            $mode = (Get-PimRowValue -Row $r -Column 'ManagementMode').Trim()
            # 77.20 (2.4.388): the rings are 0 (dev), 1 (test), 2 (broad) only.
            if ($mode -ieq 'msp' -and (Get-PimRowValue -Row $r -Column 'Ring').Trim() -notmatch '^[0-2]$') {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Ring' `
                    -Message "'$upn' is ManagementMode=msp (synced to slaves) but has no valid Ring (blank, or not 0, 1 or 2) -- the downlink sends it to NO slave." `
                    -Suggestion "Set Ring to 0 (dev tenants), 1 (dev + test) or 2 (every tenant), or set ManagementMode=local if it should not be synced."))
            }
            $tgt = (Get-PimRowValue -Row $r -Column 'Target').Trim()
            if ($tgt -and (Get-Command Test-PimAdminTargetSelector -ErrorAction SilentlyContinue)) {
                $sel = Test-PimAdminTargetSelector -Target $tgt -KnownTags @($mspTags.tags) -TagsKnown:([bool]$mspTags.known)
                if (@($sel.malformed).Count -or @($sel.unknownTags).Count) {
                    $what = @()
                    if (@($sel.malformed).Count)   { $what += "malformed: $(@($sel.malformed) -join ', ')" }
                    if (@($sel.unknownTags).Count) { $what += "no managed tenant carries tag(s): $(@($sel.unknownTags) -join ', ')" }
                    [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'Target' `
                        -Message "Target '$tgt' for '$upn' -- $($what -join '; '). A tag nobody carries sends the admin to no slave." `
                        -Suggestion "Pick tags from the managed tenants' tags (use tag:<name>, tenant:<id>, all or none)."))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-MSP-003 / 004 / 005 + PIM-MSP-002 on every replicable entity (REQUIREMENTS §71, framework
    # MSP-4 SURFACE). One rule, shared with the wizard, the grid and the Manager's PUT gate
    # (Test-PimReplicationRowFields), so the three can never disagree about what is acceptable.
    #   003 ERROR   = Replicate is not No/Yes/Follow, is Follow on an admin, or DISAGREES with the admin's
    #                 ManagementMode (msp <-> Yes, local/blank <-> No). The bundle fails such a row closed,
    #                 so saving it would silently stop (or never start) replicating the admin.
    #   004 warning = replication fields on a tenant that is NOT the MSP master -- they mean nothing here
    #                 and the Manager refuses to change them. Only raised when the mode is KNOWN.
    #   005 warning = a group-model row's Ring is not 0/1/2 -- it reaches no tenant.
    #   002 warning = a group-model row's Target is malformed or names an unknown tag (admins: above).
    # ------------------------------------------------------------------
    if (Get-Command Test-PimReplicationRowFields -ErrorAction SilentlyContinue) {
        $repTags = @{ known = $false; tags = @() }
        if ($global:PIM_ValidatorKnownTenantTags -is [hashtable]) { $repTags = $global:PIM_ValidatorKnownTenantTags }
        elseif (Get-Command Get-PimManagerKnownTenantTags -ErrorAction SilentlyContinue) { try { $repTags = Get-PimManagerKnownTenantTags } catch { } }
        $repMaster = $null
        if ($null -ne $global:PIM_ValidatorIsMspMaster) { $repMaster = [bool]$global:PIM_ValidatorIsMspMaster }
        elseif (Get-Command Test-PimManagerIsMspMaster -ErrorAction SilentlyContinue) { try { $repMaster = [bool](Test-PimManagerIsMspMaster) } catch { $repMaster = $null } }
        foreach ($repEnt in @(Get-PimReplicationEntities)) {
            if (-not $loaded.ContainsKey($repEnt)) { continue }
            $rows = $loaded[$repEnt].rows
            $repKind = Get-PimReplicationKindForEntity -Entity $repEnt
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                $label = (Get-PimRowValue -Row $r -Column 'GroupTag')
                if (-not $label) { $label = (Get-PimRowValue -Row $r -Column 'UserPrincipalName') }
                if (-not $label) { $label = (Get-PimRowValue -Row $r -Column 'UserName') }
                if (-not $label) { $label = (Get-PimRowValue -Row $r -Column 'Username') }
                if (-not $label) { $label = "$((Get-PimRowValue -Row $r -Column 'TargetGroupTag')) <- $((Get-PimRowValue -Row $r -Column 'SourceGroupTag'))" }
                $repVal = (Get-PimRowValue -Row $r -Column 'Replicate').Trim()
                $ringVal = (Get-PimRowValue -Row $r -Column 'Ring').Trim()
                $tgtVal = (Get-PimRowValue -Row $r -Column 'Target').Trim()
                $hasFields = [bool]$repVal -or ($repKind -ne 'admin' -and ([bool]$ringVal -or [bool]$tgtVal))
                if (-not $hasFields) { continue }
                if ($repMaster -eq $false) {
                    [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-004' -Csv $repEnt -Row $i -Column 'Replicate' `
                        -Message "'$label' carries replication fields (Replicate/Ring/Target) but this tenant is not the MSP master -- they have no effect here." `
                        -Suggestion "Clear them. Replication is authored only on the MSP master and pulled by managed tenants."))
                    continue
                }
                $chk = Test-PimReplicationRowFields -Row $r -Entity $repEnt -KnownTags @($repTags.tags) -TagsKnown:([bool]$repTags.known)
                foreach ($err in @($chk.errors)) {
                    if ("$err" -match '^Target ') {
                        if ($repKind -ne 'admin') {
                            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-002' -Csv $repEnt -Row $i -Column 'Target' -Message "'$label' -- $err" `
                                -Suggestion "Use tag:<key:value>, tag:a+b (all of), tenant:<id>, or leave blank for every tenant the ring admits."))
                        }
                        continue
                    }
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-MSP-003' -Csv $repEnt -Row $i -Column 'Replicate' -Message "'$label' -- $err" `
                        -Suggestion "Pick the replication from the dropdown -- no replication (blank) or Replicate to managed tenants; an admin also offers 'only where a delegation needs this admin'. On an admin it must match Management mode: msp = replicate, local/blank = no replication."))
                }
                if ($repKind -ne 'admin') {
                    foreach ($w in @($chk.warnings)) {
                        if ("$w" -match '^Ring ') {
                            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-005' -Csv $repEnt -Row $i -Column 'Ring' -Message "'$label' -- $w" -Suggestion 'Use a whole-number Ring (0, 1, 2, ...), or leave it blank (not narrowed by ring).'))
                        } elseif ("$w" -match 'no managed tenant carries') {
                            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-MSP-002' -Csv $repEnt -Row $i -Column 'Target' -Message "'$label' -- $w" -Suggestion "Pick tags from the managed tenants' tags."))
                        }
                    }
                }
            }
        }
    }

    # PIM-TAP-001 (CreateTAP=TRUE on an AD-only admin) was RETIRED 2026-09-13: TAP is enforced for every
    # admin (operator "enforce tap to true"), CreateTAP is no longer read, and the engine simply issues no
    # TAP to an AD-only admin -- there is nothing left for the operator to fix.
    # PIM-TAP-003 (71.17, operator 2026-09-15 "tap is on for all"): CreateTAP=FALSE on an ENTRA admin is a value the
    # engine ignores -- every Entra admin gets a TAP. Accepting it silently lets the row claim a choice that does not
    # exist, so it is reported (warning) with a one-click fix to TRUE. Blank is fine (means the enforced default).
    if ($loaded.ContainsKey('Account-Definitions-Admins')) {
        $tapRows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $tapRows.Count; $i++) {
            $r = $tapRows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'TargetPlatform').Trim() -ieq 'AD') { continue }
            $ct = (Get-PimRowValue -Row $r -Column 'CreateTAP').Trim()
            if ($ct -and $ct -notmatch '(?i)^(true|1|yes)$') {
                $who = (Get-PimRowValue -Row $r -Column 'UserPrincipalName').Trim(); if (-not $who) { $who = (Get-PimRowValue -Row $r -Column 'UserName').Trim() }
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-TAP-003' -Csv 'Account-Definitions-Admins' -Row $i -Column 'CreateTAP' `
                    -Message "'$who' -- CreateTAP='$ct' has NO effect: a Temporary Access Pass is enforced for every Entra admin (single tenant, MSP master and managed tenants alike)." `
                    -Suggestion 'Set CreateTAP to TRUE (or leave it blank). To stop a TAP, the admin must not be an Entra admin (TargetPlatform=AD).'))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-SCHED-* + PIM-TAP-002: scheduling columns (LIFECYCLE-GOVERNANCE
    # phase 1). ProvisionDate must be a valid date expression (grammar only
    # -- the engine treats unparseable as Now, which would provision EARLY);
    # TAPStartDate failures are warnings (legacy natural-language values like
    # 'tomorrow 9am' resolve in the engine's extended parser, which is not
    # loaded here); TAPLifetimeHours must be numeric 1..720; TAPStartDate
    # before ProvisionDate means the TAP window predates the account.
    # ------------------------------------------------------------------
    if ($loaded.ContainsKey('Account-Definitions-Admins') -and (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
        $rows = $loaded['Account-Definitions-Admins'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $upn = Get-PimRowValue -Row $r -Column 'UserPrincipalName'

            $provRaw = (Get-PimRowValue -Row $r -Column 'ProvisionDate').Trim()
            $provUtc = $null
            if ($provRaw) {
                try { $provUtc = Resolve-PimDateExpression -Expression $provRaw } catch {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-SCHED-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'ProvisionDate' `
                        -Message "ProvisionDate '$provRaw' for '$upn' is not a valid date expression -- the engine would treat it as Now and provision immediately." `
                        -Suggestion "Use: Now | FirstDayNextMonth / FirstWorkdayNextMonth / FirstDayNextWeek / FirstWorkdayNextWeek with optional +Nd/-Nd and @HH:mm, or yyyy-MM-dd[@HH:mm] (e.g. 'FirstWorkdayNextMonth-3d')."))
                }
            }

            # AD-only admins hold no TAP (password only): no TAP-schedule findings for them.
            $adOnlyRow = ((Get-PimRowValue -Row $r -Column 'TargetPlatform').Trim() -ieq 'AD')
            $tapRaw = if ($adOnlyRow) { '' } else { (Get-PimRowValue -Row $r -Column 'TAPStartDate').Trim() }
            $tapUtc = $null
            if ($tapRaw) {
                try { $tapUtc = Resolve-PimDateExpression -Expression $tapRaw } catch {
                    [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-SCHED-001' -Csv 'Account-Definitions-Admins' -Row $i -Column 'TAPStartDate' `
                        -Message "TAPStartDate '$tapRaw' for '$upn' does not match the date-expression grammar. The engine's extended parser may still accept it (legacy natural-language values), but prefer the grammar so the GUI preview and validator can verify it." `
                        -Suggestion "Use e.g. 'FirstWorkdayNextMonth@08:00' or '2026-07-01@08:00'."))
                }
            }

            if ($provUtc -and $tapUtc -and $tapUtc -lt $provUtc) {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-SCHED-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'TAPStartDate' `
                    -Message "TAPStartDate ($($tapUtc.ToString('yyyy-MM-dd HH:mm')) UTC) for '$upn' is EARLIER than ProvisionDate ($($provUtc.ToString('yyyy-MM-dd HH:mm')) UTC) -- the TAP window would open before the account exists." `
                    -Suggestion "Move TAPStartDate to or after ProvisionDate (the operator pattern is: provision a few days early, TAP opens on the start day, e.g. ProvisionDate=FirstWorkdayNextMonth-3d, TAPStartDate=FirstWorkdayNextMonth@08:00)."))
            }

            $lifeRaw = if ($adOnlyRow) { '' } else { (Get-PimRowValue -Row $r -Column 'TAPLifetimeHours').Trim() }
            if ($lifeRaw) {
                $lifeNum = 0
                if (-not [double]::TryParse($lifeRaw, [ref]$lifeNum) -or $lifeNum -lt 1 -or $lifeNum -gt 720) {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-TAP-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'TAPLifetimeHours' `
                        -Message "TAPLifetimeHours '$lifeRaw' for '$upn' must be a number between 1 and 720 (Graph caps TAP lifetime at 30 days). The engine falls back to the tenant default lifetime for invalid values." `
                        -Suggestion "Set the intended validity window in hours, e.g. 8."))
                }
            }

            # Phase 5: offboarding columns
            # 🔴 71.23 -- AutoDisableDate (legacy name: OffboardDate). Three cases, in order:
            #   BOTH names set and different -> ERROR. The engine refuses the row rather than
            #     guessing which date disables the account, so the Manager must say so too.
            #   only the legacy name         -> WARNING to rename (the row still works).
            #   unreadable date expression   -> ERROR (the sweep skips it: the account is NOT disabled).
            $offPlan = Get-PimAdminAutoDisableDate -Row $r
            if ($offPlan.conflict) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-OFF-002' -Csv 'Account-Definitions-Admins' -Row $i -Column 'AutoDisableDate' `
                    -Message "'$upn' carries BOTH AutoDisableDate and the legacy OffboardDate, with different dates. PIM will NOT guess which one disables the account, so this admin is skipped entirely by the auto-disable sweep." `
                    -Suggestion "Keep the date you mean in AutoDisableDate and clear OffboardDate."))
            } elseif ($offPlan.source -eq 'legacy') {
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-OFF-003' -Csv 'Account-Definitions-Admins' -Row $i -Column 'OffboardDate' `
                    -Message "'$upn' still uses the old column name OffboardDate. It is read, so nothing is broken -- but the column is now AutoDisableDate, because the sweep only DISABLES the account (PIM never deletes an account)." `
                    -Suggestion "Move the date to AutoDisableDate and clear OffboardDate."))
            }
            $offRaw = "$($offPlan.value)".Trim()
            if ($offRaw) {
                $offCol = if ($offPlan.source -eq 'legacy') { 'OffboardDate' } else { 'AutoDisableDate' }
                try { $null = Resolve-PimDateExpression -Expression $offRaw } catch {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-SCHED-001' -Csv 'Account-Definitions-Admins' -Row $i -Column $offCol `
                        -Message "$offCol '$offRaw' for '$upn' is not a valid date expression -- the auto-disable sweep skips the row, so this admin's account will NOT be disabled." `
                        -Suggestion "Use the date-expression grammar, e.g. '2026-09-30' or 'FirstDayNextMonth'."))
                }
            }
            # 🔴 71.21 -- THERE IS NO PIM-OFF-001 ANY MORE. It warned that DeleteAfterDays was inert.
            # The field is no longer supported at all (operator, 2026-09-16: "nobody uses it yet, so
            # dont worry about deleteafterdays, as i dont want it to be shown as it confuses"), so
            # there is nothing left to warn about: a row that still carries the value is accepted in
            # SILENCE and the schema preflight drops the column. Warning about a field the product
            # does not have would be noise the operator cannot act on.
        }
    }

    # ------------------------------------------------------------------
    # PIM-LC-001: Lifecycle column on definition rows (phase 5) -- only
    # blank or 'Retire' are meaningful; anything else is a typo that
    # silently does nothing.
    # ------------------------------------------------------------------
    foreach ($defBase in @('PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-Projects','PIM-Definitions-CrossOrg')) {
        if (-not $loaded.ContainsKey($defBase)) { continue }
        $rows = $loaded[$defBase].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $lc = (Get-PimRowValue -Row $r -Column 'Lifecycle').Trim()
            if ($lc -and $lc -ne 'Retire') {
                $gn = (Get-PimRowValue -Row $r -Column 'GroupName').Trim()
                [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-LC-001' -Csv $defBase -Row $i -Column 'Lifecycle' `
                    -Message "Lifecycle '$lc' for '$gn' is not a recognized value -- the engine only acts on 'Retire' (case-sensitive); this row's value does nothing." `
                    -Suggestion "Use 'Retire' to retire the group (role assignments + members removed, group deleted), or leave blank."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-POL-001 + PIM-APR-001: policy templates + approvals (LIFECYCLE-
    # GOVERNANCE phases 3+4). A PolicyTemplate value must reference a policy
    # template in the SQL store (pim.Settings 'PolicyTemplates' -- seeded once from the shipped
    # templates, no file overrides; operator decisions 2026-09-12); rows whose
    # effective template requires approval need owners (>=2 for Serial, or
    # the escalation has nowhere to go).
    # ------------------------------------------------------------------
    $policyTpls = @{}
    $rawTpls = @{}
    try {
        # SQL ONLY: the same store the engine reads (Get-PimEnginePolicyTemplates). The hydrated
        # setting is used when present; otherwise it is read from the store.
        $polRaw = $null
        if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PolicyTemplates')) { $polRaw = $global:PIM_NamingConventions['PolicyTemplates'] }
        elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { try { $polRaw = Get-PimManagerSetting -Name 'PolicyTemplates' } catch { $polRaw = $null } }
        if ((Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue) -and $null -ne $polRaw) {
            $rawTpls = ConvertTo-PimPolicyTemplateMap -Value $polRaw
            foreach ($tid in @($rawTpls.Keys)) {
                $pj = $rawTpls[$tid]
                $apr = $null
                # 'extends' resolves like the engine: id, current name, former id ('default' -> Groups_Standard).
                $ext = if (-not $pj.extends) { '' } elseif (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) { Resolve-PimPolicyTemplateKey -Map $rawTpls -Id ([string]$pj.extends) } elseif ($rawTpls.ContainsKey([string]$pj.extends)) { [string]$pj.extends } else { '' }
                if ($ext -and $rawTpls[$ext].rules -and $rawTpls[$ext].rules.Approval) {
                    $apr = $rawTpls[$ext].rules.Approval
                }
                if ($pj.rules -and $pj.rules.Approval) { $apr = $pj.rules.Approval }
                $policyTpls[$tid] = @{ ApprovalMode = $(if ($apr -and $apr.mode) { [string]$apr.mode } else { 'None' }) }
            }
        }
    } catch { $policyTpls = @{} }
    # 2026-09-19: a PolicyTemplate value resolves exactly as the engine resolves it -- the id, then the current name, then
    # a former id ('default' -> Groups_Standard, 'approval-required' -> Groups_RequireApproval) -- so a row naming a former
    # id is NOT PIM-POL-001. A BLANK value means the per-kind default (pim.Settings['PolicyTemplateDefaults'], else built-in).
    $resolveTpl = {
        param([string]$v)
        if (-not "$v".Trim()) { return '' }
        if (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) { return (Resolve-PimPolicyTemplateKey -Map $rawTpls -Id $v) }
        if ($policyTpls.ContainsKey("$v".Trim())) { return "$v".Trim() }
        return ''
    }
    $tplDefaults = [ordered]@{ group = 'Groups_Standard'; directoryRole = 'EntraIDRoles_Standard'; azureRole = 'AzureRoles_Standard' }
    if ($policyTpls.Count -gt 0 -and (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue)) {
        $defSet = $null
        if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PolicyTemplateDefaults')) { $defSet = $global:PIM_NamingConventions['PolicyTemplateDefaults'] }
        elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { try { $defSet = Get-PimManagerSetting -Name 'PolicyTemplateDefaults' } catch { $defSet = $null } }
        try { $tplDefaults = (Resolve-PimPolicyTemplateTypeDefaults -Setting $defSet -Map $rawTpls).defaults } catch { }
    }

    # TEMPLATE-UPGRADE-AVAILABLE (info): a stored template that was CUSTOMISED is never overwritten by a
    # newer shipped version (Update-PimPolicyTemplateStore records it in upgradeAvailable). Say so, and
    # name what the shipped version would change, so the operator can take it deliberately.
    try {
        $upg = $null
        if ($null -ne $polRaw) {
            $pv = $polRaw; if ($pv -is [string]) { try { $pv = $pv | ConvertFrom-Json } catch { $pv = $null } }
            if ($pv -is [System.Collections.IDictionary]) { if ($pv.Contains('upgradeAvailable')) { $upg = $pv['upgradeAvailable'] } }
            elseif ($pv -and $pv.PSObject.Properties['upgradeAvailable']) { $upg = $pv.upgradeAvailable }
        }
        foreach ($u in @($upg | Where-Object { $_ })) {
            $uid = "$($u.id)"; if (-not $uid) { continue }
            $chg = @(@($u.changes) | Where-Object { "$_".Trim() })
            $chgText = if ($chg.Count) { ((@($chg | Select-Object -First 10)) -join ', ') + $(if ($chg.Count -gt 10) { " (+$($chg.Count - 10) more)" } else { '' }) } else { 'annotations only' }
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'TEMPLATE-UPGRADE-AVAILABLE' -Csv 'PolicyTemplates' -Row $null -Column 'PolicyTemplate' -Subject $uid -Target "$($u.shippedFingerprint)" `
                -Message "Policy template '$uid' was customised in the store, so the newer shipped version was NOT applied. The shipped version changes: $chgText." `
                -Suggestion "Review the difference. To take the shipped version, replace the stored template with it (the next db-init or Manager start keeps it current from then on); to keep yours, no action is needed -- this notice stays until the two match."))
        }
    } catch { }

    if ($policyTpls.Count -gt 0) {
        foreach ($defBase in @('PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-Projects','PIM-Definitions-CrossOrg')) {
            if (-not $loaded.ContainsKey($defBase)) { continue }
            $rows = $loaded[$defBase].rows
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                $tplVal = (Get-PimRowValue -Row $r -Column 'PolicyTemplate').Trim()
                $gName  = (Get-PimRowValue -Row $r -Column 'GroupName').Trim()

                $tplKey = & $resolveTpl $tplVal
                if ($tplVal -and -not $tplKey) {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-POL-001' -Csv $defBase -Row $i -Column 'PolicyTemplate' `
                        -Message "PolicyTemplate '$tplVal' for '$gName' is not a policy template in the store -- the engine skips the row's policy apply." `
                        -Suggestion ("Available templates: " + (@($policyTpls.Keys | Sort-Object) -join ', ') + ".")))
                    continue
                }
                $effTpl = if ($tplKey) { $tplKey } else { "$($tplDefaults['group'])" }
                if (-not $policyTpls.ContainsKey($effTpl)) { continue }
                $mode = $policyTpls[$effTpl].ApprovalMode
                if ($mode -eq 'None') { continue }

                $ownersRaw = (Get-PimRowValue -Row $r -Column 'Owners').Trim()
                if (-not $ownersRaw) { $ownersRaw = (Get-PimRowValue -Row $r -Column 'SponsorUpn').Trim() }
                # BUG-192 (§33.28): the Manager stores Owners PIPE-joined ('a|b'); the engine splits on [|,;]
                # (Invoke-PimGroupsPolicyApply). Splitting on [;,] only read 'a|b' as ONE owner, so a Serial
                # approval with two owners was flagged as having one.
                $owners = @($ownersRaw -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($owners.Count -eq 0) {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-APR-001' -Csv $defBase -Row $i -Column 'Owners' `
                        -Message "'$gName' links policy template '$effTpl' ($mode approval) but the row has NO owners -- there is nobody to approve, so the engine will not apply the approval rule." `
                        -Suggestion "Add approver UPNs to the Owners column (semicolon-separated). Serial approval escalates down the list in order."))
                } elseif ($mode -eq 'Serial' -and $owners.Count -lt 2) {
                    [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-APR-001' -Csv $defBase -Row $i -Column 'Owners' `
                        -Message "'$gName' uses SERIAL approval with only one owner -- an unanswered request has nowhere to escalate." `
                        -Suggestion "Add a second owner, or switch the template's approval mode to Parallel."))
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # REQ-L / §68.6 #37(c): the PolicyTemplate column on the ROLE-ASSIGNMENT entities (Roles-Groups, Roles-AUs,
    # Azure-Resources). The engine reads it per role (Get-PimManagedRolePolicyTargets) and per Azure (scope, role)
    # (Get-PimAzResPolicyTargets), blank = the per-kind default (EntraIDRoles_Standard for an Entra role, AzureRoles_Standard
    # for an Azure role, unless pim.Settings['PolicyTemplateDefaults'] sets another), and SKIPS the policy of a row naming a
    # template the store does not have (id, name or former id) -- PIM-POL-001, as for the definition rows above. A row
    # naming a template written for ANOTHER kind (an Azure row still on EntraIDRoles_Standard) is NOT flagged: the engine
    # applies it (same rules); the Manager marks it in the grid. An Entra role whose template needs
    # approval takes its approvers from ApproverUpns ONLY, and the engine refuses to write an approval with none
    # (EntraRolePolicies: "NO approver resolved") -- PIM-APR-001 when no row naming that role carries ApproverUpns.
    # (An Azure role falls back to the owners of the groups assigned it, so it is not flagged here.)
    # ------------------------------------------------------------------
    if ($policyTpls.Count -gt 0) {
        $roleApprovers = @{}; $roleApprovalRows = New-Object System.Collections.Generic.List[object]
        foreach ($asgBase in @('PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Azure-Resources')) {
            if (-not $loaded.ContainsKey($asgBase)) { continue }
            $rows = $loaded[$asgBase].rows
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $r = $rows[$i]
                if (Test-PimRowIsBlank -Row $r) { continue }
                if ((Get-PimRowValue -Row $r -Column 'Action').Trim() -eq 'Remove') { continue }
                $tplVal = (Get-PimRowValue -Row $r -Column 'PolicyTemplate').Trim()
                $what = if ($asgBase -eq 'PIM-Assignments-Azure-Resources') { "Azure role '$((Get-PimRowValue -Row $r -Column 'AzScopePermission').Trim())' at $((Get-PimRowValue -Row $r -Column 'AzScope').Trim())" }
                        else { "role '$((Get-PimRowValue -Row $r -Column 'RoleDefinitionName').Trim())'" }
                $tplKey = & $resolveTpl $tplVal
                if ($tplVal -and -not $tplKey) {
                    [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-POL-001' -Csv $asgBase -Row $i -Column 'PolicyTemplate' -Subject (Get-PimRowValue -Row $r -Column 'GroupTag').Trim() -Target $tplVal `
                        -Message "PolicyTemplate '$tplVal' on $what is not a policy template in the store -- the engine skips that role's policy apply." `
                        -Suggestion ("Leave it blank for the standard template, or use one of: " + (@($policyTpls.Keys | Sort-Object) -join ', ') + ".")))
                    continue
                }
                if ($asgBase -eq 'PIM-Assignments-Azure-Resources') { continue }
                $rn = (Get-PimRowValue -Row $r -Column 'RoleDefinitionName').Trim().ToLowerInvariant()
                if (-not $rn) { continue }
                if ((Get-PimRowValue -Row $r -Column 'ApproverUpns').Trim()) { $roleApprovers[$rn] = $true }
                $effTpl = if ($tplKey) { $tplKey } else { "$($tplDefaults['directoryRole'])" }
                if ($policyTpls.ContainsKey($effTpl) -and $policyTpls[$effTpl].ApprovalMode -ne 'None') {
                    [void]$roleApprovalRows.Add(@{ base = $asgBase; i = $i; rn = $rn; tpl = $effTpl; what = $what; tag = (Get-PimRowValue -Row $r -Column 'GroupTag').Trim() })
                }
            }
        }
        foreach ($x in $roleApprovalRows) {
            if ($roleApprovers.ContainsKey($x.rn)) { continue }
            [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-APR-001' -Csv $x.base -Row $x.i -Column 'ApproverUpns' -Subject $x.tag -Target $x.tpl `
                -Message "$($x.what) links policy template '$($x.tpl)', which needs APPROVAL, but no row for that role names approvers in ApproverUpns -- the engine refuses to write an approval with nobody to approve, so the role keeps its current policy." `
                -Suggestion "Put the approvers' UPNs in the ApproverUpns column (separated by |), or switch the row back to the standard template (blank)."))
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

    # ------------------------------------------------------------------
    # PIM-WL-004 (REQ-U, 2026-09-19): a workload group and its workload binding are ONE unit. Operator:
    # "otherwise we will end with orphaned permission groups that are not connected with the actual workload" /
    # "you must have a warning if that is the case". Both directions, severity warning:
    #   (a) a definition row whose Workload has a binding entity (Intune -> PIM-Assignments-Intune, Defender ->
    #       PIM-Assignments-Defender, both + the generic PIM-Assignments-Workloads; the generic connectors ->
    #       PIM-Assignments-Workloads) but NO binding row for its GroupTag (or its group name) -- the engine
    #       creates the group and it never holds the workload role;
    #   (b) a PIM-Assignments-Intune / -Defender row whose GroupTag no definition defines -- a workload role
    #       for a group PIM does not define. (The same break in PIM-Assignments-Workloads is already an ERROR,
    #       PIM-FK-001, so it is not reported twice.)
    # This checks the DESIRED rows. The live check (does the group really hold the role) is the drift snapshot's.
    # ------------------------------------------------------------------
    foreach ($db in $defGroupBases) {
        if (-not $loaded.ContainsKey($db)) { continue }
        $rows = $loaded[$db].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $wlv = (Get-PimRowValue -Row $r -Column 'Workload').Trim()
            if (-not $wlv) { continue }
            $kind = & $wlKindOf $wlv
            if (-not $kind) { continue }
            if ((Get-PimRowValue -Row $r -Column 'Lifecycle').Trim() -match '(?i)^retire') { continue }
            $tag = (Get-PimRowValue -Row $r -Column 'GroupTag').Trim()
            $gnm = (Get-PimRowValue -Row $r -Column 'GroupName').Trim()
            if (-not $tag -and -not $gnm) { continue }
            $ents = @(if (Get-Command Get-PimWorkloadBindingEntities -ErrorAction SilentlyContinue) { Get-PimWorkloadBindingEntities -Kind $kind }
                      elseif ($kind -eq 'intune') { 'PIM-Assignments-Intune', 'PIM-Assignments-Workloads' }
                      elseif ($kind -eq 'defender') { 'PIM-Assignments-Defender', 'PIM-Assignments-Workloads' }
                      else { 'PIM-Assignments-Workloads' })
            $bound = $wlBound.ContainsKey($kind) -and (($tag -and $wlBound[$kind].ContainsKey($tag.ToLowerInvariant())) -or ($gnm -and $wlBound[$kind].ContainsKey($gnm.ToLowerInvariant())))
            if ($bound) { continue }
            $unread = @($ents | Where-Object { $wlBindUnread.ContainsKey($_) })
            if ($unread.Count) {
                [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-WL-004' -Csv $db -Row $i -Column 'Workload' -Subject $tag -Target $tag `
                    -Message "Workload group '$(if ($tag) { $tag } else { $gnm })' ($wlv): its binding could NOT be checked -- $($unread -join ', ') could not be read ($(@($unread | ForEach-Object { $wlBindUnread[$_] }) -join '; '))." `
                    -Suggestion "Re-run Validate when the store answers."))
                continue
            }
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-WL-004' -Csv $db -Row $i -Column 'GroupTag' -Subject $tag -Target $tag `
                -Message "Workload group '$(if ($tag) { $tag } else { $gnm })' has Workload '$wlv' but NO binding row in $($ents -join ' or ') -- the engine creates the group and never gives it a $kind role, so it is an orphan permission group." `
                -Suggestion "Add its binding row (GroupTag '$tag' + the $kind role) so the group and its role are deployed as one unit, or clear Workload if this group is bound some other way."))
        }
    }
    foreach ($pair in @(@('PIM-Assignments-Intune', 'Intune'), @('PIM-Assignments-Defender', 'Defender XDR'))) {
        if ($wlBindUnread.ContainsKey($pair[0])) { continue }
        $rows = @($loaded[$pair[0]].rows)
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            if ((Get-PimRowValue -Row $r -Column 'Action').Trim() -ieq 'Remove') { continue }
            $bt = (Get-PimRowValue -Row $r -Column 'GroupTag').Trim()
            if (-not $bt) { continue }
            $btl = $bt.ToLowerInvariant()
            if ($groupTagIndex.ContainsKey($btl) -or $defNameToTag.ContainsKey($btl)) { continue }
            $role = (Get-PimRowValue -Row $r -Column 'RoleDefinitionName').Trim()
            [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-WL-004' -Csv $pair[0] -Row $i -Column 'GroupTag' -Subject $role -Target $bt `
                -Message "$($pair[1]) binding '$role' names GroupTag '$bt', which no definition defines -- a workload role for a group PIM does not define (the engine cannot resolve it, or binds a group it does not manage)." `
                -Suggestion "Define '$bt' in a Definitions entity (with Workload set), or remove this binding row."))
        }
    }

    # ------------------------------------------------------------------
    # PIM-ROLE-OWNER-001: a role / org / task definition row should name an
    # accountable sponsor/owner (Owners or SponsorUpn) -- required for
    # validation/audit/renewal (REQUIREMENTS §13 "Role sponsor/owner",
    # §23 "Admin metadata fields" Sponsor). Severity INFO (never blocks Save):
    # a role with no owner has nobody to recertify it.
    # ------------------------------------------------------------------
    foreach ($defBase in @('PIM-Definitions-Roles','PIM-Definitions-Organization','PIM-Definitions-Tasks')) {
        if (-not $loaded.ContainsKey($defBase)) { continue }
        $rows = $loaded[$defBase].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $gn = (Get-PimRowValue -Row $r -Column 'GroupName').Trim()
            if (-not $gn) { continue }
            $owners  = (Get-PimRowValue -Row $r -Column 'Owners').Trim()
            $sponsor = (Get-PimRowValue -Row $r -Column 'SponsorUpn').Trim()
            $dept    = (Get-PimRowValue -Row $r -Column 'Department').Trim()
            if (-not $owners -and -not $sponsor -and -not $dept) {
                [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-ROLE-OWNER-001' -Csv $defBase -Row $i -Column 'Owners' `
                    -Message "Role/org/task '$gn' has no accountable owner (Owners, SponsorUpn and Department are all empty) -- there is nobody to recertify or renew it in an access review." `
                    -Suggestion "Set Owners (semicolon-separated UPNs) or SponsorUpn, or assign a Department whose contact owns it. The owner is the renewal/audit contact."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-AUTH-001 / PIM-AUTH-002: each admin must have the required strong
    # auth methods (REQUIREMENTS §23 "Auth-method validator", ROADMAP #13).
    # The live methods come from an optional 'auth-methods' tenant cache
    # (upn-lower -> @(method-types)); when that cache is absent the check
    # degrades to a single info (no live data) instead of breaking. The
    # required set is $global:PIM_RequiredAuthMethods (default: a phishing-
    # resistant authenticator OR passkey), overridable.
    #   PIM-AUTH-001 = admin has NONE of the required methods.
    #   PIM-AUTH-002 = admin has only weak methods (sms/voice) and no strong one.
    #   BOTH ARE WARNINGS (operator 2026-09-19: "this must be a warning (non error), as it blocks everything"): they
    #   describe the LIVE directory, not the rows being committed -- a newly created admin has no method until its TAP
    #   is used -- and nothing in the grid can fix them, so an ERROR blocked every commit on the environment.
    # ------------------------------------------------------------------
    $authCache = $null
    if (Get-Command Read-PimTenantListCache -ErrorAction SilentlyContinue) {
        try {
            if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
                $authCache = Get-PimTenantCacheEntry -Kind 'auth-methods'   # SQL pim.TenantCache
            }
        } catch { $authCache = $null }
    }
    if ($adminIndex.Count -gt 0) {
        $required = if ($global:PIM_RequiredAuthMethods) { @($global:PIM_RequiredAuthMethods) } else { @('microsoftAuthenticator','passkey','fido2','windowsHelloForBusiness','certificate') }
        $weakOnly = @('sms','voice','phone','email')
        $reqLc = @($required | ForEach-Object { "$_".ToLowerInvariant() })
        $weakLc = @($weakOnly | ForEach-Object { "$_".ToLowerInvariant() })
        if (-not $authCache) {
            [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-AUTH-001' -Csv 'Account-Definitions-Admins' `
                -Message "Admin auth-method validation skipped: no 'auth-methods' tenant cache is present (needs UserAuthenticationMethod.Read.All on the engine SPN + a refresh)." `
                -Suggestion "Run a tenant-list refresh that includes auth methods to enable PIM-AUTH-001/002 per-admin checks."))
        } else {
            # Build a upn-lower -> @(method-type-lower) map from the cache (tolerant of shapes).
            $methodsByUpn = @{}
            foreach ($prop in $authCache.PSObject.Properties) {
                $key = "$($prop.Name)".ToLowerInvariant()
                $methodsByUpn[$key] = @(@($prop.Value) | ForEach-Object { "$_".ToLowerInvariant() })
            }
            foreach ($k in $adminIndex.Keys) {
                $a = $adminIndex[$k]
                if ("$($a.TargetPlatform)".Trim() -ieq 'AD') { continue }   # AD-only: no Entra auth methods exist (password only)
                $methods = @()
                if ($methodsByUpn.ContainsKey($k)) { $methods = $methodsByUpn[$k] }
                $hasStrong = $false
                foreach ($m in $methods) { if ($reqLc -contains $m) { $hasStrong = $true; break } }
                if (-not $hasStrong) {
                    if ($methods.Count -gt 0 -and (@($methods | Where-Object { $weakLc -contains $_ }).Count -eq $methods.Count)) {
                        [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-AUTH-002' -Csv 'Account-Definitions-Admins' -Row $a.Row -Column 'UserPrincipalName' `
                            -Message "Admin '$($a.Upn)' has only weak auth methods ($($methods -join ', ')) and no phishing-resistant method. Privileged accounts must use a strong method." `
                            -Suggestion "Register an authenticator / passkey / FIDO2 / WHfB for this admin (the required set is `$global:PIM_RequiredAuthMethods)."))
                    } else {
                        [void]$violations.Add((New-PimViolation -Severity 'warning' -Code 'PIM-AUTH-001' -Csv 'Account-Definitions-Admins' -Row $a.Row -Column 'UserPrincipalName' `
                            -Message "Admin '$($a.Upn)' has none of the required auth methods ($($required -join ', ')). Live methods: $(if ($methods.Count) { $methods -join ', ' } else { '(none registered)' })." `
                            -Suggestion "Register one of the required methods before granting privileged access."))
                    }
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-ORPHAN-AZ-001: an Azure-RBAC assignment whose AzScope no longer
    # exists in the tenant (REQUIREMENTS §23 "Orphaned-Azure-scope validator",
    # ROADMAP #19). Only runs when an azure-scopes cache is present; otherwise
    # skips (no false positives without live truth). Scope match is a prefix
    # match (a row at .../resourceGroups/x is valid if its subscription scope
    # is cached) so RG/resource rows under a known sub aren't flagged.
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # PIM-AZ-PLACEHOLDER-001: an AzScope that is a TEMPLATE PLACEHOLDER, not a real scope.
    # 🔴 Measured live 2026-09-12: four rows imported from templates/azure-rbac.template.json still
    # carried /subscriptions/00000000-0000-0000-0000-000000000000. ARM answers 404
    # SubscriptionNotFound, so the engine fails those rows on EVERY run (delta-pim-azure, 4 of its 17
    # failures) -- and the validator called them "may have been deleted or moved", which sends an
    # operator looking for a subscription that never existed. ERROR: such a row can never be applied.
    # Needs no cache -- it is a property of the value itself -- so it runs even when the cache is absent.
    # A subscription id is ALWAYS a GUID; a management-group id is a free-form name, so for MGs only
    # the all-zero GUID is treated as a placeholder.
    # ------------------------------------------------------------------
    $placeholderRows = @{}
    if ($loaded.ContainsKey('PIM-Assignments-Azure-Resources')) {
        $zeroGuid = '00000000-0000-0000-0000-000000000000'
        $rows = $loaded['PIM-Assignments-Azure-Resources'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $sc = (Get-PimRowValue -Row $r -Column 'AzScope').Trim()
            if (-not $sc) { continue }
            $why = $null
            if ($sc -match '(?i)^/subscriptions/([^/]*)') {
                $sid = $Matches[1]
                $g = [guid]::Empty
                if ($sid -eq $zeroGuid) { $why = 'the all-zero subscription id is a template placeholder' }
                elseif (-not [guid]::TryParse($sid, [ref]$g)) { $why = "'$sid' is not a subscription id (a subscription id is always a GUID)" }
            } elseif ($sc -match "(?i)^/providers/Microsoft\.Management/managementGroups/$zeroGuid(/|$)") {
                $why = 'the all-zero management-group id is a template placeholder'
            }
            if ($why) {
                $placeholderRows[$i] = $true
                # Name the ROW, not only the scope: several rows share one placeholder, and four identical
                # cards gave the operator no way to tell which group/role each one was (2026-09-12).
                $phTag  = "$(Get-PimRowValue -Row $r -Column 'GroupTag')".Trim()
                $phRole = "$(Get-PimRowValue -Row $r -Column 'AzScopePermission')".Trim()
                $phWho  = if ($phTag -or $phRole) { "'$phTag' -> $phRole " } else { '' }
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-AZ-PLACEHOLDER-001' -Csv 'PIM-Assignments-Azure-Resources' -Row $i -Column 'AzScope' `
                    -Subject $sc `
                    -Message "Assignment $($phWho)at AzScope '$sc' is not a real scope: $why. This row can never be applied -- the engine fails it on every run." `
                    -Suggestion "Replace it with a real subscription id (Azure portal -> Subscriptions) or management-group id, or delete the row."))
            }
        }
    }

    # PIM-ORPHAN-AZ-001 -- definitive when the azure-scopes cache is fresh (ERROR: a scope that does not
    # exist can never be assigned), silent per row with ONE info finding when it is not.
    $ciAz = $cacheInfo['azureScopes']
    if ($cachedAzureScopesPresent -and -not $ciAz.fresh -and $loaded.ContainsKey('PIM-Assignments-Azure-Resources') -and @($loaded['PIM-Assignments-Azure-Resources'].rows).Count -gt 0) {
        [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-ORPHAN-AZ-001' -Csv '<global>' `
            -Message "Azure scopes were NOT checked: the 'azure-scopes' tenant cache is $($ciAz.ageText), so it cannot prove whether a scope exists. No Azure row has been judged either way." `
            -Suggestion "The scheduler's tenant-cache job refreshes it automatically; to refresh now click the cache badge in the UI, or run Open-PimManager.ps1 -RefreshTenantLists."))
    }
    if ($cachedAzureScopesPresent -and $ciAz.fresh -and $loaded.ContainsKey('PIM-Assignments-Azure-Resources')) {
        $scopeKeys = @($cachedAzureScopes.Keys)
        $azAt = & $cacheReadAt $ciAz
        $rows = $loaded['PIM-Assignments-Azure-Resources'].rows
        for ($i = 0; $i -lt $rows.Count; $i++) {
            if ($placeholderRows.ContainsKey($i)) { continue }   # already an error with the real reason
            $r = $rows[$i]
            if (Test-PimRowIsBlank -Row $r) { continue }
            $sc = (Get-PimRowValue -Row $r -Column 'AzScope').Trim()
            if (-not $sc) { continue }
            $scLc = $sc.ToLowerInvariant()
            $found = $false
            if ($cachedAzureScopes.ContainsKey($scLc)) { $found = $true }
            else {
                # Accept the row if any cached scope is a prefix of it (child of a known sub/MG).
                foreach ($sk in $scopeKeys) { if ($scLc.StartsWith($sk + '/') -or $sk.StartsWith($scLc + '/')) { $found = $true; break } }
            }
            if (-not $found) {
                [void]$violations.Add((New-PimViolation -Severity 'error' -Code 'PIM-ORPHAN-AZ-001' -Csv 'PIM-Assignments-Azure-Resources' -Row $i -Column 'AzScope' `
                    -Subject $sc `
                    -Message "Azure scope '$sc' does not exist (and is not under any existing scope) -- checked against the $($ciAz.count) management groups/subscriptions read at $azAt. This row can never be applied as written." `
                    -Suggestion "If the subscription/management group was removed or moved, delete this row; if the scope id is mistyped, correct it."))
            }
        }
    }

    # ------------------------------------------------------------------
    # PIM-STALE-003: a PIM permission/role group that has not been activated
    # in N days (REQUIREMENTS §23 "Stale-group detection", ROADMAP #20).
    # Activity comes from an optional 'pim-activity' tenant cache
    # (groupTag-lower -> lastActivatedUtc ISO string). When absent, skip.
    # Threshold = $global:PIM_StaleGroupDays (default 90).
    # ------------------------------------------------------------------
    $activityCache = $null
    if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
        try { $activityCache = Get-PimTenantCacheEntry -Kind 'pim-activity' }   # SQL pim.TenantCache
        catch { $activityCache = $null }
    }
    if ($activityCache -and $groupTagIndex.Count -gt 0) {
        $staleDays = if ($global:PIM_StaleGroupDays) { [int]$global:PIM_StaleGroupDays } else { 90 }
        $nowUtc = (Get-Date).ToUniversalTime()
        $actByTag = @{}
        foreach ($prop in $activityCache.PSObject.Properties) { $actByTag["$($prop.Name)".ToLowerInvariant()] = "$($prop.Value)" }
        foreach ($key in $groupTagIndex.Keys) {
            $g = $groupTagIndex[$key]
            $last = if ($actByTag.ContainsKey($key)) { $actByTag[$key] } else { $null }
            $ageDays = $null
            # IMP-02: locale-safe; the helper never throws, so the catch is no longer load-bearing.
            if ($last) { $lastDt = Get-PimUtcStamp $last; if ($null -ne $lastDt) { $ageDays = ($nowUtc - $lastDt).TotalDays } }
            if (($null -eq $last) -or ($null -ne $ageDays -and $ageDays -gt $staleDays)) {
                $detail = if ($null -eq $last) { "never activated" } else { "last activated $([int]$ageDays) days ago" }
                [void]$violations.Add((New-PimViolation -Severity 'info' -Code 'PIM-STALE-003' -Csv $g.Csv -Row $g.Row -Column 'GroupTag' `
                    -Message "PIM group '$($g.Tag)' has $detail (stale threshold $staleDays days) -- it may be an unused grant that should be removed from Entra and the data." `
                    -Suggestion "Confirm the grant is still needed; if not, retire the group (Lifecycle=Retire) and delete its assignment rows. Adjust `$global:PIM_StaleGroupDays to change the threshold."))
            }
        }
    }

    # ------------------------------------------------------------------
    # WARNING OVERRIDE POST-FILTER (REQUIREMENTS §11). THE single hook: apply
    # the operator's acknowledgements over the produced finding set. Matched
    # warnings are DOWNGRADED to 'acknowledged' (kept + annotated, never
    # dropped); expired overrides resurface their finding as active. Guarded so
    # the validator never breaks if the module or config is absent/malformed.
    # ------------------------------------------------------------------
    $finalViolations = @($violations.ToArray())
    $ackResult = $null
    if (Get-Command Apply-PimWarningOverrides -ErrorAction SilentlyContinue) {
        try {
            $ackResult = $null
            if (Get-Command Get-PimManagerWarningOverrides -ErrorAction SilentlyContinue) {
                # The SQL store (pim.Settings['WarningOverrides']). Read-PimWarningOverrideConfig
                # accepts the parsed document as -Config, so no shape translation.
                $ackResult = Apply-PimWarningOverrides -Findings $finalViolations -Config (Get-PimManagerWarningOverrides)
            }
            # Standalone dot-source (a test loading _validator.ps1 with no Manager around it): no store,
            # so nothing is acknowledged. There is no override FILE to fall back to (SQL-only).
            if ($ackResult) { $finalViolations = @($ackResult.findings) }
        } catch { $ackResult = $null }
    }

    $acknowledged    = if ($ackResult) { [int]$ackResult.acknowledged } else { 0 }
    $expiredToActive = if ($ackResult) { [int]$ackResult.expiredToActive } else { 0 }

    return [ordered]@{
        violations     = @($finalViolations)
        ranAt          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        cacheFreshness = $cacheFreshness
        summary        = [ordered]@{
            errors          = @($finalViolations | Where-Object { $_.Severity -eq 'error'   }).Count
            warnings        = @($finalViolations | Where-Object { $_.Severity -eq 'warning' }).Count
            infos           = @($finalViolations | Where-Object { $_.Severity -eq 'info'    }).Count
            acknowledged    = $acknowledged
            expiredToActive = $expiredToActive
            total           = @($finalViolations).Count
        }
    }
}
