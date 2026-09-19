<#
  PIM-BreakGlassAccounts.ps1 -- IMP-39 (§33.28): the break-glass ACCOUNT list lives in SQL.

  WHY THIS FILE EXISTS
  --------------------
  The accounts that PIM must NEVER disable, revoke or offboard (the emergency accounts you recover
  WITH) came only from $global:PIM_BreakGlassAccounts / env PIM_BREAKGLASS_ACCOUNTS. No setup script
  set either, the value had to be set by hand on BOTH ca-pim-manager and ca-pim-tick, a change was not
  audited, and the Manager could not show or edit it. Four readers (ApprovalGate, SessionRevoke,
  DisableGuard, the Manager's revoke exclusion) each carried their own copy of the parser.

  WHAT IT IS NOW
  --------------
  * The list is pim.Settings['BreakGlassAccounts'] -- a JSON ARRAY of UPNs and/or object ids. Both
    containers read the same row, so a change takes effect on both without touching either app.
  * The legacy global/env value is UNIONED in, so nothing configured today is lost when this ships.
  * This file is the ONE definition of Get-PimBreakGlassIdentifiers / Test-PimRowIsBreakGlass. The
    engine files dot-source it instead of defining their own.

  🔒 FAIL SAFE. When a SQL store is configured but the list cannot be read, the engine guards cannot
  prove an account is NOT break-glass. Get-PimBreakGlassIdentifiers then returns the UNREADABLE marker,
  and Test-PimRowIsBreakGlass treats EVERY row as protected -- nothing is disabled or revoked this run,
  and it says so loudly. A guard that cannot read its list must never read it as "empty".

  Contract (M-SERVER / M-CLIENT build against it):
    Get-PimBreakGlassAccountList [-ConnectionString <cs>] [-StoreOnly]  -> string[] (lower-case, unique)
        THROWS when a store is configured and cannot be read. -StoreOnly = only the SQL row (for an
        editor), without the legacy global/env union.
    Set-PimBreakGlassAccountList -ConnectionString <cs> -Accounts <string[]> [-Actor <upn>]
        -> string[] as stored. THROWS on an invalid entry or a failed write. Audited when -Actor is given.
        [-ExpectedSnapshotHash <h>] writes only if the stored list still hashes to <h> (compare-and-set);
        used by the Manager's maker/checker (PIM-BreakGlassChange.ps1). The Manager never writes the
        list without it: a change there needs a SECOND SuperAdmin's approval.
    Get-PimBreakGlassListHash -Accounts <list> -> the order/case-insensitive snapshot hash.
    Get-PimBreakGlassAccountStatus [-ConnectionString <cs>] -> the full read verdict (for a UI).

  PS 5.1-safe (no ?./??, no ternary).
#>

Set-StrictMode -Off

if ($null -eq $script:PimBreakGlassCache) { $script:PimBreakGlassCache = $null }

function Get-PimBreakGlassSettingName { 'BreakGlassAccounts' }
function Get-PimBreakGlassUnreadableMarker { '<break-glass-list-unreadable>' }

function ConvertTo-PimBreakGlassList {
    <#
      PURE. Normalise any stored/configured shape to a lower-case, trimmed, unique string[]:
      a JSON-array string, a ';'/',' separated string, an array, or an object carrying .accounts.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return @() }
    $items = @()
    if ($Value -is [string]) {
        $s = "$Value".Trim()
        if (-not $s) { return @() }
        if ($s.StartsWith('[')) {
            # PS 5.1 emits a JSON array as ONE object: assign first, then @() (the temp-then-@() idiom).
            try { $tmp = $s | ConvertFrom-Json; $items = @($tmp) } catch { throw "break-glass list is not a valid JSON array: $($_.Exception.Message)" }
        } else {
            $items = @($s -split '[;,]')
        }
    } elseif ($Value.PSObject -and $Value.PSObject.Properties['accounts']) {
        $items = @($Value.accounts)
    } else {
        $items = @($Value)
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($i in $items) {
        if ($null -eq $i) { continue }
        $t = "$i".Trim().ToLowerInvariant()
        if ($t -and -not $out.Contains($t)) { $out.Add($t) }
    }
    return $out.ToArray()
}

function Get-PimBreakGlassLegacyAccounts {
    # The pre-IMP-39 sources, unchanged: $global:PIM_BreakGlassAccounts, then env PIM_BREAKGLASS_ACCOUNTS
    # (SEC-07: through the one safety-knob reader when it is loaded).
    [CmdletBinding()] param()
    $raw = $null
    if (Get-Command Get-PimSafetyKnob -ErrorAction SilentlyContinue) {
        $raw = Get-PimSafetyKnob -Name 'PIM_BreakGlassAccounts' -EnvName 'PIM_BREAKGLASS_ACCOUNTS'
    } else {
        # Same precedence as Get-PimSafetyKnob (global, then env), for a host that loaded only this file.
        $raw = Get-Variable -Name 'PIM_BreakGlassAccounts' -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if (-not $raw -and "$env:PIM_BREAKGLASS_ACCOUNTS") { $raw = "$env:PIM_BREAKGLASS_ACCOUNTS" }
    }
    return @(ConvertTo-PimBreakGlassList -Value $raw)
}

function Resolve-PimBreakGlassStore {
    <#
      Which store holds the list? Returns @{ configured; cs; error }.
        configured=$false -> no SQL store in this process at all (an offline test, a bare shell):
                             the legacy sources are the whole answer and that is not a failure.
        configured=$true, cs='' -> a store SHOULD exist (hosted, or a server is named) but could
                             not be resolved: that IS a failure, and the guards fail safe on it.
    #>
    [CmdletBinding()] param([string]$ConnectionString)
    if ("$ConnectionString".Trim()) { return [pscustomobject]@{ configured = $true; cs = "$ConnectionString"; error = '' } }
    if ("$($global:PIM_EngineSqlCs)".Trim())        { return [pscustomobject]@{ configured = $true; cs = "$($global:PIM_EngineSqlCs)"; error = '' } }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return [pscustomobject]@{ configured = $true; cs = "$($global:PIM_SqlConnectionString)"; error = '' } }
    $wanted = ("$($global:PIM_SqlServer)".Trim() -or "$env:PIM_HOSTED" -eq '1' -or "$env:PIM_SqlServer".Trim())
    if (-not $wanted) { return [pscustomobject]@{ configured = $false; cs = ''; error = '' } }
    if (-not (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ configured = $true; cs = ''; error = 'the SQL store library is not loaded in this runtime' }
    }
    try {
        $cs = Get-PimSqlConnectionString
        if ("$cs".Trim()) { return [pscustomobject]@{ configured = $true; cs = "$cs"; error = '' } }
        return [pscustomobject]@{ configured = $true; cs = ''; error = 'the SQL connection string resolved empty' }
    } catch {
        return [pscustomobject]@{ configured = $true; cs = ''; error = "the SQL connection string could not be resolved: $($_.Exception.Message)" }
    }
}

function Clear-PimBreakGlassCache { [CmdletBinding()] param() $script:PimBreakGlassCache = $null }

function Get-PimBreakGlassAccountStatus {
    <#
      The full read verdict. Never throws. Returns:
        accounts        union of store + legacy (what the guards protect)
        storeAccounts   the SQL row only (what an editor shows and saves)
        legacyAccounts  global/env only (shown so an operator can move them into SQL)
        storeConfigured is a SQL store expected in this process
        storeOk         the SQL row was read (absent row = ok, empty)
        error           why not, when storeOk is $false
      Cached for 60 s per connection string (successful reads only) -- the engine asks per scope.
    #>
    [CmdletBinding()] param([string]$ConnectionString, [switch]$NoCache)
    $legacy = @(Get-PimBreakGlassLegacyAccounts)
    $st = Resolve-PimBreakGlassStore -ConnectionString $ConnectionString
    $store = @(); $ok = $true; $err = ''
    if ($st.configured) {
        if (-not $st.cs) { $ok = $false; $err = $st.error }
        elseif (-not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { $ok = $false; $err = 'Get-PimSqlSetting is not loaded in this runtime' }
        else {
            $c = $script:PimBreakGlassCache
            if (-not $NoCache -and $c -and "$($c.cs)" -eq "$($st.cs)" -and (([datetime]::UtcNow - $c.at).TotalSeconds -lt 60)) {
                $store = @($c.accounts)
            } else {
                try {
                    $v = Get-PimSqlSetting -ConnectionString $st.cs -Name (Get-PimBreakGlassSettingName)
                    $store = @(ConvertTo-PimBreakGlassList -Value $v)
                    $script:PimBreakGlassCache = [pscustomobject]@{ cs = "$($st.cs)"; at = [datetime]::UtcNow; accounts = @($store) }
                } catch { $ok = $false; $err = "pim.Settings['$(Get-PimBreakGlassSettingName)'] could not be read: $($_.Exception.Message)" }
            }
        }
    }
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($a in (@($store) + @($legacy))) { if ($a -and -not $all.Contains($a)) { $all.Add($a) } }
    return [pscustomobject]@{
        accounts        = $all.ToArray()
        storeAccounts   = @($store)
        legacyAccounts  = @($legacy)
        storeConfigured = [bool]$st.configured
        storeOk         = [bool]$ok
        error           = "$err"
    }
}

function Get-PimBreakGlassAccountList {
    # IMP-39 contract. string[] (lower-case, unique). THROWS when a store is configured and unreadable:
    # an unreadable list is not an empty list, and the caller must decide what "unknown" means for it.
    [CmdletBinding()] param([string]$ConnectionString, [switch]$StoreOnly)
    $s = Get-PimBreakGlassAccountStatus -ConnectionString $ConnectionString
    if ($s.storeConfigured -and -not $s.storeOk) { throw "break-glass account list is UNREADABLE: $($s.error)" }
    if ($StoreOnly) { return @($s.storeAccounts) }
    return @($s.accounts)
}

function Test-PimBreakGlassAccountEntry {
    # PURE. One entry is a UPN (x@y) or an object id (GUID). Nothing else can match a row, so anything
    # else is a typo that would silently protect nobody.
    [CmdletBinding()] param([string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $false }
    if ($v -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $true }
    return ($v -match '^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$')
}

function Get-PimBreakGlassListHash {
    <#
      PURE. The SNAPSHOT hash of a break-glass list (maker/checker, PIM-BreakGlassChange.ps1): SHA-256
      (lower-case hex) over the normalised entries, sorted ORDINALLY and joined with a newline. The list
      is a SET -- order and case never protect anyone differently, so they never change the hash.
      An empty list (or an absent row) hashes to the hash of the empty string, one fixed value.
    #>
    [CmdletBinding()] param([AllowNull()][AllowEmptyCollection()][object]$Accounts)
    $list = @(ConvertTo-PimBreakGlassList -Value $Accounts)
    $arr = [string[]]@($list)
    [Array]::Sort($arr, [System.StringComparer]::Ordinal)
    $text = [string]::Join("`n", $arr)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    return (([System.BitConverter]::ToString($bytes)) -replace '-', '').ToLowerInvariant()
}

function Get-PimBreakGlassStaleMarker { 'BREAKGLASS-STALE' }

function Set-PimBreakGlassAccountList {
    # IMP-39 contract. Replace the SQL list. THROWS on an invalid entry or a failed write -- an operator
    # must never believe an emergency account is protected when it is not. Returns the stored list.
    #   -ActorSource           recorded on the audit row ('setup' for the host-side operator script).
    #   -AuditDetail           extra fields merged into the audit row's After (justification, maker, checker ...).
    #   -ExpectedSnapshotHash  MAKER/CHECKER (PIM-BreakGlassChange.ps1): write ONLY IF the stored list still
    #                          hashes to this snapshot, atomically (compare-and-set on the raw row). A list that
    #                          changed since the request was made THROWS a message starting BREAKGLASS-STALE and
    #                          writes nothing -- a checker must never approve a diff against a list they did not see.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][string[]]$Accounts,
        [string]$Actor = '',
        [string]$ActorSource = '',
        [hashtable]$AuditDetail = $null,
        [string]$ExpectedSnapshotHash = ''
    )
    $bad = @(@($Accounts) | Where-Object { "$_".Trim() -and -not (Test-PimBreakGlassAccountEntry -Value "$_") })
    if ($bad.Count) { throw ("invalid break-glass entr{0}: {1} -- each entry must be a UPN or an object id" -f $(if ($bad.Count -eq 1) { 'y' } else { 'ies' }), ($bad -join ', ')) }
    $list = @(ConvertTo-PimBreakGlassList -Value @($Accounts))
    $before = $null
    $json = ConvertTo-Json -InputObject @($list) -Compress
    if (-not $json -or $json -eq 'null') { $json = '[]' }
    if ("$ExpectedSnapshotHash".Trim()) {
        # Compare-and-set. Read the row EXACTLY as stored, check it is the snapshot the maker saw, and write
        # only if that exact row is still there -- so a concurrent writer (a second approval, the setup
        # script) can never be overwritten by a diff computed against an older list.
        if (-not (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue) -or -not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) {
            throw 'the compare-and-set store functions (Get-PimSqlSettingRaw / Set-PimSqlSettingIfUnchanged) are not loaded -- nothing was written'
        }
        $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name (Get-PimBreakGlassSettingName)
        $before = @(ConvertTo-PimBreakGlassList -Value $raw)
        $nowHash = Get-PimBreakGlassListHash -Accounts $before
        if ($nowHash -ne "$ExpectedSnapshotHash".Trim().ToLowerInvariant()) {
            throw ("{0}: the break-glass list changed since the request was made (snapshot {1}, now {2}) -- nothing was written" -f (Get-PimBreakGlassStaleMarker), "$ExpectedSnapshotHash".Substring(0, [Math]::Min(12, "$ExpectedSnapshotHash".Length)), $nowHash.Substring(0, 12))
        }
        $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimBreakGlassSettingName) -NewValueJson $json -ExpectedValueJson $raw
        if ([int]$n -ne 1) {
            throw ("{0}: the break-glass list was changed by someone else while this change was being applied -- nothing was written" -f (Get-PimBreakGlassStaleMarker))
        }
    } else {
        try { $before = @(ConvertTo-PimBreakGlassList -Value (Get-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimBreakGlassSettingName))) } catch { $before = $null }
        Set-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimBreakGlassSettingName) -ValueJson $json
    }
    Clear-PimBreakGlassCache
    if ("$Actor".Trim() -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
        try {
            $after = @{ accounts = @($list) }
            if ($AuditDetail) { foreach ($k in @($AuditDetail.Keys)) { $after[$k] = $AuditDetail[$k] } }
            $auditArgs = @{ ConnectionString = $ConnectionString; Actor = "$Actor"; Action = 'breakglass.accounts.set'
                            Target = (Get-PimBreakGlassSettingName); Before = @{ accounts = @($before) }; After = $after }
            if ("$ActorSource".Trim()) { $auditArgs['ActorSource'] = "$ActorSource" }
            Write-PimSqlAuditEvent @auditArgs
        } catch {
            # The list IS saved; the audit row is not. Say so -- this is the governance record for
            # the one list that exempts accounts from every guard.
            Write-Warning "[break-glass] the list was saved but its AUDIT event was NOT written: $($_.Exception.Message)"
        }
    }
    return @($list)
}

# ---- the engine guards' reader (the ONE definition) --------------------------------------------
function Get-PimBreakGlassIdentifiers {
    <#
      Break-glass / emergency principals to NEVER disable, revoke or offboard (lower-case UPNs and/or
      object ids). Store (pim.Settings) UNION legacy global/env.
      🔒 FAIL SAFE: a configured store that cannot be read returns the UNREADABLE marker, which
      Test-PimRowIsBreakGlass matches against EVERY row -- so every guard that consults it holds.
    #>
    [CmdletBinding()] param([string]$ConnectionString)
    $s = Get-PimBreakGlassAccountStatus -ConnectionString $ConnectionString
    if ($s.storeConfigured -and -not $s.storeOk) {
        Write-Warning ("[break-glass] the break-glass account list is UNREADABLE ({0}). Treating EVERY account as break-glass: nothing is disabled, revoked or offboarded until the list can be read." -f $s.error)
        return @(@($s.accounts) + @((Get-PimBreakGlassUnreadableMarker)))
    }
    return @($s.accounts)
}

function Test-PimBreakGlassListUnreadable {
    [CmdletBinding()] param([string[]]$Identifiers)
    return (@($Identifiers) -contains (Get-PimBreakGlassUnreadableMarker))
}

function Test-PimRowIsBreakGlass {
    # TRUE when the row's id/UPN/label matches a configured break-glass identifier -- or when the list
    # could not be read (fail safe: an unconfirmable account is treated as protected).
    param([Parameter(Mandatory)]$Row, [string[]]$Identifiers)
    if (-not $Identifiers -or $Identifiers.Count -eq 0) { return $false }
    if ($Identifiers -contains (Get-PimBreakGlassUnreadableMarker)) { return $true }
    $cand = @()
    foreach ($k in 'id','principalId','principal','principalUpn','principalName','target','userPrincipalName','UserPrincipalName','Username') {
        $p = $Row.PSObject.Properties[$k]
        if ($p -and "$($p.Value)".Trim()) { $cand += "$($p.Value)".Trim().ToLowerInvariant() }
    }
    foreach ($c in $cand) { if ($Identifiers -contains $c) { return $true } }
    return $false
}
