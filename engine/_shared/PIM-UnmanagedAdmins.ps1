#Requires -Version 5.1
<#
.SYNOPSIS
    IMP-33 (2026-09-18) -- the unmanaged-admin REPORT: privileged accounts that exist in the directory but have NO
    desired-state row. The ENGINE writes it (pim.Settings 'UnmanagedAdmins'); the MANAGER reads it for its overview tile.

.DESCRIPTION
    🪤 ITS OWN FILE ON PURPOSE. These lived in PIM-DisableGuard.ps1, and the Manager dot-sourced that whole file for the
    tile -- which also defined the account-disable guard functions the Manager probes with Get-Command, and turned the
    offboard path into 'account-disable is OFF' (Test-PimManagerSql, measured 2026-09-18). Pure functions + one
    never-throwing save; nothing here decides or performs a disable. PIM-DisableGuard.ps1 dot-sources this file.
#>

function Get-PimUnmanagedAdminSettingName { 'UnmanagedAdmins' }

function New-PimUnmanagedAdminRecord {
    <#
      🔴 IMP-33 (2026-09-18) -- PURE. The stored form of "privileged accounts that exist in the directory
      but have NO desired-state row", per account-disable scope.

      Measured on EFIF: the Admins scope ran `desired=5 live=14` every five minutes and NOTHING reported the
      nine accounts in between -- the unmanaged report above only ran when the diff proposed removals,
      which a Delta pass never does. So six real admin accounts had no TAP healing, no reminders and no
      review, and the Manager's admin-tap reset answered 404 for them, with no surface saying why.
      REPORT ONLY, like 71.22: this never disables, never creates, never proposes either.
      -Previous is the stored record (or $null); other scopes in it are kept. Returns
      @{ record; changed; accounts } -- `changed` is true when THIS scope's account set differs, which is
      what the caller logs on (a per-tick repeat is IMP-35's noise).
    #>
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string[]]$Unmanaged = @(),
        [string[]]$BreakGlass = @(),
        [object]$Previous,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $acc = @(@($Unmanaged) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $bg  = @(@($BreakGlass) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $scopes = [ordered]@{}
    if ($Previous -and $Previous.PSObject.Properties['scopes'] -and $Previous.scopes) {
        foreach ($pp in $Previous.scopes.PSObject.Properties) { $scopes[$pp.Name] = $pp.Value }
    }
    $before = @()
    if ($scopes.Contains($Scope) -and $scopes[$Scope] -and $scopes[$Scope].PSObject.Properties['accounts']) { $before = @($scopes[$Scope].accounts | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique) }
    $changed = (($before -join '|') -ne ($acc -join '|'))
    # 🪤 ALWAYS UTC: a caller's [datetime] can be Local kind (Windows PowerShell turns '...Z' into local time),
    # and a local stamp read back next to a UTC clock is off by the zone -- measured: a 10-minute-old record
    # read as 2h10m old (stale) on PS 5.1 in CEST.
    $obs = if ($NowUtc.Kind -eq [DateTimeKind]::Utc) { $NowUtc } else { $NowUtc.ToUniversalTime() }
    $scopes[$Scope] = [pscustomobject][ordered]@{ count = $acc.Count; accounts = $acc; breakGlassExcluded = $bg.Count; observedUtc = $obs.ToString('o') }
    $rec = [pscustomobject][ordered]@{
        schema  = 1
        scopes  = [pscustomobject]$scopes
        total   = (@($scopes.Values | ForEach-Object { [int]$_.count }) | Measure-Object -Sum).Sum
        fix     = 'Add each account to the definitions (on an MSP master: tools/setup/Add-PimCentralAdmin.ps1, then publish + downlink), or remove the account in Entra. PIM never creates, disables or removes an account because of this report.'
    }
    return @{ record = $rec; changed = $changed; accounts = $acc }
}

function Save-PimUnmanagedAdminReport {
    <#
      IMP-33 -- store the report in pim.Settings['UnmanagedAdmins'] for the Manager. NEVER throws (a reporting
      write must never fail an engine pass). Refuses when the desired set was not positively resolved: a
      failed read makes every admin look unmanaged, and a report that cries wolf is worse than none.
      -Reader/-Writer are test seams: { param($cs,$name) } / { param($cs,$name,$value) }.
    #>
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string[]]$Unmanaged = @(),
        [string[]]$BreakGlass = @(),
        [AllowNull()][object]$DesiredResolved,
        [AllowEmptyString()][AllowNull()][string]$ConnectionString,
        [scriptblock]$Reader,
        [scriptblock]$Writer
    )
    try {
        if ($DesiredResolved -ne $true) { return @{ ok = $false; changed = $false; reason = 'desired set not positively resolved -- not reporting (it would call every admin unmanaged)' } }
        if (-not "$ConnectionString".Trim()) { return @{ ok = $false; changed = $false; reason = 'no SQL store' } }
        if (-not $Reader) { $Reader = { param($cs, $n) Get-PimSqlSetting -ConnectionString $cs -Name $n } }
        if (-not $Writer) { $Writer = { param($cs, $n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } }
        $name = Get-PimUnmanagedAdminSettingName
        $prev = $null; try { $prev = & $Reader $ConnectionString $name } catch { $prev = $null }
        $r = New-PimUnmanagedAdminRecord -Scope $Scope -Unmanaged $Unmanaged -BreakGlass $BreakGlass -Previous $prev
        & $Writer $ConnectionString $name $r.record
        return @{ ok = $true; changed = $r.changed; accounts = $r.accounts; reason = 'recorded' }
    } catch {
        return @{ ok = $false; changed = $false; reason = "$($_.Exception.Message)" }
    }
}

function Get-PimUnmanagedAdminTile {
    <#
      IMP-33 -- PURE. The Manager's overview tile from the stored record (or $null). Never guesses:
      no record = "not reported yet" (the engine writes it on its next Admins pass), never "0".
      A record older than -StaleHours is flagged stale rather than trusted.
    #>
    param([AllowNull()][object]$Record, [datetime]$NowUtc = [datetime]::UtcNow, [int]$StaleHours = 2)
    if ($null -eq $Record -or -not $Record.PSObject.Properties['scopes'] -or -not $Record.scopes) {
        return [ordered]@{ ok = $true; reported = $false; count = $null; accounts = @(); stale = $false; observedUtc = ''
                           message = 'not reported yet -- the engine records this on its next Admins pass' }
    }
    $acc = New-Object System.Collections.Generic.List[string]; $latest = $null
    foreach ($sp in $Record.scopes.PSObject.Properties) {
        foreach ($a in @($sp.Value.accounts)) { if ("$a".Trim() -and -not $acc.Contains("$a")) { [void]$acc.Add("$a") } }
        # 🪤 pwsh 7's ConvertFrom-Json hands back a [datetime] for an ISO string (5.1 keeps the string); stringifying
        # that uses the CURRENT culture, which an invariant parse then misreads. Take a real [datetime] as-is.
        $ov = $sp.Value.observedUtc
        $t = [datetime]::MinValue; $okT = $false
        if ($ov -is [datetime]) { $t = $ov.ToUniversalTime(); $okT = $true }
        elseif ([datetime]::TryParse("$ov", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { $okT = $true }
        if ($okT -and ($null -eq $latest -or $t -gt $latest)) { $latest = $t }
    }
    # DateTime subtraction ignores Kind, so both sides must be UTC (see New-PimUnmanagedAdminRecord).
    $nowU = if ($NowUtc.Kind -eq [DateTimeKind]::Utc) { $NowUtc } else { $NowUtc.ToUniversalTime() }
    $stale = ($null -eq $latest) -or (($nowU - $latest).TotalHours -gt $StaleHours)
    return [ordered]@{
        ok = $true; reported = $true; count = $acc.Count; accounts = @($acc | Sort-Object)
        stale = $stale; observedUtc = $(if ($latest) { $latest.ToString('u') } else { '' })
        message = $(if ($acc.Count) { "$($acc.Count) privileged account(s) exist in the directory with NO desired-state row: no TAP healing, no reminders, no review. $($Record.fix)" } else { 'every admin account in the directory has a desired-state row' })
    }
}

# ---- REQ-ADM-REIMPORT-1 (operator 2026-09-27: "we need a way to re-import him using the configuration drift solution or import
# him"). An unmanaged admin account -- one PIM stopped managing, or one made outside PIM -- is IMPORTED: its definition row is
# built from the account itself, and its memberships come from the latest drift check's Keep rows. The Manager hands both
# to the page, which STAGES them (Review & commit); nothing is written here.
function ConvertTo-PimAdminImportRow {
    <#
      PURE. A directory user (Graph: userPrincipalName, givenName, surname, displayName, department, companyName,
      usageLocation, userType, accountEnabled) -> an Account-Definitions-Admins row. Nothing is invented: a value the
      account lacks stays empty for the operator to fill in; UserName is the UPN's local part (the account exists already).
    #>
    param([Parameter(Mandatory)][object]$User)
    $g = { param($n) $p = $User.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { "$($p.Value)".Trim() } else { '' } }
    $upn = & $g 'userPrincipalName'
    if (-not $upn) { throw 'the account has no userPrincipalName' }
    $first = & $g 'givenName'; $last = & $g 'surname'; $disp = & $g 'displayName'
    if (-not $first -and -not $last -and $disp) { $pp = @($disp -split '\s+'); $first = $pp[0]; $last = $(if ($pp.Count -gt 1) { ($pp[1..($pp.Count - 1)] -join ' ') } else { '' }) }
    $ini = (("$(if ($first) { $first.Substring(0, 1) })" + "$(if ($last) { $last.Substring(0, 1) })")).ToUpperInvariant()
    $enabled = $User.PSObject.Properties['accountEnabled'] -and $User.accountEnabled -ne $false
    [ordered]@{
        FirstName = $first; LastName = $last; Initials = $ini
        DisplayName = $(if ($disp) { $disp } else { ("$first $last").Trim() })
        UserPrincipalName = $upn; UserName = ($upn -split '@')[0]
        UserType = $(if ((& $g 'userType') -ieq 'Guest') { 'External' } else { 'Internal' })
        AccountStatus = $(if ($enabled) { 'Enabled' } else { 'Disabled' })
        Department = (& $g 'department'); Company = (& $g 'companyName'); UsageLocation = (& $g 'usageLocation')
        Purpose = 'Imported from the tenant (was not managed by PIM)'
    }
}

function Get-PimAdminImportMemberships {
    <#
      PURE. From a stored drift document (pim.TenantCache 'drift'), the PIM-Assignments-Admins rows that would KEEP the
      admin's live memberships -- the EXTRA items whose keep row names this admin (Username = the UPN, case-insensitive).
      Returns @(rows), each with Action=Assign added.
    #>
    param([AllowNull()][object]$DriftDoc, [Parameter(Mandatory)][string]$Upn)
    $u = $Upn.Trim().ToLowerInvariant(); $out = New-Object System.Collections.Generic.List[object]; $seen = @{}
    foreach ($s in @($DriftDoc.scopes)) {
        foreach ($it in @($s.items)) {
            if ("$($it.type)" -ne 'extra' -or -not $it.keep -or "$($it.keep.base)" -ne 'PIM-Assignments-Admins') { continue }
            $row = $it.keep.row; if ("$($row.Username)".Trim().ToLowerInvariant() -ne $u) { continue }
            $k = ("$($row.Username)|$($row.GroupTag)|$($row.AssignmentType)").ToLowerInvariant(); if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
            $o = [ordered]@{}; foreach ($p in $row.PSObject.Properties) { $o[$p.Name] = "$($p.Value)" }; if (-not $o.Contains('Action')) { $o['Action'] = 'Assign' }
            $out.Add([pscustomobject]$o)
        }
    }
    return @($out.ToArray())
}
