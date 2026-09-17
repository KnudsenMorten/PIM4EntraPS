# ---------------------------------------------------------------------------
# IMP-02 -- ONE locale-safe way to read a UTC timestamp this product wrote.
#
# §22 requires "locale-safe date parsing (US dates on da-DK)", and Ensure-DateTime
# (PIM-Functions.psm1) implements it properly for USER-SUPPLIED dates. But 26 sites
# read MACHINE-written stamps with a bare [datetime]::TryParse / ::Parse, which uses
# the AMBIENT culture. Every one of those stamps is written with ToString('o'), so
# the correct reading is INVARIANT -- a da-DK host could otherwise fail to read a
# stamp it had written itself. BUG-02 was exactly that class: a lease whose expiry
# could not be parsed was treated as free, letting two schedulers run at once.
#
# Two rules this helper exists to enforce:
#   1. Parse INVARIANTLY first (these are 'o'/ISO-8601 round-trip stamps).
#   2. NEVER throw. PIM-CommitBackup used unguarded [datetime]::Parse inside the
#      commit-backup path, so a malformed stamp threw instead of degrading.
#
# Returns a UTC [datetime], or $null when the value cannot be understood. Callers
# decide what "cannot be understood" means for them -- and must choose the SAFE
# direction explicitly rather than inheriting whatever a failed parse left behind.
# ---------------------------------------------------------------------------

function Get-PimUtcStamp {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        $s = "$Value".Trim()
        if (-not $s) { return $null }
        $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        $d = [datetime]::MinValue
        # 1. invariant -- what ToString('o') produces, and what almost every stamp is
        if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
        # 2. current culture -- a value typed by an operator in their own locale
        if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::CurrentCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
        # 3. the project's full locale-safe ladder, when the big module is loaded
        if (Get-Command Ensure-DateTime -ErrorAction SilentlyContinue) {
            try { $alt = Ensure-DateTime $s; if ($alt -is [datetime]) { return $alt.ToUniversalTime() } } catch { }
        }
        return $null
    }
}

# ===========================================================================
# 🔴 71.23 -- AutoDisableDate: the ONE date column that disables an admin account.
#
# Operator, 2026-09-16: "flow 2 i need to have this field on the admin overview so i cna
# devine an AutoDisableDate (instead of OffboardDate). As we will not offboard but disable
# only for now. maybe i will add delete, but i dont feel comfortable with that for now".
#
# `OffboardDate` was the wrong name for what the column does now. "Offboard" reads as "remove
# the person", and the sweep behind it used to end in a DELETE. It no longer does (71.21): the
# sweep disables the account, revokes its sessions, removes its memberships and eligibilities,
# mails the notice -- and STOPS. `AutoDisableDate` says exactly that.
#
# MIGRATION -- how an existing row moves, and what is never guessed:
#   * READ: this resolver accepts BOTH names, so every row that exists today keeps working
#     with no migration step at all. AutoDisableDate wins when only it is set; OffboardDate
#     is read as legacy when only IT is set (and says so, so the surface can nudge a rename).
#   * STORE: the schema preflight (PIM-SchemaConformance.ps1) adds AutoDisableDate, copies
#     OffboardDate into it when AutoDisableDate is blank, and then drops OffboardDate. One
#     idempotent pass migrates a whole store, and afterwards the both-set state cannot arise
#     from the store at all.
#   * BOTH SET AND DIFFERENT -> REFUSED, never guessed. A row that says two different things
#     about when an account gets disabled is a data error, and picking one of them silently is
#     how an account gets disabled on a date nobody chose. The row is skipped by the sweep and
#     reported (validator PIM-OFF-002, engine warning), naming the admin and both values.
#     Both set to the SAME value is not a conflict -- there is nothing to guess.
#
# Returns @{ value; source ('auto'|'legacy'|'none'); legacy; conflict; reason }.
function Get-PimAdminAutoDisableDate {
    [CmdletBinding()] param([AllowNull()][object]$Row)
    # 🪤 `raw` is the UNTOUCHED cell value, and it matters. pwsh 7's ConvertFrom-Json hands a date
    # over as a [datetime], and "$dt" renders it in the HOST's culture -- so a resolver that only
    # returned a string would silently turn an ISO-8601 stamp into '01-10-2026 08:00:00' on a
    # Danish box the moment it passed through here. Callers that WRITE the value on (the downlink
    # bundle) must use .raw; callers that compare or parse it use .value.
    $get = {
        param($name)
        if ($null -eq $Row) { return $null }
        if ($Row -is [System.Collections.IDictionary]) {
            foreach ($k in @($Row.Keys)) { if ("$k" -ieq $name) { return $Row[$k] } }
            return $null
        }
        $p = $Row.PSObject.Properties | Where-Object { "$($_.Name)" -ieq $name } | Select-Object -First 1
        if ($p) { return $p.Value }
        return $null
    }
    $newRaw = & $get 'AutoDisableDate'
    $oldRaw = & $get 'OffboardDate'
    $new = "$newRaw".Trim()
    $old = "$oldRaw".Trim()
    if ($new -and $old -and ($new -ne $old)) {
        return [pscustomobject]@{
            value = ''; raw = ''; source = 'none'; legacy = $true; conflict = $true
            reason = "this row carries BOTH AutoDisableDate '$new' AND the legacy OffboardDate '$old', and they disagree. PIM will not guess which date disables the account: clear OffboardDate (AutoDisableDate is the column now), then re-run."
        }
    }
    if ($new) { return [pscustomobject]@{ value = $new; raw = $newRaw; source = 'auto'; legacy = [bool]$old; conflict = $false; reason = '' } }
    if ($old) {
        return [pscustomobject]@{
            value = $old; raw = $oldRaw; source = 'legacy'; legacy = $true; conflict = $false
            reason = "read from the legacy column OffboardDate. Rename it to AutoDisableDate -- the sweep only disables the account (PIM never deletes an account)."
        }
    }
    return [pscustomobject]@{ value = ''; raw = ''; source = 'none'; legacy = $false; conflict = $false; reason = '' }
}
