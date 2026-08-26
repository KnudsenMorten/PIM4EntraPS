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
