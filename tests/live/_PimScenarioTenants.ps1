#Requires -Version 5.1
<#
  BUG-26 -- the -TenantJson parse contract, in one dot-sourceable place (REQUIREMENTS §33.8).

  WHY THIS FILE EXISTS. Both scenario scripts used to parse the tenant file inline, as:

      foreach ($t in @(Get-Content -LiteralPath $TenantJson -Raw | ConvertFrom-Json)) { ... }

  In Windows PowerShell 5.1 `ConvertFrom-Json` emits a JSON array as ONE object, so
  `@(pipeline)` yields a 1-element array whose single element is the whole [Object[]].
  In PowerShell 7 `ConvertFrom-Json` enumerates by default, so the identical line yields 2.
  Measured on the real 2-tenant file: PS 5.1 -> 1 iteration, PS 7 -> 2 iterations.

  That made Clear-PimScenarioEstate.ps1 fail OPEN: it built one bogus tenant whose tenantId
  was both real ids joined by a space, could not authenticate to it, WARNed, swept NOTHING,
  and printed "WHAT-IF: 0 object(s)/row(s) would be removed" -- indistinguishable from a
  genuinely clean estate. Both scripts declare #Requires -Version 5.1, a compatibility they
  did not actually have on this path.

  THE RULE: assign FIRST, then wrap the VARIABLE -- `@($var)` on an existing [Object[]] is a
  correct no-op in BOTH shells. (Same family as the recorded "@() must wrap the whole
  pipeline" trap, but the opposite direction.)

  Isolated from I/O below the file read so it can be unit-tested offline
  (tests/Test-PimScenarioCleanup.ps1) under BOTH shells -- a PS 7-only test would not have
  caught the original defect. Dot-sourcing has NO side effects.
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# RETIRED TENANTS -- refuse them in code, not in a human's memory.
# Operator 2026-08-08: "Stop using my two old test tenants -- use only the new ones."
# Framework DOCS/REQUIREMENTS.md s10.0 carries the rule and the tenant ids.
#
# WHY THIS IS A GUARD AND NOT A NOTE: the exclusion lived only in an external brief and
# the estate workbook, neither of which is in the repository, so every doc a session
# actually reads still pointed here -- and the live scenario matrix was run against BOTH
# retired tenants, twice, on 2026-08-08. A rule that depends on someone having read a
# file outside the repo is not a rule. This is the same shape as the PIM_TestTenantIds
# allowlist Test-PimFunctionalMatrix.ps1 already enforces.
#
# Escape hatch is deliberate and NOISY: $env:PIM_AllowRetiredTenants='1'. There is no
# silent bypass, because the failure this prevents (writing to a retired tenant) looks
# exactly like a successful run.
# ---------------------------------------------------------------------------
$script:PimRetiredTenantIds = @{
    '4ff34194-fb38-4949-8e2a-58dac8f096c2' = '2linkit (old test tenant -- RETIRED)'
    '9927fa1f-a09b-4244-8aba-60fb9ce7335e' = 'managedoperation (old test tenant -- RETIRED)'
}

function Assert-PimScenarioTenantAllowed {
    <#
      Throw if a tenant id is one of the retired estate tenants. Call this from ANY live
      script before it authenticates or writes. Accepts empty/absent input as "nothing to
      check" so it can be called unconditionally.
    #>
    [CmdletBinding()]
    param([string]$TenantId, [string]$What = 'tenant')

    $tid = "$TenantId".Trim()
    if (-not $tid) { return }
    if (-not $script:PimRetiredTenantIds.ContainsKey($tid.ToLowerInvariant())) { return }
    if ("$env:PIM_AllowRetiredTenants" -eq '1') {
        Write-Warning "  [estate] RETIRED tenant $tid ($($script:PimRetiredTenantIds[$tid.ToLowerInvariant()])) allowed ONLY because PIM_AllowRetiredTenants=1."
        return
    }
    throw ("REFUSING $What '$tid' -- $($script:PimRetiredTenantIds[$tid.ToLowerInvariant()]). " +
           'The two old test tenants are retired; the live estate is environments 4-31 (the 28 new ' +
           'test1*/test2* tenants). See DOCS/REQUIREMENTS.md s10.0. ' +
           "Set PIM_AllowRetiredTenants=1 only if you deliberately intend to touch a retired tenant.")
}

function ConvertFrom-PimScenarioTenantJson {
    <#
      Parse the -TenantJson TEXT into a tenant array. Takes text, not a path, so the offline
      test needs no fixture file on disk.

      Every entry is VALIDATED, because the collapse this function exists to prevent is
      silent by nature: the 5.1 shape produced a tenantId of "<guid> <guid>", which is not a
      GUID and could never authenticate. A shape check turns any future recurrence -- here or
      in a hand-edited file -- into a loud throw at parse time instead of a sweep that looks
      clean because it looked at nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json, [string]$Source = '<text>')

    if (-not "$Json".Trim()) { throw "TenantJson is empty: $Source" }

    # ASSIGN first. Never `@(... | ConvertFrom-Json)` -- see the header.
    $parsed = $Json | ConvertFrom-Json
    $entries = @($parsed)

    if (-not $entries.Count) { throw "TenantJson contained no tenants: $Source" }

    $out = @()
    $i = 0
    foreach ($t in $entries) {
        $i++
        # The collapse signature: one entry that is itself a collection. Caught explicitly so
        # the failure names its own cause instead of surfacing as a GUID complaint.
        if ($t -is [System.Collections.IEnumerable] -and $t -isnot [string] -and $t -isnot [System.Collections.IDictionary] -and $t -isnot [psobject]) {
            throw ("TenantJson entry $i in $Source parsed as a COLLECTION, not a tenant object. " +
                   'That is the ConvertFrom-Json 5.1 array collapse (BUG-26) -- assign the ' +
                   'ConvertFrom-Json result to a variable BEFORE wrapping it in @().')
        }
        $tid = "$($t.tenantId)".Trim()
        $name = "$($t.name)".Trim()
        if (-not $name) { $name = "tenant$i" }
        if (-not $tid) { throw "TenantJson entry $i ('$name') in $Source has no tenantId." }
        if ($tid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            throw ("TenantJson entry $i ('$name') in $Source has a tenantId that is not a GUID: '$tid'. " +
                   'Two ids joined by a space is the BUG-26 array-collapse signature.')
        }
        # Refuse a retired tenant at PARSE time -- before any caller authenticates to it.
        Assert-PimScenarioTenantAllowed -TenantId $tid -What "TenantJson entry $i ('$name')"
        $out += @{
            name           = $name
            tenantId       = $tid
            clientId       = "$($t.clientId)"
            certThumbprint = "$($t.certThumbprint)"
            subscriptionId = "$($t.subscriptionId)"
        }
    }
    # RETURN FORM -- measured, not assumed, and it caught a real defect during this fix.
    # The obvious "guarantee an array" idiom `return ,$out` REINTRODUCES the exact collapse
    # this file exists to prevent, one layer up. Measured identically on 5.1 AND 7 (so this
    # half is plain PowerShell semantics, not a shell difference):
    #
    #     return ,$out  ->  @(F)                = 1   <-- COLLAPSED
    #                       $x = F; @($x)       = 2
    #     return  $out  ->  @(F)                = 2
    #                       $x = F; @($x)       = 2
    #
    # Emit PLAIN, and every caller wraps in @() -- which is this codebase's convention
    # anyway. The one style plain does not survive is a bare `$x = F` on a SINGLE tenant
    # ($x becomes a scalar Hashtable, whose .Count silently reports the KEY count, 5).
    # No caller does that, and Test-PimScenarioCleanup.ps1 pins both supported styles.
    return $out
}

function Import-PimScenarioTenantJson {
    # Path wrapper. The live scripts call this; the offline test calls the text function.
    # Same plain-return rule as above -- callers MUST wrap in @().
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "TenantJson not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw
    return (ConvertFrom-PimScenarioTenantJson -Json $raw -Source $Path)
}
