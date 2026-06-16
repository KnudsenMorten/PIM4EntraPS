#Requires -Version 5.1
# PIM-WarningOverrides.ps1 -- validator warning override / acknowledgement
# POST-FILTER (REQUIREMENTS §11 "Warning override/acknowledge").
#
# WHY this is a post-filter and not a validator-core change:
#   The validator (tools/pim-manager/_validator.ps1) produces the AUTHORITATIVE
#   finding set. The operator has hundreds of legitimate-but-noisy WARNINGs
#   (e.g. the multi-path PIM-DUP-001 "admin reaches target via 2 role-group
#   paths", or PIM-ORPHAN-001) that are CORRECT findings they want to suppress
#   knowingly. We never rewrite the rule that emits them; we run ONE post-filter
#   over the produced set that DOWNGRADES matched findings to severity
#   'acknowledged' (kept + annotated, NOT dropped -- fully auditable).
#
# Dot-sourced by _validator.ps1 (mirrors the PIM-DateExpression.ps1 pattern) so
# the single hook in the validator is one call before its return.
#
# Pure, PS 5.1-safe, no module deps. ConvertFrom-Json is the only IO.
#
# ---------------------------------------------------------------------------
# OVERRIDE CONFIG CONTRACT  (a future GUI "Overrule" button writes this shape)
# ---------------------------------------------------------------------------
# Customer-specific, gitignored (config/*.custom.json) -- ships only a .sample.
# File: config/PIM-WarningOverrides.custom.json
#
#   {
#     "overrides": [
#       {
#         "code":      "PIM-DUP-001",                 // REQUIRED  stable rule code
#         "scope":     {                              // OPTIONAL  omit/null = ALL findings of this code
#           "subject": "Admin-PAW-ID@contoso.com",    //   exact admin/UPN/object  (case-insensitive)
#           "target":  "entra:application developer", //   exact target/scope key   (case-insensitive)
#           "csv":     "PIM-Assignments-Admins",      //   exact CSV base name
#           "row":     12                             //   0-based row index
#         },
#         "pattern":   "Admin-PAW-*@contoso.com",     // OPTIONAL  wildcard over subject|target|message (any-of)
#         "reason":    "PAW admin intentionally bundled + role group",  // REQUIRED (mandatory)
#         "createdBy": "mok@contoso.com",             // OPTIONAL  audit trail
#         "expiresOn": "2026-12-31",                  // REQUIRED unless noExpiry:true (exemptions model)
#         "noExpiry":  false                          // OPTIONAL  explicit indefinite opt-out of expiry
#       }
#     ]
#   }
#
# Rules enforced (mirrors the TenantManager/exemptions "never indefinite by
# default" model):
#   * code      -- MANDATORY. An entry without it is ignored (and reported).
#   * reason    -- MANDATORY. An entry without it is ignored (and reported).
#   * expiresOn -- MANDATORY *unless* noExpiry:true. An entry that is neither
#                  dated nor explicitly flagged no-expiry is ignored (so an
#                  override can never silently live forever by omission).
#   * An override whose expiresOn is in the PAST does NOT suppress -- the
#     finding RESURFACES as an active warning, and we count it as expired.
#   * scope    -- OPTIONAL. When present, ALL provided keys must match (AND).
#                 When absent, the override applies to every finding of `code`.
#   * pattern  -- OPTIONAL. A wildcard (-like) tested against the finding's
#                 Subject, Target and Message (any match wins). Combined with
#                 scope by AND when both are present.
#
# A finding carries the per-instance key  code + Subject + Target  (plus the
# Csv/Row/Column structural anchor). The validator stamps Subject/Target on the
# findings the operator overrules most (PIM-DUP-001, PIM-ORPHAN-001); other
# rules fall back to the Csv/Row anchor for scoping.

Set-StrictMode -Off

function Resolve-PimWarningOverridesPath {
    <#
      Resolve the override config file for an instance. CSV-mode lives next to
      the other config/*.custom.json. SQL mode has no config dir of customer
      data -- callers may pass an explicit -Path (e.g. read from pim.Settings).
    #>
    [CmdletBinding()]
    param([string]$ConfigRoot)
    if (-not $ConfigRoot) { return $null }
    return (Join-Path $ConfigRoot 'PIM-WarningOverrides.custom.json')
}

function Read-PimWarningOverrideConfig {
    <#
      Read + parse the override config. Returns an array of normalized override
      hashtables. Missing file / parse error -> empty array (never throws --
      a bad override file must never break the validator).
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [object]$Config   # already-parsed object (SQL/store path) -- wins over $Path
    )
    $raw = $null
    if ($Config) {
        $raw = $Config
    } elseif ($Path -and (Test-Path -LiteralPath $Path)) {
        try {
            $text = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
            if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
            $raw = $text | ConvertFrom-Json
        } catch { return @() }
    }
    if (-not $raw) { return @() }

    # Tolerant field reader -- works for both PSCustomObject (ConvertFrom-Json)
    # and IDictionary/hashtable (store / test path).
    function _ovrField([object]$obj, [string]$name) {
        if ($null -eq $obj) { return $null }
        if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.Contains($name)) { return $obj[$name] }
            return $null
        }
        $p = $obj.PSObject.Properties[$name]
        if ($p) { return $p.Value }
        return $null
    }

    $list = $null
    $ovr = _ovrField $raw 'overrides'
    if ($null -ne $ovr) { $list = $ovr }
    elseif ($raw -is [System.Collections.IDictionary]) { $list = @($raw) }
    elseif ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) { $list = $raw }
    else { $list = @($raw) }

    $out = New-Object System.Collections.ArrayList
    foreach ($o in @($list)) {
        if (-not $o) { continue }
        $entry = [ordered]@{
            code      = "$(_ovrField $o 'code')".Trim()
            reason    = "$(_ovrField $o 'reason')".Trim()
            createdBy = "$(_ovrField $o 'createdBy')".Trim()
            expiresOn = "$(_ovrField $o 'expiresOn')".Trim()
            noExpiry  = [bool](_ovrField $o 'noExpiry')
            pattern   = "$(_ovrField $o 'pattern')".Trim()
            scope     = $null
        }
        $sc = _ovrField $o 'scope'
        if ($sc) {
            $scRow = _ovrField $sc 'row'
            $entry.scope = [ordered]@{
                subject = "$(_ovrField $sc 'subject')".Trim()
                target  = "$(_ovrField $sc 'target')".Trim()
                csv     = "$(_ovrField $sc 'csv')".Trim()
                row     = $(if ($null -ne $scRow -and "$scRow" -ne '') { [int]$scRow } else { $null })
            }
        }
        [void]$out.Add($entry)
    }
    return @($out.ToArray())
}

function Test-PimWarningOverrideValid {
    <#
      Validate an override entry against the contract. Returns a result object
      { Valid; Reason }. Enforces mandatory code + reason + (expiresOn OR
      noExpiry). Does NOT judge expiry here (that is a separate, time-based
      decision so an expired-but-well-formed override still counts as 'expired'
      rather than 'invalid').
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Override)
    if (-not $Override.code)   { return [pscustomobject]@{ Valid = $false; Reason = 'missing mandatory code' } }
    if (-not $Override.reason) { return [pscustomobject]@{ Valid = $false; Reason = 'missing mandatory reason' } }
    if (-not $Override.noExpiry -and -not $Override.expiresOn) {
        return [pscustomobject]@{ Valid = $false; Reason = 'missing mandatory expiresOn (and noExpiry is not set)' }
    }
    return [pscustomobject]@{ Valid = $true; Reason = $null }
}

function Test-PimWarningOverrideExpired {
    <#
      Is the override expired as of $AsOf (UTC default now)? noExpiry never
      expires. An unparseable date is treated as expired (fail-safe: a typo'd
      date must not grant indefinite suppression).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Override,
        [datetime]$AsOf = ([datetime]::UtcNow)
    )
    if ($Override.noExpiry) { return $false }
    if (-not $Override.expiresOn) { return $true }
    $exp = [datetime]::MinValue
    if (-not [datetime]::TryParse($Override.expiresOn, [ref]$exp)) { return $true }
    # expiresOn is an inclusive end-of-day boundary; suppress THROUGH that date.
    $expEnd = $exp.Date.AddDays(1).AddTicks(-1)
    return ($AsOf.ToUniversalTime() -gt $expEnd.ToUniversalTime())
}

function Get-PimFindingSubject {
    param([Parameter(Mandatory)][object]$Finding)
    $p = $Finding.PSObject.Properties['Subject']
    if ($p -and $p.Value) { return "$($p.Value)" }
    return ''
}
function Get-PimFindingTarget {
    param([Parameter(Mandatory)][object]$Finding)
    $p = $Finding.PSObject.Properties['Target']
    if ($p -and $p.Value) { return "$($p.Value)" }
    return ''
}

function Test-PimWarningOverrideMatches {
    <#
      Does this override match this finding? code must match (case-insensitive).
      If scope present, every supplied scope key must match (AND). If pattern
      present, it must -like Subject|Target|Message (any-of). scope AND pattern
      are ANDed when both present. No scope + no pattern = matches every finding
      of that code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Override,
        [Parameter(Mandatory)][object]$Finding
    )
    if (-not $Override.code) { return $false }
    if ("$($Finding.Code)" -ine "$($Override.code)") { return $false }

    $subject = Get-PimFindingSubject -Finding $Finding
    $target  = Get-PimFindingTarget  -Finding $Finding
    $message = "$($Finding.Message)"
    $csv     = "$($Finding.Csv)"
    $row     = $Finding.Row

    if ($Override.scope) {
        $s = $Override.scope
        if ($s.subject -and ($s.subject -ine $subject)) { return $false }
        if ($s.target  -and ($s.target  -ine $target))  { return $false }
        if ($s.csv     -and ($s.csv     -ine $csv))      { return $false }
        if ($null -ne $s.row) {
            if ($null -eq $row -or [int]$row -ne [int]$s.row) { return $false }
        }
    }
    if ($Override.pattern) {
        $hit = ($subject -like $Override.pattern) -or
               ($target  -like $Override.pattern) -or
               ($message -like $Override.pattern)
        if (-not $hit) { return $false }
    }
    return $true
}

function Apply-PimWarningOverrides {
    <#
    .SYNOPSIS
        POST-FILTER the validator's findings against an override config:
        matched findings are DOWNGRADED to severity 'acknowledged' (kept +
        annotated), never dropped. Expired overrides do not suppress -- the
        finding stays active and is counted as 'expired -> active'.

    .PARAMETER Findings
        The validator's produced finding objects (PSCustomObjects with at least
        Severity/Code/Csv/Row/Column/Message).

    .PARAMETER Path
        Path to the override config JSON (CSV mode). Optional.

    .PARAMETER Config
        Already-parsed override config object (SQL/store mode). Wins over -Path.

    .PARAMETER AsOf
        Evaluation time (UTC). Default = now. (Test seam for expiry.)

    .OUTPUTS
        @{
          findings        = <same findings, matched ones downgraded + annotated>
          acknowledged    = <count downgraded>
          expiredToActive = <count of would-suppress-but-expired>
          invalidOverrides= @( @{ code; reason } ... )   # malformed entries (ignored)
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [string]$Path,
        [object]$Config,
        [datetime]$AsOf = ([datetime]::UtcNow)
    )

    $overrides = Read-PimWarningOverrideConfig -Path $Path -Config $Config
    $invalid = New-Object System.Collections.ArrayList

    # Partition into usable (valid) overrides + a parallel "expired" list so an
    # expired-but-well-formed override can flip a finding back to active.
    $active  = New-Object System.Collections.ArrayList   # valid + not-expired -> suppress
    $expired = New-Object System.Collections.ArrayList   # valid + expired     -> resurface
    foreach ($o in $overrides) {
        $v = Test-PimWarningOverrideValid -Override $o
        if (-not $v.Valid) {
            [void]$invalid.Add([ordered]@{ code = $o.code; reason = $v.Reason })
            continue
        }
        if (Test-PimWarningOverrideExpired -Override $o -AsOf $AsOf) { [void]$expired.Add($o) }
        else { [void]$active.Add($o) }
    }

    $ackCount = 0
    $expiredToActive = 0
    $out = New-Object System.Collections.ArrayList
    foreach ($f in $Findings) {
        # Only WARNINGs (and infos) are acknowledgeable; errors are hard gates
        # and must never be silenced by an override.
        if ("$($f.Severity)" -ieq 'error') { [void]$out.Add($f); continue }

        $matchedActive  = $null
        foreach ($o in $active)  { if (Test-PimWarningOverrideMatches -Override $o -Finding $f) { $matchedActive = $o; break } }

        if ($matchedActive) {
            # Downgrade to acknowledged, keep the row, annotate for audit.
            $clone = $f.PSObject.Copy()
            $orig  = "$($f.Severity)"
            Add-Member -InputObject $clone -NotePropertyName 'OriginalSeverity' -NotePropertyValue $orig -Force
            $clone.Severity = 'acknowledged'
            Add-Member -InputObject $clone -NotePropertyName 'Acknowledged' -NotePropertyValue $true -Force
            Add-Member -InputObject $clone -NotePropertyName 'AckReason'    -NotePropertyValue $matchedActive.reason -Force
            Add-Member -InputObject $clone -NotePropertyName 'AckBy'        -NotePropertyValue $matchedActive.createdBy -Force
            Add-Member -InputObject $clone -NotePropertyName 'AckExpiresOn' -NotePropertyValue $(if ($matchedActive.noExpiry) { '' } else { $matchedActive.expiresOn }) -Force
            [void]$out.Add($clone)
            $ackCount++
            continue
        }

        # No active override. Was there an EXPIRED one that WOULD have matched?
        # Then the finding resurfaces as active and we count it.
        $matchedExpired = $null
        foreach ($o in $expired) { if (Test-PimWarningOverrideMatches -Override $o -Finding $f) { $matchedExpired = $o; break } }
        if ($matchedExpired) {
            $clone = $f.PSObject.Copy()
            Add-Member -InputObject $clone -NotePropertyName 'AckExpired' -NotePropertyValue $true -Force
            Add-Member -InputObject $clone -NotePropertyName 'AckExpiredOn' -NotePropertyValue $matchedExpired.expiresOn -Force
            [void]$out.Add($clone)
            $expiredToActive++
            continue
        }

        [void]$out.Add($f)
    }

    return [ordered]@{
        findings         = @($out.ToArray())
        acknowledged     = $ackCount
        expiredToActive  = $expiredToActive
        invalidOverrides = @($invalid.ToArray())
    }
}
