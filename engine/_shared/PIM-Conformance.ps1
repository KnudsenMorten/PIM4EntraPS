# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
# PIM4EntraPS -- native template versioning + fleet conformance.
# Dot-sourced by PIM-Functions.psm1 (and standalone by the pim-manager).
#
# Same model as the TenantManager conformance engine, applied to PIM WORKLOAD
# templates (a versioned set of PIM-group -> workload-role bindings):
#   - Rings drive rollout (tenantRing <= entryRing, §77.20); templateVersion is a
#     changelog label, not the rollout control.
#   - Only status:"approved" templates are pullable/deployable; drafts never go.
#   - Absent desired binding = GAP unless an ACTIVE exemption -> EXEMPT.
#   - Exemptions ALWAYS require an expiry; expired -> lapses back to Gap.
#   - Applied version stays LOCAL (light state stamp).
#
# Pure reconcile core (time injected) + thin I/O wrappers, so every status
# decision is testable without a tenant. A roll-forward-ROWS seam converts an
# approved template into PIM-Assignments-Workloads DESIRED-STATE rows; the Manager
# commits them through its normal safe-commit path and the ENGINE's workload
# provider applies them (IMP-37: the v1 Apply-PimWorkloadAssignments + CSV path is gone).
# The shipped *.template.json files are read-only; approvals and ring promotions live
# in SQL (pim.Settings 'ConformanceTemplateOverlay', see Read-PimApprovedTemplates).

Set-StrictMode -Off

function Set-PimConfProp {
    param([Parameter(Mandatory)][object]$Object, [Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Value)
    if ($Object.PSObject.Properties[$Name]) { $Object.$Name = $Value }
    else { Add-Member -InputObject $Object -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

function Copy-PimConfObject {
    param([Parameter(Mandatory)][object]$Object)
    return ($Object | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

# --- template doc validation + approval gate (PURE) ------------------------------
function Test-PimTemplateDoc {
    param([AllowNull()][object]$Template)
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Template) { return @{ valid = $false; errors = @('template is null') } }
    if (-not "$($Template.templateId)".Trim()) { $errors.Add('templateId is required') }
    if (-not "$($Template.workload)".Trim())   { $errors.Add('workload is required') }
    $tv = 0
    if (-not [int]::TryParse("$($Template.templateVersion)", [ref]$tv) -or $tv -lt 1) { $errors.Add('templateVersion must be an integer >= 1') }
    $status = "$($Template.status)".ToLowerInvariant()
    if ($status -notin 'draft','approved') { $errors.Add("status must be 'draft' or 'approved' (got '$($Template.status)')") }
    $entries = @($Template.entries)
    if ($entries.Count -eq 0) { $errors.Add('template has no entries') }
    $seen = @{}
    foreach ($e in $entries) {
        $k = "$($e.key)".Trim()
        if (-not $k) { $errors.Add('an entry has no key'); continue }
        if ($seen.ContainsKey($k.ToLowerInvariant())) { $errors.Add("duplicate entry key '$k'") }
        $seen[$k.ToLowerInvariant()] = $true
        $sv = 0
        if (-not [int]::TryParse("$($e.sinceVersion)", [ref]$sv) -or $sv -lt 1) { $errors.Add("entry '$k' sinceVersion must be an integer >= 1") }
        if (-not "$($e.roleName)".Trim() -and -not ($e.value -and "$($e.value.roleName)".Trim())) { $errors.Add("entry '$k' needs a roleName") }
        if (-not "$($e.groupTag)".Trim() -and -not ($e.value -and "$($e.value.groupTag)".Trim())) { $errors.Add("entry '$k' needs a groupTag") }
    }
    return @{ valid = ($errors.Count -eq 0); errors = $errors.ToArray() }
}

function Test-PimTemplateApproved {
    param([AllowNull()][object]$Template)
    if ($null -eq $Template) { return $false }
    return ("$($Template.status)".ToLowerInvariant() -eq 'approved')
}

# --- source read (the pull gate) ------------------------------------------------
function Get-PimTemplateSource {
    param([ValidateSet('local','github','courier')][string]$Mode = 'local', [string]$Location)
    return @{ kind = $Mode; location = $Location }
}

function ConvertTo-PimTemplate {
    param([Parameter(Mandatory)][string]$Json)
    $raw = $Json
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    return ($raw | ConvertFrom-Json)
}

# --- the SQL OVERLAY over the shipped templates (BUG-180 / IMP-37, §33.28) -------------
# The shipped workloads/templates/*.template.json files are the READ-ONLY catalog: they ship with the
# image, are replaced by every update and are never written at runtime (they used to be -- approve and
# promote rewrote them, on an ephemeral container filesystem, against the SQL-only rule). Everything an
# operator DECIDES about a template lives in ONE pim.Settings document instead:
#   pim.Settings['ConformanceTemplateOverlay'] =
#     { "<templateId>": { "approval": { templateVersion; approvedBy; approvedUtc },
#                         "rings":    { "<entryKey>": <int 0..9> } } }
# Read-PimApprovedTemplates merges it over each file (Merge-PimTemplateOverlay), so the engine-facing
# view, the Manager and the fleet matrix all see the same decision.
#   * an approval is VERSION-BOUND: it approves exactly the templateVersion that was reviewed, so a new
#     shipped version of a template is a draft again until someone approves THAT;
#   * a ring override applies to an entry that still exists; an unknown key is ignored (a removed entry).
$script:PimTemplateOverlayMem = $null
function Get-PimTemplateOverlayStoreName { 'ConformanceTemplateOverlay' }

function Get-PimTemplateOverlay {
    # The whole overlay document as a PSCustomObject; absent -> empty. Never throws on read errors of the
    # SHAPE, but a store that cannot be read at all THROWS (an unreadable overlay must not silently turn
    # every approved template back into a draft, or vice versa).
    [CmdletBinding()] param()
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        return (ConvertTo-PimTemplateStateDocument (Get-PimSetting -Name (Get-PimTemplateOverlayStoreName)))
    }
    if ($null -ne $script:PimTemplateOverlayMem) { return (ConvertTo-PimTemplateStateDocument $script:PimTemplateOverlayMem) }
    return [pscustomobject]@{}
}

function Save-PimTemplateOverlay {
    # Persist the whole overlay. Returns 'sql' or 'memory' (offline only, and it says so). A store that
    # rejects the write THROWS.
    param([Parameter(Mandatory)][object]$Overlay)
    $json = $Overlay | ConvertTo-Json -Depth 10 -Compress
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        Set-PimSetting -Name (Get-PimTemplateOverlayStoreName) -Value $json | Out-Null
        return 'sql'
    }
    $script:PimTemplateOverlayMem = $json
    Write-Warning "  [conformance] template overlay kept in this process only -- no SQL settings store (Set-PimSetting) is wired (PIM v2 is SQL-only)."
    return 'memory'
}

function Merge-PimTemplateOverlay {
    # PURE. A shipped template + the overlay -> the effective template (a COPY; the input is untouched).
    param([Parameter(Mandatory)][object]$Template, [AllowNull()][object]$Overlay)
    $t = Copy-PimConfObject -Object $Template
    if ($null -eq $Overlay) { return $t }
    $id = "$($t.templateId)"
    $entry = $null
    if ($Overlay.PSObject -and $Overlay.PSObject.Properties[$id]) { $entry = $Overlay.PSObject.Properties[$id].Value }
    if ($null -eq $entry) { return $t }
    $appr = $null
    if ($entry.PSObject.Properties['approval']) { $appr = $entry.approval }
    if ($appr -and "$($appr.templateVersion)" -eq "$($t.templateVersion)") {
        Set-PimConfProp -Object $t -Name 'status' -Value 'approved'
        Set-PimConfProp -Object $t -Name 'approvedBy' -Value "$($appr.approvedBy)"
        Set-PimConfProp -Object $t -Name 'approvedUtc' -Value "$($appr.approvedUtc)"
        Set-PimConfProp -Object $t -Name 'approvalSource' -Value 'sql'
    }
    if ($entry.PSObject.Properties['rings'] -and $entry.rings) {
        foreach ($p in @($entry.rings.PSObject.Properties)) {
            $r = 0
            if (-not [int]::TryParse("$($p.Value)", [ref]$r) -or $r -lt 0 -or $r -gt 2) { continue }   # 77.20: rings are 0..2
            foreach ($e in @($t.entries)) { if ("$($e.key)" -ieq "$($p.Name)") { Set-PimConfProp -Object $e -Name 'ring' -Value $r } }
        }
    }
    return $t
}

function Set-PimTemplateOverlayApproval {
    # Record an approval of THIS template version in SQL. $ApprovedBy is the authenticated caller -- never
    # a value from a request body. Returns the effective (merged) template.
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$ApprovedBy, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not "$ApprovedBy".Trim()) { throw 'Set-PimTemplateOverlayApproval: ApprovedBy (the authenticated identity) is required.' }
    $chk = Test-PimTemplateDoc -Template $Template
    if (-not $chk.valid) { throw ("template '{0}' is invalid and cannot be approved: {1}" -f $Template.templateId, ($chk.errors -join '; ')) }
    $ov = Get-PimTemplateOverlay
    $id = "$($Template.templateId)"
    if (-not $ov.PSObject.Properties[$id]) { Set-PimConfProp -Object $ov -Name $id -Value ([pscustomobject]@{}) }
    $node = $ov.PSObject.Properties[$id].Value
    Set-PimConfProp -Object $node -Name 'approval' -Value ([pscustomobject]@{
        templateVersion = [int]("$($Template.templateVersion)" -as [int]); approvedBy = "$ApprovedBy"; approvedUtc = $NowUtc.ToString('o') })
    [void](Save-PimTemplateOverlay -Overlay $ov)
    return (Merge-PimTemplateOverlay -Template $Template -Overlay $ov)
}

function Set-PimTemplateOverlayRing {
    # Record a per-entry ring promotion in SQL. Throws when the template has no such entry (same message as
    # Set-PimEntryRing, so the endpoint's 400 stays). Returns the effective (merged) template.
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateRange(0,2)][int]$Ring)
    if (-not (@($Template.entries) | Where-Object { "$($_.key)" -ieq "$Key" })) {
        throw "Set-PimEntryRing: template '$($Template.templateId)' has no entry '$Key'."
    }
    $ov = Get-PimTemplateOverlay
    $id = "$($Template.templateId)"
    if (-not $ov.PSObject.Properties[$id]) { Set-PimConfProp -Object $ov -Name $id -Value ([pscustomobject]@{}) }
    $node = $ov.PSObject.Properties[$id].Value
    if (-not $node.PSObject.Properties['rings'] -or $null -eq $node.rings) { Set-PimConfProp -Object $node -Name 'rings' -Value ([pscustomobject]@{}) }
    $canon = "$(@($Template.entries | Where-Object { "$($_.key)" -ieq "$Key" })[0].key)"
    Set-PimConfProp -Object $node.rings -Name $canon -Value $Ring
    [void](Save-PimTemplateOverlay -Overlay $ov)
    return (Merge-PimTemplateOverlay -Template $Template -Overlay $ov)
}

function Read-PimApprovedTemplates {
    # The shipped templates in -SourceDir (read-only) with the SQL overlay merged over each (see above).
    # -Overlay supplies it (tests / a caller that already read it); omitted -> Get-PimTemplateOverlay.
    # -NoOverlay reads the bare shipped files.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceDir, [switch]$IncludeDrafts, [AllowNull()][object]$Overlay = $null, [switch]$NoOverlay)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $SourceDir)) { Write-Warning "Template source dir not found: $SourceDir"; return $out.ToArray() }
    $ov = $null
    if (-not $NoOverlay) {
        if ($PSBoundParameters.ContainsKey('Overlay')) { $ov = $Overlay } else { $ov = Get-PimTemplateOverlay }
    }
    foreach ($f in Get-ChildItem -LiteralPath $SourceDir -Filter '*.template.json' -File | Sort-Object Name) {
        try { $t = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false))) }
        catch { Write-Warning ("Template {0} failed to parse: {1}" -f $f.Name, $_.Exception.Message); continue }
        if ($null -ne $ov) { $t = Merge-PimTemplateOverlay -Template $t -Overlay $ov }
        $check = Test-PimTemplateDoc -Template $t
        if (-not $check.valid) { Write-Warning ("Template {0} invalid: {1}" -f $f.Name, ($check.errors -join '; ')); continue }
        if (-not $IncludeDrafts -and -not (Test-PimTemplateApproved -Template $t)) {
            Write-Host ("  [conformance] skipping draft (not pullable): {0} v{1}" -f $t.templateId, $t.templateVersion) -ForegroundColor DarkGray; continue
        }
        $out.Add($t)
    }
    return $out.ToArray()
}

# --- WHERE THE TEMPLATE-CATALOG RING COMES FROM (BUG-179, operator decision 2026-09-18) --------------
# §77.20 (operator 2026-09-21: "ring 0 = dev, ring 1 = test, ring 2 = broad" / "make it consistent"): ONE ring
# order everywhere. An entry on ring E reaches a tenant on ring T when T <= E -- the same rule as an admin reaching
# a slave (Test-PimRingReaches). The catalog ring IS the environment's update ring, no inversion any more:
#     update ring 0 (dev)       -> 0   everything, pilots included
#     update ring 1 (internal)  -> 1
#     update ring 2 (customers) -> 2   only fully promoted entries
# Not recorded, unparseable or out of range -> 2 (the most restrictive), and the reason is reported.
# 🪤 Get-PimTenantRing (PIM-Functions.psm1) is deliberately NOT used or changed: it also drives the
# admin<->tenant ring filter (Select-PimAdminRowsByRing), which is a different axis.
# The update ring is read from the record the UPDATE JOB writes (pim.Settings['UpdateState'].ring,
# PIM-UpdateState.ps1) -- the ring is local to the environment, never set by a master.
function ConvertTo-PimTemplateCatalogRing {
    # PURE. Update ring ('2', 'ring2', 'Ring 1', ...) -> @{ ring; valid; updateRing; reason }.
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$UpdateRing)
    $raw = "$UpdateRing".Trim()
    if (-not $raw) { return [pscustomobject]@{ ring = 2; valid = $false; updateRing = $raw; reason = 'update ring not recorded -- most restrictive template ring 2' } }
    # Same normalisation as Get-PimUpdateRingLabel / the channel: 'ring2', 'ring 2', 'ring-2' and '2' are one ring.
    $n = $raw -replace '^(?i)ring[\s_-]*', ''
    $u = 0
    if (-not [int]::TryParse($n, [ref]$u) -or $u -lt 0 -or $u -gt 2) {
        return [pscustomobject]@{ ring = 2; valid = $false; updateRing = $raw; reason = "update ring '$raw' is not 0, 1 or 2 -- most restrictive template ring 2" }
    }
    return [pscustomobject]@{ ring = $u; valid = $true; updateRing = $raw; reason = "update ring $u" }
}

function Get-PimTemplateCatalogRing {
    # The template-catalog ring for THIS environment: @{ ring; source; updateRing; reason }.
    #   source = 'update-ring N' when the update job's record carries a usable ring, else 'not recorded'.
    # -UpdateStateRecord injects the record (the Manager reads it with Read-PimUpdateState in its own
    # scope); otherwise it is read here through Read-PimUpdateState when that is loaded. Never throws.
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$ConnectionString, [AllowNull()][object]$UpdateStateRecord = $null)
    $rec = $UpdateStateRecord
    if ($null -eq $rec -and -not $PSBoundParameters.ContainsKey('UpdateStateRecord') -and (Get-Command Read-PimUpdateState -ErrorAction SilentlyContinue)) {
        try { $rec = Read-PimUpdateState -ConnectionString $ConnectionString } catch { $rec = $null }
    }
    $ringRaw = ''
    if ($null -ne $rec) {
        if ($rec -is [System.Collections.IDictionary]) { if ($rec.Contains('ring')) { $ringRaw = "$($rec['ring'])" } }
        elseif ($rec.PSObject -and $rec.PSObject.Properties['ring']) { $ringRaw = "$($rec.ring)" }
    }
    $m = ConvertTo-PimTemplateCatalogRing -UpdateRing $ringRaw
    $src = if ($m.valid) { "update-ring $([int]$m.ring)" } else { 'not recorded' }
    $why = if ($null -eq $rec) { 'no update record in pim.Settings[UpdateState] -- most restrictive template ring 2' } else { "$($m.reason)" }
    return [pscustomobject]@{ ring = [int]$m.ring; source = $src; updateRing = "$ringRaw".Trim(); reason = $why }
}

# --- ring scope (self-contained; tenantRing <= entryRing, §77.20) ---------------
# An entry with no ring is on ring 0 (dev): a new entry reaches dev tenants first and is promoted 0 -> 1 -> 2.
function Get-PimTemplateEntryRing {
    param([AllowNull()][object]$Entry)
    $r = 0
    if ($Entry -and $null -ne $Entry.PSObject.Properties['ring'] -and "$($Entry.ring)" -ne '') {
        $parsed = 0
        if ([int]::TryParse("$($Entry.ring)", [ref]$parsed) -and $parsed -ge 0 -and $parsed -le 2) { $r = $parsed }
    }
    return $r
}

function Test-PimRingInScope {
    param([Parameter(Mandatory)][int]$EntryRing, [Parameter(Mandatory)][int]$TenantRing)
    return ($TenantRing -le $EntryRing)
}

function Select-PimInScopeEntries {
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][int]$TenantRing)
    return @(@($Template.entries) | Where-Object { Test-PimRingInScope -EntryRing (Get-PimTemplateEntryRing -Entry $_) -TenantRing $TenantRing })
}

# --- exemptions (PURE, time injected; expiry MANDATORY) -------------------------
function Test-PimExemptionValid {
    param([Parameter(Mandatory)][object]$Exemption, [Parameter(Mandatory)][datetime]$NowUtc)
    $reason = "$($Exemption.reason)".Trim()
    $expRaw = "$($Exemption.expiresUtc)".Trim()
    if (-not $reason) { return @{ valid = $false; active = $false; state = 'Invalid'; detail = 'reason is required' } }
    if (-not $expRaw) { return @{ valid = $false; active = $false; state = 'Invalid'; detail = 'expiresUtc is required (exemptions always expire)' } }
    # IMP-02: an unreadable expiry makes the exemption INVALID (so it grants nothing).
    $expU = Get-PimUtcStamp $expRaw
    if ($null -eq $expU) { return @{ valid = $false; active = $false; state = 'Invalid'; detail = "expiresUtc '$expRaw' is not a date" } }
    if ($expU -le $NowUtc) { return @{ valid = $true; active = $false; state = 'Expired'; detail = "expired $($expU.ToString('o'))" } }
    return @{ valid = $true; active = $true; state = 'Active'; detail = "active until $($expU.ToString('o'))" }
}

function Get-PimActiveExemptionKeys {
    param(
        [object[]]$Exemptions = @(),
        [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TemplateId,
        [Parameter(Mandatory)][datetime]$NowUtc
    )
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Exemptions)) {
        if ("$($x.tenantId)" -ne "$TenantId") { continue }
        if ("$($x.templateId)" -ne "$TemplateId") { continue }
        $v = Test-PimExemptionValid -Exemption $x -NowUtc $NowUtc
        if ($v.state -eq 'Invalid') { Write-Warning ("Exemption {0}/{1}/{2} ignored: {3}" -f $x.tenantId, $x.templateId, $x.itemKey, $v.detail); continue }
        if ($v.active) { $keys.Add("$($x.itemKey)") }
    }
    return $keys.ToArray()
}

# --- exemption REGISTER (PURE) --------------------------------------------------
# REQUIREMENTS.md s28 [L2]: exemptions must not be write-only. This builds a
# reviewable list of every stored exemption WITH its per-row state (Active /
# Expiring / Expired / Invalid), days-remaining and a stable revoke key, so the
# Manager can show an active-exemptions register and let an operator revoke one
# before it lapses on its own. Pure + time-injected (NowUtc), PS 5.1-safe.
function Get-PimExemptionRevokeKey {
    param([Parameter(Mandatory)][object]$Exemption)
    # Stable identity for ONE exemption row: tenant|template|item|expiry. Two rows
    # for the same item with different expiries are distinct (re-issued waiver).
    return ('{0}|{1}|{2}|{3}' -f "$($Exemption.tenantId)", "$($Exemption.templateId)", "$($Exemption.itemKey)", "$($Exemption.expiresUtc)")
}

function Get-PimExemptionList {
    [CmdletBinding()]
    param(
        [object[]]$Exemptions = @(),
        [string]$TenantId = '',
        [string]$TemplateId = '',
        [Parameter(Mandatory)][datetime]$NowUtc,
        [int]$ExpiringWithinDays = 30
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Exemptions)) {
        if ($null -eq $x) { continue }
        if ($TenantId   -and "$($x.tenantId)"   -ne "$TenantId")   { continue }
        if ($TemplateId -and "$($x.templateId)" -ne "$TemplateId") { continue }
        $v = Test-PimExemptionValid -Exemption $x -NowUtc $NowUtc
        $daysLeft = $null
        $state = $v.state                                          # Active | Expired | Invalid
        $expU = $null
        if ($v.valid) {
            $exp = Get-PimUtcStamp $x.expiresUtc   # IMP-02
            if ($null -ne $exp) {
                $expU = $exp
                $daysLeft = [math]::Floor(($expU - $NowUtc).TotalDays)
                # Active but inside the warning window -> 'Expiring' (still active).
                if ($v.active -and $daysLeft -le $ExpiringWithinDays) { $state = 'Expiring' }
            }
        }
        $rows.Add([pscustomobject]@{
            TenantId    = "$($x.tenantId)"
            TemplateId  = "$($x.templateId)"
            ItemKey     = "$($x.itemKey)"
            Reason      = "$($x.reason)"
            ApprovedBy  = "$($x.approvedBy)"
            ApprovedUtc = "$($x.approvedUtc)"
            ExpiresUtc  = if ($expU) { $expU.ToString('o') } else { "$($x.expiresUtc)" }
            State       = $state                                   # Active|Expiring|Expired|Invalid
            Active      = [bool]$v.active
            DaysLeft    = $daysLeft                                # $null when Invalid
            Detail      = "$($v.detail)"
            RevokeKey   = Get-PimExemptionRevokeKey -Exemption $x
        })
    }
    # Soonest-to-lapse first so the operator sees what needs attention; Invalid
    # rows (no usable expiry) sort last.
    return @($rows | Sort-Object -Property `
        @{ Expression = { if ($_.State -eq 'Invalid') { 1 } else { 0 } } }, `
        @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { $_.DaysLeft } } })
}

function Get-PimExemptionSummary {
    [CmdletBinding()]
    param([object[]]$List = @())
    $c = @{ Total = 0; Active = 0; Expiring = 0; Expired = 0; Invalid = 0 }
    foreach ($r in @($List)) {
        if ($null -eq $r) { continue }
        $c.Total++
        switch ("$($r.State)") {
            'Active'   { $c.Active++ }
            'Expiring' { $c.Active++; $c.Expiring++ }
            'Expired'  { $c.Expired++ }
            'Invalid'  { $c.Invalid++ }
        }
    }
    return [pscustomobject]$c
}

# Remove ONE exemption by its stable revoke key (PURE). Returns the kept set; the
# caller persists it. Never mutates the input array. Idempotent: an unknown key
# leaves the set unchanged (Removed=0). Defensive: refuses an empty key so a blank
# request can never wipe rows.
function Remove-PimExemptionEntry {
    [CmdletBinding()]
    param(
        [object[]]$Exemptions = @(),
        [Parameter(Mandatory)][string]$RevokeKey
    )
    $key = "$RevokeKey".Trim()
    if (-not $key) { throw 'RevokeKey is required to revoke an exemption.' }
    $kept = New-Object System.Collections.Generic.List[object]
    $removed = 0
    foreach ($x in @($Exemptions)) {
        if ($null -eq $x) { continue }
        if ((Get-PimExemptionRevokeKey -Exemption $x) -eq $key) { $removed++; continue }
        $kept.Add($x)
    }
    return [pscustomobject]@{ Kept = $kept.ToArray(); Removed = $removed }
}

# --- THE RECONCILE CORE (PURE) --------------------------------------------------
function Get-PimConformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Template,
        [Parameter(Mandatory)][int]$TenantRing,
        [string]$TenantId = '',
        [string[]]$LiveKeys = @(),
        [string[]]$ActiveExemptionKeys = @(),
        [string[]]$LiveCatalog = @(),
        [int]$AppliedVersion = 0
    )
    $liveSet = @{}; foreach ($k in @($LiveKeys)) { $liveSet["$k".ToLowerInvariant()] = $true }
    $exemptSet = @{}; foreach ($k in @($ActiveExemptionKeys)) { $exemptSet["$k".ToLowerInvariant()] = $true }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Template.entries)) {
        $key = "$($e.key)"; $kl = $key.ToLowerInvariant()
        $ring = Get-PimTemplateEntryRing -Entry $e
        $inScope = Test-PimRingInScope -EntryRing $ring -TenantRing $TenantRing
        $present = $liveSet.ContainsKey($kl)
        $exempt  = $exemptSet.ContainsKey($kl)
        $status =
            if (-not $inScope) { if ($present) { 'DriftExtra' } else { 'OutOfRing' } }
            elseif ($exempt)   { if ($present) { 'DriftExtra' } else { 'Exempt' } }
            else               { if ($present) { 'UpToDate' }   else { 'Gap' } }
        $rows.Add([pscustomobject]@{
            TenantId = $TenantId; TemplateId = "$($Template.templateId)"; Key = $key
            Ring = $ring; SinceVersion = [int]("$($e.sinceVersion)" -as [int]); InScope = $inScope
            Present = $present; Exempt = $exempt; Status = $status
        })
    }
    $known = @{}; foreach ($c in @($Template.knownCatalog)) { $known["$c".ToLowerInvariant()] = $true }
    $catalogAhead = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($LiveCatalog)) {
        if (-not $known.ContainsKey("$c".ToLowerInvariant())) {
            $catalogAhead.Add([pscustomobject]@{ TenantId = $TenantId; TemplateId = "$($Template.templateId)"; Capability = "$c"; Status = 'CatalogAhead' })
        }
    }
    $tv = [int]("$($Template.templateVersion)" -as [int])
    $counts = @{}
    foreach ($s in 'UpToDate','Gap','Exempt','DriftExtra','OutOfRing') { $counts[$s] = @($rows | Where-Object Status -eq $s).Count }
    return [pscustomobject]@{
        TemplateId = "$($Template.templateId)"; TemplateVersion = $tv; AppliedVersion = $AppliedVersion
        Behind = [math]::Max(0, $tv - $AppliedVersion); TenantId = $TenantId; TenantRing = $TenantRing
        Rows = $rows.ToArray(); CatalogAhead = $catalogAhead.ToArray(); Counts = $counts
    }
}

# --- capability-watch draft + approve + promote (PURE) --------------------------
function New-PimTemplateDraft {
    param(
        [Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string[]]$Capabilities,
        [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$NewEntryFactory
    )
    $draft = Copy-PimConfObject -Object $Template
    $newVer = [int]("$($draft.templateVersion)" -as [int]) + 1
    Set-PimConfProp -Object $draft -Name 'templateVersion' -Value $newVer
    Set-PimConfProp -Object $draft -Name 'status' -Value 'draft'
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($draft.entries)) { $entries.Add($e) }
    $known = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($draft.knownCatalog)) { $known.Add("$c") }
    foreach ($cap in @($Capabilities)) {
        if ($NewEntryFactory) { $entries.Add((& $NewEntryFactory $cap $newVer)) }
        else {
            # REQ-U (2026-09-19): a GroupTag is tenant-neutral -- the tenant's PimGroupPattern turns it into a
            # name. The placeholder used to be 'PIM-REVIEW-<cap>', i.e. it baked one tenant's 'PIM-' prefix into
            # the TAG (a 'GRP-{Role}' tenant would get 'GRP-PIM-REVIEW-...'). The placeholder is now 'REVIEW-<cap>'.
            $capTag = ("REVIEW-" + ("$cap" -replace '[^A-Za-z0-9.\-]', ''))
            $entries.Add([pscustomobject]@{
                key = "role:$cap"; sinceVersion = $newVer; ring = 2
                roleName = "$cap"; groupTag = $capTag
                value = [pscustomobject]@{ roleName = "$cap"; groupTag = $capTag; note = 'AUTO-DRAFT: set groupTag + ring before approving' }
            })
        }
        if (-not ($known | Where-Object { $_ -ieq "$cap" })) { $known.Add("$cap") }
    }
    Set-PimConfProp -Object $draft -Name 'entries' -Value $entries.ToArray()
    Set-PimConfProp -Object $draft -Name 'knownCatalog' -Value $known.ToArray()
    $hist = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($draft.versionHistory)) { $hist.Add($h) }
    $hist.Add([pscustomobject]@{ v = $newVer; date = $NowUtc.ToString('yyyy-MM-dd'); summary = ("AUTO-DRAFT +{0} catalog-ahead role(s): {1}" -f @($Capabilities).Count, (@($Capabilities) -join ', ')) })
    Set-PimConfProp -Object $draft -Name 'versionHistory' -Value $hist.ToArray()
    return $draft
}

function Approve-PimTemplate {
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$ApprovedBy, [datetime]$NowUtc = [datetime]::UtcNow)
    $t = Copy-PimConfObject -Object $Template
    Set-PimConfProp -Object $t -Name 'status' -Value 'approved'
    Set-PimConfProp -Object $t -Name 'approvedBy' -Value $ApprovedBy
    Set-PimConfProp -Object $t -Name 'approvedUtc' -Value $NowUtc.ToString('o')
    return $t
}

function Set-PimEntryRing {
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateRange(0,2)][int]$Ring)
    $t = Copy-PimConfObject -Object $Template
    $hit = $false
    foreach ($e in @($t.entries)) { if ("$($e.key)" -ieq "$Key") { Set-PimConfProp -Object $e -Name 'ring' -Value $Ring; $hit = $true } }
    if (-not $hit) { throw "Set-PimEntryRing: template '$($t.templateId)' has no entry '$Key'." }
    return $t
}

function Set-PimEntryRingInJson {
    # BUG-06: change ONE entry's ring by editing the ORIGINAL JSON TEXT in place, so a
    # ring promotion touches only the digits it means to change.
    #
    # The object round-trip (ConvertFrom-Json -> Set-PimEntryRing -> ConvertTo-Json) is
    # lossless for DATA -- verified: _doc, versionHistory and approvedBy all survive -- but
    # it re-serializes the WHOLE file: the shipped template goes 1698 -> 2952 bytes under
    # Windows PowerShell 5.1, its hand-aligned entry columns collapse, and
    # `Set-Content -Encoding UTF8` prepends a UTF-8 BOM to a file the rest of this module
    # deliberately reads and writes BOM-less (ConvertTo-PimTemplate even strips a leading
    # BOM defensively). On a customer install the template is not in git, so that rewrite
    # has no undo. A one-field GUI change must not rewrite a curated file.
    #
    # Returns the edited JSON text. Throws the same message as Set-PimEntryRing when the
    # key is unknown, so the endpoint's 400 behaviour is unchanged.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateRange(0,2)][int]$Ring
    )
    $tpl = ConvertTo-PimTemplate -Json $Json
    if (-not (@($tpl.entries) | Where-Object { "$($_.key)" -ieq "$Key" })) {
        throw "Set-PimEntryRing: template '$($tpl.templateId)' has no entry '$Key'."
    }

    # Walk the raw text and find each entry object that carries this key. Brace counting
    # skips over string literals so a brace inside a value (e.g. a groupTag) cannot throw
    # the span off.
    $text = $Json
    $escaped = [regex]::Escape(($Key | ConvertTo-Json))   # includes the surrounding quotes
    $keyRx = [regex]::new('"key"\s*:\s*' + $escaped, 'IgnoreCase')
    $edited = $false
    foreach ($m in @($keyRx.Matches($text)) | Sort-Object Index -Descending) {
        # backwards to this entry object's opening brace
        $start = -1
        for ($i = $m.Index; $i -ge 0; $i--) { if ($text[$i] -eq '{') { $start = $i; break } }
        if ($start -lt 0) { continue }
        # forwards to its matching closing brace, ignoring braces inside strings
        $depth = 0; $end = -1; $inStr = $false; $esc = $false
        for ($i = $start; $i -lt $text.Length; $i++) {
            $ch = $text[$i]
            if ($inStr) {
                if ($esc) { $esc = $false }
                elseif ($ch -eq '\') { $esc = $true }
                elseif ($ch -eq '"') { $inStr = $false }
                continue
            }
            if ($ch -eq '"') { $inStr = $true; continue }
            if ($ch -eq '{') { $depth++ }
            elseif ($ch -eq '}') { $depth--; if ($depth -eq 0) { $end = $i; break } }
        }
        if ($end -lt 0) { continue }

        $span = $text.Substring($start, $end - $start + 1)
        $ringRx = [regex]::new('("ring"\s*:\s*)(\d+)', 'IgnoreCase')
        if ($ringRx.IsMatch($span)) {
            $newSpan = $ringRx.Replace($span, { param($mm) $mm.Groups[1].Value + $Ring }, 1)
        } else {
            # No ring property yet (Get-PimTemplateEntryRing defaults such an entry to 2).
            # Insert one directly after the key pair so the entry keeps its field order.
            $rel = $m.Index - $start + $m.Length
            $newSpan = $span.Substring(0, $rel) + ', "ring": ' + $Ring + $span.Substring($rel)
        }
        if ($newSpan -ne $span) {
            $text = $text.Substring(0, $start) + $newSpan + $text.Substring($end + 1)
            $edited = $true
        } else { $edited = $true }   # already at the requested ring -- a no-op is still a hit
    }
    if (-not $edited) { throw "Set-PimEntryRing: template '$($tpl.templateId)' has no entry '$Key'." }
    return $text
}

# --- local applied-version stamp (SQL pim.Settings['ConformanceTemplateState']; version stays LOCAL) ------
# SQL-ONLY (2026-09-13). The applied-version stamps used to live in output/state/template-state.json.
# They are now ONE document in pim.Settings['ConformanceTemplateState'] with the same shape:
#   { "<tenantId>|<templateId>": { LastAppliedVersion; AppliedUtc; AppliedBy },
#     "scopeVersions":     { "<tenantId>|<scope>": { LastAppliedVersion; AppliedUtc; AppliedBy } },
#     "fleetRingByTenant": { "<tenantId>": <int> } }
# Read/written through the Get-/Set-PimSetting bridge the Manager and the scheduler both define.
# Without a bridge (offline tests, a bare dot-source) the document lives in this process's memory
# only, and a save says so -- it is never presented as persistence.
$script:PimTemplateStateMem = $null

function Get-PimTemplateStateStoreName { 'ConformanceTemplateState' }

function ConvertTo-PimTemplateStateDocument {
    # Normalize a stored value (JSON text, parsed object or dictionary) to a PSCustomObject.
    param([object]$Value)
    if ($null -eq $Value) { return [pscustomobject]@{} }
    if ($Value -is [string]) {
        if (-not "$Value".Trim()) { return [pscustomobject]@{} }
        try { $Value = $Value | ConvertFrom-Json } catch { return [pscustomobject]@{} }
        if ($Value -is [string]) { try { $Value = $Value | ConvertFrom-Json } catch { return [pscustomobject]@{} } }
    }
    if ($Value -is [System.Collections.IDictionary]) {
        try { $Value = ($Value | ConvertTo-Json -Depth 8 | ConvertFrom-Json) } catch { return [pscustomobject]@{} }
    }
    if ($null -eq $Value -or -not $Value.PSObject) { return [pscustomobject]@{} }
    return $Value
}

function Get-PimTemplateStateDocument {
    # The whole state document. Never throws; absent -> an empty object.
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { return (ConvertTo-PimTemplateStateDocument (Get-PimSetting -Name (Get-PimTemplateStateStoreName))) }
        catch { Write-Warning "  [conformance] TemplateState read failed: $($_.Exception.Message)"; return [pscustomobject]@{} }
    }
    if ($null -ne $script:PimTemplateStateMem) { return (ConvertTo-PimTemplateStateDocument $script:PimTemplateStateMem) }
    return [pscustomobject]@{}
}

function Save-PimTemplateStateDocument {
    # Persist the whole document. Returns 'sql' or 'memory'. A store that rejects the write THROWS.
    param([Parameter(Mandatory)][object]$Document)
    $json = $Document | ConvertTo-Json -Depth 8 -Compress
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        Set-PimSetting -Name (Get-PimTemplateStateStoreName) -Value $json | Out-Null
        return 'sql'
    }
    $script:PimTemplateStateMem = $json
    Write-Warning "  [conformance] TemplateState kept in this process only -- no SQL settings store (Set-PimSetting) is wired (PIM v2 is SQL-only)."
    return 'memory'
}

function Get-PimTemplateState {
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TemplateId)
    $all = Get-PimTemplateStateDocument
    $p = $all.PSObject.Properties["$TenantId|$TemplateId"]
    if ($p) { return $p.Value }
    return $null
}

function Set-PimTemplateState {
    param(
        [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TemplateId,
        [Parameter(Mandatory)][int]$Version, [string]$AppliedBy = "$env:USERNAME", [datetime]$NowUtc = [datetime]::UtcNow
    )
    $all = Get-PimTemplateStateDocument
    Set-PimConfProp -Object $all -Name "$TenantId|$TemplateId" -Value ([pscustomobject]@{ LastAppliedVersion = $Version; AppliedUtc = $NowUtc.ToString('o'); AppliedBy = $AppliedBy })
    return (Save-PimTemplateStateDocument -Document $all)
}

function Set-PimTemplateStateRing {
    # Stamp a tenant's rollout ring in the state document (fleetRingByTenant) so the fleet matrix
    # ([H8]) can read the ring of an instance it is not the active one for.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][int]$Ring)
    $all = Get-PimTemplateStateDocument
    if (-not $all.PSObject.Properties['fleetRingByTenant']) { Set-PimConfProp -Object $all -Name 'fleetRingByTenant' -Value ([pscustomobject]@{}) }
    Set-PimConfProp -Object $all.fleetRingByTenant -Name $TenantId -Value $Ring
    return (Save-PimTemplateStateDocument -Document $all)
}

# --- FLEET state read (I/O seam for [H8]) ---------------------------------------
# Read ONE instance's conformance standing from the template-state document, for the
# fleet matrix: every template's last-applied version (keyed "<tenantId>|<templateId>")
# plus an optional fleet `ring` stamp (fleetRingByTenant). Returns
# @{ appliedVersions = @{ '<templateId>' = <int> }; ring = <int?> }. Returns empty maps when
# the document is absent or unreadable so a never-deployed tenant is still a valid fleet row
# (every cell = NeverApplied). -State supplies the document (tests / a caller that already has
# it); omitted -> read from the store. $TenantId selects this instance's rows.
function Get-PimFleetStateForInstance {
    [CmdletBinding()]
    param([object]$State, [Parameter(Mandatory)][string]$TenantId)
    $applied = @{}
    $ring = $null
    $all = if ($PSBoundParameters.ContainsKey('State')) { ConvertTo-PimTemplateStateDocument $State } else { Get-PimTemplateStateDocument }
    if ($null -eq $all) { return @{ appliedVersions = $applied; ring = $ring } }
    $prefix = "$TenantId|"
    foreach ($p in @($all.PSObject.Properties)) {
        $name = "$($p.Name)"
        if ($name -eq 'scopeVersions') { continue }            # the per-scope map (different feature)
        if ($name -eq 'fleetRingByTenant') {                   # optional ring map: { '<tenant>' = <int> }
            if ($p.Value -and $p.Value.PSObject.Properties[$TenantId]) {
                $rp = 0; if ([int]::TryParse("$($p.Value.PSObject.Properties[$TenantId].Value)", [ref]$rp)) { $ring = $rp }
            }
            continue
        }
        if ($name.StartsWith($prefix) -and $p.Value -and $p.Value.PSObject.Properties['LastAppliedVersion']) {
            $tplId = $name.Substring($prefix.Length)
            $applied[$tplId] = [int]("$($p.Value.LastAppliedVersion)" -as [int])
        }
    }
    return @{ appliedVersions = $applied; ring = $ring }
}

# --- per-SCOPE desired-vs-applied template version (engine + GUI) ---------------
# The conformance core above tracks ONE template's version per tenant. A PIM run
# spans MANY scopes (provider areas: Groups, EntraRoles, AzRes, GroupsPolicies,
# ...), each of which may be governed by a different template version. This seam
# tracks the desired-vs-applied template version PER SCOPE so the engine (and the
# Manager conformance heatmap) can show, for one tenant, exactly which scopes are
# at the current template version and which are Behind / Ahead / NeverApplied.
#
# State lives in the SAME document as the template stamp (pim.Settings['ConformanceTemplateState']),
# under a distinct "scopeVersions" map keyed "<tenantId>|<scope>" -> { LastAppliedVersion;
# AppliedUtc; AppliedBy }. Pure matrix builder (Get-PimScopeConformance) takes the desired
# versions (template-version per scope) + the applied versions (from state) and returns one
# annotated row per scope. Fully testable; no Graph.

function Get-PimScopeAppliedVersion {
    # Applied template version for ONE scope of ONE tenant; 0 if never applied.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Scope)
    $all = Get-PimTemplateStateDocument
    if (-not $all.PSObject.Properties['scopeVersions']) { return 0 }
    $p = $all.scopeVersions.PSObject.Properties["$TenantId|$Scope"]
    if ($p -and $p.Value -and $p.Value.PSObject.Properties['LastAppliedVersion']) { return [int]("$($p.Value.LastAppliedVersion)" -as [int]) }
    return 0
}

function Set-PimScopeAppliedVersion {
    # Stamp the applied template version for ONE scope of ONE tenant (LOCAL state).
    param(
        [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][int]$Version, [string]$AppliedBy = "$env:USERNAME", [datetime]$NowUtc = [datetime]::UtcNow
    )
    $all = Get-PimTemplateStateDocument
    if (-not $all.PSObject.Properties['scopeVersions']) { Set-PimConfProp -Object $all -Name 'scopeVersions' -Value ([pscustomobject]@{}) }
    Set-PimConfProp -Object $all.scopeVersions -Name "$TenantId|$Scope" -Value ([pscustomobject]@{ LastAppliedVersion = $Version; AppliedUtc = $NowUtc.ToString('o'); AppliedBy = $AppliedBy })
    return (Save-PimTemplateStateDocument -Document $all)
}

function Get-PimScopeConformance {
    # PURE: build the per-scope desired-vs-applied matrix for one tenant.
    #   $DesiredVersions = @{ '<scope>' = <int templateVersion> ; ... }  (what should be applied now)
    #   $AppliedVersions = @{ '<scope>' = <int> ; ... }                  (what state says is applied)
    # Status per scope:
    #   NeverApplied (applied = 0 / absent)
    #   Behind       (applied < desired)
    #   UpToDate     (applied == desired)
    #   Ahead        (applied > desired -- desired template rolled back; flag for review)
    # Returns @{ TenantId; Rows=@( @{ Scope; DesiredVersion; AppliedVersion; Behind; Status } ); Counts }.
    param(
        [Parameter(Mandatory)][hashtable]$DesiredVersions,
        [hashtable]$AppliedVersions = @{},
        [string]$TenantId = ''
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @($DesiredVersions.Keys | Sort-Object)) {
        $want = [int]("$($DesiredVersions[$scope])" -as [int])
        $have = 0
        if ($AppliedVersions -and $AppliedVersions.ContainsKey($scope)) { $have = [int]("$($AppliedVersions[$scope])" -as [int]) }
        $status =
            if ($have -le 0)      { 'NeverApplied' }
            elseif ($have -lt $want) { 'Behind' }
            elseif ($have -gt $want) { 'Ahead' }
            else                  { 'UpToDate' }
        $rows.Add([pscustomobject]@{ Scope = "$scope"; DesiredVersion = $want; AppliedVersion = $have; Behind = [math]::Max(0, $want - $have); Status = $status })
    }
    $counts = @{}
    foreach ($s in 'NeverApplied','Behind','UpToDate','Ahead') { $counts[$s] = @($rows | Where-Object Status -eq $s).Count }
    return [pscustomobject]@{ TenantId = $TenantId; Rows = $rows.ToArray(); Counts = $counts }
}

# --- FLEET conformance matrix (PURE) -- REQUIREMENTS.md s28 [H8] ----------------
# The single-tenant cores above answer "how far behind is THIS tenant?". An MSP runs
# MANY tenants against ONE central set of approved templates and needs the cross-fleet
# view: one matrix of tenants x templates, each cell carrying behind-by-N + a status,
# so template conformance can be SEEN and DRIVEN across the whole fleet from one place
# (instead of one tenant at a time). This is the pure decision core; the Manager's thin
# live wrapper reads each instance's ring + local applied-version stamp and feeds them in.
#
# Per-cell status (mirrors the single-tenant scope vocabulary so the GUI legend is shared):
#   NeverApplied -- template never deployed to this tenant (appliedVersion <= 0)
#   Behind       -- appliedVersion < templateVersion (Behind = the version gap)
#   UpToDate     -- appliedVersion == templateVersion
#   Ahead        -- appliedVersion > templateVersion (template was rolled back; flag for review)
# Only APPROVED templates form columns: a draft is never deployable, so it is never a
# fleet column. A cell's `behind` is max(0, templateVersion - appliedVersion).
#
# Inputs (all plain objects / hashtables so the core is fully offline-testable):
#   $Templates -- approved template docs (templateId, workload, templateVersion[, status])
#   $Tenants   -- @( @{ tenantId; ring; appliedVersions = @{ '<templateId>' = <int> } } ), one
#                 per managed instance. `ring` is the tenant's rollout ring (informational
#                 here -- the per-cell behind is version-based; ring drives WHICH entries
#                 deploy, surfaced separately by the ring-rollout rollup below).
function Get-PimFleetConformance {
    [CmdletBinding()]
    param(
        [object[]]$Templates = @(),
        [object[]]$Tenants   = @()
    )
    # Only approved templates are deployable -> only they are fleet columns.
    $cols = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Templates)) {
        if ($null -eq $t) { continue }
        if (-not (Test-PimTemplateApproved -Template $t)) { continue }
        $tv = [int]("$($t.templateVersion)" -as [int]); if ($tv -lt 1) { $tv = 1 }
        $cols.Add([pscustomobject]@{
            TemplateId      = "$($t.templateId)"
            Workload        = "$($t.workload)"
            TemplateVersion = $tv
        })
    }
    # Stable column order: by templateId so the matrix is deterministic.
    $cols = @($cols | Sort-Object -Property @{ Expression = { "$($_.TemplateId)" } })

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($tn in @($Tenants)) {
        if ($null -eq $tn) { continue }
        $tid = "$($tn.tenantId)"
        $ring = 2   # 77.20: an unknown tenant ring is the most restrictive (2 = broad, fully promoted only)
        if ($null -ne $tn.ring -and "$($tn.ring)" -ne '') {
            $pr = 0; if ([int]::TryParse("$($tn.ring)", [ref]$pr) -and $pr -ge 0 -and $pr -le 2) { $ring = $pr }
        }
        $applied = @{}
        if ($tn.appliedVersions) {
            if ($tn.appliedVersions -is [hashtable]) {
                foreach ($k in @($tn.appliedVersions.Keys)) { $applied["$k"] = [int]("$($tn.appliedVersions[$k])" -as [int]) }
            } elseif ($tn.appliedVersions.PSObject) {
                foreach ($p in @($tn.appliedVersions.PSObject.Properties)) { $applied["$($p.Name)"] = [int]("$($p.Value)" -as [int]) }
            }
        }
        $cells = New-Object System.Collections.Generic.List[object]
        $maxBehind = 0; $behindCount = 0; $upToDate = 0; $never = 0; $ahead = 0
        foreach ($col in $cols) {
            $have = 0
            if ($applied.ContainsKey($col.TemplateId)) { $have = [int]$applied[$col.TemplateId] }
            $want = [int]$col.TemplateVersion
            $status =
                if ($have -le 0)        { 'NeverApplied' }
                elseif ($have -lt $want) { 'Behind' }
                elseif ($have -gt $want) { 'Ahead' }
                else                     { 'UpToDate' }
            $behind = [math]::Max(0, $want - $have)
            switch ($status) {
                'Behind'       { $behindCount++; if ($behind -gt $maxBehind) { $maxBehind = $behind } }
                'NeverApplied' { $never++;       if ($want   -gt $maxBehind) { $maxBehind = $want } }
                'UpToDate'     { $upToDate++ }
                'Ahead'        { $ahead++ }
            }
            $cells.Add([pscustomobject]@{
                TemplateId      = $col.TemplateId
                TemplateVersion = $want
                AppliedVersion  = $have
                Behind          = $behind
                Status          = $status
            })
        }
        # A tenant is "current" only when every column is UpToDate (no behind, no never, no ahead).
        $tenantCurrent = (($behindCount + $never + $ahead) -eq 0)
        $rows.Add([pscustomobject]@{
            TenantId     = $tid
            Ring         = $ring
            Cells        = $cells.ToArray()
            MaxBehind    = $maxBehind
            BehindCount  = $behindCount
            NeverCount   = $never
            UpToDate     = $upToDate
            AheadCount   = $ahead
            Current      = $tenantCurrent
        })
    }
    # Sort tenants worst-first so an MSP sees who needs attention at the top.
    $rows = @($rows | Sort-Object -Property `
        @{ Expression = { $_.MaxBehind }; Descending = $true }, `
        @{ Expression = { $_.NeverCount }; Descending = $true }, `
        @{ Expression = { "$($_.TenantId)" } })

    # Per-template fleet rollup: across all tenants, how many are up-to-date / behind / never.
    $perTemplate = New-Object System.Collections.Generic.List[object]
    foreach ($col in $cols) {
        $up = 0; $bh = 0; $nv = 0; $ah = 0; $mb = 0
        foreach ($r in $rows) {
            $cell = @($r.Cells | Where-Object { $_.TemplateId -eq $col.TemplateId })[0]
            if (-not $cell) { continue }
            switch ($cell.Status) {
                'UpToDate'     { $up++ }
                'Behind'       { $bh++; if ($cell.Behind -gt $mb) { $mb = $cell.Behind } }
                'NeverApplied' { $nv++; if ($cell.Behind -gt $mb) { $mb = $cell.Behind } }
                'Ahead'        { $ah++ }
            }
        }
        $perTemplate.Add([pscustomobject]@{
            TemplateId      = $col.TemplateId
            Workload        = $col.Workload
            TemplateVersion = $col.TemplateVersion
            UpToDate        = $up
            BehindCount     = $bh
            NeverCount      = $nv
            AheadCount      = $ah
            MaxBehind       = $mb
            NeedsRollout    = (($bh + $nv) -gt 0)
        })
    }

    $totalTenants = $rows.Count
    $currentTenants = @($rows | Where-Object { $_.Current }).Count
    return [pscustomobject]@{
        Templates       = @($cols)
        Tenants         = @($rows)
        PerTemplate     = @($perTemplate.ToArray())
        TotalTenants    = $totalTenants
        CurrentTenants  = $currentTenants
        BehindTenants   = ($totalTenants - $currentTenants)
    }
}

# --- RING-WIDE rollout plan (PURE) -- REQUIREMENTS.md s28 [H8] ------------------
# "Ring-wide deploy" view: for ONE approved template, which tenants would a deploy to
# a chosen ring touch, and where does each stand? A deploy to ring R reaches every
# tenant whose rollout ring is <= R (tenantRing <= entryRing is the per-entry rule, §77.20;
# here we group tenants by ring so an MSP can drive a wave -- "roll v3 to ring 1 and
# below" -- and see, per ring band, how many tenants are behind. This is the planning
# rollup; the actual per-tenant deploy still goes through the ring-gated
# Get-PimRollForwardRows -> desired-state commit -> engine path (no second apply).
#
# Returns, for the template, one band per distinct tenant ring present in the fleet,
# each with the tenants in that band + their behind/status, plus a fleet total. A
# tenant only appears in the band equal to its own ring (bands are exclusive); the
# "reached by a deploy to ring R" set is every band with ring <= R (the GUI sums them).
function Get-PimRingRolloutPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Template,
        [object[]]$Tenants = @()
    )
    $tv = [int]("$($Template.templateVersion)" -as [int]); if ($tv -lt 1) { $tv = 1 }
    $tid = "$($Template.templateId)"
    $approved = [bool](Test-PimTemplateApproved -Template $Template)

    # Build the per-tenant standing for THIS template.
    $perTenant = New-Object System.Collections.Generic.List[object]
    foreach ($tn in @($Tenants)) {
        if ($null -eq $tn) { continue }
        $ring = 2   # 77.20: an unknown tenant ring is the most restrictive (2 = broad, fully promoted only)
        if ($null -ne $tn.ring -and "$($tn.ring)" -ne '') {
            $pr = 0; if ([int]::TryParse("$($tn.ring)", [ref]$pr) -and $pr -ge 0 -and $pr -le 2) { $ring = $pr }
        }
        $have = 0
        if ($tn.appliedVersions) {
            if ($tn.appliedVersions -is [hashtable]) {
                if ($tn.appliedVersions.ContainsKey($tid)) { $have = [int]("$($tn.appliedVersions[$tid])" -as [int]) }
            } elseif ($tn.appliedVersions.PSObject.Properties[$tid]) {
                $have = [int]("$($tn.appliedVersions.PSObject.Properties[$tid].Value)" -as [int])
            }
        }
        $status =
            if ($have -le 0)        { 'NeverApplied' }
            elseif ($have -lt $tv)  { 'Behind' }
            elseif ($have -gt $tv)  { 'Ahead' }
            else                    { 'UpToDate' }
        $perTenant.Add([pscustomobject]@{
            TenantId = "$($tn.tenantId)"; Ring = $ring
            AppliedVersion = $have; Behind = [math]::Max(0, $tv - $have); Status = $status
        })
    }

    # Group into exclusive ring bands (ascending ring).
    $bands = New-Object System.Collections.Generic.List[object]
    foreach ($ring in @($perTenant | ForEach-Object { $_.Ring } | Sort-Object -Unique)) {
        $inBand = @($perTenant | Where-Object { $_.Ring -eq $ring } | Sort-Object -Property @{ Expression = { "$($_.TenantId)" } })
        $bh = @($inBand | Where-Object { $_.Status -eq 'Behind' }).Count
        $nv = @($inBand | Where-Object { $_.Status -eq 'NeverApplied' }).Count
        $bands.Add([pscustomobject]@{
            Ring         = $ring
            Tenants      = $inBand
            TenantCount  = $inBand.Count
            BehindCount  = $bh
            NeverCount   = $nv
            NeedsRollout = (($bh + $nv) -gt 0)
        })
    }

    $needs = @($perTenant | Where-Object { $_.Status -eq 'Behind' -or $_.Status -eq 'NeverApplied' })
    return [pscustomobject]@{
        TemplateId      = $tid
        Workload        = "$($Template.workload)"
        TemplateVersion = $tv
        Approved        = $approved
        Bands           = @($bands.ToArray())
        TotalTenants    = $perTenant.Count
        NeedsRolloutCount = $needs.Count
    }
}

# --- roll-forward ROWS seam -----------------------------------------------------
# Converts an APPROVED template into PIM-Assignments-Workloads desired-state rows
# (Workload;RoleName;GroupTag;Scope;Resource;Action). Ring-gated to the tenant;
# exemptions skipped. IMP-37: these rows are DESIRED STATE -- the Manager commits them
# into pim.Rows through its safe-commit path (POST /api/conformance/deploy) and the
# engine's workload provider applies them on its next run. There is no CSV and no
# Apply-PimWorkloadAssignments call (that v1 function does not exist in v2).
function Get-PimRollForwardRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Template,
        [Parameter(Mandatory)][int]$TenantRing,
        [string]$TenantId = '',
        [object[]]$Exemptions = @(),
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not (Test-PimTemplateApproved -Template $Template)) {
        throw "Template '$($Template.templateId)' is status '$($Template.status)', not 'approved' -- refusing to roll forward (drafts never deploy)."
    }
    $exKeys = @{}
    foreach ($k in @(Get-PimActiveExemptionKeys -Exemptions $Exemptions -TenantId "$TenantId" -TemplateId "$($Template.templateId)" -NowUtc $NowUtc)) { $exKeys["$k".ToLowerInvariant()] = $true }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Template.entries)) {
        $ring = Get-PimTemplateEntryRing -Entry $e
        if (-not (Test-PimRingInScope -EntryRing $ring -TenantRing $TenantRing)) { continue }   # ring-gated
        if ($exKeys.ContainsKey("$($e.key)".ToLowerInvariant())) { continue }                    # exemption skipped
        $roleName = if ("$($e.roleName)".Trim()) { "$($e.roleName)" } elseif ($e.value) { "$($e.value.roleName)" } else { '' }
        $groupTag = if ("$($e.groupTag)".Trim()) { "$($e.groupTag)" } elseif ($e.value) { "$($e.value.groupTag)" } else { '' }
        $scope    = if ($e.value -and $null -ne $e.value.scope) { "$($e.value.scope)" } else { '' }
        $resource = if ($e.value -and $null -ne $e.value.resource) { "$($e.value.resource)" } else { '' }
        $action   = if ("$($e.action)".Trim()) { "$($e.action)" } else { 'Assign' }
        $rows.Add([pscustomobject]@{ Workload = "$($Template.workload)"; RoleName = $roleName; GroupTag = $groupTag; Scope = $scope; Resource = $resource; Action = $action })
    }
    return $rows.ToArray()
}
