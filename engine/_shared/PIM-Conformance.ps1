# PIM4EntraPS -- native template versioning + fleet conformance.
# Dot-sourced by PIM-Functions.psm1 (and standalone by the pim-manager).
#
# Same model as the TenantManager conformance engine, applied to PIM WORKLOAD
# templates (a versioned set of PIM-group -> workload-role bindings):
#   - Rings drive rollout (entryRing <= tenantRing); templateVersion is a
#     changelog label, not the rollout control.
#   - Only status:"approved" templates are pullable/deployable; drafts never go.
#   - Absent desired binding = GAP unless an ACTIVE exemption -> EXEMPT.
#   - Exemptions ALWAYS require an expiry; expired -> lapses back to Gap.
#   - Applied version stays LOCAL (light state stamp).
#
# Pure reconcile core (time injected) + thin I/O wrappers, so every status
# decision is testable without a tenant. A roll-forward-ROWS seam converts an
# approved template into the workload-assignment rows that the existing,
# tested Apply-PimWorkloadAssignments consumes -- no second apply path.

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

function Read-PimApprovedTemplates {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceDir, [switch]$IncludeDrafts)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $SourceDir)) { Write-Warning "Template source dir not found: $SourceDir"; return $out.ToArray() }
    foreach ($f in Get-ChildItem -LiteralPath $SourceDir -Filter '*.template.json' -File | Sort-Object Name) {
        try { $t = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false))) }
        catch { Write-Warning ("Template {0} failed to parse: {1}" -f $f.Name, $_.Exception.Message); continue }
        $check = Test-PimTemplateDoc -Template $t
        if (-not $check.valid) { Write-Warning ("Template {0} invalid: {1}" -f $f.Name, ($check.errors -join '; ')); continue }
        if (-not $IncludeDrafts -and -not (Test-PimTemplateApproved -Template $t)) {
            Write-Host ("  [conformance] skipping draft (not pullable): {0} v{1}" -f $t.templateId, $t.templateVersion) -ForegroundColor DarkGray; continue
        }
        $out.Add($t)
    }
    return $out.ToArray()
}

# --- ring scope (self-contained; entryRing <= tenantRing) ------------------------
function Get-PimTemplateEntryRing {
    param([AllowNull()][object]$Entry)
    $r = 2
    if ($Entry -and $null -ne $Entry.PSObject.Properties['ring'] -and "$($Entry.ring)" -ne '') {
        $parsed = 2
        if ([int]::TryParse("$($Entry.ring)", [ref]$parsed) -and $parsed -ge 0 -and $parsed -le 9) { $r = $parsed }
    }
    return $r
}

function Test-PimRingInScope {
    param([Parameter(Mandatory)][int]$EntryRing, [Parameter(Mandatory)][int]$TenantRing)
    return ($EntryRing -le $TenantRing)
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
    $exp = [datetime]::MinValue
    if (-not [datetime]::TryParse($expRaw, [ref]$exp)) { return @{ valid = $false; active = $false; state = 'Invalid'; detail = "expiresUtc '$expRaw' is not a date" } }
    $expU = $exp.ToUniversalTime()
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
            $exp = [datetime]::MinValue
            if ([datetime]::TryParse("$($x.expiresUtc)".Trim(), [ref]$exp)) {
                $expU = $exp.ToUniversalTime()
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
            $entries.Add([pscustomobject]@{
                key = "role:$cap"; sinceVersion = $newVer; ring = 2
                roleName = "$cap"; groupTag = "PIM-REVIEW-$cap"
                value = [pscustomobject]@{ roleName = "$cap"; groupTag = "PIM-REVIEW-$cap"; note = 'AUTO-DRAFT: set groupTag + ring before approving' }
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
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateRange(0,9)][int]$Ring)
    $t = Copy-PimConfObject -Object $Template
    $hit = $false
    foreach ($e in @($t.entries)) { if ("$($e.key)" -ieq "$Key") { Set-PimConfProp -Object $e -Name 'ring' -Value $Ring; $hit = $true } }
    if (-not $hit) { throw "Set-PimEntryRing: template '$($t.templateId)' has no entry '$Key'." }
    return $t
}

# --- local applied-version stamp (I/O; version stays LOCAL) ----------------------
function Get-PimConfStateFile {
    param([string]$StateFile)
    if ($StateFile) { return $StateFile }
    if ($global:PIM_TemplateStateFile) { return $global:PIM_TemplateStateFile }
    $base = if ($global:PIM_OutputRoot) { $global:PIM_OutputRoot } else { Join-Path $PSScriptRoot '..\..\output' }
    return (Join-Path $base 'state\template-state.json')
}

function Get-PimTemplateState {
    param([string]$StateFile, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TemplateId)
    $file = Get-PimConfStateFile -StateFile $StateFile
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    try { $all = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    $p = $all.PSObject.Properties["$TenantId|$TemplateId"]
    if ($p) { return $p.Value }
    return $null
}

function Set-PimTemplateState {
    param(
        [string]$StateFile, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$TemplateId,
        [Parameter(Mandatory)][int]$Version, [string]$AppliedBy = "$env:USERNAME", [datetime]$NowUtc = [datetime]::UtcNow
    )
    $file = Get-PimConfStateFile -StateFile $StateFile
    $dir = Split-Path -Parent $file
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $all = [pscustomobject]@{}
    if (Test-Path -LiteralPath $file) { try { $all = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $all = [pscustomobject]@{} } }
    Set-PimConfProp -Object $all -Name "$TenantId|$TemplateId" -Value ([pscustomobject]@{ LastAppliedVersion = $Version; AppliedUtc = $NowUtc.ToString('o'); AppliedBy = $AppliedBy })
    $all | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding UTF8
    return $file
}

# --- FLEET state read (I/O seam for [H8]) ---------------------------------------
# Read ONE instance's conformance standing from its local template-state file, for the
# fleet matrix: every template's last-applied version (keyed "<tenantId>|<templateId>")
# plus an optional fleet `ring` stamp the deploy writes at the file root. Returns
# @{ appliedVersions = @{ '<templateId>' = <int> }; ring = <int?> }. Pure-ish (one read);
# returns empty maps when the file is absent/unparseable so a never-deployed tenant is
# still a valid fleet row (every cell = NeverApplied). $TenantId selects this instance's
# rows from a shared state file (the Manager keys state by instance name).
function Get-PimFleetStateForInstance {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StateFile, [Parameter(Mandatory)][string]$TenantId)
    $applied = @{}
    $ring = $null
    if (-not (Test-Path -LiteralPath $StateFile)) { return @{ appliedVersions = $applied; ring = $ring } }
    $all = $null
    try {
        $raw = [System.IO.File]::ReadAllText($StateFile, [System.Text.UTF8Encoding]::new($false))
        if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        $all = $raw | ConvertFrom-Json
    } catch { return @{ appliedVersions = $applied; ring = $ring } }
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
# State lives in the SAME local state file as the template stamp, under a distinct
# "scopeVersions" map keyed "<tenantId>|<scope>" -> { LastAppliedVersion; AppliedUtc;
# AppliedBy }. Pure matrix builder (Get-PimScopeConformance) takes the desired
# versions (template-version per scope) + the applied versions (from state) and
# returns one annotated row per scope. Fully testable; no Graph, no SQL.

function Get-PimScopeAppliedVersion {
    # Applied template version for ONE scope of ONE tenant; 0 if never applied.
    param([string]$StateFile, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Scope)
    $file = Get-PimConfStateFile -StateFile $StateFile
    if (-not (Test-Path -LiteralPath $file)) { return 0 }
    try { $all = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return 0 }
    if (-not $all.PSObject.Properties['scopeVersions']) { return 0 }
    $p = $all.scopeVersions.PSObject.Properties["$TenantId|$Scope"]
    if ($p -and $p.Value -and $p.Value.PSObject.Properties['LastAppliedVersion']) { return [int]("$($p.Value.LastAppliedVersion)" -as [int]) }
    return 0
}

function Set-PimScopeAppliedVersion {
    # Stamp the applied template version for ONE scope of ONE tenant (LOCAL state).
    param(
        [string]$StateFile, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][int]$Version, [string]$AppliedBy = "$env:USERNAME", [datetime]$NowUtc = [datetime]::UtcNow
    )
    $file = Get-PimConfStateFile -StateFile $StateFile
    $dir = Split-Path -Parent $file
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $all = [pscustomobject]@{}
    if (Test-Path -LiteralPath $file) { try { $all = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $all = [pscustomobject]@{} } }
    if (-not $all.PSObject.Properties['scopeVersions']) { Set-PimConfProp -Object $all -Name 'scopeVersions' -Value ([pscustomobject]@{}) }
    Set-PimConfProp -Object $all.scopeVersions -Name "$TenantId|$Scope" -Value ([pscustomobject]@{ LastAppliedVersion = $Version; AppliedUtc = $NowUtc.ToString('o'); AppliedBy = $AppliedBy })
    $all | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding UTF8
    return $file
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
        $ring = 0
        if ($null -ne $tn.ring -and "$($tn.ring)" -ne '') {
            $pr = 0; if ([int]::TryParse("$($tn.ring)", [ref]$pr) -and $pr -ge 0 -and $pr -le 9) { $ring = $pr }
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
# tenant whose rollout ring is >= R (entryRing <= tenantRing is the per-entry rule;
# here we group tenants by ring so an MSP can drive a wave -- "roll v3 to ring 1 and
# below" -- and see, per ring band, how many tenants are behind. This is the planning
# rollup; the actual per-tenant deploy still goes through the proven, ring-gated
# Get-PimRollForwardRows + Apply-PimWorkloadAssignments path (no second apply).
#
# Returns, for the template, one band per distinct tenant ring present in the fleet,
# each with the tenants in that band + their behind/status, plus a fleet total. A
# tenant only appears in the band equal to its own ring (bands are exclusive); the
# "reached by a deploy to ring R" set is every band with ring >= R (the GUI sums them).
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
        $ring = 0
        if ($null -ne $tn.ring -and "$($tn.ring)" -ne '') {
            $pr = 0; if ([int]::TryParse("$($tn.ring)", [ref]$pr) -and $pr -ge 0 -and $pr -le 9) { $ring = $pr }
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
# Converts an APPROVED template into the workload-assignment rows that the
# existing Apply-PimWorkloadAssignments consumes (Workload;RoleName;GroupTag;
# Scope;Resource;Action). Ring-gated to the tenant; exemptions skipped. No second
# apply path -- the GUI/engine writes these rows to a CSV and calls the proven
# Apply-PimWorkloadAssignments.
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
