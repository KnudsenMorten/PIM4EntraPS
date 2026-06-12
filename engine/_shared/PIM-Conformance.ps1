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
