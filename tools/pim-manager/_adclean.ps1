<#
  _adclean.ps1 -- the Manager's server half of PIM 100.123 (lane adclean, 2026-10-13). Dot-sourced by Open-PimManager.ps1;
  ONE route block there hands every path below to Invoke-PimAdCleanRoute, which answers @{ status; body }.

    GET  /api/hybrid-ad/cleanup                 the old PIM groups the worker reported, what is approved, what happened   (Admin)
    POST /api/hybrid-ad/cleanup/approve         approve the EXACT list for deletion in Active Directory                   (SuperAdmin)
    POST /api/hybrid-ad/cleanup/withdraw        take an approval back before the worker acted                             (SuperAdmin)
    POST /api/hybrid-ad/cleanup/also-delete     "delete in AD too" for a group that is being deleted in PIM Manager       (SuperAdmin)
    GET  /api/hybrid-ad/waiting                 the AD groups whose membership sync waits for a SuperAdmin                (Admin)
    POST /api/hybrid-ad/waiting/decide          the SuperAdmin's decision for exactly one waiting group                   (SuperAdmin)
    GET  /api/hybrid-ad/server-groups/waiting   the new servers above the batch size that wait for ONE approval           (Admin)
    POST /api/hybrid-ad/server-groups/approve   approve that exact list: the next run creates all of its server groups    (SuperAdmin)
    GET  /api/settings/hybrid-ad-discovery      server discovery filters, automatic OUs, clean-up OUs                     (any role)
    PUT  /api/settings/hybrid-ad-discovery      save them                                                                 (SuperAdmin)
    POST /api/hybrid-ad/discovery/preview       "with these settings the worker finds N servers" (the worker's last list) (Admin)

  The Manager never talks to Active Directory: it reads what the hybrid worker wrote into the store and writes records the
  worker pulls. Every role check is made HERE, on the server; every write is audited (who, when, what, the reason given).

  THE DECISIONS RECORD (written by /api/hybrid-ad/waiting/decide, read by the membership sync -- the reader defines it):
    settings row 'HybridAdSyncMemory.<job>.decisions' = { "v": 1, "groups": { "<AD group name>": { "kind", "forEntraGroupId",
    "decidedBy", "decidedAtEpoch" (a NUMBER), "reason", and EITHER "adoptEntraGroupId" OR "removeMembers": [ ... ] } } }.
  A decision is written only for a group that is in the sync's CURRENT waiting record, in exactly the state (kind + Entra
  group id) the SuperAdmin saw; removeMembers only names accounts of that entry's members list.
#>

if (-not (Get-Command Get-PimHybridAdDiscoverySettingCatalog -ErrorAction SilentlyContinue)) {
    $_adcDisc = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'engine\hybrid-ad\PIM-HybridAdServerDiscovery.ps1'
    if (Test-Path -LiteralPath $_adcDisc) { . $_adcDisc }
}
if (-not (Get-Command Get-PimHybridAdCleanupDecision -ErrorAction SilentlyContinue)) {
    $_adcClean = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'engine\hybrid-ad\PIM-HybridAdCleanup.ps1'
    if (Test-Path -LiteralPath $_adcClean) { . $_adcClean }
}

$script:PimAdCleanSyncJobs = @('hybrid-ad-sync', 'hybrid-ad-sync-servers')
$script:PimAdCleanGroupEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization',
    'PIM-Definitions-Tasks', 'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects',
    'PIM-Definitions-CrossOrg', 'PIM-Definitions-Resources')
function Get-PimAdCleanReportMaxAgeHours { return 26 }      # a candidate list older than this cannot be approved (the worker reports hourly)
function Get-PimAdCleanDecisionMaxHours { return 48 }       # the sync uses a decision for this long (its own rule; shown on the page)

function Get-PimAdCleanStore {
    <#
      The store seam: tests set $script:PimAdCleanStore. Default = the Manager's SQL store.
        ReadRaw      { param($name) -> the settings row's JSON text | $null; THROWS when the store cannot be read }
        WriteRaw     { param($name, $json, $expected) -> $true written | $false the row changed meanwhile } (compare-and-set)
        ReadCache    { param($kind) -> the tenant-cache document's JSON text | $null }
        ReadRows     { param($entity) -> the definition rows }
        ReadText     { param($name) -> the effective text of a simple settings row ('' = not set) }
        WriteSetting { param($name, $text) } ('' = back to the default)
    #>
    if ($script:PimAdCleanStore -is [hashtable]) { return $script:PimAdCleanStore }
    return @{
        ReadRaw = { param($n) Get-PimSqlSettingRaw -ConnectionString (Get-PimManagerSettingCs) -Name $n }
        WriteRaw = { param($n, $json, $expected) ([int](Set-PimSqlSettingIfUnchanged -ConnectionString (Get-PimManagerSettingCs) -Name "$n" -NewValueJson "$json" -ExpectedValueJson $expected) -gt 0) }
        ReadCache = {
            param($kind)
            $j = Invoke-PimSqlScalar -ConnectionString (Get-PimManagerSettingCs) -Sql 'SELECT ValueJson FROM pim.TenantCache WHERE Kind=@k' -Parameters @{ k = "$kind" }
            if ($null -eq $j -or $j -is [System.DBNull] -or "$j".Trim() -eq '') { return $null }
            "$j"
        }
        ReadRows = { param($e) @(Get-PimSqlRows -ConnectionString (Get-PimManagerSettingCs) -Entity $e) }
        ReadText = { param($n) "$(Get-PimHybridAdDiscoveryRawSetting -Name $n -Default '')".Trim() }
        WriteSetting = {
            param($n, $text)
            Set-PimManagerSetting -Name $n -Value $(if ("$text") { "$text" } else { $null })
            if ($global:PIM_NamingConventions -is [System.Collections.IDictionary]) { $global:PIM_NamingConventions[$n] = $(if ("$text") { "$text" } else { $null }) }
        }
    }
}

function ConvertFrom-PimAdCleanJson {
    # Parse stored JSON WITHOUT turning date text into dates (PowerShell 7's ConvertFrom-Json does). $null for blank text.
    param([AllowNull()][string]$Json)
    if (-not "$Json".Trim()) { return $null }
    if (Get-Command ConvertFrom-PimSharedPendingJson -ErrorAction SilentlyContinue) { return (ConvertFrom-PimSharedPendingJson -Json $Json) }
    return ($Json | ConvertFrom-Json)
}

function Get-PimAdCleanCaller {
    # Who is asking, decided on the server: @{ identity; role; admin; super }.
    $who = ''; $role = ''
    try { $r = Get-PimManagerRole; if ($r) { $who = "$($r.identity)".Trim(); $role = "$($r.role)".Trim() } } catch { $who = ''; $role = '' }
    $admin = $false; $super = $false
    try { $admin = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin') } catch { $admin = $false }
    try { $super = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $super = $false }
    return @{ identity = $who; role = $(if ($role) { $role } else { 'Reader' }); admin = $admin; super = $super }
}

function Get-PimAdCleanBodyValue {
    param($Body, [string]$Name)
    return (Get-PimHybridAdCleanupField $Body $Name)
}

function Get-PimAdCleanReason {
    # The reason a person typed: trimmed, at most 500 characters; '' when none.
    param($Body)
    $t = "$(Get-PimAdCleanBodyValue $Body 'reason')".Trim()
    if ($t.Length -gt 500) { $t = $t.Substring(0, 500) }
    return $t
}

function Get-PimAdCleanEpoch { return (Get-PimHybridAdCleanupEpoch -NowUtc ([datetime]::UtcNow)) }

function Read-PimAdCleanCandidateReport {
    <#
      The worker's candidate report (tenant cache 'ad-cleanup-candidates'): @{ found; ok; reason; ageHours; stale;
      refreshedUtc; refreshedEpoch; host; planOnly; ous[]; pattern; candidates[] (hashtables); notOffered[]; byId }.
      found = $false when the worker never reported; THROWS when the store cannot be read.
    #>
    $store = Get-PimAdCleanStore
    $raw = & $store.ReadCache 'ad-cleanup-candidates'
    $out = @{ found = $false; ok = $false; reason = ''; ageHours = $null; stale = $true; refreshedUtc = ''; refreshedEpoch = [long]0; host = ''; planOnly = $false; ous = @(); pattern = ''; candidates = @(); notOffered = @(); byId = @{}; mirroredByName = @{} }
    $doc = ConvertFrom-PimAdCleanJson "$raw"
    if ($null -eq $doc) { $out.reason = 'The hybrid worker has not reported yet. It lists the old PIM groups at every run of its "Group definitions" job (hourly).'; return $out }
    $out.found = $true
    $out.ok = ((Get-PimHybridAdCleanupField $doc 'ok') -is [bool]) -and [bool](Get-PimHybridAdCleanupField $doc 'ok')
    $out.reason = "$(Get-PimHybridAdCleanupField $doc 'reason')"
    $out.refreshedUtc = "$(Get-PimHybridAdCleanupField $doc 'refreshedUtc')"
    $ep = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $doc 'refreshedEpoch')", [ref]$ep); $out.refreshedEpoch = $ep
    if ($ep -gt 0) { $out.ageHours = [math]::Round(((Get-PimAdCleanEpoch) - $ep) / 3600.0, 1); $out.stale = [bool]($out.ageHours -gt (Get-PimAdCleanReportMaxAgeHours)) }
    $out.host = "$(Get-PimHybridAdCleanupField $doc 'host')"
    $out.planOnly = [bool](Get-PimHybridAdCleanupField $doc 'planOnly')
    $out.ous = @(Get-PimHybridAdCleanupField $doc 'ous' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
    $out.pattern = "$(Get-PimHybridAdCleanupField $doc 'pattern')"
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-PimHybridAdCleanupField $doc 'candidates')) {
        if ($null -eq $c) { continue }
        $h = [ordered]@{
            id = "$(Get-PimHybridAdCleanupField $c 'id')"; name = "$(Get-PimHybridAdCleanupField $c 'name')"; dn = "$(Get-PimHybridAdCleanupField $c 'dn')"
            created = "$(Get-PimHybridAdCleanupField $c 'created')"; changed = "$(Get-PimHybridAdCleanupField $c 'changed')"; description = "$(Get-PimHybridAdCleanupField $c 'description')"
            memberCount = 0; members = @(Get-PimHybridAdCleanupField $c 'members' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
            membersTruncated = [bool](Get-PimHybridAdCleanupField $c 'membersTruncated')
            memberOf = @(Get-PimHybridAdCleanupField $c 'memberOf' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
            server = "$(Get-PimHybridAdCleanupField $c 'server')"; serverInAd = (Get-PimHybridAdCleanupField $c 'serverInAd')
        }
        $mc = 0; [void][int]::TryParse("$(Get-PimHybridAdCleanupField $c 'memberCount')", [ref]$mc); $h.memberCount = $mc
        # the id is recomputed here from the object's own facts: an approval never rests on an id somebody could have typed
        if (-not $h.name -or -not $h.dn -or -not $h.created -or $h.id -ne (Get-PimHybridAdCleanupId -Dn $h.dn -Created $h.created)) { continue }
        $list.Add($h); $out.byId[$h.id] = $h
    }
    $out.candidates = $list.ToArray()
    $out.notOffered = @(foreach ($n in @(Get-PimHybridAdCleanupField $doc 'notOffered')) { if ($n) { [ordered]@{ name = "$(Get-PimHybridAdCleanupField $n 'name')"; reason = "$(Get-PimHybridAdCleanupField $n 'reason')" } } })
    # CODE REVIEW 1 FIXES 2026-10-13 (finding 6): the AD objects of the DEFINED mirrored groups (mirrored[]), by lower name --
    # "delete in AD too" pins the exact object from here. A name two objects carry is left out (never pinned on a guess).
    $mirBy = @{}; $mirDup = @{}
    foreach ($m in @(Get-PimHybridAdCleanupField $doc 'mirrored')) {
        if ($null -eq $m) { continue }
        $nm = "$(Get-PimHybridAdCleanupField $m 'name')".Trim(); $mdn = "$(Get-PimHybridAdCleanupField $m 'dn')".Trim(); $mcr = "$(Get-PimHybridAdCleanupField $m 'created')".Trim()
        if (-not $nm -or -not $mdn -or -not $mcr) { continue }
        $k = $nm.ToLowerInvariant()
        if ($mirBy.ContainsKey($k)) { $mirDup[$k] = $true; continue }
        $mc2 = 0; [void][int]::TryParse("$(Get-PimHybridAdCleanupField $m 'memberCount')", [ref]$mc2)
        $mirBy[$k] = [ordered]@{ name = $nm; dn = $mdn; created = $mcr; memberCount = $mc2; membersTruncated = [bool](Get-PimHybridAdCleanupField $m 'membersTruncated')
            members = @(Get-PimHybridAdCleanupField $m 'members' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }); memberOf = @(Get-PimHybridAdCleanupField $m 'memberOf' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
    }
    foreach ($k in @($mirDup.Keys)) { $mirBy.Remove($k) }
    $out['mirroredByName'] = $mirBy
    return $out
}

function Read-PimAdCleanApprovalDoc {
    # The approval record: @{ raw (the stored text | $null); items (ordered: id -> entry); also (ordered: lower name -> entry) }.
    # A stored row that cannot be parsed is treated as EMPTY for writing a new one (the worker ignores an unreadable row).
    $store = Get-PimAdCleanStore
    $raw = & $store.ReadRaw 'HybridAdCleanupApproval'
    $items = [ordered]@{}; $also = [ordered]@{}
    $doc = $null; try { $doc = ConvertFrom-PimAdCleanJson "$raw" } catch { $doc = $null }
    if ($doc -and "$(Get-PimHybridAdCleanupField $doc 'v')" -eq '1') {
        $m = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $doc 'items'); foreach ($k in @($m.Keys | Sort-Object)) { $items["$k"] = $m[$k] }
        $a = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $doc 'alsoDelete'); foreach ($k in @($a.Keys | Sort-Object)) { $also["$k"] = $a[$k] }
    }
    return @{ raw = $(if ($null -eq $raw) { $null } else { "$raw" }); items = $items; also = $also }
}

function Save-PimAdCleanApprovalDoc {
    # Write the approval record (compare-and-set against what was read). Expired entries are dropped. Returns $true / $false.
    param([Parameter(Mandatory)][hashtable]$Doc)
    $now = Get-PimAdCleanEpoch
    $items = [ordered]@{}
    foreach ($k in @($Doc.items.Keys)) { $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $Doc.items[$k] 'approvedAtEpoch')", [ref]$at); if ($at -gt 0 -and ($now - $at) -le ([long](Get-PimHybridAdCleanupApprovalMaxHours) * 3600)) { $items["$k"] = $Doc.items[$k] } }
    $also = [ordered]@{}
    foreach ($k in @($Doc.also.Keys)) { $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $Doc.also[$k] 'requestedAtEpoch')", [ref]$at); if ($at -gt 0 -and ($now - $at) -le ([long](Get-PimHybridAdCleanupAlsoDeleteMaxDays) * 86400)) { $also["$k"] = $Doc.also[$k] } }
    $json = ([ordered]@{ v = 1; items = $items; alsoDelete = $also }) | ConvertTo-Json -Depth 8 -Compress
    $store = Get-PimAdCleanStore
    return [bool](& $store.WriteRaw 'HybridAdCleanupApproval' $json $Doc.raw)
}

function Get-PimAdCleanCleanupView {
    $me = Get-PimAdCleanCaller
    if (-not $me.admin) { return @{ status = 403; body = [ordered]@{ error = 'Admin role required to see the Active Directory clean-up list.' } } }
    try {
        $rep = Read-PimAdCleanCandidateReport
        $ap = Read-PimAdCleanApprovalDoc
        $store = Get-PimAdCleanStore
        $resDoc = $null; try { $resDoc = ConvertFrom-PimAdCleanJson "$(& $store.ReadRaw 'AdCleanupResult')" } catch { $resDoc = $null }
        $res = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $resDoc 'items')
        $laDoc = $null; try { $laDoc = ConvertFrom-PimAdCleanJson "$(& $store.ReadRaw 'AdCleanupLocalAdmin')" } catch { $laDoc = $null }
        $la = @{}; $lm = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $laDoc 'groups'); foreach ($k in @($lm.Keys)) { $la["$k".ToLowerInvariant()] = $lm[$k] }
        $now = Get-PimAdCleanEpoch
        $cands = @(foreach ($c in @($rep.candidates)) {
                $o = [ordered]@{}; foreach ($k in @($c.Keys)) { $o[$k] = $c[$k] }
                $a = $ap.items[$c.id]
                $o['approved'] = $null
                if ($a) { $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $a 'approvedAtEpoch')", [ref]$at); if ($at -gt 0 -and ($now - $at) -le ([long](Get-PimHybridAdCleanupApprovalMaxHours) * 3600)) { $o['approved'] = [ordered]@{ by = "$(Get-PimHybridAdCleanupField $a 'approvedBy')"; atEpoch = $at; withoutServer = [bool](Get-PimHybridAdCleanupField $a 'withoutServer'); reason = "$(Get-PimHybridAdCleanupField $a 'reason')" } } }
                $al = $ap.also[$c.name.ToLowerInvariant()]
                $o['alsoDelete'] = $(if ($al) { [ordered]@{ by = "$(Get-PimHybridAdCleanupField $al 'requestedBy')"; atEpoch = (Get-PimHybridAdCleanupField $al 'requestedAtEpoch') } } else { $null })
                $r = $res[$c.id]; if (-not $r) { $r = $res["also:$($c.name.ToLowerInvariant())"] }
                $o['result'] = $(if ($r) { [ordered]@{ status = "$(Get-PimHybridAdCleanupField $r 'status')"; reason = "$(Get-PimHybridAdCleanupField $r 'reason')"; atEpoch = (Get-PimHybridAdCleanupField $r 'atEpoch') } } else { $null })
                $l = $la[$c.name.ToLowerInvariant()]
                $o['localAdmin'] = $(if ($l) { [ordered]@{ status = "$(Get-PimHybridAdCleanupField $l 'status')"; server = "$(Get-PimHybridAdCleanupField $l 'server')"; atEpoch = (Get-PimHybridAdCleanupField $l 'atEpoch') } } else { $null })
                $o
            })
        $all = @(foreach ($k in @($res.Keys)) { $r = $res[$k]; [ordered]@{ name = "$(Get-PimHybridAdCleanupField $r 'name')"; dn = "$(Get-PimHybridAdCleanupField $r 'dn')"; status = "$(Get-PimHybridAdCleanupField $r 'status')"; reason = "$(Get-PimHybridAdCleanupField $r 'reason')"; approvedBy = "$(Get-PimHybridAdCleanupField $r 'approvedBy')"; atEpoch = (Get-PimHybridAdCleanupField $r 'atEpoch') } })
        $history = @($all | Sort-Object { $v = [long]0; [void][long]::TryParse("$($_.atEpoch)", [ref]$v); $v } -Descending | Select-Object -First 100)
        $waitingAlso = @(foreach ($k in @($ap.also.Keys)) { $x = $ap.also[$k]; [ordered]@{ name = "$(Get-PimHybridAdCleanupField $x 'name')"; by = "$(Get-PimHybridAdCleanupField $x 'requestedBy')"; atEpoch = (Get-PimHybridAdCleanupField $x 'requestedAtEpoch') } })
        return @{ status = 200; body = [ordered]@{
                canApprove = [bool]$me.super; role = $me.role
                report = [ordered]@{ found = [bool]$rep.found; ok = [bool]$rep.ok; reason = "$($rep.reason)"; refreshedUtc = "$($rep.refreshedUtc)"; refreshedEpoch = $rep.refreshedEpoch; ageHours = $rep.ageHours; stale = [bool]$rep.stale
                    host = "$($rep.host)"; planOnly = [bool]$rep.planOnly; ous = @($rep.ous); pattern = "$($rep.pattern)" }
                candidates = $cands; notOffered = @($rep.notOffered); alsoDelete = $waitingAlso; history = $history
                approvalMaxHours = (Get-PimHybridAdCleanupApprovalMaxHours); reportMaxAgeHours = (Get-PimAdCleanReportMaxAgeHours) } }
    } catch { return @{ status = 503; body = [ordered]@{ error = "the clean-up list could not be read: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanApprove {
    <#
      POST /api/hybrid-ad/cleanup/approve { ids: [ ... ], withoutServer: [ ids ], count: <n the confirmation showed>,
      confirm: true, reason: "..." }. SuperAdmin only. Every id must be in the worker's CURRENT report, which must be a
      good one (ok) and not older than 26 hours; ONE unknown id refuses the whole request. The approval entries are built
      from the worker's report -- name, distinguished name, creation date, members, member-of -- never from the request.
    #>
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) { return @{ status = 403; body = [ordered]@{ ok = $false; error = "SuperAdmin role required to approve the deletion of Active Directory groups (you are signed in as $($me.role)). An Admin can see the list; a SuperAdmin approves it." } } }
    if (-not $me.identity) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Your sign-in could not be identified, so the approval could not be recorded under a name. Nothing was approved.' } } }
    $ids = @(Get-PimAdCleanBodyValue $Body 'ids' | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $ids.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'ids (the groups to delete) is required. Nothing was approved.' } } }
    $reason = Get-PimAdCleanReason $Body
    if (-not $reason) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'A reason is required. Nothing was approved.' } } }
    $seen = 0; [void][int]::TryParse("$(Get-PimAdCleanBodyValue $Body 'count')".Trim(), [ref]$seen)
    $confirmed = ((Get-PimAdCleanBodyValue $Body 'confirm') -is [bool]) -and [bool](Get-PimAdCleanBodyValue $Body 'confirm')
    if (-not $confirmed -or $seen -ne $ids.Count) { return @{ status = 409; body = [ordered]@{ ok = $false; needsConfirm = $true; count = $ids.Count; error = "Deleting $($ids.Count) group(s) in Active Directory needs your confirmation of exactly that number. Nothing was approved." } } }
    try {
        $rep = Read-PimAdCleanCandidateReport
        if (-not $rep.found) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "$($rep.reason) Nothing was approved." } } }
        if (-not $rep.ok) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The worker's last report proposes nothing ($($rep.reason)). Nothing was approved." } } }
        if ($rep.stale) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The worker's list is $($rep.ageHours) hours old (more than $(Get-PimAdCleanReportMaxAgeHours)). Wait for its next report and review the list again. Nothing was approved." } } }
        $unknown = @($ids | Where-Object { -not $rep.byId.ContainsKey($_) })
        if ($unknown.Count) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "$($unknown.Count) of the selected groups are not in the worker's current list any more. Load the page again and review the list. Nothing was approved."; unknown = $unknown } } }
        $without = @{}; foreach ($w in @(Get-PimAdCleanBodyValue $Body 'withoutServer')) { if ("$w".Trim()) { $without["$w".Trim()] = $true } }
        $now = Get-PimAdCleanEpoch
        for ($try = 1; $try -le 2; $try++) {
            $ap = Read-PimAdCleanApprovalDoc
            foreach ($id in $ids) {
                $c = $rep.byId[$id]
                $ap.items[$id] = [ordered]@{ name = $c.name; dn = $c.dn; created = $c.created; memberCount = [int]$c.memberCount; membersTruncated = [bool]$c.membersTruncated
                    members = [string[]]@($c.members); memberOf = [string[]]@($c.memberOf); withoutServer = [bool]($c.server -and $without.ContainsKey($id))
                    approvedBy = $me.identity; approvedAtEpoch = $now; reason = $reason }
            }
            if (Save-PimAdCleanApprovalDoc -Doc $ap) {
                foreach ($id in $ids) {
                    $c = $rep.byId[$id]
                    Write-PimManagerAuditEvent -Action 'hybrid-ad.cleanup.approve' -Target "$($c.dn)" -After ([ordered]@{ group = $c.name; created = $c.created; members = [int]$c.memberCount; memberOf = @($c.memberOf).Count; server = $c.server; withoutServer = [bool]($c.server -and $without.ContainsKey($id)); reason = $reason; approvedAtEpoch = $now }) -Result 'ok'
                }
                return @{ status = 200; body = [ordered]@{ ok = $true; approved = $ids.Count
                        note = "Approved $($ids.Count) group(s). The hybrid worker deletes them at its next run -- each one only if it is still the same object, still has no definition in PIM Manager and gained no member since this review. The approval is valid for $(Get-PimHybridAdCleanupApprovalMaxHours) hours; the outcome of each group is shown here." } }
            }
        }
        return @{ status = 409; body = [ordered]@{ ok = $false; error = 'Somebody else changed the approvals at the same moment. Load the page again. Nothing was approved.' } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the approval was NOT saved: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanWithdraw {
    # POST /api/hybrid-ad/cleanup/withdraw { ids: [ ... ], names: [ ... ] } -- SuperAdmin. Takes approvals (ids) and "delete in
    # AD too" requests (names) back. What the worker already deleted stays deleted.
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) { return @{ status = 403; body = [ordered]@{ ok = $false; error = "SuperAdmin role required to take back an approval (you are signed in as $($me.role))." } } }
    $ids = @(Get-PimAdCleanBodyValue $Body 'ids' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $names = @(Get-PimAdCleanBodyValue $Body 'names' | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if (-not $ids.Count -and -not $names.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'ids or names is required.' } } }
    try {
        for ($try = 1; $try -le 2; $try++) {
            $ap = Read-PimAdCleanApprovalDoc
            $gone = New-Object System.Collections.Generic.List[string]
            foreach ($id in $ids) { if ($ap.items.Contains($id)) { $gone.Add("$(Get-PimHybridAdCleanupField $ap.items[$id] 'name')"); $ap.items.Remove($id) } }
            foreach ($n in $names) { if ($ap.also.Contains($n)) { $gone.Add("$(Get-PimHybridAdCleanupField $ap.also[$n] 'name')"); $ap.also.Remove($n) } }
            if (-not $gone.Count) { return @{ status = 200; body = [ordered]@{ ok = $true; withdrawn = 0; note = 'None of these was approved (any more).' } } }
            if (Save-PimAdCleanApprovalDoc -Doc $ap) {
                Write-PimManagerAuditEvent -Action 'hybrid-ad.cleanup.withdraw' -Target 'HybridAdCleanupApproval' -After ([ordered]@{ groups = $gone.ToArray(); reason = (Get-PimAdCleanReason $Body) }) -Result 'ok'
                return @{ status = 200; body = [ordered]@{ ok = $true; withdrawn = $gone.Count; note = "Taken back for $($gone.Count) group(s). A group the worker already deleted stays deleted." } }
            }
        }
        return @{ status = 409; body = [ordered]@{ ok = $false; error = 'Somebody else changed the approvals at the same moment. Load the page again.' } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the change was NOT saved: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanAlsoDelete {
    <#
      POST /api/hybrid-ad/cleanup/also-delete { groups: [ "<group name>", ... ], reason } -- SuperAdmin. "Delete in AD too":
      for groups that are DEFINED in PIM Manager now, match the mirrored naming and are being deleted. The worker acts only
      after the definition is gone and the Entra group of that name is gone (30 days at most). A name that is not a
      defined, mirrored group refuses the whole request (an undefined group is the clean-up review's job).
    #>
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) { return @{ status = 403; body = [ordered]@{ ok = $false; error = "SuperAdmin role required to have an Active Directory group deleted with its PIM Manager group (you are signed in as $($me.role)). Without it the AD group stays and is listed on the clean-up review." } } }
    if (-not $me.identity) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Your sign-in could not be identified. Nothing was recorded.' } } }
    $names = @(Get-PimAdCleanBodyValue $Body 'groups' | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'groups (the group names) is required.' } } }
    $reason = Get-PimAdCleanReason $Body
    if (-not $reason) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'A reason is required. Nothing was recorded.' } } }
    try {
        $store = Get-PimAdCleanStore
        $defined = @{}
        foreach ($e in $script:PimAdCleanGroupEntities) { foreach ($r in @(& $store.ReadRows $e)) { if ($r -and "$($r.GroupName)".Trim()) { $defined["$($r.GroupName)".Trim().ToLowerInvariant()] = "$($r.GroupName)".Trim() } } }
        $pattern = ''; if (Get-Command Get-PimHybridAdGroupPattern -ErrorAction SilentlyContinue) { $pattern = "$(Get-PimHybridAdGroupPattern)" }
        if (-not (Test-PimHybridAdCleanupPattern $pattern)) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'The naming of the groups mirrored to Active Directory is not set narrowly enough. Nothing was recorded.' } } }
        $bad = @($names | Where-Object { -not $defined.ContainsKey($_.ToLowerInvariant()) -or $defined[$_.ToLowerInvariant()] -notlike $pattern })
        if ($bad.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = "Not a group that is defined in PIM Manager and mirrored to Active Directory: $($bad -join ', '). Nothing was recorded."; unknown = $bad } } }
        # CODE REVIEW 1 FIXES 2026-10-13 (lane review1, finding 6): the request PINS the exact AD object -- distinguished name,
        # creation date, members, member-of -- from the worker's current report, and the worker checks it like a reviewed
        # item (a moved / re-created object, or one that gained a member or a member-of, is not deleted). No current report,
        # or a group the report does not hold (exactly once), refuses the whole request: nothing is pinned by name only.
        $rep = Read-PimAdCleanCandidateReport
        if (-not $rep.found -or $rep.stale) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The hybrid worker's report is $(if (-not $rep.found) { 'missing' } else { "$($rep.ageHours) hours old" }), so the AD objects cannot be pinned. Wait for its next run (hourly). Nothing was recorded." } } }
        $noObj = @($names | Where-Object { -not $rep.mirroredByName.ContainsKey($_.ToLowerInvariant()) })
        if ($noObj.Count) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The worker's report holds no single AD object for: $($noObj -join ', ') (not mirrored yet, outside the configured OUs, or two objects carry the name). Nothing was recorded."; unknown = $noObj } } }
        $now = Get-PimAdCleanEpoch
        for ($try = 1; $try -le 2; $try++) {
            $ap = Read-PimAdCleanApprovalDoc
            foreach ($n in $names) {
                $o = $rep.mirroredByName[$n.ToLowerInvariant()]
                $ap.also[$n.ToLowerInvariant()] = [ordered]@{ name = $defined[$n.ToLowerInvariant()]; requestedBy = $me.identity; requestedAtEpoch = $now; reason = $reason
                    dn = "$($o.dn)"; created = "$($o.created)"; memberCount = [int]$o.memberCount; membersTruncated = [bool]$o.membersTruncated; members = [string[]]@($o.members); memberOf = [string[]]@($o.memberOf) }
            }
            if (Save-PimAdCleanApprovalDoc -Doc $ap) {
                foreach ($n in $names) { Write-PimManagerAuditEvent -Action 'hybrid-ad.cleanup.also-delete' -Target "group:$($defined[$n.ToLowerInvariant()])" -After ([ordered]@{ reason = $reason; requestedAtEpoch = $now }) -Result 'ok' }
                return @{ status = 200; body = [ordered]@{ ok = $true; recorded = $names.Count; note = "Recorded for $($names.Count) group(s): once the group is deleted in PIM Manager and in Microsoft Entra ID, the hybrid worker also takes its AD group out of its server's local Administrators and deletes it in Active Directory." } }
            }
        }
        return @{ status = 409; body = [ordered]@{ ok = $false; error = 'Somebody else changed the approvals at the same moment. Try again.' } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the request was NOT saved: $($_.Exception.Message)" } } }
}

# ---------------------------------------------------------------------------------------------------------------------
# The AD sync's waiting groups (owner decisions (13) + (26)): the SuperAdmin approval
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAdCleanKindText {
    param([string]$Kind)
    switch ("$Kind".Trim().ToLowerInvariant()) {
        'gone' { return 'The Entra group behind this AD group is confirmed deleted. The members listed have no time limit, so they stay until a SuperAdmin decides.' }
        'never-seen' { return 'No Entra group of this name has ever been seen for this AD group. The members listed stay until a SuperAdmin decides.' }
        'replaced' { return 'A DIFFERENT Entra group now carries this name. Nobody is removed on the new group''s word until a SuperAdmin says it is the right one.' }
        default { return 'The membership sync waits for a SuperAdmin.' }
    }
}

function Read-PimAdCleanWaiting {
    <#
      The sync's waiting record of one job: @{ ok; reason; groups[] (hashtables: job, group, kind, state, entraGroupId,
      replacementGroupId, sinceUtc, confirmedUtc, inDeletedItems, memberCount, members[]) }. ok = $false when the row is
      there but cannot be parsed. No row = ok, nothing waiting. THROWS when the store cannot be read.
    #>
    param([Parameter(Mandatory)][string]$Job)
    $store = Get-PimAdCleanStore
    $raw = & $store.ReadRaw "HybridAdSyncMemory.$Job.waiting"
    if (-not "$raw".Trim()) { return @{ ok = $true; reason = ''; groups = @() } }
    $doc = $null; try { $doc = ConvertFrom-PimAdCleanJson "$raw" } catch { return @{ ok = $false; reason = "the waiting record of $Job is not readable"; groups = @() } }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($x in @(Get-PimHybridAdCleanupField $doc 'groups')) {
        if ($null -eq $x) { continue }
        $g = "$(Get-PimHybridAdCleanupField $x 'group')".Trim(); if (-not $g) { continue }
        $mc = 0; [void][int]::TryParse("$(Get-PimHybridAdCleanupField $x 'memberCount')", [ref]$mc)
        $list.Add([ordered]@{ job = $Job; group = $g; kind = "$(Get-PimHybridAdCleanupField $x 'kind')".Trim().ToLowerInvariant(); state = "$(Get-PimHybridAdCleanupField $x 'state')"
                entraGroupId = "$(Get-PimHybridAdCleanupField $x 'entraGroupId')".Trim(); replacementGroupId = "$(Get-PimHybridAdCleanupField $x 'replacementGroupId')".Trim()
                sinceUtc = "$(Get-PimHybridAdCleanupField $x 'sinceUtc')"; confirmedUtc = "$(Get-PimHybridAdCleanupField $x 'confirmedUtc')"
                inDeletedItems = [bool](Get-PimHybridAdCleanupField $x 'inDeletedItems'); memberCount = $mc
                members = @(Get-PimHybridAdCleanupField $x 'members' | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) })
    }
    return @{ ok = $true; reason = ''; groups = $list.ToArray() }
}

function Read-PimAdCleanDecisions {
    # The decisions row of one job: @{ raw; groups (ordered: group name as stored -> entry) }. An unreadable row = empty
    # (the sync treats it as "no decision at all"; a new decision replaces it).
    param([Parameter(Mandatory)][string]$Job)
    $store = Get-PimAdCleanStore
    $raw = & $store.ReadRaw "HybridAdSyncMemory.$Job.decisions"
    $groups = [ordered]@{}
    $doc = $null; try { $doc = ConvertFrom-PimAdCleanJson "$raw" } catch { $doc = $null }
    if ($doc) { $m = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $doc 'groups'); foreach ($k in @($m.Keys | Sort-Object)) { if ($null -ne $m[$k]) { $groups["$k"] = $m[$k] } } }
    return @{ raw = $(if ($null -eq $raw) { $null } else { "$raw" }); groups = $groups }
}

function Get-PimAdCleanDecisionFor {
    # PURE. The decision on record for one waiting entry -- only when it was made for exactly this state (kind + Entra group
    # id) and is not older than the sync uses it. $null otherwise.
    param($Waiting, $DecisionGroups, [long]$NowEpoch = 0)
    if ($null -eq $Waiting -or $null -eq $DecisionGroups) { return $null }
    foreach ($k in @($DecisionGroups.Keys)) {
        if ("$k".ToLowerInvariant() -ne "$($Waiting.group)".ToLowerInvariant()) { continue }
        $d = $DecisionGroups[$k]
        if ("$(Get-PimHybridAdCleanupField $d 'kind')".Trim().ToLowerInvariant() -ne "$($Waiting.kind)") { return $null }
        if ("$(Get-PimHybridAdCleanupField $d 'forEntraGroupId')".Trim() -ne "$($Waiting.entraGroupId)") { return $null }
        $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $d 'decidedAtEpoch')", [ref]$at)
        if ($at -le 0 -or ($NowEpoch - $at) -gt ([long](Get-PimAdCleanDecisionMaxHours) * 3600)) { return $null }
        $adopt = "$(Get-PimHybridAdCleanupField $d 'adoptEntraGroupId')".Trim()
        return [ordered]@{ action = $(if ($adopt) { 'adopt' } else { 'remove' }); adoptEntraGroupId = $adopt
            removeMembers = @(Get-PimHybridAdCleanupField $d 'removeMembers' | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
            decidedBy = "$(Get-PimHybridAdCleanupField $d 'decidedBy')"; decidedAtEpoch = $at; reason = "$(Get-PimHybridAdCleanupField $d 'reason')" }
    }
    return $null
}

function Get-PimAdCleanWaitingView {
    $me = Get-PimAdCleanCaller
    if (-not $me.admin) { return @{ status = 403; body = [ordered]@{ error = 'Admin role required to see the Active Directory groups that wait for a SuperAdmin.' } } }
    try {
        $now = Get-PimAdCleanEpoch
        $all = New-Object System.Collections.Generic.List[object]; $problems = New-Object System.Collections.Generic.List[string]
        foreach ($job in $script:PimAdCleanSyncJobs) {
            $w = Read-PimAdCleanWaiting -Job $job
            if (-not $w.ok) { $problems.Add("$($w.reason)"); continue }
            if (-not @($w.groups).Count) { continue }
            $dec = Read-PimAdCleanDecisions -Job $job
            foreach ($g in @($w.groups)) {
                $o = [ordered]@{}; foreach ($k in @($g.Keys)) { $o[$k] = $g[$k] }
                $o['kindText'] = Get-PimAdCleanKindText $g.kind
                $o['decision'] = Get-PimAdCleanDecisionFor -Waiting $g -DecisionGroups $dec.groups -NowEpoch $now
                $all.Add($o)
            }
        }
        return @{ status = 200; body = [ordered]@{ canDecide = [bool]$me.super; role = $me.role; groups = $all.ToArray(); problems = $problems.ToArray(); decisionMaxHours = (Get-PimAdCleanDecisionMaxHours) } }
    } catch { return @{ status = 503; body = [ordered]@{ error = "the waiting groups could not be read: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanWaitingDecide {
    <#
      POST /api/hybrid-ad/waiting/decide { job, group, kind, entraGroupId, action: 'remove' | 'adopt',
                                           members: [ sAMAccountName, ... ] (remove), adoptEntraGroupId (adopt), reason }
      SuperAdmin only -- an Admin is refused with the reason. The decision is written for EXACTLY the group and the case it
      was given for: the group must be in the sync's CURRENT waiting record of that job, and kind + entraGroupId must be
      the ones in that record now (the page sends what the person saw; anything else = 409, nothing written).
        remove: every named account must be in that entry's members list; the names are stored as the record spells them.
        adopt : only for kind 'replaced', and only the replacementGroupId of that entry.
      Written to 'HybridAdSyncMemory.<job>.decisions' (read, change this one group's entry, write back -- compare-and-set),
      read back, audited (who, when, what, reason). The sync applies it in its next pass and only in that same state.
    #>
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = "SuperAdmin role required (you are signed in as $($me.role)). Only a SuperAdmin decides what happens to the members of an Active Directory group whose Entra group is gone or was replaced. Nothing was changed." } }
    }
    if (-not $me.identity) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Your sign-in could not be identified, so the decision could not be recorded under a name. Nothing was changed.' } } }
    $job = "$(Get-PimAdCleanBodyValue $Body 'job')".Trim()
    if ($job -notin $script:PimAdCleanSyncJobs) { return @{ status = 400; body = [ordered]@{ ok = $false; error = "job must be one of: $($script:PimAdCleanSyncJobs -join ', '). Nothing was changed." } } }
    $group = "$(Get-PimAdCleanBodyValue $Body 'group')".Trim()
    if (-not $group) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'group is required. Nothing was changed.' } } }
    $action = "$(Get-PimAdCleanBodyValue $Body 'action')".Trim().ToLowerInvariant()
    if ($action -notin @('remove', 'adopt')) { return @{ status = 400; body = [ordered]@{ ok = $false; error = "action must be 'remove' or 'adopt'. Nothing was changed." } } }
    $reason = Get-PimAdCleanReason $Body
    if (-not $reason) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'A reason is required. Nothing was changed.' } } }
    $sawKind = "$(Get-PimAdCleanBodyValue $Body 'kind')".Trim().ToLowerInvariant()
    $sawId = "$(Get-PimAdCleanBodyValue $Body 'entraGroupId')".Trim()
    try {
        $w = Read-PimAdCleanWaiting -Job $job
        if (-not $w.ok) { return @{ status = 503; body = [ordered]@{ ok = $false; error = "$($w.reason). Nothing was changed." } } }
        $entry = @($w.groups | Where-Object { $_.group.ToLowerInvariant() -eq $group.ToLowerInvariant() }) | Select-Object -First 1
        if (-not $entry) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The group '$group' is not waiting for a SuperAdmin (any more). Load the page again. Nothing was changed." } } }
        if ($entry.kind -notin @('gone', 'never-seen', 'replaced')) { return @{ status = 409; body = [ordered]@{ ok = $false; error = "The group waits in a state this page does not know ('$($entry.kind)'). Nothing was changed." } } }
        if ($sawKind -ne $entry.kind -or $sawId -ne $entry.entraGroupId) {
            return @{ status = 409; body = [ordered]@{ ok = $false; error = 'The situation of this group changed since you opened the page (another state, or another Entra group). Load the page again and decide on what it shows now. Nothing was changed.' } }
        }
        $new = [ordered]@{ kind = $entry.kind; forEntraGroupId = $entry.entraGroupId; decidedBy = $me.identity; decidedAtEpoch = [long](Get-PimAdCleanEpoch); reason = $reason }
        $concerned = @()
        if ($action -eq 'adopt') {
            if ($entry.kind -ne 'replaced') { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'Only a group that was replaced by another group of the same name can be taken over. Nothing was changed.' } } }
            $adopt = "$(Get-PimAdCleanBodyValue $Body 'adoptEntraGroupId')".Trim()
            if (-not $entry.replacementGroupId -or $adopt -ne $entry.replacementGroupId) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'The group that carries the name now is not the one you were shown. Load the page again. Nothing was changed.' } } }
            $new['adoptEntraGroupId'] = $adopt
        } else {
            $asked = @(Get-PimAdCleanBodyValue $Body 'members' | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
            if (-not $asked.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'members (the accounts to remove) is required: tick the exact accounts. Nothing was changed.' } } }
            $known = @{}; foreach ($m in @($entry.members)) { $known[$m.ToLowerInvariant()] = $m }
            $bad = @($asked | Where-Object { -not $known.ContainsKey($_.ToLowerInvariant()) })
            if ($bad.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = "Not among the members that wait for a SuperAdmin in this group: $($bad -join ', '). Nothing was changed."; unknown = $bad } } }
            $concerned = [string[]]@($asked | ForEach-Object { $known[$_.ToLowerInvariant()] })
            $new['removeMembers'] = $concerned
        }
        $current = @{}; foreach ($g in @($w.groups)) { $current[$g.group.ToLowerInvariant()] = $true }
        $store = Get-PimAdCleanStore
        $name = "HybridAdSyncMemory.$job.decisions"
        $nowE = [long]$new.decidedAtEpoch
        for ($try = 1; $try -le 2; $try++) {
            $dec = Read-PimAdCleanDecisions -Job $job
            $before = $null
            $out = [ordered]@{}
            foreach ($k in @($dec.groups.Keys)) {
                $lk = "$k".ToLowerInvariant()
                if ($lk -eq $group.ToLowerInvariant()) { $before = $dec.groups[$k]; continue }                       # replaced below
                if (-not $current.ContainsKey($lk)) { continue }                                                    # that group no longer waits: its entry is cleared
                $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $dec.groups[$k] 'decidedAtEpoch')", [ref]$at)
                if ($at -le 0 -or ($nowE - $at) -gt ([long](Get-PimAdCleanDecisionMaxHours) * 3600)) { continue }     # dead (older than the sync uses it)
                $out["$k"] = $dec.groups[$k]
            }
            $out[$entry.group] = $new
            $json = ([ordered]@{ v = 1; groups = $out }) | ConvertTo-Json -Depth 8 -Compress
            if (-not (& $store.WriteRaw $name $json $dec.raw)) { continue }
            # read back: the entry must be there as written
            $check = Read-PimAdCleanDecisions -Job $job
            $got = $check.groups[$entry.group]
            if (-not $got -or "$(Get-PimHybridAdCleanupField $got 'decidedBy')" -ne $me.identity -or "$(Get-PimHybridAdCleanupField $got 'decidedAtEpoch')" -ne "$nowE") {
                return @{ status = 500; body = [ordered]@{ ok = $false; error = 'The decision was written but does not read back as written. Treat it as NOT saved.' } }
            }
            Write-PimManagerAuditEvent -Action 'hybrid-ad.waiting.decide' -Target "${name}:$($entry.group)" -Before $before `
                -After ([ordered]@{ job = $job; group = $entry.group; case = $entry.kind; forEntraGroupId = $entry.entraGroupId; decision = $action; removeMembers = @($concerned); adoptEntraGroupId = "$($new['adoptEntraGroupId'])"; reason = $reason; decidedBy = $me.identity; decidedAtEpoch = $nowE }) -Result 'ok'
            $note = if ($action -eq 'adopt') { "Recorded: the Entra group $($new['adoptEntraGroupId']) is taken as the group behind '$($entry.group)'. Nobody is removed in the pass that takes it over; after that the normal rules apply to it." }
                    else { "Recorded: $(@($concerned).Count) account(s) are removed from '$($entry.group)' in the sync's next pass -- each only if it is still in the group, has no active activation and is still one the sync holds for a SuperAdmin." }
            return @{ status = 200; body = [ordered]@{ ok = $true; job = $job; group = $entry.group; action = $action; note = "$note The decision is used for $(Get-PimAdCleanDecisionMaxHours) hours and only while the group is in exactly this state." } }
        }
        return @{ status = 409; body = [ordered]@{ ok = $false; error = 'Somebody else wrote a decision at the same moment. Load the page again. Nothing was changed.' } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the decision was NOT saved: $($_.Exception.Message)" } } }
}

# ---------------------------------------------------------------------------------------------------------------------
# New servers above the batch size: ONE SuperAdmin approval of the exact waiting list (owner 2026-10-13)
# ---------------------------------------------------------------------------------------------------------------------
function Read-PimAdCleanServerWaiting {
    # The worker's waiting list of new servers: @{ found; listId; sinceEpoch; batchSize; host; servers[] (ordered: server,
    # groupName, ou, dn); consistent }. consistent = the list id IS the fingerprint of the servers in the record.
    $store = Get-PimAdCleanStore
    $raw = & $store.ReadRaw 'AdServerAutoGroupsWaiting'
    $out = @{ found = $false; listId = ''; sinceEpoch = [long]0; batchSize = 0; host = ''; servers = @(); consistent = $false }
    $doc = $null; try { $doc = ConvertFrom-PimAdCleanJson "$raw" } catch { $doc = $null }
    if (-not $doc) { return $out }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($x in @(Get-PimHybridAdCleanupField $doc 'servers')) {
        if ($null -eq $x) { continue }
        $s = "$(Get-PimHybridAdCleanupField $x 'server')".Trim(); $g = "$(Get-PimHybridAdCleanupField $x 'groupName')".Trim()
        if ($s -and $g) { $list.Add([ordered]@{ server = $s; groupName = $g; ou = "$(Get-PimHybridAdCleanupField $x 'ou')"; dn = "$(Get-PimHybridAdCleanupField $x 'dn')" }) }
    }
    $out.servers = $list.ToArray()
    $out.listId = "$(Get-PimHybridAdCleanupField $doc 'listId')".Trim()
    $e = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $doc 'sinceEpoch')", [ref]$e); $out.sinceEpoch = $e
    $b = 0; [void][int]::TryParse("$(Get-PimHybridAdCleanupField $doc 'batchSize')", [ref]$b); $out.batchSize = $b
    $out.host = "$(Get-PimHybridAdCleanupField $doc 'host')"
    $out.found = [bool]($list.Count -and $out.listId)
    $out.consistent = [bool]($out.found -and (Get-PimHybridAdServerListId -Items $out.servers) -eq $out.listId)
    return $out
}

function Get-PimAdCleanServerRunMinutes { return 60 }   # the worker's server job runs about once an hour (its schedule; used only for the estimate shown)

function Read-PimAdCleanServerApprovalState {
    <#
      The approval of a list of new servers and how far the worker is with it:
      @{ found; listId; approvedBy; approvedAtEpoch; expiresEpoch; reason; total; expired; reported (the worker has reported
      on THIS approval); created; remaining; notEligible; batchSize; runsLeft; hoursLeft; notCreated[]; inProgress }.
      inProgress = not expired AND (the worker has not reported on it yet OR it still has servers to create): while that
      holds, no second list can be approved.
    #>
    $store = Get-PimAdCleanStore
    $out = @{ found = $false; listId = ''; approvedBy = ''; approvedAtEpoch = [long]0; expiresEpoch = [long]0; reason = ''; total = 0; expired = $false; reported = $false
        created = 0; remaining = 0; notEligible = 0; batchSize = 0; runsLeft = 0; hoursLeft = 0; notCreated = @(); inProgress = $false }
    $ap = $null; try { $ap = ConvertFrom-PimAdCleanJson "$(& $store.ReadRaw 'HybridAdServerAutoGroupsApproval')" } catch { $ap = $null }
    if (-not $ap) { return $out }
    $at = [long]0; [void][long]::TryParse("$(Get-PimHybridAdCleanupField $ap 'approvedAtEpoch')", [ref]$at)
    $out.found = $true; $out.listId = "$(Get-PimHybridAdCleanupField $ap 'listId')".Trim(); $out.approvedBy = "$(Get-PimHybridAdCleanupField $ap 'approvedBy')"; $out.approvedAtEpoch = $at
    $out.reason = "$(Get-PimHybridAdCleanupField $ap 'reason')"; $out.total = @(Get-PimHybridAdCleanupField $ap 'servers' | Where-Object { $null -ne $_ }).Count
    $maxSec = [long](Get-PimHybridAdServerApprovalMaxHours) * 3600
    $out.expiresEpoch = $at + $maxSec
    $out.expired = [bool]($at -le 0 -or ((Get-PimAdCleanEpoch) - $at) -gt $maxSec)
    $pr = $null; try { $pr = ConvertFrom-PimAdCleanJson "$(& $store.ReadRaw 'AdServerAutoGroupsProgress')" } catch { $pr = $null }
    if ($pr -and "$(Get-PimHybridAdCleanupField $pr 'listId')".Trim() -eq $out.listId -and $out.listId) {
        $out.reported = $true
        foreach ($n in 'created', 'remaining', 'notEligible', 'batchSize', 'runsLeft') { $i = 0; [void][int]::TryParse("$(Get-PimHybridAdCleanupField $pr $n)", [ref]$i); $out[$n] = $i }
        $out.notCreated = @(foreach ($x in @(Get-PimHybridAdCleanupField $pr 'notCreated')) { if ($x) { [ordered]@{ server = "$(Get-PimHybridAdCleanupField $x 'server')"; reason = "$(Get-PimHybridAdCleanupField $x 'reason')" } } })
        $out.hoursLeft = [math]::Round(($out.runsLeft * (Get-PimAdCleanServerRunMinutes)) / 60.0, 1)
    }
    $out.inProgress = [bool](-not $out.expired -and (-not $out.reported -or $out.remaining -gt 0))
    return $out
}

function Get-PimAdCleanServerWaitingView {
    $me = Get-PimAdCleanCaller
    if (-not $me.admin) { return @{ status = 403; body = [ordered]@{ error = 'Admin role required to see the new servers that wait for a SuperAdmin.' } } }
    try {
        $w = Read-PimAdCleanServerWaiting
        $st = Read-PimAdCleanServerApprovalState
        $apView = $null
        if ($st.found) {
            $apView = [ordered]@{ listId = $st.listId; approvedBy = $st.approvedBy; approvedAtEpoch = $st.approvedAtEpoch; expiresEpoch = $st.expiresEpoch; count = [int]$st.total; reason = $st.reason
                expired = [bool]$st.expired; inProgress = [bool]$st.inProgress; reported = [bool]$st.reported; created = [int]$st.created; remaining = [int]$st.remaining; notEligible = [int]$st.notEligible
                batchSize = [int]$st.batchSize; runsLeft = [int]$st.runsLeft; hoursLeft = $st.hoursLeft; notCreated = @($st.notCreated)
                # will the rest be done before the 72 hours are over, at this batch size?
                finishesInTime = [bool](-not $st.reported -or $st.remaining -le 0 -or (((Get-PimAdCleanEpoch) + [long]$st.runsLeft * (Get-PimAdCleanServerRunMinutes) * 60) -le $st.expiresEpoch)) }
        }
        # the estimate for the list that waits, at the batch size in the settings now
        $batchNow = 50; [void][int]::TryParse("$(& (Get-PimAdCleanStore).ReadText 'HybridAdServerAutoGroupMaxPerRun')", [ref]$batchNow); if ($batchNow -lt 1) { $batchNow = 50 }
        # CR4 GUARD-STRICT: the same half the worker uses while Strict is active
        if (Get-Command Get-PimGuardStrictState -ErrorAction SilentlyContinue) { try { if ((Get-PimGuardStrictState).active) { $batchNow = Get-PimGuardStrictHalf -Configured $batchNow } } catch { } }
        $runs = [int][math]::Ceiling(@($w.servers).Count / [double]$batchNow)
        return @{ status = 200; body = [ordered]@{ canApprove = [bool]$me.super; role = $me.role; approvalMaxHours = (Get-PimHybridAdServerApprovalMaxHours)
                estimate = [ordered]@{ batchSize = $batchNow; runs = $runs; hours = [math]::Round(($runs * (Get-PimAdCleanServerRunMinutes)) / 60.0, 1); minutesPerRun = (Get-PimAdCleanServerRunMinutes); fitsIn72Hours = [bool](($runs * (Get-PimAdCleanServerRunMinutes)) -le ((Get-PimHybridAdServerApprovalMaxHours) * 60)) }
                waiting = [ordered]@{ found = [bool]$w.found; consistent = [bool]$w.consistent; listId = $w.listId; sinceEpoch = $w.sinceEpoch; batchSize = $w.batchSize; host = $w.host; count = @($w.servers).Count; servers = @($w.servers) }
                approval = $apView } }
    } catch { return @{ status = 503; body = [ordered]@{ error = "the waiting list of new servers could not be read: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanServerGroupsApprove {
    <#
      POST /api/hybrid-ad/server-groups/approve { listId, count, confirm: true, reason } -- SuperAdmin only; an Admin is
      refused with the reason. Approves the worker's CURRENT waiting list of new servers, exactly: listId must be the id of
      the list in the store now (the page sends the id of what the person saw), count must be its number of servers, and
      the id must be the fingerprint of the servers in the record. The approval ('HybridAdServerAutoGroupsApproval') is
      built from the worker's record -- server + group name -- never from the request. ONE approved list at a time:
      while an earlier approval is in progress (not older than 72 hours and not reported done by the worker) the request
      is refused (409). The worker creates the list in batches, each server at most once; the approval is valid for 72
      hours. Audited: who, when, how many, which list, the reason.
    #>
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) { return @{ status = 403; body = [ordered]@{ ok = $false; error = "SuperAdmin role required to approve the creation of groups for new servers (you are signed in as $($me.role)). An Admin can see the list; a SuperAdmin approves it. Nothing was approved." } } }
    if (-not $me.identity) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Your sign-in could not be identified, so the approval could not be recorded under a name. Nothing was approved.' } } }
    $reason = Get-PimAdCleanReason $Body
    if (-not $reason) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'A reason is required. Nothing was approved.' } } }
    $sawId = "$(Get-PimAdCleanBodyValue $Body 'listId')".Trim()
    if (-not $sawId) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'listId (the list you reviewed) is required. Nothing was approved.' } } }
    try {
        # ONE approval at a time: while an approved list is still being created (or the worker has not reported on it yet)
        # and its 72 hours are not over, a second list cannot be approved -- replacing it would silently drop the servers of
        # the first list that are not created yet. They are all on the page; the next list is approved when this one is done.
        $st = Read-PimAdCleanServerApprovalState
        if ($st.inProgress) {
            return @{ status = 409; body = [ordered]@{ ok = $false; inProgress = $true
                    error = "The list $($st.approvedBy) approved is still being created ($([int]$st.created) of $([int]$st.total)$(if (-not $st.reported) { '; the worker has not started on it yet' })). A second list can be approved when it is done or its $(Get-PimHybridAdServerApprovalMaxHours) hours are over. Nothing was approved." } }
        }
        $w = Read-PimAdCleanServerWaiting
        if (-not $w.found) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'No list of new servers is waiting (any more). Load the page again. Nothing was approved.' } } }
        if (-not $w.consistent) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'The waiting list in the store does not match its own fingerprint. Wait for the worker''s next run. Nothing was approved.' } } }
        if ($sawId -ne $w.listId) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'The list of new servers changed since you opened the page. Load the page again and review the list it shows now. Nothing was approved.' } } }
        $n = @($w.servers).Count
        $seen = 0; [void][int]::TryParse("$(Get-PimAdCleanBodyValue $Body 'count')".Trim(), [ref]$seen)
        $confirmed = ((Get-PimAdCleanBodyValue $Body 'confirm') -is [bool]) -and [bool](Get-PimAdCleanBodyValue $Body 'confirm')
        if (-not $confirmed -or $seen -ne $n) { return @{ status = 409; body = [ordered]@{ ok = $false; needsConfirm = $true; count = $n; error = "Creating $n server group(s) needs your confirmation of exactly that number. Nothing was approved." } } }
        $now = [long](Get-PimAdCleanEpoch)
        $doc = [ordered]@{ v = 1; listId = $w.listId; count = $n; approvedBy = $me.identity; approvedAtEpoch = $now; reason = $reason
            servers = @($w.servers | ForEach-Object { [ordered]@{ server = $_.server; groupName = $_.groupName } }) }
        $json = $doc | ConvertTo-Json -Depth 6 -Compress
        $store = Get-PimAdCleanStore
        $name = 'HybridAdServerAutoGroupsApproval'
        $written = $false
        for ($try = 1; $try -le 2 -and -not $written; $try++) { $cur = & $store.ReadRaw $name; $written = [bool](& $store.WriteRaw $name $json $(if ($null -eq $cur) { $null } else { "$cur" })) }
        if (-not $written) { return @{ status = 409; body = [ordered]@{ ok = $false; error = 'Somebody else changed the approval at the same moment. Load the page again. Nothing was approved.' } } }
        Write-PimManagerAuditEvent -Action 'hybrid-ad.server-groups.approve' -Target "${name}:$($w.listId)" `
            -After ([ordered]@{ servers = $n; listId = $w.listId; batchSize = $w.batchSize; reason = $reason; approvedBy = $me.identity; approvedAtEpoch = $now; first = @($w.servers | Select-Object -First 20 | ForEach-Object { $_.server }) }) -Result 'ok'
        return @{ status = 200; body = [ordered]@{ ok = $true; approved = $n; listId = $w.listId
                note = "Approved: $n server group(s). The hybrid worker creates them in batches, one batch per run (about hourly), and only the servers of this list that still meet every condition at that run. The approval is valid for $(Get-PimHybridAdServerApprovalMaxHours) hours; what is not created by then waits for a new approval." } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the approval was NOT saved: $($_.Exception.Message)" } } }
}

# ---------------------------------------------------------------------------------------------------------------------
# Settings > Hybrid Active Directory: server discovery, automatic OUs, clean-up OUs
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAdCleanStoredDiscoveryTexts {
    $store = Get-PimAdCleanStore
    $h = @{}
    foreach ($c in @(Get-PimHybridAdDiscoverySettingCatalog)) { $t = ''; try { $t = "$(& $store.ReadText $c.name)".Trim() } catch { $t = '' }; $h["$($c.name)"] = $t }
    return $h
}

function Get-PimAdCleanDiscoverySettingsView {
    $me = Get-PimAdCleanCaller
    try {
        $cur = Get-PimAdCleanStoredDiscoveryTexts
        $items = @(foreach ($c in @(Get-PimHybridAdDiscoverySettingCatalog)) { [ordered]@{ name = "$($c.name)"; label = "$($c.label)"; help = "$($c.help)"; kind = "$($c.kind)"; default = "$($c.default)"; defaultText = "$($c.defaultText)"; value = "$($cur[$c.name])" } })
        $store = Get-PimAdCleanStore
        $last = $null
        try {
            $doc = ConvertFrom-PimAdCleanJson "$(& $store.ReadCache 'ad-servers')"
            if ($doc) {
                $d = Get-PimHybridAdCleanupField $doc 'discovery'
                $last = [ordered]@{ refreshedUtc = "$(Get-PimHybridAdCleanupField $doc 'refreshedUtc')"; servers = @(Get-PimHybridAdCleanupField $doc 'items').Count
                    counts = $(if ($d) { Get-PimHybridAdCleanupField $d 'counts' } else { $null }); problems = @($(if ($d) { Get-PimHybridAdCleanupField $d 'problems' })) }
            }
        } catch { $last = $null }
        return @{ status = 200; body = [ordered]@{ canWrite = [bool]$me.super; settings = $items; lastListing = $last } }
    } catch { return @{ status = 500; body = [ordered]@{ error = "the server discovery settings could not be read: $($_.Exception.Message)" } } }
}

function Get-PimAdCleanValuesFromBody {
    param($Body)
    $in = @{}
    $v = Get-PimAdCleanBodyValue $Body 'values'
    if ($v) { $m = ConvertTo-PimHybridAdCleanupMap $v; foreach ($k in @($m.Keys)) { $in["$k"] = "$($m[$k])" } }
    return $in
}

function Invoke-PimAdCleanDiscoverySettingsSave {
    # PUT /api/settings/hybrid-ad-discovery { values: { name: text } } -- SuperAdmin; each changed setting audited.
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.super) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'SuperAdmin role required to change the server discovery and clean-up settings of the hybrid worker.' } } }
    $in = Get-PimAdCleanValuesFromBody $Body
    if (-not $in.Count) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'values is required. Nothing was saved.' } } }
    $cur = Get-PimAdCleanStoredDiscoveryTexts
    $chk = Test-PimHybridAdDiscoverySettingsInput -Values $in -Current $cur
    if (-not $chk.ok) { return @{ status = 400; body = [ordered]@{ ok = $false; error = (@($chk.errors) -join '; ') + '. Nothing was saved.' } } }
    $store = Get-PimAdCleanStore
    $changed = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($k in @($chk.values.Keys)) {
            $before = "$($cur[$k])"; $after = "$($chk.values[$k])"
            # a number equal to its default is stored as "not set"
            $def = "$(@(Get-PimHybridAdDiscoverySettingCatalog | Where-Object { $_.name -eq $k })[0].default)"
            if ($after -and $def -and $after -eq $def) { $after = '' }
            if ($before -ceq $after) { continue }
            & $store.WriteSetting $k $after
            Write-PimManagerAuditEvent -Action 'settings.hybrid-ad-discovery.save' -Target "settings:$k" -Before @{ value = $before } -After @{ value = $after } -Result 'ok'
            $changed.Add("$k")
        }
        return @{ status = 200; body = [ordered]@{ ok = $true; changed = $changed.ToArray()
                detail = $(if ($changed.Count) { "Saved $($changed.Count) setting(s). The hybrid worker uses them from its next server listing (hourly). A server that falls out of the filter keeps its group and its access; it only stops being listed and proposed." } else { 'Nothing changed.' }) } }
    } catch { return @{ status = 500; body = [ordered]@{ ok = $false; changed = $changed.ToArray(); error = "the settings save failed after $($changed.Count) change(s): $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanDiscoveryPreview {
    # POST /api/hybrid-ad/discovery/preview { values } -- "with these settings the worker finds N servers", computed with the
    # worker's own filter function over the inventory it last wrote. Nothing is saved.
    param($Body)
    $me = Get-PimAdCleanCaller
    if (-not $me.admin) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Admin role required to preview the server discovery.' } } }
    try {
        $in = Get-PimAdCleanValuesFromBody $Body
        $cur = Get-PimAdCleanStoredDiscoveryTexts
        $chk = Test-PimHybridAdDiscoverySettingsInput -Values $in -Current $cur
        if (-not $chk.ok) { return @{ status = 400; body = [ordered]@{ ok = $false; error = (@($chk.errors) -join '; ') } } }
        $merged = @{}; foreach ($k in @($cur.Keys)) { $merged[$k] = $cur[$k] }; foreach ($k in @($chk.values.Keys)) { $merged["$k"] = "$($chk.values[$k])" }
        $script:PimAdCleanPreviewTexts = $merged
        $settings = Get-PimHybridAdServerDiscoverySettings -Read { param($n) "$($script:PimAdCleanPreviewTexts[$n])" }
        $store = Get-PimAdCleanStore
        $doc = ConvertFrom-PimAdCleanJson "$(& $store.ReadCache 'ad-servers-inventory')"
        if (-not $doc) { return @{ status = 200; body = [ordered]@{ ok = $false; reason = 'The hybrid worker has not listed the servers yet (its "Server onboarding" job writes the list hourly). The preview is available after its next run.' } } }
        $inv = @(foreach ($x in @(Get-PimHybridAdCleanupField $doc 'items')) { if ($x) { [pscustomobject]@{ name = "$(Get-PimHybridAdCleanupField $x 'name')"; dnsHostName = "$(Get-PimHybridAdCleanupField $x 'dnsHostName')"; os = "$(Get-PimHybridAdCleanupField $x 'os')"; whenChanged = (Get-PimHybridAdCleanupField $x 'whenChanged'); dn = "$(Get-PimHybridAdCleanupField $x 'dn')" } } })
        $sel = Select-PimHybridAdServerDiscovery -Inventory $inv -Settings $settings -NowUtc ([datetime]::UtcNow)
        return @{ status = 200; body = [ordered]@{ ok = $true; inventoryUtc = "$(Get-PimHybridAdCleanupField $doc 'refreshedUtc')"; inventoryTruncated = [bool](Get-PimHybridAdCleanupField $doc 'truncated')
                counts = $sel.counts; selected = [int]$sel.counts.selected; total = [int]$sel.counts.total; automatic = [int]$sel.counts.auto; problems = @($settings.problems)
                servers = @($sel.servers | Select-Object -First 500 | ForEach-Object { [ordered]@{ name = $_.name; ou = $_.ou; autoGroup = [bool]$_.autoGroup; whenChanged = $_.whenChanged } }) } }
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the preview could not be computed: $($_.Exception.Message)" } } }
}

function Invoke-PimAdCleanRoute {
    # The ONE entry point of the route block in Open-PimManager.ps1. $null = not one of this file's routes.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Method, $Body = $null)
    $mine = @('GET /api/hybrid-ad/cleanup', 'POST /api/hybrid-ad/cleanup/approve', 'POST /api/hybrid-ad/cleanup/withdraw', 'POST /api/hybrid-ad/cleanup/also-delete', 'GET /api/hybrid-ad/waiting',
        'POST /api/hybrid-ad/waiting/decide', 'GET /api/hybrid-ad/server-groups/waiting', 'POST /api/hybrid-ad/server-groups/approve', 'GET /api/settings/hybrid-ad-discovery', 'PUT /api/settings/hybrid-ad-discovery', 'POST /api/hybrid-ad/discovery/preview',
        'GET /api/hybrid-ad/cleanup/right-notice')   # lane handover: the "Delete Group objects" notice (Get-PimAdCleanRightNoticeView, end of file)
    if ("$Method $Path" -notin $mine) { return $null }
    # an edition without the hybrid Active Directory code (its engine files are not shipped): say so, never half-work
    if (-not (Get-Command Get-PimHybridAdCleanupDecision -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimHybridAdDiscoverySettingCatalog -ErrorAction SilentlyContinue)) {
        return @{ status = 404; body = [ordered]@{ ok = $false; error = 'The hybrid Active Directory feature is not part of this installation.' } }
    }
    switch ("$Method $Path") {
        'GET /api/hybrid-ad/cleanup' { return (Get-PimAdCleanCleanupView) }
        'POST /api/hybrid-ad/cleanup/approve' { return (Invoke-PimAdCleanApprove -Body $Body) }
        'POST /api/hybrid-ad/cleanup/withdraw' { return (Invoke-PimAdCleanWithdraw -Body $Body) }
        'POST /api/hybrid-ad/cleanup/also-delete' { return (Invoke-PimAdCleanAlsoDelete -Body $Body) }
        'GET /api/hybrid-ad/waiting' { return (Get-PimAdCleanWaitingView) }
        'POST /api/hybrid-ad/waiting/decide' { return (Invoke-PimAdCleanWaitingDecide -Body $Body) }
        'GET /api/hybrid-ad/server-groups/waiting' { return (Get-PimAdCleanServerWaitingView) }
        'POST /api/hybrid-ad/server-groups/approve' { return (Invoke-PimAdCleanServerGroupsApprove -Body $Body) }
        'GET /api/settings/hybrid-ad-discovery' { return (Get-PimAdCleanDiscoverySettingsView) }
        'PUT /api/settings/hybrid-ad-discovery' { return (Invoke-PimAdCleanDiscoverySettingsSave -Body $Body) }
        'POST /api/hybrid-ad/discovery/preview' { return (Invoke-PimAdCleanDiscoveryPreview -Body $Body) }
        'GET /api/hybrid-ad/cleanup/right-notice' { return (Get-PimAdCleanRightNoticeView) }
    }
    return $null
}

# =====================================================================================================================
# lane handover (PIM 100.123 known gap, 2026-10-13): the AD clean-up cannot delete anything at an install made before
# 2.4.618 until the CUSTOMER re-runs Initialize-PimHybridWorkerAd.ps1 -AllowGroupCleanup -- the worker's gMSA lacks
# "Delete Group objects" on the groups OU. PIM Manager never runs it (the customer runs every deployment command): it
# SHOWS the exact two-line command for THIS install, and only when an approved clean-up item failed for that reason.
#   GET /api/hybrid-ad/cleanup/right-notice   (Admin)  -> { show; failureClass; groups[]; groupsOu; groupsOuKnown;
#                                                           workerHost; outsideGroupsOu[]; command (two lines); text }
# The failure catalog class is AD-CLEANUP-RIGHT-MISSING (engine/_shared/PIM-FailureCatalog.ps1), same command.
# =====================================================================================================================
function Test-PimAdCleanRightMissingReason {
    # PURE. TRUE when a clean-up result's reason is the worker's "may not delete" (access denied on the delete), the
    # sentence Invoke-PimHybridAdCleanupJob writes (engine/hybrid-ad/PIM-HybridAdCleanup.ps1), or a bare access-denied
    # answer to a deletion. Any other failure (the group changed, the server is unreachable, ...) is FALSE.
    param([AllowNull()][string]$Reason)
    $r = "$Reason"
    if (-not $r.Trim()) { return $false }
    if ($r -match "(?i)may not delete groups in that OU|'Delete Group objects'") { return $true }
    $denied = [bool]($r -match '(?i)access is denied|access denied|insufficient access rights|unauthorizedaccess|0x80070005|E_ACCESSDENIED')
    return ($denied -and $r -match '(?i)\bdelet')
}

function ConvertTo-PimAdCleanPsLiteral {
    # PURE. A value as a single-quoted PowerShell string ('' inside doubles the quote): safe to paste, never expanded.
    param([AllowNull()][string]$Value)
    return "'" + ("$Value" -replace "'", "''") + "'"
}

function Get-PimAdCleanRightNoticeCommand {
    # PURE. The two lines the customer runs on a domain controller (download + run), with THIS install's values: the OU
    # for new AD groups (setting HybridAdGroupsOu) and the worker computer that reported. -ComputerOu / -GmsaOu are not
    # stored by PIM Manager: they are the values used at the install (angle-bracket placeholders the person fills in).
    param([string]$GroupsOu = '', [string]$WorkerHost = '')
    $ou = "$GroupsOu".Trim(); $wh = "$WorkerHost".Trim()
    $run = '.\Initialize-PimHybridWorkerAd.ps1 -WorkerComputerName ' + $(if ($wh -match '^[A-Za-z0-9-]{1,15}$') { $wh } else { '<worker computer name>' }) +
        " -ComputerOu '<OU of the worker computer, as at install>' -GmsaOu '<OU of the gMSA, as at install>' -GroupsOu " +
        $(if ($ou) { ConvertTo-PimAdCleanPsLiteral $ou } else { "'<OU for new AD groups>'" }) + ' -AllowGroupCleanup'
    if (Get-Command Get-PimSupportScriptCommand -ErrorAction SilentlyContinue) { return @(Get-PimSupportScriptCommand -Script 'Initialize-PimHybridWorkerAd' -Run @($run)) }
    return @('Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimHybridWorkerAd.ps1 -OutFile Initialize-PimHybridWorkerAd.ps1', $run)
}

function Get-PimAdCleanRightNotice {
    <#
      PURE. From the worker's result record ('AdCleanupResult': { items: { key: { name, dn, status, reason, atEpoch } } })
      and the stored groups OU: show = $true ONLY when at least one item's CURRENT status is 'failed' with the access-denied
      reason (Test-PimAdCleanRightMissingReason). A deleted / waiting / expired / skipped item, or a failure for any other
      reason, shows nothing. outsideGroupsOu = failed groups whose DN is not below the groups OU (the script grants the
      right on that OU only; their OU needs the same right granted there).
    #>
    param([AllowNull()][object]$ResultDoc, [string]$GroupsOu = '', [string]$WorkerHost = '')
    $ou = "$GroupsOu".Trim()
    $items = ConvertTo-PimHybridAdCleanupMap (Get-PimHybridAdCleanupField $ResultDoc 'items')
    $hit = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($items.Keys)) {
        $x = $items[$k]
        if ("$(Get-PimHybridAdCleanupField $x 'status')" -ne 'failed') { continue }
        $reason = "$(Get-PimHybridAdCleanupField $x 'reason')"
        if (-not (Test-PimAdCleanRightMissingReason -Reason $reason)) { continue }
        $hit.Add([ordered]@{ name = "$(Get-PimHybridAdCleanupField $x 'name')"; dn = "$(Get-PimHybridAdCleanupField $x 'dn')"; reason = $reason; atEpoch = (Get-PimHybridAdCleanupField $x 'atEpoch') })
    }
    $outside = @()
    if ($ou) { $outside = @($hit | Where-Object { $_.dn -and -not ("$($_.dn)".ToLowerInvariant().EndsWith(',' + $ou.ToLowerInvariant())) } | ForEach-Object { $_.name }) }
    $show = [bool]($hit.Count -gt 0)
    $cmd = @(); $text = ''
    if ($show) {
        $cmd = @(Get-PimAdCleanRightNoticeCommand -GroupsOu $ou -WorkerHost $WorkerHost)
        $text = "The hybrid worker may not delete groups in Active Directory: $($hit.Count) approved group(s) were not deleted. Its permission group lacks 'Delete Group objects' on the OU for new AD groups. On a domain controller, as a domain administrator, run the two lines below (the same values as at the install for -ComputerOu and -GmsaOu); it grants that one right and changes nothing else. The worker deletes the approved groups at its next run."
    }
    return [ordered]@{ show = $show; failureClass = 'AD-CLEANUP-RIGHT-MISSING'; groups = $hit.ToArray(); groupsOu = $ou; groupsOuKnown = [bool]$ou
        workerHost = "$WorkerHost".Trim(); outsideGroupsOu = @($outside); command = @($cmd); text = $text }
}

function Get-PimAdCleanRightNoticeView {
    # GET /api/hybrid-ad/cleanup/right-notice -- Admin (the same reader as the clean-up list). Reads only.
    $me = Get-PimAdCleanCaller
    if (-not $me.admin) { return @{ status = 403; body = [ordered]@{ error = 'Admin role required to see the Active Directory clean-up notice.' } } }
    try {
        $store = Get-PimAdCleanStore
        $resDoc = $null; try { $resDoc = ConvertFrom-PimAdCleanJson "$(& $store.ReadRaw 'AdCleanupResult')" } catch { $resDoc = $null }
        $ou = ''; try { $ou = "$(& $store.ReadText 'HybridAdGroupsOu')".Trim() } catch { $ou = '' }
        $wh = ''; try { $rep = Read-PimAdCleanCandidateReport; $wh = "$($rep.host)" } catch { $wh = '' }
        return @{ status = 200; body = (Get-PimAdCleanRightNotice -ResultDoc $resDoc -GroupsOu $ou -WorkerHost $wh) }
    } catch { return @{ status = 503; body = [ordered]@{ error = "the clean-up notice could not be read: $($_.Exception.Message)" } } }
}
