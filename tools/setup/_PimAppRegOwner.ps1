#Requires -Version 5.1
<#
  PIM4EntraPS -- APP-REG-OWNER (framework SECAUDIT-1a item 2, Invardia ruling 2026-11-07; PIM 3.0.54): the two RECORDED
  SUPPORT-APP steps around the updater's own proof. Dot-sourced by the support tooling (run as the Invardia Support app);
  offline-tested by tests/Test-PimAppRegOwner.ps1. NEVER run by the updater itself.

    (a) Invoke-PimAppRegOwnerAdd           the updater identity (ca-pim-update's SYSTEM identity) is ADDED as an owner of every
                                           PIM product registration present (POST /applications/{id}/owners/$ref) and READ BACK.
                                           A registration with no owner at all simply gets it. Nothing is removed here.
    (b) is not here: Application.ReadWrite.OwnedBy is in the ONE updater list (engine/_shared/PIM-UpdaterGraphRoles.ps1).
    (c) is the updater's (engine/_shared/PIM-AppRegOwner.ps1 Invoke-PimAppRegOwnerUpdaterCheck): one harmless PATCH it reads
        back, recorded in pim.Settings 'AppRegOwnerProof'.
    (d) Invoke-PimAppRegOwnerSupportRemove the Invardia Support app is REMOVED as an owner -- ONLY where (c)'s proof is recorded
                                           for that registration AND the updater is read as an owner NOW; read back. Any other
                                           owner (a person, a test-estate service principal, ...) is never removed.
  Which registrations count, and how they are found: engine/_shared/PIM-AppRegOwner.ps1 (Find-PimAppRegOwnerTargets) -- a
  registration that is not a product registration is never touched.
  The Support app is recognised the way the rest of PIM does (Test-PimSqlAdminMemberIsSupportApp: its 'InvardiaSupport' tag,
  or a display name starting 'Invardia Support'), or by -SupportAppId (its app id) -- nothing new.
  Each step has a PLAN-ONLY first run (-PlanOnly: reads, returns the plan, writes nothing) and returns a RECORD (step, utc,
  updater, every row with its read-back) the caller keeps. Never throws for a Graph refusal.
  Seams: -Graph { param($Method, $Path, $Body) } (Graph v1.0 relative paths; New-PimSqlAdminGroupInvokers' Graph fits),
  -Sleep { param([int]$Seconds) }. ASCII only; PS 5.1 + 7; no modules.
#>
Set-StrictMode -Off

if (-not (Get-Command Find-PimAppRegOwnerTargets -ErrorAction SilentlyContinue)) {
    $__pimAroRoot = "$PSScriptRoot".Trim()
    if (-not $__pimAroRoot -and "$($MyInvocation.MyCommand.Path)".Trim()) { $__pimAroRoot = Split-Path -Parent "$($MyInvocation.MyCommand.Path)" }
    if ($__pimAroRoot) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $__pimAroRoot)) 'engine\_shared\PIM-AppRegOwner.ps1') }
}
if (-not (Get-Command Test-PimSqlAdminMemberIsSupportApp -ErrorAction SilentlyContinue)) {
    $__pimAroRoot2 = "$PSScriptRoot".Trim()
    if (-not $__pimAroRoot2 -and "$($MyInvocation.MyCommand.Path)".Trim()) { $__pimAroRoot2 = Split-Path -Parent "$($MyInvocation.MyCommand.Path)" }
    if ($__pimAroRoot2) { . (Join-Path $__pimAroRoot2 '_PimSqlAdminGroup.ps1') }
}

function Test-PimAppRegOwnerUpdaterIdentity {
    <#
      READ ONLY. Is -ObjectId a MANAGED IDENTITY's service principal (the updater's system identity) and NOT the Invardia Support
      app? Returns @{ ok; displayName; reason }. A person, an application, the Support app, an unreadable object = not ok.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$ObjectId)
    $o = @{ ok = $false; displayName = ''; reason = '' }
    if (-not (Test-PimAppRegOwnerGuid $ObjectId)) { $o.reason = "'$ObjectId' is not an object id"; return $o }
    try {
        $sp = & $Graph 'GET' ("/servicePrincipals/$(([guid]"$ObjectId".Trim()).ToString())?" + '$select=id,appId,displayName,servicePrincipalType,tags') $null
        if (-not $sp) { $o.reason = 'no such service principal'; return $o }
        $o.displayName = "$($sp.displayName)"
        if ("$($sp.servicePrincipalType)" -ne 'ManagedIdentity') { $o.reason = "'$($sp.displayName)' is not a managed identity -- the owner must be the updater's own identity"; return $o }
        if (@($sp.tags) -contains 'InvardiaSupport' -or "$($sp.displayName)" -match '^(?i)Invardia Support') { $o.reason = 'that is the Invardia Support app, not the updater'; return $o }
        $o.ok = $true; $o.reason = "the updater identity '$($sp.displayName)'"
    } catch { $o.reason = "the updater identity could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    return $o
}

function Get-PimAppRegOwnerAddPlan {
    <#
      PURE. Step (a)'s plan: per target ({ role; objectId; appId; displayName } + its owners read @{ ok; owners[] }):
        add      the updater is not an owner (a registration with no owner at all too)
        present  it already is -- nothing written
        unknown  the owners could not be read -- nothing written
      Returns rows { role; displayName; appId; objectId; action; ownerCount; reason }.
    #>
    param([object[]]$Targets = @(), [object[]]$OwnerReads = @(), [Parameter(Mandatory)][string]$UpdaterObjectId)
    $me = ([guid]"$UpdaterObjectId".Trim()).ToString()
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt @($Targets).Count; $i++) {
        $t = @($Targets)[$i]; $ow = @($OwnerReads)[$i]
        $r = [ordered]@{ role = $t.role; displayName = $t.displayName; appId = $t.appId; objectId = $t.objectId; action = 'unknown'; ownerCount = $null; reason = '' }
        if (-not $ow -or -not $ow.ok) { $r.reason = $(if ($ow) { "$($ow.reason)" } else { 'its owners were not read' }) }
        else {
            $r.ownerCount = @($ow.owners).Count
            if (@($ow.owners | ForEach-Object { $_.id }) -contains $me) { $r.action = 'present'; $r.reason = 'the updater already owns it' }
            else { $r.action = 'add'; $r.reason = $(if ($r.ownerCount -eq 0) { 'it has NO owner -- the updater is added' } else { 'the updater is added beside the current owner(s), who stay' }) }
        }
        [void]$rows.Add([pscustomobject]$r)
    }
    return @($rows.ToArray())
}

function Invoke-PimAppRegOwnerAdd {
    <#
      Step (a), RUN AS THE INVARDIA SUPPORT APP (never by the updater). The updater identity (-UpdaterObjectId: the update job's
      system identity, Resolve-PimAppRegOwnerInstallFacts) is added as an owner of every product registration present and READ
      BACK. Only POST .../owners/$ref is written; nothing is removed, no notes, no role. -PlanOnly = read + plan, nothing written.
      Returns @{ ok; planOnly; refused; rows[]; problems[]; record }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][AllowEmptyString()][string]$UpdaterObjectId, [AllowNull()][object]$Recorded = $null,
          [AllowEmptyString()][string]$Label = '', [switch]$PlanOnly, [int]$PollSeconds = 5, [int]$PollCount = 12, [string[]]$Roles = @(),
          [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{ ok = $false; planOnly = [bool]$PlanOnly; refused = ''; rows = @(); problems = @(); record = $null }
    $probs = New-Object System.Collections.Generic.List[string]
    $idn = Test-PimAppRegOwnerUpdaterIdentity -Graph $Graph -ObjectId $UpdaterObjectId
    if (-not $idn.ok) { $out.refused = "REFUSED -- $($idn.reason); nothing written"; $out.problems = @($out.refused); return [pscustomobject]$out }
    $me = ([guid]"$UpdaterObjectId".Trim()).ToString()
    $found = Find-PimAppRegOwnerTargets -Graph $Graph -Recorded $Recorded -Label $Label -Roles $Roles
    if (-not $found.ok) { $out.refused = "$($found.reason) -- nothing written"; $out.problems = @($out.refused); return [pscustomobject]$out }
    foreach ($a in @($found.ambiguous)) { [void]$probs.Add("$($a.count) registrations are named '$($a.name)' -- none is touched; support names the one to use") }
    $reads = @(foreach ($t in @($found.targets)) { Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $t.objectId })
    $plan = @(Get-PimAppRegOwnerAddPlan -Targets @($found.targets) -OwnerReads $reads -UpdaterObjectId $me)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $plan) {
        $r = [ordered]@{ role = $p.role; displayName = $p.displayName; appId = $p.appId; objectId = $p.objectId; action = $p.action; ownerCountBefore = $p.ownerCount; added = $false; readBack = $null; reason = $p.reason }
        [void]$rows.Add($r)
        if ($p.action -eq 'present') { $r.readBack = $true; continue }
        if ($p.action -ne 'add') { [void]$probs.Add("'$($p.displayName)': $($p.reason)"); continue }
        if ($PlanOnly) { continue }
        try { [void](& $Graph 'POST' "/applications/$($p.objectId)/owners/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$me" }); $r.added = $true }
        catch {
            $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim()
            if ($m -match '(?i)already exist') { $r.added = $true }
            else { $r.readBack = $false; $r.reason = "the add was refused: $m"; [void]$probs.Add("'$($p.displayName)': $($r.reason)"); continue }
        }
        # READ BACK, never assumed
        $r.readBack = $false
        for ($i = 0; $i -lt [Math]::Max(1, $PollCount); $i++) {
            $bk = Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $p.objectId
            if ($bk.ok -and (@($bk.owners | ForEach-Object { $_.id }) -contains $me)) { $r.readBack = $true; break }
            if ($i -lt $PollCount - 1) { & $Sleep $PollSeconds }
        }
        if ($r.readBack) { $r.reason = 'the updater added as an owner (read back)' }
        else { $r.reason = 'the add was accepted, but the updater is NOT read back as an owner -- not ok'; [void]$probs.Add("'$($p.displayName)': $($r.reason)") }
    }
    $out.rows = @($rows.ToArray() | ForEach-Object { [pscustomobject]$_ })
    $out.problems = @($probs.ToArray())
    $out.ok = (-not $PlanOnly) -and $probs.Count -eq 0
    $out.record = [pscustomobject]@{ step = 'app-reg-owner-add'; planOnly = [bool]$PlanOnly; utc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); updaterObjectId = $me
                                     updater = $idn.displayName; rows = $out.rows; notes = @($found.notes); problems = $out.problems }
    return [pscustomobject]$out
}

function Test-PimAppRegOwnerIsSupportOwner {
    <#
      READ ONLY. Is this OWNER the Invardia Support app? Only a service principal can be: its app id equals -SupportAppId, or
      Test-PimSqlAdminMemberIsSupportApp (the 'InvardiaSupport' tag / 'Invardia Support' name) says $true. $true / $false /
      $null (not proven either way -- never removed).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][object]$Owner, [AllowEmptyString()][string]$SupportAppId = '')
    if ("$($Owner.type)" -ne 'servicePrincipal') { return $false }
    if ((Test-PimAppRegOwnerGuid $SupportAppId) -and (Test-PimAppRegOwnerGuid "$($Owner.appId)") -and ([guid]"$($Owner.appId)") -eq ([guid]"$SupportAppId".Trim())) { return $true }
    return (Test-PimSqlAdminMemberIsSupportApp -Graph $Graph -ObjectId "$($Owner.id)")
}

function Invoke-PimAppRegOwnerSupportRemove {
    <#
      Step (d), RUN AS THE INVARDIA SUPPORT APP. Per product registration present:
        refused  no proof recorded for it by THIS updater (-Proof = pim.Settings 'AppRegOwnerProof', Test-PimAppRegOwnerProof),
                 or the updater is not read as an owner NOW, or its owners are not readable -- nothing written
        absent   the Support app is not an owner -- nothing written
        remove   each owner PROVEN to be the Support app (Test-PimAppRegOwnerIsSupportOwner $true) is removed
                 (a DELETE of its owner reference) and READ BACK (gone; the updater still an owner). Any other owner stays.
      -PlanOnly = read + plan, nothing written. Returns @{ ok; planOnly; rows[]; problems[]; record }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][AllowEmptyString()][string]$UpdaterObjectId, [AllowNull()][object]$Proof,
          [AllowEmptyString()][string]$SupportAppId = '', [AllowNull()][object]$Recorded = $null, [AllowEmptyString()][string]$Label = '', [switch]$PlanOnly,
          [int]$PollSeconds = 5, [int]$PollCount = 12, [string[]]$Roles = @(), [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{ ok = $false; planOnly = [bool]$PlanOnly; rows = @(); problems = @(); record = $null }
    $probs = New-Object System.Collections.Generic.List[string]
    if (-not (Test-PimAppRegOwnerGuid $UpdaterObjectId)) { $out.problems = @("REFUSED -- '$UpdaterObjectId' is not the updater's object id; nothing written"); return [pscustomobject]$out }
    $me = ([guid]"$UpdaterObjectId".Trim()).ToString()
    $found = Find-PimAppRegOwnerTargets -Graph $Graph -Recorded $Recorded -Label $Label -Roles $Roles
    if (-not $found.ok) { $out.problems = @("$($found.reason) -- nothing written"); return [pscustomobject]$out }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($found.targets)) {
        $r = [ordered]@{ role = $t.role; displayName = $t.displayName; appId = $t.appId; objectId = $t.objectId; action = 'refused'; proofUtc = ''; removed = @(); kept = 0; readBack = $null; reason = '' }
        [void]$rows.Add($r)
        # 1. the updater's RECORDED proof for THIS registration -- without it nothing is written
        $pf = Test-PimAppRegOwnerProof -Proof $Proof -UpdaterObjectId $me -ObjectId $t.objectId -AppId $t.appId -NowUtc $NowUtc
        if (-not $pf.ok) { $r.reason = "REFUSED -- $($pf.reason); the Support app stays an owner"; [void]$probs.Add("'$($t.displayName)': $($r.reason)"); continue }
        $r.proofUtc = $pf.provenUtc
        # 2. the owners NOW: the updater must be one
        $ow = Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $t.objectId
        if (-not $ow.ok) { $r.reason = "REFUSED -- $($ow.reason)"; [void]$probs.Add("'$($t.displayName)': $($r.reason)"); continue }
        if (@($ow.owners | ForEach-Object { $_.id }) -notcontains $me) { $r.reason = 'REFUSED -- the updater is not read as an owner now; the Support app stays an owner'; [void]$probs.Add("'$($t.displayName)': $($r.reason)"); continue }
        # 3. only owners PROVEN to be the Support app
        $sup = New-Object System.Collections.Generic.List[object]; $unproven = 0
        foreach ($w in @($ow.owners)) {
            if ("$($w.id)" -eq $me) { continue }
            $is = Test-PimAppRegOwnerIsSupportOwner -Graph $Graph -Owner $w -SupportAppId $SupportAppId
            if ($is -eq $true) { [void]$sup.Add($w) } elseif ($null -eq $is) { $unproven++ }
        }
        $r.kept = @($ow.owners).Count - $sup.Count
        if ($unproven) { [void]$probs.Add("'$($t.displayName)': $unproven owner(s) could not be proven NOT to be the Support app -- they stay") }
        if (-not $sup.Count) { $r.action = 'absent'; $r.readBack = $true; $r.reason = 'the Support app is not an owner -- nothing to do'; continue }
        $r.action = 'remove'
        if ($PlanOnly) { $r.reason = "would remove the Support app ($($sup.Count) owner entry); $($r.kept) other owner(s) stay"; continue }
        $err = ''
        foreach ($s in $sup) {
            try { [void](& $Graph 'DELETE' "/applications/$($t.objectId)/owners/$($s.id)/`$ref" $null); $r.removed += "$($s.id)" }
            catch { $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim(); if ($m -match '(?i)\b404\b|Request_ResourceNotFound|does not exist') { $r.removed += "$($s.id)" } else { $err = $m } }
        }
        # READ BACK: the Support app gone, the updater still an owner
        $r.readBack = $false
        $gone = @($sup | ForEach-Object { "$($_.id)" })
        for ($i = 0; $i -lt [Math]::Max(1, $PollCount); $i++) {
            $bk = Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $t.objectId
            if ($bk.ok) {
                $ids = @($bk.owners | ForEach-Object { $_.id })
                if ($ids -contains $me -and -not @($gone | Where-Object { $ids -contains $_ }).Count) { $r.readBack = $true; break }
            }
            if ($i -lt $PollCount - 1) { & $Sleep $PollSeconds }
        }
        if ($r.readBack -and -not $err) { $r.reason = "the Support app removed as an owner (read back; the updater still owns it; $($r.kept) other owner(s) stay)" }
        else { $r.reason = $(if ($err) { "the removal was refused: $err -- not ok" } else { 'the removal was accepted, but the read-back does not show it -- not ok' }); [void]$probs.Add("'$($t.displayName)': $($r.reason)") }
    }
    $out.rows = @($rows.ToArray() | ForEach-Object { [pscustomobject]$_ })
    $out.problems = @($probs.ToArray())
    $out.ok = (-not $PlanOnly) -and $probs.Count -eq 0
    $out.record = [pscustomobject]@{ step = 'app-reg-owner-support-out'; planOnly = [bool]$PlanOnly; utc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); updaterObjectId = $me
                                     rows = $out.rows; notes = @($found.notes); problems = $out.problems }
    return [pscustomobject]$out
}
