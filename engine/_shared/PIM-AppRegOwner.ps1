#Requires -Version 5.1
<#
.SYNOPSIS
    APP-REG-OWNER (framework SECAUDIT-1a item 2, Invardia ruling 2026-11-07; PIM 3.0.54) -- PIM's PRODUCT app registrations
    are OWNED by the install's UPDATER identity (ca-pim-update's system-assigned managed identity). The shared half: which
    registrations count, how they are found, how their owners are read, and the UPDATER's own step (c).

.DESCRIPTION
    The order per install, EXACTLY (Invardia):
      (a) a RECORDED SUPPORT-APP step adds the updater as an owner and reads it back (tools/setup/_PimAppRegOwner.ps1
          Invoke-PimAppRegOwnerAdd) -- never the updater itself;
      (b) Application.ReadWrite.OwnedBy is in the ONE updater list (engine/_shared/PIM-UpdaterGraphRoles.ps1): the install
          grants it, existing installs get it by the ops grant -- the updater never grants itself;
      (c) the UPDATER, every run (update-job-entry.ps1 step 2f-bis, Invoke-PimAppRegOwnerUpdaterCheck): per product
          registration present, READS whether it is an owner and REPORTS it (UpdateState.setupFacts appRegOwner); where it IS
          an owner and its token carries OwnedBy, it proves the ownership ONCE by a harmless PATCH it reads back (the
          registration's notes set to Get-PimAppRegOwnerMarker -- ONLY when the notes are empty or already that marker; a
          customer's text is never overwritten) and records the proof (pim.Settings 'AppRegOwnerProof', setupFacts
          appRegOwnerProof = ok + utc);
      (d) a RECORDED SUPPORT-APP step removes the Support app as owner -- ONLY with (c)'s proof for that registration and the
          updater read as an owner now; never any other owner (tools/setup/_PimAppRegOwner.ps1
          Invoke-PimAppRegOwnerSupportRemove).
    PRODUCT REGISTRATIONS (Invardia 2026-11-07): display names EXACTLY "PIM Manager", "PIM Manager Engine", "PIM Activator",
    "PIM Manager Deploy", "PIM access request API" -- where present. A registration the INSTALL RECORDED (the Manager's
    sign-in client id: PIM_SIGNIN_FRONT_CLIENT_ID / PIM_HOSTED_EASYAUTH_AUD / its Easy Auth client id; the engine app:
    the tick job's PIM_ClientId) is found BY ITS APP ID first and may carry an install label ("PIM Manager (<label>)"); a
    display-name search is the fallback for a role with no recorded id, EXACT names only, and more than one hit is never
    guessed. Any other registration (PIM-Exchange-Provision*, PIM-Provision-GroupMembers*, PIM-Role-Advisor,
    "PIM-Manager-Hosted", a customer's own) is NEVER touched -- not even read for owners.
    RULES OF THIS FILE (Test-PimAppRegOwner Z): the only Graph WRITE here is the PATCH of a product registration's notes;
    no owner add / remove, no app role assignment, no ARM write; ASCII only; PS 5.1 + 7; no modules.
    Seams: -Graph { param($Method, $Path, $Body) } (Graph v1.0 relative paths), -Arm { param($Method, $Path, $Body) }.
#>
Set-StrictMode -Off

function Get-PimAppRegOwnerMarker { <# PURE. LITERAL. The notes text of the one harmless proof PATCH. #> return "PIM Manager: owned by this installation's updater" }
function Get-PimAppRegOwnerProofSetting { <# PURE. LITERAL. The pim.Settings row the proof is kept in. #> return 'AppRegOwnerProof' }
function Get-PimAppRegOwnerOwnedByRole { <# PURE. LITERAL. The Graph application permission the updater writes as owner with. #> return 'Application.ReadWrite.OwnedBy' }

function Get-PimAppRegOwnerProducts {
    <# PURE. The product registrations, in order: @{ role; name }. EXACTLY Invardia's list (2026-11-07). #>
    return @(
        [pscustomobject]@{ role = 'manager';   name = 'PIM Manager' }
        [pscustomobject]@{ role = 'engine';    name = 'PIM Manager Engine' }
        [pscustomobject]@{ role = 'activator'; name = 'PIM Activator' }
        [pscustomobject]@{ role = 'deploy';    name = 'PIM Manager Deploy' }
        [pscustomobject]@{ role = 'rfa';       name = 'PIM access request API' }
    )
}

function Get-PimAppRegOwnerInstallRoles {
    <#
      PURE (Invardia 2026-11-07, option 1). The product roles an install's updater owns, by edition: a COMMUNITY install only
      its own sign-in registration ('manager'); a Pro install every product role. -Edition: 'community' | 'pro' (anything
      else = 'pro').
    #>
    param([AllowEmptyString()][string]$Edition = '')
    if ("$Edition".Trim() -ieq 'community') { return @('manager') }
    return @(Get-PimAppRegOwnerProducts | ForEach-Object { $_.role })
}

function Get-PimAppRegOwnerUpdaterEdition {
    <#
      PURE. The edition from the update job's own source settings: the Invardia Community channel (PIM_UPDATE_SOURCE
      'invardia-community', or a source address under /community/) = 'community'; anything else = 'pro'.
    #>
    param([AllowEmptyString()][string]$Source = '', [AllowEmptyString()][string]$SourceUrl = '')
    if ("$Source".Trim() -ieq 'invardia-community' -or "$SourceUrl" -match '(?i)/api/updates/[^/]+/community/') { return 'community' }
    return 'pro'
}

function Get-PimAppRegOwnerField {
    # PURE. A property of an object or a dictionary ($null when absent).
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Test-PimAppRegOwnerGuid {
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $g = [guid]::Empty
    return ([bool]"$Value".Trim() -and [guid]::TryParse("$Value".Trim(), [ref]$g))
}

function Get-PimAppRegOwnerRole {
    <#
      PURE. The product role of a display name ('' = NOT a product registration -- never touched). Case-sensitive, exact.
        -Label       an install label: "<name> (<label>)" counts too
        -AllowLabel  any "<name> (<label>)" counts (only for a registration found by the app id the INSTALL recorded)
    #>
    param([AllowEmptyString()][AllowNull()][string]$DisplayName, [AllowEmptyString()][string]$Label = '', [switch]$AllowLabel)
    $dn = "$DisplayName"
    if (-not $dn) { return '' }
    foreach ($p in @(Get-PimAppRegOwnerProducts)) {
        if ($dn -ceq $p.name) { return $p.role }
        if ("$Label".Trim() -and $dn -ceq "$($p.name) ($("$Label".Trim()))") { return $p.role }
        if ($AllowLabel -and $dn -cmatch ('^' + [regex]::Escape($p.name) + ' \([^()]{1,64}\)$')) { return $p.role }
    }
    return ''
}

function Get-PimAppRegOwnerEnvGuids {
    # PURE. The app ids (guids) a container's env variables -Names carry (comma / semicolon lists; 'api://<guid>' too).
    param([AllowNull()][object]$Resource, [string[]]$Names)
    $out = New-Object System.Collections.Generic.List[string]
    $tpl = Get-PimAppRegOwnerField (Get-PimAppRegOwnerField $Resource 'properties') 'template'
    foreach ($c in @(Get-PimAppRegOwnerField $tpl 'containers')) {
        foreach ($e in @(Get-PimAppRegOwnerField $c 'env')) {
            if (-not $e -or @($Names) -notcontains "$(Get-PimAppRegOwnerField $e 'name')") { continue }
            foreach ($tok in @("$(Get-PimAppRegOwnerField $e 'value')" -split '[,;\s]+')) {
                $t = "$tok".Trim() -replace '^(?i)api://', ''
                $g = [guid]::Empty
                if ([guid]::TryParse($t, [ref]$g) -and -not $out.Contains($g.ToString())) { [void]$out.Add($g.ToString()) }
            }
        }
    }
    return @($out.ToArray())
}

function Get-PimAppRegOwnerRecordedAppIds {
    <#
      PURE. The app ids the INSTALL recorded, per role: @{ manager = @(); engine = @() }.
        manager  the Manager's sign-in: PIM_SIGNIN_FRONT_CLIENT_ID, PIM_HOSTED_EASYAUTH_AUD (env of -ManagerApp) and its Easy
                 Auth registration's client id (-ManagerAuth = authConfigs/current)
        engine   the tick job's PIM_ClientId (-TickJob; an install on a managed identity has none)
    #>
    param([AllowNull()][object]$ManagerApp, [AllowNull()][object]$ManagerAuth, [AllowNull()][object]$TickJob)
    $m = New-Object System.Collections.Generic.List[string]
    foreach ($g in @(Get-PimAppRegOwnerEnvGuids -Resource $ManagerApp -Names @('PIM_SIGNIN_FRONT_CLIENT_ID', 'PIM_HOSTED_EASYAUTH_AUD'))) { if (-not $m.Contains($g)) { [void]$m.Add($g) } }
    $aad = Get-PimAppRegOwnerField (Get-PimAppRegOwnerField (Get-PimAppRegOwnerField $ManagerAuth 'properties') 'identityProviders') 'azureActiveDirectory'
    $cid = "$(Get-PimAppRegOwnerField (Get-PimAppRegOwnerField $aad 'registration') 'clientId')".Trim()
    $g2 = [guid]::Empty
    if ([guid]::TryParse($cid, [ref]$g2) -and -not $m.Contains($g2.ToString())) { [void]$m.Add($g2.ToString()) }
    return @{ manager = @($m.ToArray()); engine = @(Get-PimAppRegOwnerEnvGuids -Resource $TickJob -Names @('PIM_ClientId')) }
}

function Resolve-PimAppRegOwnerInstallFacts {
    <#
      READ ONLY (ARM GET). The install's updater identity (the update job's SYSTEM identity: its principalId = the service
      principal's object id) and the app ids it recorded (Get-PimAppRegOwnerRecordedAppIds). Never throws.
      Returns @{ updaterObjectId; recorded; reasons[] }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [string]$TickJob = 'ca-pim-tick', [string]$UpdateJob = 'ca-pim-update')
    $o = @{ updaterObjectId = ''; recorded = @{ manager = @(); engine = @() }; reasons = @() }
    $why = New-Object System.Collections.Generic.List[string]
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App"
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { [void]$why.Add(((("$($_.Exception.Message)") -split "`n")[0]).Trim()); $null } }
    $upd = & $get "$rg/jobs/$UpdateJob`?api-version=2024-03-01"
    $oid = "$(Get-PimAppRegOwnerField (Get-PimAppRegOwnerField $upd 'identity') 'principalId')".Trim()
    if (Test-PimAppRegOwnerGuid $oid) { $o.updaterObjectId = ([guid]$oid).ToString() } else { [void]$why.Add("the update job $UpdateJob has no system identity readable") }
    $mgr = & $get "$rg/containerApps/$ManagerApp`?api-version=2024-03-01"
    $auth = $null; if ($mgr) { $auth = & $get "$rg/containerApps/$ManagerApp/authConfigs/current?api-version=2024-03-01" }
    $tick = & $get "$rg/jobs/$TickJob`?api-version=2024-03-01"
    $o.recorded = Get-PimAppRegOwnerRecordedAppIds -ManagerApp $mgr -ManagerAuth $auth -TickJob $tick
    $o.reasons = @($why.ToArray())
    return $o
}

function Find-PimAppRegOwnerTargets {
    <#
      READ ONLY (Graph GET, Application.Read.All). The product registrations present: a role with a RECORDED app id is found by
      it (GET /applications(appId='...')), and only kept when its display name is that role's product name (an install label
      allowed); a role without one by its EXACT display name (and "<name> (<label>)" with -Label). More than one hit = ambiguous,
      none of them is a target. Never throws.
      Returns @{ ok; targets[] ({ role; objectId; appId; displayName; notes; via }); ambiguous[] ({ role; name; count }); notes[]; reason }.
    #>
    # -Roles (Invardia 2026-11-07, option 1): only these product roles count for this install (Get-PimAppRegOwnerInstallRoles);
    # empty = every product role. A Community install's updater never gets write on a Pro registration sharing its tenant.
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowNull()][object]$Recorded = $null, [AllowEmptyString()][string]$Label = '', [string[]]$Roles = @())
    $o = @{ ok = $true; targets = @(); ambiguous = @(); notes = @(); reason = '' }
    $t = New-Object System.Collections.Generic.List[object]; $amb = New-Object System.Collections.Generic.List[object]; $nt = New-Object System.Collections.Generic.List[string]
    $sel = '$select=id,appId,displayName,notes'
    $mk = { param($a, $role, $via) [pscustomobject]@{ role = $role; objectId = "$(Get-PimAppRegOwnerField $a 'id')".Trim(); appId = "$(Get-PimAppRegOwnerField $a 'appId')".Trim(); displayName = "$(Get-PimAppRegOwnerField $a 'displayName')"; notes = "$(Get-PimAppRegOwnerField $a 'notes')"; via = $via } }
    try {
        $want = @(@($Roles) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        foreach ($p in @(Get-PimAppRegOwnerProducts | Where-Object { -not $want.Count -or $want -contains $_.role })) {
            $ids = @(@(Get-PimAppRegOwnerField $Recorded $p.role) | Where-Object { Test-PimAppRegOwnerGuid "$_" })
            $byId = 0
            foreach ($id in $ids) {
                $a = $null
                try { $a = & $Graph 'GET' ("/applications(appId='$(([guid]"$id").ToString())')?" + $sel) $null }
                catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|Request_ResourceNotFound|does not exist') { $a = $null } else { throw } }
                if (-not $a -or -not "$(Get-PimAppRegOwnerField $a 'id')".Trim()) { [void]$nt.Add("the recorded $($p.role) app id $id has no app registration in this tenant"); continue }
                $r = Get-PimAppRegOwnerRole -DisplayName "$(Get-PimAppRegOwnerField $a 'displayName')" -Label $Label -AllowLabel
                if ($r -ne $p.role) { [void]$nt.Add("the recorded $($p.role) registration '$(Get-PimAppRegOwnerField $a 'displayName')' is not named as a PIM product registration -- never touched"); continue }
                [void]$t.Add((& $mk $a $p.role 'recorded')); $byId++
            }
            if ($byId) { continue }
            $names = @($p.name); if ("$Label".Trim()) { $names += "$($p.name) ($("$Label".Trim()))" }
            foreach ($n in $names) {
                $f = [uri]::EscapeDataString("displayName eq '$($n.Replace("'", "''"))'")
                $hits = @(@((& $Graph 'GET' ("/applications?`$filter=$f&" + $sel) $null).value) | Where-Object { $_ -and "$(Get-PimAppRegOwnerField $_ 'displayName')" -ceq $n -and "$(Get-PimAppRegOwnerField $_ 'id')".Trim() })
                if ($hits.Count -gt 1) { [void]$amb.Add([pscustomobject]@{ role = $p.role; name = $n; count = $hits.Count }); [void]$nt.Add("$($hits.Count) registrations are named '$n' -- none is touched (never guessed)") }
                elseif ($hits.Count -eq 1) { [void]$t.Add((& $mk $hits[0] $p.role 'name')) }
            }
        }
    } catch { $o.ok = $false; $o.reason = "the app registrations could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    # one registration once (a recorded id that also carries a searched name)
    $seen = @{}; $u = New-Object System.Collections.Generic.List[object]
    foreach ($x in $t) { $k = "$($x.objectId)".ToLowerInvariant(); if ($k -and -not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$u.Add($x) } }
    $o.targets = @($u.ToArray()); $o.ambiguous = @($amb.ToArray()); $o.notes = @($nt.ToArray())
    return $o
}

function Get-PimAppRegOwnerOwners {
    <#
      READ ONLY. The owners of ONE application object (every page, at most 10): @{ ok; owners[] ({ id; appId; displayName;
      type = servicePrincipal | user | other }); reason }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ObjectId)
    $o = @{ ok = $false; owners = @(); reason = '' }
    $l = New-Object System.Collections.Generic.List[object]
    try {
        $page = & $Graph 'GET' ("/applications/$("$ObjectId".Trim())/owners?" + '$select=id,appId,displayName') $null
        for ($i = 0; $i -lt 10 -and $null -ne $page; $i++) {
            foreach ($w in @(Get-PimAppRegOwnerField $page 'value')) {
                if (-not $w) { continue }
                $ty = "$(Get-PimAppRegOwnerField $w '@odata.type')"
                [void]$l.Add([pscustomobject]@{ id = "$(Get-PimAppRegOwnerField $w 'id')".Trim().ToLowerInvariant(); appId = "$(Get-PimAppRegOwnerField $w 'appId')".Trim()
                                                 displayName = "$(Get-PimAppRegOwnerField $w 'displayName')"
                                                 type = $(if ($ty -match '(?i)servicePrincipal') { 'servicePrincipal' } elseif ($ty -match '(?i)user') { 'user' } else { 'other' }) })
            }
            $nl = "$(Get-PimAppRegOwnerField $page '@odata.nextLink')".Trim()
            if (-not $nl) { break }
            $page = & $Graph 'GET' $nl $null
        }
        $o.ok = $true; $o.owners = @($l.ToArray())
    } catch { $o.reason = "its owners could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    return $o
}

function Test-PimAppRegOwnerProof {
    <#
      PURE. Does the RECORDED proof (the pim.Settings 'AppRegOwnerProof' record) hold for this registration and this updater?
      Shape: { updaterObjectId; registrations = @({ objectId; appId; displayName; provenUtc }) }. Every field must match; the
      time must be a real UTC time not in the future. Returns @{ ok; provenUtc; reason }.
    #>
    param([AllowNull()][object]$Proof, [AllowEmptyString()][string]$UpdaterObjectId, [AllowEmptyString()][string]$ObjectId, [AllowEmptyString()][string]$AppId, [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ ok = $false; provenUtc = ''; reason = '' }
    if ($null -eq $Proof) { $o.reason = 'no proof is recorded (the updater proves ownership on its next run as owner)'; return $o }
    $pu = "$(Get-PimAppRegOwnerField $Proof 'updaterObjectId')".Trim()
    if (-not (Test-PimAppRegOwnerGuid $UpdaterObjectId) -or -not (Test-PimAppRegOwnerGuid $pu) -or ([guid]$pu) -ne ([guid]"$UpdaterObjectId".Trim())) { $o.reason = 'the recorded proof is for another updater identity (or none)'; return $o }
    foreach ($r in @(Get-PimAppRegOwnerField $Proof 'registrations')) {
        if (-not $r) { continue }
        $ro = "$(Get-PimAppRegOwnerField $r 'objectId')".Trim(); $ra = "$(Get-PimAppRegOwnerField $r 'appId')".Trim()
        if (-not (Test-PimAppRegOwnerGuid $ro) -or -not (Test-PimAppRegOwnerGuid $ObjectId) -or ([guid]$ro) -ne ([guid]"$ObjectId".Trim())) { continue }
        if (-not (Test-PimAppRegOwnerGuid $ra) -or -not (Test-PimAppRegOwnerGuid $AppId) -or ([guid]$ra) -ne ([guid]"$AppId".Trim())) { continue }
        $ts = "$(Get-PimAppRegOwnerField $r 'provenUtc')".Trim()
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse($ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { $o.reason = 'the recorded proof has no readable time'; return $o }
        if ($d -gt $NowUtc.AddMinutes(5)) { $o.reason = 'the recorded proof is dated in the future'; return $o }
        $o.ok = $true; $o.provenUtc = $d.ToString('yyyy-MM-ddTHH:mm:ssZ'); $o.reason = "proven by the updater's own write at $($o.provenUtc)"
        return $o
    }
    $o.reason = 'no proof is recorded for this registration'
    return $o
}

function Get-PimAppRegOwnerSetupFact {
    <#
      PURE. The run record (UpdateState.setupFacts) from the updater step's result:
        appRegOwner             ok (the updater owns every product registration present) | missing | n/a (none present) | unknown
        appRegOwnerDetail       which registration lacks it (one line, <= 200)
        appRegOwnerProof        ok (every product registration's ownership proven by the updater's own write) | pending | n/a | unknown
        appRegOwnerProofUtc     the latest proof time ('' when none)
        appRegOwnerProofDetail  which registration is not proven and why (one line, <= 200)
    #>
    param([AllowNull()][object]$Result)
    $cut = { param($x) $x = ("$x" -replace '[\r\n\t]+', ' ').Trim(); if ($x.Length -gt 200) { $x = $x.Substring(0, 197) + '...' }; $x }
    if ($null -eq $Result) { return [ordered]@{ appRegOwner = 'unknown'; appRegOwnerDetail = 'app registration owner: not checked this run'; appRegOwnerProof = 'unknown'; appRegOwnerProofUtc = ''; appRegOwnerProofDetail = 'app registration owner: not checked this run' } }
    return [ordered]@{ appRegOwner = "$($Result.state)"; appRegOwnerDetail = (& $cut "$($Result.detail)"); appRegOwnerProof = "$($Result.proofState)"
                       appRegOwnerProofUtc = "$($Result.proofUtc)"; appRegOwnerProofDetail = (& $cut "$($Result.proofDetail)") }
}

function Invoke-PimAppRegOwnerUpdaterCheck {
    <#
      The UPDATER's step (c) (update-job-entry.ps1 2f-bis). Per product registration present (Find-PimAppRegOwnerTargets):
      READ its owners, report whether -UpdaterObjectId is one; where it IS and -HoldsOwnedBy is $true and no proof is recorded
      for it yet (-StoredProof), ONE harmless PATCH of its notes to Get-PimAppRegOwnerMarker -- only when the notes are empty
      or already the marker -- READ BACK, and the proof recorded in the returned record (the caller stores it).
      It NEVER adds an owner, never removes one, never grants a role. Never throws.
      Returns @{ lines; warnings; changed; state; detail; proofState; proofUtc; proofDetail; proof; proofChanged; registrations[] }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$UpdaterObjectId, [AllowNull()][object]$HoldsOwnedBy = $null,
          [AllowNull()][object]$Recorded = $null, [AllowNull()][object]$StoredProof = $null, [AllowEmptyString()][string]$Label = '',
          [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$Roles = @())
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'app-reg-owner'; level = $level; text = "app registration owner: $text" }) }
    $first = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $o = [ordered]@{ lines = $null; warnings = 0; changed = 0; state = 'unknown'; detail = ''; proofState = 'unknown'; proofUtc = ''; proofDetail = ''
                     proof = $null; proofChanged = $false; registrations = @() }
    $marker = Get-PimAppRegOwnerMarker
    $regs = New-Object System.Collections.Generic.List[object]
    $me = ''; if (Test-PimAppRegOwnerGuid $UpdaterObjectId) { $me = ([guid]"$UpdaterObjectId".Trim()).ToString() }
    # the proof record: kept entries are the stored ones FOR THIS updater only (another identity proves again)
    $keep = New-Object System.Collections.Generic.List[object]
    if ($StoredProof -and $me -and (Test-PimAppRegOwnerGuid "$(Get-PimAppRegOwnerField $StoredProof 'updaterObjectId')") -and ([guid]"$(Get-PimAppRegOwnerField $StoredProof 'updaterObjectId')".Trim()) -eq ([guid]$me)) {
        foreach ($r in @(Get-PimAppRegOwnerField $StoredProof 'registrations')) { if ($r) { [void]$keep.Add($r) } }
    }
    $proofIn = [pscustomobject]@{ updaterObjectId = $me; registrations = @($keep.ToArray()) }
    if (-not $me) {
        $o.detail = "the updater's own object id is not known this run -- not checked"; $o.proofDetail = $o.detail
        & $add 'warn' $o.detail; $o.lines = @($lines.ToArray()); $o.warnings = 1; return [pscustomobject]$o
    }
    $found = Find-PimAppRegOwnerTargets -Graph $Graph -Recorded $Recorded -Label $Label -Roles $Roles
    foreach ($n in @($found.notes)) { & $add 'info' $n }
    if (-not $found.ok) {
        $o.detail = "$($found.reason)"; $o.proofDetail = $o.detail; & $add 'warn' "not checked -- $($found.reason)"
        $o.lines = @($lines.ToArray()); $o.warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count; return [pscustomobject]$o
    }
    foreach ($tg in @($found.targets)) {
        $r = [ordered]@{ role = $tg.role; displayName = $tg.displayName; appId = $tg.appId; objectId = $tg.objectId; isOwner = $null; proven = $false; provenUtc = ''; patched = $false; reason = '' }
        [void]$regs.Add($r)
        $ow = Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $tg.objectId
        if (-not $ow.ok) { $r.reason = "$($ow.reason)"; & $add 'warn' "'$($tg.displayName)' -- $($ow.reason)"; continue }
        $r.isOwner = [bool](@($ow.owners | ForEach-Object { $_.id }) -contains $me)
        if (-not $r.isOwner) {
            $r.reason = 'the updater is NOT an owner (a recorded support step adds it; the updater never adds itself)'
            & $add 'warn' "'$($tg.displayName)' -- $($r.reason)"; continue
        }
        $pf = Test-PimAppRegOwnerProof -Proof $proofIn -UpdaterObjectId $me -ObjectId $tg.objectId -AppId $tg.appId -NowUtc $NowUtc
        if ($pf.ok) { $r.proven = $true; $r.provenUtc = $pf.provenUtc; & $add 'info' "'$($tg.displayName)' -- owned by the updater; $($pf.reason)"; continue }
        if ($HoldsOwnedBy -ne $true) {
            $r.reason = $(if ($HoldsOwnedBy -eq $false) { "the updater's Graph token does not carry $(Get-PimAppRegOwnerOwnedByRole) yet (setup grants it; a token refreshes within 24 h) -- the proof waits" } else { "the updater's Graph permissions could not be read -- the proof waits" })
            & $add 'info' "'$($tg.displayName)' -- owned by the updater; $($r.reason)"; continue
        }
        $nt = "$($tg.notes)"
        if ($nt.Trim() -and $nt -cne $marker) {
            $r.reason = 'its notes hold other text, which is never overwritten -- the proof waits (support clears the notes or proves it another way)'
            & $add 'warn' "'$($tg.displayName)' -- owned by the updater; $($r.reason)"; continue
        }
        try {
            [void](& $Graph 'PATCH' "/applications/$($tg.objectId)" @{ notes = $marker })
            $r.patched = $true
            $back = & $Graph 'GET' ("/applications/$($tg.objectId)?" + '$select=id,notes') $null
            if ("$(Get-PimAppRegOwnerField $back 'notes')" -ceq $marker) {
                $r.proven = $true; $r.provenUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                # a stored entry for this registration (another app id, a stale one) is replaced
                $kept = @($keep.ToArray() | Where-Object { -not ((Test-PimAppRegOwnerGuid "$(Get-PimAppRegOwnerField $_ 'objectId')") -and ([guid]"$(Get-PimAppRegOwnerField $_ 'objectId')".Trim()) -eq ([guid]$tg.objectId)) })
                $keep.Clear(); foreach ($k in $kept) { [void]$keep.Add($k) }
                [void]$keep.Add([pscustomobject]@{ objectId = $tg.objectId; appId = $tg.appId; displayName = $tg.displayName; provenUtc = $r.provenUtc })
                $o.proofChanged = $true
                & $add 'changed' "'$($tg.displayName)' -- ownership PROVEN by the updater's own write (notes = the marker, read back) at $($r.provenUtc)"
            } else {
                $r.reason = 'the write was accepted but its notes read back as something else -- NOT proven'
                & $add 'warn' "'$($tg.displayName)' -- $($r.reason)"
            }
        } catch {
            $m = & $first $_
            $r.reason = $(if ($m -match '(?i)\b40[13]\b|Forbidden|Authorization_RequestDenied|Insufficient privileges') { "the updater's write as owner was refused ($m) -- its token may not carry $(Get-PimAppRegOwnerOwnedByRole) / the new ownership yet; NOT proven" } else { "the proof write failed ($m) -- NOT proven" })
            & $add 'warn' "'$($tg.displayName)' -- $($r.reason)"
        }
    }
    # ---- the verdict ---------------------------------------------------------------------------------------------------
    $ra = @($regs.ToArray()); $ambN = @($found.ambiguous).Count
    if (-not $ra.Count -and -not $ambN) { $o.state = 'n/a'; $o.proofState = 'n/a'; $o.detail = 'no PIM product app registration in this tenant'; $o.proofDetail = $o.detail }
    else {
        if (@($ra | Where-Object { $_.isOwner -eq $false }).Count) { $o.state = 'missing' }
        elseif (@($ra | Where-Object { $null -eq $_.isOwner }).Count -or $ambN) { $o.state = 'unknown' }
        else { $o.state = 'ok' }
        if (@($ra | Where-Object { $null -eq $_.isOwner }).Count -or $ambN) { $o.proofState = 'unknown' }
        elseif (@($ra | Where-Object { -not $_.proven }).Count) { $o.proofState = 'pending' }
        else { $o.proofState = 'ok' }
        $parts = @($ra | ForEach-Object { "$($_.displayName): $(if ($_.isOwner -eq $true) { 'updater owns it' } elseif ($_.isOwner -eq $false) { 'updater NOT an owner' } else { 'owners not readable' })" })
        if ($ambN) { $parts += @($found.ambiguous | ForEach-Object { "$($_.name): $($_.count) registrations (none touched)" }) }
        $o.detail = $parts -join '; '
        $np = @($ra | Where-Object { -not $_.proven })
        $o.proofDetail = $(if ($np.Count) { (@($np | ForEach-Object { "$($_.displayName): not proven$(if ("$($_.reason)".Trim()) { " ($($_.reason))" })" }) -join '; ') } else { 'every product registration: ownership proven by the updater''s own write' })
        $pu = @($ra | Where-Object { $_.proven -and "$($_.provenUtc)" } | ForEach-Object { "$($_.provenUtc)" } | Sort-Object)
        if ($pu.Count) { $o.proofUtc = $pu[-1] }
    }
    $o.proof = [pscustomobject]@{ updaterObjectId = $me; registrations = @($keep.ToArray()) }
    $o.registrations = $ra; $o.lines = @($lines.ToArray())
    $o.changed = @($lines | Where-Object { $_.level -eq 'changed' }).Count; $o.warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count
    return [pscustomobject]$o
}
