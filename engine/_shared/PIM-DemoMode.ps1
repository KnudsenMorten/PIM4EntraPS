#Requires -Version 5.1
<#
  PIM-DemoMode.ps1 -- REQUIREMENTS s98 "LIVE DEMO ENVIRONMENT ON RING 2" (owner 2026-10-07).

  DEMO MODE: a setting (pim.Settings 'DemoMode', default OFF). When it is on, a signed-in viewer who is a member of the
  demo guest group (pim.Settings 'DemoGuestGroup', default 'Invardia-Demo-Guests') gets the role 'Demo': they may look
  at every page and STAGE changes in their own browser, and every request that would leave the browser and change
  something -- commit, approve, run now, revoke, a settings save, any POST / PUT / DELETE / PATCH that is not a pure
  preview -- is refused by the SERVER with a friendly 403. The GUI hint (banner, enabled buttons) is secondary; the
  server is the boundary.

  THE RULES THIS FILE ENCODES (all PURE, all offline-tested by tests/Test-PimDemoMode.ps1):
    * OFF means OFF. Test-PimDemoModeValue accepts only an explicit "on" spelling; anything else -- a missing setting,
      $null, "", "off", a typo, an object -- is OFF, and with demo mode off nothing in this file is consulted at all.
    * The Demo role is a CAP, never an elevation. For every existing role check it ranks as Reader (the Manager's
      Test-PimManagerRoleAtLeast), so a demo viewer can never pass a gate a Reader could not pass -- and secrets that a
      Reader sees masked stay masked.
    * DEFAULT DENY for writes. A demo viewer's request is allowed only when its method is a read (GET / HEAD / OPTIONS)
      or it is one of a short, named list of pure computations (Get-PimDemoPreviewRoutes) that write nothing. A route
      added to the Manager later is therefore refused for a demo viewer until somebody decides otherwise.
    * Membership that cannot be checked is treated as membership (fail CLOSED): with demo mode on, a viewer whose
      membership cannot be determined is a demo viewer. A demo environment that cannot tell a visitor from an
      operator must refuse the write, not allow it.
#>

function Get-PimDemoDefaultGuestGroup { 'Invardia-Demo-Guests' }

function Get-PimDemoRefusalMessage { 'This is a live demo: you can try everything and stage changes, but nothing is saved.' }

function Test-PimDemoModeValue {
    <#
      PURE. Is this stored DemoMode value ON? Only an explicit "on" spelling is: $true, 1, or the text true / on / 1 /
      yes / enabled (any case, trimmed), or an object whose 'on' / 'enabled' property is one of those. Everything else
      -- $null, '', 'off', 'false', 0, a typo -- is OFF. A demo switch that turns on by accident would take an
      environment's administrators away from it, so the default direction is OFF.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [int] -or $Value -is [long]) { return ([long]$Value -eq 1) }
    if ($Value -is [string]) { return ("$Value".Trim() -match '^(?i)(true|on|1|yes|enabled)$') }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in @('on', 'enabled')) { if ($Value.Contains($k)) { return (Test-PimDemoModeValue -Value $Value[$k]) } }
        return $false
    }
    if ($Value.PSObject -and $Value.PSObject.Properties) {
        foreach ($k in @('on', 'enabled')) { if ($Value.PSObject.Properties[$k]) { return (Test-PimDemoModeValue -Value $Value.$k) } }
    }
    return $false
}

function Resolve-PimDemoGuestGroupName {
    <# PURE. The configured demo guest group (display name or object id), or the default when the setting is empty. #>
    param([AllowNull()][object]$Value)
    $v = ''
    if ($null -ne $Value) {
        if ($Value -is [string]) { $v = "$Value" }
        elseif ($Value.PSObject -and $Value.PSObject.Properties['name']) { $v = "$($Value.name)" }
        else { $v = "$Value" }
    }
    $v = ($v -replace '[\x00-\x1F\x7F]', '').Trim().Trim('"').Trim()
    if (-not $v) { return (Get-PimDemoDefaultGuestGroup) }
    return $v
}

function ConvertTo-PimDemoIdentityNames {
    <#
      PURE. Every spelling one signed-in person can carry, lower-case: the name as given, and for a B2B guest UPN
      ('jane_contoso.com#EXT#@demo.onmicrosoft.com') the home address it stands for ('jane@contoso.com'). A guest
      signs in with their HOME address (the Easy Auth name is their preferred_username), while the directory lists
      them by the #EXT# UPN -- the two have to meet.
    #>
    param([string[]]$Names = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names)) {
        $s = "$n".Trim().ToLowerInvariant()
        if (-not $s) { continue }
        if (-not $out.Contains($s)) { $out.Add($s) }
        if ($s -match '^(?<local>.+)#ext#@') {
            $local = $Matches['local']
            $i = $local.LastIndexOf('_')
            if ($i -gt 0 -and $i -lt ($local.Length - 1)) {
                $homeAddr = $local.Substring(0, $i) + '@' + $local.Substring($i + 1)
                if (-not $out.Contains($homeAddr)) { $out.Add($homeAddr) }
            }
        }
    }
    return $out.ToArray()
}

function Test-PimDemoGroupMember {
    <#
      PURE. Is this person in the demo guest group? -Identities: the signed-in names. -ClaimGroupIds: the group object
      ids the sign-in token carried (the 'groups' claim; empty when the app does not emit it). -GroupId: the demo
      group's object id ('' when it could not be resolved). -Members: the group's (transitive) user members, each with
      userPrincipalName / mail / otherMails. Returns @{ member; via }.
    #>
    param([string[]]$Identities = @(), [string[]]$ClaimGroupIds = @(), [string]$GroupId = '', [object[]]$Members = @())
    $gid = "$GroupId".Trim().ToLowerInvariant()
    if ($gid) {
        foreach ($c in @($ClaimGroupIds)) { if ("$c".Trim().ToLowerInvariant() -eq $gid) { return @{ member = $true; via = 'the sign-in token''s group claim' } } }
    }
    $mine = @(ConvertTo-PimDemoIdentityNames -Names $Identities)
    if (-not $mine.Count) { return @{ member = $false; via = 'no identity' } }
    foreach ($m in @($Members)) {
        if ($null -eq $m) { continue }
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($p in @('userPrincipalName', 'mail')) {
            $v = $null
            if ($m -is [System.Collections.IDictionary]) { $v = $m[$p] } elseif ($m.PSObject.Properties[$p]) { $v = $m.$p }
            if ("$v".Trim()) { $names.Add("$v") }
        }
        $om = $null
        if ($m -is [System.Collections.IDictionary]) { $om = $m['otherMails'] } elseif ($m.PSObject.Properties['otherMails']) { $om = $m.otherMails }
        foreach ($o in @($om)) { if ("$o".Trim()) { $names.Add("$o") } }
        $theirs = @(ConvertTo-PimDemoIdentityNames -Names @($names.ToArray()))
        foreach ($t in $theirs) { if ($mine -contains $t) { return @{ member = $true; via = 'the group''s member list' } } }
    }
    return @{ member = $false; via = 'not a member' }
}

function Get-PimDemoPreviewRoutes {
    <#
      PURE. The non-read requests a demo viewer may still make, because each one only COMPUTES an answer and writes
      nothing anywhere (proven per route in tests/Test-PimDemoMode.ps1). Each still runs its OWN role check after this,
      exactly as for anyone else. method + path regex.
        POST /api/heartbeat         keeps the page's session alive (a timestamp in memory)
        POST /api/diff/<entity>     previews staged rows against the stored rows (Review & Save)
        POST /api/preflight         validates the staged rows (what the store would look like after a commit)
        POST /api/wizard/derive     derives names / sources for a wizard step
    #>
    @(
        @{ method = 'POST'; pattern = '^/api/heartbeat$' }
        @{ method = 'POST'; pattern = '^/api/diff/[\w\.-]+$' }
        @{ method = 'POST'; pattern = '^/api/preflight$' }
        @{ method = 'POST'; pattern = '^/api/wizard/derive$' }
    )
}

function Get-PimDemoRequestDecision {
    <#
      PURE. What happens to ONE request from a DEMO viewer. Returns @{ allow; kind; status }:
        kind 'read'          GET / HEAD / OPTIONS -- served as for a Reader
        kind 'preview'       one of Get-PimDemoPreviewRoutes -- served (it writes nothing)
        kind 'local-pending' GET /api/pending -- answered "staging stays in this browser" (a demo viewer neither sees
                             other visitors' staged changes nor puts theirs in the shared store)
        kind 'refused'       everything else: 403 with Get-PimDemoRefusalMessage, before any handler runs
      Not called for anyone who is not a demo viewer.
    #>
    param([string]$Method = '', [string]$Path = '')
    $m = "$Method".Trim().ToUpperInvariant()
    $p = "$Path"
    if ($m -eq 'GET' -and $p -eq '/api/pending') { return @{ allow = $false; kind = 'local-pending'; status = 200 } }
    if ($m -in @('GET', 'HEAD', 'OPTIONS')) { return @{ allow = $true; kind = 'read'; status = 0 } }
    foreach ($r in @(Get-PimDemoPreviewRoutes)) {
        if ($m -eq $r.method -and $p -match $r.pattern) { return @{ allow = $true; kind = 'preview'; status = 0 } }
    }
    return @{ allow = $false; kind = 'refused'; status = 403 }
}

function Get-PimDemoRefusalBody {
    <# PURE. The 403 body a demo viewer gets for a write. No internal names, ids or paths -- a visitor reads it. #>
    param([string]$Method = '', [string]$Path = '')
    return [ordered]@{
        ok    = $false
        demo  = $true
        gate  = 'demo'
        error = (Get-PimDemoRefusalMessage)
    }
}

function Get-PimDemoLocalPendingBody {
    <# PURE. GET /api/pending for a demo viewer: no shared store -- the page keeps the staged changes in this browser. #>
    return [ordered]@{
        ok = $true; shared = $false; demo = $true; version = 0; bases = @{}
        note = 'live demo -- staged changes stay in this browser and are never saved'
    }
}
