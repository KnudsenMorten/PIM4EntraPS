<#
  PIM-ManagerApiApps.ps1 -- SCRIPT / SERVICE SIGN-IN for the PIM Manager REST API (PIM REQUIREMENTS 93.4 / 93.5, framework
  APIDOC-1 "Who may call": "A product REST API offers script / service sign-in mapped to a product role").

  🔒 THE OWNER, binding (2026-11-01): "dont expose ways a hacker can gain access to customer". This IS a new way in, so
  everything here is DENY BY DEFAULT:
    * OFF until a SuperAdmin lists an application (its Entra app id) in Manager Settings with a role, and a SECOND
      SuperAdmin approves that change (the break-glass maker/checker shape: one request open at a time, a different
      SuperAdmin approves -- or the maker when ApprovalSelfApprove is on -- 72 h expiry, compare-and-set, every step
      audited). No list = no application is accepted, before any token is even looked at.
    * An application may hold Reader or Admin. NEVER SuperAdmin -- refused when the list is written and capped again
      when the role is read.
    * The token is verified IN THIS PROCESS: signature against the tenant's keys, issuer = this Manager's own tenant,
      audience = the pinned value (PIM_API_APP_AUDIENCE), exp / nbf, application-only (no delegated scope, no user
      claims), and it must carry this Manager's application role. No edge header (X-MS-CLIENT-PRINCIPAL ...) is read.
    * What an application may call is an explicit ALLOW-LIST of routes (Get-PimManagerAppRouteAllowList). Anything not on
      it is refused -- the GUI-only / Tier-0 actions, licence / access / MSP changes, approval decisions (a second PERSON
      approves), support bundles, diagnostics and API keys are simply not on it.
    * SETTINGS-API-1 (framework 12.31, owner 2026-11-16) + SUPPORT-FIX-API-1 (12.30): the THREE TIERS of
      Get-PimManagerAppTierMap -- tier 1 settings an Admin app changes and commits through the same guards, tier 2 grants an
      Admin app proposes and a person approves (the Support role commits on a ticket), tier 3 person only.
    * The MCP server is untouched: it stays person-only.

  Applications call the SAME routes as the page under the prefix /api/app/ (GET /api/app/drift = GET /api/drift). That
  prefix is the only place an application token is looked at; the page's /api/* is unchanged (the page token + the signed-in
  person), and the page token never opens /api/app/*.

  PURE core (no I/O): ConvertTo-PimManagerApiAppList, Get-PimManagerApiAppListHash, Get-PimManagerApiAppDiff,
  Resolve-PimManagerApiAppChangeCreate, Resolve-PimManagerApiAppChangeDecision, Resolve-PimManagerAppBearer,
  Get-PimManagerAppRouteAllowList, Test-PimManagerAppRouteAllowed, Resolve-PimManagerAppRequest.
  Store adapter (compare-and-set over pim.Settings): Get-PimManagerApiAppState, New-PimManagerApiAppChangeRequest,
  Close-PimManagerApiAppChangeRequest, Invoke-PimManagerApiAppChangeApproval. Every store call THROWS on a store failure
  (PIM v2 is SQL-only). PS 5.1-safe (no ?./??, no ternary).
  Needs PIM-HostedAuth.ps1 (Get-PimJwtParts; Invoke-PimTokenValidation from PIM-TokenValidation.ps1 -- Microsoft.IdentityModel) for the token check.
#>

Set-StrictMode -Off

function Get-PimManagerApiAppSettingName { 'ManagerApiApps' }
function Get-PimManagerApiAppChangeSettingName { 'ManagerApiAppsChange' }
function Get-PimManagerApiAppPrefix { '/api/app' }
function Get-PimManagerApiAppRoleValue { 'PimManager.Api' }
function Get-PimManagerAppBodyLimit { 1048576 }                    # framework 12.32 T29: an application's request body, at most 1 MB
function Get-PimManagerAppSupportBodyKeys {
    # PURE. framework 12.32 T30: the ONLY fields a Support body may carry (strict schema: anything else = 400, never ignored)
    param([string]$Path = '')
    if ($Path -eq '/api/support/fix') { return @('failureId', 'itemKey', 'fixId', 'reason') }
    if ($Path -eq '/api/support/change') { return @('entity', 'rows', 'baseRowsHash', 'reason') }
    return @()
}       # the application role a calling app must hold (Entra app role)
function Get-PimManagerApiAppRoles { @('Reader', 'Admin', 'Support') }   # never SuperAdmin. Support = SUPPORT-FIX-API-1 (framework 12.30): the tag-discovered support app only

function ConvertTo-PimManagerApiAppUtcText {
    # PURE. A time (a [datetime] or text) -> ISO 8601 UTC text; '' when absent / unreadable.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().ToString('o') }
    $s = "$Value".Trim(); if (-not $s) { return '' }
    $dt = [datetime]::MinValue
    $st = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $st, [ref]$dt)) { return $dt.ToUniversalTime().ToString('o') }
    return ''
}

function Get-PimManagerApiAppProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

# ---- the list ---------------------------------------------------------------------------------------------------------
function ConvertTo-PimManagerApiAppList {
    <#
      PURE. Any shape (the stored { apps:[...] }, a bare array, JSON text) -> @{ ok; apps; errors }. Each app is
      [ordered]@{ appId (lower-case GUID); role (Reader | Admin); name (<= 100 chars) }, sorted by appId, one entry per app.
      -Strict (the write path): any invalid entry -- a non-GUID id, a role that is not Reader / Admin (SuperAdmin included),
      a duplicate -- makes ok = $false with the reasons. Not strict (the read path): an invalid entry is DROPPED, never
      widened (a SuperAdmin entry written by hand is not an application with SuperAdmin; it is no application at all).
    #>
    param([AllowNull()][object]$Value, [switch]$Strict)
    $errors = New-Object System.Collections.Generic.List[string]
    $v = $Value
    if ($v -is [string]) {
        $s = "$v".Trim()
        if (-not $s -or $s -eq 'null') { $v = $null }
        else { try { $v = $s | ConvertFrom-Json } catch { return [pscustomobject]@{ ok = $false; apps = @(); errors = @('the stored application list is not valid JSON') } } }
    }
    $raw = @()
    if ($null -ne $v) {
        $inner = Get-PimManagerApiAppProp -Object $v -Name 'apps'
        if ($null -ne $inner) { $raw = @($inner) }
        elseif ($v -is [System.Collections.IDictionary]) { if ($v.Contains('appId')) { $raw = @($v) } }
        elseif ($v -is [System.Collections.IEnumerable]) { $raw = @($v) }
        elseif ($v.PSObject.Properties['appId']) { $raw = @($v) }
    }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $raw) {
        if ($null -eq $e) { continue }
        $id = "$(Get-PimManagerApiAppProp -Object $e -Name 'appId')".Trim().ToLowerInvariant()
        $role = "$(Get-PimManagerApiAppProp -Object $e -Name 'role')".Trim()
        $name = "$(Get-PimManagerApiAppProp -Object $e -Name 'name')".Trim()
        $g = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$g) -or $id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $errors.Add("'$id' is not an application (client) id"); continue }
        $canon = @(Get-PimManagerApiAppRoles | Where-Object { $_ -ieq $role })[0]
        if (-not $canon) { $errors.Add("application $id : the role must be Reader, Admin or Support (an application can never be SuperAdmin)"); continue }
        if ($name.Length -gt 100) { $name = $name.Substring(0, 100) }
        if ($seen.ContainsKey($id)) { $errors.Add("application $id is listed twice"); continue }
        $seen[$id] = $true
        $out.Add([ordered]@{ appId = $id; role = $canon; name = $name })
    }
    $sorted = @($out.ToArray() | Sort-Object { $_.appId })
    $ok = (-not $Strict) -or ($errors.Count -eq 0)
    return [pscustomobject]@{ ok = [bool]$ok; apps = @($sorted); errors = @($errors.ToArray()) }
}

function Get-PimManagerApiAppListHash {
    # PURE. A stable hash of a list (appId|role|name per app, sorted) -- the snapshot a change request is made against.
    param([AllowNull()][AllowEmptyCollection()][object]$Apps)
    $l = (ConvertTo-PimManagerApiAppList -Value @($Apps)).apps
    $text = (@($l | ForEach-Object { "$($_.appId)|$($_.role)|$($_.name)" }) -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
}

function Get-PimManagerApiAppDiff {
    # PURE. added / removed / changed (role or name) between two lists, as plain lines for the request and the audit.
    param([AllowNull()][AllowEmptyCollection()][object]$Current, [AllowNull()][AllowEmptyCollection()][object]$Proposed)
    $cur = @{}; foreach ($a in (ConvertTo-PimManagerApiAppList -Value @($Current)).apps) { $cur[$a.appId] = $a }
    $new = @{}; foreach ($a in (ConvertTo-PimManagerApiAppList -Value @($Proposed)).apps) { $new[$a.appId] = $a }
    $added = @(); $removed = @(); $changed = @()
    foreach ($k in @($new.Keys | Sort-Object)) {
        if (-not $cur.ContainsKey($k)) { $added += ("{0} ({1}){2}" -f $k, $new[$k].role, $(if ($new[$k].name) { " $($new[$k].name)" } else { '' })) }
        elseif ($cur[$k].role -ne $new[$k].role -or $cur[$k].name -ne $new[$k].name) { $changed += ("{0}: {1} -> {2}" -f $k, $cur[$k].role, $new[$k].role) }
    }
    foreach ($k in @($cur.Keys | Sort-Object)) { if (-not $new.ContainsKey($k)) { $removed += ("{0} ({1})" -f $k, $cur[$k].role) } }
    return [pscustomobject]@{ added = @($added); removed = @($removed); changed = @($changed); any = [bool]($added.Count -or $removed.Count -or $changed.Count) }
}

# ---- the change request (maker / checker) -----------------------------------------------------------------------------
function ConvertTo-PimManagerApiAppChangeRecord {
    # PURE. A stored request in any parsed shape -> one canonical ordered hashtable ($null in -> $null out).
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $s = "$Value".Trim(); if (-not $s -or $s -eq 'null') { return $null }
        try { $Value = $s | ConvertFrom-Json } catch { throw "the stored application change request is not valid JSON: $($_.Exception.Message)" }
        if ($null -eq $Value) { return $null }
    }
    $g = { param($n) Get-PimManagerApiAppProp -Object $Value -Name $n }
    $lst = { param($v) $o = @(); foreach ($x in @($v)) { if ($null -ne $x -and "$x".Trim()) { $o += "$x".Trim() } }; return ,$o }
    $r = [ordered]@{}
    $r.id = "$(& $g 'id')"; $r.status = "$(& $g 'status')".Trim().ToLowerInvariant()
    $r.proposed = @((ConvertTo-PimManagerApiAppList -Value @(& $g 'proposed')).apps)
    $r.snapshot = @((ConvertTo-PimManagerApiAppList -Value @(& $g 'snapshot')).apps)
    $r.snapshotHash = "$(& $g 'snapshotHash')".Trim().ToLowerInvariant()
    $r.added = & $lst (& $g 'added'); $r.removed = & $lst (& $g 'removed'); $r.changed = & $lst (& $g 'changed')
    $r.justification = "$(& $g 'justification')"; $r.maker = "$(& $g 'maker')"
    $r.createdUtc = ConvertTo-PimManagerApiAppUtcText (& $g 'createdUtc'); $r.expiresUtc = ConvertTo-PimManagerApiAppUtcText (& $g 'expiresUtc')
    $r.checker = "$(& $g 'checker')"; $r.decidedUtc = ConvertTo-PimManagerApiAppUtcText (& $g 'decidedUtc')
    $r.closedBy = "$(& $g 'closedBy')"; $r.closedUtc = ConvertTo-PimManagerApiAppUtcText (& $g 'closedUtc'); $r.closeNote = "$(& $g 'closeNote')"
    $r.selfApproved = [bool](& $g 'selfApproved')
    return $r
}

function ConvertTo-PimManagerApiAppChangeJson {
    param([AllowNull()][object]$Request)
    if ($null -eq $Request) { return $null }
    return (ConvertTo-Json -InputObject (ConvertTo-PimManagerApiAppChangeRecord -Value $Request) -Depth 6 -Compress)
}

function Test-PimManagerApiAppChangeOpen {
    # PURE. Pending AND inside its window. An unreadable expiry is expired (it can never be approved).
    param([AllowNull()][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Request) { return $false }
    $r = ConvertTo-PimManagerApiAppChangeRecord -Value $Request
    if ($r.status -ne 'pending') { return $false }
    $t = "$($r.expiresUtc)"; if (-not $t) { return $false }
    $exp = [datetime]::Parse($t, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    return ($NowUtc.ToUniversalTime() -lt $exp)
}

function Resolve-PimManagerApiAppChangeCreate {
    <#
      PURE maker decision -> @{ ok; code; reason; request; expiredPrevious }.
        code: created | invalid | no-justification | no-maker | no-change | open-request
    #>
    param([AllowNull()][object]$Existing, [AllowNull()][AllowEmptyCollection()][object]$Current, [AllowNull()][AllowEmptyCollection()][object]$Proposed,
          [string]$Maker, [string]$Justification, [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlHours = 72)
    $out = { param($ok, $code, $reason, $req, $prev) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req; expiredPrevious = $prev } }
    if (-not "$Maker".Trim()) { return (& $out $false 'no-maker' 'the request must name who raised it' $null $null) }
    if (-not "$Justification".Trim()) { return (& $out $false 'no-justification' 'a justification is required -- this list decides which applications may use the PIM Manager API' $null $null) }
    $p = ConvertTo-PimManagerApiAppList -Value @($Proposed) -Strict
    if (-not $p.ok) { return (& $out $false 'invalid' ($p.errors -join '; ') $null $null) }
    $cur = @((ConvertTo-PimManagerApiAppList -Value @($Current)).apps)
    $prev = $null
    $ex = ConvertTo-PimManagerApiAppChangeRecord -Value $Existing
    if ($ex) {
        if (Test-PimManagerApiAppChangeOpen -Request $ex -NowUtc $NowUtc) {
            return (& $out $false 'open-request' ("a change to the API applications is already waiting (raised by {0}, expires {1}) -- it must be approved, rejected or cancelled first" -f $ex.maker, $ex.expiresUtc) $ex $null)
        }
        if ($ex.status -eq 'pending') {
            $ex.status = 'expired'; $ex.closedUtc = $NowUtc.ToUniversalTime().ToString('o'); $ex.closeNote = 'expired before a second SuperAdmin approved it'
            $prev = $ex
        }
    }
    $d = Get-PimManagerApiAppDiff -Current $cur -Proposed $p.apps
    if (-not $d.any) { return (& $out $false 'no-change' 'the proposed list is the list already saved -- there is nothing to approve' $null $prev) }
    if ($TtlHours -lt 1 -or $TtlHours -gt 168) { $TtlHours = 72 }
    $now = $NowUtc.ToUniversalTime()
    $req = [ordered]@{
        id = [guid]::NewGuid().ToString(); status = 'pending'
        proposed = @($p.apps); snapshot = @($cur); snapshotHash = (Get-PimManagerApiAppListHash -Apps $cur)
        added = @($d.added); removed = @($d.removed); changed = @($d.changed)
        justification = "$Justification".Trim(); maker = "$Maker".Trim()
        createdUtc = $now.ToString('o'); expiresUtc = $now.AddHours($TtlHours).ToString('o')
        checker = ''; decidedUtc = ''; closedBy = ''; closedUtc = ''; closeNote = ''; selfApproved = $false
    }
    return (& $out $true 'created' ("request raised -- a second SuperAdmin must approve it before it applies (expires {0})" -f $req.expiresUtc) (ConvertTo-PimManagerApiAppChangeRecord -Value $req) $prev)
}

function Resolve-PimManagerApiAppChangeDecision {
    <#
      PURE checker decision. -Decision approve | reject | cancel -> @{ ok; code; reason; request }.
        approve: a SuperAdmin who is NOT the maker (the maker only with -AllowSelfApprove = ApprovalSelfApprove ON); the saved
                 list must still hash to the request's snapshot, else the request closes as 'stale'.
        reject : a SuperAdmin who is not the maker.   cancel: the maker only.
      Role checks are the caller's; this decides identity and state.
    #>
    param([AllowNull()][object]$Request, [string]$RequestId, [Parameter(Mandatory)][string]$Actor,
          [Parameter(Mandatory)][ValidateSet('approve', 'reject', 'cancel')][string]$Decision,
          [string]$CurrentHash = '', [string]$Note = '', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$AllowSelfApprove)
    $o = { param($ok, $code, $reason, $req) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req } }
    $r = ConvertTo-PimManagerApiAppChangeRecord -Value $Request
    if ($null -eq $r) { return (& $o $false 'not-found' 'there is no change request for the API applications' $null) }
    if ("$RequestId".Trim() -and "$RequestId".Trim() -ne $r.id) { return (& $o $false 'wrong-request' 'that is not the current change request -- reload' $r) }
    if ($r.status -ne 'pending') { return (& $o $false 'not-pending' ("the request is already {0}" -f $r.status) $r) }
    $now = $NowUtc.ToUniversalTime()
    if (-not (Test-PimManagerApiAppChangeOpen -Request $r -NowUtc $now)) {
        $r.status = 'expired'; $r.closedUtc = $now.ToString('o'); $r.closeNote = 'expired before a second SuperAdmin approved it'
        return (& $o $false 'expired' 'the request expired -- raise a new one' $r)
    }
    $isMaker = ("$Actor".Trim().ToLowerInvariant() -eq "$($r.maker)".Trim().ToLowerInvariant())
    $n = [ordered]@{}; foreach ($k in $r.Keys) { $n[$k] = $r[$k] }
    if ($Decision -eq 'cancel') {
        if (-not $isMaker) { return (& $o $false 'not-maker' 'only the SuperAdmin who raised the request can cancel it -- reject it instead' $r) }
        $n.status = 'cancelled'; $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o'); $n.closeNote = "$Note"
        return (& $o $true 'cancelled' 'request cancelled -- nothing was changed' $n)
    }
    $self = [bool]($isMaker -and $Decision -eq 'approve' -and $AllowSelfApprove)
    if ($isMaker -and -not $self) {
        return (& $o $false 'same-person' $(if ($Decision -eq 'approve') { 'you raised this request, so another SuperAdmin must approve it' } else { 'you raised this request -- cancel it instead' }) $r)
    }
    if ($Decision -eq 'reject') {
        $n.status = 'rejected'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o'); $n.closeNote = "$Note"
        return (& $o $true 'rejected' 'request rejected -- nothing was changed' $n)
    }
    if ("$CurrentHash".Trim().ToLowerInvariant() -ne $r.snapshotHash) {
        $n.status = 'stale'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o'); $n.closeNote = 'the list changed since the request was made'
        return (& $o $false 'stale' 'the list changed since the request was made -- raise a new request' $n)
    }
    $n.status = 'approved'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closeNote = "$Note"; $n.selfApproved = $self
    return (& $o $true 'approved' 'approved -- applying' $n)
}

# ---- the token ---------------------------------------------------------------------------------------------------------
function Resolve-PimManagerAppBearer {
    <#
      PURE given its inputs. Is 'Authorization: Bearer <JWT>' a genuine APPLICATION token for this Manager?
        Microsoft.IdentityModel: signature against -Jwks (RS256 only) -> exp / nbf / issuer (-ExpectedIssuers = this tenant) / audience
        (-ExpectedAudiences, pinned) -> application-only: no 'scp', no upn / preferred_username / unique_name, idtyp (when
        present) = 'app' -> it carries -RequiredRole in 'roles' -> it names its application (appid / azp, a GUID).
      -> @{ ok; status (401 = no / bad token, 403 = genuine but not an application token for this API, 503 = not set up);
            appId; reason }. The reason is for the log and the audit -- never sent to the caller.
    #>
    param([string]$Authorization = '', [AllowNull()][object]$Jwks, [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(),
          [string]$RequiredRole = '', [datetime]$NowUtc = ([datetime]::UtcNow),
          # framework 12.31 rule 4 (2026-11-16): the install tenant, pinned on the token's tid as well as through the issuer
          [string]$ExpectedTenantId = '',
          # framework 12.31 rule 2 (owner 2026-11-16 "Strict everywhere at once"): idtyp = app is REQUIRED from 3.1.31,
          # unconditionally. The switch is kept only so older callers bind; it changes nothing.
          [switch]$RequireIdtyp)
    $no = { param($s, $r, $a = '') @{ ok = $false; status = $s; appId = $a; reason = $r } }
    if (-not "$RequiredRole".Trim()) { $RequiredRole = Get-PimManagerApiAppRoleValue }
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $iss.Count -or -not $aud.Count) { return (& $no 503 'application sign-in is not set up on this Manager (no pinned tenant / audience)') }
    if ("$Authorization" -notmatch '^\s*Bearer\s+(\S+)\s*$') { return (& $no 401 'no bearer token') }
    if (-not (Get-Command Invoke-PimTokenValidation -ErrorAction SilentlyContinue)) { return (& $no 503 'the token library is not loaded (refused)') }
    $tok = $Matches[1]
    if ($null -eq (Get-PimJwtParts -Token $tok)) { return (& $no 401 'not a well-formed JWT') }
    if ($null -eq $Jwks) { return (& $no 503 'the tenant signing keys could not be fetched (refused)') }
    # AUTH-MODERN-1: signature (RS256), issuer, audience and lifetime by Microsoft.IdentityModel (Invoke-PimTokenValidation)
    $vv = Invoke-PimTokenValidation -Token $tok -Jwks $Jwks -ExpectedIssuers $iss -ExpectedAudiences $aud
    if (-not $vv.valid) { return (& $no 401 "token: $($vv.reason)") }
    $jwt = [pscustomobject]@{ payload = $vv.payload }
    $p = $jwt.payload
    $app = "$(if ("$($p.appid)".Trim()) { $p.appid } else { $p.azp })".Trim().ToLowerInvariant()
    if ($app -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return (& $no 401 'the token names no application') }
    if ("$($p.scp)".Trim()) { return (& $no 403 'a delegated (person) token is not an application token' $app) }
    foreach ($c in @('upn', 'preferred_username', 'unique_name')) { if ("$($p.$c)".Trim()) { return (& $no 403 'the token carries user claims' $app) } }
    if ("$($p.idtyp)".Trim() -and "$($p.idtyp)".Trim() -ne 'app') { return (& $no 403 "the token type is '$($p.idtyp)', not app" $app) }
    if ("$($p.idtyp)".Trim() -ne 'app') { return (& $no 403 'the token does not say it is an application token (idtyp) -- run Set-PimManagerApiAuth.ps1 -Apply once' $app) }
    if ("$ExpectedTenantId".Trim() -and "$($p.tid)".Trim().ToLowerInvariant() -ne "$ExpectedTenantId".Trim().ToLowerInvariant()) { return (& $no 401 'the token is from another tenant' $app) }
    $roles = @(@($p.roles) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($roles -notcontains $RequiredRole) { return (& $no 403 'the token does not carry the PIM Manager API application role' $app) }
    return @{ ok = $true; status = 200; appId = $app; reason = 'application token verified' }
}

# ---- what an application may call (ALLOW-LIST, deny by default) --------------------------------------------------------
# SETTINGS-API-1 (framework 12.31, owner 2026-11-16 "it should be possible to manage settings using code, not only gui";
# wizard "All but security controls"): THREE TIERS, one fixed literal map (Get-PimManagerAppTierMap), code -- never a
# setting, and no route changes it:
#   tier 1  settings + routine operations: an Admin application changes them and commits, through the SAME handler and
#           guards as a person (a mass / weakening change is still held for a SuperAdmin; an application never approves).
#   tier 2  grants (accounts, role / group / workload assignments, the groups that carry roles): an Admin application
#           PROPOSES (POST /api/approvals/app-submit/<entity>, PEOPLE-API-APPROVAL-1) and a PERSON approves and executes.
#           The Support role (SUPPORT-DIRECT-GRANT-1) commits tier 2 directly, on a ticket, with mail + rate limit.
#   tier 3  security controls: person only (who signs in, approves or acts; break-glass; licence / edition; API
#           application enrolment; second-person rules; anything that shrinks or switches off the audit trail; the
#           tier map and the lists themselves).
# A route or entity NOT in the map is never "allowed by default": tier 2 when it touches people or access, else tier 3.
# The map covers the WRITE routes (PUT / POST / DELETE / PATCH). Reads are the explicit read allow-list below.

function Get-PimManagerAppTierMap {
    <#
      PURE. THE LITERAL TIER MAP (framework 12.31). First match wins, so a specific entry precedes a broader one. Each entry:
      method, pattern (anchored regex over the page route), tier (1 | 2 | 3 | 'entity' = the tier of the entity in the path),
      kind, appRole (the application role that may call it: 'Admin' | 'Support' | '' = no application), reason.
    #>
    $e = { param($m, $p, $t, $k, $ar, $why) [pscustomobject]@{ method = $m; pattern = $p; tier = $t; kind = $k; appRole = $ar; reason = $why } }
    $stage = ((@(Get-PimManagerAppStageEntities) | ForEach-Object { [regex]::Escape($_) }) -join '|')
    $submit = ((@(Get-PimManagerAppSubmitEntities) | ForEach-Object { [regex]::Escape($_) }) -join '|')
    return @(
        # ===== TIER 1: settings an Admin application may change (the handler's own SuperAdmin gate is met by an Admin app on THESE routes only) =====
        (& $e 'PUT'    '^/api/settings/(?:naming|filters)$'        1 'setting'   'Admin' 'naming conventions and filters (the admin account domain inside naming stays person-only, refused by the handler)')
        (& $e 'PUT'    '^/api/settings/environment-name$'          1 'setting'   'Admin' 'the display name of this environment')
        (& $e 'PUT'    '^/api/settings/hide-names$'                1 'setting'   'Admin' 'how names are shown in the page')
        (& $e 'PUT'    '^/api/settings/portal-branding$'           1 'setting'   'Admin' 'company name and support address shown in the portal')
        (& $e 'PUT'    '^/api/settings/pending-reminders$'         1 'setting'   'Admin' 'reminders about uncommitted changes')
        (& $e 'PUT'    '^/api/settings/activator-targets$'         1 'setting'   'Admin' 'the tenants the activator lists')
        (& $e 'PUT'    '^/api/settings/mail$'                      1 'setting'   'Admin' 'the mail sender')
        (& $e 'PUT'    '^/api/settings/mail/mailbox$'              1 'setting'   'Admin' 'the shared mailbox setup')
        (& $e 'POST'   '^/api/settings/mail/mailbox/use$'          1 'setting'   'Admin' 'use the prepared shared mailbox')
        (& $e 'POST'   '^/api/settings/mail/test$'                 1 'setting'   'Admin' 'send a test mail')
        (& $e 'PUT'    '^/api/settings/email-controls$'            1 'setting'   'Admin' 'which product mails are sent')
        (& $e 'PUT'    '^/api/reports/management/settings$'        1 'setting'   'Admin' 'the management report')
        (& $e 'PUT'    '^/api/mail-notifications$'                 1 'setting'   'Admin' 'per-person mail notification choices')
        (& $e 'PUT'    '^/api/mail-template$'                      1 'setting'   'Admin' 'a mail template text')
        (& $e 'DELETE' '^/api/mail-template$'                      1 'setting'   'Admin' 'reset a mail template to the default')
        (& $e 'PUT'    '^/api/job-schedule$'                       1 'setting'   'Admin' 'when the engine jobs run')
        (& $e 'PUT'    '^/api/drift/settings$'                     1 'setting'   'Admin' 'how often drift is mailed')
        (& $e 'POST'   '^/api/settings/import$'                    1 'setting'   'Admin' 'settings import (refuses every person-only setting, 403 with the list)')
        (& $e 'POST'   '^/api/jobs/run$'                           1 'operation' 'Admin' 'run one engine job now')
        # owner 2026-11-16 ("goal is to adjust and baseline customers", "so i can script 10+ things"): RECLASSIFIED to tier 1 WITH a
        # DIRECTION RULE per setting key (Get-PimManagerAppSettingDirectionMap): enabling / adding / tightening applies; a WEAKENING
        # (a protection off, MFA / approval / justification lower, retention shorter, auditing off) is HELD for a SuperAdmin (409).
        (& $e 'PUT'    '^/api/settings/feature-flags$'             1 'setting'   'Admin' 'feature flags (switching one off = held)')
        (& $e 'PUT'    '^/api/settings/(?:feature-settings|auto-offboarding|reconcile-removal)$' 1 'setting' 'Admin' 'feature settings and the offboarding / removal protection switches (a protection off = held)')
        (& $e 'PUT'    '^/api/settings/ai-chat$'                   1 'setting'   'Admin' 'the AI chat (its endpoint / keys = held)')
        (& $e 'PUT'    '^/api/settings/autoextend$'                1 'setting'   'Admin' 'auto-extend (switching it on keeps access without a person = held)')
        (& $e 'PUT'    '^/api/settings/group-retirement$'          1 'setting'   'Admin' 'group deletion (switching deletion on = held)')
        (& $e 'PUT'    '^/api/settings/operational-policy$'        1 'setting'   'Admin' 'MFA on activation (off = held) and the longest activation / eligibility (longer = held)')
        (& $e 'PUT'    '^/api/settings/policy-template-defaults$'  1 'setting'   'Admin' 'role activation policy defaults (a requirement off or a longer duration = held)')
        (& $e 'PUT'    '^/api/policy-templates/rules$'             1 'setting'   'Admin' 'role activation policy rules (a requirement off or a longer duration = held)')
        (& $e 'PUT'    '^/api/template-state$'                     1 'setting'   'Admin' 'permission packs (enabling a pack applies, disabling = held)')
        (& $e 'PUT'    '^/api/settings/governance-preview$'        1 'setting'   'Admin' 'the approval surfaces (off = held)')
        (& $e 'PUT'    '^/api/alerting$'                           1 'setting'   'Admin' 'security alerting (a recipient removed / an event off / the webhook changed = held)')
        (& $e 'POST'   '^/api/alerting/test$'                      1 'setting'   'Admin' 'send a test alert')
        (& $e 'PUT'    '^/api/settings/audit-retention$'           1 'setting'   'Admin' 'audit retention (raise = applies, lower = held)')
        (& $e 'PUT'    '^/api/settings/config-backup-retention$'   1 'setting'   'Admin' 'configuration backup retention (raise = applies, lower = held)')
        # ===== entity writes: the tier of the ENTITY decides (Get-PimManagerAppEntityTier) =====
        (& $e 'PUT'    ('^/api/(?:csv|data)/(?:' + $stage + ')$')  1 'commit'    'Admin' 'commit a tier-1 entity through the same commit path and guards as a person')
        (& $e 'PUT'    ('^/api/pending/(?:' + $stage + ')$')       1 'stage'     'Admin' 'stage a tier-1 entity')
        (& $e 'POST'   ('^/api/approvals/app-submit/(?:' + $submit + ')$') 2 'submit' 'Admin' 'PEOPLE-API-APPROVAL-1: propose a tier-2 change; a person approves and executes it')
        (& $e 'POST'   '^/api/support/fix$'                        2 'support-fix'    'Support' 'SUPPORT-FIX-API-1 (12.30): only a fix the failure catalog offers for that failure, on a SUP ticket')
        (& $e 'POST'   '^/api/support/change$'                     2 'support-change' 'Support' 'SUPPORT-DIRECT-GRANT-1: a tier-1/2 change on a SUP ticket, mailed to the admins, rate limited')
        (& $e 'PUT'    '^/api/(?:csv|data)/[\w\.-]+$'              'entity' 'commit' '' 'a commit of any other entity: its tier decides (tier 2 = propose through app-submit, tier 3 = person only)')
        (& $e 'PUT'    '^/api/pending/[\w\.-]+$'                   'entity' 'stage'  '' 'staging any other entity: its tier decides')
        (& $e 'POST'   '^/api/diff/[\w\.-]+$'                      'entity' 'page'   '' 'the page preview of a commit')
        # ===== TIER 3: person only (security controls) -- the reasons are the owner's 2026-11-16 list + the 12.31 refinements =====
        (& $e 'PUT'    '^/api/settings/api-applications$'          3 'security' '' 'API-application enrolment: which applications may use the API (the listed-applications store)')
        (& $e 'ANY'    '^/api/settings/api-applications/request(?:/[\w\.-]+)?$' 3 'security' '' 'API-application enrolment requests and decisions (a second SuperAdmin)')
        (& $e 'PUT'    '^/api/settings/breakglass-accounts$'       3 'security' '' 'break-glass accounts')
        (& $e 'ANY'    '^/api/settings/breakglass-accounts/request(?:/[\w\.-]+)?$' 3 'security' '' 'break-glass change requests and decisions')
        (& $e 'PUT'    '^/api/license$'                            3 'security' '' 'licence')
        (& $e 'PUT'    '^/api/settings/edition$'                   3 'security' '' 'edition')
        (& $e 'PUT'    '^/api/settings/approvers$'                 3 'security' '' 'approvers (who approves)')
        (& $e 'POST'   '^/api/settings/approvers/import$'          3 'security' '' 'approvers import (who approves)')
        (& $e 'PUT'    '^/api/settings/approval-self-approve$'     3 'security' '' 'second-person rule: may a maker approve their own request')
        (& $e 'PUT'    '^/api/settings/pending-second-approver$'   3 'security' '' 'second-person rule: a second administrator commits staged changes')
        (& $e 'PUT'    '^/api/settings/guard-release-second-person$' 3 'security' '' 'second-person rule: releasing a guard')
        (& $e 'PUT'    '^/api/settings/invardia-connect$'          3 'security' '' 'the support connection (who from outside may act)')
        (& $e 'POST'   '^/api/settings/mail/relay-password$'       3 'security' '' 'a secret value: a SuperAdmin hands the relay password over sealed, never an application')
        (& $e 'PUT'    '^/api/settings/admin-domain$'              3 'security' '' 'the domain admin accounts sign in with')
        (& $e 'PUT'    '^/api/settings/department-owners-reader$'  3 'security' '' 'gives department owners sign-in to the Manager')
        (& $e 'PUT'    '^/api/settings/departments$'               3 'security' '' 'department owners approve and act as delegated administrators')
        (& $e 'POST'   '^/api/settings/departments/import$'        3 'security' '' 'department owners import (who approves and acts)')
        (& $e 'PUT'    '^/api/settings/demo-mode$'                 3 'security' '' 'demo mode lets a guest group sign in')
        (& $e 'PUT'    '^/api/settings/hybrid-ad$'                 3 'security' '' 'the hybrid worker that creates on-premises accounts (Tier 0)')
        (& $e 'PUT'    '^/api/rfa/settings$'                       3 'security' '' 'request-for-access settings name the applications that may call it')
        (& $e 'PUT'    '^/api/settings/scenario$'                  3 'security' '' 'the deployment scenario decides which tenant governs this one')
        (& $e 'PUT'    '^/api/settings/feature-gates$'             3 'security' '' 'feature gates hold the second-approver (maker / checker) switch')
        (& $e 'PUT'    '^/api/settings/support-fix-mode$'          3 'security' '' 'who may act without approval (SupportFixMode: auto / approve)')
        (& $e 'ANY'    '^/api/app-proposals(?:/(?:decide|execute))?$' 3 'security' '' 'a PERSON lists, approves and runs the proposals of applications; an application never does')
        (& $e 'POST'   '^/api/policy-templates/rename$'            3 'page' '' 'renaming a policy template is a page action')
        (& $e 'PUT'    '^/api/settings/[\w\.-]+$'                  3 'security' '' 'a settings section written by the page''s generic form (naming / filters / departments are mapped above)')
        (& $e 'POST'   '^/api/job-schedule/run-now$'               3 'security' '' 'a page action (the Run now of the scheduler); an application uses POST /api/jobs/run')
        (& $e 'POST'   '^/api/(?:approvals|approvals/decide|approvals/execute)$' 3 'security' '' 'approval decisions: a PERSON approves; an application can never approve or execute')
        (& $e 'POST'   '^/api/(?:emergency|emergency-restore|revoke|admin-sessions/revoke|backups/restore|config-backups(?:/[\w\.-]+)?)$' 3 'security' '' 'emergency, revoke, restore and backups')
        (& $e 'ANY'    '^/api/guards(?:/.*)?$'                     3 'security' '' 'guards and their release')
        (& $e 'ANY'    '^/api/drift/(?:remediate|group-delete|ignore)$' 3 'security' '' 'drift remediation and ignores')
        (& $e 'ANY'    '^/api/(?:msp|downlink|downlink-intents)(?:/.*)?$' 3 'security' '' 'the managing-tenant link')
        (& $e 'ANY'    '^/api/(?:hybrid-ad|custom-workloads|access-packages|discovery-policy|discovery-decisions|discovery-baseline)(?:/.*)?$' 3 'security' '' 'the hybrid worker, custom workload connectors, access packages and discovery -- they create groups, accounts or access')
        (& $e 'ANY'    '^/api/(?:workload-crawl|workload-prereqs)(?:/.*)?$' 3 'page' '' 'workload checks a person starts in the page')
        (& $e 'ANY'    '^/api/(?:admin-accounts|authoring|owner|onboarding|groups|unmanaged-admins|access-map|access-reviews?|access-review-campaigns|access-review-rules|company-review|autoextend|rfa|engine|conformance|coverage|workload-exemptions|warning-overrides|policy-choices|activator|reconcile|scheduler|jobs|queue|pending-discard|pending-discard-all|support|template-file|wizard|get-started|instance|preflight|refresh-tenant-lists|reports-overview|export|chat|heartbeat)(?:/.*)?$' 3 'page' '' 'the page''s own actions for a signed-in person (an application proposes people / access changes through app-submit)')
    )
}

function Get-PimManagerAppEntityTierMap {
    <#
      PURE. THE LITERAL ENTITY TIERS (framework 12.31). 1 = an Admin application stages and commits; 2 = grants: an Admin
      application proposes, a person approves (the Support role commits on a ticket); 3 = person only.
    #>
    return [ordered]@{
        'PIM-Definitions-AU'               = 1   # a scope (name, description, tag, visibility) -- no grant
        'Account-Definitions-Admins'       = 2   # creates / changes / disables admin ACCOUNTS
        'PIM-Definitions-Roles'            = 2   # the groups that carry roles, and their owners
        'PIM-Definitions-Tasks'            = 2
        'PIM-Definitions-Services'         = 2
        'PIM-Definitions-Processes'        = 2
        'PIM-Definitions-Resources'        = 2
        'PIM-Definitions-Organization'     = 2
        'PIM-Definitions-Projects'         = 2
        'PIM-Definitions-CrossOrg'         = 2
        'PIM-Definitions-Departments'      = 2
        'PIM-Assignments-Admins'           = 2   # a role / group membership
        'PIM-Assignments-Groups'           = 2
        'PIM-Assignments-Roles-Groups'     = 2
        'PIM-Assignments-Roles-AUs'        = 2
        'PIM-Assignments-Azure-Resources'  = 2
        'PIM-Assignments-Workloads'        = 2
        'AccessPackage'                    = 2
        'Account-Definitions-Companies'    = 3   # company contacts sign in to the company review portal
    }
}

function Get-PimManagerAppEntityTier {
    # PURE. -> @{ entity; mapped; tier }. Unmapped (fail closed): 2 when the name is about people or access, else 3.
    param([string]$Entity = '')
    $m = Get-PimManagerAppEntityTierMap
    foreach ($k in $m.Keys) { if ("$k" -ceq "$Entity") { return [pscustomobject]@{ entity = $Entity; mapped = $true; tier = [int]$m[$k] } } }
    $t = if ("$Entity" -match '(?i)account|assign|access|role|group|admin|member|owner|definition') { 2 } else { 3 }
    return [pscustomobject]@{ entity = $Entity; mapped = $false; tier = $t }
}

function Get-PimManagerAppStageEntities {
    <#
      PURE. The entities an application may STAGE and COMMIT -- the tier-1 entities of the literal map (deny by default).
      Everything that creates an account, grants a role or changes who can sign in or act is tier 2 or 3 (see the map).
    #>
    $m = Get-PimManagerAppEntityTierMap
    return @($m.Keys | Where-Object { [int]$m[$_] -eq 1 })
}

function Get-PimManagerAppSubmitEntities {
    # PURE. PEOPLE-API-APPROVAL-1: the tier-2 entities an Admin application may PROPOSE (never commit). Companies stay out (tier 3).
    $m = Get-PimManagerAppEntityTierMap
    return @($m.Keys | Where-Object { [int]$m[$_] -eq 2 })
}

function Get-PimManagerAppRouteTier {
    <#
      PURE. One write route -> @{ mapped; tier; kind; appRole; reason; entity; pattern }. 'entity' entries take the tier of the
      entity named in the path. Unmapped (fail closed): tier 2 when the path touches people or access, else tier 3; never
      callable by an application.
    #>
    param([string]$Method = '', [string]$Path = '')
    $m = "$Method".Trim().ToUpperInvariant()
    foreach ($r in @(Get-PimManagerAppTierMap)) {
        if ($r.method -ne 'ANY' -and $r.method -ne $m) { continue }
        if ("$Path" -cnotmatch $r.pattern) { continue }
        $tier = $r.tier; $ent = ''
        if ("$tier" -eq 'entity') {
            $ent = ("$Path" -split '/')[-1]
            $tier = (Get-PimManagerAppEntityTier -Entity $ent).tier
        } elseif ("$Path" -match '^/api/(?:csv|data|pending|approvals/app-submit)/([\w\.-]+)$') { $ent = $Matches[1] }
        return [pscustomobject]@{ mapped = $true; tier = [int]$tier; kind = "$($r.kind)"; appRole = "$($r.appRole)"; reason = "$($r.reason)"; entity = $ent; pattern = "$($r.pattern)" }
    }
    $t = if ("$Path" -match '(?i)account|assign|access|role|group|admin|member|owner|approv|review|onboard|user') { 2 } else { 3 }
    return [pscustomobject]@{ mapped = $false; tier = $t; kind = 'unmapped'; appRole = ''; reason = 'not in the tier map: treated as the strictest applicable tier'; entity = ''; pattern = '' }
}

function Get-PimManagerAppPersonOnlyRoutes {
    <#
      PURE. THE PERSON-ONLY LIST (tier 3 of the literal map), each with its reason. No application route may match one of
      these (tested), and Test-PimManagerAppRouteAllowed refuses them before the allow-list is looked at.
    #>
    return @(Get-PimManagerAppTierMap | Where-Object { "$($_.tier)" -eq '3' } | ForEach-Object { [pscustomobject]@{ method = $_.method; pattern = $_.pattern; reason = $_.reason } })
}

function Get-PimManagerAppPersonOnlySettings {
    <#
      PURE. The stored settings (pim.Settings names) an application may never change -- the import refuses them (403 with
      the list) and the export marks them read-only. Same reasons as the person-only routes.
    #>
    return [ordered]@{
        ManagerAccess = 'who signs in to the Manager and with which role'; ManagerApiApps = 'API-application enrolment'; ManagerApiAppsChange = 'API-application enrolment'
        BreakGlassAccounts = 'break-glass accounts'; Edition = 'edition'; License = 'licence'; Approvers = 'who approves'
        ApprovalSelfApprove = 'second-person rule'; PendingSecondApprover = 'second-person rule'; GuardReleaseSecondPerson = 'second-person rule'
        DepartmentOwnersGetReader = 'department owners sign in'; Departments = 'department owners approve and act'; DemoMode = 'a guest group signs in'
        FeatureGates = 'holds the second-approver switch'; DiscoveryAutoCreate = 'creates group definitions without a person'
        Scenario ='which tenant governs this one'; RfaSettings = 'the applications that may request access'; HybridAd = 'the hybrid worker (Tier 0)'; InvardiaConnect = 'the support connection'; SupportFixMode = 'who may act without approval'
    }
}

function Get-PimManagerAppSettingDirectionMap {
    <#
      PURE. LITERAL. owner 2026-11-16 ("goal is to adjust and baseline customers"; "so i can script 10+ things"): the DIRECTION
      RULE of every tier-1 setting an application may change. One entry per route: the stored setting (for the current value;
      '' = each key is its own setting), a rule per value type, and rules per key name / key-name pattern. A rule says which
      direction is a WEAKENING (held for a SuperAdmin, 409); anything a rule does not cover is 'held' (unknown = held):
        free      any change applies                       on-ok     on applies, off / false = held (a protection off)
        off-ok    off applies, on = held                   raise-ok  a higher number applies, lower = held (retention)
        lower-ok  a lower number / shorter duration applies, higher = held
        grow-ok   a list may grow; an item removed = held  held      every change is held
        @{ rank = @('weakest', ..., 'strongest') }        moving toward the strongest applies, back = held
    #>
    $r = { param($route, $setting, $bool, $number, $string, $array, $keys = @{}, $patterns = @())
        [pscustomobject]@{ route = $route; setting = $setting; bool = $bool; number = $number; string = $string; array = $array; keys = $keys; patterns = @($patterns) } }
    $policyPatterns = @(@{ re = '(?i)allow|permanent|skip|bypass|exempt|disable'; rule = 'off-ok' }, @{ re = '(?i)duration|hours|days|maximum|^max'; rule = 'lower-ok' })
    return @(
        (& $r '^/api/settings/naming$'                  'NamingConventions'        'free'  'free'     'free' 'free')
        (& $r '^/api/settings/filters$'                 'Filters'                  'free'  'free'     'free' 'free')
        (& $r '^/api/settings/environment-name$'          'EnvironmentName'          'free'  'free'     'free' 'free')
        (& $r '^/api/settings/hide-names$'                'HideNames'                'free'  'free'     'free' 'free')
        (& $r '^/api/settings/portal-branding$'           ''                         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/pending-reminders$'         'PendingReminders'         'on-ok' 'free'     'free' 'free')
        (& $r '^/api/settings/activator-targets$'         'ActivatorTargets'         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/mail$'                      ''                         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/mail/mailbox$'              'MailboxSetup'             'free'  'free'     'free' 'free')
        (& $r '^/api/settings/mail/mailbox/use$'          ''                         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/mail/test$'                 ''                         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/email-controls$'            'EmailControls'            'on-ok' 'free'     'free' 'grow-ok')
        (& $r '^/api/reports/management/settings$'        'ManagementReport'         'on-ok' 'free'     'free' 'grow-ok')
        (& $r '^/api/mail-notifications$'                 'MailNotifications'        'on-ok' 'free'     'free' 'grow-ok')
        (& $r '^/api/mail-template$'                      'MailTemplates'            'free'  'free'     'free' 'free')
        (& $r '^/api/job-schedule$'                       'JobSchedule'              'on-ok' 'free'     'free' 'free')
        (& $r '^/api/drift/settings$'                     'DriftAlertCadence'        'on-ok' 'free'     'free' 'grow-ok')
        (& $r '^/api/settings/feature-flags$'             'FeatureFlags'             'on-ok' 'held'     'held' 'grow-ok')
        (& $r '^/api/settings/(?:feature-settings|auto-offboarding|reconcile-removal)$' '' 'on-ok' 'held' 'held' 'grow-ok' `
            @{ ApprovalRequestTtlHours = 'lower-ok'; BreakGlassChangeTtlHours = 'lower-ok'; OwnerExtendMaxDays = 'lower-ok'; StaleGroupDays = 'lower-ok'; TapCreateLeadHours = 'free'
               DiscoveryNotifyRecipients = 'free'; mode = @{ rank = @('off', 'report', 'enforce') }; ReconcileRemovalMode = @{ rank = @('off', 'report', 'enforce') } })
        (& $r '^/api/settings/ai-chat$'                   ''                         'on-ok' 'held'     'held' 'held')
        (& $r '^/api/settings/autoextend$'                'AutoExtendPolicy'         'off-ok' 'lower-ok' 'held' 'held')
        (& $r '^/api/settings/group-retirement$'          ''                         'off-ok' 'held'    'held' 'held')
        (& $r '^/api/settings/operational-policy$'        'OperationalPolicy'        'on-ok' 'lower-ok' 'held' 'grow-ok' `
            @{ maxActivationDuration = 'lower-ok'; maxEligibilityDuration = 'lower-ok'; mfaOnActivation = 'on-ok' } $policyPatterns)
        (& $r '^/api/settings/policy-template-defaults$'  'PolicyTemplateDefaults'   'on-ok' 'lower-ok' 'held' 'grow-ok' @{} $policyPatterns)
        (& $r '^/api/policy-templates/rules$'             'PolicyTemplates'          'on-ok' 'lower-ok' 'held' 'grow-ok' @{} $policyPatterns)
        # the route's body is { id; disabled }: enabling a permission pack (disabled = false) applies, disabling one is held
        (& $r '^/api/template-state$'                     ''                         'held'  'held'     'held' 'held' @{ id = 'free'; disabled = 'off-ok' })
        # the import writes the stored TemplateState map { <pack id> = true (disabled) }: a pack newly disabled is held
        (& $r '^$never-a-route^'                          'TemplateState'            'off-ok' 'held'    'held' 'held')
        (& $r '^/api/settings/governance-preview$'        'GovernancePreview'        'on-ok' 'held'     'held' 'held')
        (& $r '^/api/alerting$'                           'Alerting'                 'on-ok' 'held'     'held' 'grow-ok' @{ webhookUrl = 'held' })
        (& $r '^/api/alerting/test$'                      ''                         'free'  'free'     'free' 'free')
        (& $r '^/api/settings/audit-retention$'           'AuditRetentionMonths'     'held'  'raise-ok' 'held' 'held')
        (& $r '^/api/settings/config-backup-retention$'   'ConfigBackupRetentionDays' 'held' 'raise-ok' 'held' 'held')
    )
}

function Get-PimManagerAppDirectionLeaves {
    # PURE. A value as @( @{ path; name; value } ) leaves (objects walked; a list is ONE leaf).
    param([AllowNull()][object]$Value, [string]$Path = '', [int]$Depth = 0)
    if ($Depth -gt 20) { return @() }
    $name = if ($Path) { ($Path -split '\.')[-1] } else { '' }
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return @([pscustomobject]@{ path = $Path; name = $name; value = $Value }) }
    if ($Value -is [System.Collections.IDictionary]) { return @(foreach ($k in @($Value.Keys)) { Get-PimManagerAppDirectionLeaves -Value $Value[$k] -Path $(if ($Path) { "$Path.$k" } else { "$k" }) -Depth ($Depth + 1) }) }
    if ($Value -is [System.Collections.IEnumerable]) { return @([pscustomobject]@{ path = $Path; name = $name; value = @($Value) }) }
    return @(foreach ($p in @($Value.PSObject.Properties)) { Get-PimManagerAppDirectionLeaves -Value $p.Value -Path $(if ($Path) { "$Path.$($p.Name)" } else { "$($p.Name)" }) -Depth ($Depth + 1) })
}

function Get-PimManagerAppDirectionAt {
    # PURE. The value at a dotted path of an object ($null when absent). A scalar current answers for every path.
    param([AllowNull()][object]$Value, [string]$Path)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    $cur = $Value
    foreach ($seg in @("$Path" -split '\.' | Where-Object { $_ })) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $hit = $null; foreach ($k in @($cur.Keys)) { if ("$k" -ieq $seg) { $hit = $cur[$k] } }; $cur = $hit }
        elseif ($cur.PSObject.Properties[$seg]) { $cur = $cur.PSObject.Properties[$seg].Value } else { return $null }
    }
    return $cur
}

function ConvertTo-PimManagerAppDirectionNumber {
    # PURE. A number, or an ISO 8601 duration (PT8H, P30D) as minutes; $null when neither.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if ($Value -is [ValueType]) { return [double]$Value }
    $s = "$Value".Trim(); $d = 0.0
    if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    if ($s -match '^-?P') { try { return [System.Xml.XmlConvert]::ToTimeSpan($s).TotalMinutes } catch { return $null } }
    return $null
}

function Test-PimManagerAppSettingDirection {
    <#
      PURE. Is an application's change to a tier-1 setting a WEAKENING? -Route (the page route), -Body (the request body, or the
      import's new value), -Current (the stored value; a scalar setting compares every number leaf), -Entry (optional: the map
      entry; else found by route). Only CHANGED leaves are judged. -> @{ known; held; reasons = @(path: why) }.
      No entry = held (unknown). A leaf no rule covers = held.
    #>
    param([string]$Route = '', [AllowNull()][object]$Body, [AllowNull()][object]$Current, [AllowNull()][object]$Entry)
    $e = $Entry
    if ($null -eq $e) { $e = @(Get-PimManagerAppSettingDirectionMap | Where-Object { "$Route" -cmatch $_.route })[0] }
    if ($null -eq $e) { return [pscustomobject]@{ known = $false; held = $true; reasons = @("no direction rule for $Route (unknown = held)") } }
    $b = $Body
    if ($b -and -not ($b -is [string]) -and -not ($b -is [ValueType])) {
        $vp = $null; if ($b -is [System.Collections.IDictionary]) { if ($b.Contains('value')) { $vp = $b['value'] } } elseif ($b.PSObject.Properties['value']) { $vp = $b.PSObject.Properties['value'].Value }
        if ($null -ne $vp) { $b = $vp }
    }
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($lf in @(Get-PimManagerAppDirectionLeaves -Value $b)) {
        $nv = $lf.value
        $cv = Get-PimManagerAppDirectionAt -Value $Current -Path $lf.path
        $nj = ConvertTo-Json -InputObject $nv -Compress -Depth 10; $cj = ConvertTo-Json -InputObject $cv -Compress -Depth 10
        if ($nj -eq $cj) { continue }
        $rule = $null
        foreach ($k in @($e.keys.Keys)) { if ("$k" -ieq "$($lf.name)") { $rule = $e.keys[$k] } }
        if ($null -eq $rule) { foreach ($pt in @($e.patterns)) { if ("$($lf.name)" -match $pt.re) { $rule = $pt.rule; break } } }
        if ($null -eq $rule) {
            $rule = if ($nv -is [bool]) { $e.bool }
                     elseif ($nv -is [System.Collections.IEnumerable] -and -not ($nv -is [string])) { $e.array }
                     elseif (($nv -is [ValueType]) -or ("$nv" -match '^-?P\d|^-?PT\d')) { $e.number }
                     else { $e.string }
        }
        $why = ''
        if ($rule -is [System.Collections.IDictionary] -and $rule.Contains('rank')) {
            $rk = @($rule['rank']); $ni = [array]::IndexOf(@($rk | ForEach-Object { "$_".ToLowerInvariant() }), "$nv".ToLowerInvariant()); $ci = [array]::IndexOf(@($rk | ForEach-Object { "$_".ToLowerInvariant() }), "$cv".ToLowerInvariant())
            if ($ni -lt 0 -or $ci -lt 0 -or $ni -lt $ci) { $why = "'$cv' -> '$nv' is a weaker setting" }
        } else {
            switch ("$rule") {
                'free'     { }
                'on-ok'    { if (-not ($nv -is [bool] -and $nv)) { $why = 'switches a protection or feature off' } }
                'off-ok'   { if (-not ($nv -is [bool] -and -not $nv)) { $why = 'switches on something that removes or keeps access without a person' } }
                'raise-ok' { $n = ConvertTo-PimManagerAppDirectionNumber $nv; $c = ConvertTo-PimManagerAppDirectionNumber $cv; if ($null -eq $n -or $null -eq $c -or $n -lt $c) { $why = 'lowers a retention' } }
                'lower-ok' { $n = ConvertTo-PimManagerAppDirectionNumber $nv; $c = ConvertTo-PimManagerAppDirectionNumber $cv; if ($null -eq $n -or $null -eq $c -or $n -gt $c) { $why = 'makes a limit longer or larger' } }
                'grow-ok'  { $na = @(@($nv) | ForEach-Object { "$_".ToLowerInvariant() }); $gone = @(@($cv) | Where-Object { $null -ne $_ -and "$_".ToLowerInvariant() -notin $na }); if ($gone.Count) { $why = "removes $(@($gone) -join ', ')" } }
                default    { $why = 'a change of this value is held (no rule applies it)' }
            }
        }
        if ($why) { $reasons.Add("$($lf.path): $why") }
    }
    return [pscustomobject]@{ known = $true; held = [bool]$reasons.Count; reasons = @($reasons.ToArray()) }
}

function Get-PimManagerAppSettingDirectionEntryBySetting {
    # PURE. The direction entry of a STORED setting name (the import judges each setting it would write); $null = none (held).
    param([string]$Name)
    return @(Get-PimManagerAppSettingDirectionMap | Where-Object { "$($_.setting)" -and "$($_.setting)" -ieq "$Name" })[0]
}

function Get-PimManagerAppRouteAllowList {
    <#
      PURE. THE ALLOW-LIST. Reads (literal) + every application-callable entry of the tier map (tier 1 for Admin, the
      app-submit proposal, the Support routes). Each entry: method, pattern, minRole ('Reader' | 'Admin' | 'Support'), support
      (a read the Support role may use too), settings (an Admin app meets the handler's SuperAdmin gate on this route only),
      tier, kind. Everything else is refused. A route added to the product is NOT reachable until it is mapped here on purpose.
    #>
    $e = { param($m, $p, $r, $sup = $false) [pscustomobject]@{ method = $m; pattern = $p; minRole = $r; support = [bool]$sup; settings = $false; tier = 0; kind = 'read' } }
    $reads = @(
        (& $e 'GET' '^/api/config$' 'Reader' $true)
        (& $e 'GET' '^/api/(?:csv|data)/[A-Za-z0-9_.-]+$' 'Reader')
        (& $e 'GET' '^/api/pending$' 'Reader')
        (& $e 'GET' '^/api/drift$' 'Reader')
        (& $e 'GET' '^/api/coverage$' 'Reader')
        (& $e 'GET' '^/api/approvals$' 'Reader')
        (& $e 'GET' '^/api/access-reviews$' 'Reader')
        (& $e 'GET' '^/api/access-review-campaigns$' 'Reader')
        (& $e 'GET' '^/api/guards$' 'Reader')
        (& $e 'GET' '^/api/jobs$' 'Reader' $true)
        (& $e 'GET' '^/api/jobs/history$' 'Reader')
        (& $e 'GET' '^/api/jobs/log$' 'Reader')
        (& $e 'GET' '^/api/search$' 'Reader')
        (& $e 'GET' '^/api/autoextend/upcoming$' 'Reader')
        (& $e 'GET' '^/api/tier-impact$' 'Reader')
        (& $e 'GET' '^/api/role-lookup/reverse$' 'Reader')
        (& $e 'GET' '^/api/access-report/who-can$' 'Reader')
        (& $e 'GET' '^/api/access-report/who-has$' 'Reader')
        (& $e 'GET' '^/api/engine-failures$' 'Reader' $true)          # the failures a Support fix names
        (& $e 'GET' '^/api/settings/export$' 'Reader')                 # SETTINGS-API-1: the settings as ONE JSON (no secret values)
        (& $e 'GET' '^/api/job-schedule$' 'Reader')
        (& $e 'GET' '^/api/active-assignments$' 'Admin')
        (& $e 'GET' '^/api/unmanaged-admins$' 'Admin')
    )
    $writes = @(Get-PimManagerAppTierMap | Where-Object { "$($_.appRole)" -in @('Admin', 'Support') } | ForEach-Object {
        [pscustomobject]@{ method = $_.method; pattern = $_.pattern; minRole = "$($_.appRole)"; support = $false; settings = ("$($_.kind)" -eq 'setting'); tier = [int]$_.tier; kind = "$($_.kind)" }
    })
    # the READ of every tier-1 setting an Admin app may change (the one-time baseline client previews it); never a tier-3 one
    $settingReads = @(Get-PimManagerAppTierMap | Where-Object { "$($_.kind)" -eq 'setting' -and $_.method -eq 'PUT' } | ForEach-Object {
        [pscustomobject]@{ method = 'GET'; pattern = $_.pattern; minRole = 'Reader'; support = $false; settings = $false; tier = 0; kind = 'setting-read' }
    })
    return @($reads + $settingReads + $writes)
}

function Test-PimManagerAppRouteAllowed {
    <#
      PURE. -> @{ allowed; minRole; reason; settings; tier; kind }. -Role is the application's listed role (Reader | Admin |
      Support; anything else = no access). Order: a plain path -> a person-only (tier 3) route is refused whatever the role
      -> the allow-list. Reader < Admin; Support is its own lane (its Support-only routes + the reads marked for it).
    #>
    param([string]$Method = '', [string]$Path = '', [string]$Role = '')
    $m = "$Method".Trim().ToUpperInvariant(); $p = "$Path"
    $no = { param($why, $mr = '') [pscustomobject]@{ allowed = $false; minRole = $mr; reason = $why; settings = $false; tier = 0; kind = '' } }
    if ("$Role" -cnotin @('Reader', 'Admin', 'Support')) { return (& $no 'the application holds no role') }
    if ($p -match '[\\%]' -or $p -match '/\.\.?(/|$)' -or $p -match '//') { return (& $no 'not a plain route') }
    if ($m -ne 'GET') {
        $t = Get-PimManagerAppRouteTier -Method $m -Path $p
        if ($t.tier -eq 3) { return (& $no "person only: $($t.reason)") }
    }
    $rank = @{ Reader = 0; Admin = 1 }
    foreach ($r in @(Get-PimManagerAppRouteAllowList)) {
        if ($r.method -ne $m) { continue }
        if ($p -cnotmatch $r.pattern) { continue }
        $ok = $false
        if ("$Role" -eq 'Support') { $ok = ($r.minRole -eq 'Support' -or $r.support) }
        elseif ($r.minRole -eq 'Support') { $ok = $false }
        else { $ok = ($rank["$Role"] -ge $rank[$r.minRole]) }
        if ($ok) { return [pscustomobject]@{ allowed = $true; minRole = $r.minRole; reason = 'on the application allow-list'; settings = [bool]($r.settings -and "$Role" -eq 'Admin'); tier = [int]$r.tier; kind = "$($r.kind)" } }
        return (& $no "needs an application with the $($r.minRole) role" $r.minRole)
    }
    return (& $no 'not open to applications')
}

# ---- SETTINGS-API-1: export / import helpers (PURE) ---------------------------------------------------------------------
function Get-PimManagerAppSecretMarker { '[withheld]' }

function Test-PimManagerAppSecretKey {
    # PURE. A property name that holds a secret value (never exported to an application).
    param([string]$Name)
    return ("$Name" -match '(?i)secret|password|passwd|pwd|token|apikey|api_key|connectionstring|privatekey|private_key|webhook|thumbprint|credential|signature|(^|_)sas($|_)|^key$|clientkey')
}

function ConvertTo-PimManagerAppRedactedValue {
    # PURE. A setting value with every secret-named property replaced by the marker (any depth). Values only change shape
    # to plain objects; arrays stay arrays.
    param([AllowNull()][object]$Value, [int]$Depth = 0)
    if ($null -eq $Value -or $Depth -gt 30) { return $Value }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) { $o["$k"] = $(if (Test-PimManagerAppSecretKey -Name "$k") { Get-PimManagerAppSecretMarker } else { ConvertTo-PimManagerAppRedactedValue -Value $Value[$k] -Depth ($Depth + 1) }) }
        return [pscustomobject]$o
    }
    if ($Value -is [System.Collections.IEnumerable]) { return ,@(@($Value) | ForEach-Object { ConvertTo-PimManagerAppRedactedValue -Value $_ -Depth ($Depth + 1) }) }
    $o2 = [ordered]@{}
    foreach ($pp in $Value.PSObject.Properties) { $o2[$pp.Name] = $(if (Test-PimManagerAppSecretKey -Name $pp.Name) { Get-PimManagerAppSecretMarker } else { ConvertTo-PimManagerAppRedactedValue -Value $pp.Value -Depth ($Depth + 1) }) }
    return [pscustomobject]$o2
}

function Restore-PimManagerAppRedactedValue {
    # PURE. An imported value in which a secret-named property carries the marker gets the CURRENT value back (an export
    # imported again never overwrites a secret with the marker). A real new value is kept as sent.
    param([AllowNull()][object]$Incoming, [AllowNull()][object]$Current, [int]$Depth = 0)
    if ($null -eq $Incoming -or $Depth -gt 30) { return $Incoming }
    if ($Incoming -is [string] -or $Incoming -is [ValueType]) { return $Incoming }
    if ($Incoming -is [System.Collections.IEnumerable] -and -not ($Incoming -is [System.Collections.IDictionary])) { return ,@($Incoming) }
    $get = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }; $q = $o.PSObject.Properties[$n]; if ($q) { return $q.Value }; return $null }
    $names = if ($Incoming -is [System.Collections.IDictionary]) { @($Incoming.Keys) } else { @($Incoming.PSObject.Properties | ForEach-Object { $_.Name }) }
    $o = [ordered]@{}
    foreach ($n in $names) {
        $iv = & $get $Incoming $n; $cv = & $get $Current $n
        if ((Test-PimManagerAppSecretKey -Name "$n") -and "$iv" -eq (Get-PimManagerAppSecretMarker)) { $o["$n"] = $cv }
        else { $o["$n"] = Restore-PimManagerAppRedactedValue -Incoming $iv -Current $cv -Depth ($Depth + 1) }
    }
    return [pscustomobject]$o
}

function Get-PimManagerAppImportRefusal {
    <#
      PURE. Which items of an import plan (Get-PimSettingsImportPlan items: name; state) an APPLICATION may not apply: every
      person-only setting whose state is not 'same', plus every changed entry of the document's readOnly block.
      -> @{ refused = @(@{ name; reason }); any }.
    #>
    param([object[]]$Items = @(), [AllowNull()][object]$ReadOnlyIncoming, [scriptblock]$Reader)
    $po = Get-PimManagerAppPersonOnlySettings
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        if ($po.Contains("$($it.name)") -and "$($it.state)" -ne 'same') { $out.Add([pscustomobject]@{ name = "$($it.name)"; reason = "$($po["$($it.name)"])" }) }
    }
    if ($null -ne $ReadOnlyIncoming) {
        foreach ($p in $ReadOnlyIncoming.PSObject.Properties) {
            if (-not $po.Contains($p.Name)) { continue }   # a read-only tier-1 value is changed through its own route, never refused here
            $cur = $null; if ($Reader) { try { $cur = & $Reader $p.Name } catch { $cur = $null } }
            $inc = $p.Value; if ($inc -and $inc.PSObject.Properties['value']) { $inc = $inc.value }
            $j = { param($x) if ($null -eq $x) { '' } else { (ConvertTo-PimManagerAppRedactedValue -Value $x | ConvertTo-Json -Depth 30 -Compress) } }
            if ((& $j $cur) -ne (& $j $inc) -and -not (@($out | Where-Object { $_.name -eq $p.Name }).Count)) {
                $why = if ($po.Contains($p.Name)) { "$($po[$p.Name])" } else { 'read-only in the export' }
                $out.Add([pscustomobject]@{ name = "$($p.Name)"; reason = $why })
            }
        }
    }
    return [pscustomobject]@{ refused = @($out.ToArray()); any = [bool]($out.Count) }
}

function Get-PimManagerAppExportReadOnlyNames {
    # PURE. The settings an application export shows READ-ONLY beside the copyable sections (what a person sees in Settings).
    return @('EnvironmentName', 'CompanyName', 'SupportEmail', 'PendingReminders', 'ActivatorTargets', 'MailNotifications', 'ManagementReport', 'DriftAlertCadence',
             'AuditRetentionMonths', 'ConfigBackupRetentionDays', 'ApprovalSelfApprove', 'PendingSecondApprover', 'GuardReleaseSecondPerson', 'DepartmentOwnersGetReader',
             'AutoExtendPolicy', 'Scenario', 'Edition', 'DemoMode')
}

# ---- PEOPLE-API-APPROVAL-1 / SUPPORT: row changes (PURE) ----------------------------------------------------------------
function ConvertTo-PimManagerAppRowText {
    # PURE. A row as stable text (properties sorted, values as strings) -- equality of two rows.
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    $names = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys | ForEach-Object { "$_" }) } else { @($Row.PSObject.Properties | ForEach-Object { $_.Name }) }
    $parts = foreach ($n in @($names | Sort-Object)) {
        $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$n] } else { $Row.$n }
        if ($null -eq $v -or "$v" -eq '') { continue }   # an absent column and an empty one are the same row
        "$n=$v"
    }
    return ($parts -join "`n")
}

function Get-PimManagerAppRowChanges {
    <#
      PURE. Before / after row sets keyed by -KeyOf ({ param($row) <key> }) -> @( @{ op = add | modify | remove; key; before; row } ).
      A key twice in -After = ok $false (ambiguous). -> @{ ok; reason; changes }.
    #>
    param([object[]]$Before = @(), [object[]]$After = @(), [Parameter(Mandatory)][scriptblock]$KeyOf)
    $b = [ordered]@{}; foreach ($r in @($Before | Where-Object { $null -ne $_ })) { $k = "$(& $KeyOf $r)".ToLowerInvariant(); if (-not $b.Contains($k)) { $b[$k] = $r } }
    $a = [ordered]@{}
    foreach ($r in @($After | Where-Object { $null -ne $_ })) {
        $k = "$(& $KeyOf $r)".ToLowerInvariant()
        if (-not $k.Trim()) { return [pscustomobject]@{ ok = $false; reason = 'a row has no key'; changes = @() } }
        if ($a.Contains($k)) { return [pscustomobject]@{ ok = $false; reason = "the key '$k' is in the rows twice"; changes = @() } }
        $a[$k] = $r
    }
    $ch = New-Object System.Collections.Generic.List[object]
    foreach ($k in $a.Keys) {
        if (-not $b.Contains($k)) { $ch.Add([pscustomobject]@{ op = 'add'; key = $k; before = $null; row = $a[$k] }) }
        elseif ((ConvertTo-PimManagerAppRowText $b[$k]) -ne (ConvertTo-PimManagerAppRowText $a[$k])) { $ch.Add([pscustomobject]@{ op = 'modify'; key = $k; before = $b[$k]; row = $a[$k] }) }
    }
    foreach ($k in $b.Keys) { if (-not $a.Contains($k)) { $ch.Add([pscustomobject]@{ op = 'remove'; key = $k; before = $b[$k]; row = $null }) } }
    return [pscustomobject]@{ ok = $true; reason = ''; changes = @($ch.ToArray()) }
}

function Merge-PimManagerAppRowChanges {
    <#
      PURE. Apply stored changes to the CURRENT rows. A modify / remove whose row is no longer what it was when the change
      was proposed, or an add whose key exists by now, is STALE: nothing is applied (ok $false, stale = the keys).
    #>
    param([object[]]$Current = @(), [object[]]$Changes = @(), [Parameter(Mandatory)][scriptblock]$KeyOf)
    $cur = [ordered]@{}; foreach ($r in @($Current | Where-Object { $null -ne $_ })) { $cur["$(& $KeyOf $r)".ToLowerInvariant()] = $r }
    $stale = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Changes)) {
        $k = "$($c.key)".ToLowerInvariant()
        if ("$($c.op)" -eq 'add') { if ($cur.Contains($k)) { $stale.Add($k) } }
        elseif (-not $cur.Contains($k) -or (ConvertTo-PimManagerAppRowText $cur[$k]) -ne (ConvertTo-PimManagerAppRowText $c.before)) { $stale.Add($k) }
    }
    if ($stale.Count) { return [pscustomobject]@{ ok = $false; stale = @($stale.ToArray()); rows = @() } }
    foreach ($c in @($Changes)) {
        $k = "$($c.key)".ToLowerInvariant()
        if ("$($c.op)" -eq 'remove') { $cur.Remove($k) } else { $cur[$k] = $c.row }
    }
    return [pscustomobject]@{ ok = $true; stale = @(); rows = @($cur.Values) }
}

function Get-PimManagerAppChangeLines {
    # PURE. Short readable lines for the approver / the mail (capped at 200, each <= 200 chars).
    param([object[]]$Changes = @(), [string]$Base = '')
    @(@($Changes) | Select-Object -First 200 | ForEach-Object {
        $l = "{0} {1} {2}" -f "$($_.op)", $Base, "$($_.key)"
        if ($l.Length -gt 200) { $l.Substring(0, 197) + '...' } else { $l }
    })
}

function Test-PimManagerAppSupportTicket {
    # PURE. The reason carries a support ticket id SUP-YYYY-NNNNN. -> the id, or '' when none.
    param([string]$Reason = '')
    $m = [regex]::Match("$Reason", '\bSUP-(\d{4})-(\d{5})\b')
    if ($m.Success) { return $m.Value }
    return ''
}

function Get-PimManagerAppSupportRateLimit { 25 }   # SUPPORT-DIRECT-GRANT-1 (c): tier-2 rows per hour per install from the Support role

function Test-PimManagerAppSupportRate {
    <#
      PURE. SUPPORT-DIRECT-GRANT-1 (c). -Ledger = @(@{ atUtc; rows }) of the Support role's committed tier-2 changes. A change
      of -Rows rows is allowed when the rows in the last hour + -Rows <= -Limit. -> @{ allowed; used; limit; rows }.
    #>
    param([object[]]$Ledger = @(), [int]$Rows = 0, [int]$Limit = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($Limit -le 0) { $Limit = Get-PimManagerAppSupportRateLimit }
    $since = $NowUtc.ToUniversalTime().AddHours(-1)
    $used = 0
    foreach ($l in @($Ledger | Where-Object { $_ })) {
        $t = ConvertTo-PimManagerApiAppUtcText $l.atUtc
        if ($l.PSObject.Properties['tier'] -and "$($l.tier)" -eq '1') { continue }   # only grant (tier-2) rows count
        if (-not $t) { $used += [int]$l.rows; continue }   # an unreadable stamp counts (fail closed)
        if ([datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() -ge $since) { $used += [int]$l.rows }
    }
    return [pscustomobject]@{ allowed = [bool](($used + $Rows) -le $Limit); used = $used; limit = $Limit; rows = $Rows }
}

function Get-PimManagerAppSupportFixCatalog {
    <#
      PURE. SUPPORT-FIX-API-1 (framework 12.30): every fixId POST /api/app/support/fix accepts. A fix applies only when the
      failure catalog ALSO offers it for that failure's code (PIM-FailureCatalog.ps1 rule 'fixes'). Each one only REMOVES a
      row or makes an assignment Eligible -- it never adds access and never touches a person-only setting.
    #>
    return @(
        [pscustomobject]@{ fixId = 'delete-row';    kind = 'delete-row'; set = $null; changes = 'removes exactly the one row the failure names (stops managing it)' }
        [pscustomobject]@{ fixId = 'make-eligible'; kind = 'set';        set = [ordered]@{ AssignmentType = 'Eligible' }; changes = 'sets AssignmentType = Eligible on exactly the one row the failure names' }
        # owner 2026-11-16 "Support creates them on a ticket": the ONE Support exception to "PIM never creates a Defender role" (the
        # engine's own runs never do). Offered by THIS catalog for DEFENDER-ROLE-MISSING only (codes); created by the ENGINE identity
        # through a queued action with EXACTLY the name + permissions PIM's definition lists and the managed-role marker.
        [pscustomobject]@{ fixId = 'create-defender-role'; kind = 'create-defender-role'; set = $null; codes = @('DEFENDER-ROLE-MISSING'); changes = 'creates the missing Defender XDR custom role with exactly the name and permissions PIM''s definition lists (nothing else), by the engine identity' }
    )
}

function Get-PimManagerAppFailureRowKeys {
    # PURE. The columns that identify the failing row per entity -- the SAME list the page's fix uses (ENG_FAIL_ROW_KEYS).
    return @{
        'PIM-Assignments-Roles-AUs' = @('GroupTag', 'RoleDefinitionName', 'AdministrativeUnitTag', 'AssignmentType')
        'PIM-Assignments-Groups'    = @('TargetGroupTag', 'SourceGroupTag')
        'PIM-Assignments-Admins'    = @('Username', 'GroupTag')
        'PIM-Assignments-Workloads' = @('Workload', 'GroupTag', 'Resource', 'Scope', 'RoleName')
    }
}

function Resolve-PimManagerAppSupportFix {
    <#
      PURE. One support fix -> @{ ok; status; reason; entity; afterRows; matched }:
        400 unknown fixId (not in Get-PimManagerAppSupportFixCatalog)    409 the catalog does not offer it for this failure
        409 the entity is person-only (tier 3)                            409 not exactly one row matches (never a guess)
      -CatalogFixes = the fixes the failure catalog offers for the item's code (never the stored item's own list alone).
    #>
    param([AllowNull()][object]$Item, [string]$FixId = '', [object[]]$CatalogFixes = @(), [object[]]$Rows = @())
    $no = { param($s, $why) [pscustomobject]@{ ok = $false; status = $s; reason = $why; entity = "$(if ($Item) { $Item.entity })"; afterRows = @(); matched = 0 } }
    $fx = @(Get-PimManagerAppSupportFixCatalog | Where-Object { $_.fixId -ceq "$FixId" })[0]
    if (-not $fx) { return (& $no 400 "'$FixId' is not a fix this route applies") }
    if ($null -eq $Item) { return (& $no 404 'no such failure') }
    $offered = @(@($CatalogFixes) | Where-Object { $_ -and ("$($_.id)" -ceq "$FixId") -and ("$($_.kind)" -ceq "$($fx.kind)") })
    if (-not $offered.Count) { return (& $no 409 "the failure catalog does not offer '$FixId' for $($Item.code)") }
    $ent = "$($Item.entity)"
    $et = Get-PimManagerAppEntityTier -Entity $ent
    if (-not $ent -or $et.tier -ge 3) { return (& $no 409 "the fix would change $ent, which is person only") }
    $row = $Item.row; if ($null -eq $row) { return (& $no 409 'the failure carries no row values to locate the row') }
    $keys = (Get-PimManagerAppFailureRowKeys)[$ent]
    if (-not $keys) { $keys = @($row.PSObject.Properties | ForEach-Object { $_.Name }) }
    $crit = [ordered]@{}; foreach ($k in $keys) { $v = $row.$k; if ($null -ne $v -and "$v" -ne '') { $crit[$k] = "$v" } }
    if (-not $crit.Count) { return (& $no 409 'the failure carries no row values to locate the row') }
    $hit = @(); $i = 0
    foreach ($r in @($Rows)) {
        $all = $true; foreach ($k in $crit.Keys) { if ("$($r.$k)" -cne $crit[$k]) { $all = $false; break } }
        if ($all) { $hit += $i }
        $i++
    }
    if ($hit.Count -ne 1) { return (& $no 409 $(if ($hit.Count) { "$($hit.Count) rows match -- not applied (fix it in the page)" } else { "the row is no longer in $ent" })) }
    $after = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($r in @($Rows)) {
        if ($i -eq $hit[0]) {
            if ($fx.kind -eq 'set') {
                $o = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $o[$p.Name] = $p.Value }
                foreach ($k in $fx.set.Keys) { $o[$k] = "$($fx.set[$k])" }
                $after.Add([pscustomobject]$o)
            }
        } else { $after.Add($r) }
        $i++
    }
    return [pscustomobject]@{ ok = $true; status = 200; reason = "$($fx.changes)"; entity = $ent; afterRows = @($after.ToArray()); matched = 1 }
}

function Resolve-PimManagerAppDefenderRoleFix {
    <#
      PURE. owner 2026-11-16 "Support creates them on a ticket". The role a DEFENDER-ROLE-MISSING failure names, with EXACTLY the
      permissions PIM's DEFINITION lists -- read from the CURRENT stored row of that binding (-Rows), never from the request.
      -> @{ ok; status; reason; name; actions }:
        400 not this fix         409 another failure class (only DEFENDER-ROLE-MISSING)    409 the definition lists no permissions
        409 the role name is not resolved ('{GroupName}' left)    409 an action that is not a Defender XDR action (microsoft.xdr/...)
    #>
    param([AllowNull()][object]$Item, [string]$FixId = '', [object[]]$Rows = @())
    $no = { param($s, $why) [pscustomobject]@{ ok = $false; status = $s; reason = $why; name = ''; actions = @() } }
    $fx = @(Get-PimManagerAppSupportFixCatalog | Where-Object { $_.fixId -ceq "$FixId" -and $_.kind -eq 'create-defender-role' })[0]
    if (-not $fx) { return (& $no 400 "'$FixId' is not the create-defender-role fix") }
    if ($null -eq $Item) { return (& $no 404 'no such failure') }
    if ("$($Item.code)" -notin @($fx.codes)) { return (& $no 409 "create-defender-role is offered only for $(@($fx.codes) -join ', '), not for $($Item.code)") }
    $name = ''
    $m = [regex]::Match("$($Item.message)", "Defender XDR role '([^']+)' does not exist")
    if ($m.Success) { $name = $m.Groups[1].Value.Trim() }
    $row = $Item.row
    if (-not $name -and $row) { foreach ($n in 'RoleDefinitionName', 'RoleName') { if (-not $name -and $row.PSObject.Properties[$n] -and "$($row.$n)".Trim()) { $name = "$($row.$n)".Trim() } } }
    if (-not $name -or $name -match '\{|\}') { return (& $no 409 'the role name is not resolved -- nothing to create') }
    $gt = if ($row -and $row.PSObject.Properties['GroupTag']) { "$($row.GroupTag)".Trim() } else { '' }
    $def = @(@($Rows) | Where-Object {
        $_ -and ("$($_.GroupTag)".Trim() -ieq $gt) -and ("$(@($_.Permissions, $_.AllowedResourceActions) | Where-Object { "$_".Trim() } | Select-Object -First 1)".Trim()) -and
        ("$($_.Workload)" -match '(?i)defender' -or -not $_.PSObject.Properties['Workload'])
    })
    if ($def.Count -ne 1) { return (& $no 409 $(if ($def.Count) { "$($def.Count) definitions match -- not created (fix it in the page)" } else { "PIM's definition lists no permissions for '$name' -- nothing to create" })) }
    $perm = "$(@($def[0].Permissions, $def[0].AllowedResourceActions) | Where-Object { "$_".Trim() } | Select-Object -First 1)"
    $acts = @($perm -split '[;,\r\n]+' | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $acts.Count) { return (& $no 409 "PIM's definition lists no permissions for '$name' -- nothing to create") }
    $bad = @($acts | Where-Object { $_ -notmatch '^microsoft\.xdr/[A-Za-z0-9_\-\*/\.]+$' })
    if ($bad.Count) { return (& $no 409 "not Defender XDR permissions: $($bad -join ', ') -- nothing created") }
    return [pscustomobject]@{ ok = $true; status = 200; reason = 'creates exactly the listed permissions'; name = $name; actions = @($acts) }
}

# ---- SUPPORT-FIX-API-1 enrolment by the UPDATER (PURE) -------------------------------------------------------------------
function Get-PimManagerSupportAppTag { 'InvardiaSupport' }
function Get-PimManagerSupportAppEntryName { 'Invardia Support (enrolled by the updater)' }

function Resolve-PimManagerSupportAppEnrolment {
    <#
      PURE. The updater's step (framework 12.30): -Found = the service principals in THIS tenant tagged InvardiaSupport
      (@{ appId; displayName }). Exactly one -> listed with role Support (idempotent; an earlier updater entry for another app
      is replaced). None -> info, nothing changes. More than one -> refused, nothing changes. The updater NEVER writes Admin or
      Reader and never changes an entry a PERSON listed (that app stays as the person listed it).
      -> @{ action = enrolled | already | none | refused | person-listed; apps; changed; lines }.
    #>
    param([AllowNull()][AllowEmptyCollection()][object]$Current, [object[]]$Found = @(), [string]$TenantId = '')
    $cur = @((ConvertTo-PimManagerApiAppList -Value @($Current)).apps)
    $f = @(@($Found) | Where-Object { $_ -and "$($_.appId)".Trim() } | Sort-Object { "$($_.appId)" } -Unique)
    $mk = { param($a, $apps, $ch, $l) [pscustomobject]@{ action = $a; apps = @($apps); changed = [bool]$ch; lines = @($l) } }
    # single-tenant per customer: an application registered in ANOTHER tenant is never the support app of this one
    $foreign = @($f | Where-Object { "$TenantId".Trim() -and "$($_.appOwnerOrganizationId)".Trim() -and "$($_.appOwnerOrganizationId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant() })
    if ($foreign.Count) { return (& $mk 'refused' $cur $false @("the tagged application $(@($foreign | ForEach-Object { $_.appId }) -join ', ') is registered in another tenant -- refused, none enrolled")) }
    if ($f.Count -eq 0) { return (& $mk 'none' $cur $false @("no service principal tagged '$(Get-PimManagerSupportAppTag)' in this tenant -- nothing enrolled (information)")) }
    if ($f.Count -gt 1) { return (& $mk 'refused' $cur $false @("$($f.Count) service principals are tagged '$(Get-PimManagerSupportAppTag)' ($(@($f | ForEach-Object { "$($_.appId) $($_.displayName)" }) -join '; ')) -- refused, none enrolled")) }
    $id = "$($f[0].appId)".Trim().ToLowerInvariant()
    if ($id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return (& $mk 'refused' $cur $false @("the tagged service principal has no valid application id ('$id')")) }
    $name = Get-PimManagerSupportAppEntryName
    $mine = @($cur | Where-Object { $_.appId -eq $id })[0]
    if ($mine -and $mine.role -ne 'Support') { return (& $mk 'person-listed' $cur $false @("$id is listed by a person with role $($mine.role) -- left as it is")) }
    if ($mine -and $mine.role -eq 'Support' -and @($cur | Where-Object { $_.role -eq 'Support' -and $_.name -eq $name -and $_.appId -ne $id }).Count -eq 0) {
        return (& $mk 'already' $cur $false @("$id is enrolled with role Support"))
    }
    $new = @($cur | Where-Object { -not ($_.role -eq 'Support' -and $_.name -eq $name) -and $_.appId -ne $id })
    $new += [ordered]@{ appId = $id; role = 'Support'; name = $name }
    $out = @((ConvertTo-PimManagerApiAppList -Value @($new)).apps)
    return (& $mk 'enrolled' $out $true @("$id ($($f[0].displayName)) enrolled with role Support"))
}

function Invoke-PimManagerSupportAppEnrolment {
    <#
      The updater's write (framework 12.30): read the list, decide (Resolve-PimManagerSupportAppEnrolment), write with
      compare-and-set, READ BACK. The second-SuperAdmin approval a person-added application needs is skipped here on purpose:
      this is the product's own step, for the one tag-discovered app, with the narrow Support role only. Never throws.
      -Graph { param($path) <GET result> }. -> @{ action; ok; lines }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][scriptblock]$Graph, [string]$TenantId = '')
    $lines = New-Object System.Collections.Generic.List[string]
    try {
        $tag = Get-PimManagerSupportAppTag
        $r = & $Graph "/servicePrincipals?`$filter=tags/any(t:t eq '$tag')&`$select=id,appId,displayName,tags,appOwnerOrganizationId"
        $found = @(@($r.value) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ appId = "$($_.appId)"; displayName = "$($_.displayName)"; appOwnerOrganizationId = "$($_.appOwnerOrganizationId)" } })
        $st = Get-PimManagerApiAppState -ConnectionString $ConnectionString
        $d = Resolve-PimManagerSupportAppEnrolment -Current $st.apps -Found $found -TenantId $TenantId
        foreach ($l in $d.lines) { $lines.Add($l) }
        if (-not $d.changed) { return [pscustomobject]@{ action = $d.action; ok = ($d.action -ne 'refused'); lines = @($lines.ToArray()) } }
        foreach ($a in @($d.apps)) { if ("$($a.role)" -eq 'Admin' -and -not @($st.apps | Where-Object { $_.appId -eq $a.appId -and $_.role -eq 'Admin' }).Count) { throw 'refused: the updater never writes role Admin' } }
        $json = ConvertTo-Json -InputObject ([ordered]@{ apps = @($d.apps) }) -Depth 5 -Compress
        $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimManagerApiAppSettingName) -NewValueJson $json -ExpectedValueJson $st.raw
        if ([int]$n -ne 1) { $lines.Add('the list changed while it was being written -- the next update tries again'); return [pscustomobject]@{ action = 'conflict'; ok = $false; lines = @($lines.ToArray()) } }
        $back = Get-PimManagerApiAppState -ConnectionString $ConnectionString
        $okBack = ($back.hash -eq (Get-PimManagerApiAppListHash -Apps @($d.apps)))
        $lines.Add($(if ($okBack) { 'read back: the list holds the Support entry' } else { 'read back FAILED: the list does not match what was written' }))
        return [pscustomobject]@{ action = $d.action; ok = $okBack; lines = @($lines.ToArray()) }
    } catch {
        $lines.Add("support app enrolment not done: $($_.Exception.Message)")
        return [pscustomobject]@{ action = 'failed'; ok = $false; lines = @($lines.ToArray()) }
    }
}

# ---- framework 12.31 rules 2 / 4 / 5: the API app's hardening, READ BACK by the updater (never granted by it) -----------
function Get-PimManagerApiHardeningSettingName { 'ManagerApiHardening' }

function Resolve-PimManagerApiHardeningState {
    <#
      PURE. From the API application (Graph: optionalClaims), its service principal (appRoleAssignmentRequired, appRoles, id)
      and the support app's role assignments -> @{ idtypConfigured; assignmentRequired; supportRoleAssigned; steps (setup
      steps to do); info (information lines); record }. The updater WRITES nothing in Entra ID.
    #>
    param([AllowNull()][object]$Application, [AllowNull()][object]$ServicePrincipal, [object[]]$SupportAssignments = @(), [bool]$SupportFound = $false,
          [string]$RoleValue = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not "$RoleValue".Trim()) { $RoleValue = Get-PimManagerApiAppRoleValue }
    $idtyp = $false
    if ($Application -and $Application.optionalClaims -and $Application.optionalClaims.accessToken) {
        $idtyp = [bool](@(@($Application.optionalClaims.accessToken) | Where-Object { $_ -and "$($_.name)" -eq 'idtyp' }).Count)
    }
    $req = [bool]($ServicePrincipal -and $ServicePrincipal.appRoleAssignmentRequired -eq $true)
    $roleId = ''
    if ($ServicePrincipal) { $roleId = "$((@(@($ServicePrincipal.appRoles) | Where-Object { $_ -and "$($_.value)" -eq $RoleValue }) | Select-Object -First 1).id)" }
    $sup = [bool]($SupportFound -and $roleId -and $ServicePrincipal -and @(@($SupportAssignments) | Where-Object { $_ -and "$($_.resourceId)" -eq "$($ServicePrincipal.id)" -and "$($_.appRoleId)" -eq $roleId }).Count)
    # owner 2026-11-16 "Strict everywhere at once": a missing idtyp claim is a SETUP STEP (scripts are refused until it is
    # done). Assignment required (rule 5) is DEFERRED ("Skip that rule for now": one app registration for sign-in and API) --
    # read and recorded, never a step. Support "On by default": the support app's role not assigned yet = a SETUP STEP.
    $steps = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]
    if (-not $idtyp) { $steps.Add('API applications: run Set-PimManagerApiAuth.ps1 -Apply (the idtyp claim is missing on the API application -- application calls are refused until then)') }
    if ($SupportFound -and -not $sup) { $steps.Add('Invardia support fixes: run Set-PimManagerApiAuth.ps1 -SupportApp once') }
    elseif ($sup) { $info.Add('Invardia support fixes: enabled') }
    $rec = [ordered]@{ idtypConfigured = $idtyp; assignmentRequired = $req; supportRoleAssigned = $sup; supportFound = [bool]$SupportFound; checkedUtc = $NowUtc.ToUniversalTime().ToString('o') }
    return [pscustomobject]@{ idtypConfigured = $idtyp; assignmentRequired = $req; supportRoleAssigned = $sup; steps = @($steps.ToArray()); info = @($info.ToArray()); record = $rec }
}

function Invoke-PimManagerApiHardeningCheck {
    <#
      The updater's step (framework 12.30 + 12.31): enrol the tag-discovered support app in PIM's OWN list (role Support), then
      READ the API application + service principal + the support app's role assignments and store the result
      (pim.Settings ManagerApiHardening; the Manager requires idtyp once idtypConfigured is true). GET only in Entra ID --
      never an app-role assignment, never a manifest write. Never throws. -> @{ lines; record; enrolment }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][scriptblock]$Graph, [string]$TenantId = '', [string]$ApiAppId = '')
    $lines = New-Object System.Collections.Generic.List[string]
    $en = Invoke-PimManagerSupportAppEnrolment -ConnectionString $ConnectionString -Graph $Graph -TenantId $TenantId
    foreach ($l in @($en.lines)) { $lines.Add("support app: $l") }
    $rec = $null
    try {
        $id = "$ApiAppId".Trim().ToLowerInvariant()
        if ($id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $lines.Add('API hardening not read: the API application id is not known (PIM_API_APP_AUDIENCE not set -- application sign-in is not set up)'); return [pscustomobject]@{ lines = @($lines.ToArray()); record = $null; enrolment = $en } }
        $app = @((& $Graph "/applications?`$filter=appId eq '$id'&`$select=id,appId,optionalClaims").value)[0]
        $sp = @((& $Graph "/servicePrincipals?`$filter=appId eq '$id'&`$select=id,appId,appRoleAssignmentRequired,appRoles").value)[0]
        $supFound = $false; $asg = @()
        $tag = Get-PimManagerSupportAppTag
        $sups = @((& $Graph "/servicePrincipals?`$filter=tags/any(t:t eq '$tag')&`$select=id,appId").value | Where-Object { $_ })
        if ($sups.Count -eq 1) { $supFound = $true; $asg = @((& $Graph "/servicePrincipals/$($sups[0].id)/appRoleAssignments").value) }
        $st = Resolve-PimManagerApiHardeningState -Application $app -ServicePrincipal $sp -SupportAssignments $asg -SupportFound $supFound
        foreach ($s in @($st.steps)) { $lines.Add("setup step: $s") }
        foreach ($s in @($st.info)) { $lines.Add($s) }
        if (-not @($st.steps).Count) { $lines.Add('API applications: the idtyp claim is in place') }
        $rec = $st.record
        if (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue) { Set-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimManagerApiHardeningSettingName) -ValueJson (ConvertTo-Json -InputObject $rec -Compress) }
    } catch { $lines.Add("API hardening not read: $($_.Exception.Message)") }
    return [pscustomobject]@{ lines = @($lines.ToArray()); record = $rec; enrolment = $en }
}

function Resolve-PimManagerAppRequest {
    <#
      PURE given its inputs. The whole decision for one request under /api/app/:
        1. the path is under the prefix (else ok=$false, handled=$false: not an application call at all);
        2. no application listed -> 403 (application sign-in is OFF; no token is looked at);
        3. the token (Resolve-PimManagerAppBearer) -> 401 / 403 / 503;
        4. the token's application is on the list -> else 403;
        5. the route is on the allow-list for the application's role -> else 403.
      -> @{ handled; ok; status; appId; name; role; path (the page route, /api/...); reason; audit (= a verified application
         was involved, so the outcome belongs in the audit trail) }.
    #>
    param([string]$Method = '', [string]$Path = '', [string]$Authorization = '', [AllowNull()][object]$Apps, [AllowNull()][object]$Jwks,
          [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(), [datetime]$NowUtc = ([datetime]::UtcNow),
          [string]$ExpectedTenantId = '', [switch]$RequireIdtyp)
    $pre = Get-PimManagerApiAppPrefix
    $res = { param($h, $ok, $s, $why, $a = '', $n = '', $r = '', $p = '', $au = $false, $set = $false, $kind = '', $tier = 0) [pscustomobject]@{ handled = $h; ok = $ok; status = $s; appId = $a; name = $n; role = $r; path = $p; reason = $why; audit = [bool]$au; settings = [bool]$set; kind = "$kind"; tier = [int]$tier } }
    $raw = "$Path"
    if (-not ($raw -eq $pre -or $raw.StartsWith("$pre/", [System.StringComparison]::Ordinal))) { return (& $res $false $false 0 'not an application route') }
    $rest = $raw.Substring($pre.Length)
    $page = '/api' + $rest
    $list = @((ConvertTo-PimManagerApiAppList -Value $Apps).apps)
    if ($list.Count -eq 0) { return (& $res $true $false 403 'no application is allowed to use the API (none listed)') }
    $b = Resolve-PimManagerAppBearer -Authorization $Authorization -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences -NowUtc $NowUtc -ExpectedTenantId $ExpectedTenantId -RequireIdtyp:$RequireIdtyp
    if (-not $b.ok) { return (& $res $true $false ([int]$b.status) "$($b.reason)" "$($b.appId)" '' '' $page ([bool]"$($b.appId)")) }
    $hit = @($list | Where-Object { $_.appId -eq "$($b.appId)" })[0]
    if (-not $hit) { return (& $res $true $false 403 'the application is not on the list of allowed applications' "$($b.appId)" '' '' $page $true) }
    $rt = Test-PimManagerAppRouteAllowed -Method $Method -Path $page -Role "$($hit.role)"
    if (-not $rt.allowed) { return (& $res $true $false 403 "$($rt.reason)" "$($hit.appId)" "$($hit.name)" "$($hit.role)" $page $true) }
    return (& $res $true $true 200 'allowed' "$($hit.appId)" "$($hit.name)" "$($hit.role)" $page $true ([bool]$rt.settings) "$($rt.kind)" ([int]$rt.tier))
}

# ---- store adapter (compare-and-set over pim.Settings) -----------------------------------------------------------------
function Assert-PimManagerApiAppStore {
    foreach ($c in @('Get-PimSqlSettingRaw', 'Set-PimSqlSettingIfUnchanged')) {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "the API application store is unavailable: $c is not loaded (kept in SQL only)" }
    }
}

function Get-PimManagerApiAppState {
    # The saved list + its hash + the raw row (the compare-and-set token). THROWS when unreadable -- an unreadable list
    # is never "empty, so nothing changed".
    param([Parameter(Mandatory)][string]$ConnectionString)
    Assert-PimManagerApiAppStore
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name (Get-PimManagerApiAppSettingName)
    $l = ConvertTo-PimManagerApiAppList -Value $raw
    if (-not $l.ok) { throw 'the saved API application list cannot be read' }
    return [pscustomobject]@{ raw = $raw; apps = @($l.apps); hash = (Get-PimManagerApiAppListHash -Apps @($l.apps)) }
}

function Get-PimManagerApiAppChangeRaw {
    param([Parameter(Mandatory)][string]$ConnectionString)
    Assert-PimManagerApiAppStore
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name (Get-PimManagerApiAppChangeSettingName)
    return [pscustomobject]@{ raw = $raw; request = (ConvertTo-PimManagerApiAppChangeRecord -Value $raw) }
}

function Save-PimManagerApiAppChange {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Request, [AllowNull()][string]$ExpectedRaw)
    $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimManagerApiAppChangeSettingName) -NewValueJson (ConvertTo-PimManagerApiAppChangeJson -Request $Request) -ExpectedValueJson $ExpectedRaw
    return ([int]$n -eq 1)
}

function New-PimManagerApiAppChangeRequest {
    # MAKER. Raise a pending request against the list saved NOW (-BaseHash = the list the maker's screen showed). THROWS on a
    # store failure. Nothing is written unless ok.
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][AllowEmptyCollection()][object]$Proposed, [Parameter(Mandatory)][string]$Maker,
          [string]$Justification = '', [string]$BaseHash = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $st = Get-PimManagerApiAppState -ConnectionString $ConnectionString
    if ("$BaseHash".Trim() -and "$BaseHash".Trim().ToLowerInvariant() -ne $st.hash) {
        return [pscustomobject]@{ ok = $false; code = 'base-changed'; reason = 'the list changed since you loaded it -- reload and make your change again'; request = $null; expiredPrevious = $null }
    }
    $rec = Get-PimManagerApiAppChangeRaw -ConnectionString $ConnectionString
    $res = Resolve-PimManagerApiAppChangeCreate -Existing $rec.request -Current $st.apps -Proposed $Proposed -Maker $Maker -Justification $Justification -NowUtc $NowUtc
    if (-not $res.ok) { return $res }
    if (-not (Save-PimManagerApiAppChange -ConnectionString $ConnectionString -Request $res.request -ExpectedRaw $rec.raw)) {
        return [pscustomobject]@{ ok = $false; code = 'conflict'; reason = 'another change request was raised at the same moment -- reload'; request = $null; expiredPrevious = $null }
    }
    return $res
}

function Close-PimManagerApiAppChangeRequest {
    # REJECT (another SuperAdmin) or CANCEL (the maker). THROWS on a store failure.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$RequestId, [Parameter(Mandatory)][string]$Actor,
          [Parameter(Mandatory)][ValidateSet('reject', 'cancel')][string]$Decision, [string]$Note = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $rec = Get-PimManagerApiAppChangeRaw -ConnectionString $ConnectionString
    $res = Resolve-PimManagerApiAppChangeDecision -Request $rec.request -RequestId $RequestId -Actor $Actor -Decision $Decision -Note $Note -NowUtc $NowUtc
    if ($res.ok -or $res.code -eq 'expired') {
        if (-not (Save-PimManagerApiAppChange -ConnectionString $ConnectionString -Request $res.request -ExpectedRaw $rec.raw)) {
            return [pscustomobject]@{ ok = $false; code = 'conflict'; reason = 'the request changed while this was being recorded -- reload'; request = $rec.request }
        }
    }
    return $res
}

function Invoke-PimManagerApiAppChangeApproval {
    <#
      CHECKER. Decide (not the maker unless -AllowSelfApprove, not expired, not stale), CLAIM the request (compare-and-set),
      write the list (compare-and-set against the snapshot row), READ BACK, close as applied | stale | failed.
      -> @{ ok; code; reason; request; apps (read back) }. THROWS only when the store cannot be read at all.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$RequestId, [Parameter(Mandatory)][string]$Checker,
          [string]$Note = '', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$AllowSelfApprove)
    $mk = { param($ok, $code, $reason, $req, $apps) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req; apps = @($apps) } }
    $st = Get-PimManagerApiAppState -ConnectionString $ConnectionString
    $rec = Get-PimManagerApiAppChangeRaw -ConnectionString $ConnectionString
    $dec = Resolve-PimManagerApiAppChangeDecision -Request $rec.request -RequestId $RequestId -Actor $Checker -Decision approve -CurrentHash $st.hash -Note $Note -NowUtc $NowUtc -AllowSelfApprove:$AllowSelfApprove
    if (-not $dec.ok) {
        if ($dec.code -in @('stale', 'expired')) { [void](Save-PimManagerApiAppChange -ConnectionString $ConnectionString -Request $dec.request -ExpectedRaw $rec.raw) }
        return (& $mk $false $dec.code $dec.reason $dec.request $st.apps)
    }
    $claim = ConvertTo-PimManagerApiAppChangeJson -Request $dec.request
    if (-not (Save-PimManagerApiAppChange -ConnectionString $ConnectionString -Request $dec.request -ExpectedRaw $rec.raw)) {
        return (& $mk $false 'conflict' 'the request changed while it was being approved -- reload' $rec.request $st.apps)
    }
    $final = ConvertTo-PimManagerApiAppChangeRecord -Value $dec.request
    $final.closedBy = "$Checker"; $final.closedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $code = 'applied'; $reason = 'applied -- the Manager uses the new list within a minute'; $back = @($st.apps)
    try {
        $json = ConvertTo-Json -InputObject ([ordered]@{ apps = @($final.proposed) }) -Depth 5 -Compress
        $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimManagerApiAppSettingName) -NewValueJson $json -ExpectedValueJson $st.raw
        if ([int]$n -ne 1) { $code = 'stale'; $reason = 'the list changed since the request was made -- raise a new request' }
        else {
            $st2 = Get-PimManagerApiAppState -ConnectionString $ConnectionString
            $back = @($st2.apps)
            if ($st2.hash -ne (Get-PimManagerApiAppListHash -Apps @($final.proposed))) { $code = 'failed'; $reason = 'the list was written but the read-back does not match the approved list' }
        }
    } catch { $code = 'failed'; $reason = "the list was NOT changed: $($_.Exception.Message)" }
    $final.status = $code
    if ($code -ne 'applied') { $final.closeNote = $reason }
    [void](Save-PimManagerApiAppChange -ConnectionString $ConnectionString -Request $final -ExpectedRaw $claim)
    return (& $mk ($code -eq 'applied') $code $reason $final $back)
}
