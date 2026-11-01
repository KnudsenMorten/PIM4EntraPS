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
      it is refused -- the GUI-only / Tier-0 actions, every settings / licence / access / MSP change, approval decisions
      (a second PERSON approves), support bundles, diagnostics and API keys are simply not on it.
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
  Needs PIM-HostedAuth.ps1 (Get-PimJwtParts / Test-PimJwtSignature / Test-PimJwtClaims) for the token check.
#>

Set-StrictMode -Off

function Get-PimManagerApiAppSettingName { 'ManagerApiApps' }
function Get-PimManagerApiAppChangeSettingName { 'ManagerApiAppsChange' }
function Get-PimManagerApiAppPrefix { '/api/app' }
function Get-PimManagerApiAppRoleValue { 'PimManager.Api' }       # the application role a calling app must hold (Entra app role)
function Get-PimManagerApiAppRoles { @('Reader', 'Admin') }      # never SuperAdmin

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
        if (-not $canon) { $errors.Add("application $id : the role must be Reader or Admin (an application can never be SuperAdmin)"); continue }
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
        signature against -Jwks (RS256/384/512 only) -> exp / nbf / issuer (-ExpectedIssuers = this tenant) / audience
        (-ExpectedAudiences, pinned) -> application-only: no 'scp', no upn / preferred_username / unique_name, idtyp (when
        present) = 'app' -> it carries -RequiredRole in 'roles' -> it names its application (appid / azp, a GUID).
      -> @{ ok; status (401 = no / bad token, 403 = genuine but not an application token for this API, 503 = not set up);
            appId; reason }. The reason is for the log and the audit -- never sent to the caller.
    #>
    param([string]$Authorization = '', [AllowNull()][object]$Jwks, [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(),
          [string]$RequiredRole = '', [datetime]$NowUtc = ([datetime]::UtcNow))
    $no = { param($s, $r, $a = '') @{ ok = $false; status = $s; appId = $a; reason = $r } }
    if (-not "$RequiredRole".Trim()) { $RequiredRole = Get-PimManagerApiAppRoleValue }
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $iss.Count -or -not $aud.Count) { return (& $no 503 'application sign-in is not set up on this Manager (no pinned tenant / audience)') }
    if ("$Authorization" -notmatch '^\s*Bearer\s+(\S+)\s*$') { return (& $no 401 'no bearer token') }
    if (-not (Get-Command Get-PimJwtParts -ErrorAction SilentlyContinue)) { return (& $no 503 'the token library is not loaded (refused)') }
    $jwt = Get-PimJwtParts -Token $Matches[1]
    if ($null -eq $jwt) { return (& $no 401 'not a well-formed JWT') }
    if ($null -eq $Jwks) { return (& $no 503 'the tenant signing keys could not be fetched (refused)') }
    $sig = Test-PimJwtSignature -Jwt $jwt -Jwks $Jwks
    if (-not $sig.valid) { return (& $no 401 "signature: $($sig.reason)") }
    $cl = Test-PimJwtClaims -Payload $jwt.payload -ExpectedIssuers $iss -ExpectedAudiences $aud -NowUtc $NowUtc
    if (-not $cl.valid) { return (& $no 401 "claims: $($cl.reason)") }
    $p = $jwt.payload
    $app = "$(if ("$($p.appid)".Trim()) { $p.appid } else { $p.azp })".Trim().ToLowerInvariant()
    if ($app -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return (& $no 401 'the token names no application') }
    if ("$($p.scp)".Trim()) { return (& $no 403 'a delegated (person) token is not an application token' $app) }
    foreach ($c in @('upn', 'preferred_username', 'unique_name')) { if ("$($p.$c)".Trim()) { return (& $no 403 'the token carries user claims' $app) } }
    if ("$($p.idtyp)".Trim() -and "$($p.idtyp)".Trim() -ne 'app') { return (& $no 403 "the token type is '$($p.idtyp)', not app" $app) }
    $roles = @(@($p.roles) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($roles -notcontains $RequiredRole) { return (& $no 403 'the token does not carry the PIM Manager API application role' $app) }
    return @{ ok = $true; status = 200; appId = $app; reason = 'application token verified' }
}

# ---- what an application may call (ALLOW-LIST, deny by default) --------------------------------------------------------
function Get-PimManagerAppRouteAllowList {
    <#
      PURE. THE ALLOW-LIST. Each entry: method, pattern (an anchored regex over the page route, e.g. ^/api/drift$), and the
      minimum role of the APPLICATION. Everything else is refused. Deliberately NOT here (the owner's list, 2026-11-01):
      emergency / break-glass / restore / revoke / drift remediate / group delete / hybrid-AD delete / guard release, every
      settings / licence / access / MSP change, approval decisions (a second PERSON approves), support bundles,
      diagnostics, API keys, the MCP server. A route added to the product is NOT reachable by an application until it is
      added here on purpose.
    #>
    $e = { param($m, $p, $r) [pscustomobject]@{ method = $m; pattern = $p; minRole = $r } }
    return @(
        # --- reads (Reader) ---
        (& $e 'GET' '^/api/config$' 'Reader')
        (& $e 'GET' '^/api/(?:csv|data)/[A-Za-z0-9_.-]+$' 'Reader')
        (& $e 'GET' '^/api/pending$' 'Reader')
        (& $e 'GET' '^/api/drift$' 'Reader')
        (& $e 'GET' '^/api/coverage$' 'Reader')
        (& $e 'GET' '^/api/approvals$' 'Reader')
        (& $e 'GET' '^/api/access-reviews$' 'Reader')
        (& $e 'GET' '^/api/access-review-campaigns$' 'Reader')
        (& $e 'GET' '^/api/guards$' 'Reader')
        (& $e 'GET' '^/api/jobs$' 'Reader')
        (& $e 'GET' '^/api/jobs/history$' 'Reader')
        (& $e 'GET' '^/api/jobs/log$' 'Reader')
        (& $e 'GET' '^/api/search$' 'Reader')
        (& $e 'GET' '^/api/autoextend/upcoming$' 'Reader')
        (& $e 'GET' '^/api/tier-impact$' 'Reader')
        (& $e 'GET' '^/api/role-lookup/reverse$' 'Reader')
        (& $e 'GET' '^/api/access-report/who-can$' 'Reader')
        (& $e 'GET' '^/api/access-report/who-has$' 'Reader')
        # --- reads (Admin) ---
        (& $e 'GET' '^/api/active-assignments$' 'Admin')
        (& $e 'GET' '^/api/unmanaged-admins$' 'Admin')
        # --- routine writes (Admin), each through the page's own handler and gates ---
        # STAGE only, and only an entity on Get-PimManagerAppStageEntities. A PERSON commits: there is deliberately no commit
        # route here (PUT /api/csv|data/<entity>), so no change an application made reaches the engine without a person's
        # commit -- and that commit records the application as the one who staged it (initiatedBy) and the person as approver.
        (& $e 'PUT' ('^/api/pending/(?:' + ((@(Get-PimManagerAppStageEntities) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$') 'Admin')
        (& $e 'POST' '^/api/jobs/run$' 'Admin')                         # run one engine job now
    )
}

function Get-PimManagerAppStageEntities {
    <#
      PURE. The entities an application may STAGE a change to -- an ALLOW-list, deny by default (coordinator + owner rule
      2026-11-01: never an entity that creates an account, grants a role, or changes who can sign in or act). Left OUT, and why:
        Account-Definitions-Admins        creates / changes / disables admin ACCOUNTS (and their TAP sign-in)
        Account-Definitions-Companies     company Contacts sign in to the company review portal
        PIM-Definitions-Roles/-Tasks/-Services/-Processes/-Resources/-Organization/-Projects/-CrossOrg/-Departments
                                          define the groups that carry roles (role-assignable, Tier, Plane) and their OWNERS,
                                          who manage membership and, as department owners, act as delegated administrators
        PIM-Assignments-*                 grant a role, a group membership or an Azure / workload permission
      Break-glass, emergency and Manager access are not entities at all (settings routes, never on the route allow-list).
      What is left: administrative-unit definitions (a name, a description, a tag, visibility) -- a scope, no grant.
    #>
    return @('PIM-Definitions-AU')
}

function Test-PimManagerAppRouteAllowed {
    # PURE. -> @{ allowed; minRole; reason }. -Role is the application's listed role (Reader | Admin; anything else = no access).
    param([string]$Method = '', [string]$Path = '', [string]$Role = '')
    $m = "$Method".Trim().ToUpperInvariant(); $p = "$Path"
    $rank = @{ Reader = 0; Admin = 1 }
    if (-not $rank.ContainsKey("$Role")) { return [pscustomobject]@{ allowed = $false; minRole = ''; reason = 'the application holds no role' } }
    if ($p -match '[\\%]' -or $p -match '/\.\.?(/|$)' -or $p -match '//') { return [pscustomobject]@{ allowed = $false; minRole = ''; reason = 'not a plain route' } }
    foreach ($r in @(Get-PimManagerAppRouteAllowList)) {
        if ($r.method -ne $m) { continue }
        if ($p -cmatch $r.pattern) {
            if ($rank["$Role"] -ge $rank[$r.minRole]) { return [pscustomobject]@{ allowed = $true; minRole = $r.minRole; reason = 'on the application allow-list' } }
            return [pscustomobject]@{ allowed = $false; minRole = $r.minRole; reason = "needs an application with the $($r.minRole) role" }
        }
    }
    return [pscustomobject]@{ allowed = $false; minRole = ''; reason = 'not open to applications' }
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
          [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(), [datetime]$NowUtc = ([datetime]::UtcNow))
    $pre = Get-PimManagerApiAppPrefix
    $res = { param($h, $ok, $s, $why, $a = '', $n = '', $r = '', $p = '', $au = $false) [pscustomobject]@{ handled = $h; ok = $ok; status = $s; appId = $a; name = $n; role = $r; path = $p; reason = $why; audit = [bool]$au } }
    $raw = "$Path"
    if (-not ($raw -eq $pre -or $raw.StartsWith("$pre/", [System.StringComparison]::Ordinal))) { return (& $res $false $false 0 'not an application route') }
    $rest = $raw.Substring($pre.Length)
    $page = '/api' + $rest
    $list = @((ConvertTo-PimManagerApiAppList -Value $Apps).apps)
    if ($list.Count -eq 0) { return (& $res $true $false 403 'no application is allowed to use the API (none listed)') }
    $b = Resolve-PimManagerAppBearer -Authorization $Authorization -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences -NowUtc $NowUtc
    if (-not $b.ok) { return (& $res $true $false ([int]$b.status) "$($b.reason)" "$($b.appId)" '' '' $page ([bool]"$($b.appId)")) }
    $hit = @($list | Where-Object { $_.appId -eq "$($b.appId)" })[0]
    if (-not $hit) { return (& $res $true $false 403 'the application is not on the list of allowed applications' "$($b.appId)" '' '' $page $true) }
    $rt = Test-PimManagerAppRouteAllowed -Method $Method -Path $page -Role "$($hit.role)"
    if (-not $rt.allowed) { return (& $res $true $false 403 "$($rt.reason)" "$($hit.appId)" "$($hit.name)" "$($hit.role)" $page $true) }
    return (& $res $true $true 200 'allowed' "$($hit.appId)" "$($hit.name)" "$($hit.role)" $page $true)
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
