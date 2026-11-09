# =================================================================================================
# PIM-SupportConsent.ps1 -- OPEN-01: time-limited support database access driven by INVARDIA'S CONSENT CHANNEL
# (framework "SUPPORT ACCESS" points 1 + 2 -- referenced, not restated; PIM REQUIREMENTS "CONSENT CHANNEL").
#
#   GET <base>/api/support/consent   header x-invardia-install-key
#   -> { environmentId, product, supportConsent: { level: troubleshoot | setup | none, appId? },
#        support: { state: 'open', level, maxUntil, reason, ticketNumber?, openedBy } | { state: 'closed' } }
#
# WHO: the UPDATER (ca-pim-update) reads it on EVERY run -- the nightly one and every 15-minute "update now" check --
# early, cheap, never failing the update. It DECIDES here (Get-PimSupportConsentDecision, PURE) and, when an action is
# due, starts ONE run of the in-network support SQL job (tools/setup/_PimSupportSqlJob.ps1, mode consent: a one-time
# job copied from ca-pim-dbinit, the database job) which does the SQL through the signed procedures and the
# support-session step (engine/_shared/PIM-SupportJit.ps1) and reads it back. NEVER the engine: the heartbeat's
# supportConsent is information only (Test-PimSupportConsent scans the engine's entry points for it).
#
# [!] NO SECURITY STATEMENT IN THIS FILE (Test-PimSqlAccess L2: it is on the update path). The only SQL it sends is the
#    read of the signed state procedure; every right is given or taken by the job, as the database job's identity.
# [!] Consent and session come ONLY from Invardia's answer -- never from a row the engine can write.
# [!] Doubt changes nothing: an unreadable answer (no key, no answer, a bad shape, an open session without a readable end)
#    = NOTHING is opened or closed; an already-ended grant is still closed by the sweep (heartbeat, Manager, every job run).
#
# PS 5.1 + 7 (no ?. / ??, no ternary). ASCII only. Never throws (every caller-facing function).
# =================================================================================================
Set-StrictMode -Off

function Get-PimSupportConsentPath { <# PURE. The consent channel's path (a literal). #> return '/api/support/consent' }
function Get-PimSupportConsentStateSetting { <# PURE. The pim.Settings name the updater records the last decision in (a literal). #> return 'SupportConsentState' }
function Get-PimSupportConsentJobName { <# PURE. The one-time job of a consent run (a literal; never the manual job's caj-pim-supportsql). #> return 'caj-pim-supportconsent' }
function Get-PimSupportConsentMaxHours { <# PURE. The longest an admin access may run after its open (framework point 1, a literal). #> return 8 }
function Get-PimSupportConsentRetryMinutes { <# PURE. A failed action is not started again within this many minutes (a literal). #> return 60 }
function Get-PimSupportConsentLevels { <# PURE. Invardia's consent levels (literals). #> return @('none', 'troubleshoot', 'setup') }
function Get-PimSupportConsentActions { <# PURE. What the updater may decide (literals). #> return @('nothing', 'ensure-read-user', 'remove-user', 'open-admin', 'close-admin') }

function ConvertFrom-PimSupportConsentUtc {
    # PURE. A time from Invardia or from the state procedure -> a UTC [datetime], or $null. ISO 8601 with Z or an offset,
    # with or without fractions; a [datetime] (PowerShell 7's ConvertFrom-Json makes one). Never the local culture.
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $t = "$Value".Trim()
    if ($t -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})$') { return $null }
    $o = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) { return $o.UtcDateTime }
    return $null
}

function Format-PimSupportConsentUtc {
    # PURE. yyyy-MM-ddTHH:mm:ssZ (invariant), '' for $null.
    param([AllowNull()]$Utc)
    if ($null -eq $Utc) { return '' }
    return ([datetime]$Utc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PimSupportConsentLevel {
    # PURE. none | troubleshoot | setup; anything else ''. (The database's v1 words read / owner -> troubleshoot / setup.)
    param([AllowNull()][string]$Level)
    $l = "$Level".Trim().ToLowerInvariant()
    switch ($l) { 'read' { return 'troubleshoot' } 'owner' { return 'setup' } }
    if ($l -in @(Get-PimSupportConsentLevels)) { return $l }
    return ''
}

function ConvertFrom-PimSupportConsentAnswer {
    <#
      PURE. Invardia's answer body -> { ok; consent; appId; session = { state; open; level; maxUntil ([datetime] UTC);
      reason; ticketNumber; openedBy }; environmentId; problem }. ok = $false + problem on ANY doubt: no object, a consent
      level that is not one of the three, an appId that is not an id, a session state that is not open / closed, or an
      OPEN session without a readable maxUntil. A doubtful answer changes nothing (the caller acts only on ok).
    #>
    param([AllowNull()]$Body)
    $o = [ordered]@{ ok = $false; consent = ''; appId = ''; environmentId = ''; session = [ordered]@{ state = ''; open = $false; level = ''; maxUntil = $null; reason = ''; ticketNumber = ''; openedBy = '' }; problem = '' }
    try {
        if ($null -eq $Body -or $Body -is [string] -or $Body -is [array]) { $o.problem = 'the answer is not an object'; return [pscustomobject]$o }
        $sc = $Body.supportConsent
        if ($null -eq $sc) { $o.problem = 'the answer carries no supportConsent'; return [pscustomobject]$o }
        $lv = "$($sc.level)".Trim().ToLowerInvariant()
        if ($lv -notin @(Get-PimSupportConsentLevels)) { $o.problem = "the consent level '$lv' is not none, troubleshoot or setup"; return [pscustomobject]$o }
        $o.consent = $lv
        $aid = "$($sc.appId)".Trim().ToLowerInvariant()
        if ($aid) {
            if ($aid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $aid -eq '00000000-0000-0000-0000-000000000000') { $o.problem = 'the Support app id in the answer is not an application id'; return [pscustomobject]$o }
            $o.appId = $aid
        }
        $o.environmentId = "$($Body.environmentId)".Trim()
        $sp = $Body.support
        $st = if ($null -eq $sp) { 'closed' } else { "$($sp.state)".Trim().ToLowerInvariant() }
        if ($st -notin @('open', 'closed')) { $o.problem = "the support session state '$st' is not open or closed"; return [pscustomobject]$o }
        $o.session.state = $st
        if ($st -eq 'open') {
            $mu = ConvertFrom-PimSupportConsentUtc $sp.maxUntil
            if (-not $mu) { $o.problem = 'the open support session has no readable end (maxUntil)'; return [pscustomobject]$o }
            $o.session.open = $true; $o.session.maxUntil = $mu
            $o.session.level = ConvertTo-PimSupportConsentLevel "$($sp.level)"
            $o.session.reason = (("$($sp.reason)" -replace '[^A-Za-z0-9 ._@:#/()+,-]', ' ') -replace '\s+', ' ').Trim()
            if ($o.session.reason.Length -gt 120) { $o.session.reason = $o.session.reason.Substring(0, 120) }
            $o.session.ticketNumber = (("$($sp.ticketNumber)" -replace '[^A-Za-z0-9._#-]', '')).Trim()
            if ($o.session.ticketNumber.Length -gt 40) { $o.session.ticketNumber = $o.session.ticketNumber.Substring(0, 40) }
            $o.session.openedBy = (("$($sp.openedBy)" -replace '[^A-Za-z0-9 ._@:#/()+,-]', ' ') -replace '\s+', ' ').Trim()
            if ($o.session.openedBy.Length -gt 120) { $o.session.openedBy = $o.session.openedBy.Substring(0, 120) }
        }
        $o.ok = $true
    } catch { $o.ok = $false; $o.problem = "the answer could not be read: $((("$($_.Exception.Message)") -split "`n")[0])" }
    return [pscustomobject]$o
}

function Invoke-PimSupportConsentHttp {
    <# The real seam: one GET, 15 s, @{ status; body; error } -- the update client's signal seam (PIM-InvardiaUpdate.ps1) when loaded. #>
    param([Parameter(Mandatory)][string]$Url, [hashtable]$Headers = @{})
    if (Get-Command Invoke-PimInvardiaSignalHttp -ErrorAction SilentlyContinue) { return (Invoke-PimInvardiaSignalHttp -Url $Url -Headers $Headers) }
    try {
        $r = Invoke-WebRequest -Uri $Url -Method GET -Headers $Headers -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        return @{ status = $code; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}

function Invoke-PimSupportConsentRead {
    <#
      Ask Invardia for this install's consent and support session. Never throws. -Http { param($Url, $Headers) } ->
      @{ status; body; error } (default Invoke-PimSupportConsentHttp: 15 s). ONE retry, only when there was no answer at all
      (status 0) or a gateway answer (502 / 503 / 504), after -RetryDelaySec. No install key = NO call.
      Returns @{ status; attempts; answer (ConvertFrom-PimSupportConsentAnswer); error }. The key is never in any text.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [AllowEmptyString()][AllowNull()][string]$InstallKey = '', [int]$RetryDelaySec = 5, [scriptblock]$Sleep)
    $key = "$InstallKey".Trim()
    # 2026-11-05 (a Community test install): the recorded reason must name the REAL cause (no key / not https), not the
    # empty answer's generic 'the answer is not an object'.
    $no = { param($e) $a0 = ConvertFrom-PimSupportConsentAnswer $null; $a0.problem = $e; @{ status = 0; attempts = 0; answer = $a0; error = $e } }
    if (-not $key) { return (& $no 'no install key -- the consent channel was not asked') }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { 'https://invardia.com' }
    if ($base -notmatch '^(?i)https://') { return (& $no 'the Invardia address is not https -- the consent channel was not asked') }
    $url = "$base$(Get-PimSupportConsentPath)"
    $h = @{ 'x-invardia-install-key' = $key }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $r = $null; $n = 0
    while ($n -lt 2) {
        $n++
        try { if ($Http) { $r = & $Http $url $h } else { $r = Invoke-PimSupportConsentHttp -Url $url -Headers $h } }
        catch { $r = @{ status = 0; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) } }
        $code = 0; try { $code = [int]$r.status } catch { $code = 0 }
        if (-not ($code -eq 0 -or $code -eq 502 -or $code -eq 503 -or $code -eq 504) -or $n -ge 2) { break }
        if ($RetryDelaySec -gt 0) { & $Sleep $RetryDelaySec }
    }
    $code = 0; try { $code = [int]$r.status } catch { $code = 0 }
    $err = ((("$($r.error)") -split "`n")[0]); if ($err.Contains($key)) { $err = 'the request failed' }
    $ans = $null
    if ($code -eq 200) { $ans = ConvertFrom-PimSupportConsentAnswer $r.body }
    else {
        $ans = ConvertFrom-PimSupportConsentAnswer $null
        $ans.problem = $(switch ($code) { 0 { "no answer from Invardia ($err)" } 401 { 'Invardia refused the install key (401)' } 403 { 'Invardia refused the install key (403)' } 404 { 'Invardia has no consent channel for this install (404)' } default { "Invardia answered HTTP $code" } })
    }
    return @{ status = $code; attempts = $n; answer = $ans; error = $err }
}

function ConvertFrom-PimSupportConsentState {
    <#
      PURE. The ONE JSON scalar of [pimsupport].[usp_SupportState] -> { installed; read; consented; appId; userExists;
      readOnly; legacyReader; inOwner; jitOpen; jitUntil; jitOpenedUtc; expiredOpen; problem }. A v1 procedure (not yet
      re-installed) sends no userExists -> $null (the decision then migrates). The same answer Get-PimSupportJitState
      reads -- a small copy here, so this file carries no security SQL (PIM-SupportJit.ps1 holds the install batches).
    #>
    param([AllowNull()]$Raw)
    $o = [ordered]@{ installed = $true; read = $false; consented = ''; appId = ''; userExists = $null; readOnly = $null; legacyReader = $null; inOwner = $null
                     jitOpen = $null; jitUntil = ''; jitOpenedUtc = ''; expiredOpen = 0; problem = '' }
    $t = "$Raw".Trim()
    if (-not $t.StartsWith('{')) { $o.problem = 'the database did not answer the support access state'; return [pscustomobject]$o }
    try { $a = $t | ConvertFrom-Json } catch { $o.problem = 'the support access state is not JSON'; return [pscustomobject]$o }
    $b = { param($n) if ($a.PSObject.Properties[$n]) { ([int]$a.$n -eq 1) } else { $null } }
    $o.read = $true
    $o.consented = ConvertTo-PimSupportConsentLevel "$($a.consented)"; if (-not $o.consented) { $o.consented = "$($a.consented)".Trim().ToLowerInvariant() }
    if ($a.PSObject.Properties['appId']) { $o.appId = "$($a.appId)".Trim().ToLowerInvariant() }
    $o.userExists = & $b 'userExists'; $o.readOnly = & $b 'readOnly'; $o.legacyReader = & $b 'legacyReader'; $o.inOwner = & $b 'inOwner'
    $om = 0; if ($a.PSObject.Properties['openMarkers']) { $om = [int]$a.openMarkers }
    $o.jitOpen = ($om -gt 0)
    if ($a.PSObject.Properties['expiredOpen']) { $o.expiredOpen = [int]$a.expiredOpen }
    if ($o.jitOpen) { $o.jitUntil = Format-PimSupportConsentUtc (ConvertFrom-PimSupportConsentUtc (Join-PimSupportConsentZ $a.jitUntil)) }
    if ($o.jitOpen -and $a.PSObject.Properties['jitOpenedUtc']) { $o.jitOpenedUtc = Format-PimSupportConsentUtc (ConvertFrom-PimSupportConsentUtc (Join-PimSupportConsentZ $a.jitOpenedUtc)) }
    return [pscustomobject]$o
}

function Join-PimSupportConsentZ {
    # PURE. A procedure time ('yyyy-MM-ddTHH:mm:ssZ' text, or a [datetime] from PowerShell 7) as something ConvertFrom-PimSupportConsentUtc reads.
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [datetime]) { return $Value }
    $t = "$Value".Trim(); if ($t -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$') { $t += 'Z' }
    return $t
}

function Get-PimSupportConsentDbState {
    <#
      Read the support access state through the SIGNED read procedure (EXECUTE only; the updater's role pim_updater has
      it from the support-session step; while it is still in the SQL admin group it is dbo). Never throws. A missing
      procedure = installed $false (the step has not run here -- a known state, not a doubt).
    #>
    param([AllowNull()][scriptblock]$Sql)
    if (-not $Sql) { return [pscustomobject]@{ installed = $null; read = $false; problem = 'no database session' } }
    try { return (ConvertFrom-PimSupportConsentState (& $Sql 'EXEC [pimsupport].[usp_SupportState];')) }
    catch {
        $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim()
        if ($m -match '(?i)Could not find stored procedure|Msg 2812|Invalid object name .pimsupport') {
            return [pscustomobject]@{ installed = $false; read = $true; consented = 'none'; appId = ''; userExists = $null; readOnly = $false; legacyReader = $null; inOwner = $null; jitOpen = $false; jitUntil = ''; jitOpenedUtc = ''; expiredOpen = 0; problem = 'time-limited support access is not set up on this install' }
        }
        # 2026-11-04 live proof at internal: an EARLIER (v1) support module grants its state procedure to the engine, not to
        # the updater -> "The EXECUTE permission was denied on the object 'usp_SupportState'". That is a KNOWN state (the module
        # predates this version), not doubt: report it as installed v1 (userExists $null) so the decision maps it to v2 with
        # ensure-read-user (the job installs the current module; never widens, never opens an admin access).
        if ($m -match "(?i)EXECUTE permission was denied on the object 'usp_SupportState'") {
            return [pscustomobject]@{ installed = $true; read = $true; consented = ''; appId = ''; userExists = $null; readOnly = $null; legacyReader = $null; inOwner = $null; jitOpen = $false; jitUntil = ''; jitOpenedUtc = ''; expiredOpen = 0; problem = 'an earlier support access module (its state is not readable by the updater) -- the step installs the current one' }
        }
        return [pscustomobject]@{ installed = $null; read = $false; problem = $m }
    }
}

function Get-PimSupportConsentDecision {
    <#
      PURE. (Invardia's answer, the database's state) -> the ONE action: nothing | ensure-read-user | remove-user |
      open-admin (with untilUtc) | close-admin, and the reason. -Answer: ConvertFrom-PimSupportConsentAnswer (or $null);
      -State: Get-PimSupportConsentDbState; -Last: the previous decision record (pim.Settings SupportConsentState) for the
      retry pause. Rules (framework "SUPPORT ACCESS" points 1 + 2):
        * an unreadable answer -> NOTHING (never close or open on doubt; an ended grant is closed by the sweep)
        * the state not readable -> NOTHING
        * none -> no Support database user at all: remove-user while one is there (or the step is not set up here)
        * troubleshoot -> the standing read-only user only; NEVER an admin access (an open one is closed)
        * setup -> the read-only user, and db_owner ONLY while Invardia's session is open AND its level is setup, ending at
          the earlier of maxUntil and 8 h after the open (an open past maxUntil is closed even if Invardia still says open)
        * a v1 install (read / owner, db_datareader) -> ensure-read-user: the job maps it (read -> troubleshoot, owner ->
          setup), never widened
        * the same action failed less than -RetryMinutes ago -> nothing (said), so a broken install is not hit every 15 min
      Returns [pscustomobject]{ action; consent; appId; untilUtc; session; reason; note }.
    #>
    param([AllowNull()]$Answer, [AllowNull()]$State, [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()]$Last = $null,
          [int]$RetryMinutes = (Get-PimSupportConsentRetryMinutes))
    $now = $NowUtc.ToUniversalTime()
    $d = [ordered]@{ action = 'nothing'; consent = ''; appId = ''; untilUtc = ''; session = ''; reason = ''; note = '' }
    $fin = { return [pscustomobject]$d }
    if (-not $Answer -or -not $Answer.ok) {
        $why = if ($Answer -and "$($Answer.problem)") { "$($Answer.problem)" } else { 'no answer' }
        $d.reason = "Invardia's consent could not be read ($why) -- nothing changes; an ended grant is closed by the sweep"
        return (& $fin)
    }
    $d.consent = "$($Answer.consent)"
    $sess = $Answer.session
    $d.session = if ($sess -and $sess.open) { "open until $(Format-PimSupportConsentUtc $sess.maxUntil)$(if ($sess.level) { " ($($sess.level))" })" } else { 'closed' }
    if (-not $State -or (-not $State.read -and $State.installed -ne $false)) {
        $d.reason = "the support access state could not be read ($(if ($State) { "$($State.problem)" } else { 'no state' })) -- nothing changes"
        return (& $fin)
    }
    $installed = ($State.installed -ne $false)
    $v2 = ($installed -and $null -ne $State.userExists)
    $d.appId = if ("$($Answer.appId)") { "$($Answer.appId)" } elseif ("$($State.appId)") { "$($State.appId)" } else { '' }
    if ($installed -and $State.inOwner -and -not $State.jitOpen) { $d.note = 'the Support user holds db_owner outside any support session (not given by a grant) -- not taken here; the OPEN-01 step removes the standing access' }

    if ($d.consent -eq 'none') {
        if ($installed -and $v2 -and $State.userExists -eq $false -and -not $State.jitOpen) { $d.reason = 'consent none: no Support database user -- as agreed'; return (& $fin) }
        if (-not $d.appId) { $d.reason = 'consent none, and no Support app is known (neither Invardia''s answer nor the database names one) -- nothing to remove'; return (& $fin) }
        $d.action = 'remove-user'
        $d.reason = $(if (-not $installed) { 'consent none: the support access is not set up here -- the step runs with none (no Support database user)' } elseif ($State.jitOpen) { 'consent none: an admin access is open -- every grant closed and the Support user removed' } else { 'consent none: the Support database user is there -- removed' })
    } else {
        if (-not $d.appId) { $d.reason = "consent $($d.consent), but Invardia's answer names no Support app and the database knows none -- nothing changes"; return (& $fin) }
        $open = [bool]($sess -and $sess.open -and $sess.maxUntil -and ([datetime]$sess.maxUntil) -gt $now)
        $sessLevel = if ($sess -and "$($sess.level)") { "$($sess.level)" } else { 'troubleshoot' }   # a session without a level gives no admin
        $admin = ($open -and $d.consent -eq 'setup' -and $sessLevel -eq 'setup')
        # 2026-11-04 live proof: an EARLIER (v1) module is first brought to the current one (ensure-read-user); an admin access
        # is opened only on the current module, on the next run -- never through the old procedures.
        if ($admin -and $installed -and -not $v2 -and -not $State.jitOpen) {
            $d.action = 'ensure-read-user'
            $d.reason = "consent setup and an open support session, but this install runs an earlier support access module -- the current one is installed first (read-only user); the admin access opens on the next run"
            return (Test-PimSupportConsentRetry -Decision $d -Last $Last -NowUtc $now -RetryMinutes $RetryMinutes)
        }
        if ($admin) {
            $cap = $now.AddHours((Get-PimSupportConsentMaxHours))
            $openedAt = ConvertFrom-PimSupportConsentUtc "$($State.jitOpenedUtc)"
            if ($State.jitOpen -and $openedAt) { $cap = $openedAt.AddHours((Get-PimSupportConsentMaxHours)) }     # 8 h from the OPEN, also when extended
            $until = [datetime]$sess.maxUntil; if ($until -gt $cap) { $until = $cap }
            if ($until -le $now) {
                # the 8 hours from the open are used up while Invardia's session runs on: closed, never longer
                if ($State.jitOpen) { $d.action = 'close-admin'; $d.reason = "the admin access reached $(Get-PimSupportConsentMaxHours) h after its open -- closed (never longer)" }
                else { $d.reason = 'the admin access reached its cap' }
                return (Test-PimSupportConsentRetry -Decision $d -Last $Last -NowUtc $now -RetryMinutes $RetryMinutes)
            }
            $d.untilUtc = Format-PimSupportConsentUtc $until
            $cur = ConvertFrom-PimSupportConsentUtc "$($State.jitUntil)"
            if ($State.jitOpen -and $State.inOwner -and $cur) {
                if ($cur -gt $until.AddSeconds(60)) { $d.action = 'close-admin'; $d.reason = "Invardia's session now ends at $($d.untilUtc), before the open grant ($(Format-PimSupportConsentUtc $cur)) -- closed; the next run opens it to the new end" }
                elseif ($cur -lt $until.AddSeconds(-60)) { $d.action = 'open-admin'; $d.reason = "Invardia's session runs to $($d.untilUtc) -- the open grant (to $(Format-PimSupportConsentUtc $cur)) is extended, at most $(Get-PimSupportConsentMaxHours) h after its open" }
                else { $d.reason = "consent setup, support session open: admin until $(Format-PimSupportConsentUtc $cur) as Invardia's session says" }
            } else {
                $d.action = 'open-admin'
                $d.reason = "consent setup and an open support session$(if ($sess.ticketNumber) { " (ticket $($sess.ticketNumber))" }): db_owner until $($d.untilUtc)"
            }
        } else {
            $why = if (-not ($sess -and $sess.open)) { 'the support session is closed' } elseif (-not $open) { "the support session ended at $(Format-PimSupportConsentUtc $sess.maxUntil)" } elseif ($d.consent -ne 'setup') { "consent $($d.consent) never gives an admin access" } else { "the session's level is $sessLevel" }
            if ($State.jitOpen) { $d.action = 'close-admin'; $d.reason = "$why -- the open admin access is closed" }
            elseif (-not $installed -or -not $v2 -or -not $State.readOnly -or $State.legacyReader -or "$($State.consented)" -ne $d.consent) {
                $d.action = 'ensure-read-user'
                $d.reason = $(if (-not $installed) { "consent $($d.consent): the support access is not set up here -- the step runs (the standing read-only user)" }
                              elseif (-not $v2) { "consent $($d.consent): this install is on the v1 support access (read / owner, db_datareader) -- mapped to v2, never widened" }
                              elseif (-not $State.readOnly) { "consent $($d.consent): the standing read-only user is missing" }
                              elseif ($State.legacyReader) { "consent $($d.consent): the Support user is still in db_datareader (v1) -- narrowed to pim_support_read" }
                              else { "consent $($d.consent): the database records '$($State.consented)' -- Invardia's level is recorded" })
            } else { $d.reason = "consent $($d.consent): the standing read-only user is in place; $why" }
        }
    }
    return (Test-PimSupportConsentRetry -Decision $d -Last $Last -NowUtc $now -RetryMinutes $RetryMinutes)
}

function Test-PimSupportConsentRetry {
    # PURE. The same action that FAILED less than -RetryMinutes ago is not started again (said in the reason).
    param([Parameter(Mandatory)]$Decision, [AllowNull()]$Last, [datetime]$NowUtc, [int]$RetryMinutes)
    $d = $Decision
    # merge review 2026-11-04: TAKING ACCESS AWAY is never paused -- a failed close-admin / remove-user is tried again on the
    # very next run, so an ended session's db_owner never outlives it by the retry pause. Only giving access backs off.
    if ("$($d.action)" -in @('close-admin', 'remove-user')) { return [pscustomobject]$d }
    if ("$($d.action)" -ne 'nothing' -and $Last -and "$($Last.action)" -eq "$($d.action)" -and "$($Last.result)" -eq 'failed') {
        $at = ConvertFrom-PimSupportConsentUtc "$($Last.atUtc)"
        if ($at -and $NowUtc -lt $at.AddMinutes($RetryMinutes)) {
            $d.reason = "$($d.reason) -- NOT started again yet: the same action failed at $(Format-PimSupportConsentUtc $at) ($("$($Last.detail)".Trim())); next try after $(Format-PimSupportConsentUtc $at.AddMinutes($RetryMinutes))"
            $d.action = 'nothing'
        }
    }
    return [pscustomobject]$d
}

function Invoke-PimSupportConsentStep {
    <#
      The updater's step, on EVERY run. NEVER throws, never fails the update. Seams:
        -Http      { param($Url, $Headers) } -> @{ status; body; error }   (default: the 15 s GET)
        -Sql       { param($Query) } ONE scalar from the PIM database as the updater ($null = no store)
        -StartJob  { param($Decision, $Answer) } -> @{ ok; status; problems[] }: ONE run of the support SQL job with that
                   action, waited for (the updater builds it from tools/setup/_PimSupportSqlJob.ps1, mode consent)
        -GetLast / -SetLast  the previous record / record this one (pim.Settings SupportConsentState) -- for the heartbeat
      Returns { ok; action; started; jobOk; line; record; answer; appId }. ok = $false only when a due action could not be applied.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [AllowEmptyString()][AllowNull()][string]$InstallKey = '', [AllowNull()][scriptblock]$Sql,
          [AllowNull()][scriptblock]$StartJob, [AllowNull()][scriptblock]$GetLast, [AllowNull()][scriptblock]$SetLast,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$RetryDelaySec = 5, [scriptblock]$Sleep)
    # SUPPORT-SQL-JIT-1: answer + appId are handed on to the updater's SQL admin group step (PIM-SupportSqlGroupJit.ps1), and
    # the record carries that step's last record (sqlGroup) forward unchanged -- this step never reads or changes it.
    $out = [ordered]@{ ok = $true; action = 'nothing'; started = $false; jobOk = $null; line = ''; record = $null; answer = $null; appId = '' }
    try {
        $last = $null; if ($GetLast) { try { $last = & $GetLast; if ($last -is [string] -and "$last".Trim().StartsWith('{')) { $last = "$last" | ConvertFrom-Json } } catch { $last = $null } }
        $rd = Invoke-PimSupportConsentRead -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -RetryDelaySec $RetryDelaySec -Sleep $Sleep
        $st = Get-PimSupportConsentDbState -Sql $Sql
        $dec = Get-PimSupportConsentDecision -Answer $rd.answer -State $st -NowUtc $NowUtc -Last $last
        $out.answer = $rd.answer; $out.appId = "$($dec.appId)"
        $out.action = "$($dec.action)"
        $res = 'ok'; $detail = ''
        $after = $st
        if ($dec.action -ne 'nothing') {
            if (-not $StartJob) { $res = 'failed'; $detail = 'no way to start the support SQL job in this run' }
            else {
                $out.started = $true
                $j = $null
                try { $j = & $StartJob $dec $rd.answer } catch { $j = @{ ok = $false; status = ''; problems = @("the job could not be started: $((("$($_.Exception.Message)") -split "`n")[0])") } }
                $out.jobOk = [bool]($j -and $j.ok)
                if ($j -and $j.skipped) {
                    # another updater execution is applying it right now (its one-time job is there): left to it, not a failure
                    $out.started = $false; $out.jobOk = $null; $res = 'skipped'; $detail = "not started: $($j.reason)"
                }
                elseif (-not $out.jobOk) { $res = 'failed'; $detail = (@(@($j.problems) | Where-Object { "$_" }) -join '; '); if (-not $detail) { $detail = "the job ended '$($j.status)'" } }
                # READ BACK: the state as the job left it
                $after = Get-PimSupportConsentDbState -Sql $Sql
                if ($out.jobOk -and $after.read) {
                    $miss = switch ($dec.action) {
                        'ensure-read-user' { if (-not $after.readOnly) { 'the read-only user is not there' } }
                        'remove-user'      { if ($after.userExists -ne $false) { 'the Support user is still there' } }
                        'open-admin'       { if (-not ($after.inOwner -and $after.jitOpen)) { 'no open admin access' } }
                        'close-admin'      { if ($after.jitOpen) { 'an admin access is still open' } }
                    }
                    if ($miss) { $res = 'failed'; $detail = "read back: $miss" }
                } elseif ($out.jobOk) { $detail = "the job read it back; the updater could not ($($after.problem))" }
            }
        }
        $out.ok = ($res -ne 'failed')
        $stateText = if ($after -and $after.read) { "read-only $(if ($after.readOnly) { 'yes' } else { 'no' }), admin $(if ($after.jitOpen) { "open until $($after.jitUntil)" } else { 'closed' })" } else { 'state not read' }
        $out.line = "support consent: $(if ($rd.answer.ok) { "Invardia says $($rd.answer.consent), session $($dec.session)" } else { 'Invardia not read' }) -> $($dec.action)$(if ($dec.action -ne 'nothing') { " ($res)" }) -- $($dec.reason)$(if ($detail) { " -- $detail" }); $stateText$(if ($dec.note) { " -- NOTE: $($dec.note)" })"
        $out.record = [pscustomobject][ordered]@{
            atUtc = (Format-PimSupportConsentUtc $NowUtc); action = "$($dec.action)"; result = $res; detail = $detail; reason = "$($dec.reason)"
            consent = "$($dec.consent)"; session = "$($dec.session)"; untilUtc = "$($dec.untilUtc)"; invardiaStatus = [int]$rd.status
            readOnly = $(if ($after -and $after.read) { $after.readOnly } else { $null }); jitOpen = $(if ($after -and $after.read) { $after.jitOpen } else { $null }); jitUntil = $(if ($after -and $after.read) { "$($after.jitUntil)" } else { '' })
        }
        $sgPrev = $null
        if ($last -is [System.Collections.IDictionary]) { if ($last.Contains('sqlGroup')) { $sgPrev = $last['sqlGroup'] } }
        elseif ($last -and $last -isnot [string] -and $last.PSObject.Properties['sqlGroup']) { $sgPrev = $last.sqlGroup }
        if ($null -ne $sgPrev) { $out.record | Add-Member -NotePropertyName 'sqlGroup' -NotePropertyValue $sgPrev -Force }
        if ($SetLast) { try { & $SetLast $out.record } catch { $out.line += " (not recorded: $((("$($_.Exception.Message)") -split "`n")[0]))" } }
    } catch {
        $out.ok = $false
        $out.line = "support consent: the check stopped ($((("$($_.Exception.Message)") -split "`n")[0])) -- nothing changes; the update continues"
    }
    return [pscustomobject]$out
}

function Invoke-PimSupportConsentJob {
    <#
      ONE run of the in-network support SQL job for a decision (mode consent), waited for. Never throws. Needs the job
      builder loaded by the caller (tools/setup/_PimSupportSqlJob.ps1: Invoke-PimSupportSqlJobGrant) -- this file loads
      nothing that carries SQL. -Arm { param($Method, $Path, $Body) } (the path carries its api-version; throws "HTTP <code>").
      A consent job of the same name created less than -BusyMinutes ago = another updater execution is applying it ->
      @{ skipped = $true } (never removed under it). Returns @{ ok; skipped; reason; status; problems[] }.
    #>
    param([Parameter(Mandatory)]$Decision, [AllowNull()]$Answer, [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [string]$TemplateJobName = 'ca-pim-dbinit', [int]$BusyMinutes = 30, [int]$TimeoutSeconds = 600,
          [int]$PollSeconds = 10, [scriptblock]$Sleep, [datetime]$NowUtc = [datetime]::UtcNow)
    $jn = Get-PimSupportConsentJobName
    try {
        if (-not (Get-Command Invoke-PimSupportSqlJobGrant -ErrorAction SilentlyContinue)) { return @{ ok = $false; skipped = $false; reason = ''; status = ''; problems = @('the support SQL job builder is not loaded') } }
        $old = $null
        try { $old = & $Arm 'GET' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/${jn}?api-version=2024-03-01" $null }
        catch { if ("$($_.Exception.Message)" -notmatch '(?i)HTTP 404\b|ResourceNotFound|NotFound') { return @{ ok = $false; skipped = $false; reason = ''; status = ''; problems = @("could not read whether the job $jn is there: $((("$($_.Exception.Message)") -split "`n")[0])") } } }
        if ($old) {
            $made = $null; try { $made = ConvertFrom-PimSupportConsentUtc $old.systemData.createdAt } catch { $made = $null }
            if (-not $made -or $made -gt $NowUtc.ToUniversalTime().AddMinutes(-$BusyMinutes)) {
                return @{ ok = $true; skipped = $true; reason = "the job $jn is there$(if ($made) { " (made $(Format-PimSupportConsentUtc $made))" }) -- another updater run is applying the consent"; status = ''; problems = @() }
            }
        }
        # CONSENT-AFTER-CONVERGE (seen live 2026-11-05): the consent step runs at the TOP of every updater run, the database job
        # it copies is created by the converge later in the run (OPEN-06). On the first run after an upgrade that job is not
        # there YET: NOT READY -- nothing started, skipped (never 'failed', so no retry pause); the next run applies it. Only a
        # confirmed 404 is 'not ready'; any other read error goes on to the builder, which reports it as before.
        $tplMissing = $false
        try { [void](& $Arm 'GET' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/${TemplateJobName}?api-version=2024-03-01" $null) }
        catch { if ("$($_.Exception.Message)" -match '(?i)HTTP 404\b|ResourceNotFound|NotFound') { $tplMissing = $true } }
        if ($tplMissing) {
            return @{ ok = $true; skipped = $true; notReady = $true; reason = "not ready yet: this installation has no job '$TemplateJobName' yet -- the updater's full run creates it (OPEN-06), and the next run after that applies the consent"; status = ''; problems = @() }
        }
        $sess = if ($Answer) { $Answer.session } else { $null }
        $by = if ($sess -and "$($sess.openedBy)") { "Invardia: $($sess.openedBy)" } else { 'Invardia consent channel' }
        $a = @{ Arm = $Arm; Graph = $null; Logs = $null; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; SupportAppId = "$($Decision.appId)"
                TemplateJobName = $TemplateJobName; JobName = $jn; Mode = 'consent'; ConsentAction = "$($Decision.action)"; ConsentLevel = "$($Decision.consent)"
                UntilUtc = "$($Decision.untilUtc)"; Reason = $(if ($sess) { "$($sess.reason)" } else { '' }); TicketNumber = $(if ($sess) { "$($sess.ticketNumber)" } else { '' }); OpenedBy = $by
                TimeoutSeconds = $TimeoutSeconds; PollSeconds = $PollSeconds; LogWaitSeconds = 0; NowUtc = $NowUtc }
        if ($Sleep) { $a['Sleep'] = $Sleep }
        $r = Invoke-PimSupportSqlJobGrant @a
        return @{ ok = [bool]$r.ok; skipped = $false; reason = ''; status = "$($r.status)"; problems = @(@($r.problems) | ForEach-Object { (("$_" -split "`n")[0]).Trim() }) }
    } catch { return @{ ok = $false; skipped = $false; reason = ''; status = ''; problems = @("the support SQL job stopped: $((("$($_.Exception.Message)") -split "`n")[0])") } }
}
