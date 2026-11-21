#Requires -Version 5.1
<#
.SYNOPSIS
    FIRST-SUPERADMIN-1 (Invardia approved design 2026-11-20) -- the FIRST SuperAdmin of a PRIVATE-SQL first install, without
    anything about that person on the database job's definition or its start body (framework SEC-08 point 8).

.DESCRIPTION
    THE FLOW
      1. The INSTALLER (a deploy) writes ONE Key Vault secret 'pim-first-superadmin' in the install's OWN vault, through ARM
         (the control plane: it works on a private vault with no data-plane route from the installer's host). The value is
         JSON { objectId, userPrincipalName, tenantId, issuedUtc, expiresUtc = issued + 48 h, nonce }, content type
         'pim-first-superadmin-v1'. The object id is the INSTALLING person's own oid, read from the installer's OWN sign-in
         token -- never a parameter. An application sign-in has no person: nothing is written (said). The installer then
         grants the database job's identity Key Vault Secrets Officer on THAT ONE SECRET (secret scope), read back.
      2. The DATABASE JOB (first run, empty start body) reads the secret, checks it (content type, its own tenant, not
         expired, the lifetime not stretched, the oid a GUID, a sign-in name), seeds pim.Settings ManagerAccess with
         { identity, objectId, role SuperAdmin, seededBy 'first-install', seededUtc } ONLY when ManagerAccess holds no
         SuperAdmin (never overwrites), DELETES the secret and reads back 404, and records pim.Settings FirstAdminSeed
         { state, atUtc, objectId, reason, grant }.
      3. After the delete the job identity's Secrets Officer on the secret is REMOVED and read back -- by the job when its
         identity may, else by the installer after the run, else by the UPDATER on its next run (Invoke-PimFirstAdminGrantTrim).
      4. RECOVERY: refused / expired before the job ran -> a re-run of the installer by the SAME installing person writes a
         FRESH secret (new nonce, new 48 h) and the grant again. A DIFFERENT person writes nothing (said).
      5. The Manager matches a seeded entry on the token's oid ONLY (Test-PimAccessEntryRequiresObjectId); with no
         SuperAdmin nobody gets a role by signing in first.
      6. The heartbeat's soft key FirstAdminSeed { state, atUtc } (Get-PimFirstAdminHeartbeatField).

    STATES: used | used-not-deleted (the delete was refused) | refused (expired / wrong tenant / malformed / a SuperAdmin
    exists already: NOT seeded, secret deleted, reason) | pending (no SuperAdmin yet) | none (no seed was ever asked).

    PURE first, then the thin steps with seams: -Arm param($Method, $Path, $Body) (the path carries its api-version; a 404
    THROWS "... HTTP 404 ..." or answers $null), -KvGet / -KvDelete param($Name) -> @{ status; body }. No module, no az.
    ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimFirstAdminSecretName { <# PURE. LITERAL. #> return 'pim-first-superadmin' }
function Get-PimFirstAdminContentType { <# PURE. LITERAL. #> return 'pim-first-superadmin-v1' }
function Get-PimFirstAdminSettingName { <# PURE. LITERAL. The pim.Settings row the job records its answer in. #> return 'FirstAdminSeed' }
function Get-PimFirstAdminLifetimeHours { <# PURE. LITERAL. #> return 48 }
function Get-PimFirstAdminIssuerTag { <# PURE. LITERAL. The VAULT tag naming who the first secret was written for (an object id, no secret). #> return 'pim-first-superadmin-issuer' }
function Get-PimFirstAdminExpiresTag { <# PURE. LITERAL. The SECRET tag carrying its expiry (readable through ARM, which never returns a value). #> return 'pim-first-superadmin-expires' }
function Get-PimFirstAdminSecretsOfficerRoleId { <# PURE. LITERAL. Azure built-in role Key Vault Secrets Officer. #> return 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' }
function Get-PimFirstAdminVaultEnvName { <# PURE. LITERAL. The database job setting naming the install's own vault (a resource id; nothing about a person). #> return 'PIM_KeyVaultId' }
function Get-PimFirstAdminSeedStates { <# PURE. LITERAL. #> return @('used', 'used-not-deleted', 'refused', 'pending', 'none') }
function Get-PimFirstAdminSeededBy { <# PURE. LITERAL. #> return 'first-install' }
function Get-PimFirstAdminKvArmApi { <# PURE. LITERAL. #> return '2023-07-01' }
function Get-PimFirstAdminAuthzApi { <# PURE. LITERAL. #> return '2022-04-01' }

function Test-PimFirstAdminGuid {
    param([AllowNull()][object]$Value)
    return ("$Value".Trim() -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
}

function Get-PimFirstAdminField {
    # One field of a dictionary or an object; $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimFirstAdminUtcText {
    param([Parameter(Mandatory)][datetime]$Utc)
    return $Utc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-PimFirstAdminUtcText {
    # PURE. An ISO-8601 UTC text (or a [datetime]) -> [datetime] UTC, or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function ConvertFrom-PimFirstAdminJwtPayload {
    # PURE. The claims of the token the installer's OWN sign-in just issued to this process (Entra ID signed it for this
    # process's own request) -> object, or $null.
    param([AllowEmptyString()][string]$Token)
    $parts = "$Token".Trim() -split '\.'
    if ($parts.Count -lt 2 -or -not "$($parts[1])".Trim()) { return $null }
    $seg = "$($parts[1])".Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
    try { return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json) } catch { return $null }
}

function Get-PimFirstAdminInstaller {
    <#
      PURE. WHO is installing, from the installer's OWN sign-in token (the ARM token its sign-in issued): the oid, the sign-in
      name and the tenant. An APPLICATION token (idtyp app, or no person's sign-in name) has no person -> ok = $false: the
      first SuperAdmin is never an application and never a name typed on a command line. -TenantId: the install's tenant
      (a token from another tenant is refused). Returns @{ ok; objectId; userPrincipalName; tenantId; reason }.
    #>
    param([AllowEmptyString()][string]$Token, [AllowEmptyString()][string]$TenantId = '')
    $no = { param($why) return @{ ok = $false; objectId = ''; userPrincipalName = ''; tenantId = ''; reason = $why } }
    $p = ConvertFrom-PimFirstAdminJwtPayload -Token $Token
    if ($null -eq $p) { return (& $no 'the installer''s sign-in token could not be read -- no first SuperAdmin is written') }
    $upn = ''
    foreach ($c in @('upn', 'preferred_username', 'unique_name')) { $v = "$(Get-PimFirstAdminField $p $c)".Trim(); if ($v) { $upn = $v; break } }
    $idtyp = "$(Get-PimFirstAdminField $p 'idtyp')".Trim()
    if ($idtyp -ieq 'app' -or -not $upn -or $upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        # FIRST-SUPERADMIN-1 (Support-app install, Invardia 2026-11-20): an APPLICATION has no person -- it is never the first
        # SuperAdmin. Which application (appid / azp) and whether its token is for THIS tenant are kept for
        # Get-PimFirstAdminSubject (the Invardia Support app may NAME the customer's administrator; resolved in the directory).
        $r = & $no 'the installer signed in as an application, not a person -- no first SuperAdmin is written (a person runs the installer, or a SuperAdmin adds one in PIM Manager > Settings > Manager access & roles)'
        $aid = ''; foreach ($c in @('appid', 'azp')) { $v = "$(Get-PimFirstAdminField $p $c)".Trim(); if (Test-PimFirstAdminGuid $v) { $aid = $v.ToLowerInvariant(); break } }
        $atid = "$(Get-PimFirstAdminField $p 'tid')".Trim()
        $r['isApplication'] = $true; $r['appId'] = $aid
        $r['tenantMatches'] = [bool]((Test-PimFirstAdminGuid $atid) -and (-not "$TenantId".Trim() -or $atid -ieq "$TenantId".Trim()))
        return $r
    }
    $oid = "$(Get-PimFirstAdminField $p 'oid')".Trim()
    if (-not (Test-PimFirstAdminGuid $oid)) { return (& $no 'the installer''s sign-in token carries no object id -- no first SuperAdmin is written') }
    $tid = "$(Get-PimFirstAdminField $p 'tid')".Trim()
    if ("$TenantId".Trim() -and $tid -and $tid -ine "$TenantId".Trim()) { return (& $no "the installer is signed in to another tenant ($tid) -- no first SuperAdmin is written") }
    if (-not (Test-PimFirstAdminGuid $tid)) { $tid = "$TenantId".Trim() }
    return @{ ok = $true; objectId = $oid.ToLowerInvariant(); userPrincipalName = $upn; tenantId = "$tid".ToLowerInvariant(); reason = "the installing person $upn" }
}

function ConvertTo-PimFirstAdminAuditText {
    # PURE. A reason for the audit: control characters out, spaces collapsed, at most 200 characters.
    param([AllowNull()][object]$Text)
    $t = ("$Text" -replace '[\x00-\x1f\x7f]', ' ' -replace '\s+', ' ').Trim()
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200).Trim() }
    return $t
}

function Get-PimFirstAdminNamedBy {
    <#
      PURE. FIRST-SUPERADMIN-1 (Support-app install, Invardia 2026-11-20): WHO named the first SuperAdmin of an application
      install -- the Invardia Support app (its app id) with the reason / ticket its session carries (Connect-InvardiaSupport
      -Reason / -Ticket). -State = the Support session ($global:InvardiaSupportState: AppId, Reason, Ticket). Returns
      [ordered]@{ kind = 'support-app'; appId; reason; ticket } or $null (no Support session = nobody may name a person).
    #>
    param([AllowNull()][object]$State)
    if ($null -eq $State) { return $null }
    $app = "$(Get-PimFirstAdminField $State 'AppId')".Trim()
    if (-not (Test-PimFirstAdminGuid $app)) { return $null }
    $tk = "$(Get-PimFirstAdminField $State 'Ticket')".Trim(); if ($tk -notmatch '^[A-Za-z0-9#-]{1,40}$') { $tk = '' }
    $why = ConvertTo-PimFirstAdminAuditText (Get-PimFirstAdminField $State 'Reason')
    if (-not $why -and $tk) { $why = "Ticket $tk" }
    if (-not $why) { $why = 'no reason given' }
    return [ordered]@{ kind = 'support-app'; appId = $app.ToLowerInvariant(); reason = $why; ticket = $tk }
}

function Test-PimFirstAdminNamedBy {
    # PURE. Is -Value exactly the agreed namedBy shape (the job's check of the secret)?
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [array]) { return $false }
    $have = @(if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties | ForEach-Object { $_.Name }) })
    $want = @('kind', 'appId', 'reason', 'ticket')
    if (@($have | Where-Object { $want -cnotcontains $_ }).Count -or @($want | Where-Object { $have -cnotcontains $_ }).Count) { return $false }
    if ("$(Get-PimFirstAdminField $Value 'kind')" -cne 'support-app') { return $false }
    if (-not (Test-PimFirstAdminGuid (Get-PimFirstAdminField $Value 'appId'))) { return $false }
    $r = "$(Get-PimFirstAdminField $Value 'reason')"
    if (-not $r.Trim() -or $r.Length -gt 200 -or $r -match '[\x00-\x1f\x7f]') { return $false }
    $t = "$(Get-PimFirstAdminField $Value 'ticket')"
    if ($t -and $t -notmatch '^[A-Za-z0-9#-]{1,40}$') { return $false }
    return $true
}

function Get-PimFirstAdminNamedLookupPath {
    <# PURE. The ONE directory read of the named administrator (a lookup KEY, never the binding): Graph v1.0, relative. #>
    param([Parameter(Mandatory)][string]$Upn)
    return ('/users/' + [uri]::EscapeDataString("$Upn".Trim()) + '?$select=id,userType,accountEnabled,userPrincipalName')
}

function Resolve-PimFirstAdminNamedPerson {
    <#
      FIRST-SUPERADMIN-1 (Support-app install): the administrator the CUSTOMER named (-Upn, a lookup KEY from the order /
      portal request / the install's admin contact) resolved in the customer's OWN tenant through -Graph param($Method, $Path,
      $Body) (Graph v1.0; a 404 THROWS "... HTTP 404 ..." or answers $null). REQUIRED: a sign-in name (never an object id
      typed in), userType Member, accountEnabled true, the directory's own sign-in name equal to the key. Anything else =
      nobody (ok = $false, code + reason). Never throws.
      Returns @{ ok; code; objectId; userPrincipalName; tenantId; reason; namedBy; named }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$Upn = '', [AllowEmptyString()][string]$TenantId = '',
          [AllowNull()][object]$NamedBy = $null)
    $k = "$Upn".Trim()
    $no = { param($code, $why) return @{ ok = $false; code = $code; objectId = ''; userPrincipalName = ''; tenantId = ''; reason = $why; namedBy = $NamedBy; named = $k } }
    if (-not $k) { return (& $no 'none' 'no administrator was named for this install') }
    if ($k -notmatch '^[^@\s;,''/\\?#]+@[^@\s;,''/\\?#]+\.[^@\s;,''/\\?#]+$') { return (& $no 'bad-name' "'$k' is not a sign-in name (user@domain) -- the named administrator is looked up by sign-in name only") }
    if (-not (Test-PimFirstAdminGuid $TenantId)) { return (& $no 'no-tenant' 'the install''s tenant is not known -- the named administrator cannot be looked up') }
    $u = $null
    try { $u = & $Graph 'GET' (Get-PimFirstAdminNamedLookupPath -Upn $k) $null }
    catch {
        if (Test-PimFirstAdminNotFound $_) { return (& $no 'not-found' "the named administrator $k is not an account of this tenant") }
        return (& $no 'lookup-failed' "the named administrator $k could not be looked up in the directory ($((("$($_.Exception.Message)") -split "`n")[0]))")
    }
    if ($null -eq $u) { return (& $no 'not-found' "the named administrator $k is not an account of this tenant") }
    $id = "$(Get-PimFirstAdminField $u 'id')".Trim()
    $type = "$(Get-PimFirstAdminField $u 'userType')".Trim()
    $en = Get-PimFirstAdminField $u 'accountEnabled'
    $got = "$(Get-PimFirstAdminField $u 'userPrincipalName')".Trim()
    if (-not (Test-PimFirstAdminGuid $id)) { return (& $no 'lookup-failed' "the directory answered no object id for $k") }
    if ($got -ine $k) { return (& $no 'mismatch' "the directory answered another account ($got) for $k") }
    if ($type -cne 'Member') { return (& $no 'not-member' "the named administrator $k is $(if ($type) { "a $type account" } else { 'an account of unknown type' }), not a member of this tenant") }
    if (-not ($en -is [bool] -and $en)) { return (& $no 'disabled' "the named administrator $k is a disabled account") }
    return @{ ok = $true; code = ''; objectId = $id.ToLowerInvariant(); userPrincipalName = $got; tenantId = "$TenantId".Trim().ToLowerInvariant()
              reason = "the administrator the customer named, $got (a member account of this tenant, enabled), bound to its object id"; namedBy = $NamedBy; named = $k }
}

function Get-PimFirstAdminSubject {
    <#
      PURE. WHO becomes the first SuperAdmin of this install (the subject of the one-time hand-over).
        -Installer  Get-PimFirstAdminInstaller (the installer's OWN token)
        -NamedUpn   the named administrator (Install -FirstSuperAdminUpn; a lookup key)
        -Named      Resolve-PimFirstAdminNamedPerson's answer for it ($null = not looked up)
        -NamedBy    Get-PimFirstAdminNamedBy (the Invardia Support session; $null = none)
      A PERSON installs -> that person (a named one is NOT used: said). An APPLICATION -> ONLY a person the Invardia Support
      app named (its session, and the token IS that session's app, for this tenant), resolved as a Member + enabled account;
      anything else = NOBODY, said plainly. Never "first sign-in wins", never the typed name as the binding.
      Returns @{ ok; objectId; userPrincipalName; tenantId; reason; namedBy; notes }.
    #>
    param([Parameter(Mandatory)][object]$Installer, [AllowEmptyString()][string]$NamedUpn = '', [AllowNull()][object]$Named = $null,
          [AllowNull()][object]$NamedBy = $null)
    $k = "$NamedUpn".Trim()
    $nobodyTail = ' -- NOBODY is seeded, and nobody can administer this install until a first SuperAdmin exists: the customer''s administrator runs the installer themselves (their own sign-in becomes the first SuperAdmin), or the Invardia Support app runs it again naming them (-FirstSuperAdminUpn)'
    $no = { param($why) return @{ ok = $false; objectId = ''; userPrincipalName = ''; tenantId = ''; reason = $why; namedBy = $null; notes = @() } }
    if ([bool](Get-PimFirstAdminField $Installer 'ok')) {
        $r = @{} + $Installer
        if (-not $r.ContainsKey('namedBy')) { $r['namedBy'] = $null }
        $r['notes'] = @(if ($k -and $k -ine "$(Get-PimFirstAdminField $Installer 'userPrincipalName')") { "the named administrator $k is NOT seeded: a person runs this install, so that person is the first SuperAdmin (they add others in PIM Manager > Settings > Manager access & roles)" })
        return $r
    }
    if (-not [bool](Get-PimFirstAdminField $Installer 'isApplication')) { return (& $no "$(Get-PimFirstAdminField $Installer 'reason')") }
    if (-not $k) { return (& $no ("the installation runs as an application and no administrator was named" + $nobodyTail)) }
    if ($null -eq $NamedBy -or -not (Test-PimFirstAdminNamedBy $NamedBy)) { return (& $no ("the installation runs as an application that is not an Invardia Support session, so the named administrator $k is not used" + $nobodyTail)) }
    if ("$(Get-PimFirstAdminField $Installer 'appId')" -ine "$(Get-PimFirstAdminField $NamedBy 'appId')") { return (& $no ("the installer's sign-in is not the Invardia Support app of this session, so the named administrator $k is not used" + $nobodyTail)) }
    if (-not [bool](Get-PimFirstAdminField $Installer 'tenantMatches')) { return (& $no ("the Invardia Support app is signed in to another tenant, so the named administrator $k is not used" + $nobodyTail)) }
    if ($null -eq $Named) { return (& $no ("the named administrator $k was not looked up in the directory" + $nobodyTail)) }
    if (-not [bool](Get-PimFirstAdminField $Named 'ok')) { return (& $no ("$(Get-PimFirstAdminField $Named 'reason')" + $nobodyTail)) }
    if ("$(Get-PimFirstAdminField $Named 'named')".Trim() -ine $k) { return (& $no ("the directory answer is not for the named administrator $k" + $nobodyTail)) }
    return @{ ok = $true; objectId = "$(Get-PimFirstAdminField $Named 'objectId')"; userPrincipalName = "$(Get-PimFirstAdminField $Named 'userPrincipalName')"
              tenantId = "$(Get-PimFirstAdminField $Named 'tenantId')"; namedBy = $NamedBy; notes = @()
              reason = "$(Get-PimFirstAdminField $Named 'reason') -- named by the Invardia Support app $(Get-PimFirstAdminField $NamedBy 'appId') ($(Get-PimFirstAdminField $NamedBy 'reason'))" }
}

function Resolve-PimFirstAdminSubjectLive {
    <#
      The installer's ONE call: the token's subject (Get-PimFirstAdminInstaller), and -- only for an application whose token
      is the Invardia Support session's app -- the named administrator looked up through -Graph (seam param($Method, $Path,
      $Body)). -SupportState = $global:InvardiaSupportState. Never throws. Returns Get-PimFirstAdminSubject's answer.
    #>
    param([AllowEmptyString()][string]$Token = '', [AllowEmptyString()][string]$TenantId = '', [AllowEmptyString()][string]$NamedUpn = '',
          [scriptblock]$Graph = $null, [AllowNull()][object]$SupportState = $null)
    try {
        $inst = Get-PimFirstAdminInstaller -Token $Token -TenantId $TenantId
        $by = Get-PimFirstAdminNamedBy -State $SupportState
        $named = $null
        if (-not [bool]$inst.ok -and [bool]$inst['isApplication'] -and "$NamedUpn".Trim() -and $by -and "$($inst['appId'])" -ieq "$($by.appId)" -and [bool]$inst['tenantMatches'] -and $Graph) {
            $named = Resolve-PimFirstAdminNamedPerson -Graph $Graph -Upn $NamedUpn -TenantId $TenantId -NamedBy $by
        }
        return (Get-PimFirstAdminSubject -Installer $inst -NamedUpn $NamedUpn -Named $named -NamedBy $by)
    } catch { return @{ ok = $false; objectId = ''; userPrincipalName = ''; tenantId = ''; reason = "the first SuperAdmin could not be determined ($((("$($_.Exception.Message)") -split "`n")[0]))"; namedBy = $null; notes = @() } }
}

function New-PimFirstAdminNonce {
    # 16 random bytes, hex (a fresh one for every secret written -- a re-run never re-uses one).
    $b = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-PimFirstAdminSeedValue {
    <#
      PURE (with -Nonce). The secret's value for -Installer (Get-PimFirstAdminInstaller): JSON { objectId, userPrincipalName,
      tenantId, issuedUtc, expiresUtc = issued + 48 h, nonce }. Returns @{ json; contentType; issuedUtc; expiresUtc; nonce }.
    #>
    param([Parameter(Mandatory)][object]$Installer, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Nonce = '')
    $n = "$Nonce".Trim(); if (-not $n) { $n = New-PimFirstAdminNonce }
    $iss = ConvertTo-PimFirstAdminUtcText -Utc $NowUtc
    $exp = ConvertTo-PimFirstAdminUtcText -Utc ($NowUtc.ToUniversalTime().AddHours((Get-PimFirstAdminLifetimeHours)))
    $v = [ordered]@{
        objectId          = "$(Get-PimFirstAdminField $Installer 'objectId')".Trim().ToLowerInvariant()
        userPrincipalName = "$(Get-PimFirstAdminField $Installer 'userPrincipalName')".Trim()
        tenantId          = "$(Get-PimFirstAdminField $Installer 'tenantId')".Trim().ToLowerInvariant()
        issuedUtc         = $iss
        expiresUtc        = $exp
        nonce             = $n
    }
    # FIRST-SUPERADMIN-1 (Support-app install): who NAMED this person (the Invardia Support app + its session's reason /
    # ticket) rides the secret, so the database job records it in the install's audit. Absent for a person's own install.
    $nb = Get-PimFirstAdminField $Installer 'namedBy'
    if ($null -ne $nb -and (Test-PimFirstAdminNamedBy $nb)) {
        $v['namedBy'] = [ordered]@{ kind = 'support-app'; appId = "$(Get-PimFirstAdminField $nb 'appId')".ToLowerInvariant(); reason = "$(Get-PimFirstAdminField $nb 'reason')"; ticket = "$(Get-PimFirstAdminField $nb 'ticket')" }
    }
    return @{ json = (ConvertTo-Json -InputObject $v -Compress); contentType = (Get-PimFirstAdminContentType); issuedUtc = $iss; expiresUtc = $exp; nonce = $n }
}

function Test-PimFirstAdminSeedValue {
    <#
      PURE. The database job's check of the secret it read. -TenantId = the job's OWN tenant. Returns
      @{ ok; code ('' | content-type | malformed | wrong-tenant | expired); reason; objectId; userPrincipalName; nonce;
         issuedUtc; expiresUtc }. Anything not exactly the agreed shape is REFUSED (never seeded).
    #>
    param([AllowEmptyString()][string]$Value, [AllowEmptyString()][string]$ContentType = '', [AllowEmptyString()][string]$TenantId = '',
          [datetime]$NowUtc = [datetime]::UtcNow)
    $r = @{ ok = $false; code = ''; reason = ''; objectId = ''; userPrincipalName = ''; nonce = ''; issuedUtc = ''; expiresUtc = ''; namedBy = $null }
    $bad = { param($code, $why) $r.code = $code; $r.reason = $why; return $r }
    if ("$ContentType".Trim() -cne (Get-PimFirstAdminContentType)) { return (& $bad 'content-type' "the secret's content type is '$ContentType', not '$(Get-PimFirstAdminContentType)'") }
    $o = $null
    try { $o = "$Value" | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
    if ($null -eq $o -or $o -is [string] -or $o -is [array]) { return (& $bad 'malformed' 'the secret is not the agreed JSON object') }
    $want = @('objectId', 'userPrincipalName', 'tenantId', 'issuedUtc', 'expiresUtc', 'nonce')
    $have = @($o.PSObject.Properties | ForEach-Object { $_.Name })
    # the ONE optional field: namedBy (a Support-app install) -- exactly its agreed shape, else refused
    $extra = @($have | Where-Object { $want -cnotcontains $_ -and $_ -cne 'namedBy' })
    $miss = @($want | Where-Object { $have -cnotcontains $_ })
    if ($miss.Count -or $extra.Count) { return (& $bad 'malformed' ("the secret does not carry exactly the agreed fields" + $(if ($miss.Count) { " (missing $($miss -join ', '))" }) + $(if ($extra.Count) { " (unexpected $($extra -join ', '))" }))) }
    if ($have -ccontains 'namedBy' -and -not (Test-PimFirstAdminNamedBy $o.namedBy)) { return (& $bad 'malformed' 'the secret''s namedBy is not the agreed shape') }
    $oid = "$($o.objectId)".Trim()
    if (-not (Test-PimFirstAdminGuid $oid)) { return (& $bad 'malformed' 'the object id in the secret is not a GUID') }
    $upn = "$($o.userPrincipalName)".Trim()
    if ($upn -notmatch '^[^@\s;,'']+@[^@\s;,'']+\.[^@\s;,'']+$') { return (& $bad 'malformed' 'the sign-in name in the secret is not a sign-in name') }
    $n = "$($o.nonce)".Trim()
    if ($n -notmatch '^[0-9a-fA-F]{32,128}$') { return (& $bad 'malformed' 'the nonce in the secret is not the agreed shape') }
    $tid = "$($o.tenantId)".Trim()
    if (-not (Test-PimFirstAdminGuid $tid)) { return (& $bad 'malformed' 'the tenant id in the secret is not a GUID') }
    if (-not (Test-PimFirstAdminGuid $TenantId)) { return (& $bad 'wrong-tenant' 'this database job does not know its own tenant -- the secret cannot be checked against it') }
    if ($tid -ine "$TenantId".Trim()) { return (& $bad 'wrong-tenant' "the secret was written for another tenant ($tid)") }
    $iss = ConvertFrom-PimFirstAdminUtcText -Value $o.issuedUtc
    $exp = ConvertFrom-PimFirstAdminUtcText -Value $o.expiresUtc
    if ($null -eq $iss -or $null -eq $exp) { return (& $bad 'malformed' 'the times in the secret cannot be read') }
    $now = $NowUtc.ToUniversalTime()
    if ($exp -le $iss) { return (& $bad 'malformed' 'the secret expires before it was issued') }
    if (($exp - $iss).TotalMinutes -gt ((Get-PimFirstAdminLifetimeHours) * 60 + 1)) { return (& $bad 'malformed' "the secret's lifetime is longer than $(Get-PimFirstAdminLifetimeHours) hours") }
    if ($iss -gt $now.AddMinutes(10)) { return (& $bad 'malformed' 'the secret was issued in the future') }
    if ($now -gt $exp) { return (& $bad 'expired' "the secret expired at $(ConvertTo-PimFirstAdminUtcText -Utc $exp) -- the installing person re-runs the installer for a fresh one") }
    $r.ok = $true; $r.objectId = $oid.ToLowerInvariant(); $r.userPrincipalName = $upn; $r.nonce = $n
    $r.issuedUtc = ConvertTo-PimFirstAdminUtcText -Utc $iss; $r.expiresUtc = ConvertTo-PimFirstAdminUtcText -Utc $exp
    if ($have -ccontains 'namedBy') { $r.namedBy = [ordered]@{ kind = "$($o.namedBy.kind)"; appId = "$($o.namedBy.appId)".ToLowerInvariant(); reason = "$($o.namedBy.reason)"; ticket = "$($o.namedBy.ticket)" } }
    $r.reason = 'the secret is valid'
    return $r
}

function ConvertTo-PimFirstAdminAccessEntries {
    <#
      PURE. The stored ManagerAccess value (raw JSON text, a parsed object, { managerAccess = [...] } or a bare list, $null)
      -> its entries. A value that is TEXT and not JSON THROWS -- an unreadable access model is never read as "empty".
    #>
    param([AllowNull()][object]$Raw)
    if ($null -eq $Raw) { return @() }
    $v = $Raw
    if ($v -is [string]) {
        if (-not "$v".Trim()) { return @() }
        $v = "$v" | ConvertFrom-Json -ErrorAction Stop
        if ($v -is [string]) { $v = "$v" | ConvertFrom-Json -ErrorAction Stop }
    }
    $list = Get-PimFirstAdminField $v 'managerAccess'
    if ($null -eq $list -and -not ($v -is [System.Collections.IDictionary]) -and -not $v.PSObject.Properties['managerAccess']) { $list = $v }
    return @(@($list) | Where-Object { $null -ne $_ })
}

function Test-PimFirstAdminHasSuperAdmin {
    <# PURE. Does the access model hold at least one SuperAdmin with a name? #>
    param([AllowNull()][object[]]$Entries = @())
    return [bool](@(@($Entries) | Where-Object { $_ -and "$(Get-PimFirstAdminField $_ 'role')".Trim() -ceq 'SuperAdmin' -and "$(Get-PimFirstAdminField $_ 'identity')".Trim() }).Count)
}

function Get-PimFirstAdminSeedPlan {
    <#
      PURE. What the job writes into ManagerAccess for a VALID -Seed (Test-PimFirstAdminSeedValue). A SuperAdmin already there
      = nothing (NEVER overwritten). Otherwise the entries stay, an entry with the same sign-in name (never a SuperAdmin here)
      is replaced, and the seeded SuperAdmin is added, bound to the object id. Returns @{ seed; reason; entries; entry }.
    #>
    param([AllowNull()][object[]]$Entries = @(), [Parameter(Mandatory)][object]$Seed, [datetime]$NowUtc = [datetime]::UtcNow)
    $cur = @(@($Entries) | Where-Object { $null -ne $_ })
    if (Test-PimFirstAdminHasSuperAdmin -Entries $cur) {
        return @{ seed = $false; reason = 'a SuperAdmin exists already -- the access model is never overwritten'; entries = $cur; entry = $null }
    }
    $upn = "$(Get-PimFirstAdminField $Seed 'userPrincipalName')".Trim()
    $e = [ordered]@{ identity = $upn; objectId = "$(Get-PimFirstAdminField $Seed 'objectId')".Trim().ToLowerInvariant(); role = 'SuperAdmin'
                     seededBy = (Get-PimFirstAdminSeededBy); seededUtc = (ConvertTo-PimFirstAdminUtcText -Utc $NowUtc) }
    $keep = @($cur | Where-Object { "$(Get-PimFirstAdminField $_ 'identity')".Trim().ToLowerInvariant() -ne $upn.ToLowerInvariant() })
    return @{ seed = $true; reason = "the first SuperAdmin $upn (bound to its object id)"; entries = @($keep + @($e)); entry = $e }
}

function Test-PimFirstAdminSeedLanded {
    <# PURE. Read back: the seeded entry is in -Entries as a SuperAdmin with the same object id. #>
    param([AllowNull()][object[]]$Entries = @(), [Parameter(Mandatory)][string]$ObjectId)
    return [bool](@(@($Entries) | Where-Object { $_ -and "$(Get-PimFirstAdminField $_ 'role')".Trim() -ceq 'SuperAdmin' -and "$(Get-PimFirstAdminField $_ 'objectId')".Trim() -ieq "$ObjectId".Trim() }).Count)
}

function New-PimFirstAdminSeedRecord {
    <# PURE. pim.Settings FirstAdminSeed. #>
    param([Parameter(Mandatory)][ValidateSet('used', 'used-not-deleted', 'refused', 'pending', 'none')][string]$State,
          [datetime]$AtUtc = [datetime]::UtcNow, [string]$ObjectId = '', [string]$Reason = '', [string]$Grant = '',
          [AllowNull()][object]$NamedBy = $null, [string]$Named = '')
    $r = [ordered]@{ state = $State; atUtc = (ConvertTo-PimFirstAdminUtcText -Utc $AtUtc); objectId = $(if (Test-PimFirstAdminGuid $ObjectId) { "$ObjectId".Trim().ToLowerInvariant() } else { '' }) }
    if ("$Reason".Trim()) { $r['reason'] = "$Reason".Trim() }
    if ("$Grant".Trim()) { $r['grant'] = "$Grant".Trim() }
    # FIRST-SUPERADMIN-1 (Support-app install): the audit's who-named-whom -- the person named, by the Invardia Support app,
    # with the reason / ticket its session carried. Never on the heartbeat (only state + atUtc go there).
    if ($null -ne $NamedBy -and (Test-PimFirstAdminNamedBy $NamedBy)) {
        $r['namedBy'] = [ordered]@{ kind = 'support-app'; appId = "$(Get-PimFirstAdminField $NamedBy 'appId')"; reason = "$(Get-PimFirstAdminField $NamedBy 'reason')"
                                    ticket = "$(Get-PimFirstAdminField $NamedBy 'ticket')"; named = "$Named".Trim() }
    }
    return $r
}

function Get-PimFirstAdminIssueDecision {
    <#
      PURE. Does THIS installer run write a (fresh) first-SuperAdmin secret?
        -Installer          Get-PimFirstAdminInstaller (a person, or not)
        -StoreReadable      the store's ManagerAccess could be read from here (public SQL; a private store usually cannot)
        -StoreHasSuperAdmin it holds a SuperAdmin
        -RecordedIssuerOid  the vault tag: who the first secret was written for ('' = never written)
      A SuperAdmin that is KNOWN to exist = nothing (the first SuperAdmin adds the others in Manager > Settings). A DIFFERENT
      person than the one the first secret was written for = nothing (said) -- whether or not a SuperAdmin exists. The same
      person (or the first write) = a fresh secret. Returns @{ write; reason; recovery }.
    #>
    param([Parameter(Mandatory)][object]$Installer, [bool]$StoreReadable = $false, [bool]$StoreHasSuperAdmin = $false,
          [AllowEmptyString()][string]$RecordedIssuerOid = '')
    if (-not [bool](Get-PimFirstAdminField $Installer 'ok')) { return @{ write = $false; recovery = $false; reason = "$(Get-PimFirstAdminField $Installer 'reason')" } }
    $oid = "$(Get-PimFirstAdminField $Installer 'objectId')".Trim().ToLowerInvariant()
    if ($StoreReadable -and $StoreHasSuperAdmin) {
        return @{ write = $false; recovery = $false; reason = 'a SuperAdmin exists already -- nothing is written. Other SuperAdmins are added by a SuperAdmin in PIM Manager > Settings > Manager access & roles' }
    }
    $rec = "$RecordedIssuerOid".Trim().ToLowerInvariant()
    if ($rec -and (Test-PimFirstAdminGuid $rec) -and $rec -ne $oid) {
        return @{ write = $false; recovery = $false; reason = 'the first SuperAdmin of this install is the person who installed it, and this is a different person -- nothing is written. A SuperAdmin adds others in PIM Manager > Settings > Manager access & roles' }
    }
    $who = $(if ($null -ne (Get-PimFirstAdminField $Installer 'namedBy')) { "the administrator the customer named ($(Get-PimFirstAdminField $Installer 'userPrincipalName'))" } else { 'the installing person' })
    if ($rec -eq $oid) { return @{ write = $true; recovery = $true; reason = "$who again -- a FRESH first-SuperAdmin secret (new nonce, new 48 hours)" } }
    return @{ write = $true; recovery = $false; reason = "$who becomes the first SuperAdmin" }
}

function Get-PimFirstAdminOtherSuperAdminsNote {
    <#
      PURE. The one line the installer prints when -ManagerSuperAdmins named people other than the installing person: they
      are NOT seeded by the installer; the first SuperAdmin adds them. '' when there is nobody else.
    #>
    param([AllowNull()][string[]]$Named = @(), [AllowEmptyString()][string]$InstallerUpn = '')
    $me = "$InstallerUpn".Trim().ToLowerInvariant()
    $others = @(@($Named) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_.ToLowerInvariant() -ne $me } | Select-Object -Unique)
    if (-not $others.Count) { return '' }
    return ("NOT seeded by the installer: $($others -join ', ') -- the first SuperAdmin (the person who installs) adds them in PIM Manager > Settings > Manager access & roles")
}

function Get-PimFirstAdminSecretScope {
    <# PURE. The role assignment scope of the one secret. #>
    param([Parameter(Mandatory)][string]$VaultId)
    return ("$VaultId".Trim().TrimEnd('/') + '/secrets/' + (Get-PimFirstAdminSecretName))
}

function Get-PimFirstAdminRoleAssignmentName {
    <# PURE. A stable GUID for (scope, principal, role) -- a re-run writes the same assignment, never a second one. #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [string]$RoleId = (Get-PimFirstAdminSecretsOfficerRoleId))
    $txt = ("$Scope|$PrincipalId|$RoleId").ToLowerInvariant()
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $h = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($txt)) } finally { $md5.Dispose() }
    return ([guid]::new($h)).ToString()
}

function Get-PimFirstAdminHeartbeatField {
    <#
      PURE. The heartbeat's SOFT key FirstAdminSeed { state; atUtc } from pim.Settings FirstAdminSeed (-Record) and
      ManagerAccess (-Access). Not readable (either read failed) = $null (the key is left out). No SuperAdmin = 'pending'
      (a recorded refusal stays 'refused': the installing person must re-run the installer). A SuperAdmin + a record = the
      record's state; a SuperAdmin + no record = 'none'. atUtc = the record's time, else absent.
      -LeftoverGrant: the UPDATER's last step-2h-ter answer (UpdateState.setupFacts.firstAdminGrant) -> the soft key
      leftoverGrant (Invardia added it 2026-11-20): 'reported' (a role on the USED secret is still there and the updater, no
      new right, could not remove it) = $true; 'removed' / 'none' (checked, none left) = $false; anything else (not
      checked, the secret still pending, unknown) = LEFT OUT, never guessed. It never changes state ('used-not-deleted'
      keeps its own meaning: the SECRET was not deleted).
    #>
    param([AllowNull()][object]$Record = $null, [AllowNull()][object]$Access = $null, [bool]$RecordReadable = $true, [bool]$AccessReadable = $true,
          [AllowEmptyString()][string]$LeftoverGrant = '')
    if (-not $RecordReadable -or -not $AccessReadable) { return $null }
    $rec = $Record
    if ($rec -is [string]) { if ("$rec".Trim()) { try { $rec = "$rec" | ConvertFrom-Json -ErrorAction Stop } catch { return $null } } else { $rec = $null } }
    $entries = $null
    try { $entries = @(ConvertTo-PimFirstAdminAccessEntries -Raw $Access) } catch { return $null }
    $rs = "$(Get-PimFirstAdminField $rec 'state')".Trim()
    if ($rs -and (Get-PimFirstAdminSeedStates) -notcontains $rs) { $rs = '' }
    $at = ConvertFrom-PimFirstAdminUtcText -Value (Get-PimFirstAdminField $rec 'atUtc')
    $state = if (-not (Test-PimFirstAdminHasSuperAdmin -Entries $entries)) { if ($rs -eq 'refused') { 'refused' } else { 'pending' } }
             elseif ($rs) { $rs } else { 'none' }
    $o = [ordered]@{ state = $state }
    if ($null -ne $at) { $o['atUtc'] = ConvertTo-PimFirstAdminUtcText -Utc $at }
    $lg = "$LeftoverGrant".Trim()
    if ($lg -ceq 'reported') { $o['leftoverGrant'] = $true }
    elseif ($lg -ceq 'removed' -or $lg -ceq 'none') { $o['leftoverGrant'] = $false }
    return [pscustomobject]$o
}

function Test-PimFirstAdminNotFound {
    param([AllowNull()][object]$ErrorRecord)
    return ("$ErrorRecord" -match '(?i)HTTP 404|NotFound|ResourceNotFound|SecretNotFound|RoleAssignmentNotFound|was not found')
}

function Invoke-PimFirstAdminArmGet {
    # GET through the seam; a 404 = $null, anything else throws.
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    try { return (& $Arm 'GET' $Path $null) } catch { if (Test-PimFirstAdminNotFound $_) { return $null }; throw }
}

function Invoke-PimFirstAdminSecretIssue {
    <#
      THE INSTALLER'S WRITE (a deploy). Writes the secret through ARM (works on a private vault), reads it back, records the
      issuer on the vault (a tag: an object id, no secret), grants the database job's identity Key Vault Secrets Officer on
      THAT ONE SECRET and reads the grant back. -JobPrincipalId = the job identity's principal (object) id. Never throws.
      Returns @{ ok; wrote; granted; reason; lines; expiresUtc; roleAssignmentId }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VaultId, [Parameter(Mandatory)][object]$Installer,
          [Parameter(Mandatory)][AllowEmptyString()][string]$JobPrincipalId, [datetime]$NowUtc = [datetime]::UtcNow, [string]$Nonce = '')
    $res = @{ ok = $false; wrote = $false; granted = $false; reason = ''; lines = (New-Object System.Collections.Generic.List[string]); expiresUtc = ''; roleAssignmentId = '' }
    $vid = "$VaultId".Trim().TrimEnd('/')
    if ($vid -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}$') { $res.reason = "'$VaultId' is not a Key Vault resource id"; return $res }
    if (-not [bool](Get-PimFirstAdminField $Installer 'ok')) { $res.reason = "$(Get-PimFirstAdminField $Installer 'reason')"; return $res }
    if (-not (Test-PimFirstAdminGuid $JobPrincipalId)) { $res.reason = 'the database job''s identity is not known (no principal id) -- no first-SuperAdmin secret is written'; return $res }
    $sub = ($vid -split '/')[2]
    $kvApi = Get-PimFirstAdminKvArmApi; $azApi = Get-PimFirstAdminAuthzApi
    $name = Get-PimFirstAdminSecretName
    $secretPath = "$vid/secrets/$name"
    try {
        $val = New-PimFirstAdminSeedValue -Installer $Installer -NowUtc $NowUtc -Nonce $Nonce
        $body = [ordered]@{ tags = [ordered]@{ (Get-PimFirstAdminExpiresTag) = $val.expiresUtc }
                            properties = [ordered]@{ value = $val.json; contentType = $val.contentType; attributes = [ordered]@{ enabled = $true } } }
        [void](& $Arm 'PUT' "$secretPath`?api-version=$kvApi" $body)
        $back = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$secretPath`?api-version=$kvApi"
        if (-not $back -or "$($back.properties.contentType)" -cne $val.contentType) { $res.reason = "the secret '$name' was written but NOT read back in the vault"; return $res }
        $res.wrote = $true; $res.expiresUtc = $val.expiresUtc
        $res.lines.Add("first SuperAdmin: secret '$name' written for $($Installer.userPrincipalName) (valid until $($val.expiresUtc)), read back") | Out-Null
        # the issuer, on the vault: who may write a fresh one later (recovery) -- an object id, never a secret
        try {
            $v = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$vid`?api-version=$kvApi"
            $tags = [ordered]@{}
            if ($v -and $v.tags) { foreach ($p in $v.tags.PSObject.Properties) { $tags[$p.Name] = "$($p.Value)" } }
            if ("$($tags[(Get-PimFirstAdminIssuerTag)])" -ne "$($Installer.objectId)") {
                $tags[(Get-PimFirstAdminIssuerTag)] = "$($Installer.objectId)"
                [void](& $Arm 'PATCH' "$vid`?api-version=$kvApi" @{ tags = $tags })
            }
        } catch { $res.lines.Add("first SuperAdmin: the installing person could not be recorded on the vault ($((("$($_.Exception.Message)") -split "`n")[0])) -- a later re-run cannot tell who installed") | Out-Null }
        # the grant: Key Vault Secrets Officer on THIS ONE SECRET, for the database job's identity -- read back
        $scope = "$vid/secrets/$name"
        $raName = Get-PimFirstAdminRoleAssignmentName -Scope $scope -PrincipalId $JobPrincipalId
        $raPath = "$scope/providers/Microsoft.Authorization/roleAssignments/$raName"
        $raBody = @{ properties = @{ roleDefinitionId = "/subscriptions/$sub/providers/Microsoft.Authorization/roleDefinitions/$(Get-PimFirstAdminSecretsOfficerRoleId)"
                                     principalId = "$JobPrincipalId".Trim().ToLowerInvariant(); principalType = 'ServicePrincipal' } }
        try { [void](& $Arm 'PUT' "$raPath`?api-version=$azApi" $raBody) } catch { if ("$_" -notmatch '(?i)RoleAssignmentExists|HTTP 409') { throw } }
        $raBack = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$raPath`?api-version=$azApi"
        if (-not $raBack -or "$($raBack.properties.principalId)" -ine "$JobPrincipalId".Trim() -or "$($raBack.properties.scope)".TrimEnd('/') -ine $scope) {
            $res.reason = "the secret is in the vault but the database job's role on it was NOT read back -- the job cannot read it"; return $res
        }
        $res.granted = $true; $res.roleAssignmentId = "$raPath"
        $res.lines.Add("first SuperAdmin: Key Vault Secrets Officer on that one secret -> the database job's identity, read back (removed again after the job used it)") | Out-Null
        $res.ok = $true; $res.reason = 'written and granted'
    } catch { $res.reason = "the first-SuperAdmin secret could not be written: $((("$($_.Exception.Message)") -split "`n")[0])" }
    return $res
}

function Invoke-PimFirstAdminSeedJob {
    <#
      THE DATABASE JOB'S STEP. Seams:
        -KvGet    param($Name) -> @{ status; body }  (the data plane, as the job's identity)
        -KvDelete param($Name) -> @{ status }
        -ReadAccess  { } -> the stored ManagerAccess (THROWS when unreadable)
        -WriteAccess param($Value)   ({ managerAccess = [...] })
        -ReadRecord  { } -> the stored FirstAdminSeed (or $null)
        -WriteRecord param($Value)
        -RemoveGrant { } -> @{ removed (bool); reason }
      -TenantId = the job's OWN tenant. Returns @{ state; seeded; deleted; grant; reason; lines; failed; record }.
      'failed' is true only when the seed was written and did NOT read back (the job then fails: nobody could administer).
      No secret (404) = nothing to do, nothing recorded. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$KvGet, [Parameter(Mandatory)][scriptblock]$KvDelete, [Parameter(Mandatory)][scriptblock]$ReadAccess,
          [Parameter(Mandatory)][scriptblock]$WriteAccess, [scriptblock]$ReadRecord = { $null }, [Parameter(Mandatory)][scriptblock]$WriteRecord,
          [scriptblock]$RemoveGrant = { @{ removed = $false; reason = 'not attempted' } }, [AllowEmptyString()][string]$TenantId = '',
          [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ state = ''; seeded = $false; deleted = $false; grant = ''; reason = ''; lines = (New-Object System.Collections.Generic.List[string]); failed = $false; record = $null; namedBy = $null; named = '' }
    $say ={ param($t) $o.lines.Add("$t") | Out-Null }
    $name = Get-PimFirstAdminSecretName
    $prev = $null; try { $prev = & $ReadRecord; if ($prev -is [string] -and "$prev".Trim()) { $prev = "$prev" | ConvertFrom-Json } } catch { $prev = $null }
    $prevState = "$(Get-PimFirstAdminField $prev 'state')".Trim()
    $record = { param($state, $oid, $why)
        # a refusal because a SuperAdmin existed never replaces an earlier 'used' answer (the heartbeat would say refused)
        if ($state -eq 'refused' -and $o.reason -match 'exists already' -and $prevState -in @('used', 'used-not-deleted')) { & $say "first SuperAdmin: the earlier answer '$prevState' is kept"; $o.state = $prevState; return }
        $rec = New-PimFirstAdminSeedRecord -State $state -AtUtc $NowUtc -ObjectId $oid -Reason $why -Grant $o.grant -NamedBy $o.namedBy -Named $o.named
        try { & $WriteRecord $rec; $o.record = $rec } catch { & $say "first SuperAdmin: the answer could not be recorded ($((("$($_.Exception.Message)") -split "`n")[0]))" }
        $o.state = $state
    }
    $delete = {
        $d = $null; try { $d = & $KvDelete $name } catch { $d = @{ status = 0; error = "$($_.Exception.Message)" } }
        $g2 = $null; try { $g2 = & $KvGet $name } catch { $g2 = @{ status = 0 } }
        if ([int]$g2.status -eq 404) { $o.deleted = $true; & $say "first SuperAdmin: secret '$name' deleted, read back 404"; return $true }
        & $say "first SuperAdmin: secret '$name' NOT deleted (delete answered $([int]$d.status), read back $([int]$g2.status))"
        return $false
    }
    $ungrant = {
        $gr = $null; try { $gr = & $RemoveGrant } catch { $gr = @{ removed = $false; reason = "$($_.Exception.Message)" } }
        if ([bool]$gr.removed) { $o.grant = 'removed'; & $say "first SuperAdmin: the job identity's role on the secret removed, read back" }
        else { $o.grant = 'left-for-installer-or-updater'; & $say "first SuperAdmin: the job identity's role on the secret stays until the installer or the updater removes it ($($gr.reason))" }
    }
    $g = $null
    try { $g = & $KvGet $name } catch { $g = @{ status = 0; error = "$($_.Exception.Message)" } }
    $st = [int]$g.status
    if ($st -eq 404) { $o.reason = 'no first-SuperAdmin secret in the vault -- nothing to do'; & $say "first SuperAdmin: $($o.reason)"; return $o }
    if ($st -ne 200) {
        $o.reason = "the first-SuperAdmin secret could not be read (HTTP $st$(if ($g.error) { ": $((("$($g.error)") -split "`n")[0])" })) -- it stays; the next run reads it again"
        & $say "first SuperAdmin: $($o.reason)"
        if ($prevState -notin @('used', 'used-not-deleted')) { & $record 'pending' '' $o.reason }
        return $o
    }
    $sec = $null; try { $sec = "$($g.body)" | ConvertFrom-Json } catch { $sec = $null }
    $chk = Test-PimFirstAdminSeedValue -Value "$(Get-PimFirstAdminField $sec 'value')" -ContentType "$(Get-PimFirstAdminField $sec 'contentType')" -TenantId $TenantId -NowUtc $NowUtc
    if (-not $chk.ok) {
        $o.reason = "REFUSED ($($chk.code)): $($chk.reason) -- NOT seeded"
        & $say "first SuperAdmin: $($o.reason)"
        if (& $delete) { & $ungrant }
        & $record 'refused' '' $o.reason
        return $o
    }
    if ($chk.namedBy) {
        $o.namedBy = $chk.namedBy; $o.named = $chk.userPrincipalName
        & $say "first SuperAdmin: $($chk.userPrincipalName) was named by the Invardia Support app $($chk.namedBy.appId) ($($chk.namedBy.reason))"
    }
    $entries = $null
    try { $entries = @(ConvertTo-PimFirstAdminAccessEntries -Raw (& $ReadAccess)) } catch {
        $o.reason = "the access model could not be read ($((("$($_.Exception.Message)") -split "`n")[0])) -- NOT seeded, the secret stays for the next run"
        & $say "first SuperAdmin: $($o.reason)"
        & $record 'pending' $chk.objectId $o.reason
        return $o
    }
    $plan = Get-PimFirstAdminSeedPlan -Entries $entries -Seed $chk -NowUtc $NowUtc
    if (-not $plan.seed) {
        $o.reason = "REFUSED: $($plan.reason) -- NOT seeded"
        & $say "first SuperAdmin: $($o.reason)"
        if (& $delete) { & $ungrant }
        & $record 'refused' $chk.objectId $o.reason
        return $o
    }
    try {
        & $WriteAccess ([ordered]@{ managerAccess = @($plan.entries) })
        $back = @(ConvertTo-PimFirstAdminAccessEntries -Raw (& $ReadAccess))
        if (-not (Test-PimFirstAdminSeedLanded -Entries $back -ObjectId $chk.objectId)) { throw 'the seeded SuperAdmin is not in the access model read back' }
    } catch {
        $o.failed = $true
        $o.reason = "the first SuperAdmin did NOT land ($((("$($_.Exception.Message)") -split "`n")[0])) -- the secret stays for the next run"
        & $say "first SuperAdmin: $($o.reason)"
        & $record 'pending' $chk.objectId $o.reason
        return $o
    }
    $o.seeded = $true
    & $say "first SuperAdmin: $($chk.userPrincipalName) seeded as SuperAdmin, bound to its object id, read back"
    if (& $delete) { & $ungrant; $o.reason = 'seeded; the secret deleted'; & $record 'used' $chk.objectId '' }
    else { $o.reason = 'seeded; the secret could NOT be deleted (it expires; the job deletes it on its next run)'; & $record 'used-not-deleted' $chk.objectId $o.reason }
    return $o
}

function Invoke-PimFirstAdminGrantTrim {
    <#
      THE INSTALLER (after the job ran) AND THE UPDATER (every run): nothing standing left. When the secret is GONE from the
      vault, every role assignment at the secret's scope is removed and read back (404). While the secret is still there the
      grant is kept (the job needs it to read and delete); an expired one is said. A refused removal (403: the caller may
      not delete role assignments) is REPORTED, never fatal. -Arm param($Method, $Path, $Body). Never throws.
      Returns @{ ok; removed; reported; secretPresent; lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowEmptyString()][string]$VaultId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $o = @{ ok = $true; removed = 0; reported = 0; secretPresent = $false; lines = (New-Object System.Collections.Generic.List[string]) }
    $vid = "$VaultId".Trim().TrimEnd('/')
    if (-not $vid) { $o.lines.Add('first SuperAdmin: no install vault is known -- nothing to check') | Out-Null; return $o }
    $kvApi = Get-PimFirstAdminKvArmApi; $azApi = Get-PimFirstAdminAuthzApi
    $scope = Get-PimFirstAdminSecretScope -VaultId $vid
    try {
        $v = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$vid`?api-version=$kvApi"
        if (-not $v) { $o.lines.Add('first SuperAdmin: the install vault was not found -- nothing to check') | Out-Null; return $o }
        $s = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$scope`?api-version=$kvApi"
        if ($s) {
            $o.secretPresent = $true
            $exp = $null; if ($s.tags) { $exp = ConvertFrom-PimFirstAdminUtcText -Value "$($s.tags.(Get-PimFirstAdminExpiresTag))" }
            if ($null -ne $exp -and $NowUtc.ToUniversalTime() -gt $exp) { $o.lines.Add("first SuperAdmin: the secret expired $(ConvertTo-PimFirstAdminUtcText -Utc $exp) and is still in the vault -- the database job refuses and deletes it on its next run; the installing person re-runs the installer for a fresh one") | Out-Null }
            else { $o.lines.Add('first SuperAdmin: the secret is still in the vault (not used yet) -- the job''s role on it stays') | Out-Null }
            return $o
        }
        $list = & $Arm 'GET' "$vid/providers/Microsoft.Authorization/roleAssignments`?api-version=$azApi" $null
        $items = @(if ($list -and $list.PSObject.Properties['value']) { @($list.value) } else { @($list) }) | Where-Object { $_ -and "$($_.properties.scope)".TrimEnd('/') -ieq $scope }
        if (-not @($items).Count) { $o.lines.Add('first SuperAdmin: no role assignment remains on the used secret') | Out-Null; return $o }
        foreach ($ra in @($items)) {
            $id = "$($ra.id)".Trim()
            try {
                [void](& $Arm 'DELETE' "$id`?api-version=$azApi" $null)
                $after = Invoke-PimFirstAdminArmGet -Arm $Arm -Path "$id`?api-version=$azApi"
                if ($after) { $o.reported++; $o.ok = $false; $o.lines.Add("first SuperAdmin: the role on the used secret ($($ra.properties.principalId)) is still there after the removal") | Out-Null }
                else { $o.removed++; $o.lines.Add("first SuperAdmin: the role on the used secret ($($ra.properties.principalId)) removed, read back") | Out-Null }
            } catch {
                if (Test-PimFirstAdminNotFound $_) { $o.removed++; continue }
                $o.reported++; $o.ok = $false
                $o.lines.Add("first SuperAdmin: the role on the used secret ($($ra.properties.principalId)) could not be removed by this identity ($((("$($_.Exception.Message)") -split "`n")[0])) -- REPORTED; the installer's next run removes it") | Out-Null
            }
        }
    } catch { $o.ok = $false; $o.lines.Add("first SuperAdmin: the grant check could not run ($((("$($_.Exception.Message)") -split "`n")[0]))") | Out-Null }
    return $o
}
