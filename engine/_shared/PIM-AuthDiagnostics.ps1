#Requires -Version 5.1
<#
.SYNOPSIS
    Auth / Identity diagnostics for PIM4EntraPS (REQUIREMENTS.md / FEATURES.md section 9).

.DESCRIPTION
    Pure, dependency-free helpers (no Graph/Az/MSAL modules, PS 5.1 + 7 compatible)
    that turn opaque auth failures into a precise, operator-actionable hint:

      * Get-PimMissingRoleHint
          A Microsoft Graph (or ARM) 403 / "insufficient privileges" no longer dead-ends.
          Maps the failing request (HTTP status + error body + the API path that was
          being called) to the EXACT Graph application role / Azure RBAC role to grant,
          and to the directory role an operator should ACTIVATE in PIM. Used both by the
          engine (app-only SPN -- names the missing app-role + the Grant-PimGraphAppRoles
          permission) and by interactive/operator sign-in (names the PIM role to activate).

      * Get-PimAccountSignInHint / ConvertTo-PimAuthCodePrompt
          Account sign-in prompt clarity. Reports the account currently cached for the
          interactive (Edge PKCE loopback) flow and resolves the OAuth `prompt` value so
          a stale cached account is never silently reused -- `select_account` by default,
          `login` when a fresh sign-in is forced.

      * Get-PimAdFailureDiagnostic
          AD-failure diagnostics. When a hybrid-AD action fails despite a Domain Admin,
          surface the process identity, whether it is a real domain principal vs SYSTEM /
          a local/virtual account, Kerberos-ticket presence, and DC discovery -- so the
          operator sees WHY (wrong identity / no DC / no ticket) instead of a bare error.

      * ConvertFrom-PimJwtClaims / Test-PimTokenHasMfa / Assert-PimManagerMfa
          MFA-gated Manager login. Decode a JWT's claims with no library, test whether the
          `amr` (authentication-methods) claim proves MFA, and gate the Manager so a stolen
          script can't be replayed without a fresh MFA sign-in. Reuses the Edge PKCE
          loopback (Get-PimInteractiveToken) -- NEVER device-code (MS blocks it via CA),
          never the system-default browser. On the hosted Manager, Easy Auth is the MFA
          boundary, so this gate is a no-op there (it must never break Easy Auth).

    Everything here is offline-testable: the decision logic is separated from any
    network/host call so the test suite can assert it without a tenant.

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# section 9  Missing-role hint  (don't hard-fail a 403 -- name the role to grant)
# ---------------------------------------------------------------------------

# Map: a fragment of the Graph API PATH being called -> the app-role(s) the engine
# SPN needs (granted by setup/Grant-PimGraphAppRoles.ps1) AND the directory role an
# interactive operator should ACTIVATE in PIM. Ordered most-specific first.
$script:PimRoleHintByPath = @(
    @{ match = 'roleManagement/directory/roleAssignmentSchedule';            appRoles = @('RoleManagement.ReadWrite.Directory'); pimRoles = @('Privileged Role Administrator') }
    @{ match = 'roleManagement/directory/roleDefinitions';                    appRoles = @('RoleManagement.ReadWrite.Directory','Directory.Read.All'); pimRoles = @('Privileged Role Administrator') }
    @{ match = 'policies/roleManagementPolic';                                appRoles = @('RoleManagementPolicy.ReadWrite.AzureADGroup','RoleManagementPolicy.ReadWrite.Directory'); pimRoles = @('Privileged Role Administrator') }
    @{ match = 'identityGovernance/privilegedAccess/group';                   appRoles = @('PrivilegedAccess.ReadWrite.AzureADGroup'); pimRoles = @('Privileged Role Administrator') }
    @{ match = 'identityGovernance/accessReviews';                            appRoles = @('AccessReview.Read.All'); pimRoles = @('Identity Governance Administrator') }
    @{ match = 'directory/administrativeUnits';                               appRoles = @('AdministrativeUnit.ReadWrite.All'); pimRoles = @('Privileged Role Administrator') }
    @{ match = 'servicePrincipals/';                                          appRoles = @('Application.ReadWrite.All'); pimRoles = @('Cloud Application Administrator','Application Administrator') }
    @{ match = 'applications';                                                appRoles = @('Application.ReadWrite.All'); pimRoles = @('Application Administrator') }
    @{ match = '/sendMail';                                                   appRoles = @('Mail.Send'); pimRoles = @() }
    @{ match = '/groups';                                                     appRoles = @('Group.ReadWrite.All'); pimRoles = @('Groups Administrator') }
    @{ match = '/users';                                                      appRoles = @('User.ReadWrite.All'); pimRoles = @('User Administrator') }
    @{ match = '/directory';                                                  appRoles = @('Directory.Read.All'); pimRoles = @() }
)

function Test-PimIsAuthForbidden {
    # True when an error looks like a permissions failure (403 / known Graph error
    # codes) rather than a transient/server error. Pure -- takes the status + body.
    [CmdletBinding()]
    param([int]$StatusCode = 0, [string]$ErrorBody = '')
    if ($StatusCode -eq 403 -or $StatusCode -eq 401) { return $true }
    if ("$ErrorBody" -match '(?i)Authorization_RequestDenied|Insufficient privileges|InsufficientScope|MissingClaim|InvalidAuthenticationToken|does not have permission|AuthorizationFailed') { return $true }
    return $false
}

function Get-PimMissingRoleHint {
    <#
    .SYNOPSIS
        Turn a Graph/ARM 403 into the exact role(s) to grant / activate.
    .DESCRIPTION
        Pure: given the API path that failed (and optionally the HTTP status + error
        body), return a structured hint naming the Graph application role the engine
        SPN needs (and the Grant-PimGraphAppRoles command to add it) plus the directory
        role an interactive operator should ACTIVATE in PIM. Returns $null when the
        failure is not a permissions failure (so callers don't mis-hint a 500/429).
    .PARAMETER Path
        The API path or URL that was being called when the call failed.
    .PARAMETER StatusCode
        HTTP status (0 = unknown -- then ErrorBody decides).
    .PARAMETER ErrorBody
        The API error body, if captured.
    .PARAMETER AppOnly
        $true (default) = engine/SPN context: lead with the app-role to grant.
        $false = interactive operator: lead with the PIM role to activate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$StatusCode = 0,
        [string]$ErrorBody = '',
        [bool]$AppOnly = $true
    )
    # Only hint on a genuine permissions failure. If status/body were supplied and they
    # are NOT a 403-class failure, return $null so the caller surfaces the real error.
    if (($StatusCode -ne 0 -or "$ErrorBody".Trim()) -and -not (Test-PimIsAuthForbidden -StatusCode $StatusCode -ErrorBody $ErrorBody)) {
        return $null
    }

    $entry = $null
    foreach ($e in $script:PimRoleHintByPath) {
        if ("$Path" -match [regex]::Escape($e.match)) { $entry = $e; break }
    }
    $appRoles = if ($entry) { @($entry.appRoles) } else { @('Directory.Read.All') }
    $pimRoles = if ($entry) { @($entry.pimRoles) } else { @('Privileged Role Administrator') }

    if ($AppOnly) {
        $grant = "setup/Grant-PimGraphAppRoles.ps1 (Permissions includes: $($appRoles -join ', ')) -- then re-consent."
        $msg   = "Access denied calling '$Path'. The engine app (SPN) is missing the Graph application role(s): $($appRoles -join ', '). Grant via $grant"
    } else {
        $act = if ($pimRoles.Count) { $pimRoles -join ' / ' } else { '(no directory role -- this is an app-only permission)' }
        $msg = "Access denied calling '$Path'. Your token lacks the required role. Activate in PIM: $act -- then sign in again."
    }
    [pscustomobject]@{
        Path           = $Path
        IsAuthFailure  = $true
        AppRolesToGrant = $appRoles
        PimRolesToActivate = $pimRoles
        AppOnly        = $AppOnly
        Hint           = $msg
    }
}

# ---------------------------------------------------------------------------
# section 9  Account sign-in prompt clarity  (never silently reuse a stale account)
# ---------------------------------------------------------------------------

function ConvertTo-PimAuthCodePrompt {
    <#
    .SYNOPSIS
        Resolve the OAuth `prompt` value for the interactive flow.
    .DESCRIPTION
        Pure. `select_account` (default) always shows the account picker so a stale
        cached account is never reused silently; `login` forces a brand-new credential
        prompt (-ForceFresh / a stale-cache hint). Returns the prompt string only.
    #>
    [CmdletBinding()]
    param([switch]$ForceFresh, [string]$KnownStaleAccount)
    if ($ForceFresh -or "$KnownStaleAccount".Trim()) { return 'login' }
    return 'select_account'
}

function Get-PimAccountSignInHint {
    <#
    .SYNOPSIS
        Report the account that the interactive flow would (re)use, with clear guidance.
    .DESCRIPTION
        Pure. Given the previously-cached account (UPN) and the account the operator
        EXPECTED, returns a hint object that tells the operator which account will be
        used and whether they must pick a different one -- so a stale cached account is
        surfaced, never silently reused. CachedAccount empty = no cache (fresh picker).
    #>
    [CmdletBinding()]
    param([string]$CachedAccount = '', [string]$ExpectedAccount = '')
    $cached = "$CachedAccount".Trim()
    $expected = "$ExpectedAccount".Trim()
    $mismatch = [bool]($cached -and $expected -and ($cached.ToLowerInvariant() -ne $expected.ToLowerInvariant()))
    if (-not $cached) {
        $hint = 'No cached account -- the account picker will be shown (prompt=select_account).'
    } elseif ($mismatch) {
        $hint = "A different account ('$cached') is cached than the one you expected ('$expected'). Forcing a fresh sign-in (prompt=login) -- pick '$expected'."
    } else {
        $hint = "Cached account '$cached' will be offered; the picker is still shown so you can choose another (prompt=select_account)."
    }
    [pscustomobject]@{
        CachedAccount   = $cached
        ExpectedAccount = $expected
        Mismatch        = $mismatch
        Prompt          = (ConvertTo-PimAuthCodePrompt -ForceFresh:$mismatch)
        Hint            = $hint
    }
}

# ---------------------------------------------------------------------------
# section 9  AD-failure diagnostics  (surface identity / Kerberos / DC on AD failure)
# ---------------------------------------------------------------------------

function Resolve-PimAdFailureDiagnostic {
    <#
    .SYNOPSIS
        PURE core of Get-PimAdFailureDiagnostic -- classify an AD failure from facts.
    .DESCRIPTION
        Given the running identity name, whether a high-priv -Credential was supplied,
        Kerberos-ticket presence, and a discovered DC (or none), produce an ordered list
        of likely causes + the single most useful next step. No host calls -- unit-testable.
    #>
    [CmdletBinding()]
    param(
        [string]$ProcessIdentity = '',
        [bool]$HasExplicitCredential = $false,
        [bool]$HasKerberosTickets = $false,
        [string]$DiscoveredDc = '',
        [string]$ErrorMessage = ''
    )
    $who = "$ProcessIdentity".Trim()
    $isSystemish = [bool]($who -match '(?i)(^|\\)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' -or $who -match '(?i)\$$' -or $who -eq '')
    $causes = New-Object System.Collections.Generic.List[string]
    $nextStep = $null

    if (-not $DiscoveredDc) {
        $causes.Add('No domain controller was reachable (DC discovery returned nothing) -- DNS / network / this host is not domain-joined.')
        $nextStep = 'Verify this host can reach a DC (nltest /dsgetdc:<domain>); fix DNS/site/network before retrying.'
    }
    if ($isSystemish -and -not $HasExplicitCredential) {
        $causes.Add("The action is running as a non-domain identity ('$who') and no high-priv -Credential was supplied, so AD calls use the machine/SYSTEM context, not a Domain Admin.")
        if (-not $nextStep) { $nextStep = 'Pass an explicit high-priv -Credential ($AD_Credentials) instead of relying on the ambient SYSTEM identity.' }
    }
    if (-not $HasKerberosTickets -and $DiscoveredDc) {
        $causes.Add('No Kerberos tickets are cached for this identity (klist empty) -- the identity has not authenticated to the domain.')
        if (-not $nextStep) { $nextStep = 'Confirm the identity can authenticate (klist; re-supply -Credential); a Domain Admin in a different forest still needs a trust path.' }
    }
    if ($causes.Count -eq 0) {
        $causes.Add("Identity '$who' looks like a domain principal with tickets and a reachable DC; the failure is likely an authorization (rights on the target object) rather than authentication problem.")
        $nextStep = "Check the target object's ACL / the role the identity holds in AD; the original error was: $ErrorMessage"
    }
    [pscustomobject]@{
        ProcessIdentity      = $who
        LooksLikeSystem      = $isSystemish
        HasExplicitCredential = $HasExplicitCredential
        HasKerberosTickets   = $HasKerberosTickets
        DiscoveredDc         = "$DiscoveredDc"
        Causes               = $causes.ToArray()
        NextStep             = $nextStep
    }
}

function Get-PimAdFailureDiagnostic {
    <#
    .SYNOPSIS
        Collect live AD-context facts (identity / Kerberos / DC) and classify a failure.
    .DESCRIPTION
        Thin host-bound wrapper around Resolve-PimAdFailureDiagnostic: reads the running
        WindowsIdentity, runs `klist` to detect cached tickets, and `nltest /dsgetdc` to
        discover a DC, then returns the classified diagnostic. Best-effort; every probe
        is guarded so this never throws (it explains a failure, it must not cause one).
    #>
    [CmdletBinding()]
    param([bool]$HasExplicitCredential = $false, [string]$Domain = '', [string]$ErrorMessage = '')
    $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" }
    $hasTickets = $false
    try {
        $kl = & klist 2>$null | Out-String
        if ("$kl" -match '(?i)Cached Tickets:\s*\(([1-9]\d*)\)' -or "$kl" -match '(?i)krbtgt') { $hasTickets = $true }
    } catch {}
    $dc = ''
    try {
        $dom = if ("$Domain".Trim()) { $Domain } elseif ("$env:USERDNSDOMAIN".Trim()) { $env:USERDNSDOMAIN } else { $env:USERDOMAIN }
        if ("$dom".Trim()) {
            $nl = & nltest "/dsgetdc:$dom" 2>$null | Out-String
            if ("$nl" -match '(?im)^\s*DC:\s*\\\\([^\s]+)') { $dc = $Matches[1] }
        }
    } catch {}
    Resolve-PimAdFailureDiagnostic -ProcessIdentity $who -HasExplicitCredential $HasExplicitCredential `
        -HasKerberosTickets $hasTickets -DiscoveredDc $dc -ErrorMessage $ErrorMessage
}

# ---------------------------------------------------------------------------
# section 9  MFA-gated Manager login  (verify amr=mfa; reuse Edge PKCE; never device-code)
# ---------------------------------------------------------------------------

function ConvertFrom-PimJwtClaims {
    <#
    .SYNOPSIS
        Decode a JWT's payload claims with no library (PS 5.1 + 7 safe).
    .DESCRIPTION
        Pure: splits the token, base64url-decodes the payload segment, returns the claims
        as a PSCustomObject. Returns $null for anything that isn't a 3-part JWT. Does NOT
        validate the signature -- claims are used only for UX/gating after the token was
        already obtained from Entra over TLS (the Edge PKCE flow), not as a trust anchor.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Token)
    try {
        $parts = "$Token" -split '\.'
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } 1 { return $null } }
        return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json)
    } catch { return $null }
}

function Test-PimTokenHasMfa {
    <#
    .SYNOPSIS
        True when a decoded token proves the sign-in satisfied MFA.
    .DESCRIPTION
        Pure. Accepts either a raw JWT (-Token) or already-decoded claims (-Claims).
        MFA is proven when the `amr` (authentication methods references) claim contains
        'mfa' (or a strong second-factor method: fido, hwk, otp, sms, phr, pop), OR an
        `acr` of '1' per the legacy contract. Conservative: unknown/absent claim = $false
        (fail closed), so the gate never passes a token it can't prove is MFA'd.
    #>
    [CmdletBinding()]
    param([string]$Token, [object]$Claims)
    if (-not $Claims) { if ("$Token".Trim()) { $Claims = ConvertFrom-PimJwtClaims -Token $Token } }
    if (-not $Claims) { return $false }
    $amr = @()
    try { if ($null -ne $Claims.amr) { $amr = @($Claims.amr) } } catch {}
    foreach ($m in $amr) {
        if ("$m" -match '(?i)^(mfa|fido|hwk|otp|sms|phr|pop|swk)$') { return $true }
    }
    try { if ("$($Claims.acr)" -eq '1') { return $true } } catch {}
    return $false
}

function Assert-PimManagerMfa {
    <#
    .SYNOPSIS
        MFA gate for the Manager login. Returns a decision object (never throws on policy).
    .DESCRIPTION
        Decision logic for whether the Manager should grant access:
          * Hosted (Easy Auth in front) -- Entra + CA already enforced MFA at the edge; the
            gate is a NO-OP here so it can never break Easy Auth. Returns Allowed=$true.
          * Local/loopback -- require an MFA-proven token. If a token is supplied, its `amr`
            is checked; if not, the caller is told to run the Edge PKCE sign-in
            (Get-PimInteractiveToken -- NEVER device-code, never system browser).
        This is the pure DECISION half; Invoke-PimManagerMfaLogin does the actual sign-in.
    .PARAMETER Hosted
        $true when running behind App Service Easy Auth.
    .PARAMETER Token
        An access/id token already obtained for the operator (optional).
    .PARAMETER RequireMfa
        Enforce the MFA requirement on the local path (default $true).
    #>
    [CmdletBinding()]
    param([switch]$Hosted, [string]$Token, [bool]$RequireMfa = $true)
    if ($Hosted) {
        return [pscustomobject]@{ Allowed = $true; Source = 'hosted: Easy Auth enforces MFA at the edge (gate is a no-op)'; NeedSignIn = $false; Upn = '' }
    }
    if (-not $RequireMfa) {
        return [pscustomobject]@{ Allowed = $true; Source = 'local: MFA gate disabled by config'; NeedSignIn = $false; Upn = '' }
    }
    if (-not "$Token".Trim()) {
        return [pscustomobject]@{ Allowed = $false; Source = 'local: no token yet -- run the Edge sign-in'; NeedSignIn = $true; Upn = ''
                                  Hint = 'Sign in with Get-PimInteractiveToken (Edge PKCE loopback) and complete MFA.' }
    }
    $claims = ConvertFrom-PimJwtClaims -Token $Token
    $upn = ''
    try { $upn = "$($claims.upn)"; if (-not $upn) { $upn = "$($claims.preferred_username)" }; if (-not $upn) { $upn = "$($claims.unique_name)" } } catch {}
    if (Test-PimTokenHasMfa -Claims $claims) {
        return [pscustomobject]@{ Allowed = $true; Source = 'local: token amr proves MFA'; NeedSignIn = $false; Upn = $upn }
    }
    return [pscustomobject]@{ Allowed = $false; Source = 'local: token present but amr does not prove MFA'; NeedSignIn = $true; Upn = $upn
                              Hint = 'The sign-in did not satisfy MFA. Re-run the Edge sign-in and complete MFA; the Manager will not unlock without it.' }
}

# ---------------------------------------------------------------------------
# section 28 [M9]  Support / diagnostics  (first-line self-check + handoff bundle)
# ---------------------------------------------------------------------------
# THREE pure cores, all probe-INJECTABLE so the test suite asserts them without a
# tenant (no live SQL/Graph/ARM):
#   * Get-PimConnectivityCheck     -> classify ONE probe result (sql|graph|arm)
#                                      into pass/fail + an actionable remediation hint.
#   * Get-PimSupportHealthSummary  -> store mode / cache freshness / last run /
#                                      instance identity from INJECTED state.
#   * New-PimDiagnosticsBundle     -> assemble a SANITIZED handoff bundle and prove
#                                      (via Protect-PimDiagnosticsText) no secret /
#                                      cert / token / connection-string / full GUID leaks.
# The Manager's /api/support/* endpoints pass LIVE probe results into these cores;
# the cores never touch the network themselves.

function Protect-PimDiagnosticsText {
    <#
    .SYNOPSIS
        Mask secrets / certs / tokens / connection-strings / full tenant+subscription
        GUIDs out of any text destined for a shareable diagnostics bundle.
    .DESCRIPTION
        Pure + idempotent. The bundle is handed to support, so it MUST NOT carry
        anything sensitive. We mask, in order:
          * connection-string secret fields (Password/Pwd/User ID/UID/AccountKey/
            SharedAccessKey/sig=) -> the field name is kept, the value -> ***REDACTED***
          * Bearer/JWT tokens (eyJ... three-part) and 'Bearer xxx' -> ***REDACTED***
          * PEM blocks (BEGIN ... PRIVATE KEY / CERTIFICATE) -> a single ***REDACTED***
          * certificate thumbprints (40-hex) -> ***REDACTED-THUMBPRINT***
          * any GUID (tenant / subscription / object id) -> first 8 chars + masked tail,
            so a bundle can still SAY "tenant 1234abcd-..." for correlation without
            exposing the full id (REQUIREMENTS s22: never tenant/subscription IDs).
          * key=value pairs whose KEY looks secret (password/secret/key/token/pwd/
            clientsecret/sas/connectionstring) -> value masked.
        Returns the masked string; on $null/empty returns ''.
    #>
    [CmdletBinding()]
    param([string]$Text)
    $t = "$Text"
    if (-not $t) { return '' }

    # 1. PEM private-key / certificate blocks -> one redaction marker.
    $t = [regex]::Replace($t, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '***REDACTED-PRIVATE-KEY***')
    $t = [regex]::Replace($t, '(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', '***REDACTED-CERTIFICATE***')

    # 2. Bearer / JWT tokens (eyJ header.payload.sig).
    $t = [regex]::Replace($t, '(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer ***REDACTED***')
    $t = [regex]::Replace($t, '\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', '***REDACTED-TOKEN***')

    # 3. Connection-string secret fields (ADO.NET / SQL / storage SAS).
    $t = [regex]::Replace($t, '(?i)\b(Password|Pwd|User ID|UID|AccountKey|SharedAccessKey|AccountSecret)\s*=\s*[^;""]*', '$1=***REDACTED***')
    $t = [regex]::Replace($t, '(?i)([?&]sig=)[^&\s""]+', '$1***REDACTED***')

    # 4. Generic secret-looking key=value / key:value pairs.
    $t = [regex]::Replace($t, '(?i)\b(client[_\-]?secret|secret|password|pwd|api[_\-]?key|access[_\-]?key|token|sas|connection[_\-]?string)\b(\s*[:=]\s*)("?)([^\s"";,]+)("?)', '$1$2***REDACTED***')

    # 5. Certificate thumbprints (exactly 40 hex) BEFORE the generic GUID mask.
    $t = [regex]::Replace($t, '(?i)\b[0-9A-F]{40}\b', '***REDACTED-THUMBPRINT***')

    # 6. GUIDs (tenant / subscription / object ids) -> keep first 8 for correlation.
    $t = [regex]::Replace($t, '\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '$1-****-****-****-************')

    return $t
}

function Get-PimConnectivityCheck {
    <#
    .SYNOPSIS
        Classify ONE injected connectivity/permission probe result into pass/fail + hint.
    .DESCRIPTION
        Pure -- the caller does the live probe (open a SQL connection / call Graph /
        call ARM) and passes the OUTCOME in; this turns it into a uniform check record
        with an ACTIONABLE remediation hint. No network here, so it is unit-testable.

        Reuses the canonical permission-hint helper Get-PimMissingRoleHint for Graph/ARM
        permission failures (so the diagnostics surface and the engine name the SAME
        missing app-role), and gives SQL its own MI/firewall-oriented hint.
    .PARAMETER Surface
        sql | graph | arm  (arm is OPTIONAL -- only configured when an Azure scope exists).
    .PARAMETER Reachable
        $true if the resource answered at all (TCP/HTTP), regardless of authorization.
    .PARAMETER StatusCode
        HTTP status for graph/arm probes (0 = n/a). 401/403 -> a permission failure.
    .PARAMETER ErrorMessage
        The probe's error text (used for permission/auth classification + the hint).
    .PARAMETER Configured
        $false marks a surface that isn't in play (e.g. ARM with no Azure scope) -> 'skipped'.
    .PARAMETER ProbePath
        The Graph/ARM path that was probed (drives Get-PimMissingRoleHint role mapping).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('sql','graph','arm')][string]$Surface,
        [bool]$Reachable = $false,
        [int]$StatusCode = 0,
        [string]$ErrorMessage = '',
        [bool]$Configured = $true,
        [string]$ProbePath = ''
    )
    $label = switch ($Surface) { 'sql' { 'SQL store' } 'graph' { 'Microsoft Graph (engine SPN)' } 'arm' { 'Azure Resource Manager' } }

    if (-not $Configured) {
        return [pscustomobject]@{ surface = $Surface; label = $label; status = 'skipped'; reachable = $false
                                  isPermissionFailure = $false; hint = "$label is not configured for this instance -- nothing to test." }
    }

    $isAuth = Test-PimIsAuthForbidden -StatusCode $StatusCode -ErrorBody $ErrorMessage

    # A clean pass: reachable, no auth failure, and (for HTTP surfaces) a non-error status.
    $httpOk = ($StatusCode -eq 0) -or ($StatusCode -ge 200 -and $StatusCode -lt 400)
    if ($Reachable -and -not $isAuth -and $httpOk -and -not "$ErrorMessage".Trim()) {
        return [pscustomobject]@{ surface = $Surface; label = $label; status = 'pass'; reachable = $true
                                  isPermissionFailure = $false; hint = '' }
    }

    # Permission failure: name the exact role to grant.
    if ($isAuth) {
        $hint = ''
        if ($Surface -eq 'sql') {
            $hint = ("$label rejected the engine identity. Grant the engine MI/SPN as a contained DB user " +
                     "(db_datareader + db_datawriter on the PIM database): " +
                     "CREATE USER [<engine-app>] FROM EXTERNAL PROVIDER; then ALTER ROLE db_datareader/db_datawriter ADD MEMBER [<engine-app>].")
        } else {
            $rh = Get-PimMissingRoleHint -Path $(if ("$ProbePath".Trim()) { $ProbePath } else { "/$Surface" }) -StatusCode $StatusCode -ErrorBody $ErrorMessage -AppOnly $true
            $hint = if ($rh) { $rh.Hint } else { "$label denied access -- grant the engine SPN the required app-role and re-consent." }
        }
        return [pscustomobject]@{ surface = $Surface; label = $label; status = 'fail'; reachable = [bool]$Reachable
                                  isPermissionFailure = $true; hint = $hint }
    }

    # Not reachable / transport / transient -> a connectivity (not permission) hint.
    $hint = switch ($Surface) {
        'sql'   { 'SQL store unreachable. Check the SQL server name/FQDN, the firewall/VNet rule for this host, and that serverless auto-pause is disabled (persistent compute) so the first request does not cold-start.' }
        'graph' { 'Microsoft Graph unreachable. Check outbound HTTPS to graph.microsoft.com, the engine SPN certificate (LocalMachine\My) and tenant id, and DNS.' }
        'arm'   { 'Azure Resource Manager unreachable. Check outbound HTTPS to management.azure.com and the engine SPN token for the ARM audience.' }
    }
    if ("$ErrorMessage".Trim()) { $hint = "$hint (probe error: " + ("$ErrorMessage" -split "`n")[0] + ')' }
    return [pscustomobject]@{ surface = $Surface; label = $label; status = 'fail'; reachable = [bool]$Reachable
                              isPermissionFailure = $false; hint = $hint }
}

function Get-PimSupportHealthSummary {
    <#
    .SYNOPSIS
        Build the Support health summary from INJECTED state (no live calls).
    .DESCRIPTION
        Pure. Folds the store mode, per-kind tenant-cache freshness, the last
        engine/job run outcome, and the instance identity into one summary object
        the GUI renders and the bundle embeds. Every field is supplied by the caller
        (the Manager reads them from $script:PimStorageMode / Get-PimCacheFreshness /
        Get-PimJobsStatus / $script:PimInstanceName) so this stays unit-testable.
    .PARAMETER StorageMode
        'sql' or 'file' (CSV/local).
    .PARAMETER CacheFreshness
        Hashtable kind->'live'|'stale'|'none' (the Get-PimCacheFreshness shape).
    .PARAMETER LastRun
        @{ name; whenUtc; ok; detail } for the most recent engine/job run, or $null.
    .PARAMETER InstanceName
        The active instance identity (e.g. 'sql:PimPlatform' / 'local' / a tenant key).
    .PARAMETER ManagerVersion
        The running Manager version (for the summary header).
    #>
    [CmdletBinding()]
    param(
        [string]$StorageMode = 'file',
        [hashtable]$CacheFreshness,
        [object]$LastRun,
        [string]$InstanceName = 'local',
        [string]$ManagerVersion = ''
    )
    $mode = if ("$StorageMode".ToLowerInvariant() -eq 'sql') { 'sql' } else { 'file' }

    $cache = [ordered]@{}
    $live = 0; $stale = 0; $none = 0
    if ($CacheFreshness) {
        foreach ($k in $CacheFreshness.Keys) {
            $v = "$($CacheFreshness[$k])"
            $cache[$k] = $v
            switch ($v) { 'live' { $live++ } 'stale' { $stale++ } default { $none++ } }
        }
    }
    # Worst-case cache verdict: any stale -> stale; none present + none live -> none; else live.
    $cacheVerdict = if ($stale -gt 0) { 'stale' } elseif ($live -gt 0) { 'live' } else { 'none' }

    # NB: $lastRun and $LastRun are the SAME variable (PS is case-insensitive), so
    # use a distinct name for the normalised result -- never reassign the parameter.
    $runOut = $null
    if ($LastRun) {
        $ok = $true
        try { if ($null -ne $LastRun.ok) { $ok = [bool]$LastRun.ok } } catch {}
        $runOut = [ordered]@{
            name    = "$($LastRun.name)"
            whenUtc = "$($LastRun.whenUtc)"
            ok      = $ok
            detail  = "$($LastRun.detail)"
        }
    }

    $runStatus = if (-not $runOut) { 'unknown' } elseif ($runOut.ok) { 'green' } else { 'red' }

    [pscustomobject]@{
        managerVersion = "$ManagerVersion"
        instance       = "$InstanceName"
        storeMode      = $mode
        cacheVerdict   = $cacheVerdict
        cacheFreshness = $cache
        cacheLive      = $live
        cacheStale     = $stale
        cacheNone      = $none
        lastRun        = $runOut
        lastRunStatus  = $runStatus
        generatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

function New-PimDiagnosticsBundle {
    <#
    .SYNOPSIS
        Assemble a SANITIZED, shareable diagnostics bundle (handoff for support).
    .DESCRIPTION
        Pure. Folds versions, the connectivity/permission check results, the health
        summary, non-secret config, and recent run outcomes into one object, then runs
        EVERY string value (recursively) through Protect-PimDiagnosticsText so the
        bundle can never carry a secret / cert / token / connection-string / full
        tenant+subscription GUID. Returns @{ object = <redacted hashtable>; text =
        <redacted JSON> } -- the GUI offers the text as a download.
    .PARAMETER Versions
        @{ manager; powershell; dotnet; ... } -- the running versions.
    .PARAMETER Checks
        The array of Get-PimConnectivityCheck results.
    .PARAMETER Health
        The Get-PimSupportHealthSummary object.
    .PARAMETER Config
        Non-secret config to include (hashtable). Redaction still runs over it as defence
        in depth, so even an accidental secret value is masked.
    .PARAMETER RecentRuns
        Array of recent run outcomes (@{ name; whenUtc; ok; detail }).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Versions,
        [object[]]$Checks,
        [object]$Health,
        [hashtable]$Config,
        [object[]]$RecentRuns
    )
    $raw = [ordered]@{
        kind         = 'pim-support-diagnostics'
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        versions     = $(if ($Versions) { $Versions } else { @{} })
        checks       = @($Checks)
        health       = $Health
        config       = $(if ($Config) { $Config } else { @{} })
        recentRuns   = @($RecentRuns)
        note         = 'Sanitized bundle: secrets, certificates, tokens, connection-string credentials, and full tenant/subscription GUIDs are masked. Safe to attach to a support request.'
    }

    # Serialize, then redact the WHOLE serialized form (catches any nested string,
    # including ones the typed walk might miss). ConvertTo-Json is fine here -- the
    # bundle is flat data, not nested JSON-in-a-string.
    $json = $raw | ConvertTo-Json -Depth 12
    $redactedJson = Protect-PimDiagnosticsText -Text $json
    # Re-parse the redacted JSON back into an object so the GUI gets a clean,
    # already-masked structure too (PS 5.1-safe; on any parse hiccup fall back to raw).
    $obj = $null
    try { $obj = $redactedJson | ConvertFrom-Json } catch { $obj = $null }

    [pscustomobject]@{
        object = $obj
        text   = $redactedJson
    }
}
