#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-27 -- a REST failure must report WHY, not just a status code.

    THE DEFECT THIS LOCKS DOWN. Every AzRes create in the session-8 live run failed with,
    verbatim:

        PUT https://management.azure.com/.../roleEligibilityScheduleRequests/...
            -> HTTP 409 :

    The colon is where the reason should be. With only that, every plausible reading was
    wrong -- an orphaned schedule, a duplicate request id, a stale live read, a permanent
    assignment blocking an eligible one -- and each was checked and DISPROVEN with live
    ARM queries. Replaying the identical PUT by hand answered it in one call:

        { "error": { "code": "ReadOnlyDisabledSubscription",
                     "message": "The subscription '...' is disabled and therefore
                                 marked as read only." } }

    The engine had that JSON in its hands and threw it away.

    WHY IT IS WORTH A SUITE. The whole audit rests on believing what the engine reports.
    A scope that reports errors=1 with no cause is indistinguishable from a real code
    defect. In a customer tenant the same log line is a support round-trip, not a fix.
    That is D4.a's lesson -- an assertion that passes while checking nothing -- applied
    to diagnostics.

    Offline: pure string/JSON handling, no network, no tenant.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-Rest.ps1')

Write-Host "=== BUG-27: REST errors must carry their reason ===" -ForegroundColor Cyan
Write-Host ("  (PowerShell {0})" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
Write-Host "`n[the exact body from the live failure]" -ForegroundColor Cyan
# Verbatim shape from the session-8 reproduction, with the ids replaced.
$armBody = '{"error":{"code":"ReadOnlyDisabledSubscription","message":"The subscription ''00000000-0000-0000-0000-000000000000'' is disabled and therefore marked as read only."}}'
$d = Get-PimRestErrorDetail -Body $armBody
T 'the ARM 409 body yields a detail'          ([bool]$d)
T '  ...naming the CODE'                      ($d -match 'ReadOnlyDisabledSubscription')
T '  ...and the human message'                ($d -match 'disabled and therefore marked as read only')
T '  ...and it is NOT the raw JSON'           ($d -notmatch '\{"error"')

# ---------------------------------------------------------------------------
Write-Host "`n[the shapes both APIs actually return]" -ForegroundColor Cyan
$graph = '{"error":{"code":"Request_BadRequest","message":"Invalid value specified for property.","innerError":{"request-id":"abc"}}}'
$dg = Get-PimRestErrorDetail -Body $graph
T 'Graph { error: { code, message } }'        ($dg -match 'Request_BadRequest' -and $dg -match 'Invalid value')
$flat = '{"code":"Conflict","message":"already exists"}'
T 'flat { code, message }'                    ((Get-PimRestErrorDetail -Body $flat) -match 'Conflict' -and (Get-PimRestErrorDetail -Body $flat) -match 'already exists')
$odata = '{"odata.error":{"code":"AuthN","message":{"lang":"en","value":"token expired"}}}'
$do = Get-PimRestErrorDetail -Body $odata
T 'odata { message: { value } } is unwrapped' ($do -match 'AuthN' -and $do -match 'token expired')
$codeOnly = '{"error":{"code":"Throttled"}}'
T 'code with no message still reports'        ((Get-PimRestErrorDetail -Body $codeOnly) -match 'Throttled')
$msgOnly = '{"error":{"message":"something broke"}}'
T 'message with no code still reports'        ((Get-PimRestErrorDetail -Body $msgOnly) -match 'something broke')

# ---------------------------------------------------------------------------
Write-Host "`n[nothing usable must SAY nothing usable, not print an empty reason]" -ForegroundColor Cyan
# This is the whole finding: "HTTP 409 :" reads as "no reason exists".
T 'an EMPTY body yields $null'                ($null -eq (Get-PimRestErrorDetail -Body ''))
T 'a WHITESPACE body yields $null'            ($null -eq (Get-PimRestErrorDetail -Body "  `t `n "))
T 'a $null body yields $null'                 ($null -eq (Get-PimRestErrorDetail -Body $null))
T 'an empty JSON object yields $null'         ($null -eq (Get-PimRestErrorDetail -Body '{}'))
# "HTTP 409 : {}" would be exactly as useless as "HTTP 409 :".
T '  ...it does NOT echo "{}" back'           ((Get-PimRestErrorDetail -Body '{}') -notmatch '\{\}')
# Azure is not consistent about casing; -contains is case-SENSITIVE, so this shape used
# to fall through to printing the raw body.
$capital = '{"Message":"The subscription is disabled.","Code":"Disabled"}'
$dc = Get-PimRestErrorDetail -Body $capital
T 'a capitalised {Message,Code} is understood' ($dc -match 'Disabled' -and $dc -match 'subscription is disabled')
T '  ...and is not the raw JSON'               ($dc -notmatch '"Message"')

# ---------------------------------------------------------------------------
Write-Host "`n[non-JSON is still better than nothing, but bounded]" -ForegroundColor Cyan
$html = '<html><head><title>502 Bad Gateway</title></head><body>   <h1>502</h1>   </body></html>'
$dh = Get-PimRestErrorDetail -Body $html
T 'an HTML error page still yields something' ([bool]$dh -and $dh -match '502')
T '  ...with its whitespace collapsed'        ($dh -notmatch '   ')
$long = '{"error":{"code":"X","message":"' + ('y' * 5000) + '"}}'
$dl = Get-PimRestErrorDetail -Body $long
T 'a 5 KB message is TRUNCATED'               ($dl.Length -lt 500)
T '  ...and says it was truncated'            ($dl.EndsWith('...'))
$longHtml = ('z' * 5000)
T 'a 5 KB non-JSON body is truncated too'     ((Get-PimRestErrorDetail -Body $longHtml).Length -lt 500)

# ---------------------------------------------------------------------------
Write-Host "`n[the body READ takes the longer of the two sources]" -ForegroundColor Cyan
# 🪤 The original code was `if (ErrorDetails.Message) {...} else { read the stream }`.
# On 5.1 ErrorDetails.Message is often PRESENT BUT EMPTY, so the else-branch never ran
# and the stream -- which held the real answer -- was never read. That is how the body
# reached the throw as blank-but-truthy and produced "HTTP 409 :".
function New-FakeErrorRecord {
    param([string]$Details, [string]$Stream)
    $ms = New-Object System.IO.MemoryStream (, [System.Text.Encoding]::UTF8.GetBytes($Stream))
    $resp = [pscustomobject]@{}
    $resp | Add-Member -MemberType ScriptMethod -Name GetResponseStream -Value { $ms }.GetNewClosure()
    [pscustomobject]@{
        ErrorDetails = [pscustomobject]@{ Message = $Details }
        Exception    = [pscustomobject]@{ Response = $resp }
    }
}
$body = Get-PimRestErrorBody -ErrorRecord (New-FakeErrorRecord -Details '' -Stream $armBody)
T 'an EMPTY ErrorDetails does not hide the stream' ((Get-PimRestErrorDetail -Body $body) -match 'ReadOnlyDisabledSubscription')
$body2 = Get-PimRestErrorBody -ErrorRecord (New-FakeErrorRecord -Details $armBody -Stream '')
T 'ErrorDetails alone (PS7 shape) still works'     ((Get-PimRestErrorDetail -Body $body2) -match 'ReadOnlyDisabledSubscription')
$body3 = Get-PimRestErrorBody -ErrorRecord (New-FakeErrorRecord -Details '   ' -Stream $armBody)
T 'a WHITESPACE ErrorDetails does not win'         ((Get-PimRestErrorDetail -Body $body3) -match 'ReadOnlyDisabledSubscription')

# ---------------------------------------------------------------------------
Write-Host "`n[structural: the throw path cannot regress to a bare status code]" -ForegroundColor Cyan
$src = Get-Content -Raw (Join-Path $root 'engine\_shared\PIM-Rest.ps1')
T 'the error path uses the shared body reader'  ($src -match 'Get-PimRestErrorBody -ErrorRecord \$_')
T 'the throw reports code\+message, not the raw body' ($src -match '\$detail = Get-PimRestErrorDetail -Body \$body')
T 'an unreadable body says so EXPLICITLY'       ($src -match 'no error body returned by the service')
# The regression itself: "HTTP $code : $body" is what produced "HTTP 409 :".
T 'the raw body is no longer interpolated into the throw' ($src -notmatch 'HTTP \$code : \$body')
# The retry heuristic must keep working off the body it now reads.
T 'the PrincipalNotFound retry still reads the body' ($src -match 'PrincipalNotFound' -and $src -match '\$isReplDelay')


# ===========================================================================
Write-Host "`n=== SEC-12: an explicit identity that cannot be honoured is an ERROR, not a cue to become somebody else ===" -ForegroundColor Cyan
# ===========================================================================
# 🔴 MEASURED 2026-08-28, and this suite exists for exactly this class. A caller asked for tenant
# f0fa27a0 (myfamilynetwork) + the PIM engine client id + its certificate thumbprint, and got back
# a token for tenant 7825c48b -- ExpertsLiveDK, A DIFFERENT COMPANY -- with a different appid.
# Nothing in the return value said so. The certificate had failed to resolve, the failure went to
# Write-Verbose, and the "dev convenience" az fallback minted a token for whatever subscription
# was the az DEFAULT context.
# 🔑 The defect was never that a fallback exists. It is that it ran AFTER the caller had named a
# tenant, a client id and a credential. Answering that with a different principal is WORSE than an
# error: the token WORKS, so the failure surfaces far away as "Login failed" / "permission denied"
# and reads like an RBAC problem. Same family as BUG-34, which fixed this shape one layer down in
# New-PimSqlConnection and left the az branch here standing.

# --- the token inspectors: asking for a tenant is not the same as being GIVEN one -------------
function New-FakeJwt([string]$tid, [string]$appid) {
    $claims = @{ tid = $tid; appid = $appid } | ConvertTo-Json -Compress
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims)).TrimEnd('=').Replace('+','-').Replace('/','_')
    return "header.$b64.signature"
}
T 'SEC-12: Get-PimTokenTenantId is defined'  ($null -ne (Get-Command Get-PimTokenTenantId -ErrorAction SilentlyContinue))
T 'SEC-12: Get-PimTokenAppId is defined'     ($null -ne (Get-Command Get-PimTokenAppId    -ErrorAction SilentlyContinue))
$jwt = New-FakeJwt 'AAAA1111-0000-0000-0000-000000000000' 'BBBB2222-0000-0000-0000-000000000000'
T '  ...it reads the tid a token CLAIMS'     ((Get-PimTokenTenantId -Token $jwt) -eq 'aaaa1111-0000-0000-0000-000000000000')
T '  ...and the appid'                       ((Get-PimTokenAppId    -Token $jwt) -eq 'bbbb2222-0000-0000-0000-000000000000')
# 🔒 A sanity check must never be the thing that breaks the caller.
T '  ...garbage returns empty rather than throwing' ((Get-PimTokenTenantId -Token 'not-a-jwt') -eq '')
T '  ...and so does an empty string'                ((Get-PimTokenTenantId -Token '') -eq '')

# --- the refusal itself ------------------------------------------------------------------------
# A thumbprint that cannot resolve to a certificate is the ORIGINAL trigger: the request named a
# credential, and the credential could not be loaded.
$sec12msg = ''
try {
    [void](Get-PimRestToken -Resource 'https://database.windows.net' `
            -TenantId '11111111-1111-1111-1111-111111111111' `
            -ClientId '22222222-2222-2222-2222-222222222222' `
            -CertThumbprint 'DEADBEEF00000000000000000000000000000000' -Force)
} catch { $sec12msg = "$($_.Exception.Message)" }
T 'SEC-12: a named-but-unresolvable certificate THROWS instead of falling back' ([bool]$sec12msg)
T '  ...refusing the ambient identity in so many words' ($sec12msg -match 'REFUSING to fall back')
# 🔑 The message has to name the CREDENTIAL. The old failure was unactionable precisely because
# the one fact that explained everything (this cert did not load) was dropped into Write-Verbose.
T '  ...naming the certificate that could not be loaded' ($sec12msg -match 'DEADBEEF')
T '  ...and the identity that was asked for'             ($sec12msg -match '11111111-1111-1111-1111-111111111111' -and $sec12msg -match '22222222-2222-2222-2222-222222222222')
# 🪤 The explicit-identity test must key on the thumbprint REQUESTED, not the certificate
# RESOLVED. Keying on the resolved object is precisely how "the cert is missing" became "no
# explicit identity was asked for" and slid onto the fallback -- the check would evaporate in the
# one case it exists for.
$restSrc = Get-Content -LiteralPath (Join-Path $root 'engine\_shared\PIM-Rest.ps1') -Raw
T '  ...and the check keys on the REQUESTED thumbprint, not the resolved cert object' (
    $restSrc -match '\$explicitIdentity\s*=\s*\[bool\]\("\$tenant"[\s\S]{0,200}?\$thumb')
# 🔒 The refusal must come BEFORE the az fallback in the file, or it cannot prevent anything.
# 🪤 Searched for the literal 'account get-access-token' first and it FAILED against correct
# code: the call is an args array (@('account','get-access-token',…)), so those words are never
# contiguous in the source. *When a source assertion fails, suspect the pattern before the code*
# — this suite's own recorded lesson, earned again.
$idxRefuse = $restSrc.IndexOf('REFUSING to fall back')
$idxAz     = $restSrc.IndexOf("'get-access-token'")
T '  ...and the refusal is placed BEFORE the az fallback (order is the whole guard)' (
    $idxRefuse -gt 0 -and $idxAz -gt 0 -and $idxRefuse -lt $idxAz)

# --- the fallback, when it legitimately runs ---------------------------------------------------
# 🔒 Without --tenant, az answers for its DEFAULT context, which on a machine logged into several
# directories is a coin flip -- and on the dev machine it lands on another company's tenant.
T 'SEC-12: the az fallback passes --tenant when a tenant is known' (
    $restSrc -match "azArgs \+= @\('--tenant'")
# 🔒 ...and verifies what came back. Asking is not receiving.
T '  ...and DISCARDS a token whose tid is not the tenant that was asked for' (
    $restSrc -match 'Get-PimTokenTenantId' -and $restSrc -match 'DISCARDED an az token')
# 🪤 The primary failure reason must be KEPT. It was Write-Verbose only, so the single fact that
# explained every downstream symptom was thrown away at the moment it was known.
T '  ...and the primary auth failure reason is retained, not only Write-Verbose''d' (
    $restSrc -match '\$primaryErr\s*=' -and $restSrc -match 'elseif \(\$primaryErr\)')
Write-Host ""
Write-Host ("==== REST error test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
