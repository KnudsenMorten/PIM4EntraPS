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

Write-Host ""
Write-Host ("==== REST error test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
