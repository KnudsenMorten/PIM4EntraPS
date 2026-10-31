# PIM-LoopbackAnswer.ps1 -- the ONE wait for a browser sign-in's answer on the localhost loopback (auth code + PKCE).
# Used by every PIM browser sign-in: the REST library's own (signed-in setup scripts), the mail setup (Initialize-PimMailSender,
# Set-PimSmtpRelayPassword, Set-PimSqlTier), the engine-permissions grant and the Activator deploy scripts. The tools load the
# identical copy in tools\setup (they may not load engine files). Build-PimSupportScripts inlines it into each published script.
#
# Owner 2026-10-30/31 ("people are reporting this error" -- "This site can't be reached"; "yes fix the sign-in page in all
# scripts"), the same fix as Invardia's Wait-AuthCode: the old loops took the FIRST request -- often the browser's preload
# of the address or its icon request -- and a request that never sent a line held the loop, and once the answer came the
# listener stopped at once, so the browser's real load or a reload got "This site can't be reached". Now:
#   1. only a request whose query carries code= or error= is the answer; the loop goes on until one comes;
#   2. EVERY request gets a page (waiting / signed in / failed), never a closed connection;
#   3. after the answer the listener keeps answering for -GraceSeconds (10), so a second load shows "Signed in" too;
#   4. it throws only when no answer came within -Seconds.
# A connection that sends nothing (a speculative preconnect) is dropped after -ReadTimeoutMs and never blocks the loop.

function Test-PimLoopbackAnswerQuery {
    # PURE. Is this request line the sign-in's answer? Returns the query string ('' when not).
    param([AllowEmptyString()][AllowNull()][string]$RequestLine)
    $m = [regex]::Match("$RequestLine", '^GET /[^?\s]*\?(?<q>\S+) HTTP')
    if (-not $m.Success) { return '' }
    $q = $m.Groups['q'].Value
    if ($q -match '(^|&)(code|error)=') { return $q }
    return ''
}

function Get-PimLoopbackPage {
    # PURE. The page for one request: before the answer 'waiting', after it 'done' (or 'failed' when the answer is an error).
    param([ValidateSet('waiting', 'done', 'failed')][string]$Kind, [string]$ReturnTo = 'PowerShell', [string]$ErrorText = '')
    $body = switch ($Kind) {
        'waiting' { '<h3>Waiting for the sign-in...</h3>Finish the sign-in in the other tab.' }
        'done'    { "<h3>Sign-in complete.</h3>You can close this tab and return to $([System.Net.WebUtility]::HtmlEncode($ReturnTo))." }
        'failed'  { "<h3>Sign-in failed</h3>$([System.Net.WebUtility]::HtmlEncode($ErrorText))<br>Return to $([System.Net.WebUtility]::HtmlEncode($ReturnTo))." }
    }
    "<html><head><meta charset=`"utf-8`"></head><body style=`"font-family:sans-serif`">$body</body></html>"
}

function Wait-PimLoopbackAnswer {
    <#
      Waits on the loopback listener(s) (TcpListener, started by the caller; both loopbacks may share one port) for the
      sign-in's answer and returns its raw query string. Throws only when no answer came within -Seconds. The caller still
      checks state / error / code and stops the listeners (this function does not stop them).
    #>
    param([Parameter(Mandatory)][object[]]$Listeners, [int]$Seconds = 300, [int]$GraceSeconds = 10, [int]$ReadTimeoutMs = 2000,
          [string]$ReturnTo = 'PowerShell', [string]$TimeoutMessage = '')
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds); $graceEnd = $null
    $answer = $null; $kind = 'waiting'; $errText = ''
    while ($true) {
        $now = [DateTime]::UtcNow
        if ($answer) { if ($now -ge $graceEnd) { break } } elseif ($now -ge $deadline) { break }
        $ready = @($Listeners | Where-Object { $_.Pending() })[0]
        if (-not $ready) { Start-Sleep -Milliseconds 100; continue }
        $client = $null
        try {
            $client = $ready.AcceptTcpClient()
            $client.ReceiveTimeout = $ReadTimeoutMs
            $stream = $client.GetStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $line = $null
            try { $line = $reader.ReadLine() } catch { $line = $null }   # a connection that sends nothing: dropped, never waited on
            if ($null -eq $line) { continue }
            if (-not $answer) {
                $q = Test-PimLoopbackAnswerQuery -RequestLine $line
                if ($q) {
                    $answer = $q; $graceEnd = [DateTime]::UtcNow.AddSeconds($GraceSeconds)
                    if ($q -match '(^|&)error=') {
                        $kind = 'failed'
                        $d = [regex]::Match($q, '(^|&)error_description=(?<d>[^&]*)')
                        $errText = if ($d.Success) { [uri]::UnescapeDataString(($d.Groups['d'].Value -replace '\+', ' ')) } else { '' }
                    } else { $kind = 'done' }
                }
            }
            $html = Get-PimLoopbackPage -Kind $kind -ReturnTo $ReturnTo -ErrorText $errText
            $bytes = [Text.Encoding]::UTF8.GetBytes($html)
            $head = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
            $stream.Write($head, 0, $head.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
        } catch { }   # a browser that closed the connection itself: nothing to answer
        finally { if ($client) { try { $client.Close() } catch { } } }
    }
    if (-not $answer) {
        throw $(if ("$TimeoutMessage".Trim()) { $TimeoutMessage } else { "Timed out ($([int]($Seconds / 60)) minutes) waiting for the browser to finish the sign-in." })
    }
    return $answer
}
