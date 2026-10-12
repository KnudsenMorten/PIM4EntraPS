#Requires -Version 5.1
<#
.SYNOPSIS
  100.91 / 100.79 (4a) -- "GET SUPPORT": PIM Manager opens a support ticket at Invardia, from the Manager SERVER.

.DESCRIPTION
  Contract (Invardia, live): POST https://invardia.com/api/mcp/v1 -- MCP Streamable HTTP in plain-JSON mode (JSON-RPC 2.0,
  no SSE, no session), header X-Invardia-Install-Key = this install's own key. Tools used here:
    ticket_create { title, text, category, priority?, userName, userEmail, productVersion, ring, sourceRef?, logExcerpt? }
        -> { ticketId, ticketNumber, portalUrl, uploadLink { page, api } }     (a known sourceRef returns the same ticket)
    ticket_list {}                                                              (this environment's tickets only)
  A failure has ONE shape: { error: { code, message, fields? } }.

  THE RULES THIS FILE HOLDS (tests/Test-PimSupportTicket.ps1):
    * The install key is read on the server (Resolve-PimSetupInstallKey: the secret PIM_UPLINK_KEY, else pim.Settings
      'InvardiaInstallKey') and goes into ONE place: the request header. It is in no body this file returns -- every body
      is swept for it once more before it leaves (Remove-PimSupportInstallKey), so a reply that echoes it cannot leak it.
    * The endpoint is a CONSTANT. No setting can point the install key at another address, and a redirect is not followed.
    * Every free text that is sent (title, text, log excerpt) goes through the support bundle's redactor
      (Protect-PimDiagnosticsText, PIM-AuthDiagnostics.ps1) -- when the draft is built, so the person SEES what is sent,
      and again when it is sent, so an edit cannot put a secret back. The redactor missing = the text is withheld.
    * Admin + SuperAdmin only (the caller passes -IsAdmin from Test-PimManagerRoleAtLeast -Minimum 'Admin').
    * No install key = no ticket path: the answer is the public support page and the contact address.
    * Nothing here throws to the page: no network, a timeout or an error reply is a plain message.

  Everything is PURE or takes its I/O as a seam (-Http, -GetSetting, -GetRunLog), like PIM-LicenceRequest.ps1. Plain
  scriptblocks only -- never .GetNewClosure() (a closure cannot see the dot-sourced store functions).
#>

$script:PimSupportEndpoint   = 'https://invardia.com/api/mcp/v1'
$script:PimSupportKeyHeader  = 'X-Invardia-Install-Key'
$script:PimSupportCategories = @('install', 'update', 'sign-in', 'data', 'performance', 'other')
$script:PimSupportPriorities = @('P1', 'P2', 'P3')
$script:PimSupportLogMax     = 20000      # contract: logExcerpt <= 20000 chars
$script:PimSupportTextMax    = 20000
$script:PimSupportTitleMax   = 200
$script:PimSupportContact    = 'info@invardia.com'
$script:PimSupportRpcId      = 0

function Get-PimSupportEndpoint { return $script:PimSupportEndpoint }
function Get-PimSupportCategories { return @($script:PimSupportCategories) }
function Get-PimSupportPriorities { return @($script:PimSupportPriorities) }

function Get-PimSupportPublicUrl {
    <# The public support page: the ONE constant PIM-License.ps1 already holds ($script:PimProSupportUrl) when it is loaded. #>
    $u = "$script:PimProSupportUrl".Trim()
    if ($u -match '^https://') { return $u }
    return 'https://portal.invardia.com'
}

function Get-PimSupportField {
    # PURE. A property of a PSCustomObject or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Protect-PimSupportText {
    <#
      PURE. Free text -> the text that may leave the install. The install key first (its literal value, then anything of
      its shape -- the rule the uplink already uses), then the support bundle's redactor, Protect-PimDiagnosticsText:
      passwords, secrets, tokens, connection strings, SAS signatures, PEM blocks, thumbprints; ids keep their first 8.
      FAIL CLOSED: without the redactor nothing is returned but a line that says so.
    #>
    param([AllowNull()][string]$Text, [AllowNull()][string]$InstallKey)
    $t = "$Text"
    if (-not $t) { return '' }
    $k = "$InstallKey".Trim()
    if ($k) { $t = $t.Replace($k, '[install-key]') }
    $t = [regex]::Replace($t, 'inv-[A-Za-z0-9_-]{20,}', '[install-key]')
    if (-not (Get-Command Protect-PimDiagnosticsText -ErrorAction SilentlyContinue)) { return '(withheld: the redaction step is not available in this build, so nothing was copied)' }
    return (Protect-PimDiagnosticsText -Text $t)
}

function Get-PimSupportLogTail {
    <# PURE. The LAST lines of a log, at most -MaxLines and -MaxChars (the end of a failed run says why it failed). #>
    param([AllowNull()][string]$Text, [int]$MaxLines = 200, [int]$MaxChars = 20000)
    $t = ("$Text" -replace "`r`n", "`n").TrimEnd()
    if (-not $t) { return '' }
    $lines = @($t -split "`n")
    $cut = $false
    if ($lines.Count -gt $MaxLines) { $lines = @($lines[($lines.Count - $MaxLines)..($lines.Count - 1)]); $cut = $true }
    $note = '(earlier lines left out)'
    $out = ($lines -join "`n")
    $room = $MaxChars - $note.Length - 1
    if ($out.Length -gt $room) { $out = $out.Substring($out.Length - $room); $cut = $true }
    if ($cut) { $out = $note + "`n" + $out }
    return $out
}

function ConvertTo-PimSupportRefPart {
    # PURE. One part of a sourceRef: letters, digits, dot, dash, underscore; at most 80 chars.
    param([AllowNull()][string]$Value)
    $v = ("$Value".Trim() -replace '[^A-Za-z0-9._-]', '_')
    if ($v.Length -gt 80) { $v = $v.Substring(0, 80) }
    return $v
}

function Get-PimSupportContext {
    <#
      PURE. What the PAGE says about where the person is stuck -> a bounded, plain context. Nothing in it is trusted:
      every value is cut to a length, and kind is one of help | job | setup | get-started | error.
        job          jobName + runId        (Scheduler: a failed run)
        setup        ids[] + message        (Overview: setup-health lines)
        get-started  stepId + message       (Get Started: a step that does not go through)
        error        page + message
        help         page                   (Support page: nothing failed)
    #>
    param([AllowNull()][object]$Context)
    $cut = { param($v, $n) $s = "$v".Trim(); if ($s.Length -gt $n) { $s = $s.Substring(0, $n) }; $s }
    $kind = "$(Get-PimSupportField $Context 'kind')".Trim().ToLowerInvariant()
    if ($kind -notin @('job', 'setup', 'get-started', 'error')) { $kind = 'help' }
    $ids = @()
    foreach ($i in @(Get-PimSupportField $Context 'ids')) { $p = ConvertTo-PimSupportRefPart "$i"; if ($p -and $ids.Count -lt 5) { $ids += $p } }
    return [ordered]@{
        kind    = $kind
        page    = (& $cut (Get-PimSupportField $Context 'page') 100)
        jobName = (ConvertTo-PimSupportRefPart "$(Get-PimSupportField $Context 'jobName')")
        runId   = (ConvertTo-PimSupportRefPart "$(Get-PimSupportField $Context 'runId')")
        stepId  = (ConvertTo-PimSupportRefPart "$(Get-PimSupportField $Context 'stepId')")
        ids     = @($ids | Sort-Object -Unique)
        message = (& $cut (Get-PimSupportField $Context 'message') 4000)
    }
}

function Get-PimSupportSourceRef {
    <#
      PURE. The stable id of the failing thing -- Invardia answers a second ticket_create with the same sourceRef with the
      ticket that already exists. '' = nothing failed (a question from the Support page is a new ticket every time).
        pim-manager:job:<job name>:<run id>    pim-manager:setup:<control ids>    pim-manager:get-started:<step id>
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Context)
    switch ("$($Context.kind)") {
        'job'         { if ($Context.jobName -and $Context.runId) { return "pim-manager:job:$($Context.jobName):$($Context.runId)" } }
        'setup'       { if (@($Context.ids).Count) { return "pim-manager:setup:$(@($Context.ids) -join '+')" } }
        'get-started' { if ($Context.stepId) { return "pim-manager:get-started:$($Context.stepId)" } }
    }
    return ''
}

function Get-PimSupportCategoryGuess {
    # PURE. A first guess the person can change: an update job -> update; a setup / Get Started finding -> install.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Context)
    if ("$($Context.kind)" -eq 'job' -and "$($Context.jobName)" -match '(?i)update') { return 'update' }
    if ("$($Context.kind)" -in @('setup', 'get-started')) { return 'install' }
    return 'other'
}

function New-PimSupportTicketDraft {
    <#
      The draft the person edits: @{ title; text; category; priority; userName; userEmail; productVersion; ring;
      sourceRef; logExcerpt }. From a failed job it carries the run's last log lines (-GetRunLog { param($RunId) -> a run
      record with name / status / startedUtc / finishedUtc / log }). Title, text and log excerpt are ALREADY redacted here,
      so what the form shows is what would be sent.
    #>
    param([AllowNull()][object]$Context, [string]$Version = '', [AllowNull()][object]$Ring = $null, [string]$UserName = '',
          [string]$UserEmail = '', [string]$InstallKey = '', [scriptblock]$GetRunLog)
    $c = Get-PimSupportContext -Context $Context
    $where = ''; $title = ''; $log = ''; $status = ''
    switch ($c.kind) {
        'job' {
            $rec = $null
            if ($GetRunLog -and $c.runId) { try { $rec = & $GetRunLog $c.runId } catch { $rec = $null } }
            # the run record names its job: a job name the page sent is only used when the run is not found
            if ($rec -and "$(Get-PimSupportField $rec 'name')".Trim()) { $c.jobName = ConvertTo-PimSupportRefPart "$(Get-PimSupportField $rec 'name')" }
            $title = "Job '$($c.jobName)' failed"
            $where = "Scheduler > job '$($c.jobName)'$(if ($c.runId) { ", run $($c.runId)" })"
            if ($rec) {
                $status = "Run status: $(Get-PimSupportField $rec 'status'); started $(Get-PimSupportField $rec 'startedUtc'); finished $(Get-PimSupportField $rec 'finishedUtc')"
                $log = Get-PimSupportLogTail -Text "$(Get-PimSupportField $rec 'log')" -MaxChars ($script:PimSupportLogMax - 500)
            }
        }
        'setup'       { $title = 'Setup health: a finding I cannot solve'; $where = "Overview > what needs your attention$(if (@($c.ids).Count) { " ($(@($c.ids) -join ', '))" })" }
        'get-started' { $title = "Get Started: step '$($c.stepId)' does not go through"; $where = "Get Started > step '$($c.stepId)'" }
        'error'       { $title = "An error on the page '$($c.page)'"; $where = "Page '$($c.page)'" }
        default       { $title = ''; $where = $(if ($c.page) { "Page '$($c.page)'" } else { '' }) }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('What happened, and what did you expect?')
    $lines.Add('(write it here)')
    $lines.Add('')
    if ($where)     { $lines.Add("Where: $where") }
    if ($status)    { $lines.Add($status) }
    if ($c.message) { $lines.Add("What the page said: $($c.message)") }
    $lines.Add("PIM Manager version $Version$(if ($null -ne $Ring -and "$Ring" -ne '') { ", ring $Ring" })")
    $mail = "$UserEmail".Trim()
    if ($mail -notmatch '^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$') { $mail = '' }
    return [ordered]@{
        title          = (Protect-PimSupportText -Text $title -InstallKey $InstallKey)
        text           = (Protect-PimSupportText -Text ($lines -join "`n") -InstallKey $InstallKey)
        category       = (Get-PimSupportCategoryGuess -Context $c)
        priority       = 'P3'
        userName       = "$UserName"
        userEmail      = $mail
        productVersion = "$Version"
        ring           = $Ring
        sourceRef      = (Get-PimSupportSourceRef -Context $c)
        logExcerpt     = (Protect-PimSupportText -Text $log -InstallKey $InstallKey)
    }
}

function New-PimSupportTicketArguments {
    <#
      PURE. What the person pressed Send on -> the ticket_create arguments: @{ ok; arguments; fields }. fields = one plain
      message per field that is wrong (nothing is sent then). The redaction runs AGAIN here. userName, productVersion,
      ring and sourceRef are the SERVER's values -- the page cannot send a ticket as somebody else or for another version.
    #>
    param([AllowNull()][object]$Fields, [AllowNull()][object]$Context, [string]$Version = '', [AllowNull()][object]$Ring = $null,
          [string]$UserName = '', [string]$InstallKey = '')
    $bad = [ordered]@{}
    $title = (Protect-PimSupportText -Text "$(Get-PimSupportField $Fields 'title')".Trim() -InstallKey $InstallKey)
    $text  = (Protect-PimSupportText -Text "$(Get-PimSupportField $Fields 'text')".Trim() -InstallKey $InstallKey)
    $mail  = "$(Get-PimSupportField $Fields 'userEmail')".Trim()
    $cat   = "$(Get-PimSupportField $Fields 'category')".Trim().ToLowerInvariant()
    $prio  = "$(Get-PimSupportField $Fields 'priority')".Trim().ToUpperInvariant()
    if (-not $title) { $bad['title'] = 'Give the ticket a title.' }
    elseif ($title.Length -gt $script:PimSupportTitleMax) { $bad['title'] = "The title is too long (at most $($script:PimSupportTitleMax) characters)." }
    if (-not $text) { $bad['text'] = 'Describe what happened.' }
    elseif ($text.Length -gt $script:PimSupportTextMax) { $bad['text'] = "The description is too long (at most $($script:PimSupportTextMax) characters). Put long output in the log excerpt, or upload it after the ticket is created." }
    if ($mail -notmatch '^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$') { $bad['userEmail'] = 'Enter the e-mail address of a real mailbox -- the answer is sent there.' }
    if (-not $cat) { $cat = 'other' }
    if ($cat -notin $script:PimSupportCategories) { $bad['category'] = "Choose a category: $($script:PimSupportCategories -join ', ')." }
    if (-not $prio) { $prio = 'P3' }
    if ($prio -notin $script:PimSupportPriorities) { $bad['priority'] = "Choose a priority: $($script:PimSupportPriorities -join ', ')." }
    if ($bad.Count) { return @{ ok = $false; arguments = $null; fields = $bad } }
    $c = Get-PimSupportContext -Context $Context
    $a = [ordered]@{ title = $title; text = $text; category = $cat; priority = $prio
                     userName = $(if ("$UserName".Trim()) { "$UserName".Trim() } else { $mail }); userEmail = $mail; productVersion = "$Version" }
    # ring 0-3: sent when this environment knows its ring; an unknown ring is left out, never guessed
    $r = 0
    if ($null -ne $Ring -and [int]::TryParse("$Ring", [ref]$r) -and $r -ge 0 -and $r -le 3) { $a['ring'] = $r }
    $ref = Get-PimSupportSourceRef -Context $c
    if ($ref) { $a['sourceRef'] = $ref }
    $log = (Protect-PimSupportText -Text "$(Get-PimSupportField $Fields 'logExcerpt')" -InstallKey $InstallKey).Trim()
    if ($log.Length -gt $script:PimSupportLogMax) { $log = $log.Substring($log.Length - $script:PimSupportLogMax) }
    if ($log) { $a['logExcerpt'] = $log }
    return @{ ok = $true; arguments = $a; fields = $null }
}

function New-PimSupportRpcBody {
    <# PURE. One JSON-RPC 2.0 tools/call request. #>
    param([Parameter(Mandatory)][string]$Tool, [AllowNull()][System.Collections.IDictionary]$Arguments, [int]$Id = 1)
    return [ordered]@{ jsonrpc = '2.0'; id = $Id; method = 'tools/call'
                       params = [ordered]@{ name = $Tool; arguments = $(if ($Arguments) { $Arguments } else { [ordered]@{} }) } }
}

function ConvertFrom-PimSupportReply {
    <#
      PURE. An HTTP answer (@{ status; text; error }) -> @{ ok; data; error = @{ code; message; fields } }.
      Read in this order: no answer; the contract's failure shape { error: { code, message, fields? } } at the top (also a
      JSON-RPC error); the tool result -- result.structuredContent, else the JSON in result.content[].text -- which may
      itself be that failure shape; result.isError; a non-2xx status. Never throws.
    #>
    param([AllowNull()][object]$Reply)
    $status = 0; try { $status = [int]"0$(Get-PimSupportField $Reply 'status')" } catch { $status = 0 }
    $text = "$(Get-PimSupportField $Reply 'text')".Trim()
    $fail = { param($code, $msg, $fields) @{ ok = $false; data = $null; error = @{ code = "$code"; message = "$msg"; fields = $fields } } }
    if ($status -eq 0) { return (& $fail 'unreachable' "Invardia could not be reached$(if ("$(Get-PimSupportField $Reply 'error')") { " ($(Get-PimSupportField $Reply 'error'))" })." $null) }
    # a server that answers one JSON message as an event stream: the last data: line is the message
    if ($text -match '(?m)^data:\s*\{') { $text = "$(@([regex]::Matches($text, '(?m)^data:\s*(\{.*)$') | ForEach-Object { $_.Groups[1].Value }) | Select-Object -Last 1)".Trim() }
    $doc = $null
    if ($text) { try { $doc = ConvertFrom-Json -InputObject $text -ErrorAction Stop } catch { $doc = $null } }
    $asError = { param($o)
        $e = Get-PimSupportField $o 'error'
        if ($null -eq $e) { return $null }
        if ($e -is [string]) { return @{ code = 'error'; message = $e; fields = $null } }
        return @{ code = "$(Get-PimSupportField $e 'code')"; message = "$(Get-PimSupportField $e 'message')"; fields = (Get-PimSupportField $e 'fields') } }
    if ($null -ne $doc) {
        $e = & $asError $doc
        if ($e) { return (& $fail $e.code $(if ($e.message) { $e.message } else { "Invardia refused the request (HTTP $status)." }) $e.fields) }
        $res = Get-PimSupportField $doc 'result'
        if ($null -ne $res) {
            $data = Get-PimSupportField $res 'structuredContent'
            $plain = ''
            if ($null -eq $data) {
                foreach ($part in @(Get-PimSupportField $res 'content')) {
                    $pt = "$(Get-PimSupportField $part 'text')".Trim()
                    if (-not $pt) { continue }
                    if (-not $plain) { $plain = $pt }
                    if ($pt.StartsWith('{') -or $pt.StartsWith('[')) { try { $data = ConvertFrom-Json -InputObject $pt -ErrorAction Stop; break } catch { $data = $null } }
                }
            }
            $e = & $asError $data
            if ($e) { return (& $fail $e.code $(if ($e.message) { $e.message } else { 'Invardia refused the request.' }) $e.fields) }
            if ([bool](Get-PimSupportField $res 'isError')) { return (& $fail 'error' $(if ($plain) { $plain } else { 'Invardia refused the request.' }) $null) }
            if ($status -ge 200 -and $status -lt 300 -and $null -ne $data) { return @{ ok = $true; data = $data; error = $null } }
        }
    }
    if ($status -eq 401 -or $status -eq 403) { return (& $fail 'unauthorized' "Invardia did not accept this installation's install key (HTTP $status)." $null) }
    if ($status -lt 200 -or $status -ge 300) { return (& $fail "http-$status" "Invardia answered HTTP $status." $null) }
    return (& $fail 'bad-reply' 'Invardia answered, but not with something PIM Manager can read.' $null)
}

function Invoke-PimSupportHttp {
    <#
      The real HTTP seam: POST JSON -> @{ status; text; error }. .NET HttpClient (PowerShell 7 and Windows PowerShell 5.1),
      30 s timeout, a non-2xx answer is READ (its body is the contract's error), never thrown. A redirect is NOT followed:
      the install key header goes to the address it was meant for and nowhere else.
    #>
    param([Parameter(Mandatory)][string]$Url, [hashtable]$Headers, [string]$BodyJson = '{}', [int]$TimeoutSec = 30)
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
    $handler = $null; $client = $null
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $msg = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $Url)
        if ($Headers) { foreach ($k in $Headers.Keys) { [void]$msg.Headers.TryAddWithoutValidation("$k", "$($Headers[$k])") } }
        $msg.Content = New-Object System.Net.Http.StringContent($BodyJson, [System.Text.Encoding]::UTF8, 'application/json')
        $r = $client.SendAsync($msg).GetAwaiter().GetResult()
        $t = $r.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return @{ status = [int]$r.StatusCode; text = "$t" }
    } catch {
        $m = "$($_.Exception.GetBaseException().Message)"
        if ($_.Exception.GetBaseException() -is [System.Threading.Tasks.TaskCanceledException]) { $m = "no answer within $TimeoutSec seconds" }
        return @{ status = 0; text = ''; error = $m }
    } finally {
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
    }
}

function Invoke-PimSupportTool {
    <#
      One tools/call at Invardia. Seam: -Http { param($Url, $Headers, $BodyJson) -> @{ status; text; error } }.
      Returns ConvertFrom-PimSupportReply's shape. The install key is in the header and nowhere else. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$Tool,
          [AllowNull()][System.Collections.IDictionary]$Arguments)
    $script:PimSupportRpcId = [int]$script:PimSupportRpcId + 1
    $json = ConvertTo-Json -InputObject (New-PimSupportRpcBody -Tool $Tool -Arguments $Arguments -Id $script:PimSupportRpcId) -Depth 8 -Compress
    # MCP Streamable HTTP: the client names both types; this server answers plain JSON
    $headers = @{ $script:PimSupportKeyHeader = $InstallKey; 'Accept' = 'application/json, text/event-stream' }
    $reply = $null
    try { $reply = & $Http $script:PimSupportEndpoint $headers $json } catch { $reply = @{ status = 0; text = ''; error = "$($_.Exception.Message)" } }
    return (ConvertFrom-PimSupportReply -Reply $reply)
}

function ConvertTo-PimSupportSafeUrl {
    <# PURE. A link Invardia returned is shown ONLY when it is https on invardia.com or one of its subdomains; else ''. #>
    param([AllowNull()][string]$Url)
    $u = $null
    if (-not [uri]::TryCreate("$Url".Trim(), [System.UriKind]::Absolute, [ref]$u)) { return '' }
    if ($u.Scheme -ne 'https') { return '' }
    $h = $u.Host.ToLowerInvariant()
    if ($h -ne 'invardia.com' -and -not $h.EndsWith('.invardia.com')) { return '' }
    return $u.AbsoluteUri
}

function Remove-PimSupportInstallKey {
    <# PURE. The last sweep before a body goes to the browser: the install key, wherever a string carries it, is replaced. #>
    param([AllowNull()][object]$Value, [AllowNull()][string]$InstallKey)
    $k = "$InstallKey".Trim()
    if (-not $k -or $null -eq $Value) { return $Value }
    if ($Value -is [string]) { return $Value.Replace($k, '[install-key]') }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($n in @($Value.Keys)) { $o["$n"] = Remove-PimSupportInstallKey -Value $Value[$n] -InstallKey $k }
        return $o
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = Remove-PimSupportInstallKey -Value $p.Value -InstallKey $k }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Value) { $l.Add((Remove-PimSupportInstallKey -Value $i -InstallKey $k)) }
        return , @($l.ToArray())
    }
    return $Value
}

function ConvertTo-PimSupportTicketRows {
    <#
      PURE. A ticket_list answer -> rows for the page: @{ ticketNumber; title; status; priority; updated; portalUrl }.
      The list is taken from the answer itself, or its tickets / items; at most 50 rows; a link only when it is Invardia's.
    #>
    param([AllowNull()][object]$Data)
    $list = $Data
    foreach ($n in 'tickets', 'items') { $v = Get-PimSupportField $Data $n; if ($null -ne $v) { $list = $v; break } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($list)) {
        if ($null -eq $t -or $t -is [string] -or $rows.Count -ge 50) { continue }
        $num = "$(Get-PimSupportField $t 'ticketNumber')".Trim()
        if (-not $num) { continue }
        $when = $null
        foreach ($n in 'updatedAt', 'updatedUtc', 'createdAt', 'createdUtc') { $when = Get-PimSupportField $t $n; if ($null -ne $when -and "$when") { break } }
        if ($when -is [datetime]) { $when = $when.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $rows.Add([ordered]@{ ticketNumber = $num; title = "$(Get-PimSupportField $t 'title')"; status = "$(Get-PimSupportField $t 'status')"
                              priority = "$(Get-PimSupportField $t 'priority')"; updated = "$when"
                              portalUrl = (ConvertTo-PimSupportSafeUrl "$(Get-PimSupportField $t 'portalUrl')") })
    }
    return , @($rows.ToArray())
}

function Invoke-PimSupportApi {
    <#
      THE four Manager routes, as one decision the Manager only wraps (and the tests call without a listener):
        status  GET  /api/support/ticket         any signed-in role: is there a ticket path here, and may I use it
        draft   POST /api/support/ticket/draft   Admin+: the pre-filled, already redacted draft for a context
        create  POST /api/support/ticket         Admin+: send what the person edited -> ticket number + links
        list    GET  /api/support/tickets        Admin+: this environment's tickets
      Returns @{ status = <HTTP status>; body = <ordered>; audit = <ordered or $null> }. The body never holds the install
      key. Seams: -GetSetting { param($Name) } (pim.Settings), -Http (Invoke-PimSupportTool), -GetRunLog { param($RunId) }.
    #>
    param([Parameter(Mandatory)][ValidateSet('status', 'draft', 'create', 'list')][string]$Action,
          [bool]$IsAdmin = $false, [scriptblock]$GetSetting, [scriptblock]$Http, [AllowNull()][object]$Body,
          [string]$Version = '', [AllowNull()][object]$Ring = $null, [string]$UserName = '', [scriptblock]$GetRunLog)
    $key = ''
    if (Get-Command Resolve-PimSetupInstallKey -ErrorAction SilentlyContinue) { try { $key = "$(Resolve-PimSetupInstallKey -GetSetting $GetSetting)".Trim() } catch { $key = '' } }
    $link = [ordered]@{ supportUrl = (Get-PimSupportPublicUrl); contact = $script:PimSupportContact }
    $done = { param($Status, $B, $Audit) @{ status = $Status; body = (Remove-PimSupportInstallKey -Value $B -InstallKey $key); audit = $Audit } }
    $mail = "$UserName".Trim(); if ($mail -notmatch '^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$') { $mail = '' }

    if ($Action -eq 'status') {
        return (& $done 200 ([ordered]@{ available = [bool]$key; canCreate = [bool]($key -and $IsAdmin); supportUrl = $link.supportUrl; contact = $link.contact
            productVersion = "$Version"; ring = $Ring; categories = @($script:PimSupportCategories); priorities = @($script:PimSupportPriorities); logMax = $script:PimSupportLogMax
            reason = $(if (-not $key) { 'This installation has no Invardia install key, so a ticket cannot be opened from PIM Manager. Use the support page instead.' }
                       elseif (-not $IsAdmin) { 'Only an Admin or a SuperAdmin can open a support ticket from PIM Manager.' } else { '' }) }) $null)
    }
    if (-not $IsAdmin) {
        return (& $done 403 ([ordered]@{ ok = $false; error = 'Only an Admin or a SuperAdmin can open a support ticket from PIM Manager. Ask one of them, or use the support page.'; supportUrl = $link.supportUrl; contact = $link.contact }) $null)
    }
    if (-not $key) {
        return (& $done 409 ([ordered]@{ ok = $false; noInstallKey = $true; error = 'This installation has no Invardia install key, so a ticket cannot be opened from PIM Manager. Use the support page instead.'; supportUrl = $link.supportUrl; contact = $link.contact }) $null)
    }
    $unreachable = 'Try again in a moment, or use the support page.'

    if ($Action -eq 'draft') {
        $d = New-PimSupportTicketDraft -Context (Get-PimSupportField $Body 'context') -Version $Version -Ring $Ring -UserName $UserName -UserEmail $mail -InstallKey $key -GetRunLog $GetRunLog
        return (& $done 200 ([ordered]@{ ok = $true; draft = $d }) $null)
    }
    if (-not $Http) { return (& $done 500 ([ordered]@{ ok = $false; error = 'The support call is not available in this build.'; supportUrl = $link.supportUrl; contact = $link.contact }) $null) }

    if ($Action -eq 'list') {
        $r = Invoke-PimSupportTool -Http $Http -InstallKey $key -Tool 'ticket_list' -Arguments ([ordered]@{})
        if (-not $r.ok) { return (& $done 502 ([ordered]@{ ok = $false; code = "$($r.error.code)"; error = "The tickets could not be read: $($r.error.message)"; supportUrl = $link.supportUrl; contact = $link.contact }) $null) }
        return (& $done 200 ([ordered]@{ ok = $true; tickets = (ConvertTo-PimSupportTicketRows -Data $r.data) }) $null)
    }

    # create
    $ctx = Get-PimSupportField $Body 'context'
    if ("$(Get-PimSupportField $ctx 'kind')".Trim().ToLowerInvariant() -eq 'job' -and $GetRunLog) {
        # the sourceRef names the run's OWN job (the same rule as the draft), so both clicks give one ticket
        $rid = ConvertTo-PimSupportRefPart "$(Get-PimSupportField $ctx 'runId')"
        $rec = $null; if ($rid) { try { $rec = & $GetRunLog $rid } catch { $rec = $null } }
        if ($rec -and "$(Get-PimSupportField $rec 'name')".Trim()) { $ctx = [ordered]@{ kind = 'job'; runId = $rid; jobName = "$(Get-PimSupportField $rec 'name')" } }
    }
    $a = New-PimSupportTicketArguments -Fields $Body -Context $ctx -Version $Version -Ring $Ring -UserName $UserName -InstallKey $key
    if (-not $a.ok) { return (& $done 400 ([ordered]@{ ok = $false; error = 'The ticket was not sent: some fields need your attention.'; fields = $a.fields }) $null) }
    $r = Invoke-PimSupportTool -Http $Http -InstallKey $key -Tool 'ticket_create' -Arguments $a.arguments
    if (-not $r.ok) {
        $msg = "The ticket was not created: $($r.error.message)"
        if ("$($r.error.code)" -eq 'unreachable') { $msg = "$msg $unreachable" }
        return (& $done 502 ([ordered]@{ ok = $false; code = "$($r.error.code)"; error = $msg; fields = $r.error.fields; supportUrl = $link.supportUrl; contact = $link.contact }) $null)
    }
    $num = "$(Get-PimSupportField $r.data 'ticketNumber')".Trim()
    if (-not $num) { return (& $done 502 ([ordered]@{ ok = $false; code = 'bad-reply'; error = 'Invardia answered without a ticket number, so PIM Manager cannot tell whether the ticket exists. Check the support page before you send it again.'; supportUrl = $link.supportUrl; contact = $link.contact }) $null) }
    $out = [ordered]@{ ok = $true; ticketNumber = $num; ticketId = "$(Get-PimSupportField $r.data 'ticketId')"
                       portalUrl = (ConvertTo-PimSupportSafeUrl "$(Get-PimSupportField $r.data 'portalUrl')")
                       uploadUrl = (ConvertTo-PimSupportSafeUrl "$(Get-PimSupportField (Get-PimSupportField $r.data 'uploadLink') 'page')")
                       sent = $a.arguments; supportUrl = $link.supportUrl }
    $audit = [ordered]@{ ticketNumber = $num; category = "$($a.arguments.category)"; priority = "$($a.arguments.priority)"
                         sourceRef = "$($a.arguments['sourceRef'])"; logExcerptChars = "$($a.arguments['logExcerpt'])".Length }
    return (& $done 200 $out $audit)
}
