#Requires -Version 5.1
<#
  PIM-Wake.ps1 -- WAKE-1 (framework SECURE-WEB-1 point 1, 3.1.26): an immediate engine start after a Commit / "Run now",
  without any job right for the internet-facing web app.

  THE PATTERN (Microsoft-standard; the same shape as EntraPolicySuite's eps-wake, copied here -- isolation, no shared file):
    * ONE Azure Storage queue 'pim-wake' in the install's own storage account (the PIM storage account the as-built step
      keeps; shared-key access OFF, Entra tokens only).
    * The WEB identity holds 'Storage Queue Data Message Sender' on THAT queue only (granted by setup / the Support app;
      the updater only REPORTS a missing grant). On Commit / Run now the Manager puts ONE message on it with its managed
      identity over REST (no SAS, no key). The message is a job NAME and nothing else: {"job":"engine"}.
    * The wake job 'caj-pim-wake' is a Container Apps job with an EVENT trigger: the platform's KEDA azure-queue scaler,
      authenticated as the engine's user-assigned identity, starts an execution when a message arrives. It runs the SAME
      image and the same engine run (Start-PimScheduler.ps1 -Once) as the scheduled engine job, as the same identity.
      A Container Apps job has ONE trigger type, so it is a separate job beside the schedule-triggered engine job.
    * THE JOB is the gate, never the sender: it refuses a message older than 15 minutes (or with no readable insertion
      time, or one more than 5 minutes in the future), accepts only a NAME from its shipped allow-list
      (Get-PimWakeAllowList) and nothing else in the message, and audits every accepted / refused message.
    * The web holds no job right, and the Manager still never starts a job itself ($script:PimManagerMayStartJobs).

  Engine-side and setup-side functions only take seams (-Http / -Arm / -Store / -Grant / -Run / -Audit); the PURE ones
  have no seam. PS 5.1 + 7. ASCII.
#>
Set-StrictMode -Off

# ---- the fixed names (LITERALS: never read from a request, a setting or the environment) ------------------------------
function Get-PimWakeQueueName { return 'pim-wake' }
function Get-PimWakeJobName { return 'caj-pim-wake' }
function Get-PimWakeSettingName { return 'WakeQueue' }
function Get-PimWakeMaxAgeMinutes { return 15 }
function Get-PimWakeAcaApiVersion { return '2025-01-01' }   # the first Container Apps jobs api that takes an identity on a scale rule
function Get-PimWakeEntryPath { return '/app/PIM4EntraPS/tools/pim-engine/wake-job-entry.ps1' }
function Get-PimWakeAllowList {
    <# PURE. LITERAL. The ONLY names a wake message may carry -- each one = one thing the wake job runs. 'engine' = one normal
       engine run (Start-PimScheduler.ps1 -Once: the same claims, leases, guards and run records as a scheduled start). #>
    return @('engine')
}
function Get-PimWakeRoleIds {
    <# PURE. Microsoft's built-in role definition ids (Learn: role-based-access-control/built-in-roles, Storage). #>
    return [ordered]@{
        Sender    = 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'   # Storage Queue Data Message Sender    -- web, on the wake queue only
        Processor = '8a0f0c08-91a1-4084-bc3d-661d67233fed'   # Storage Queue Data Message Processor -- engine (the wake job reads + deletes)
        Reader    = '19e7f393-937e-4f77-808e-94535e297925'   # Storage Queue Data Reader            -- engine (KEDA counts the messages)
    }
}
function Get-PimWakeDefaultStorageAccountName {
    <# PURE. The install's PIM storage account default name -- the same rule as PIM-AsBuilt.ps1 Get-PimAsBuiltStorageAccountName
       ('stpimab' + 12 hex of SHA-256(subscription/resourceGroup)); kept here so the wake code loads on its own. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hx = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(("$SubscriptionId/$ResourceGroup").ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    return ('stpimab' + $hx.Substring(0, 12))
}
function Test-PimWakeStorageAccountName { param([AllowEmptyString()][string]$Name) return ("$Name" -cmatch '^[a-z0-9]{3,24}$') }

function Get-PimWakeField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

# ---- the message (sender side) ------------------------------------------------------------------------------------------
function New-PimWakeMessageText {
    <# PURE. The queue message text for -Kind: base64 of {"job":"<kind>"} -- a NAME only, no command, argument or environment.
       A kind that is not on the allow-list THROWS (the sender never builds what the job would refuse anyway). #>
    param([string]$Kind = 'engine')
    if (@(Get-PimWakeAllowList) -cnotcontains "$Kind") { throw "wake: '$Kind' is not a wake name (allowed: $(@(Get-PimWakeAllowList) -join ', '))" }
    $json = '{"job":"' + "$Kind" + '"}'
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}

function Send-PimWakeMessage {
    <#
      The Manager's side: ONE message on the wake queue, with the web app's managed identity (REST, no SAS, no key). Never
      throws. -Post { param($uri, $body, $headers) -> HTTP status (int) } and -Token { -> bearer token for storage } are seams.
      Returns @{ ok; status; reason }.
    #>
    param([Parameter(Mandatory)][string]$StorageAccount, [string]$Kind = 'engine', [scriptblock]$Post, [scriptblock]$Token)
    if (-not (Test-PimWakeStorageAccountName $StorageAccount)) { return @{ ok = $false; status = 0; reason = "'$StorageAccount' is not a storage account name" } }
    try { $text = New-PimWakeMessageText -Kind $Kind } catch { return @{ ok = $false; status = 0; reason = "$($_.Exception.Message)" } }
    # messagettl: the queue drops it after 15 min; the JOB checks the age itself (the TTL is the sender's choice, not a control)
    $uri = "https://$StorageAccount.queue.core.windows.net/$(Get-PimWakeQueueName)/messages?messagettl=$((Get-PimWakeMaxAgeMinutes) * 60)"
    $body = "<QueueMessage><MessageText>$text</MessageText></QueueMessage>"
    try {
        if (-not $Token) { $Token = { Get-PimRestToken -Resource 'https://storage.azure.com' } }
        $tok = "$(& $Token)".Trim()
        if (-not $tok) { return @{ ok = $false; status = 0; reason = 'no storage token for the web identity' } }
        $h = @{ Authorization = "Bearer $tok"; 'x-ms-version' = '2021-08-06' }
        if (-not $Post) {
            $Post = {
                param($u, $b, $hh)
                try { $r = Invoke-WebRequest -UseBasicParsing -Method POST -Uri $u -Body $b -ContentType 'application/xml' -Headers $hh -TimeoutSec 10; return [int]$r.StatusCode }
                catch { $sc = 0; try { $sc = [int]$_.Exception.Response.StatusCode } catch { $sc = 0 }; if ($sc) { return $sc }; throw }
            }
        }
        $st = [int](& $Post $uri $body $h)
        if ($st -ge 200 -and $st -lt 300) { return @{ ok = $true; status = $st; reason = 'queued' } }
        $why = if ($st -eq 403) { 'the web identity may not send to the wake queue (no Storage Queue Data Message Sender on it)' } elseif ($st -eq 404) { 'the wake queue does not exist' } else { "HTTP $st" }
        return @{ ok = $false; status = $st; reason = $why }
    } catch { return @{ ok = $false; status = 0; reason = ((("$($_.Exception.Message)") -split "`n")[0]) } }
}

# ---- the message (job side: the gate) -----------------------------------------------------------------------------------
function Test-PimWakeMessage {
    <#
      PURE. THE GATE. One queue message -> @{ accepted; kind; reason; ageSeconds }.
      Refused: no readable insertion time (RFC 1123, as the queue service writes it), older than -MaxAgeMinutes, more than
      5 minutes in the future (a clock that cannot be trusted would widen the window), text over 256 characters, not base64
      JSON, not an object with EXACTLY one property 'job', or a 'job' that is not on the shipped allow-list (exact case).
    #>
    param([AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$InsertionTime, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$MaxAgeMinutes = (Get-PimWakeMaxAgeMinutes))
    $out = [ordered]@{ accepted = $false; kind = ''; reason = ''; ageSeconds = $null }
    $now = [datetime]::SpecifyKind($NowUtc.ToUniversalTime(), [DateTimeKind]::Utc)
    $ins = [datetimeoffset]::MinValue
    $it = "$InsertionTime".Trim()
    if (-not $it -or -not [datetimeoffset]::TryParseExact($it, 'r', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$ins)) {
        $out.reason = 'no readable insertion time -- refused (older than the limit cannot be ruled out)'; return [pscustomobject]$out
    }
    $age = $now - $ins.UtcDateTime
    $out.ageSeconds = [int][Math]::Round($age.TotalSeconds)
    if ($age.TotalMinutes -gt $MaxAgeMinutes) { $out.reason = "$([int][Math]::Ceiling($age.TotalMinutes)) min old (inserted $($ins.UtcDateTime.ToString('u'))) -- older than $MaxAgeMinutes min, refused"; return [pscustomobject]$out }
    if ($age.TotalMinutes -lt -5) { $out.reason = "inserted $([int][Math]::Ceiling(-$age.TotalMinutes)) min in the future ($($ins.UtcDateTime.ToString('u'))) -- the clock or the message cannot be trusted, refused"; return [pscustomobject]$out }
    $t = "$Text"
    if ($t.Length -gt 256) { $out.reason = "the message is $($t.Length) characters -- a wake name is short, refused"; return [pscustomobject]$out }
    $obj = $null
    try { $obj = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)) | ConvertFrom-Json } catch { $obj = $null }
    if ($null -eq $obj -or $obj -isnot [System.Management.Automation.PSCustomObject]) { $out.reason = 'not a wake message (base64 JSON object) -- refused'; return [pscustomobject]$out }
    $names = @($obj.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names.Count -ne 1 -or $names[0] -cne 'job') { $out.reason = "the message carries $(if ($names.Count) { "'" + ($names -join "', '") + "'" } else { 'nothing' }) -- a wake message is a job name only, refused"; return [pscustomobject]$out }
    $k = $obj.job
    if ($k -isnot [string]) { $out.reason = 'the job name is not a string -- refused'; return [pscustomobject]$out }
    if (@(Get-PimWakeAllowList) -cnotcontains $k) { $out.reason = "'$(if ($k.Length -gt 40) { $k.Substring(0, 40) + '...' } else { $k })' is not on the wake allow-list ($(@(Get-PimWakeAllowList) -join ', ')) -- refused"; return [pscustomobject]$out }
    $out.accepted = $true; $out.kind = $k; $out.reason = "accepted ($($out.ageSeconds) s old)"
    return [pscustomobject]$out
}

function ConvertFrom-PimWakeQueueXml {
    <# PURE. The queue service's GET messages answer -> @(@{ id; popReceipt; text; insertionTime }). #>
    param([AllowEmptyString()][string]$Xml)
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches("$Xml", '(?s)<QueueMessage>(.*?)</QueueMessage>')) {
        $b = $m.Groups[1].Value
        $g = { param($tag) $mm = [regex]::Match($b, "(?s)<$tag>([^<]*)</$tag>"); if ($mm.Success) { [System.Net.WebUtility]::HtmlDecode($mm.Groups[1].Value) } else { '' } }
        $res.Add([pscustomobject]@{ id = (& $g 'MessageId'); popReceipt = (& $g 'PopReceipt'); text = (& $g 'MessageText'); insertionTime = (& $g 'InsertionTime') })
    }
    return @($res.ToArray())
}

function Read-PimWakeMessages {
    <#
      The job's side: take up to -Max messages from the wake queue and DELETE each at once (a message left behind would start
      another execution), then judge each one (Test-PimWakeMessage). -Http { param($method, $uri, $headers, $body) ->
      @{ Status; Body } } and -Token are seams. Throws when the queue cannot be read (the job then fails, visibly).
      Returns @{ messages = @(@{ id; accepted; kind; reason; ageSeconds; deleted }); accepted (any); kind }.
    #>
    param([Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][scriptblock]$Http, [scriptblock]$Token,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$Max = 32)
    if (-not (Test-PimWakeStorageAccountName $StorageAccount)) { throw "wake: '$StorageAccount' is not a storage account name" }
    if (-not $Token) { $Token = { Get-PimRestToken -Resource 'https://storage.azure.com' } }
    $base = "https://$StorageAccount.queue.core.windows.net/$(Get-PimWakeQueueName)/messages"
    $h = @{ Authorization = "Bearer $("$(& $Token)".Trim())"; 'x-ms-version' = '2021-08-06' }
    $n = [Math]::Max(1, [Math]::Min(32, $Max))
    $r = & $Http 'GET' "$base`?numofmessages=$n&visibilitytimeout=300" $h $null
    if ([int]$r.Status -ge 300) { throw "wake queue: HTTP $($r.Status)" }
    $out = New-Object System.Collections.Generic.List[object]
    $acc = $false; $kind = ''
    foreach ($m in @(ConvertFrom-PimWakeQueueXml -Xml "$($r.Body)")) {
        if (-not "$($m.id)".Trim()) { continue }
        $del = $false
        try {
            $d = & $Http 'DELETE' "$base/$($m.id)?popreceipt=$([uri]::EscapeDataString("$($m.popReceipt)"))" $h $null
            $del = ([int]$d.Status -lt 300 -or [int]$d.Status -eq 404)
        } catch { $del = $false }
        $v = Test-PimWakeMessage -Text "$($m.text)" -InsertionTime "$($m.insertionTime)" -NowUtc $NowUtc
        if ($v.accepted -and -not $acc) { $acc = $true; $kind = "$($v.kind)" }
        $out.Add([pscustomobject]@{ id = "$($m.id)"; accepted = [bool]$v.accepted; kind = "$($v.kind)"; reason = "$($v.reason)"; ageSeconds = $v.ageSeconds; deleted = $del })
    }
    return [pscustomobject]@{ messages = @($out.ToArray()); accepted = $acc; kind = $kind }
}

function Invoke-PimWakeJob {
    <#
      The wake job's whole run. Reads the queue (Read-PimWakeMessages), AUDITS every message (-Audit { param($action, $result,
      $after) }: wake.accepted / wake.refused), and when at least one message was accepted runs the allow-listed name ONCE
      (-Run { param($kind) -> exit code }: 'engine' = one engine run). Nothing accepted = nothing run, exit 0 (an execution
      KEDA started for a message another execution took). A queue that cannot be read = exit 1.
    #>
    param([Parameter(Mandatory)][string]$StorageAccount, [Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$Run,
          [scriptblock]$Audit, [scriptblock]$Say, [scriptblock]$Token, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Say) { $Say = { param($m) Write-Host $m } }
    $rd = $null
    try { $rd = Read-PimWakeMessages -StorageAccount $StorageAccount -Http $Http -Token $Token -NowUtc $NowUtc }
    catch { & $Say "wake: the queue could not be read -- $((("$($_.Exception.Message)") -split "`n")[0])"; return [pscustomobject]@{ exitCode = 1; ran = $false; accepted = 0; refused = 0 } }
    $na = 0; $nr = 0
    foreach ($m in @($rd.messages)) {
        if ($m.accepted) { $na++ } else { $nr++ }
        & $Say ("wake: message {0} {1} -- {2}" -f $m.id, $(if ($m.accepted) { 'ACCEPTED' } else { 'REFUSED' }), $m.reason)
        if ($Audit) {
            try { & $Audit $(if ($m.accepted) { 'wake.accepted' } else { 'wake.refused' }) $(if ($m.accepted) { 'ok' } else { 'refused' }) ([ordered]@{ messageId = $m.id; kind = $m.kind; reason = $m.reason; ageSeconds = $m.ageSeconds; deleted = $m.deleted }) }
            catch { & $Say "wake: the audit record for $($m.id) was not written ($((("$($_.Exception.Message)") -split "`n")[0]))" }
        }
    }
    if (-not $rd.accepted) {
        & $Say $(if (@($rd.messages).Count) { "wake: no message accepted ($nr refused) -- nothing run" } else { 'wake: no message on the queue (another execution took it) -- nothing run' })
        return [pscustomobject]@{ exitCode = 0; ran = $false; accepted = $na; refused = $nr }
    }
    & $Say "wake: running '$($rd.kind)' once ($na accepted, $nr refused)"
    $code = 0
    try { $code = [int](& $Run $rd.kind) } catch { & $Say "wake: '$($rd.kind)' failed -- $((("$($_.Exception.Message)") -split "`n")[0])"; $code = 1 }
    return [pscustomobject]@{ exitCode = $code; ran = $true; accepted = $na; refused = $nr }
}

# ---- the job (setup / updater side) -------------------------------------------------------------------------------------
function Get-PimWakeSignIn {
    <# PURE. The identity an app / job SIGNS IN AS (same rule as tools\setup\_PimSignInIdentity.ps1, kept here so the engine
       side loads on its own): PIM_ManagedIdentityClientId -> that attached user-assigned identity; not set -> the system one.
       Returns @{ principalId; clientId; kind = user|system|''; resourceId; reason }. #>
    param($Resource)
    $o = [ordered]@{ principalId = ''; clientId = ''; kind = ''; resourceId = ''; reason = '' }
    if ($null -eq $Resource) { $o.reason = 'not found'; return [pscustomobject]$o }
    $cid = ''
    foreach ($c in @(Get-PimWakeField (Get-PimWakeField (Get-PimWakeField $Resource 'properties') 'template') 'containers')) {
        if (-not $c -or "$(Get-PimWakeField $c 'name')" -eq 'signin-front') { continue }
        foreach ($e in @(Get-PimWakeField $c 'env')) { if ($e -and "$(Get-PimWakeField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimWakeField $e 'value')".Trim()) { $cid = "$(Get-PimWakeField $e 'value')".Trim() } }
        if ($cid) { break }
    }
    $idn = Get-PimWakeField $Resource 'identity'
    if ($cid) {
        $ua = Get-PimWakeField $idn 'userAssignedIdentities'
        $pairs = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys | ForEach-Object { @{ k = "$_"; v = $ua[$_] } }) } elseif ($ua) { @($ua.PSObject.Properties | ForEach-Object { @{ k = $_.Name; v = $_.Value } }) } else { @() }
        foreach ($p in $pairs) {
            if ("$(Get-PimWakeField $p.v 'clientId')".Trim() -ieq $cid -and "$(Get-PimWakeField $p.v 'principalId')".Trim()) {
                $o.principalId = "$(Get-PimWakeField $p.v 'principalId')".Trim(); $o.clientId = $cid; $o.kind = 'user'; $o.resourceId = "$($p.k)"
                return [pscustomobject]$o
            }
        }
        $o.reason = "it signs in with client id $cid, but no attached user-assigned identity has that client id"; return [pscustomobject]$o
    }
    $sp = "$(Get-PimWakeField $idn 'principalId')".Trim()
    if ($sp) { $o.principalId = $sp; $o.kind = 'system'; return [pscustomobject]$o }
    $o.reason = 'it has no managed identity'; return [pscustomobject]$o
}

function Get-PimWakeJobSpec {
    <#
      PURE. The wake job's ARM body, DERIVED FROM THE ENGINE JOB (-EngineJob = its ARM GET): the same environment, workload
      profile, image (or -Image), container size, replica timeout, store settings and identity -- an EVENT trigger instead of
      the schedule, and the wake entry instead of the scheduler. KEDA's azure-queue rule counts the wake queue as the engine's
      USER-ASSIGNED identity (no connection string, no key). REFUSED (ok = false, reason): the engine signs in as its
      system-assigned identity (a second job cannot share it -- the wake job needs the identity move first), an env value
      carried as a plain secret (only Key Vault references are copied, never a value), a registry pulled with a password,
      a storage account name that is not one.
      Returns @{ ok; reason; resource; identity = @{ principalId; clientId; resourceId }; image }.
    #>
    param([Parameter(Mandatory)]$EngineJob, [Parameter(Mandatory)][string]$StorageAccount, [string]$JobName = (Get-PimWakeJobName),
          [string]$Image = '', [string]$EntryPath = (Get-PimWakeEntryPath))
    $no = { param($why) return @{ ok = $false; reason = $why; resource = $null; identity = $null; image = '' } }
    if (-not (Test-PimWakeStorageAccountName $StorageAccount)) { return (& $no "'$StorageAccount' is not a storage account name") }
    $si = Get-PimWakeSignIn -Resource $EngineJob
    if ($si.kind -ne 'user' -or "$($si.resourceId)" -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/]+$') {
        return (& $no "the engine job signs in as $(if ($si.kind -eq 'system') { 'its system-assigned identity' } else { "no readable identity ($($si.reason))" }) -- the wake job runs as the engine's USER-ASSIGNED identity, available after the identity move")
    }
    $props = Get-PimWakeField $EngineJob 'properties'
    $cfg = Get-PimWakeField $props 'configuration'
    $tpl = Get-PimWakeField $props 'template'
    $c0 = @(Get-PimWakeField $tpl 'containers')[0]
    if (-not $c0) { return (& $no 'the engine job declares no container') }
    $img = if ("$Image".Trim()) { "$Image".Trim() } else { "$(Get-PimWakeField $c0 'image')".Trim() }
    if (-not $img) { return (& $no 'the engine job has no image') }
    $envId = "$(Get-PimWakeField $props 'environmentId')".Trim(); if (-not $envId) { $envId = "$(Get-PimWakeField $props 'managedEnvironmentId')".Trim() }
    if (-not $envId) { return (& $no 'the engine job names no Container Apps environment') }
    # ---- secrets: only Key Vault references (name + keyVaultUrl + identity) -- a value is never read or copied
    $engSecrets = @{}
    foreach ($s in @(Get-PimWakeField $cfg 'secrets')) { if ($s -and "$(Get-PimWakeField $s 'name')") { $engSecrets["$(Get-PimWakeField $s 'name')"] = $s } }
    $secrets = New-Object System.Collections.Generic.List[object]
    $envList = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-PimWakeField $c0 'env')) {
        $en = "$(Get-PimWakeField $e 'name')"
        if (-not $en -or $en -like 'PIM_WAKE_*') { continue }
        $sr = "$(Get-PimWakeField $e 'secretRef')".Trim()
        if ($sr) {
            $sd = $engSecrets[$sr]
            $kv = "$(Get-PimWakeField $sd 'keyVaultUrl')".Trim()
            if (-not $kv) { return (& $no "the engine job carries '$en' as a plain secret -- the wake job copies only Key Vault references (move the secrets to Key Vault first)") }
            if (-not @($secrets | Where-Object { $_.name -eq $sr }).Count) { $secrets.Add([ordered]@{ name = $sr; keyVaultUrl = $kv; identity = "$(Get-PimWakeField $sd 'identity')".Trim() }) }
            $envList.Add([ordered]@{ name = $en; secretRef = $sr })
        } else {
            $ev = "$(Get-PimWakeField $e 'value')"
            if ($ev -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN)') { return (& $no "the engine job's '$en' looks like a credential -- the wake job carries none") }
            $envList.Add([ordered]@{ name = $en; value = $ev })
        }
    }
    $envList.Add([ordered]@{ name = 'PIM_WAKE_STORAGE'; value = "$StorageAccount" })
    $envList.Add([ordered]@{ name = 'PIM_WAKE_QUEUE'; value = (Get-PimWakeQueueName) })
    # ---- registries: the engine's pull; a pull with the engine job's OWN system identity becomes the engine's user identity
    $regs = New-Object System.Collections.Generic.List[object]
    $uaIds = [ordered]@{}; $uaIds["$($si.resourceId)"] = @{}
    foreach ($rg0 in @(Get-PimWakeField $cfg 'registries')) {
        if (-not $rg0) { continue }
        if ("$(Get-PimWakeField $rg0 'passwordSecretRef')".Trim()) { return (& $no 'the engine job pulls its image with a registry password -- the wake job pulls with a managed identity only') }
        $ri = "$(Get-PimWakeField $rg0 'identity')".Trim()
        if (-not $ri -or $ri -ieq 'system') { $ri = "$($si.resourceId)" }
        elseif ($ri -match '(?i)/userAssignedIdentities/') { $uaIds[$ri] = @{} }
        $regs.Add([ordered]@{ server = "$(Get-PimWakeField $rg0 'server')"; identity = $ri })
    }
    $timeout = 0; try { $timeout = [int](Get-PimWakeField $cfg 'replicaTimeout') } catch { $timeout = 0 }
    if ($timeout -le 0) { $timeout = 3600 }
    $res0 = Get-PimWakeField $c0 'resources'
    $resources = [ordered]@{ cpu = 0.5; memory = '1Gi' }
    if ($res0 -and "$(Get-PimWakeField $res0 'memory')".Trim()) { $resources = [ordered]@{ cpu = [double](Get-PimWakeField $res0 'cpu'); memory = "$(Get-PimWakeField $res0 'memory')" } }
    $config = [ordered]@{
        triggerType        = 'Event'
        replicaTimeout     = $timeout
        replicaRetryLimit  = 0
        eventTriggerConfig = [ordered]@{
            parallelism = 1; replicaCompletionCount = 1
            scale = [ordered]@{ minExecutions = 0; maxExecutions = 1; pollingInterval = 30
                rules = @([ordered]@{ name = 'wake-queue'; type = 'azure-queue'; identity = "$($si.resourceId)"
                    metadata = [ordered]@{ accountName = "$StorageAccount"; queueName = (Get-PimWakeQueueName); queueLength = '1' } }) }
        }
        registries         = @($regs.ToArray())
    }
    if ($secrets.Count) { $config['secrets'] = @($secrets.ToArray()) }
    $p2 = [ordered]@{ environmentId = $envId; configuration = $config
        template = [ordered]@{ containers = @([ordered]@{ name = $JobName; image = $img; command = @('pwsh'); args = @('-NoProfile', '-File', "$EntryPath"); env = @($envList.ToArray()); resources = $resources }) } }
    $wp = "$(Get-PimWakeField $props 'workloadProfileName')".Trim(); if ($wp) { $p2['workloadProfileName'] = $wp }
    $resource = [ordered]@{ location = "$(Get-PimWakeField $EngineJob 'location')"; tags = @{ 'pim-component' = 'wake' }
                            identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uaIds }; properties = $p2 }
    return @{ ok = $true; reason = ''; resource = $resource; image = $img; identity = @{ principalId = "$($si.principalId)"; clientId = "$($si.clientId)"; resourceId = "$($si.resourceId)" } }
}

function Get-PimWakeJobDrift {
    <# PURE. What differs between the wake job as it is (-Job, ARM GET) and the spec (Get-PimWakeJobSpec) -- @() = current. #>
    param($Job, [Parameter(Mandatory)][hashtable]$Spec)
    $why = New-Object System.Collections.Generic.List[string]
    $cfg = Get-PimWakeField (Get-PimWakeField $Job 'properties') 'configuration'
    $c0 = @(Get-PimWakeField (Get-PimWakeField (Get-PimWakeField $Job 'properties') 'template') 'containers')[0]
    $want = $Spec.resource.properties.template.containers[0]
    if ("$(Get-PimWakeField $cfg 'triggerType')" -ne 'Event') { $why.Add("trigger $(Get-PimWakeField $cfg 'triggerType') -> Event") }
    if ("$(Get-PimWakeField $c0 'image')" -ne "$($want.image)") { $why.Add("image -> $($want.image)") }
    if ((@(Get-PimWakeField $c0 'args') -join ' ') -ne (@($want.args) -join ' ')) { $why.Add('entry -> the wake entry') }
    $rule = @(Get-PimWakeField (Get-PimWakeField (Get-PimWakeField $cfg 'eventTriggerConfig') 'scale') 'rules')[0]
    $md = Get-PimWakeField $rule 'metadata'
    $wr = $Spec.resource.properties.configuration.eventTriggerConfig.scale.rules[0]
    if ("$(Get-PimWakeField $rule 'type')" -ne 'azure-queue' -or "$(Get-PimWakeField $md 'queueName')" -ne (Get-PimWakeQueueName) -or "$(Get-PimWakeField $md 'accountName')" -ne "$($wr.metadata.accountName)") { $why.Add("queue rule -> $($wr.metadata.accountName)/$(Get-PimWakeQueueName)") }
    if ("$(Get-PimWakeField $rule 'identity')" -ine "$($wr.identity)") { $why.Add('queue rule identity -> the engine identity') }
    $have = @{}; foreach ($e in @(Get-PimWakeField $c0 'env')) { if ($e) { $have["$(Get-PimWakeField $e 'name')"] = "$(Get-PimWakeField $e 'value')$(Get-PimWakeField $e 'secretRef')" } }
    $envBad = @(foreach ($e in @($want.env)) { $k = "$($e.name)"; $v = "$($e.value)$($e.secretRef)"; if (-not $have.ContainsKey($k) -or $have[$k] -cne $v) { $k } })
    $wantNames = @($want.env | ForEach-Object { "$($_.name)" })
    $envBad += @($have.Keys | Where-Object { $wantNames -notcontains $_ })
    if ($envBad.Count) { $why.Add("env ($(@($envBad | Select-Object -First 5) -join ', '))") }
    return @($why.ToArray())
}

function Invoke-PimWakeConverge {
    <#
      The wake queue + the wake job on an install, idempotent, with read-back. Run by setup (tools\setup\Deploy-PimWakeJob.ps1,
      with -Grant) and by the in-cloud updater (no -Grant: Contributor on the resource group may create the queue and the job,
      it may NOT write role assignments -- it REPORTS a missing one). In order:
        1. the engine job (its image, identity, store settings, environment) -- missing = nothing done;
        2. the storage account (-StorageAccount, else the one the as-built job names, else the default name): must exist
           and allow NO shared key (the as-built step creates and hardens it) -- else nothing done;
        3. the queue 'pim-wake' (created when missing, read back);
        4. the job 'caj-pim-wake' (Get-PimWakeJobSpec; created when missing, re-written when it drifts, read back);
        5. the rights on the wake queue ONLY: web = Storage Queue Data Message Sender; engine = Message Processor + Data Reader.
           With -Grant { param($scope, $principalId, $roleId) } a missing one is granted and read back; without, REPORTED;
        6. pim.Settings 'WakeQueue' { account; queue; job } through -Store { param($op, $name, $value) } -- what the Manager
           reads to send; written only when the queue and the job are in place, and only when it changes.
      -Arm { param($method, $path, $body) } (path WITH api-version; a GET of an absent resource may throw or return $null).
      NEVER throws. Returns @{ lines = @(@{ id; level = info|changed|warn; text }); changed; warnings; state = ok|missing|
      unknown; rights = ok|missing|unknown; account; jobImage }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$EngineJob, [string]$ManagerApp = 'ca-pim-manager', [string]$StorageAccount = '',
          [string]$AsBuiltJob = '', [string]$Image = '',
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Store = $null, [scriptblock]$Grant = $null,
          [string]$FixHint = 'run tools/setup/Deploy-PimWakeJob.ps1 as an Owner / User Access Administrator of the resource group (or through the Invardia Support app)')
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { $null } }
    $state = 'unknown'; $rights = 'unknown'; $acct = ''; $jobImage = ''
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $aca = "api-version=$(Get-PimWakeAcaApiVersion)"; $st = 'api-version=2023-01-01'; $az = 'api-version=2022-04-01'
    $jn = Get-PimWakeJobName; $qn = Get-PimWakeQueueName
    $finish = {
        $arr = @($lines.ToArray())
        return [pscustomobject]@{ lines = $arr; changed = @($arr | Where-Object { $_.level -eq 'changed' }).Count; warnings = @($arr | Where-Object { $_.level -eq 'warn' }).Count
                                  state = $state; rights = $rights; account = $acct; jobImage = $jobImage }
    }
    try {
        # ---- 1. the engine job -------------------------------------------------------------------------------------------
        $eng = & $get "$rg/providers/Microsoft.App/jobs/$EngineJob`?$aca"
        if (-not $eng) { & $add 'wake' 'warn' "wake: the engine job '$EngineJob' could not be read -- the wake queue and job were not converged (Commit / Run now wait for the next scheduled start)"; $state = 'missing'; return (& $finish) }
        # ---- 2. the storage account --------------------------------------------------------------------------------------
        $acct = "$StorageAccount".Trim()
        if (-not $acct -and "$AsBuiltJob".Trim()) {
            $ab = & $get "$rg/providers/Microsoft.App/jobs/$("$AsBuiltJob".Trim())`?$aca"
            foreach ($c in @(Get-PimWakeField (Get-PimWakeField (Get-PimWakeField $ab 'properties') 'template') 'containers')) { foreach ($e in @(Get-PimWakeField $c 'env')) { if ("$(Get-PimWakeField $e 'name')" -eq 'PIM_ASBUILT_STORAGE') { $acct = "$(Get-PimWakeField $e 'value')".Trim() } } }
        }
        if (-not (Test-PimWakeStorageAccountName $acct)) { $acct = Get-PimWakeDefaultStorageAccountName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup }
        $saPath = "$rg/providers/Microsoft.Storage/storageAccounts/$acct"
        $sa = & $get "$saPath`?$st"
        if (-not $sa) { & $add 'wake-storage' 'warn' "wake: the storage account $acct does not exist yet (the as-built step creates it) -- the wake queue waits for it"; $state = 'missing'; return (& $finish) }
        if ((Get-PimWakeField (Get-PimWakeField $sa 'properties') 'allowSharedKeyAccess') -ne $false) { & $add 'wake-storage' 'warn' "wake: the storage account $acct allows shared-key access -- the wake queue is created only on an Entra-only account (the as-built step hardens it)"; $state = 'missing'; return (& $finish) }
        # ---- 3. the queue ------------------------------------------------------------------------------------------------
        $qPath = "$saPath/queueServices/default/queues/$qn"
        $q = & $get "$qPath`?$st"
        if (-not $q) {
            try { [void](& $Arm 'PUT' "$qPath`?$st" @{ properties = @{} }) } catch { & $add 'wake-queue' 'warn' "wake: the queue $acct/$qn could not be created: $((("$($_.Exception.Message)") -split "`n")[0])"; $state = 'missing'; return (& $finish) }
            $q = & $get "$qPath`?$st"
            if (-not $q) { & $add 'wake-queue' 'warn' "wake: the queue $acct/$qn does not read back after the create -- the next run retries"; $state = 'missing'; return (& $finish) }
            & $add 'wake-queue' 'changed' "wake: queue $acct/$qn created (Entra-only account, no shared key)"
        } else { & $add 'wake-queue' 'info' "wake: queue $acct/$qn present" }
        # ---- 4. the job --------------------------------------------------------------------------------------------------
        $spec = Get-PimWakeJobSpec -EngineJob $eng -StorageAccount $acct -Image $Image
        if (-not $spec.ok) { & $add 'wake-job' 'warn' "wake: job $jn not converged -- $($spec.reason); Commit / Run now wait for the next scheduled start"; $state = 'missing'; return (& $finish) }
        $job = & $get "$rg/providers/Microsoft.App/jobs/$jn`?$aca"
        $why = if ($job) { @(Get-PimWakeJobDrift -Job $job -Spec $spec) } else { @() }
        if (-not $job -or $why.Count) {
            try { [void](& $Arm 'PUT' "$rg/providers/Microsoft.App/jobs/$jn`?$aca" $spec.resource) }
            catch { & $add 'wake-job' 'warn' "wake: job $jn not $(if ($job) { 'updated' } else { 'created' }): $((("$($_.Exception.Message)") -split "`n")[0]) -- the next run retries"; $state = 'missing'; return (& $finish) }
            $back = & $get "$rg/providers/Microsoft.App/jobs/$jn`?$aca"
            $left = if ($back) { @(Get-PimWakeJobDrift -Job $back -Spec $spec) } else { @('not readable') }
            if ($left.Count) { & $add 'wake-job' 'warn' "wake: job $jn written but does not read back as planned ($($left -join '; ')) -- the next run retries"; $state = 'missing'; return (& $finish) }
            & $add 'wake-job' 'changed' "wake: job $jn $(if ($job) { "updated ($($why -join '; '))" } else { 'created' }) -- event trigger on $acct/$qn, image $($spec.image), as the engine identity; read back"
        } else { & $add 'wake-job' 'info' "wake: job $jn current ($($spec.image))" }
        $jobImage = "$($spec.image)"; $state = 'ok'
        # ---- 5. the rights on the wake queue ONLY ------------------------------------------------------------------------
        $ids = Get-PimWakeRoleIds
        $mgr = & $get "$rg/providers/Microsoft.App/containerApps/$ManagerApp`?api-version=2024-03-01"
        $web = Get-PimWakeSignIn -Resource $mgr
        $need = @(
            @{ who = 'web'; oid = "$($web.principalId)"; role = 'Storage Queue Data Message Sender'; id = $ids.Sender; why = 'the Manager puts the wake message on it' }
            @{ who = 'engine'; oid = "$($spec.identity.principalId)"; role = 'Storage Queue Data Message Processor'; id = $ids.Processor; why = 'the wake job reads and deletes the message' }
            @{ who = 'engine'; oid = "$($spec.identity.principalId)"; role = 'Storage Queue Data Reader'; id = $ids.Reader; why = 'the platform counts the messages to start the job' }
        )
        $missing = 0; $unknown = 0
        $holds = {
            param($oid, $roleId)
            $ra = & $get ("$qPath/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId%20eq%20%27{0}%27&{1}" -f [uri]::EscapeDataString($oid), $az)
            if ($null -eq $ra) { return $null }
            return (@(@(Get-PimWakeField $ra 'value') | Where-Object { $_ -and ("$(Get-PimWakeField (Get-PimWakeField $_ 'properties') 'roleDefinitionId')" -split '/')[-1] -ieq $roleId -and "$(Get-PimWakeField (Get-PimWakeField $_ 'properties') 'principalId')" -ieq $oid }).Count -gt 0)
        }
        foreach ($n in $need) {
            if (-not $n.oid) { $unknown++; & $add "wake-right-$($n.who)" 'warn' "wake: the $($n.who) identity could not be read -- its '$($n.role)' on $acct/$qn was not checked"; continue }
            $h = & $holds $n.oid $n.id
            if ($h -eq $true) { & $add "wake-right-$($n.who)-$($n.id.Substring(0, 8))" 'info' "wake: $($n.who) holds '$($n.role)' on $acct/$qn ($($n.why))"; continue }
            if ($Grant) {
                try { [void](& $Grant $qPath $n.oid $n.id) } catch { }
                $h = & $holds $n.oid $n.id
                if ($h -eq $true) { & $add "wake-right-$($n.who)-$($n.id.Substring(0, 8))" 'changed' "wake: '$($n.role)' granted to the $($n.who) identity on $acct/$qn only; read back"; continue }
            }
            if ($null -eq $h) { $unknown++ } else { $missing++ }
            & $add "wake-right-$($n.who)-$($n.id.Substring(0, 8))" 'warn' "wake: the $($n.who) identity has no '$($n.role)' on $acct/$qn ($($n.why)) -- MISSING; $FixHint. Until then Commit / Run now wait for the next scheduled start"
        }
        $rights = if ($missing) { 'missing' } elseif ($unknown) { 'unknown' } else { 'ok' }
        # ---- 6. the setting the Manager reads ----------------------------------------------------------------------------
        if ($Store) {
            $sn = Get-PimWakeSettingName
            $cur = $null; try { $cur = & $Store 'get' $sn $null } catch { $cur = $null }
            if ($cur -is [string] -and "$cur".Trim()) { try { $cur = "$cur" | ConvertFrom-Json } catch { $cur = $null } }
            if ("$(Get-PimWakeField $cur 'account')" -ceq $acct -and "$(Get-PimWakeField $cur 'queue')" -ceq $qn) { & $add 'wake-setting' 'info' "wake: pim.Settings '$sn' current ($acct/$qn)" }
            else {
                try {
                    [void](& $Store 'set' $sn ([pscustomobject][ordered]@{ account = $acct; queue = $qn; job = $jn; recordedUtc = [datetime]::UtcNow.ToString('o') }))
                    & $add 'wake-setting' 'changed' "wake: pim.Settings '$sn' = $acct/$qn (the Manager sends the wake message there)"
                } catch { & $add 'wake-setting' 'warn' "wake: pim.Settings '$sn' was not written: $((("$($_.Exception.Message)") -split "`n")[0]) -- the Manager keeps waiting for the next scheduled start" }
            }
        } else { & $add 'wake-setting' 'info' "wake: no store in this run -- pim.Settings '$(Get-PimWakeSettingName)' not checked" }
    } catch { & $add 'wake' 'warn' "wake: converge stopped: $((("$($_.Exception.Message)") -split "`n")[0])" }
    return (& $finish)
}
