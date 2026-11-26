#Requires -Version 5.1
<#
.SYNOPSIS
  SEC-IMAGE-OVERVIEW-1 (owner 2026-11-25, relayed by Invardia 2026-11-26): Operations > "Security image release overview" --
  PIM's own security image releases (image-only base-image patches), read from Invardia by the Manager SERVER.

.DESCRIPTION
  Contract (Invardia 2026-11-26):
    GET https://invardia.com/api/updates/pim-manager/security-image-releases?days=7|30|90|365   (default 90)
    header X-Invardia-Install-Key = this install's own key; server-side only.
    401 { error: 'key' }
    200 { generatedAt, days, rows: [ { product, version (null = detected, no release yet), detectedAt, startedAt,
          rings: [ { ring 0..3, at } ] (first time on that ring), hoursToNewestRing, newestRing, inProgress, replaced, what } ] }
    Every time is ISO UTC or null (= "not recorded").

  THE RULES THIS FILE HOLDS (tests/Test-PimSecImageReleases.ps1):
    * The SAME mechanism as Get support (PIM-SupportTicket.ps1, 100.91): the install key is read on the server
      (Resolve-PimSetupInstallKey: the secret PIM_UPLINK_KEY, else pim.Settings 'InvardiaInstallKey'), goes into ONE place --
      the request header -- and into no body this file returns (every body is swept for it before it leaves).
    * The address is a CONSTANT. No setting can point the install key at another host, and a redirect is not followed.
    * A missing time is null and the page shows "not recorded". The hours between two steps are computed ONLY when both
      ends are recorded -- never a guess, never interpolated over a missing step.
    * Ring numbers other than 0..3 are ignored; a ring listed twice keeps its EARLIEST recorded time (first time on it).
    * Nothing here throws to the page: no key, no network, a 401 or an unreadable reply is ONE plain message:
      "PIM Manager could not read the security image releases from Invardia: <reason>".
  Everything is PURE or takes its I/O as a seam (-GetSetting, -Http). Plain scriptblocks only -- never .GetNewClosure().
#>

$script:PimSecImageEndpoint     = 'https://invardia.com/api/updates/pim-manager/security-image-releases'
$script:PimSecImageKeyHeader    = 'X-Invardia-Install-Key'
$script:PimSecImageDays         = @(7, 30, 90, 365)
$script:PimSecImageDefaultDays  = 90
$script:PimSecImageNotRecorded  = 'not recorded'
$script:PimSecImageNoRelease    = 'detected, no release yet'
$script:PimSecImageFailPrefix   = 'PIM Manager could not read the security image releases from Invardia: '
$script:PimSecImageMaxRows      = 500
$script:PimSecImageCacheSeconds = 300
if (-not $script:PimSecImageCache) { $script:PimSecImageCache = @{} }

function Get-PimSecImageReleaseDayChoices { <# PURE. LITERAL. #> return @($script:PimSecImageDays) }
function Get-PimSecImageNotRecordedText { <# PURE. LITERAL. #> return $script:PimSecImageNotRecorded }

function ConvertTo-PimSecImageReleaseDays {
    <#
      PURE. The ?days value -> 7 / 30 / 90 / 365. Absent or empty = 90 (the default). Anything else (another number, '090',
      '30.5', '-7', text) = $null: the caller refuses the request (400), it never silently picks another period.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $script:PimSecImageDefaultDays }
    $s = "$Value".Trim()
    if ($s -eq '') { return $script:PimSecImageDefaultDays }
    if ($s -notmatch '^(7|30|90|365)$') { return $null }
    return [int]$s
}

function Get-PimSecImageField {
    # PURE. A property of a PSCustomObject or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimSecImageUtc {
    <#
      PURE. A recorded time -> [datetime] UTC, or $null (= not recorded). Accepts an ISO 8601 string with a zone (as the
      contract sends), or a [datetime] / [DateTimeOffset] (PowerShell 7's ConvertFrom-Json turns ISO strings into dates).
      Empty, null or anything that is not an ISO time = $null -- an unreadable time is NOT a recorded time.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $s = "$Value".Trim()
    if ($s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}') { return $null }
    $o = [DateTimeOffset]::MinValue
    $st = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $st, [ref]$o)) { return $null }
    return $o.UtcDateTime
}

function ConvertTo-PimSecImageIso {
    # PURE. [datetime] UTC -> 'yyyy-MM-ddTHH:mm:ssZ'; $null stays $null.
    param([AllowNull()][object]$Utc)
    if ($null -eq $Utc) { return $null }
    return ([datetime]$Utc).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PimSecImageRingNumber {
    # PURE. A ring value -> 0..3, or $null (unknown ring: ignored). 2, '2', 2.0 = 2; 4, -1, 2.5, 'x', null = $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { $n = [long]$Value }
    elseif ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { if ([double]$Value -ne [Math]::Floor([double]$Value)) { return $null }; $n = [long]$Value }
    else { $s = "$Value".Trim(); if ($s -notmatch '^\d$') { return $null }; $n = [long]$s }
    if ($n -lt 0 -or $n -gt 3) { return $null }
    return [int]$n
}

function Get-PimSecImageHoursBetween {
    <# PURE. The hours from one recorded time to the next, 1 decimal -- ONLY when BOTH are recorded; otherwise $null. #>
    param([AllowNull()][object]$FromUtc, [AllowNull()][object]$ToUtc)
    if ($null -eq $FromUtc -or $null -eq $ToUtc) { return $null }
    return [Math]::Round((([datetime]$ToUtc) - ([datetime]$FromUtc)).TotalHours, 1)
}

function ConvertTo-PimSecImageBool {
    # PURE. Only a real true (or the text 'true') is true; null / anything else is false.
    param([AllowNull()][object]$Value)
    if ($Value -is [bool]) { return $Value }
    return ("$Value".Trim() -ieq 'true')
}

function ConvertTo-PimSecImageReleaseRows {
    <#
      PURE. Invardia's answer (the parsed 200 body, or its rows array) -> the rows the page shows, newest first:
        version (string | null), versionLabel ('detected, no release yet' when the version is null), product,
        detectedAt, startedAt, ring0At, ring1At, ring2At, ring3At   (ISO UTC, or null = "not recorded"),
        steps: [ { from, to, fromLabel, toLabel, hours } ] x5 -- detected -> started -> ring 0 -> 1 -> 2 -> 3; hours is null
               unless BOTH ends are recorded (a missing step is never bridged: started null = both neighbouring gaps null),
        newestRing (0..3 | null), inProgress, replaced (bool).
      The ring list may come in any order; a ring outside 0..3 is ignored; a ring listed twice keeps its earliest time.
      At most 500 rows. A row that is not an object is skipped.
    #>
    param([AllowNull()][object]$Data)
    $list = $Data
    $inner = Get-PimSecImageField $Data 'rows'
    if ($null -ne $inner) { $list = $inner }
    elseif ($Data -is [System.Collections.IDictionary] -or $Data -is [System.Management.Automation.PSCustomObject]) { $list = @() }
    $tmp = New-Object System.Collections.Generic.List[object]
    $idx = 0
    foreach ($r in @($list)) {
        if ($null -eq $r -or $r -is [string] -or $r -is [ValueType]) { continue }
        # review finding 3.1.69: only PIM's OWN releases -- a row that names another product is dropped (never shown here)
        $prodF = "$(Get-PimSecImageField $r 'product')".Trim()
        if ($prodF -and $prodF -ine 'pim-manager') { continue }
        if ($tmp.Count -ge $script:PimSecImageMaxRows) { break }
        $ver = Get-PimSecImageField $r 'version'
        $ver = if ($null -eq $ver -or -not "$ver".Trim()) { $null } else { "$ver".Trim() }
        $det = ConvertTo-PimSecImageUtc (Get-PimSecImageField $r 'detectedAt')
        $sta = ConvertTo-PimSecImageUtc (Get-PimSecImageField $r 'startedAt')
        $ring = @{ 0 = $null; 1 = $null; 2 = $null; 3 = $null }
        foreach ($e in @(Get-PimSecImageField $r 'rings')) {
            if ($null -eq $e -or $e -is [string] -or $e -is [ValueType]) { continue }
            $n = ConvertTo-PimSecImageRingNumber (Get-PimSecImageField $e 'ring')
            if ($null -eq $n) { continue }
            $at = ConvertTo-PimSecImageUtc (Get-PimSecImageField $e 'at')
            if ($null -eq $at) { continue }
            if ($null -eq $ring[$n] -or $at -lt $ring[$n]) { $ring[$n] = $at }
        }
        $seq = @(
            @{ k = 'detected'; label = 'Detected';     at = $det }
            @{ k = 'started';  label = 'Work started'; at = $sta }
            @{ k = 'ring0';    label = 'Ring 0';       at = $ring[0] }
            @{ k = 'ring1';    label = 'Ring 1';       at = $ring[1] }
            @{ k = 'ring2';    label = 'Ring 2';       at = $ring[2] }
            @{ k = 'ring3';    label = 'Ring 3';       at = $ring[3] }
        )
        $steps = @(for ($i = 0; $i -lt 5; $i++) {
            [ordered]@{ from = $seq[$i].k; to = $seq[$i + 1].k; fromLabel = $seq[$i].label; toLabel = $seq[$i + 1].label
                        hours = (Get-PimSecImageHoursBetween -FromUtc $seq[$i].at -ToUtc $seq[$i + 1].at) }
        })
        $nr = ConvertTo-PimSecImageRingNumber (Get-PimSecImageField $r 'newestRing')
        $first = @($seq | Where-Object { $null -ne $_.at } | Select-Object -First 1)
        $row = [ordered]@{
            version      = $ver
            versionLabel = $(if ($null -eq $ver) { $script:PimSecImageNoRelease } else { $ver })
            product      = "$(Get-PimSecImageField $r 'product')".Trim()
            detectedAt   = (ConvertTo-PimSecImageIso $det)
            startedAt    = (ConvertTo-PimSecImageIso $sta)
            ring0At      = (ConvertTo-PimSecImageIso $ring[0])
            ring1At      = (ConvertTo-PimSecImageIso $ring[1])
            ring2At      = (ConvertTo-PimSecImageIso $ring[2])
            ring3At      = (ConvertTo-PimSecImageIso $ring[3])
            steps        = $steps
            newestRing   = $nr
            inProgress   = (ConvertTo-PimSecImageBool (Get-PimSecImageField $r 'inProgress'))
            replaced     = (ConvertTo-PimSecImageBool (Get-PimSecImageField $r 'replaced'))
        }
        $tmp.Add([pscustomobject]@{ i = $idx; t = $(if ($first.Count) { $first[0].at } else { $null }); row = $row }); $idx++
    }
    # newest first by the first recorded step; a row with no recorded time at all goes last, in Invardia's order
    $timed = @($tmp | Where-Object { $null -ne $_.t } | Sort-Object -Property @{ Expression = { $_.t }; Descending = $true }, @{ Expression = { $_.i }; Descending = $false })
    $untimed = @($tmp | Where-Object { $null -eq $_.t } | Sort-Object -Property i)
    # The rows go out ONE BY ONE (each an ordered dictionary, which the pipeline does not unroll); callers wrap the call in
    # @(...). NOT ', @(...)': that writes ONE array object, and @(f) then holds a single nested array -- Count 1 for an empty
    # or a two-row answer, and the browser got rows: [[...]] (found by the Azure runner, 2026-11-26).
    foreach ($t in @(@($timed) + @($untimed))) { $t.row }
}

function Protect-PimSecImageBody {
    <# PURE. The last sweep before a body goes to the browser: the install key, wherever a string carries it, is replaced. #>
    param([AllowNull()][object]$Value, [AllowNull()][string]$InstallKey)
    $k = "$InstallKey".Trim()
    if (-not $k -or $null -eq $Value) { return $Value }
    if ($Value -is [string]) { return $Value.Replace($k, '[install-key]') }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($n in @($Value.Keys)) { $o["$n"] = Protect-PimSecImageBody -Value $Value[$n] -InstallKey $k }
        return $o
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = Protect-PimSecImageBody -Value $p.Value -InstallKey $k }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Value) { $l.Add((Protect-PimSecImageBody -Value $i -InstallKey $k)) }
        return , @($l.ToArray())
    }
    return $Value
}

function Invoke-PimSecImageReleaseHttp {
    <#
      The real HTTP seam: ONE GET -> @{ status; text; error }. .NET HttpClient (PowerShell 7 and Windows PowerShell 5.1), 30 s,
      a non-2xx answer is READ, never thrown. A redirect is NOT followed: the install key goes to the address it was meant for.
    #>
    param([Parameter(Mandatory)][string]$Url, [hashtable]$Headers, [int]$TimeoutSec = 30)
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
    $handler = $null; $client = $null
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $msg = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
        if ($Headers) { foreach ($k in $Headers.Keys) { [void]$msg.Headers.TryAddWithoutValidation("$k", "$($Headers[$k])") } }
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

function Get-PimSecImageReleaseOverview {
    <#
      THE route's decision, which the Manager only wraps (and the tests call without a listener or a network):
        -> @{ status = <HTTP status>; body = <ordered> }   the body never holds the install key.
      200 { ok; days; generatedAt; readUtc; cached; count; rows; notRecorded; noReleaseLabel }
      409 { ok = $false; code = 'no-key'; error }          this install has no install key -- NO call is made
      502 { ok = $false; code = 'key' | 'unreachable' | 'http-<n>' | 'bad-reply'; error }
      Never 401 toward the page: the page reads a 401 as its own sign-in having ended.
      Seams: -GetSetting { param($Name) } (pim.Settings), -Http { param($Url, $Headers) -> @{ status; text; error } }.
      A good answer is kept -CacheSeconds per period (default 300); -Refresh reads again.
    #>
    param([Parameter(Mandatory)][ValidateSet(7, 30, 90, 365)][int]$Days, [scriptblock]$GetSetting, [scriptblock]$Http,
          [switch]$Refresh, [int]$CacheSeconds = $script:PimSecImageCacheSeconds, [AllowNull()][object]$NowUtc = $null)
    $now = if ($NowUtc) { [datetime]$NowUtc } else { [datetime]::UtcNow }
    $key = ''
    if (Get-Command Resolve-PimSetupInstallKey -ErrorAction SilentlyContinue) { try { $key = "$(Resolve-PimSetupInstallKey -GetSetting $GetSetting)".Trim() } catch { $key = '' } }
    $fail = { param($Status, $Code, $Reason) @{ status = $Status; body = (Protect-PimSecImageBody -Value ([ordered]@{ ok = $false; code = $Code; days = $Days; error = ($script:PimSecImageFailPrefix + $Reason) }) -InstallKey $key) } }
    if (-not $key) { return (& $fail 409 'no-key' 'this installation has no Invardia install key.') }

    $c = $script:PimSecImageCache["$Days"]
    if (-not $Refresh -and $CacheSeconds -gt 0 -and $c -and ($now - [datetime]$c.at).TotalSeconds -lt $CacheSeconds -and ($now -ge [datetime]$c.at)) {
        $b = [ordered]@{}; foreach ($n in @($c.body.Keys)) { $b[$n] = $c.body[$n] }; $b['cached'] = $true
        return @{ status = 200; body = (Protect-PimSecImageBody -Value $b -InstallKey $key) }
    }
    if (-not $Http) { $Http = { param($u, $h) Invoke-PimSecImageReleaseHttp -Url $u -Headers $h } }
    $url = "$($script:PimSecImageEndpoint)?days=$Days"
    $headers = @{ $script:PimSecImageKeyHeader = $key; 'Accept' = 'application/json' }
    $reply = $null
    try { $reply = & $Http $url $headers } catch { $reply = @{ status = 0; text = ''; error = "$($_.Exception.Message)" } }
    $st = 0; try { $st = [int](Get-PimSecImageField $reply 'status') } catch { $st = 0 }
    if ($st -eq 0) {
        $why = (("$(Get-PimSecImageField $reply 'error')") -split "`r?`n")[0].Trim()
        return (& $fail 502 'unreachable' ("Invardia could not be reached$(if ($why) { " ($why)" }). Try again in a moment."))
    }
    if ($st -eq 401) { return (& $fail 502 'key' "Invardia did not accept this installation's install key.") }
    if ($st -lt 200 -or $st -ge 300) { return (& $fail 502 "http-$st" "Invardia answered HTTP $st.") }
    $data = $null
    try { $data = "$(Get-PimSecImageField $reply 'text')" | ConvertFrom-Json -ErrorAction Stop } catch { $data = $null }
    # the rows property must be THERE (an empty list is a good answer: nothing in the period); a missing one is not the contract
    $hasRows = ($data -is [System.Management.Automation.PSCustomObject]) -and ($null -ne $data.PSObject.Properties['rows']) -and
               ($null -eq $data.rows -or $data.rows -is [System.Array] -or $data.rows -is [System.Collections.IList])
    if (-not $hasRows -or $null -eq $data.rows) {
        return (& $fail 502 'bad-reply' 'Invardia answered, but not with something PIM Manager can read.')
    }
    $rows = @(ConvertTo-PimSecImageReleaseRows -Data $data)
    $body = [ordered]@{
        ok             = $true
        days           = $Days
        generatedAt    = (ConvertTo-PimSecImageIso (ConvertTo-PimSecImageUtc (Get-PimSecImageField $data 'generatedAt')))
        readUtc        = (ConvertTo-PimSecImageIso $now)
        cached         = $false
        count          = $rows.Count
        rows           = $rows
        notRecorded    = $script:PimSecImageNotRecorded
        noReleaseLabel = $script:PimSecImageNoRelease
    }
    $body = Protect-PimSecImageBody -Value $body -InstallKey $key
    if ($CacheSeconds -gt 0) { $script:PimSecImageCache["$Days"] = @{ at = $now; body = $body } }
    return @{ status = 200; body = $body }
}
