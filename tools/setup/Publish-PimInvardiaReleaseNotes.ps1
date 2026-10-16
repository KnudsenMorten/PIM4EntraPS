#Requires -Version 5.1
<#
.SYNOPSIS
  Send the release notes of a PIM release to Invardia (the fix list the owner reads in the ring-2 / ring-3 approval mail),
  as PIM's OWN publisher identity. Maintainer / release-host script: never run in a customer environment.

.DESCRIPTION
  Owner 2026-10-16 (via Invardia): "i would like to have a little more context of fixes going into a release when i get
  the mail. so i can decide" -- REQUIREMENTS 33.0 "RELEASE CONTEXT IN THE APPROVAL MAIL".

  Invardia's contract (2026-10-16):
    PUT <endpoint>/api/releases/pim-manager/<version>/notes   (publisher identity, Invardia Back Office audience)
    { summary (REQUIRED, <= 4000), title? (<= 200), fixes?: [ { text (<= 1000), ticket?: "SUP-YYYY-NNNNN" } ] (<= 200),
      features?: [ { text } ], breaking? (<= 4000) }   -- plain text; a second call REPLACES the notes.
  Any time after the publish, also before the ring-2 call. The owner's mail shows up to 10 fix lines, each cut at 160
  characters: write each fix as ONE plain sentence (what was wrong, who saw it).

  Without -Apply it is a PLAN: the notes are built, every limit is checked and the exact JSON is printed; nothing is sent.
  With -Apply: sign in as the publisher app (client credentials, CERTIFICATE -- never a secret) and PUT the notes.
    2xx  -> done.  4xx -> Invardia's answer is printed, exit 1.
    5xx  -> "unknown" until read back: GET the same URL; the notes there with OUR summary = done, other notes = not done,
            nothing readable (no GET route yet, a network error) = unknown. The PUT replaces, so sending again is safe.

  The notes:
    -Summary (required unless -FromReleaseNotes), -Title, -Fix "text" or "text|SUP-2026-00012", -Feature "text", -Breaking.
    -FromReleaseNotes builds them from RELEASENOTES.md's "## <version>" section: every "- " bullet is a fix; a bullet that
    lists several points separated by "; " (the RELEASENOTES habit) gives one fix per point. Markdown is made plain text.
    The section's text is the summary unless -Summary is given; an "Upgrade note" line is the breaking text unless
    -Breaking is given; -Fix / -Feature are added after the section's points.
  Limits: a fix or feature over 1000 characters is CUT to 1000 (a warning); over 160 a warning (the mail cuts there);
  more than 200 fixes or features, a summary or breaking text over 4000, a title over 200, an empty summary or a ticket
  not shaped SUP-YYYY-NNNNN -> refused before anything is sent.

  Identity: -ClientId + -CertThumbprint, or -KeyVault: invardia-publisher-clientid-pim-manager /
  invardia-publisher-thumbprint-pim-manager are read from that vault over its REST API (no command-line tool, no module),
  as -KeyVaultClientId + -KeyVaultCertThumbprint (a vault reader, certificate; in -KeyVaultTenantId, default -TenantId)
  or else this host's managed identity.
  No -KeyVaultSubscription: the REST read addresses the vault by name (Publish-PimInvardiaRelease.ps1 needs one for its
  command-line read; this script does not). The publisher certificate (key not exportable) is in Cert:\LocalMachine\My on the publishing machine.

.EXAMPLE
  .\tools\setup\Publish-PimInvardiaReleaseNotes.ps1 -Version 2.4.644 -TenantId <tenant of the publisher app> -FromReleaseNotes          # plan
  .\tools\setup\Publish-PimInvardiaReleaseNotes.ps1 -Version 2.4.644 -TenantId <tenant of the publisher app> -FromReleaseNotes -Apply   # send
.EXAMPLE
  .\tools\setup\Publish-PimInvardiaReleaseNotes.ps1 -Version 2.4.644 -TenantId <tenant> -Summary 'Two fixes for ring 2.' -Fix 'The updater stopped after a licence read failed once on Pro installs.|SUP-2026-00012' -Apply
#>
[CmdletBinding()]
param(
    [string]$Version = '',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$KeyVault = '',
    [string]$KeyVaultClientId = '',
    [string]$KeyVaultCertThumbprint = '',
    [string]$KeyVaultTenantId = '',
    [string]$Endpoint = 'https://invardia.com',
    [string]$Audience = 'api://a5a57537-c847-482b-8878-9a229cbca61b',
    [string]$Summary = '',
    [string]$Title = '',
    [string[]]$Fix = @(),
    [string[]]$Feature = @(),
    [string]$Breaking = '',
    [switch]$FromReleaseNotes,
    [string]$ReleaseNotesPath = '',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }

# ---- the limits (Invardia's contract, 2026-10-16) ----------------------------------------------------------------------
$script:PimNotesLimits = @{ summary = 4000; title = 200; text = 1000; items = 200; breaking = 4000; mailLine = 160 }

function ConvertTo-PimNotesPlainText {
    # PURE. Markdown -> plain text: [a](b) -> a, no ** / __ / backticks, whitespace collapsed. -KeepLines: per line,
    # empty lines dropped, joined with a line feed (the summary and the breaking text keep their lines).
    param([AllowNull()][string]$Text, [switch]$KeepLines)
    if ($KeepLines) { return ((@("$Text" -split "\r?\n") | ForEach-Object { ConvertTo-PimNotesPlainText $_ } | Where-Object { $_ }) -join "`n") }
    $t = "$Text"
    $t = [regex]::Replace($t, '\[([^\]]*)\]\([^)]*\)', '$1')
    $t = $t.Replace('**', '').Replace('`', '')
    $t = [regex]::Replace($t, '(?<![A-Za-z0-9])__|__(?![A-Za-z0-9])', '')
    $t = [regex]::Replace($t, '[\x00-\x1F]', ' ')
    return ([regex]::Replace($t, '\s+', ' ')).Trim()
}

function Split-PimNotesPoints {
    # PURE. One RELEASENOTES bullet -> its points: split on "; " outside parentheses, each point starts with a capital.
    param([AllowNull()][string]$Text)
    $out = New-Object System.Collections.Generic.List[string]
    $s = "$Text"; $depth = 0; $cur = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $s.Length; $i++) {
        $ch = $s[$i]
        if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')' -and $depth -gt 0) { $depth-- }
        if ($ch -eq ';' -and $depth -eq 0 -and ($i + 1 -ge $s.Length -or [char]::IsWhiteSpace($s[$i + 1]))) {
            [void]$out.Add($cur.ToString()); [void]$cur.Clear(); continue
        }
        [void]$cur.Append($ch)
    }
    [void]$out.Add($cur.ToString())
    $res = @()
    foreach ($p in $out) {
        $q = "$p".Trim()
        if (-not $q) { continue }
        $res += ($q.Substring(0, 1).ToUpperInvariant() + $q.Substring(1))
    }
    return $res
}

function Get-PimReleaseNotesSection {
    <# PURE. The "## <version>" section of a RELEASENOTES.md text:
       @{ found; date; bullets = @(raw bullet text); upgrade = 'text' or ''; text = the section's lines, plain }. #>
    param([AllowNull()][string]$Text, [Parameter(Mandatory)][string]$Version)
    $lines = @("$Text" -split "\r?\n")
    $rx = '^##\s+' + [regex]::Escape($Version) + '(\s|$)'
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $rx) { $start = $i; break } }
    if ($start -lt 0) { return @{ found = $false; date = ''; bullets = @(); upgrade = ''; text = '' } }
    $date = ''
    if ($lines[$start] -match '(\d{4}-\d{2}-\d{2})') { $date = $Matches[1] }
    $bullets = New-Object System.Collections.Generic.List[string]
    $upgrade = New-Object System.Collections.Generic.List[string]
    $body = New-Object System.Collections.Generic.List[string]
    $cur = $null
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        $l = $lines[$j]
        if ($l -match '^##\s' -or $l -match '^---\s*$' -or $l -match '^<!--') { break }
        if (-not $l.Trim()) { if ($null -ne $cur) { [void]$bullets.Add($cur); $cur = $null }; continue }
        [void]$body.Add($l.Trim())
        $isUpgrade = ($l -match '(?i)upgrade note')
        if ($l -match '^\s*[-*]\s+(.*)$') {
            if ($null -ne $cur) { [void]$bullets.Add($cur) }
            $cur = $Matches[1]
            if ($isUpgrade) { [void]$upgrade.Add($cur); $cur = $null }
        } elseif ($isUpgrade) {
            if ($null -ne $cur) { [void]$bullets.Add($cur); $cur = $null }
            [void]$upgrade.Add($l.Trim())
        } elseif ($null -ne $cur) {
            $cur = "$cur $($l.Trim())"       # a continuation line of the bullet
        }
    }
    if ($null -ne $cur) { [void]$bullets.Add($cur) }
    $up = ConvertTo-PimNotesPlainText ((@($upgrade) -join ' ') -replace '(?i)^\W*upgrade note\W*', '')
    return @{ found = $true; date = $date; bullets = @($bullets); upgrade = $up; text = (ConvertTo-PimNotesPlainText (@($body) -join "`n") -KeepLines) }
}

function ConvertFrom-PimNotesFixArg {
    # PURE. "text" or "text|SUP-2026-00012" -> @{ text; ticket }. Only a trailing SUP-shaped part after the LAST | is a ticket.
    param([AllowNull()][string]$Value)
    $v = "$Value"
    $k = $v.LastIndexOf('|')
    if ($k -ge 0) {
        $tail = $v.Substring($k + 1).Trim()
        if ($tail -match '^(?i)SUP-') { return @{ text = $v.Substring(0, $k); ticket = $tail.ToUpperInvariant() } }
    }
    return @{ text = $v; ticket = '' }
}

function New-PimReleaseNotesBody {
    <# PURE. The PUT body and what is wrong with it: @{ body = [ordered] or $null; errors = @(); warnings = @(); fixes; features }.
       A text over 1000 is cut to 1000 (a warning) -- never refused; over 160 a warning (the owner's mail cuts there). #>
    param([AllowNull()][string]$Summary, [AllowNull()][string]$Title, [object[]]$Fixes = @(), [string[]]$Features = @(), [AllowNull()][string]$Breaking)
    $L = $script:PimNotesLimits
    if (-not $L) { $L = @{ summary = 4000; title = 200; text = 1000; items = 200; breaking = 4000; mailLine = 160 } }
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $sum = ConvertTo-PimNotesPlainText $Summary -KeepLines
    if (-not $sum) { [void]$errors.Add('summary is required (pass -Summary, or -FromReleaseNotes with a section that has text)') }
    elseif ($sum.Length -gt $L.summary) { [void]$errors.Add("summary is $($sum.Length) characters (Invardia's limit is $($L.summary))") }
    $ttl = ConvertTo-PimNotesPlainText $Title
    if ($ttl.Length -gt $L.title) { [void]$errors.Add("title is $($ttl.Length) characters (Invardia's limit is $($L.title))") }
    $brk = ConvertTo-PimNotesPlainText $Breaking -KeepLines
    if ($brk.Length -gt $L.breaking) { [void]$errors.Add("breaking is $($brk.Length) characters (Invardia's limit is $($L.breaking))") }
    $fx = @()
    $n = 0
    foreach ($f in @($Fixes)) {
        if ($null -eq $f) { continue }
        $n++
        $t = ''; $tk = ''
        if ($f -is [string]) { $p = ConvertFrom-PimNotesFixArg $f; $t = $p.text; $tk = $p.ticket } else { $t = "$($f.text)"; $tk = "$($f.ticket)" }
        $t = ConvertTo-PimNotesPlainText $t; $tk = "$tk".Trim()
        if (-not $t) { [void]$warnings.Add("fix $n is empty -- left out"); continue }
        if ($t.Length -gt $L.text) { [void]$warnings.Add("fix $n is $($t.Length) characters -- cut to $($L.text)"); $t = $t.Substring(0, $L.text).TrimEnd() }
        if ($t.Length -gt $L.mailLine) { [void]$warnings.Add("fix $n is $($t.Length) characters -- the owner's mail shows only the first $($L.mailLine)") }
        $o = [ordered]@{ text = $t }
        if ($tk) {
            if ($tk -cnotmatch '^SUP-\d{4}-\d{5}$') { [void]$errors.Add("fix $n has ticket '$tk' -- not shaped SUP-YYYY-NNNNN") }
            $o['ticket'] = $tk
        }
        $fx += , $o
    }
    if ($fx.Count -gt $L.items) { [void]$errors.Add("$($fx.Count) fixes (Invardia's limit is $($L.items))") }
    $ft = @()
    $m = 0
    foreach ($f in @($Features)) {
        $m++
        $t = ConvertTo-PimNotesPlainText $f
        if (-not $t) { continue }
        if ($t.Length -gt $L.text) { [void]$warnings.Add("feature $m is $($t.Length) characters -- cut to $($L.text)"); $t = $t.Substring(0, $L.text).TrimEnd() }
        $ft += , ([ordered]@{ text = $t })
    }
    if ($ft.Count -gt $L.items) { [void]$errors.Add("$($ft.Count) features (the limit is $($L.items))") }
    $body = [ordered]@{ summary = $sum }
    if ($ttl) { $body['title'] = $ttl }
    if ($fx.Count) { $body['fixes'] = @($fx) }
    if ($ft.Count) { $body['features'] = @($ft) }
    if ($brk) { $body['breaking'] = $brk }
    return @{ body = $(if ($errors.Count) { $null } else { $body }); errors = @($errors); warnings = @($warnings); fixes = $fx.Count; features = $ft.Count }
}

function ConvertTo-PimReleaseNotesJson {
    # PURE. The body as JSON (arrays stay arrays on PS 5.1 and 7).
    param([Parameter(Mandatory)]$Body, [switch]$Pretty)
    if ($Pretty) { return ($Body | ConvertTo-Json -Depth 6) }
    return ($Body | ConvertTo-Json -Depth 6 -Compress)
}

function Get-PimReleaseNotesUrl {
    # PURE. PUT <endpoint>/api/releases/pim-manager/<version>/notes
    param([Parameter(Mandatory)][string]$Endpoint, [Parameter(Mandatory)][string]$Version)
    return "$($Endpoint.TrimEnd('/'))/api/releases/pim-manager/$Version/notes"
}

function Invoke-PimInvardiaNotesCall {
    # One HTTP call, PS 5.1 + 7: a non-2xx answer is read from the exception's response. @{ status; content }.
    param([string]$Method, [string]$Url, [string]$Token, $Body = $null, [string]$ContentType = 'application/json; charset=utf-8', [int]$TimeoutSec = 120)
    try {
        $a = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $Token" }; TimeoutSec = $TimeoutSec; UseBasicParsing = $true }
        if ($null -ne $Body) { $a['Body'] = $Body; $a['ContentType'] = $ContentType }
        $r = Invoke-WebRequest @a
        return @{ status = [int]$r.StatusCode; content = "$($r.Content)" }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { return @{ status = 0; content = "the request failed: $($_.Exception.Message)" } }
        $c = "$($_.ErrorDetails.Message)"; if (-not $c) { $c = "$($_.Exception.Message)" }
        return @{ status = [int]$resp.StatusCode; content = $c }
    }
}

function Get-PimReleaseNotesReadBackVerdict {
    <# PURE (framework 12.22 3(c)). What a GET of the notes says about a PUT that answered 5xx: @{ verdict = done | not-done |
       unknown; reason }. No answer, no GET route (404 / 405) or an unreadable body = unknown -- the PUT replaces, so a resend is safe. #>
    param([AllowNull()]$ReadBack, [AllowNull()][string]$Summary)
    if ($null -eq $ReadBack -or [int]$ReadBack.status -lt 200 -or [int]$ReadBack.status -ge 300) {
        $st = if ($null -eq $ReadBack) { 'none' } else { "HTTP $($ReadBack.status)" }
        return @{ verdict = 'unknown'; reason = "the notes could not be read back ($st) -- sending them again is safe (the PUT replaces)" }
    }
    $j = $null; try { $j = "$($ReadBack.content)" | ConvertFrom-Json } catch { $j = $null }
    $s = $null
    if ($j) { if ($j.PSObject.Properties['summary']) { $s = "$($j.summary)" } elseif ($j.PSObject.Properties['notes'] -and $j.notes -and $j.notes.PSObject.Properties['summary']) { $s = "$($j.notes.summary)" } }
    if ($null -eq $s) { return @{ verdict = 'unknown'; reason = 'the read-back carried no summary -- sending them again is safe (the PUT replaces)' } }
    if ($s.Trim() -eq "$Summary".Trim()) { return @{ verdict = 'done'; reason = 'Invardia holds these notes (same summary) -- the 5xx came after the write' } }
    return @{ verdict = 'not-done'; reason = 'Invardia holds OTHER notes for this version' }
}

function Send-PimReleaseNotes {
    <# The PUT and what it means: @{ ok; status; content; verdict; reason; exitCode }. 2xx ok; 4xx refused (exit 1);
       5xx read back with a GET of the same URL. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Json, [string]$Summary = '')
    $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $r = Invoke-PimInvardiaNotesCall -Method PUT -Url $Url -Token $Token -Body $bytes
    $st = [int]$r.status; $c = "$($r.content)"
    if ($st -ge 200 -and $st -lt 300) { return @{ ok = $true; status = $st; content = $c; verdict = 'done'; reason = 'Invardia stored the notes'; exitCode = 0 } }
    if ($st -ge 400 -and $st -lt 500) { return @{ ok = $false; status = $st; content = $c; verdict = 'refused'; reason = "Invardia refused the notes (HTTP $st)"; exitCode = 1 } }
    if ($st -ge 500 -or $st -eq 0) {
        $g = Invoke-PimInvardiaNotesCall -Method GET -Url $Url -Token $Token
        $rb = Get-PimReleaseNotesReadBackVerdict -ReadBack $g -Summary $Summary
        return @{ ok = ($rb.verdict -eq 'done'); status = $st; content = $c; verdict = $rb.verdict; reason = $rb.reason; exitCode = $(if ($rb.verdict -eq 'done') { 0 } else { 1 }) }
    }
    return @{ ok = $false; status = $st; content = $c; verdict = 'unknown'; reason = "unexpected HTTP $st"; exitCode = 1 }
}

function Get-PimKeyVaultSecretValue {
    # One Key Vault secret over REST (no command-line tool, no module); '' when it cannot be read.
    param([Parameter(Mandatory)][string]$Vault, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Token)
    try {
        $u = "https://$Vault.vault.azure.net/secrets/$Name" + '?api-version=7.4'
        $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60
        return "$($r.value)".Trim()
    } catch { return '' }
}

# ---- main ------------------------------------------------------------------------------------------------------------
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not "$Version".Trim()) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "not a release version: '$Version'" }
Step "release notes for $Version"

$fixIn = @()
$sumIn = $Summary; $brkIn = $Breaking
if ($FromReleaseNotes) {
    if (-not "$ReleaseNotesPath".Trim()) { $ReleaseNotesPath = Join-Path $sol 'RELEASENOTES.md' }
    if (-not (Test-Path -LiteralPath $ReleaseNotesPath)) { throw "RELEASENOTES not found: $ReleaseNotesPath -- nothing was sent" }
    $sec = Get-PimReleaseNotesSection -Text ([IO.File]::ReadAllText($ReleaseNotesPath)) -Version $Version
    if (-not $sec.found) { throw "RELEASENOTES has no '## $Version' section -- write it first; nothing was sent" }
    foreach ($b in @($sec.bullets)) { foreach ($p in @(Split-PimNotesPoints (ConvertTo-PimNotesPlainText $b))) { $fixIn += , $p } }
    if (-not "$sumIn".Trim()) { $sumIn = $sec.text }
    if (-not "$brkIn".Trim()) { $brkIn = $sec.upgrade }
    Write-Host ("    from {0}: section {1}{2}, {3} bullet(s) -> {4} point(s)" -f $ReleaseNotesPath, $Version, $(if ($sec.date) { " ($($sec.date))" } else { '' }), @($sec.bullets).Count, $fixIn.Count)
}
foreach ($f in @($Fix)) { if ("$f".Trim()) { $fixIn += , "$f" } }
$ttlIn = if ("$Title".Trim()) { $Title } else { "PIM Manager $Version" }

$nb = New-PimReleaseNotesBody -Summary $sumIn -Title $ttlIn -Fixes $fixIn -Features @($Feature) -Breaking $brkIn
foreach ($w in @($nb.warnings)) { Write-Host "    WARNING: $w" -ForegroundColor Yellow }
if (@($nb.errors).Count) {
    foreach ($e in @($nb.errors)) { Write-Host "    REFUSED: $e" -ForegroundColor Red }
    throw ("the release notes for {0} break Invardia's limits ({1}) -- nothing was sent" -f $Version, (@($nb.errors) -join '; '))
}
$url = Get-PimReleaseNotesUrl -Endpoint $Endpoint -Version $Version
$json = ConvertTo-PimReleaseNotesJson -Body $nb.body
Write-Host ("    version {0}: {1} fix(es), {2} feature(s), summary {3} characters{4}" -f $Version, $nb.fixes, $nb.features, "$($nb.body.summary)".Length, $(if ($nb.body.Contains('breaking')) { ', breaking text' } else { '' }))
Write-Host "    PUT $url"
Write-Host (ConvertTo-PimReleaseNotesJson -Body $nb.body -Pretty)
if (-not $Apply) {
    Write-Host ("`nPLAN ONLY -- nothing was sent. With -Apply the JSON above is PUT to {0} as Invardia.Publisher.pim-manager (tenant {1})." -f $url, $TenantId) -ForegroundColor Yellow
    Write-Host ("RESULT: version {0}, {1} fix(es), HTTP none (plan)" -f $Version, $nb.fixes)
    return [pscustomobject]@{ sent = $false; version = $Version; fixes = $nb.fixes; features = $nb.features; url = $url; json = $json; status = 0 }
}

Step 'publisher identity (certificate, from Key Vault unless passed)'
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
if (-not $ClientId -or -not $CertThumbprint) {
    # No vault is baked in (the source ships publicly): name it, or pass -ClientId and -CertThumbprint.
    if (-not $KeyVault) { throw 'pass -ClientId and -CertThumbprint, or -KeyVault (with -KeyVaultClientId + -KeyVaultCertThumbprint, or on a host with a managed identity) to read them' }
    $kvTenant = $TenantId
    if ($KeyVaultTenantId) { $kvTenant = $KeyVaultTenantId.Trim() }
    $kvToken = if ($KeyVaultClientId -and $KeyVaultCertThumbprint) { Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $kvTenant -ClientId $KeyVaultClientId -CertThumbprint $KeyVaultCertThumbprint -Force }
               else { Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $kvTenant -UseManagedIdentity -Force }
    if (-not "$kvToken".Trim()) { throw "no token for Key Vault $KeyVault" }
    if (-not $ClientId) { $ClientId = Get-PimKeyVaultSecretValue -Vault $KeyVault -Name 'invardia-publisher-clientid-pim-manager' -Token $kvToken }
    if (-not $CertThumbprint) { $CertThumbprint = Get-PimKeyVaultSecretValue -Vault $KeyVault -Name 'invardia-publisher-thumbprint-pim-manager' -Token $kvToken }
}
if ($ClientId -notmatch '^[0-9a-fA-F-]{36}$' -or $CertThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'publisher client id / certificate thumbprint not found (Key Vault or parameters)' }
$token = Get-PimRestToken -Resource $Audience -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force
if (-not "$token".Trim()) { throw 'no token for the Invardia Back Office audience' }

Step "PUT $url"
$res = Send-PimReleaseNotes -Url $url -Token $token -Json $json -Summary "$($nb.body.summary)"
$c = "$($res.content)"
Write-Host ("    HTTP {0} {1}" -f $res.status, $c.Substring(0, [Math]::Min(800, $c.Length))) -ForegroundColor $(if ($res.ok) { 'Green' } else { 'Red' })
if ($res.status -ge 500 -or $res.status -eq 0) { Write-Host ("    read-back: {0} -- {1}" -f $res.verdict, $res.reason) -ForegroundColor $(if ($res.ok) { 'Green' } else { 'Yellow' }) }
Write-Host ("RESULT: version {0}, {1} fix(es), HTTP {2} -- {3}" -f $Version, $nb.fixes, $res.status, $res.reason)
if ($res.exitCode -ne 0) {
    if ($res.verdict -eq 'refused') { Write-Host "    Invardia's answer: $c" -ForegroundColor Red }
    exit 1
}
[pscustomobject]@{ sent = $true; version = $Version; fixes = $nb.fixes; features = $nb.features; url = $url; status = $res.status; verdict = $res.verdict }
