<#
  PIM4EntraPS -- the MAIL TRANSPORT (framework DOCS/REQUIREMENTS.md 12.3 MAIL-1; owner 2026-10-08: "remember i need to have
  2 options: shared mailbox or smtp relay solution"). ONE setting decides how every mail of this environment leaves:

    pim.Settings 'MailMode'  = none | sharedMailbox | smtp     (absent = sharedMailbox, the default of every install)
    pim.Settings 'SmtpRelay' = { host; port; security (starttls | none); username; from; vaultName; secretName }

  * sharedMailbox -- Microsoft Graph /users/<MailSender>/sendMail as the environment's own managed identity, the send
    right scoped to that one mailbox (tools/setup/Initialize-PimMailSender.ps1). Unchanged; PIM-Notify.ps1 does it.
  * smtp          -- an SMTP relay through System.Net.Mail.SmtpClient (.NET, no module, no package -- MailKit is NOT
    allowed). 🔒 The PASSWORD is never in SQL, never in the page and never in a log: it is a secret in the environment's
    own Key Vault (vaultName / secretName), read at send time by the sender's managed identity.
  * none          -- mail is switched off; every send returns "not sent" with that reason (a TAP mail then cannot
    arrive, and Test-PimTapMailReady says so). MAIL-OFF-1 (2026-11-17): 'none' (alias 'off') is the DELIBERATE
    "not set up (on purpose)" state -- the mail check, the Get Started step, the setup control and the heartbeat Mail field
    report it as NEUTRAL (never a failure, never a fix request); a skipped send is logged once a day at info level.

  Everything here is PURE or has a seam: $global:PIM_SmtpClientFactory (param($Config) -> an object with .Send(MailMessage)
  and .Dispose()) replaces the real SmtpClient in tests; $global:PIM_SmtpSecretReader (param($VaultName, $SecretName))
  replaces the Key Vault read. PS 5.1 + 7.
#>
Set-StrictMode -Off
# SCRIPT-DOC-1 (framework 12.7 + 12.10 item 11): every command this file builds for a person to run comes from the ONE
# command form in tools\setup\_PimScriptDoc.ps1 -- line 1 download, line 2 run (owner 2026-10-11; doc page linked next to it).
. (Join-Path $PSScriptRoot '..\..\tools\setup\_PimScriptDoc.ps1')

function Get-PimMailModeCatalog { @('none', 'sharedMailbox', 'smtp') }
# MAIL-OFF-1 (2026-11-17): the ONE wording of the deliberate "no mail" state (mail check, Get Started, Settings, the log line)
function Get-PimMailOffNote { 'not set up (on purpose): mail is switched off, so TAP codes, approvals and alerts are not sent' }

function Write-PimMailOffNotice {
    <#
      MAIL-OFF-1 (2026-11-17). A mail PIM would send while mail is switched off on purpose is simply not sent: ONE info line
      per process per UTC day (never a warning, never an error). Returns $true when it wrote the line. -NowUtc for tests.
    #>
    param([string]$Type = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $day = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    if ("$($global:PIM_MailOffLoggedDay)" -eq $day) { return $false }
    $global:PIM_MailOffLoggedDay = $day
    Write-Host "  [Mail] mail is not set up (on purpose) -- $(if ($Type) { "'$Type' and " })other mails are not sent today (Settings > Mail & alerting)."
    return $true
}
function Get-PimSmtpRelayDefaultSecretName { 'PIM-SmtpRelayPassword' }

function ConvertTo-PimMailMode {
    # PURE: a stored / posted mode -> its canonical spelling, or '' when it is not one.
    param([AllowNull()][object]$Value)
    $v = "$Value".Trim().Trim('"')
    switch -regex ($v) {
        '^(?i)(none|off)$'                        { return 'none' }
        '^(?i)(sharedmailbox|shared|mailbox)$'    { return 'sharedMailbox' }
        '^(?i)(smtp|smtprelay|relay)$'            { return 'smtp' }
    }
    return ''
}

function Get-PimMailSettingValue {
    # The value of one mail setting in THIS process: the projected global first, then the hydrated settings table.
    param([Parameter(Mandatory)][string]$Name)
    $g = switch ($Name) { 'MailMode' { $global:PIM_MailMode } 'SmtpRelay' { $global:PIM_SmtpRelay } default { $null } }
    if ($null -ne $g -and "$g".Trim()) { return $g }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) { return $global:PIM_NamingConventions[$Name] }
    return $null
}

function Get-PimMailMode {
    # The effective mode: the stored one when it is valid, else 'sharedMailbox' (the default for every install).
    $m = ConvertTo-PimMailMode -Value (Get-PimMailSettingValue -Name 'MailMode')
    if (-not $m) { $m = ConvertTo-PimMailMode -Value $env:PIM_MailMode }
    if ($m) { return $m }
    return 'sharedMailbox'
}

function Test-PimMailAddress {
    param([AllowNull()][string]$Value)
    return ("$Value".Trim() -match '^[^@\s<>"(),;:]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$')
}

function ConvertTo-PimSmtpRelayConfig {
    <#
      PURE: validate an SMTP relay record (hashtable, object or JSON text). Returns @{ ok; config; errors } where errors is
      @{ <field> = 'why' } -- every field is checked, so the page shows every reason at once and nothing is stored.
      🔒 A 'password' field is NEVER part of the record: it is refused here, so it cannot reach pim.Settings by accident.
      System.Net.Mail.SmtpClient speaks STARTTLS only (no implicit TLS), so port 465 is refused with that reason.
    #>
    param([AllowNull()][object]$Value)
    $rec = $Value
    if ($rec -is [string]) { $s = "$rec".Trim(); $rec = $null; if ($s) { try { $rec = $s | ConvertFrom-Json } catch { $rec = $null } } }
    $get = {
        param($o, $n)
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }
        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value }; return $null
    }
    $errors = [ordered]@{}
    if ($null -eq $rec) { return @{ ok = $false; config = $null; errors = @{ host = 'No SMTP relay is configured.' } } }
    foreach ($bad in 'password', 'pass', 'pwd', 'secret') { if ($null -ne (& $get $rec $bad)) { $errors['password'] = 'The password is not stored with the settings -- it goes to the environment''s Key Vault.' } }
    $h = "$(& $get $rec 'host')".Trim()
    if (-not $h) { $errors['host'] = 'Enter the SMTP server (for example smtp.example.com).' }
    elseif ($h.Length -gt 253 -or $h -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') { $errors['host'] = "Not a host name: $h" }
    $portRaw = & $get $rec 'port'
    $port = 0
    if ($null -eq $portRaw -or -not "$portRaw".Trim()) { $port = 587 }
    elseif (-not [int]::TryParse("$portRaw".Trim(), [ref]$port) -or $port -lt 1 -or $port -gt 65535) { $errors['port'] = "Not a port: $portRaw (1-65535)" }
    $sec = "$(& $get $rec 'security')".Trim().ToLowerInvariant()
    if (-not $sec) { $sec = 'starttls' }
    if ($sec -in @('tls', 'ssl', 'on', 'true')) { $sec = 'starttls' }
    if ($sec -in @('off', 'false', 'plain')) { $sec = 'none' }
    if ($sec -notin @('starttls', 'none')) { $errors['security'] = "Choose STARTTLS or none (not '$sec')." }
    if ($port -eq 465 -and -not $errors.Contains('port')) { $errors['port'] = 'Port 465 (implicit TLS) is not supported -- use 587 with STARTTLS (every relay offers it).' }
    $user = "$(& $get $rec 'username')".Trim()
    # ONE-SENDER-1 point A (Invardia 2026-11-25): pim.Settings 'MailSender' is the ONLY From -- the relay record no longer
    # asks for its own. An older record's 'from' is still read (validated when present) as the one-time migration source
    # (Resolve-PimMailSenderFromRelay) and as the From only while MailSender is empty (Get-PimSmtpFromAddress).
    $from = "$(& $get $rec 'from')".Trim()
    if ($from -and -not (Test-PimMailAddress -Value $from)) { $errors['from'] = "Not a mail address: $from" }
    $vault = "$(& $get $rec 'vaultName')".Trim()
    $secretName = "$(& $get $rec 'secretName')".Trim()
    if (-not $secretName) { $secretName = Get-PimSmtpRelayDefaultSecretName }
    if ($user -and -not $vault) { $errors['vaultName'] = 'Enter the Key Vault that holds the password (the environment''s own vault).' }
    if ($vault -and $vault -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') { $errors['vaultName'] = "Not a Key Vault name: $vault (3-24 letters, digits and hyphens)" }
    if ($secretName -notmatch '^[0-9A-Za-z-]{1,127}$') { $errors['secretName'] = "Not a Key Vault secret name: $secretName" }
    $cfg = [ordered]@{ host = $h; port = $port; security = $sec; username = $user; from = $from; vaultName = $vault; secretName = $secretName }
    return @{ ok = ($errors.Count -eq 0); config = $cfg; errors = $errors }
}

function Get-PimSmtpRelayConfig {
    # The stored relay record of THIS environment, validated (ConvertTo-PimSmtpRelayConfig).
    return (ConvertTo-PimSmtpRelayConfig -Value (Get-PimMailSettingValue -Name 'SmtpRelay'))
}

function Get-PimSmtpFromAddress {
    <#
      PURE. ONE-SENDER-1 point A, CORRECTED after the 3.1.69 review (agreed by both reviewers): the From of an SMTP relay mail
      is the relay record's own 'from' WHEN IT IS SET -- it is the address the relay is proven to accept. A different
      pim.Settings 'MailSender' (e.g. an old shared mailbox from before the move to a relay) never switches it unproven: relays
      that enforce the sender would refuse every mail (TAP codes, alerts). That difference is DRIFT (Get-PimSmtpSenderDrift),
      reported, never acted on. MailSender is the From only while the record has no 'from'. Neither -> ''.
    #>
    param([AllowEmptyString()][AllowNull()][string]$MailSender, [AllowNull()][object]$Config)
    $f = ''
    if ($null -ne $Config) { $f = "$(if ($Config -is [System.Collections.IDictionary]) { $Config['from'] } elseif ($Config.PSObject.Properties['from']) { $Config.from } else { '' })".Trim() }
    if ($f) { return $f }
    return "$MailSender".Trim().Trim('"')
}

function Get-PimSmtpSenderDrift {
    <#
      PURE (ONE-SENDER-1, 3.1.69 review). SMTP relay mode: the relay's From and pim.Settings 'MailSender' both set and
      DIFFERENT = drift -- the relay keeps sending as its From; the plain line says what differs and how to make them one
      (send a test mail through the relay with the new address, then save it). Returns @{ drift; relayFrom; mailSender; text }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$MailSender, [AllowNull()][object]$Config)
    $f = ''
    if ($null -ne $Config) { $f = "$(if ($Config -is [System.Collections.IDictionary]) { $Config['from'] } elseif ($Config.PSObject.Properties['from']) { $Config.from } else { '' })".Trim() }
    $s = "$MailSender".Trim().Trim('"')
    if (-not $f -or -not $s -or $f -ieq $s) { return @{ drift = $false; relayFrom = $f; mailSender = $s; text = '' } }
    return @{ drift = $true; relayFrom = $f; mailSender = $s
              text = "the SMTP relay sends as $f, but the mail sender setting is $s -- mail keeps going out as $f (the address the relay accepts). To use one sender, put $s in the relay's From and send a test mail; only a successful test proves the relay accepts it." }
}

function Resolve-PimMailSenderFromRelay {
    <#
      PURE. ONE-SENDER-1 point A: the ONE-TIME migration of SmtpRelay.from into MailSender. Returns @{ migrate; sender; reason }:
      migrate = $true only when MailSender is EMPTY and the relay record carries a valid 'from' -- the caller then writes
      MailSender once (after that MailSender is set, so it never runs again). A set MailSender is never overwritten.
    #>
    param([AllowEmptyString()][AllowNull()][string]$MailSender, [AllowNull()][object]$SmtpRelay)
    if ("$MailSender".Trim().Trim('"')) { return @{ migrate = $false; sender = "$MailSender".Trim().Trim('"'); reason = 'MailSender is set (the ONE sender) -- nothing to migrate' } }
    $rel = ConvertTo-PimSmtpRelayConfig -Value $SmtpRelay
    $f = "$($rel.config.from)".Trim()
    if (-not $f) { return @{ migrate = $false; sender = ''; reason = 'no SmtpRelay.from to migrate' } }
    if (-not (Test-PimMailAddress -Value $f)) { return @{ migrate = $false; sender = ''; reason = "SmtpRelay.from '$f' is not a mail address -- not migrated" } }
    return @{ migrate = $true; sender = $f; reason = "MailSender was empty -- SmtpRelay.from '$f' becomes the ONE sender (one-time migration)" }
}

# ---- ONE-SENDER-1 A1 (Invardia 2026-11-26): a NEW SMTP From is held as PENDING until its test mail passes -------------------
# An operator who saves another From for the relay (Settings > Mail & alerting, PUT /api/settings/mail) does not switch the
# relay at once: the relay keeps sending as its CURRENT From (the address it is proven to accept), the new one is stored in
# pim.Settings 'SmtpRelayFromPending', and the engine's next test mail is sent WITH the new From. Only a test that passes
# makes it the From (SmtpRelay.from, and MailSender when that was the old From or empty); a failed test leaves the current
# From in place and the pending one with its failure. The From is never blanked.
function Get-PimSmtpFromPendingSettingName { <# PURE. The pim.Settings name of the pending From (a literal). #> return 'SmtpRelayFromPending' }

function ConvertTo-PimSmtpFromPending {
    <# PURE. The stored pending From -> { from; previous; savedUtc; by; lastTest } or $null (none, cleared, not a mail address). #>
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { $t = "$v".Trim(); if (-not $t) { return $null }; try { $v = $t | ConvertFrom-Json } catch { return $null } }
    if ($null -eq $v) { return $null }
    $g = { param($k) if ($v -is [System.Collections.IDictionary]) { if ($v.Contains($k)) { $v[$k] } else { $null } } elseif ($v.PSObject.Properties[$k]) { $v.$k } else { $null } }
    if ("$(& $g 'status')".Trim() -ne 'pending') { return $null }
    $f = "$(& $g 'from')".Trim()
    if (-not $f -or -not (Test-PimMailAddress -Value $f)) { return $null }
    return [pscustomobject][ordered]@{ status = 'pending'; from = $f; previous = "$(& $g 'previous')".Trim(); savedUtc = "$(& $g 'savedUtc')".Trim(); by = "$(& $g 'by')".Trim(); lastTest = (& $g 'lastTest') }
}

function Resolve-PimSmtpFromSave {
    <#
      PURE. ONE-SENDER-1 A1: what a save of the relay's From does. -CurrentFrom = the stored relay record's From; -WantedFrom =
      the From the operator typed. Returns @{ from (the From the relay record keeps NOW); pending (the address held until its
      test mail passes, '' = none); clearPending (a pending one is dropped); reason }:
        nothing typed                  -> the current From stays (never blanked)
        the relay has no From yet      -> the typed one is the From at once (nothing proven to keep)
        the same address               -> unchanged; a pending one is dropped (the operator went back)
        another address                -> the CURRENT From stays, the typed one is PENDING
    #>
    param([AllowEmptyString()][AllowNull()][string]$CurrentFrom, [AllowEmptyString()][AllowNull()][string]$WantedFrom)
    $c = "$CurrentFrom".Trim().Trim('"'); $w = "$WantedFrom".Trim().Trim('"')
    if (-not $w) { return @{ from = $c; pending = ''; clearPending = $false; reason = $(if ($c) { "no From typed -- the relay keeps $c" } else { 'no From typed' }) } }
    if (-not $c) { return @{ from = $w; pending = ''; clearPending = $true; reason = "the relay had no From yet -- $w is its From" } }
    if ($w -ieq $c) { return @{ from = $c; pending = ''; clearPending = $true; reason = "the From is unchanged ($c)" } }
    return @{ from = $c; pending = $w; clearPending = $false
              reason = "the new From $w is held until its test mail passes -- mail keeps going out as $c until then" }
}

function New-PimSmtpFromPendingRecord {
    <# PURE. The pim.Settings 'SmtpRelayFromPending' record of a save (status pending), or of a dropped one (-Cleared). #>
    param([AllowEmptyString()][string]$From = '', [AllowEmptyString()][string]$Previous = '', [AllowEmptyString()][string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Cleared)
    $at = $NowUtc.ToUniversalTime().ToString('o')
    if ($Cleared) { return [ordered]@{ status = 'cleared'; from = ''; previous = ''; savedUtc = $at; by = "$By".Trim(); lastTest = $null } }
    return [ordered]@{ status = 'pending'; from = "$From".Trim(); previous = "$Previous".Trim(); savedUtc = $at; by = "$By".Trim(); lastTest = $null }
}

function Complete-PimSmtpFromPending {
    <#
      PURE. ONE-SENDER-1 A1: after the engine's test mail sent WITH the pending From (-TestedFrom). Returns @{ promote; relay
      (the relay config to store, $null = unchanged); mailSender (the MailSender to store, '' = unchanged); pending (the record
      to store); line }. A pass -> the pending From becomes SmtpRelay.from, and MailSender too when it was empty or the old
      From (so the two stay one); the pending record is cleared. A failure -> nothing changes but the pending record's
      lastTest. A pending From that changed since the test was queued (or none) -> nothing is changed at all.
      3.1.71 I4 (3.1.70 re-review B7): it settles ONLY a test that the send path says went out over the SMTP relay
      (-SentAs 'smtp', Send-PimNotifyMail's sentAs) WITH the pending From as its From (-SentFrom, the send path's from). A test
      that went out over Graph (the mode was switched to shared mailbox after it was queued), as another From, or with no
      answer (blank -- fail closed) settles nothing: the pending From stays pending, untouched (settled = $false).
    #>
    param([AllowNull()][object]$Pending, [AllowNull()][object]$Relay, [AllowEmptyString()][AllowNull()][string]$MailSender, [bool]$Ok,
          [AllowEmptyString()][string]$Reason = '', [AllowEmptyString()][string]$TestedFrom = '',
          [AllowEmptyString()][AllowNull()][string]$SentAs = '', [AllowEmptyString()][AllowNull()][string]$SentFrom = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $p = ConvertTo-PimSmtpFromPending -Value $Pending
    $tf = "$TestedFrom".Trim()
    if ($null -eq $p -or -not $tf -or $p.from -ine $tf) { return @{ promote = $false; settled = $false; relay = $null; mailSender = ''; pending = $null; line = 'no pending From for this test mail -- nothing changed' } }
    $sa = "$SentAs".Trim(); $sf = "$SentFrom".Trim()
    if ($sa -ine 'smtp' -or $sf -ine $p.from) {
        return @{ promote = $false; settled = $false; relay = $null; mailSender = ''; pending = $null
                  line = "the test mail did not go out over the SMTP relay as $($p.from) (sent as '$(if ($sa) { $sa } else { 'unknown' })'$(if ($sf) { ", from $sf" })) -- the pending From stays pending; send the test mail again over the relay" }
    }
    $at = $NowUtc.ToUniversalTime().ToString('o')
    if (-not $Ok) {
        $one = "$Reason" -replace "[\r\n]+", ' '; if ($one.Length -gt 300) { $one = $one.Substring(0, 300) }
        $rec = [ordered]@{ status = 'pending'; from = $p.from; previous = $p.previous; savedUtc = $p.savedUtc; by = $p.by; lastTest = [ordered]@{ ok = $false; at = $at; reason = $one } }
        return @{ promote = $false; settled = $true; relay = $null; mailSender = ''; pending = $rec; line = "the test mail as $($p.from) did not pass -- the relay keeps its current From" }
    }
    $cfg = ConvertTo-PimSmtpRelayConfig -Value $Relay
    if (-not $cfg.ok) { return @{ promote = $false; settled = $false; relay = $null; mailSender = ''; pending = $null; line = 'the stored relay record is not valid -- the pending From was not applied' } }
    $old = "$($cfg.config.from)".Trim()
    $new = [ordered]@{}; foreach ($k in @($cfg.config.Keys)) { $new[$k] = $cfg.config[$k] }
    $new['from'] = $p.from
    $ms = "$MailSender".Trim().Trim('"')
    $msNew = if (-not $ms -or ($old -and $ms -ieq $old)) { $p.from } else { '' }
    return @{ promote = $true; settled = $true; relay = $new; mailSender = $msNew; pending = (New-PimSmtpFromPendingRecord -Cleared -By $p.by -NowUtc $NowUtc)
              line = "the test mail as $($p.from) passed -- it is the relay's From now$(if ($old) { " (was $old)" })" }
}

function Get-PimSmtpRelayPassword {
    # The relay password, read at send time from Key Vault by THIS process's identity (the managed identity when hosted).
    # '' when the relay needs no sign-in. Throws when it needs one and the secret cannot be read (the caller reports it).
    param([Parameter(Mandatory)][object]$Config)
    if (-not "$($Config.username)".Trim()) { return '' }
    $reader = $global:PIM_SmtpSecretReader
    if ($reader -is [scriptblock]) { return "$(& $reader "$($Config.vaultName)" "$($Config.secretName)")" }
    if (Get-Command Get-PimSqlSecretFromKeyVault -ErrorAction SilentlyContinue) { return "$(Get-PimSqlSecretFromKeyVault -VaultName "$($Config.vaultName)" -SecretName "$($Config.secretName)")" }
    if (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue) {
        $tok = Get-PimRestToken -Resource 'https://vault.azure.net'
        return "$((Invoke-RestMethod -Method GET -Uri ("https://{0}.vault.azure.net/secrets/{1}?api-version=7.4" -f $Config.vaultName, $Config.secretName) -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop).value)"
    }
    throw 'no Key Vault reader is loaded in this runtime'
}

function New-PimSmtpMailMessage {
    # The .NET message: From = the relay's From address, every recipient in To, HTML body + a plain-text alternative,
    # attachments (@{ name; contentType; bytes }).
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string[]]$To, [string]$Subject, [string]$BodyHtml, [string]$BodyText, [object[]]$Attachments = @())
    $m = New-Object System.Net.Mail.MailMessage
    $m.From = New-Object System.Net.Mail.MailAddress($From)
    foreach ($t in @($To | Where-Object { "$_".Trim() })) { $m.To.Add("$t".Trim()) }
    $m.Subject = "$Subject"
    $m.SubjectEncoding = [System.Text.Encoding]::UTF8
    $m.BodyEncoding = [System.Text.Encoding]::UTF8
    $m.IsBodyHtml = $true
    $m.Body = "$BodyHtml"
    if ("$BodyText".Trim()) {
        $alt = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString("$BodyText", [System.Text.Encoding]::UTF8, 'text/plain')
        $m.AlternateViews.Add($alt)
    }
    foreach ($a in @($Attachments | Where-Object { $_ -and $_.bytes -and "$($_.name)".Trim() })) {
        $ct = if ("$($a.contentType)".Trim()) { "$($a.contentType)" } else { 'application/octet-stream' }
        $att = New-Object System.Net.Mail.Attachment((New-Object System.IO.MemoryStream(, [byte[]]$a.bytes)), "$($a.name)", $ct)
        # MAIL-2: an inline image (the logo, <img src="cid:pim-logo">) is sent with its Content-ID and an inline disposition
        if ("$($a.contentId)".Trim()) { $att.ContentId = "$($a.contentId)".Trim(); if ($a.isInline) { $att.ContentDisposition.Inline = $true } }
        $m.Attachments.Add($att)
    }
    return $m
}

function New-PimSmtpClient {
    # The real client (or the test seam). EnableSsl = STARTTLS on the plain port (System.Net.Mail has no implicit TLS).
    param([Parameter(Mandatory)][object]$Config, [string]$Password)
    $f = $global:PIM_SmtpClientFactory
    if ($f -is [scriptblock]) { return (& $f $Config $Password) }
    $c = New-Object System.Net.Mail.SmtpClient("$($Config.host)", [int]$Config.port)
    $c.EnableSsl = ("$($Config.security)" -eq 'starttls')
    $c.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
    $c.Timeout = 30000
    $c.UseDefaultCredentials = $false
    if ("$($Config.username)".Trim()) { $c.Credentials = New-Object System.Net.NetworkCredential("$($Config.username)", "$Password") }
    return $c
}

function Send-PimSmtpMail {
    <#
      Send ONE rendered mail through the configured relay. Returns @{ sent; reason; sentAs = 'smtp' }; never throws (the
      notify path reports, it does not crash a run). The reason never carries the password.
    #>
    param([Parameter(Mandatory)][object]$Config, [Parameter(Mandatory)][string[]]$Recipients, [string]$Subject, [string]$BodyHtml, [string]$BodyText,
          [object[]]$Attachments = @(),
          # ONE-SENDER-1 point A: the From = pim.Settings MailSender (Get-PimSmtpFromAddress); '' = the record's own 'from'
          [string]$From = '')
    $fromAddr = Get-PimSmtpFromAddress -MailSender $From -Config $Config
    if (-not $fromAddr) { return @{ sent = $false; sentAs = 'smtp'; reason = 'no From address: set the mail sender (pim.Settings MailSender, Settings > Mail & alerting) -- the SMTP relay sends as it' } }
    $pw = ''
    try { $pw = Get-PimSmtpRelayPassword -Config $Config }
    catch { return @{ sent = $false; sentAs = 'smtp'; reason = "the SMTP relay password could not be read from Key Vault '$($Config.vaultName)' (secret '$($Config.secretName)'): $(($_.Exception.Message -split "`n")[0]) -- the sending identity needs 'Key Vault Secrets User' on that secret" } }
    if ("$($Config.username)".Trim() -and -not "$pw") { return @{ sent = $false; sentAs = 'smtp'; reason = "the SMTP relay password secret '$($Config.secretName)' in Key Vault '$($Config.vaultName)' is empty" } }
    $msg = $null; $client = $null
    try {
        $msg = New-PimSmtpMailMessage -From $fromAddr -To $Recipients -Subject $Subject -BodyHtml $BodyHtml -BodyText $BodyText -Attachments $Attachments
        $client = New-PimSmtpClient -Config $Config -Password $pw
        $client.Send($msg)
        return @{ sent = $true; sentAs = 'smtp'; reason = '' }
    } catch {
        $e = $_.Exception
        $txt = "$($e.Message)"
        if ($e.InnerException) { $txt += " ($($e.InnerException.Message))" }
        if ($pw) { $txt = $txt.Replace("$pw", '***') }
        return @{ sent = $false; sentAs = 'smtp'; reason = "SMTP relay $($Config.host):$($Config.port) refused or failed: $(($txt -split "`n")[0])" }
    } finally {
        $pw = $null
        if ($msg) { try { $msg.Dispose() } catch { } }
        if ($client -and ($client | Get-Member -Name Dispose -ErrorAction SilentlyContinue)) { try { $client.Dispose() } catch { } }
    }
}

function Get-PimMailTestFingerprint {
    # PURE: what a "test mail sent" proof was taken against. A changed relay, From address or mailbox makes an older proof
    # stale, so the Get Started step goes back to "not done" until the new settings are proven.
    param([string]$Mode, [string]$Sender, [object]$Smtp)
    $m = ConvertTo-PimMailMode -Value $Mode
    # ONE-SENDER-1 (3.1.69 review): the From of a relay mail = the record's own 'from' when set (else MailSender) -- the same
    # address as before ONE-SENDER-1, so an older proof stays valid
    if ($m -eq 'smtp') { return ('smtp|{0}|{1}|{2}|{3}' -f "$($Smtp.host)".ToLowerInvariant(), "$($Smtp.port)", (Get-PimSmtpFromAddress -MailSender $Sender -Config $Smtp).ToLowerInvariant(), "$($Smtp.username)".ToLowerInvariant()) }
    if ($m -eq 'sharedMailbox') { return ('sharedMailbox|{0}' -f "$Sender".Trim().ToLowerInvariant()) }
    return "$m"
}

function Get-PimMailSenderShown {
    <#
      PURE (INSTALL-FIX, REQUIREMENTS 100.25 item 4). What a person SEES as the mail sender. MailSender stays the mailbox's
      UPN -- the key Microsoft Graph sends by (BUG-296), often on the tenant's initial domain -- but the customer chose the PRIMARY
      SMTP address (name@their domain). -Record = pim.Settings 'MailSenderAddress' { sender; address } as the mail-sender setup
      (Initialize-PimMailSender, Get Started > Mail sender step 2) stored it; it counts only while its 'sender' is still -Sender.
      Returns @{ address; upn; text }: text = "<address> (mailbox UPN <upn>)" when they differ, else the sender as it is.
    #>
    param([AllowEmptyString()][string]$Sender, [AllowNull()][object]$Record)
    $s = "$Sender".Trim().Trim('"')
    if ($Record -is [string] -and "$Record".Trim()) { try { $Record = $Record | ConvertFrom-Json } catch { $Record = $null } }
    $g = { param($n) if ($null -eq $Record) { '' } elseif ($Record -is [System.Collections.IDictionary]) { "$($Record[$n])".Trim() } elseif ($Record.PSObject.Properties[$n]) { "$($Record.$n)".Trim() } else { '' } }
    $addr = ''
    if ($s -and (& $g 'sender') -ieq $s) { $addr = & $g 'address' }
    if (-not $addr -or $addr -ieq $s) { return @{ address = $s; upn = $s; text = $s } }
    return @{ address = $addr; upn = $s; text = "$addr (mailbox UPN $s)" }
}

function Get-PimMailSetupState {
    <#
      PURE: the Get Started / Settings verdict for mail, from the stored values. Returns @{ mode; done; note; sender; smtp }.
        sharedMailbox -- done when a sender mailbox is stored and no later test mail to it FAILED.
        smtp          -- done when the relay record is valid AND a test mail through exactly these settings was SENT.
        none          -- MAIL-OFF-1: done + off (switched off on purpose = "not set up (on purpose)", a neutral choice);
                         proven stays $null (nothing is sent, nothing to prove).
      -LastTest: @{ ok; fingerprint; at; reason } as the test-mail route stores it (pim.Settings 'MailLastTest').
    #>
    param([string]$Mode, [string]$Sender, [AllowNull()][object]$SmtpRelay, [AllowNull()][object]$LastTest,
          # 100.25 item 4: pim.Settings 'MailSenderAddress' -- the note names the PRIMARY SMTP address, the UPN as detail
          [AllowNull()][object]$SenderAddressRecord)
    $m = ConvertTo-PimMailMode -Value $Mode; if (-not $m) { $m = 'sharedMailbox' }
    $smtp = ConvertTo-PimSmtpRelayConfig -Value $SmtpRelay
    $fp = Get-PimMailTestFingerprint -Mode $m -Sender $Sender -Smtp $smtp.config
    $proof = $null
    if ($LastTest -and "$($LastTest.fingerprint)" -eq $fp) { $proof = [bool]$LastTest.ok }
    $s = "$Sender".Trim()
    switch ($m) {
        # MAIL-OFF-1 (2026-11-17): switched off ON PURPOSE = a finished choice (done), not a missing step; 'off' says so
        'none' { return @{ mode = $m; done = $true; off = $true; note = (Get-PimMailOffNote); sender = $s; proven = $null } }
        'smtp' {
            # ONE-SENDER-1 (3.1.69 review): the relay's own From when set, else MailSender; a different MailSender is drift
            $sf = Get-PimSmtpFromAddress -MailSender $s -Config $smtp.config
            if (-not $smtp.ok) { return @{ mode = $m; done = $false; note = 'SMTP relay: ' + (@($smtp.errors.Values) -join ' '); sender = $sf; proven = $null } }
            if (-not $sf) { return @{ mode = $m; done = $false; note = 'SMTP relay configured, but no mail sender is set -- the relay sends as the mail sender'; sender = ''; proven = $null } }
            if ($proof -eq $true) { return @{ mode = $m; done = $true; note = "SMTP relay $($smtp.config.host):$($smtp.config.port) as $sf -- test mail sent"; sender = $sf; proven = $true } }
            if ($proof -eq $false) { return @{ mode = $m; done = $false; note = "SMTP relay configured, but the test mail failed: $($LastTest.reason)"; sender = $sf; proven = $false } }
            return @{ mode = $m; done = $false; note = 'SMTP relay configured -- send a test mail to prove it'; sender = $sf; proven = $null }
        }
        default {
            if (-not $s) { return @{ mode = 'sharedMailbox'; done = $false; note = 'no sender: TAP codes and notifications are not sent'; sender = ''; proven = $null } }
            $shown = (Get-PimMailSenderShown -Sender $s -Record $SenderAddressRecord).text
            if ($proof -eq $false) { return @{ mode = 'sharedMailbox'; done = $false; note = "sends as $shown, but the test mail failed: $($LastTest.reason)"; sender = $s; proven = $false } }
            return @{ mode = 'sharedMailbox'; done = $true; note = "sends as $shown$(if ($proof -eq $true) { ' -- test mail sent' })"; sender = $s; proven = $proof }
        }
    }
}

# =====================================================================================================================
# MAIL CHECK (owner 2026-10-08: "mail is optional, but include it in the get started + home and test exactly what is
# needed, provide scripts so customer can run it"). ONE pure verdict, one line per PREREQUISITE, shown in Get Started >
# Mail sender and in the Home permissions banner (Verify permissions re-runs it). Mail is OPTIONAL: an incomplete check is
# amber on Home and a skippable Get Started step -- it never turns anything red and never fails an install.
# A line is @{ id; title; state = ok | missing | failed | unproven | unknown; detail; fix }. 'unproven' = "not proven
# yet": the check never GUESSES that a send right works -- only the identity's own last real send (or test mail) proves it.
# 'waiting' (MAIL-STEP-PROOF, owner 2026-10-09) = the ENGINE job's send right is not proven yet: an INFO line that counts as
# complete (the customer cannot prove it on demand; Send test mail queues an engine test send). Only a recorded engine
# send FAILURE turns that row red.
# =====================================================================================================================
$script:PimGraphMailSendAppRoleId = 'b633e1c5-b582-4048-a93e-9f11b44c7e96'   # Microsoft Graph application permission Mail.Send

function Get-PimMailSetupCommand {
    <#
      PURE. The published, browser-sign-in command lines for one fix, with this environment's values filled in (a
      <placeholder> for an unknown one). -Kind mailbox = Initialize-PimMailSender.ps1 (an Exchange or Global Administrator:
      creates / scopes the shared mailbox, gives the ENGINE job's identity its scoped send right, revokes a tenant-wide
      Mail.Send); smtpPassword = Set-PimSmtpRelayPassword.ps1. Never a certificate, never a secret.
      🔒 SECURE-WEB-1 / MAIL-WEB-RIGHTS-1: both commands name the ENGINE job's identity ONLY (-Setup tickObjectId). The web
      app (PIM Manager) sends no mail and reads no Key Vault secret, so its identity is never put in a fix command -- a
      -Setup managerObjectId is ignored here.
    #>
    param([ValidateSet('mailbox', 'smtpPassword')][string]$Kind, [object]$Setup, [object]$Smtp)
    $g = { param($o, $n) if ($null -eq $o) { '' } elseif ($o -is [System.Collections.IDictionary]) { "$($o[$n])".Trim() } elseif ($o.PSObject.Properties[$n]) { "$($o.$n)".Trim() } else { '' } }
    $v = { param($x, $ph) if ("$x".Trim()) { "$x".Trim() } else { $ph } }
    $miArg = & $v (& $g $Setup 'tickObjectId') '<engine job identity object id>'
    if ($Kind -eq 'mailbox') {
        $run = '.\Initialize-PimMailSender.ps1 -TenantId ' + (& $v (& $g $Setup 'tenantId') '<tenant id>') + ' -ManagedIdentityObjectId ' + $miArg +
               ' -SqlServerFqdn ' + (& $v (& $g $Setup 'sqlServer') '<server>.database.windows.net')
        return @(Get-PimSupportScriptCommand -Script 'Initialize-PimMailSender' -Run @($run))
    }
    $vault = & $v (& $g $Smtp 'vaultName') (& $v (& $g $Setup 'vaultHint') '<key vault name>')
    $sec = & $g $Smtp 'secretName'
    $run = '.\Set-PimSmtpRelayPassword.ps1 -TenantId ' + (& $v (& $g $Setup 'tenantId') '<tenant id>') + ' -SubscriptionId ' + (& $v (& $g $Setup 'subscriptionId') '<subscription id>') +
           ' -VaultName ' + $vault + $(if ($sec -and $sec -ne (Get-PimSmtpRelayDefaultSecretName)) { " -SecretName $sec" } else { '' }) + ' -ManagedIdentityObjectId ' + $miArg
    return @(Get-PimSupportScriptCommand -Script 'Set-PimSmtpRelayPassword' -Run @($run))
}

function Get-PimMailSendProofVerdict {
    <#
      PURE. Does ONE identity's own last real send prove its send right for THESE settings? -Proof = the identity's record
      in pim.Settings 'MailSendProof' (@{ ok; at; reason; mode; sender }). A record for another mode or another sender is
      stale = not proven. Returns @{ state = ok | failed | unproven; detail }.
    #>
    param([AllowNull()]$Proof, [string]$Mode, [string]$Sender)
    $g = { param($n) if ($null -eq $Proof) { $null } elseif ($Proof -is [System.Collections.IDictionary]) { $Proof[$n] } elseif ($Proof.PSObject.Properties[$n]) { $Proof.$n } else { $null } }
    if ($null -eq $Proof -or $null -eq (& $g 'ok')) { return @{ state = 'unproven'; detail = 'not proven yet' } }
    $pm = ConvertTo-PimMailMode -Value "$(& $g 'mode')"; $ps = "$(& $g 'sender')".Trim()
    if (($pm -and $pm -ne $Mode) -or ($ps -and "$Sender".Trim() -and $ps -ine "$Sender".Trim())) { return @{ state = 'unproven'; detail = 'not proven yet for the current settings (the last send was with other settings)' } }
    $at = "$(& $g 'at')".Trim()
    if ([bool](& $g 'ok')) { return @{ state = 'ok'; detail = "proven by its last real send$(if ($at) { " ($at)" })" } }
    return @{ state = 'failed'; detail = "its last send FAILED$(if ($at) { " ($at)" }): $("$(& $g 'reason')".Trim())" }
}

function Get-PimMailCheck {
    <#
      PURE. Every mail prerequisite as its own line, from facts the caller read (the Manager: Graph, the store, Key Vault).
      -Facts:
        mode (stored MailMode or ''), sender, alertRecipients[], lastTest (MailLastTest), smtp (the SmtpRelay record),
        senderLookup  @{ found = $true|$false|$null; upn; error }       -- Graph /users/<sender> as the Manager reads it
        identities    @(@{ role = engine|manager; label; proof; tenantWideMailSend = $true|$false|$null })
        smtpPassword  @{ readable = $true|$false|$null; reason }        -- the ENGINE's own check of the secret (never its value)
        setup         the values the fix commands carry (tenantId, tickObjectId = the ENGINE job's identity, subscriptionId,
                      sqlServer, vaultHint); the web app's identity is never one of them (SECURE-WEB-1)
        engineTest    the engine test request (pim.Settings 'MailEngineTest') -- only words the engine row while it waits
        setupCheck    the mail-sender script's read-back (pim.Settings 'MailSenderSetupCheck'): with the Manager's successful
                      test mail it grants the engine row at once (Get-PimMailSetupCheckVerdict)
      Returns @{ mode; complete; lines[]; summary }. complete = every line ok. Mail is optional: the caller shows an
      incomplete check as amber / a skippable step, never red.
    #>
    param([hashtable]$Facts = @{})
    $f = { param($n) if ($Facts.ContainsKey($n)) { $Facts[$n] } else { $null } }
    $gv = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $title, $state, $detail, $fix) $lines.Add([pscustomobject][ordered]@{ id = $id; title = $title; state = $state; detail = "$detail"; fix = "$fix" }) }
    $setup = & $f 'setup'
    $mbFix = (Get-PimMailSetupCommand -Kind mailbox -Setup $setup) -join "`n"
    $storedMode = ConvertTo-PimMailMode -Value (& $f 'mode')
    $sender = "$(& $f 'sender')".Trim()
    $mode = if ($storedMode) { $storedMode } elseif ($sender) { 'sharedMailbox' } else { '' }
    $guiFix = 'PIM Manager > Get Started > Mail sender (or Settings > Mail & alerting): choose Shared mailbox or SMTP relay'
    if (-not $mode) { & $add 'mail-mode' 'Mail mode chosen' 'missing' 'no mail mode is chosen yet -- TAP codes, approvals and alerts are not sent' $guiFix }
    elseif ($mode -eq 'none') {
        # MAIL-OFF-1 (2026-11-17): switched off ON PURPOSE is a NEUTRAL state ('off'): one line, complete, nothing to fix and
        # nothing else to check (no sender, no send right, no alert mail) -- never amber, never a reminder, never a ticket.
        & $add 'mail-mode' 'Mail mode chosen' 'off' (Get-PimMailOffNote) ''
        return [pscustomobject][ordered]@{ mode = 'none'; complete = $true; proven = $false; waiting = 0; off = $true; lines = @($lines.ToArray()); summary = "mail: $(Get-PimMailOffNote)" }
    }
    else { & $add 'mail-mode' 'Mail mode chosen' 'ok' $(if ($mode -eq 'smtp') { 'SMTP relay' } else { "shared mailbox$(if (-not $storedMode) { ' (the default)' })" }) '' }

    if ($mode -eq 'smtp') {
        $relay = ConvertTo-PimSmtpRelayConfig -Value (& $f 'smtp')
        $c = $relay.config
        # ONE-SENDER-1 (3.1.69 review): the relay sends as its own From when set (else MailSender); a different MailSender is drift
        $smtpFrom = Get-PimSmtpFromAddress -MailSender $sender -Config $c
        if ($relay.ok) { & $add 'smtp-settings' 'SMTP relay: server, port, user' 'ok' ("$($c.host):$($c.port) ($($c.security)) as $(if ($smtpFrom) { $smtpFrom } else { '(no mail sender set)' })" + $(if ($c.username) { ", user $($c.username)" } else { ', no sign-in' })) '' }
        else { & $add 'smtp-settings' 'SMTP relay: server, port, user' 'missing' ((@($relay.errors.Values) | ForEach-Object { "$_" }) -join ' ') 'PIM Manager > Get Started > Mail sender > SMTP relay: fill in the server, port, From address and user name' }
        # ONE-SENDER-1 (3.1.69 review): the relay's From and the mail sender setting differ -> an INFO line (mail still works
        # as the relay's From; nothing is switched unproven), shown in Get Started / Home and counted as drift by the heartbeat
        $dr = Get-PimSmtpSenderDrift -MailSender $sender -Config $c
        if ($dr.drift) { & $add 'smtp-sender-drift' 'One mail sender' 'info' $dr.text '' }
        $pwFix = (Get-PimMailSetupCommand -Kind smtpPassword -Setup $setup -Smtp $c) -join "`n"
        if ($relay.ok -and -not "$($c.username)".Trim()) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'ok' 'the relay needs no sign-in -- no password' '' }
        else {
            $pw = & $f 'smtpPassword'; $rd = & $gv $pw 'readable'
            # SECURE-WEB-1 (3.1.26): the ENGINE (the sender) reads the password -- the web app reads no secret; the fact is
            # the engine's own check at its test mail (pim.Settings 'MailSmtpPasswordCheck')
            if ($rd -eq $true) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'ok' "secret '$($c.secretName)' in Key Vault '$($c.vaultName)' is readable by the engine (the sender)" '' }
            elseif ($rd -eq $false) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'failed' "the engine cannot read the password: $(& $gv $pw 'reason')" $pwFix }
            else { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'unknown' "not checked yet$(if ("$(& $gv $pw 'reason')".Trim()) { ': ' + "$(& $gv $pw 'reason')".Trim() } else { ' (the relay settings are incomplete)' })" $pwFix }
        }
        $lt = & $f 'lastTest'
        $fp = Get-PimMailTestFingerprint -Mode 'smtp' -Sender $sender -Smtp $c   # ONE-SENDER-1: the From is MailSender
        $ltOk = & $gv $lt 'ok'
        if ($lt -and "$(& $gv $lt 'fingerprint')" -eq $fp -and $ltOk -eq $true) { & $add 'smtp-test' 'Test mail sent through these settings' 'ok' "sent $("$(& $gv $lt 'at')".Trim()) to $("$(& $gv $lt 'to')".Trim())" '' }
        elseif ($lt -and "$(& $gv $lt 'fingerprint')" -eq $fp -and $ltOk -eq $false) { & $add 'smtp-test' 'Test mail sent through these settings' 'failed' "the test mail FAILED: $("$(& $gv $lt 'reason')".Trim())" 'PIM Manager > Get Started > Mail sender: correct the relay settings, then Save and send a test mail' }
        else { & $add 'smtp-test' 'Test mail sent through these settings' 'unproven' 'not proven yet -- no test mail was sent through these exact settings' 'PIM Manager > Get Started > Mail sender: Save and send a test mail' }
    }
    elseif ($mode -eq 'sharedMailbox') {
        $lk = & $f 'senderLookup'; $found = & $gv $lk 'found'
        if (-not $sender) { & $add 'mail-mailbox' 'Sender mailbox exists' 'missing' 'no sender mailbox is set' $mbFix }
        elseif ($found -eq $true) {
            # 100.25 item 4: name the PRIMARY SMTP address the customer chose (the stored record, else the directory's 'mail' of
            # the UPN the lookup returned); the stored sender is the UPN (BUG-296) and is shown as the detail.
            $shownSender = Get-PimMailSenderShown -Sender $sender -Record (& $f 'senderAddress')
            $lkMail = "$(& $gv $lk 'mail')".Trim()
            if ($shownSender.address -ieq $sender -and $lkMail -and $lkMail -ine $sender) { $shownSender = Get-PimMailSenderShown -Sender $sender -Record @{ sender = $sender; address = $lkMail } }
            & $add 'mail-mailbox' 'Sender mailbox exists' 'ok' "$($shownSender.text) (Microsoft Graph resolves it$(if ("$(& $gv $lk 'upn')".Trim() -and "$(& $gv $lk 'upn')".Trim() -ine $sender) { " as $(& $gv $lk 'upn')" }))" '' }
        elseif ($found -eq $false) { & $add 'mail-mailbox' 'Sender mailbox exists' 'failed' "Microsoft Graph does not find '$sender' -- PIM sends as exactly this address" $mbFix }
        else { & $add 'mail-mailbox' 'Sender mailbox exists' 'unknown' "'$sender' could not be looked up$(if ("$(& $gv $lk 'error')".Trim()) { ": $(& $gv $lk 'error')" })" $mbFix }
        $ids = @(@(& $f 'identities') | Where-Object { $_ })
        # SECURE-WEB-1 (3.1.26): only the ENGINE sends mail -- the web app's identity holds no send right any more, so its
        # row is gone (it is still named below when it holds a tenant-wide Mail.Send: that must never be).
        foreach ($role in @('engine')) {
            $i = @($ids | Where-Object { "$(& $gv $_ 'role')" -eq $role }) | Select-Object -First 1
            $title = if ($role -eq 'engine') { 'Engine job: scoped send right' } else { 'PIM Manager: scoped send right' }
            $prove = if ($role -eq 'engine') { "the engine's next mail (a TAP code, a reminder or an alert) proves it" } else { 'PIM Manager > Get Started > Mail sender: Save and send a test mail (the Manager sends it as its own identity)' }
            if (-not $sender) { & $add "mail-send-$role" $title 'missing' 'no sender mailbox yet' $mbFix; continue }
            $pv = Get-PimMailSendProofVerdict -Proof (& $gv $i 'proof') -Mode 'sharedMailbox' -Sender $sender
            $lbl = "$(& $gv $i 'label')".Trim()
            switch ($pv.state) {
                'ok'     { & $add "mail-send-$role" $title 'ok' "$(if ($lbl) { "$lbl -- " })$($pv.detail)" '' }
                'failed' { & $add "mail-send-$role" $title 'failed' "$(if ($lbl) { "$lbl -- " })$($pv.detail)" $mbFix }
                default  {
                    $sc = if ($role -eq 'engine') { Get-PimMailSetupCheckVerdict -SetupCheck (& $f 'setupCheck') -Sender $sender -Setup $setup -ManagerProof (& $gv (@($ids | Where-Object { "$(& $gv $_ 'role')" -eq 'manager' }) | Select-Object -First 1) 'proof') } else { $null }
                    if ($sc -and $sc.ok) {
                        # MAIL-STEP-PROOF (owner 2026-10-09: "why dont you trigger somehing or accept that we just did a test
                        # mail"): the setup script's read-back confirmed the scoped Mail.Send for the ENGINE identity in ONE
                        # scope on this mailbox, and a test mail through it succeeded -> granted, at once.
                        & $add "mail-send-$role" $title 'ok' "$(if ($lbl) { "$lbl -- " })$($sc.detail)" ''
                    } elseif ($role -eq 'engine') {
                        # MAIL-STEP-PROOF (owner 2026-10-09: "i have run 3 cmdlet, and test mail works - but it still shows
                        # eros"): the engine job cannot be proven by the customer on demand -- only its own send proves it. Not
                        # proven yet is therefore an INFO line ('waiting'): it never makes the step "not done", shows no "If it
                        # fails" command, and only a RECORDED engine failure ('failed' above) turns it red.
                        & $add "mail-send-$role" $title 'waiting' "$(if ($lbl) { "$lbl -- " })$(Get-PimMailEngineWaitingDetail -EngineTest (& $f 'engineTest') -Sender $sender -StaleProof:($pv.detail -match 'other settings'))" ''
                    } else {
                        & $add "mail-send-$role" $title 'unproven' "$(if ($lbl) { "$lbl -- " })$($pv.detail) -- $prove (no guess: only a real send proves the scoped send right)" "$prove`nIf it fails: $mbFix"
                    }
                }
            }
        }
        $tw = @($ids | Where-Object { (& $gv $_ 'tenantWideMailSend') -eq $true } | ForEach-Object { "$(& $gv $_ 'label')" })
        $twUnknown = @($ids | Where-Object { $null -eq (& $gv $_ 'tenantWideMailSend') }).Count -gt 0 -or -not $ids.Count
        if ($tw.Count) {
            # MAIL-WEB-RIGHTS-1 (SECURE-WEB-1): the leftover finding on the WEB app's identity stays visible, but the mail-sender
            # script no longer touches that identity (it names the engine only) -- so its fix does not claim the script revokes it.
            $twEng = @($ids | Where-Object { (& $gv $_ 'tenantWideMailSend') -eq $true -and "$(& $gv $_ 'role')" -ne 'manager' })
            $twWeb = @($ids | Where-Object { (& $gv $_ 'tenantWideMailSend') -eq $true -and "$(& $gv $_ 'role')" -eq 'manager' } | ForEach-Object { "$(& $gv $_ 'label')" })
            $twFix = @()
            if ($twEng.Count) { $twFix += "$mbFix`n(the script revokes the tenant-wide permission on the engine job's identity)" }
            if ($twWeb.Count) { $twFix += "$($twWeb -join ', '): PIM Manager's web app sends no mail, so its identity must hold no Mail.Send. Remove the Microsoft Graph application permission Mail.Send from it (Microsoft Entra admin center > Enterprise applications > that managed identity > Permissions); the mail-sender script does not change the web app's identity." }
            & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'failed' "tenant-wide Microsoft Graph Mail.Send on $($tw -join ', ') -- it could send as ANY mailbox and defeats the per-mailbox scope" ($twFix -join "`n")
        }
        elseif ($twUnknown) { & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'unknown' 'the sending identities'' Graph permissions could not be read' '' }
        else { & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'ok' 'neither sending identity holds it -- sending is scoped to the one mailbox' '' }
    }
    $rec = @(@(& $f 'alertRecipients') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($rec.Count) { & $add 'mail-alerts' 'Alert recipients' 'ok' ($rec -join ', ') '' }
    else { & $add 'mail-alerts' 'Alert recipients' 'missing' 'nobody receives the alerts' 'PIM Manager > Settings > Alerting > Recipients (Get Started > Alert recipients)' }
    # MAIL-STEP-PROOF: 'waiting' (the engine job's first send has not happened yet) is information, not an open item --
    # complete = every line ok OR waiting; proven = every line ok.
    # MAIL-TENANTWIDE-UNKNOWN (owner 2026-11-10 "this will also not complete even though mail is working"): the tenant-wide
    # Mail.Send line NOT CHECKED (the permissions could not be read) is information -- it never holds the step open. Only a
    # tenant-wide Mail.Send that IS found ('failed') does.
    # ONE-SENDER-1 (3.1.69 review): 'info' (the relay's From differs from the mail sender) is information -- mail works
    $notOk = @($lines | Where-Object { $_.state -ne 'ok' -and $_.state -ne 'waiting' -and $_.state -ne 'info' -and -not ($_.id -eq 'mail-no-tenantwide' -and $_.state -eq 'unknown') })
    $waiting = @($lines | Where-Object { $_.state -eq 'waiting' })
    $summary = if (-not $notOk.Count -and -not $waiting.Count) { 'mail: every prerequisite is in place and proven' }
               elseif (-not $notOk.Count) { "mail: every prerequisite is in place -- waiting for the engine's first send to prove its send right (not a problem)" }
               else { "mail: $($notOk.Count) of $($lines.Count) not complete -- $(@($notOk | ForEach-Object { $_.title }) -join ', ')" }
    return [pscustomobject][ordered]@{ mode = $mode; complete = (-not $notOk.Count); proven = (-not $notOk.Count -and -not $waiting.Count); waiting = $waiting.Count; off = $false; lines = @($lines.ToArray()); summary = $summary }
}

function Get-PimMailSetupCheckVerdict {
    <#
      PURE (MAIL-STEP-PROOF). Is the ENGINE job's send right confirmed without an engine send? Yes only when ALL hold:
        * -SetupCheck (pim.Settings 'MailSenderSetupCheck', stored by Initialize-PimMailSender from its read-back) is ok,
          for THIS sender, and names ONE scope;
        * it lists the ENGINE job's identity (-Setup tickObjectId, as this Manager knows it; an unknown id = not confirmed).
          SECURE-WEB-1 / MAIL-WEB-RIGHTS-1: the web app's identity is NOT required (it sends no mail and gets no send right);
        * the recorded test mail (-ManagerProof) through this mailbox SUCCEEDED.
      Returns @{ ok; detail }.
    #>
    param([AllowNull()]$SetupCheck, [string]$Sender, [AllowNull()]$Setup, [AllowNull()]$ManagerProof)
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $no = { param($why) @{ ok = $false; detail = $why } }
    if ($SetupCheck -is [string]) { try { $SetupCheck = $SetupCheck | ConvertFrom-Json } catch { $SetupCheck = $null } }
    if ($null -eq $SetupCheck -or -not ("$(& $g $SetupCheck 'ok')" -match '(?i)^true$')) { return (& $no 'no confirmed setup check') }
    if ("$(& $g $SetupCheck 'sender')".Trim() -ine "$Sender".Trim()) { return (& $no 'the setup check was for another mailbox') }
    # MAIL-SCOPE-SMTP (2026-11-11): only Exchange's Test-ServicePrincipalAuthorization InScope = True proves the scope covers the
    # mailbox. A record from before (objects existed) is not that proof -- a customer's scope matched NO mailbox while it said "confirmed".
    if ("$(& $g $SetupCheck 'inScope')".Trim() -ne 'confirmed') { return (& $no 'the setup check has no in-scope proof (Test-ServicePrincipalAuthorization) -- re-run the mail-sender script') }
    $scope = "$(& $g $SetupCheck 'scope')".Trim()
    if (-not $scope) { return (& $no 'the setup check names no scope') }
    $oids = @(@(& $g $SetupCheck 'identities') | ForEach-Object { "$(& $g $_ 'objectId')".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $eng = "$(& $g $Setup 'tickObjectId')".Trim().ToLowerInvariant()
    if (-not $eng -or $oids -notcontains $eng) { return (& $no "the setup check does not cover the engine job's identity") }
    $mp = Get-PimMailSendProofVerdict -Proof $ManagerProof -Mode 'sharedMailbox' -Sender $Sender
    if ($mp.state -ne 'ok') { return (& $no "the Manager's test mail has not succeeded through this mailbox") }
    $at = "$(& $g $SetupCheck 'at')".Trim()
    return @{ ok = $true; detail = "granted -- confirmed by the setup check (scoped Mail.Send for the engine job's identity in $scope$(if ($at) { ", $at" })) and the test mail" }
}

function Get-PimMailEngineWaitingDetail {
    <#
      PURE (MAIL-STEP-PROOF). The INFO text of the engine row while the engine job has not proven its send right yet, from
      the engine test request the Manager queued (pim.Settings 'MailEngineTest': @{ status = queued | sending | sent | failed;
      queuedUtc; to; sender; at; reason }). A request for another sender is ignored (the mailbox changed since).
    #>
    param([AllowNull()]$EngineTest, [string]$Sender, [switch]$StaleProof)
    $g = { param($n) if ($null -eq $EngineTest) { $null } elseif ($EngineTest -is [System.Collections.IDictionary]) { $EngineTest[$n] } elseif ($EngineTest.PSObject.Properties[$n]) { $EngineTest.$n } else { $null } }
    $base = "waiting for the engine's first send$(if ($StaleProof) { ' with these settings' })"
    $st = "$(& $g 'status')".Trim().ToLowerInvariant()
    $ts = "$(& $g 'sender')".Trim()
    if ($EngineTest -and $st -and (-not $ts -or -not "$Sender".Trim() -or $ts -ieq "$Sender".Trim())) {
        $to = "$(& $g 'to')".Trim(); $q = "$(& $g 'queuedUtc')".Trim()
        switch ($st) {
            'queued'  { return "$base -- engine test mail queued$(if ($q) { " $q" })$(if ($to) { " to $to" }); proven in about a minute" }
            'sending' { return "$base -- the engine is sending its test mail$(if ($to) { " to $to" }) now" }
            'sent'    { return "$base -- the engine reported its test mail sent$(if ("$(& $g 'at')".Trim()) { " ($("$(& $g 'at')".Trim()))" }); its proof is read on the next check" }
            'failed'  { return "$base -- the engine test mail was not sent: $("$(& $g 'reason')".Trim()) (this is not a refused send right; Send test mail queues a new one)" }
        }
    }
    return "$base -- Send test mail (Get Started > Mail sender) queues an engine test mail; a TAP code, a reminder or an alert proves it too"
}

function Test-PimTenantWideMailSend {
    <# PURE. Does a service principal's appRoleAssignments list hold Graph's application Mail.Send? -GraphSpId: the Microsoft Graph SP's object id. #>
    param([object[]]$Assignments = @(), [string]$GraphSpId)
    return (@(@($Assignments) | Where-Object { $_ -and "$($_.appRoleId)" -eq $script:PimGraphMailSendAppRoleId -and (-not "$GraphSpId".Trim() -or "$($_.resourceId)" -eq "$GraphSpId".Trim()) }).Count -gt 0)
}
