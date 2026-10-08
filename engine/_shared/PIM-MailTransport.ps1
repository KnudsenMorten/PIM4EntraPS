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
    arrive, and Test-PimTapMailReady says so).

  Everything here is PURE or has a seam: $global:PIM_SmtpClientFactory (param($Config) -> an object with .Send(MailMessage)
  and .Dispose()) replaces the real SmtpClient in tests; $global:PIM_SmtpSecretReader (param($VaultName, $SecretName))
  replaces the Key Vault read. PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimMailModeCatalog { @('none', 'sharedMailbox', 'smtp') }
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
    $from = "$(& $get $rec 'from')".Trim()
    if (-not $from) { $errors['from'] = 'Enter the From address the mail is sent as.' }
    elseif (-not (Test-PimMailAddress -Value $from)) { $errors['from'] = "Not a mail address: $from" }
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
          [object[]]$Attachments = @())
    $pw = ''
    try { $pw = Get-PimSmtpRelayPassword -Config $Config }
    catch { return @{ sent = $false; sentAs = 'smtp'; reason = "the SMTP relay password could not be read from Key Vault '$($Config.vaultName)' (secret '$($Config.secretName)'): $(($_.Exception.Message -split "`n")[0]) -- the sending identity needs 'Key Vault Secrets User' on that secret" } }
    if ("$($Config.username)".Trim() -and -not "$pw") { return @{ sent = $false; sentAs = 'smtp'; reason = "the SMTP relay password secret '$($Config.secretName)' in Key Vault '$($Config.vaultName)' is empty" } }
    $msg = $null; $client = $null
    try {
        $msg = New-PimSmtpMailMessage -From "$($Config.from)" -To $Recipients -Subject $Subject -BodyHtml $BodyHtml -BodyText $BodyText -Attachments $Attachments
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
    if ($m -eq 'smtp') { return ('smtp|{0}|{1}|{2}|{3}' -f "$($Smtp.host)".ToLowerInvariant(), "$($Smtp.port)", "$($Smtp.from)".ToLowerInvariant(), "$($Smtp.username)".ToLowerInvariant()) }
    if ($m -eq 'sharedMailbox') { return ('sharedMailbox|{0}' -f "$Sender".Trim().ToLowerInvariant()) }
    return "$m"
}

function Get-PimMailSetupState {
    <#
      PURE: the Get Started / Settings verdict for mail, from the stored values. Returns @{ mode; done; note; sender; smtp }.
        sharedMailbox -- done when a sender mailbox is stored and no later test mail to it FAILED.
        smtp          -- done when the relay record is valid AND a test mail through exactly these settings was SENT.
        none          -- never done (nothing can be sent; the note says so).
      -LastTest: @{ ok; fingerprint; at; reason } as the test-mail route stores it (pim.Settings 'MailLastTest').
    #>
    param([string]$Mode, [string]$Sender, [AllowNull()][object]$SmtpRelay, [AllowNull()][object]$LastTest)
    $m = ConvertTo-PimMailMode -Value $Mode; if (-not $m) { $m = 'sharedMailbox' }
    $smtp = ConvertTo-PimSmtpRelayConfig -Value $SmtpRelay
    $fp = Get-PimMailTestFingerprint -Mode $m -Sender $Sender -Smtp $smtp.config
    $proof = $null
    if ($LastTest -and "$($LastTest.fingerprint)" -eq $fp) { $proof = [bool]$LastTest.ok }
    $s = "$Sender".Trim()
    switch ($m) {
        'none' { return @{ mode = $m; done = $false; note = 'mail is switched off: TAP codes, approvals and alerts are not sent'; sender = $s; proven = $null } }
        'smtp' {
            if (-not $smtp.ok) { return @{ mode = $m; done = $false; note = 'SMTP relay: ' + (@($smtp.errors.Values) -join ' '); sender = "$($smtp.config.from)"; proven = $null } }
            if ($proof -eq $true) { return @{ mode = $m; done = $true; note = "SMTP relay $($smtp.config.host):$($smtp.config.port) as $($smtp.config.from) -- test mail sent"; sender = "$($smtp.config.from)"; proven = $true } }
            if ($proof -eq $false) { return @{ mode = $m; done = $false; note = "SMTP relay configured, but the test mail failed: $($LastTest.reason)"; sender = "$($smtp.config.from)"; proven = $false } }
            return @{ mode = $m; done = $false; note = 'SMTP relay configured -- send a test mail to prove it'; sender = "$($smtp.config.from)"; proven = $null }
        }
        default {
            if (-not $s) { return @{ mode = 'sharedMailbox'; done = $false; note = 'no sender: TAP codes and notifications are not sent'; sender = ''; proven = $null } }
            if ($proof -eq $false) { return @{ mode = 'sharedMailbox'; done = $false; note = "sends as $s, but the test mail failed: $($LastTest.reason)"; sender = $s; proven = $false } }
            return @{ mode = 'sharedMailbox'; done = $true; note = "sends as $s$(if ($proof -eq $true) { ' -- test mail sent' })"; sender = $s; proven = $proof }
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
# =====================================================================================================================
$script:PimGraphMailSendAppRoleId = 'b633e1c5-b582-4048-a93e-9f11b44c7e96'   # Microsoft Graph application permission Mail.Send

function Get-PimMailSetupCommand {
    <#
      PURE. The published, browser-sign-in command lines for one fix, with this environment's values filled in (a
      <placeholder> for an unknown one). -Kind mailbox = Initialize-PimMailSender.ps1 (an Exchange or Global Administrator:
      creates / scopes the shared mailbox, gives BOTH sending identities their scoped send right, revokes a tenant-wide
      Mail.Send); smtpPassword = Set-PimSmtpRelayPassword.ps1. Never a certificate, never a secret.
    #>
    param([ValidateSet('mailbox', 'smtpPassword')][string]$Kind, [object]$Setup, [object]$Smtp)
    $g = { param($o, $n) if ($null -eq $o) { '' } elseif ($o -is [System.Collections.IDictionary]) { "$($o[$n])".Trim() } elseif ($o.PSObject.Properties[$n]) { "$($o.$n)".Trim() } else { '' } }
    $v = { param($x, $ph) if ("$x".Trim()) { "$x".Trim() } else { $ph } }
    $mi = @((& $g $Setup 'managerObjectId'), (& $g $Setup 'tickObjectId') | Where-Object { $_ })
    $miArg = if ($mi.Count) { $mi -join ',' } else { '<manager identity object id>,<engine job identity object id>' }
    if ($Kind -eq 'mailbox') {
        $run = '.\Initialize-PimMailSender.ps1 -TenantId ' + (& $v (& $g $Setup 'tenantId') '<tenant id>') + ' -ManagedIdentityObjectId ' + $miArg +
               ' -SqlServerFqdn ' + (& $v (& $g $Setup 'sqlServer') '<server>.database.windows.net')
        return @('Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimMailSender.ps1 -OutFile Initialize-PimMailSender.ps1', $run)
    }
    $vault = & $v (& $g $Smtp 'vaultName') (& $v (& $g $Setup 'vaultHint') '<key vault name>')
    $sec = & $g $Smtp 'secretName'
    $run = '.\Set-PimSmtpRelayPassword.ps1 -TenantId ' + (& $v (& $g $Setup 'tenantId') '<tenant id>') + ' -SubscriptionId ' + (& $v (& $g $Setup 'subscriptionId') '<subscription id>') +
           ' -VaultName ' + $vault + $(if ($sec -and $sec -ne (Get-PimSmtpRelayDefaultSecretName)) { " -SecretName $sec" } else { '' }) + ' -ManagedIdentityObjectId ' + $miArg
    return @('Invoke-WebRequest https://invardia.com/support/pim/Set-PimSmtpRelayPassword.ps1 -OutFile Set-PimSmtpRelayPassword.ps1', $run)
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
        smtpPassword  @{ readable = $true|$false|$null; reason }        -- the Manager reading the secret (never its value)
        setup         the values the fix commands carry (tenantId, managerObjectId, tickObjectId, subscriptionId, sqlServer, vaultHint)
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
    elseif ($mode -eq 'none') { & $add 'mail-mode' 'Mail mode chosen' 'missing' 'mail is switched off (mode none) -- TAP codes, approvals and alerts are not sent' $guiFix }
    else { & $add 'mail-mode' 'Mail mode chosen' 'ok' $(if ($mode -eq 'smtp') { 'SMTP relay' } else { "shared mailbox$(if (-not $storedMode) { ' (the default)' })" }) '' }

    if ($mode -eq 'smtp') {
        $relay = ConvertTo-PimSmtpRelayConfig -Value (& $f 'smtp')
        $c = $relay.config
        if ($relay.ok) { & $add 'smtp-settings' 'SMTP relay: server, port, user' 'ok' ("$($c.host):$($c.port) ($($c.security)) as $($c.from)" + $(if ($c.username) { ", user $($c.username)" } else { ', no sign-in' })) '' }
        else { & $add 'smtp-settings' 'SMTP relay: server, port, user' 'missing' ((@($relay.errors.Values) | ForEach-Object { "$_" }) -join ' ') 'PIM Manager > Get Started > Mail sender > SMTP relay: fill in the server, port, From address and user name' }
        $pwFix = (Get-PimMailSetupCommand -Kind smtpPassword -Setup $setup -Smtp $c) -join "`n"
        if ($relay.ok -and -not "$($c.username)".Trim()) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'ok' 'the relay needs no sign-in -- no password' '' }
        else {
            $pw = & $f 'smtpPassword'; $rd = & $gv $pw 'readable'
            if ($rd -eq $true) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'ok' "secret '$($c.secretName)' in Key Vault '$($c.vaultName)' is readable by this PIM Manager" '' }
            elseif ($rd -eq $false) { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'failed' "the password cannot be read: $(& $gv $pw 'reason')" $pwFix }
            else { & $add 'smtp-password' 'SMTP password in Key Vault, readable by the sender' 'unknown' 'not checked yet (the relay settings are incomplete, or Key Vault could not be asked)' $pwFix }
        }
        $lt = & $f 'lastTest'
        $fp = Get-PimMailTestFingerprint -Mode 'smtp' -Sender '' -Smtp $c
        $ltOk = & $gv $lt 'ok'
        if ($lt -and "$(& $gv $lt 'fingerprint')" -eq $fp -and $ltOk -eq $true) { & $add 'smtp-test' 'Test mail sent through these settings' 'ok' "sent $("$(& $gv $lt 'at')".Trim()) to $("$(& $gv $lt 'to')".Trim())" '' }
        elseif ($lt -and "$(& $gv $lt 'fingerprint')" -eq $fp -and $ltOk -eq $false) { & $add 'smtp-test' 'Test mail sent through these settings' 'failed' "the test mail FAILED: $("$(& $gv $lt 'reason')".Trim())" 'PIM Manager > Get Started > Mail sender: correct the relay settings, then Save and send a test mail' }
        else { & $add 'smtp-test' 'Test mail sent through these settings' 'unproven' 'not proven yet -- no test mail was sent through these exact settings' 'PIM Manager > Get Started > Mail sender: Save and send a test mail' }
    }
    elseif ($mode -eq 'sharedMailbox') {
        $lk = & $f 'senderLookup'; $found = & $gv $lk 'found'
        if (-not $sender) { & $add 'mail-mailbox' 'Sender mailbox exists' 'missing' 'no sender mailbox is set' $mbFix }
        elseif ($found -eq $true) { & $add 'mail-mailbox' 'Sender mailbox exists' 'ok' "$sender (Microsoft Graph resolves it$(if ("$(& $gv $lk 'upn')".Trim() -and "$(& $gv $lk 'upn')".Trim() -ine $sender) { " as $(& $gv $lk 'upn')" }))" '' }
        elseif ($found -eq $false) { & $add 'mail-mailbox' 'Sender mailbox exists' 'failed' "Microsoft Graph does not find '$sender' -- PIM sends as exactly this address" $mbFix }
        else { & $add 'mail-mailbox' 'Sender mailbox exists' 'unknown' "'$sender' could not be looked up$(if ("$(& $gv $lk 'error')".Trim()) { ": $(& $gv $lk 'error')" })" $mbFix }
        $ids = @(@(& $f 'identities') | Where-Object { $_ })
        foreach ($role in 'engine', 'manager') {
            $i = @($ids | Where-Object { "$(& $gv $_ 'role')" -eq $role }) | Select-Object -First 1
            $title = if ($role -eq 'engine') { 'Engine job: scoped send right' } else { 'PIM Manager: scoped send right' }
            $prove = if ($role -eq 'engine') { "the engine's next mail (a TAP code, a reminder or an alert) proves it" } else { 'PIM Manager > Get Started > Mail sender: Save and send a test mail (the Manager sends it as its own identity)' }
            if (-not $sender) { & $add "mail-send-$role" $title 'missing' 'no sender mailbox yet' $mbFix; continue }
            $pv = Get-PimMailSendProofVerdict -Proof (& $gv $i 'proof') -Mode 'sharedMailbox' -Sender $sender
            $lbl = "$(& $gv $i 'label')".Trim()
            switch ($pv.state) {
                'ok'     { & $add "mail-send-$role" $title 'ok' "$(if ($lbl) { "$lbl -- " })$($pv.detail)" '' }
                'failed' { & $add "mail-send-$role" $title 'failed' "$(if ($lbl) { "$lbl -- " })$($pv.detail)" $mbFix }
                default  { & $add "mail-send-$role" $title 'unproven' "$(if ($lbl) { "$lbl -- " })$($pv.detail) -- $prove (no guess: only a real send proves the scoped send right)" "$prove`nIf it fails: $mbFix" }
            }
        }
        $tw = @($ids | Where-Object { (& $gv $_ 'tenantWideMailSend') -eq $true } | ForEach-Object { "$(& $gv $_ 'label')" })
        $twUnknown = @($ids | Where-Object { $null -eq (& $gv $_ 'tenantWideMailSend') }).Count -gt 0 -or -not $ids.Count
        if ($tw.Count) { & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'failed' "tenant-wide Microsoft Graph Mail.Send on $($tw -join ', ') -- it could send as ANY mailbox and defeats the per-mailbox scope" "$mbFix`n(the script revokes the tenant-wide permission)" }
        elseif ($twUnknown) { & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'unknown' 'the sending identities'' Graph permissions could not be read' '' }
        else { & $add 'mail-no-tenantwide' 'No tenant-wide Graph Mail.Send' 'ok' 'neither sending identity holds it -- sending is scoped to the one mailbox' '' }
    }
    $rec = @(@(& $f 'alertRecipients') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($rec.Count) { & $add 'mail-alerts' 'Alert recipients' 'ok' ($rec -join ', ') '' }
    else { & $add 'mail-alerts' 'Alert recipients' 'missing' 'nobody receives the alerts' 'PIM Manager > Settings > Alerting > Recipients (Get Started > Alert recipients)' }
    $notOk = @($lines | Where-Object { $_.state -ne 'ok' })
    $summary = if (-not $notOk.Count) { 'mail: every prerequisite is in place and proven' }
               else { "mail: $($notOk.Count) of $($lines.Count) not complete -- $(@($notOk | ForEach-Object { $_.title }) -join ', ')" }
    return [pscustomobject][ordered]@{ mode = $mode; complete = (-not $notOk.Count); lines = @($lines.ToArray()); summary = $summary }
}

function Test-PimTenantWideMailSend {
    <# PURE. Does a service principal's appRoleAssignments list hold Graph's application Mail.Send? -GraphSpId: the Microsoft Graph SP's object id. #>
    param([object[]]$Assignments = @(), [string]$GraphSpId)
    return (@(@($Assignments) | Where-Object { $_ -and "$($_.appRoleId)" -eq $script:PimGraphMailSendAppRoleId -and (-not "$GraphSpId".Trim() -or "$($_.resourceId)" -eq "$GraphSpId".Trim()) }).Count -gt 0)
}
