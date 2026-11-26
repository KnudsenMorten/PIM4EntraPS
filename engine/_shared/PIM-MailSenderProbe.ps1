<#
  PIM4EntraPS -- ONE-SENDER-1 point D (Invardia 2026-11-25, framework ONE-SENDER-1; the probe is SecurityInsight's method):
  a DAILY Graph probe of EVERY sending identity, and once before the first send.

  For each identity, as that identity:
    POST /users/<sender>/sendMail  with a message that has NO recipient
        400 ErrorInvalidRecipients -> the identity MAY send as that mailbox (Exchange checked the right first) = allowed
        403 ErrorAccessDenied      -> it may not                                                            = denied
    POST /users/<probe mailbox>/sendMail  (a mailbox that is NOT the sender) -- the same empty message
        it MUST be denied: an 'allowed' there proves a tenant-wide Graph Mail.Send (it could send as ANY mailbox).
  Nothing is ever delivered: a message without a recipient cannot be sent.

  Per identity: verified (sender allowed + probe denied) | pending (sender denied within 2 h of the mail-sender setup:
  Exchange app RBAC can take that long) | not-verified (could not tell: no probe mailbox, an unknown answer) | failed.
  The record goes to pim.Settings 'MailSenderProbe'; the heartbeat Mail block reads it (New-PimUplinkMailField):
  restriction = verified | pending | not-verified | failed, sender, drift. NO new Exchange right and no extra Exchange role
  group: the probe uses only the send right being checked.

  The ENGINE probes itself (the tick job's identity). The RFA broker probes ITSELF (tools/pim-rfa/Start-PimRfaBroker.ps1,
  Invoke-PimRfaBrokerProbeIfDue) and publishes its answer to its store; rfa-sync copies it to pim.Settings
  'MailSenderProbeRfa', which the engine's record merges. PURE functions + seams (-Invoke / -Reader / -Writer). PS 7.
#>
Set-StrictMode -Off

function Get-PimMailSenderProbeSettingName { 'MailSenderProbe' }

function ConvertTo-PimMailProbeUtc {
    # PURE. A stored time (ISO text, or the [datetime] ConvertFrom-Json already made of it) -> UTC [datetime], $null when unreadable.
    param([AllowNull()][object]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if (-not "$Value".Trim()) { return $null }
    try { return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return $null }
}

function New-PimMailSendProbeBody {
    # PURE. The probe message: NO recipient of any kind (to, cc or bcc) -- Graph refuses it (400 ErrorInvalidRecipients) AFTER the send
    # right was checked, so nothing can ever be delivered. Not saved to Sent Items.
    return [ordered]@{ message = [ordered]@{ subject = 'PIM Manager sender check (never delivered: no recipient)'; body = [ordered]@{ contentType = 'Text'; content = 'PIM Manager checks that it may send as this mailbox. This message has no recipient and is never delivered.' } }; saveToSentItems = $false }
}

function Get-PimMailSendProbeVerdict {
    <#
      PURE. Graph's answer to ONE empty-recipient sendMail -> @{ verdict = allowed | denied | unknown; detail }.
        400 + ErrorInvalidRecipients (or "recipient")  -> allowed (the right was checked first, then the message refused)
        202 / 200 (accepted -- should not happen)       -> allowed
        403 / ErrorAccessDenied / "Access is denied"     -> denied
        anything else (404 no mailbox, 401, 429, 5xx)    -> unknown -- never read as allowed or denied
    #>
    param([int]$StatusCode = 0, [AllowEmptyString()][AllowNull()][string]$ErrorText = '')
    $t = "$ErrorText"
    if ($t -match '(?i)ErrorInvalidRecipients|At least one recipient') { return @{ verdict = 'allowed'; detail = 'ErrorInvalidRecipients (the send right was granted, the empty message refused)' } }
    if ($t -match '(?i)ErrorAccessDenied|Access is denied|AccessDenied' -or $StatusCode -eq 403) { return @{ verdict = 'denied'; detail = 'ErrorAccessDenied (no send right for this mailbox)' } }
    if ($StatusCode -in @(200, 202)) { return @{ verdict = 'allowed'; detail = "accepted ($StatusCode)" } }
    if ($StatusCode -eq 400 -and $t -match '(?i)recipient') { return @{ verdict = 'allowed'; detail = '400 about the recipients (the send right was granted)' } }
    $one = (($t -split "`n")[0]).Trim(); if ($one.Length -gt 200) { $one = $one.Substring(0, 200) }
    return @{ verdict = 'unknown'; detail = "no clear answer$(if ($StatusCode) { " ($StatusCode)" })$(if ($one) { ": $one" })" }
}

function Invoke-PimMailSendProbe {
    <#
      ONE probe call as the CALLER's identity. -Invoke param($path, $body) does the POST (the engine: Invoke-PimGraph; the
      broker: its own token; tests: a stub) and THROWS on a non-2xx like Invoke-RestMethod. Returns @{ mailbox; verdict; detail }.
    #>
    param([AllowEmptyString()][string]$Mailbox, [Parameter(Mandatory)][scriptblock]$Invoke)
    $mb = "$Mailbox".Trim()
    if (-not $mb) { return @{ mailbox = ''; verdict = 'unknown'; detail = 'no mailbox to probe' } }
    try {
        [void](& $Invoke "/users/$([uri]::EscapeDataString($mb))/sendMail" (New-PimMailSendProbeBody))
        $v = Get-PimMailSendProbeVerdict -StatusCode 202
    } catch {
        $sc = 0
        try { if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $sc = [int]$_.Exception.Response.StatusCode } } catch { $sc = 0 }
        $txt = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        if (-not $sc -and $txt -match '\b(400|401|403|404|429|500|502|503)\b') { $sc = [int]$Matches[1] }
        $v = Get-PimMailSendProbeVerdict -StatusCode $sc -ErrorText $txt
    }
    return @{ mailbox = $mb; verdict = $v.verdict; detail = $v.detail }
}

function Resolve-PimMailSenderProbeState {
    <#
      PURE. One identity's result from its two answers:
        sender allowed + probe denied  -> verified
        sender allowed + probe allowed -> failed (a tenant-wide Graph Mail.Send: it may send as ANY mailbox)
        sender allowed + probe unknown -> not-verified (the restriction cannot be shown)
        sender denied, the mail-sender setup (or its pending change) less than -PendingHours ago -> pending
        sender denied otherwise -> failed
        sender unknown -> not-verified
      -SetupAtUtc: MailSenderSetupCheck 'pendingSince' (a pending run) else its 'at'. Returns @{ restriction; detail }.
    #>
    param([string]$SenderVerdict, [string]$ProbeVerdict, [AllowNull()][object]$SetupAtUtc, [datetime]$NowUtc = [datetime]::UtcNow, [double]$PendingHours = 2)
    switch ("$SenderVerdict") {
        'allowed' {
            if ("$ProbeVerdict" -eq 'denied') { return @{ restriction = 'verified'; detail = 'may send as the sender, refused for another mailbox (scoped to the one mailbox)' } }
            if ("$ProbeVerdict" -eq 'allowed') { return @{ restriction = 'failed'; detail = 'may send as ANOTHER mailbox too -- a tenant-wide Microsoft Graph Mail.Send defeats the per-mailbox scope; remove it' } }
            return @{ restriction = 'not-verified'; detail = 'may send as the sender; the check against another mailbox gave no clear answer, so the restriction is not shown' }
        }
        'denied' {
            $at = ConvertTo-PimMailProbeUtc $SetupAtUtc
            if ($at -and ($NowUtc.ToUniversalTime() - $at).TotalHours -lt $PendingHours -and ($NowUtc.ToUniversalTime() - $at).TotalHours -ge -0.1) {
                return @{ restriction = 'pending'; detail = "may not send as the sender yet -- the send right was set up $([int]($NowUtc.ToUniversalTime() - $at).TotalMinutes) min ago and Exchange can take up to $PendingHours h" }
            }
            return @{ restriction = 'failed'; detail = 'may NOT send as the sender (ErrorAccessDenied) -- run Initialize-PimMailSender for every sending identity' }
        }
    }
    return @{ restriction = 'not-verified'; detail = 'the check of the sender gave no clear answer' }
}

function Get-PimMailSenderProbeWorst {
    # PURE. The overall restriction of several identities: failed > pending > not-verified > verified ('' = none given).
    param([string[]]$Restrictions = @())
    $r = @(@($Restrictions) | Where-Object { "$_".Trim() })
    if (-not $r.Count) { return '' }
    foreach ($w in 'failed', 'pending', 'not-verified') { if ($r -contains $w) { return $w } }
    return 'verified'
}

function New-PimMailSenderProbeRecord {
    <#
      PURE. The pim.Settings 'MailSenderProbe' record: @{ at; sender; probeMailbox; restriction; drift; driftReasons[];
      identities = @({ role; sender; restriction; senderVerdict; probeVerdict; detail; at }) }.
      drift = $true when ANY component sends as another mailbox than MailSender (an identity's own 'sender'), or the
      mail-sender setup check was made for another mailbox -- the 2026-11-25 internal state (the broker on an OLD mailbox).
    #>
    param([AllowEmptyString()][string]$MailSender, [object[]]$Identities = @(), [AllowNull()][object]$SetupCheck, [string]$ProbeMailbox = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if ($SetupCheck -is [string]) { try { $SetupCheck = $SetupCheck | ConvertFrom-Json } catch { $SetupCheck = $null } }
    $ms = "$MailSender".Trim().Trim('"')
    $ids = @(@($Identities) | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ role = "$(& $g $_ 'role')"; sender = "$(& $g $_ 'sender')".Trim(); restriction = "$(& $g $_ 'restriction')"; senderVerdict = "$(& $g $_ 'senderVerdict')"
                    probeVerdict = "$(& $g $_ 'probeVerdict')"; detail = "$(& $g $_ 'detail')"; at = "$(& $g $_ 'at')" } })
    $why = New-Object System.Collections.Generic.List[string]
    foreach ($i in $ids) { if ($i.sender -and $ms -and $i.sender -ine $ms) { $why.Add("the $($i.role) sends as $($i.sender), not the mail sender $ms") } }
    $scS = "$(& $g $SetupCheck 'sender')".Trim()
    if ($scS -and $ms -and $scS -ine $ms) { $why.Add("the mail-sender setup was made for $scS, not the mail sender $ms") }
    return [ordered]@{ at = $NowUtc.ToUniversalTime().ToString('o'); sender = $ms; probeMailbox = "$ProbeMailbox".Trim(); restriction = (Get-PimMailSenderProbeWorst -Restrictions @($ids | ForEach-Object { $_.restriction }))
                       drift = [bool]($why.Count -gt 0); driftReasons = @($why.ToArray()); identities = $ids }
}

function Select-PimMailSenderProbeMailbox {
    <#
      PURE. The mailbox the probe must be REFUSED for: -Configured (pim.Settings 'MailSenderProbeMailbox') first, else the first
      -Candidates address (directory MEMBER users with a mailbox) -- never the sender itself, never an invalid address, and
      (3.1.69 review) never one of -Exclude: an OLD sender still holding its right (the recorded previous state / retire list,
      the broker's not-yet-switched sender) would answer 'allowed' and read as a false "tenant-wide Mail.Send". '' = none.
    #>
    param([AllowEmptyString()][string]$Sender, [AllowEmptyString()][AllowNull()][string]$Configured = '', [string[]]$Candidates = @(), [string[]]$Exclude = @())
    $s = "$Sender".Trim().ToLowerInvariant()
    $ex = @(@($Exclude) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($c in @(@("$Configured") + @($Candidates))) {
        $v = "$c".Trim().Trim('"')
        if ($v -and $v.ToLowerInvariant() -ne $s -and $ex -notcontains $v.ToLowerInvariant() -and $v -match '^[^@\s<>"(),;:]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { return $v }
    }
    return ''
}

function Get-PimMailSenderProbeExcludes {
    <#
      PURE (3.1.69 review). The OLD senders a probe mailbox must never be: the addresses the recorded state's old scopes pin
      (MailSenderSetupCheck .retire / .previous -> scopes[].filter "PrimarySmtpAddress -eq '<old>'"), and the broker's own
      sender when it differs from the mail sender (it still sends as its old address until its probe allows the new one).
    #>
    param([AllowNull()][object]$SetupCheck, [AllowNull()][object]$RfaProbe, [string]$MailSender = '')
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if ($SetupCheck -is [string]) { try { $SetupCheck = $SetupCheck | ConvertFrom-Json } catch { $SetupCheck = $null } }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($st in @((& $g $SetupCheck 'retire'), (& $g $SetupCheck 'previous'))) {
        foreach ($sc in @(& $g $st 'scopes')) {
            $m = [regex]::Match("$(& $g $sc 'filter')", "(?i)PrimarySmtpAddress\s+-eq\s+['""]([^'""]+)['""]")
            if ($m.Success) { $out.Add($m.Groups[1].Value.Trim()) }
        }
    }
    $rs = "$(& $g $RfaProbe 'sender')".Trim()
    if ($rs -and $rs -ine "$MailSender".Trim()) { $out.Add($rs) }
    return @($out | Sort-Object -Unique)
}

function Test-PimMailSenderProbeDue {
    # PURE. A probe is due when none is recorded, the recorded one is older than -MaxAgeHours (24), or it was for another sender.
    param([AllowNull()][object]$Record, [AllowEmptyString()][string]$MailSender, [datetime]$NowUtc = [datetime]::UtcNow, [double]$MaxAgeHours = 24)
    if ($Record -is [string]) { try { $Record = $Record | ConvertFrom-Json } catch { $Record = $null } }
    if ($null -eq $Record) { return $true }
    $rs = if ($Record -is [System.Collections.IDictionary]) { "$($Record['sender'])" } else { "$($Record.sender)" }
    if ("$rs".Trim() -ine "$MailSender".Trim().Trim('"')) { return $true }
    $ra = if ($Record -is [System.Collections.IDictionary]) { $Record['at'] } else { $Record.at }
    $at = ConvertTo-PimMailProbeUtc $ra
    if ($null -eq $at) { return $true }
    return (($NowUtc.ToUniversalTime() - $at).TotalHours -ge $MaxAgeHours)
}

function Get-PimMailSenderSetupAt {
    # PURE. When the send right was (last) set up: a pending setup check's 'pendingSince', else its 'at'. '' = unknown.
    param([AllowNull()][object]$SetupCheck)
    if ($SetupCheck -is [string]) { try { $SetupCheck = $SetupCheck | ConvertFrom-Json } catch { $SetupCheck = $null } }
    if ($null -eq $SetupCheck) { return '' }
    foreach ($n in 'pendingSince', 'at') {
        $v = if ($SetupCheck -is [System.Collections.IDictionary]) { $SetupCheck[$n] } elseif ($SetupCheck.PSObject.Properties[$n]) { $SetupCheck.$n } else { $null }
        if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('o') }   # ConvertFrom-Json already made a [datetime] of it
        if ("$v".Trim()) { return "$v".Trim() }
    }
    return ''
}

function Invoke-PimMailSenderProbeRun {
    <#
      The ENGINE's probe (ONE-SENDER-1 point D): the engine identity's two calls, the RFA broker's own published answer
      (pim.Settings 'MailSenderProbeRfa', when RFA is set up), one record written to pim.Settings 'MailSenderProbe'.
      -Reader param($name) / -Writer param($name, $value) = the settings store; -Invoke param($path, $body) = a POST as the
      engine identity; -Lookup param() -> candidate probe mailboxes (directory users with a mailbox). Mode none or smtp, or
      no sender -> nothing probed ($null): a Graph probe proves only the shared-mailbox send right.
      Returns the record (or $null). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Reader, [scriptblock]$Writer, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Lookup, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Force)
    try {
        $val = { param($n) $v = $null; try { $v = & $Reader $n } catch { $v = $null }; if ($v -is [string]) { $t = "$v".Trim(); if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { $v = $t | ConvertFrom-Json } catch { } } else { $v = $t.Trim('"') } }; $v }
        $mode = if (Get-Command ConvertTo-PimMailMode -ErrorAction SilentlyContinue) { ConvertTo-PimMailMode -Value (& $val 'MailMode') } else { "$(& $val 'MailMode')" }
        if ($mode -eq 'none') { return $null }
        if ($mode -eq 'smtp') {
            # 3.1.69 review: no Graph probe for a relay (it proves only the shared-mailbox right) -- but the daily check records
            # the relay's DRIFT (its own From differs from the mail sender setting), so the health view and Invardia see it
            $rel = & $val 'SmtpRelay'; $ms = "$(& $val 'MailSender')".Trim()
            $dr = if (Get-Command Get-PimSmtpSenderDrift -ErrorAction SilentlyContinue) { Get-PimSmtpSenderDrift -MailSender $ms -Config $rel } else { @{ drift = $false; relayFrom = ''; text = '' } }
            $recS = [ordered]@{ at = $NowUtc.ToUniversalTime().ToString('o'); mode = 'smtp'; sender = $(if ($dr.relayFrom) { $dr.relayFrom } else { $ms }); restriction = ''
                                drift = [bool]$dr.drift; driftReasons = @($(if ($dr.drift) { $dr.text })); identities = @() }
            if ($Writer) { try { & $Writer (Get-PimMailSenderProbeSettingName) $recS } catch { Write-Warning "  [Mail] the sender check could not be stored: $($_.Exception.Message)" } }
            if ($dr.drift) { Write-Host "  [Mail] sender check (ONE-SENDER-1): SMTP relay -- DRIFT: $($dr.text)" }
            return $recS
        }
        $sender = "$(& $val 'MailSender')".Trim()
        if (-not $sender) { return $null }
        $prev = & $val (Get-PimMailSenderProbeSettingName)
        if (-not $Force -and -not (Test-PimMailSenderProbeDue -Record $prev -MailSender $sender -NowUtc $NowUtc)) { return $prev }
        $setup = & $val 'MailSenderSetupCheck'
        $cands = @(); if ($Lookup) { try { $cands = @(& $Lookup) } catch { $cands = @() } }
        $pm = Select-PimMailSenderProbeMailbox -Sender $sender -Configured "$(& $val 'MailSenderProbeMailbox')" -Candidates $cands `
                  -Exclude (Get-PimMailSenderProbeExcludes -SetupCheck $setup -RfaProbe (& $val 'MailSenderProbeRfa') -MailSender $sender)
        $sv = Invoke-PimMailSendProbe -Mailbox $sender -Invoke $Invoke
        $pv = if ($pm) { Invoke-PimMailSendProbe -Mailbox $pm -Invoke $Invoke } else { @{ verdict = 'unknown'; detail = 'no other mailbox to probe (set pim.Settings MailSenderProbeMailbox)' } }
        $st = Resolve-PimMailSenderProbeState -SenderVerdict $sv.verdict -ProbeVerdict $pv.verdict -SetupAtUtc (Get-PimMailSenderSetupAt -SetupCheck $setup) -NowUtc $NowUtc
        $ids = @([ordered]@{ role = 'engine'; sender = $sender; restriction = $st.restriction; senderVerdict = $sv.verdict; probeVerdict = $pv.verdict; detail = "$($st.detail) [sender: $($sv.detail); other mailbox: $($pv.detail)]"; at = $NowUtc.ToUniversalTime().ToString('o') })
        # the RFA broker's own probe (it signs in as ITS identity -- the engine cannot test it), published by rfa-sync
        $rfaOn = $false; $rs = & $val 'RfaSettings'; if ($rs -and "$(if ($rs -is [System.Collections.IDictionary]) { $rs['storeAccount'] } else { $rs.storeAccount })".Trim()) { $rfaOn = $true }
        $rp = & $val 'MailSenderProbeRfa'
        if ($rp) {
            $rg = { param($n) if ($rp -is [System.Collections.IDictionary]) { $rp[$n] } elseif ($rp.PSObject.Properties[$n]) { $rp.$n } else { $null } }
            $rst = Resolve-PimMailSenderProbeState -SenderVerdict "$(& $rg 'senderVerdict')" -ProbeVerdict "$(& $rg 'probeVerdict')" -SetupAtUtc (Get-PimMailSenderSetupAt -SetupCheck $setup) -NowUtc $NowUtc
            $rat = ConvertTo-PimMailProbeUtc (& $rg 'at')
            $stale = ($null -eq $rat) -or (($NowUtc.ToUniversalTime() - $rat).TotalHours -gt 48)
            # 3.1.69 review: 'sender' = the address the broker probed (the one it must switch to); 'sendsAs' = what it really sends as
            $rSends = "$(& $rg 'sendsAs')".Trim(); if (-not $rSends) { $rSends = "$(& $rg 'sender')".Trim() }
            $ids += [ordered]@{ role = 'rfa'; sender = $rSends; restriction = $(if ($stale) { 'not-verified' } else { $rst.restriction }); senderVerdict = "$(& $rg 'senderVerdict')"; probeVerdict = "$(& $rg 'probeVerdict')"
                                detail = $(if ($stale) { 'the RFA broker has not checked its send right for more than 48 h (it checks before its first mail of a day)' } else { $rst.detail }); at = "$(& $rg 'at')" }
        } elseif ($rfaOn) {
            $ids += [ordered]@{ role = 'rfa'; sender = ''; restriction = 'not-verified'; senderVerdict = ''; probeVerdict = ''; detail = 'the RFA broker has not checked its send right yet (it does before its first mail of a day)'; at = '' }
        }
        $rec = New-PimMailSenderProbeRecord -MailSender $sender -Identities $ids -SetupCheck $setup -ProbeMailbox $pm -NowUtc $NowUtc
        if ($Writer) { try { & $Writer (Get-PimMailSenderProbeSettingName) $rec } catch { Write-Warning "  [Mail] the sender check could not be stored: $($_.Exception.Message)" } }
        Write-Host "  [Mail] sender check (ONE-SENDER-1): $($rec.restriction)$(if ($rec.drift) { ' -- DRIFT: ' + (@($rec.driftReasons) -join '; ') })"
        return $rec
    } catch { Write-Warning "  [Mail] the sender check did not run: $($_.Exception.Message)"; return $null }
}

function Invoke-PimMailSenderProbeScheduled {
    <#
      The engine's own wiring of Invoke-PimMailSenderProbeRun: the store (Get-PimSqlSetting / Set-PimSqlSetting on the
      cold-process connection string), Graph as the engine's send identity (Resolve-PimMailSendIdentity: the managed identity
      when hosted), and up to 10 directory users with a mailbox as probe candidates. No store -> nothing ($null).
      -BeforeFirstSend: once per process, only when the stored probe is due (the daily job keeps it fresh).
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$Force, [switch]$BeforeFirstSend)
    if ($global:PIM_MailProbeDisabled) { return $null }
    if ($BeforeFirstSend) { if ($script:PimMailProbeFirstSendDone) { return $null }; $script:PimMailProbeFirstSendDone = $true }
    if (-not (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -or -not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return $null }
    $cs = $null; try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null }
    if (-not "$cs".Trim()) { return $null }
    $mi = $false; try { $mi = ((Resolve-PimMailSendIdentity).kind -eq 'managed-identity') } catch { $mi = $false }
    $inv = { param($p, $b) $a = @{ Method = 'POST'; Path = $p; Body = $b }; if ($mi) { $a['UseManagedIdentity'] = $true }; Invoke-PimGraph @a }
    # 3.1.69 review: MEMBER users only (a guest has no mailbox here: 404 -> not-verified), with a mail address
    $look = { @(@((Invoke-PimGraph -Path "/users?`$filter=userType eq 'Member'&`$select=mail,userPrincipalName,userType&`$top=25").value) | Where-Object { "$($_.userType)" -ne 'Guest' -and "$($_.mail)".Trim() } | ForEach-Object { "$($_.mail)" }) }
    return (Invoke-PimMailSenderProbeRun -Reader { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n } -Writer { param($n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } `
                -Invoke $inv -Lookup $look -NowUtc $NowUtc -Force:$Force)
}
