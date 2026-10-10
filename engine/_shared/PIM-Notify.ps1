<#
  PIM4EntraPS -- notifications (REST-only, no modules). Renders the shipped mail
  templates (the SQL template store pim.Settings['MailTemplates'], seeded from templates/mail/*.mailtemplate.html) and sends via
  Microsoft Graph /users/<sender>/sendMail (app-only, Mail.Send). Ported from
  Send-PimTemplatedMail / ConvertTo-PimMailRendering in PIM-Functions.psm1.

  Config:
    $global:PIM_MailSender        UPN of the shared sender mailbox (required to send)
    $global:PIM_MailRedirectAllTo lab/test: every mail goes here instead of the real
                                  recipient (original surfaced as {{RedirectedFrom}})
    $global:PIM_MailTemplateDir   override the templates/mail location
  Render is split from send so it is unit-testable with no network.
#>
Set-StrictMode -Off

# The notification BATCH logic (daily summary / tier 0-1 report / approval escalation /
# ServiceNow intake) lives in PIM-Notifications.ps1 -- load it alongside the sender so
# any context that dot-sources PIM-Notify also gets the aggregation/render-prep + intake
# broker (idempotent: re-defining the functions is harmless).
if ($PSScriptRoot) {
    $__pimNotifBatch = Join-Path $PSScriptRoot 'PIM-Notifications.ps1'
    if ((Test-Path -LiteralPath $__pimNotifBatch) -and -not (Get-Command Get-PimDailySummary -ErrorAction SilentlyContinue)) { . $__pimNotifBatch }
    # The ONE mail template store (SQL pim.Settings['MailTemplates']) the send path renders from.
    $__pimMailStore = Join-Path $PSScriptRoot 'PIM-MailTemplateStore.ps1'
    if (Test-Path -LiteralPath $__pimMailStore) { . $__pimMailStore }
    # MAIL-1: the transport (shared mailbox | SMTP relay | none) -- the one setting every mail of this environment follows.
    $__pimMailTransport = Join-Path $PSScriptRoot 'PIM-MailTransport.ps1'
    if (Test-Path -LiteralPath $__pimMailTransport) { . $__pimMailTransport }
    # MAIL-2 (framework §12.11, PIM §100.5): the designed layout (logo, summary, blue audience button, footer) and the
    # per-recipient notification preferences the senders read at send time.
    foreach ($__pimMail2 in 'PIM-MailLayout.ps1', 'PIM-MailNotifications.ps1', 'PIM-GetStartedReminder.ps1') {
        $__pimMail2Path = Join-Path $PSScriptRoot $__pimMail2
        if (Test-Path -LiteralPath $__pimMail2Path) { . $__pimMail2Path }
    }
}

# --- EMAIL CONTROLS authority (the GUI-state == actual-behavior fix) -----------
# The Manager persists the kill switch / redirect-all / allowlist to SQL pim.Settings
# under 'EmailControls' and mirrors them to $global:PIM_Mail* so its OWN process honours
# them live. But a COLD-booted scheduled job (daily-summary / tier-report / escalations)
# or a one-shot engine run never ran that mirror, so the kill switch would NOT stop the
# send -- the exact "kill switch that doesn't actually stop sends" gap. The two helpers
# below make the SEND PATH itself authoritative against the persisted store, so EVERY
# process honours the GUI-saved controls. FAIL-SAFE throughout: a store-read failure
# NEVER clears an existing kill switch and never relaxes the allowlist/redirect.
function Set-PimEmailControlsGlobals {
    # PURE: apply an EmailControls record { killSwitch; redirectAllTo; allowlist[] } to the
    # $global:PIM_Mail* the send path reads. Accepts a hashtable, PSCustomObject, or a JSON
    # string (SQL keeps scalars as text). FAIL-SAFE: an ON kill switch is only ever turned
    # ON here, never OFF (a malformed/blank record can't silently re-enable sending); the
    # allowlist/redirect are only set from a well-formed record. Returns the applied shape.
    # -Authoritative: the record is the operator's SAVE (the Manager applies its own save through this) -- the kill switch
    # follows it both ways. Without it (a store hydrate) the kill switch is only ever ARMED here.
    # MAIL-2 (owner-approved 2026-10-09): a well-formed record whose redirectAllTo is present and BLANK clears the redirect
    # (it used to be set-only, so a cleared redirect stayed in force in a running process until a restart). A record
    # without the key, or a malformed one, leaves the redirect as it is.
    param([object]$EmailControls, [switch]$Authoritative)
    $rec = $EmailControls
    if ($rec -is [string]) { $s = "$rec".Trim(); if ($s) { try { $rec = $s | ConvertFrom-Json } catch { $rec = $null } } else { $rec = $null } }
    $get = {
        param($obj, $name)
        if ($null -eq $obj) { return $null }
        if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } ; return $null }
        $p = $obj.PSObject.Properties[$name]; if ($p) { return $p.Value } else { return $null }
    }
    $has = {
        param($obj, $name)
        if ($null -eq $obj) { return $false }
        if ($obj -is [System.Collections.IDictionary]) { return [bool]$obj.Contains($name) }
        return [bool]$obj.PSObject.Properties[$name]
    }
    $kill = & $get $rec 'killSwitch'
    if ($null -ne $kill -and [bool]$kill) { $global:PIM_MailKillSwitch = $true }   # a hydrate only ever ARMS
    elseif ($Authoritative -and $null -ne $kill) { $global:PIM_MailKillSwitch = $false }   # the operator's save disarms
    $redir = & $get $rec 'redirectAllTo'
    if ($null -ne $redir -and "$redir".Trim()) { $global:PIM_MailRedirectAllTo = "$redir".Trim() }
    elseif ((& $has $rec 'redirectAllTo') -and -not "$redir".Trim()) { $global:PIM_MailRedirectAllTo = '' }
    $allow = & $get $rec 'allowlist'
    if ($null -ne $allow) { $global:PIM_MailAllowlist = @(@($allow) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    return [pscustomobject]@{ killSwitch = [bool]$global:PIM_MailKillSwitch; redirectAllTo = "$($global:PIM_MailRedirectAllTo)"; allowlist = @($global:PIM_MailAllowlist) }
}
function Initialize-PimEmailControlsFromStore {
    # Make the send path authoritative against SQL pim.Settings: read 'EmailControls'
    # directly and apply it to the $global:PIM_Mail* globals BEFORE sending, so a cold
    # scheduled job / engine run honours a GUI-set kill switch / redirect / allowlist.
    # Hydrates ONCE per process by default (cheap; -Force re-reads). FAIL-SAFE: any read
    # failure leaves the current globals untouched -- it never clears an armed kill switch
    # and never opens the allowlist. No-op (returns $false) when no store is configured.
    param([switch]$Force)
    if ($script:PimEmailControlsHydrated -and -not $Force) { return $false }
    if (-not (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue)) { return $false }
    $n = -1
    try { $n = Import-PimSettingsFromStore } catch { $n = -1 }   # applies EmailControls via Set-PimEmailControlsGlobals
    if ($n -ge 0) { $script:PimEmailControlsHydrated = $true; return $true }
    return $false   # store unreachable -> leave globals as-is (fail-safe), retry next send
}

function Get-PimPortalBaseUrl {
    <#
      §79.3 -- the PIM Manager's address for links in mail. Order: the 'ManagerUrl' setting (pim.Settings, hydrated into
      $global:PIM_NamingConventions; a hosted Manager records its own address there on its first request), else
      $global:PIM_ManagerUrl, else env PIM_MANAGER_URL. '' when unknown -- a mail is then sent without a link, never with a
      guessed one. Only https:// (or http://localhost for a local Manager) is accepted.
    #>
    $v = ''
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('ManagerUrl')) { $v = "$($global:PIM_NamingConventions['ManagerUrl'])" }
    if (-not $v.Trim() -and "$($global:PIM_ManagerUrl)".Trim()) { $v = "$($global:PIM_ManagerUrl)" }
    if (-not $v.Trim() -and "$($env:PIM_MANAGER_URL)".Trim()) { $v = "$($env:PIM_MANAGER_URL)" }
    $v = $v.Trim().Trim('"').TrimEnd('/')
    if ($v -notmatch '^(?i)(https://[^\s/?#]+|http://(localhost|127\.0\.0\.1)(:\d+)?)$') { return '' }
    return $v
}

function Get-PimPortalLink {
    # §79.3 -- the deep link for one mail: base + '/?tab=<page>'. The page comes from the caller (Tokens.PortalTab, then
    # Tokens.AlertTab) or the mail type's own page. Returns @{ base; url; tab } (url '' when no base is known).
    param([string]$Type, [hashtable]$Tokens = @{})
    # A credential delivery goes to a sponsor / department owner who usually has no Manager access -- no link there.
    if ("$Type" -match '^(tap-delivery|ad-password-delivery)$') { return [pscustomobject]@{ base = ''; tab = ''; url = '' } }
    $base = Get-PimPortalBaseUrl
    $tab = ''
    foreach ($k in 'PortalTab', 'AlertTab') { if (-not $tab -and $Tokens -and $Tokens.ContainsKey($k) -and "$($Tokens[$k])".Trim() -match '^[a-z0-9-]+$') { $tab = "$($Tokens[$k])".Trim() } }
    if (-not $tab) {
        $tab = switch -Regex ("$Type") {
            '^access-review'   { 'accessreview'; break }
            '^approval'        { 'approvals'; break }
            '^(new-admin|offboarding|tap-delivery|ad-password)' { 'accounts'; break }
            '^discovery'       { 'discovery'; break }
            '^emergency'       { 'emergency'; break }
            '^tier-report'     { 'reports'; break }
            '^update-outcome'  { 'jobs'; break }
            default            { 'home' }
        }
    }
    # §79.8: Tokens.PortalQuery deep-links one record on that page (e.g. person=<upn> on the owner page). Each value is
    # URL-encoded; a malformed query is dropped rather than shipped, so a link never carries caller-built text raw.
    $q = ''
    if ($Tokens -and $Tokens.ContainsKey('PortalQuery') -and "$($Tokens['PortalQuery'])".Trim()) {
        $parts = foreach ($kv in ("$($Tokens['PortalQuery'])".Trim() -split '&')) {
            if ($kv -match '^([a-z][a-z0-9]{0,30})=(.{1,200})$') { '{0}={1}' -f $Matches[1], [uri]::EscapeDataString($Matches[2]) }
        }
        if (@($parts).Count) { $q = '&' + (@($parts) -join '&') }
    }
    [pscustomobject]@{ base = $base; tab = $tab; url = $(if ($base) { "$base/?tab=$tab$q" } else { '' }) }
}

function Get-PimNotifyTemplateDir {
    if ($global:PIM_MailTemplateDir) { return "$($global:PIM_MailTemplateDir)" }
    if ($PSScriptRoot) { return (Join-Path (Resolve-Path "$PSScriptRoot\..\..").Path 'templates\mail') }
    return $null
}
function Get-PimNotifyTemplate {
    # Path of the SHIPPED template for a type (the store's default), or $null. There is no
    # <type>.mailtemplate.custom.html any more -- customisation lives in the SQL template store.
    param([Parameter(Mandatory)][string]$Type)
    $dir = Get-PimNotifyTemplateDir; if (-not $dir) { return $null }
    $p = Join-Path $dir "$Type.mailtemplate.html"; if (Test-Path -LiteralPath $p) { return $p }
    return $null
}
function Get-PimNotifyTemplateText {
    # Resolve the EFFECTIVE template body for a type from the ONE template store
    # (SQL pim.Settings['MailTemplates'], PIM-MailTemplateStore.ps1), else the shipped file for a
    # type the store has not been seeded with yet. Returns @{ text; source } or $null.
    # REMOVED 2026-09-13 (operator: one template store in SQL): the MailTemplateOverrides layer and
    # the <type>.mailtemplate.custom.html file override are not read.
    param([Parameter(Mandatory)][string]$Type)
    if (Get-Command Get-PimMailTemplateEffective -ErrorAction SilentlyContinue) {
        $e = Get-PimMailTemplateEffective -Type $Type -TemplateDir (Get-PimNotifyTemplateDir)
        if ($e) { return @{ text = $e.text; source = $e.source } }
        return $null
    }
    $shipped = Get-PimNotifyTemplate -Type $Type
    if ($shipped) { return @{ text = (Get-Content -LiteralPath $shipped -Raw -Encoding UTF8); source = 'shipped' } }
    return $null
}
function ConvertTo-PimNotifyRendering {
    # PURE: template text + tokens -> @{ Subject; BodyHtml; BodyText }. Subject from a
    # leading <!-- subject: ... --> comment. Unknown {{tokens}} render empty (warned).
    param([Parameter(Mandatory)][string]$TemplateText, [Parameter(Mandatory)][hashtable]$Tokens)
    $subject = 'PIM4EntraPS notification'
    if ($TemplateText -match '<!--\s*subject:\s*(.+?)\s*-->') { $subject = $Matches[1] }
    $render = {
        param([string]$text)
        foreach ($k in $Tokens.Keys) { $text = $text -replace ('\{\{' + [regex]::Escape($k) + '\}\}'), ([string]$Tokens[$k] -replace '\$', '$$$$') }
        $leftover = @([regex]::Matches($text, '\{\{(\w+)\}\}') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        if ($leftover.Count -gt 0) { Write-Warning "  [Mail] unknown token(s): $($leftover -join ', ') -- rendered empty."; $text = [regex]::Replace($text, '\{\{\w+\}\}', '') }
        $text
    }
    $subject  = & $render $subject
    $bodyHtml = & $render $TemplateText
    $bodyText = $bodyHtml -replace '<!--.*?-->', ''
    $bodyText = $bodyText -replace '(?i)<br\s*/?>', "`r`n" -replace '(?i)</(p|div|li|h[1-6]|tr)>', "`r`n"
    $bodyText = $bodyText -replace '<[^>]+>', '' -replace '&nbsp;', ' ' -replace '&amp;', '&' -replace '&lt;', '<' -replace '&gt;', '>' -replace '&quot;', '"'
    $bodyText = (($bodyText -split "`r?`n" | ForEach-Object { $_.TrimEnd() }) -join "`r`n") -replace "(`r`n){3,}", "`r`n`r`n"
    @{ Subject = $subject; BodyHtml = $bodyHtml; BodyText = $bodyText.Trim() }
}
function Resolve-PimMailSendIdentity {
    <#
      WHICH principal sends the mail (REQUIREMENTS 65.11, operator decision 2026-09-13).
      Hosted (Container Apps / App Service expose IDENTITY_ENDPOINT or MSI_ENDPOINT) -> the host's
      MANAGED IDENTITY, even when an engine SPN is also configured: the scoped Exchange
      'Application Mail.Send' assignment is made for the tick job's managed identity, so sending as
      the SPN from a container would be refused. Not hosted -> the engine SPN (certificate).
      Neither -> 'ambient' (a dev session), named as such rather than guessed.
      Returns { kind = managed-identity|engine-spn|ambient; hosted; clientId; label }. Reads only
      the environment and the engine globals; no network.
    #>
    [CmdletBinding()] param()
    $hosted = [bool]("$($env:IDENTITY_ENDPOINT)".Trim() -or "$($env:MSI_ENDPOINT)".Trim())
    if ($hosted) {
        $miCid = if ("$($global:PIM_ManagedIdentityClientId)".Trim()) { "$($global:PIM_ManagedIdentityClientId)".Trim() }
                 elseif ("$($env:PIM_ManagedIdentityClientId)".Trim()) { "$($env:PIM_ManagedIdentityClientId)".Trim() } else { '' }
        $label = if ($miCid) { "managed identity (client id $miCid)" } else { 'managed identity (system-assigned)' }
        return [pscustomobject]@{ kind = 'managed-identity'; hosted = $true; clientId = $miCid; label = $label }
    }
    $cid = "$($global:PIM_ClientId)".Trim()
    if (-not $cid) { $cid = "$($env:PIM_ClientId)".Trim() }
    $thumb = "$($global:PIM_CertThumbprint)".Trim()
    if (-not $thumb) { $thumb = "$($env:PIM_CertThumbprint)".Trim() }
    if ($cid -and $thumb) {
        return [pscustomobject]@{ kind = 'engine-spn'; hosted = $false; clientId = $cid; label = "engine SPN $cid (certificate)" }
    }
    return [pscustomobject]@{ kind = 'ambient'; hosted = $false; clientId = $cid; label = 'ambient identity (no managed identity and no engine SPN certificate configured)' }
}

function Get-PimMailSendDenialMessage {
    <#
      PURE. Turn a sendMail refusal into a message that NAMES the identity and the fix, or return ''
      when the error is not an authorization refusal (a throttle or a bad address must not be
      reported as a missing grant). Mail.Send here is the SCOPED Exchange RBAC assignment, never a
      tenant-wide Graph consent -- the remedy says so, so nobody "fixes" it by granting the wide one.
    #>
    [CmdletBinding()] param([object]$Identity, [string]$Sender, [string]$ErrorText, [string]$ObservedAppId = '')
    $e = "$ErrorText"
    if ($e -notmatch '(?i)ErrorAccessDenied|Authorization_RequestDenied|AccessDenied|Access is denied|\b403\b|Forbidden|MailboxNotEnabledForRESTAPI') { return '' }
    $who = if ($Identity -and "$($Identity.label)".Trim()) { "$($Identity.label)" } else { 'the current identity' }
    if ("$ObservedAppId".Trim()) { $who = "$who, token appId $ObservedAppId" }
    $fix = switch ("$($Identity.kind)") {
        'managed-identity' { "Run tools/setup/Initialize-PimMailSender.ps1 with -ManagedIdentityObjectId <the tick job's managed identity principalId> so Exchange grants that identity 'Application Mail.Send' scoped to '$Sender'." }
        'engine-spn'       { "Run tools/setup/Initialize-PimMailSender.ps1 with -EngineAppId <engine appId> so Exchange grants the engine SPN 'Application Mail.Send' scoped to '$Sender'." }
        default            { 'Configure the engine identity (managed identity when hosted, engine SPN certificate otherwise) and give it the scoped Exchange assignment.' }
    }
    return ("mail send DENIED as {0}: this identity has no Exchange 'Application Mail.Send' assignment for the sender mailbox '{1}' (sending is granted per mailbox by Exchange RBAC for Applications -- do NOT grant tenant-wide Graph Mail.Send). {2} Error: {3}" -f $who, $Sender, $fix, (($e -split "`n")[0]))
}

function Get-PimMailEnvironmentInfo {
    <#
      MAIL-1: what names THIS environment in a mail -- @{ name; tenantName; tenantId; version; portal }. name = the
      environment name the Manager header shows (pim.Settings 'EnvironmentName', or $global:PIM_EnvironmentName), else the
      tenant name, else the tenant id -- never "this tenant". Read once per process; never throws (a mail is never blocked).
    #>
    param([string]$PortalBase = '')
    if (-not $script:PimMailEnvInfo) {
        $name = "$($global:PIM_EnvironmentName)".Trim()
        if (-not $name -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            try { $cs = Get-PimSqlSettingsConnectionString; if ($cs) { $v = Get-PimSqlSetting -ConnectionString $cs -Name 'EnvironmentName'; if ($v -is [string]) { $name = $v.Trim() } elseif ($v -and $v.PSObject.Properties['name']) { $name = "$($v.name)".Trim() } } } catch { }
        }
        $tn = "$($global:PIM_TenantName)".Trim(); $tid = "$($global:PIM_TenantId)".Trim()
        $ver = ''
        try { $vf = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'VERSION'; if (Test-Path -LiteralPath $vf) { $ver = "$(Get-Content -Raw -LiteralPath $vf)".Trim() } } catch { }
        $script:PimMailEnvInfo = @{ name = $(if ($name) { $name } elseif ($tn) { $tn } else { $tid }); tenantName = $tn; tenantId = $tid; version = $ver }
    }
    $i = @{} + $script:PimMailEnvInfo; $i['portal'] = "$PortalBase".Trim()
    return $i
}

function Save-PimMailSendProof {
    <#
      MAIL CHECK (owner 2026-10-08: "test exactly what is needed"): record THIS identity's last REAL send result, so Get
      Started > Mail sender and the Home banner can say per sending identity "proven" / "failed" / "not proven yet" instead
      of guessing that its scoped send right works. pim.Settings 'MailSendProof' = { engine: {...}; manager: {...} }, each
      @{ ok; at; reason; mode; sender }. The role is the Manager when this process is the Manager (Set-PimManagerSetting is
      loaded), else the engine; $global:PIM_MailProofRole overrides. Written at most every 15 minutes per process unless the
      result or the settings change. NEVER throws: a proof that cannot be written must not fail the mail.
      TEST seam: $global:PIM_MailProofWriter = param($Role, $Record).
    #>
    param([bool]$Ok, [string]$Reason = '', [string]$Mode = '', [string]$Sender = '')
    try {
        $role = if ("$($global:PIM_MailProofRole)".Trim()) { "$($global:PIM_MailProofRole)".Trim() } elseif (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { 'manager' } else { 'engine' }
        $one = "$Reason" -replace "[\r\n]+", ' '; if ($one.Length -gt 300) { $one = $one.Substring(0, 300) }
        $rec = [ordered]@{ ok = $Ok; at = (Get-Date).ToUniversalTime().ToString('o'); reason = $one; mode = "$Mode"; sender = "$Sender".Trim() }
        $key = "$role|$Ok|$Mode|$("$Sender".Trim().ToLowerInvariant())"
        if ($script:PimMailProofLast -and $script:PimMailProofLast.key -eq $key -and ((Get-Date) - $script:PimMailProofLast.at).TotalMinutes -lt 15) { return }
        $script:PimMailProofLast = @{ key = $key; at = (Get-Date) }
        if ($global:PIM_MailProofWriter -is [scriptblock]) { & $global:PIM_MailProofWriter $role $rec | Out-Null; return }
        $merge = { param($cur) $o = [ordered]@{}; if ($cur) { foreach ($p in @($cur.PSObject.Properties)) { if ($p.Name -in 'engine', 'manager') { $o[$p.Name] = $p.Value } } }; $o[$role] = $rec; $o }
        if (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) {
            $cur = $null; try { $cur = Get-PimManagerSetting -Name 'MailSendProof' } catch { }
            if ($cur -is [string]) { try { $cur = $cur | ConvertFrom-Json } catch { $cur = $null } }
            Set-PimManagerSetting -Name 'MailSendProof' -Value (& $merge $cur)
            return
        }
        if ((Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $cs = Get-PimSqlSettingsConnectionString
            if (-not $cs) { return }
            $cur = $null; try { $cur = Get-PimSqlSetting -ConnectionString $cs -Name 'MailSendProof' } catch { }
            if ($cur -is [string]) { try { $cur = $cur | ConvertFrom-Json } catch { $cur = $null } }
            Set-PimSqlSetting -ConnectionString $cs -Name 'MailSendProof' -Value (& $merge $cur)
        }
    } catch { Write-Verbose "  [Mail] the send proof could not be recorded: $($_.Exception.Message)" }
}

# =====================================================================================================================
# MAIL-STEP-PROOF (owner 2026-10-09: "i have run 3 cmdlet, and test mail works - but it still shows eros"). "Send test mail"
# proves BOTH sending identities: the Manager sends its own test at once, and queues ONE engine test send in pim.Settings
# 'MailEngineTest'. The engine job (ca-pim-tick, Start-PimScheduler -Once) sends it at the start of its next run as ITS OWN
# identity through Send-PimNotifyMail -- so the proof is recorded exactly as a real engine send records it (MailSendProof
# .engine: ok, or FAILED with the reason, e.g. 403 ErrorAccessDenied).
#   record: @{ id; status = queued | sending | sent | failed; to; by; sender; mode; queuedUtc; claimedUtc; at; reason }
# =====================================================================================================================
function New-PimMailEngineTestRequest {
    # PURE. The record the Manager writes when Send test mail is pressed.
    param([Parameter(Mandatory)][string]$To, [string]$By = '', [string]$Mode = 'sharedMailbox', [string]$Sender = '', [datetime]$NowUtc = [datetime]::UtcNow)
    return [ordered]@{ id = [guid]::NewGuid().ToString(); status = 'queued'; to = "$To".Trim(); by = "$By".Trim(); sender = "$Sender".Trim(); mode = "$Mode".Trim()
                       queuedUtc = $NowUtc.ToUniversalTime().ToString('o'); claimedUtc = ''; at = ''; reason = '' }
}

function Get-PimMailEngineTestAction {
    <#
      PURE. Should THIS engine run send the queued engine test mail? Returns @{ act; reason }.
        queued                                  -> act
        sending, claimed more than 15 min ago   -> act again (the run that claimed it died)
        older than -MaxAgeHours (24)            -> no (a stale request is never sent days later)
        no / invalid recipient, sent, failed    -> no
    #>
    param([AllowNull()]$Request, [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxAgeHours = 24)
    $g = { param($n) if ($null -eq $Request) { $null } elseif ($Request -is [System.Collections.IDictionary]) { $Request[$n] } elseif ($Request.PSObject.Properties[$n]) { $Request.$n } else { $null } }
    if ($null -eq $Request) { return @{ act = $false; reason = 'no engine test mail is queued' } }
    $st = "$(& $g 'status')".Trim().ToLowerInvariant()
    $to = "$(& $g 'to')".Trim()
    $parse = { param($s) $d = [datetime]::MinValue; $sty = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
               if ("$s".Trim() -and [datetime]::TryParse("$s", [Globalization.CultureInfo]::InvariantCulture, $sty, [ref]$d)) { $d.ToUniversalTime() } else { $null } }
    $now = $NowUtc.ToUniversalTime()
    if ($st -notin @('queued', 'sending')) { return @{ act = $false; reason = "the engine test mail is already $(if ($st) { $st } else { 'handled' })" } }
    if ($to -notmatch '^[^@\s;,<>]+@[^@\s;,<>]+\.[^@\s;,<>]+$') { return @{ act = $false; reason = 'the queued engine test mail has no valid recipient' } }
    $q = & $parse (& $g 'queuedUtc')
    if (-not $q -or ($now - $q).TotalHours -gt $MaxAgeHours) { return @{ act = $false; reason = "the queued engine test mail is older than $MaxAgeHours h -- not sent (press Send test mail again)" } }
    if ($st -eq 'sending') {
        $c = & $parse (& $g 'claimedUtc')
        if ($c -and ($now - $c).TotalMinutes -lt 15) { return @{ act = $false; reason = 'another engine run is sending the test mail' } }
    }
    return @{ act = $true; reason = 'an engine test mail is queued' }
}

function Invoke-PimMailEngineTest {
    <#
      The ENGINE side (called by Start-PimScheduler -Once before the tick, main instance only). Sends the queued engine test
      mail as this process's identity (the engine job's) and records the result on the request; the send proof itself is
      recorded by Send-PimNotifyMail (role engine), unthrottled for this one send. Returns @{ ran; sent; detail }. NEVER throws.
      -Reader / -Writer: test seams (param($Name) / param($Name, $Value)); default Get-PimSetting / Set-PimSetting.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Reader, [scriptblock]$Writer, [switch]$WhatIf)
    try {
        if (-not $Reader) { if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $Reader = { param($n) Get-PimSetting -Name $n } } else { return @{ ran = $false; sent = $false; detail = 'no settings store in this process' } } }
        if (-not $Writer) { if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { $Writer = { param($n, $v) Set-PimSetting -Name $n -Value $v | Out-Null } } else { return @{ ran = $false; sent = $false; detail = 'no settings store in this process' } } }
        $req = & $Reader 'MailEngineTest'
        if ($req -is [string]) { try { $req = $req | ConvertFrom-Json } catch { $req = $null } }
        $plan = Get-PimMailEngineTestAction -Request $req -NowUtc $NowUtc
        if (-not $plan.act) { return @{ ran = $false; sent = $false; detail = $plan.reason } }
        if ($WhatIf) { return @{ ran = $false; sent = $false; detail = 'whatif -- the queued engine test mail would be sent' } }
        $rec = [ordered]@{}
        if ($req -is [System.Collections.IDictionary]) { foreach ($k in @($req.Keys)) { $rec["$k"] = $req[$k] } }
        else { foreach ($p in @($req.PSObject.Properties)) { $rec[$p.Name] = $p.Value } }
        $rec['status'] = 'sending'; $rec['claimedUtc'] = $NowUtc.ToUniversalTime().ToString('o')
        & $Writer 'MailEngineTest' $rec
        $prevRole = $global:PIM_MailProofRole
        $global:PIM_MailProofRole = 'engine'
        $script:PimMailProofLast = $null   # this one send is always recorded (never throttled away)
        $r = $null
        try {
            $r = Send-PimNotifyMail -Type 'alert-notice' -Recipient "$($rec['to'])" -Tokens @{
                AlertTitle = 'PIM Manager engine test mail'; AlertEvent = 'mail-test'; AlertTab = 'getstarted'
                AlertDetail = 'This test mail was sent by the PIM engine job as its own identity, because Send test mail was pressed in Get Started / Settings > Mail & alerting. It proves that the engine can send TAP codes, reminders and alerts.'
                AlertHeadline = 'Mail from the PIM engine works.'; AlertAction = 'Nothing to do -- this was a test.'
                WhenUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
        } catch { $r = @{ sent = $false; reason = "$($_.Exception.Message)" } }
        finally { $global:PIM_MailProofRole = $prevRole }
        $ok = ("$($r.sent)" -match '(?i)^true$')
        $one = "$($r.reason)" -replace "[\r\n]+", ' '; if ($one.Length -gt 300) { $one = $one.Substring(0, 300) }
        $rec['status'] = $(if ($ok) { 'sent' } else { 'failed' }); $rec['at'] = (Get-Date).ToUniversalTime().ToString('o'); $rec['reason'] = $(if ($ok) { '' } else { $one })
        try { & $Writer 'MailEngineTest' $rec } catch { Write-Warning "  [Mail] the engine test mail result could not be recorded: $($_.Exception.Message)" }
        return @{ ran = $true; sent = $ok; detail = $(if ($ok) { "engine test mail sent to $($rec['to'])" } else { "engine test mail NOT sent: $one" }) }
    } catch {
        return @{ ran = $false; sent = $false; detail = "the engine test mail failed: $($_.Exception.Message)" }
    }
}

function Send-PimNotifyMail {
    # Render type+tokens and send via Graph sendMail. Returns @{ sent; recipient; subject;
    # rendered; reason }. No send (returns rendered only) when -WhatIf / $global:WhatIfMode,
    # no sender configured, or no template -- so it is safe to call unconditionally.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][hashtable]$Tokens, [string]$Recipient, [switch]$WhatIf,
          # §79.14: files to attach -- each @{ name; contentType; bytes = [byte[]] } (a CAB workbook on a policy hold).
          [object[]]$Attachments = @())
    $rcpt = $Recipient

    # --- AUTHORITATIVE EMAIL CONTROLS: hydrate from SQL pim.Settings before sending,
    # so a COLD-booted scheduled job / engine run honours the GUI-saved kill switch /
    # redirect / allowlist -- not just the Manager's in-process globals. Fail-safe: a
    # read failure leaves the current globals untouched (never disarms a kill switch).
    if (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue) { [void](Initialize-PimEmailControlsFromStore) }

    # --- EMAIL CONTROLS (REQUIREMENTS s29) ------------------------------------
    # 1) Global email KILL SWITCH: when $global:PIM_MailKillSwitch is set, OR the
    #    'alerting.email' feature is disabled/unlicensed, EVERY send is a no-op.
    #    Honoured here so every send path + every job/scheduler is covered at the
    #    one chokepoint. A disabled feature performs NO sends, no matter the trigger.
    if ($global:PIM_MailKillSwitch) { return @{ sent = $false; recipient = $rcpt; reason = 'email kill switch on' } }
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'alerting.email' -Quiet)) {
        return @{ sent = $false; recipient = $rcpt; reason = 'email feature disabled' }
    }
    # 2) Override/redirect target -- $global:PIM_MailRedirectAllTo handled below
    #    (existing behaviour). 3) Allowlist: when $global:PIM_MailAllowlist is a
    #    non-empty set, a recipient NOT on it (after redirect resolution) is dropped.
    if ($global:PIM_MailRedirectAllTo -and "$($global:PIM_MailRedirectAllTo)".Trim()) {
        $redir = "$($global:PIM_MailRedirectAllTo)".Trim()
        if ($rcpt -and $rcpt -ne $redir) { $Tokens = @{} + $Tokens; $Tokens['RedirectedFrom'] = $rcpt; Write-Host "  [Mail] redirect: '$rcpt' -> $redir" -ForegroundColor DarkYellow }
        $rcpt = $redir
    }
    # Allowlist (REQUIREMENTS s29): when configured + non-empty, drop any recipient
    # not on it (after the redirect resolution above). Empty/unset = no restriction.
    # 71.19: -Recipient may name SEVERAL addresses (a sponsor department can have more than one owner, and the operator's
    # rule is that they all get the mail). They are carried as one ';'-joined string so every caller keeps its signature,
    # and split here into one message with several toRecipients -- one mail, one TAP code, all the owners.
    $rcptList = @("$rcpt" -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $allow = @($global:PIM_MailAllowlist | Where-Object { "$_".Trim() })
    if ($allow.Count -gt 0 -and $rcptList.Count) {
        $allowLc = @($allow | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        $kept = @($rcptList | Where-Object { $allowLc -contains "$_".ToLowerInvariant() })
        if (-not $kept.Count) { Write-Host "  [Mail] '$rcpt' not on allowlist -- not sent." -ForegroundColor DarkYellow; return @{ sent = $false; recipient = $rcpt; reason = 'recipient not on allowlist' } }
        if ($kept.Count -ne $rcptList.Count) { Write-Host "  [Mail] allowlist dropped $($rcptList.Count - $kept.Count) of $($rcptList.Count) recipient(s)." -ForegroundColor DarkYellow }
        $rcptList = $kept; $rcpt = ($kept -join ';')
    }
    $tpl = Get-PimNotifyTemplateText -Type $Type
    if (-not $tpl) { return @{ sent = $false; recipient = $rcpt; reason = "no template '$Type'" } }
    # §79.3 (operator 2026-09-25: "verify all emails include links to the portal"): the link is added HERE, at the one
    # chokepoint, so every mail carries it -- including a template a customer edited in the store before the link existed.
    $portal = Get-PimPortalLink -Type $Type -Tokens $Tokens
    if ($portal.url) {
        $Tokens = @{} + $Tokens; $Tokens['PortalUrl'] = $portal.base; $Tokens['PortalLink'] = $portal.url
        # The review / approval templates carry their own button ({{ReviewUrl}} / {{ApprovalUrl}}) that no caller filled --
        # a dead link in every reminder. An empty one now points at the same page.
        foreach ($k in 'ReviewUrl', 'ApprovalUrl') { if (-not "$($Tokens[$k])".Trim()) { $Tokens[$k] = $portal.url } }
    }
    $r = ConvertTo-PimNotifyRendering -TemplateText $tpl.text -Tokens $Tokens
    # §100.5 MAIL-2 leftover (b), 2.4.555: an alert / transactional template (not built with New-PimMailDocument) is put in
    # the ONE designed layout here -- logo + environment header, its own content unchanged, the blue button AFTER it and the
    # designed footer (environment, tenant, version, Open PIM Manager, Change what you receive). A template that opts out
    # (<!-- pim-no-layout -->) or is already designed keeps its body; the old button / MAIL-1 footer below then apply.
    if ((Get-Command ConvertTo-PimMailLayoutFrame -ErrorAction SilentlyContinue) -and $r.BodyHtml -notmatch 'class="pim-mail"' -and $tpl.text -notmatch '<!--\s*pim-no-layout\s*-->') {
        $envF = Get-PimMailEnvironmentInfo -PortalBase "$($portal.base)"
        $homeF = ''; $notifF = ''
        if ("$($portal.base)".Trim()) {
            $homeF = "$($portal.base)".Trim()
            if (Get-Command Get-PimAudienceLink -ErrorAction SilentlyContinue) { try { $notifF = "$((Get-PimAudienceLink -Type 'settings' -Base $portal.base -LinkTab 'settings' -Query 'section=notifications').url)" } catch { $notifF = '' } }
        }
        try {
            $framed = ConvertTo-PimMailLayoutFrame -BodyHtml $r.BodyHtml -Subject "$($r.Subject)" -Button $(if ($portal.url) { @{ url = $portal.url; label = 'Open in PIM Manager' } } else { $null }) `
                        -HomeUrl $homeF -NotificationsUrl $notifF -Environment @{ name = $envF.name; tenantName = $envF.tenantName; tenantId = $envF.tenantId; version = $envF.version }
            if ("$framed".Trim()) { $r.BodyHtml = $framed }
        } catch { Write-Verbose "  [Mail] the designed layout could not be applied ($($_.Exception.Message)) -- the template is sent as it is" }
        if ($portal.url -and "$($r.BodyText)" -notmatch [regex]::Escape($portal.url)) { $r.BodyText = "$($r.BodyText)`r`n`r`nOpen in PIM Manager: $($portal.url)" }
        # MAIL-1: the plain-text part names the environment too (the HTML footer is the designed one, so the block below skips)
        if ($envF.name -and "$($r.BodyHtml)" -match 'class="pim-env-footer"' -and "$($r.BodyText)" -notmatch '-- Environment: ') {
            $r.BodyText = "$($r.BodyText)`r`n`r`n-- Environment: $($envF.name)" + $(if ($envF.tenantName -or $envF.tenantId) { " | tenant $($envF.tenantName) ($($envF.tenantId))" } else { '' }) +
                          $(if ($envF.version) { " | PIM Manager $($envF.version)" } else { '' }) + $(if ($portal.base) { " | $($portal.base)" } else { '' })
        }
    }
    if ($portal.url -and $r.BodyHtml -notmatch [regex]::Escape($portal.base)) {
        # MAIL-2 item 1: the bulletproof blue button (a table cell carries the colour, so Outlook draws it too).
        $block = if (Get-Command New-PimMailButton -ErrorAction SilentlyContinue) { New-PimMailButton -Url $portal.url -Label 'Open in PIM Manager' } else { '' }
        if (-not $block) {
            $block = '<p style="margin:18px 0 0 0;font-family:''Segoe UI'',Helvetica,Arial,sans-serif;font-size:14px;"><a href="' + [System.Net.WebUtility]::HtmlEncode($portal.url) +
                     '" style="display:inline-block;background:#0969da;color:#ffffff;text-decoration:none;padding:8px 14px;border-radius:6px;">Open in PIM Manager &rarr;</a></p>'
        }
        $r.BodyHtml = if ($r.BodyHtml -match '(?i)</body>') { [regex]::Replace($r.BodyHtml, '(?i)</body>', ($block -replace '\$', '$$$$') + '</body>', 1) } else { $r.BodyHtml + $block }
        $r.BodyText = "$($r.BodyText)`r`n`r`nOpen in PIM Manager: $($portal.url)"
    }
    # MAIL-1 (framework §12.3, operator 2026-10-07: "for all emails in any solution, we need to include environment name in
    # the footer" -- a hold mail said only "this tenant"): EVERY mail names its environment, at this one chokepoint -- the
    # subject starts with it and the footer carries environment, tenant name + id, PIM Manager version and the link.
    $envInfo = Get-PimMailEnvironmentInfo -PortalBase "$($portal.base)"
    if ($envInfo.name) {
        # StartsWith, never -like: '[...]' is a wildcard character SET to -like ("[Contoso]*" matched "CUSTOM ...")
        if (-not "$($r.Subject)".StartsWith("[$($envInfo.name)]", [System.StringComparison]::OrdinalIgnoreCase)) { $r.Subject = "[$($envInfo.name)] $($r.Subject)" }
    }
    # MAIL-2: a designed mail (PIM-MailLayout.ps1 New-PimMailDocument) carries its OWN footer with the same facts -- one footer,
    # not two. Every other mail gets the MAIL-1 footer here, as before.
    if ($envInfo.name -and $r.BodyHtml -notmatch 'class="pim-env-footer"') {
        $enc = { param($v) [System.Net.WebUtility]::HtmlEncode("$v") }
        $foot = '<p class="pim-env-footer" style="margin:22px 0 0 0;padding-top:8px;border-top:1px solid #d0d7de;font-family:''Segoe UI'',Helvetica,Arial,sans-serif;font-size:12px;color:#57606a;">' +
                'Environment: <b>' + (& $enc $envInfo.name) + '</b>' +
                $(if ($envInfo.tenantName -or $envInfo.tenantId) { ' &middot; tenant ' + (& $enc $envInfo.tenantName) + $(if ($envInfo.tenantId) { ' (' + (& $enc $envInfo.tenantId) + ')' } else { '' }) } else { '' }) +
                $(if ($envInfo.version) { ' &middot; PIM Manager ' + (& $enc $envInfo.version) } else { '' }) +
                $(if ($envInfo.portal) { ' &middot; <a href="' + (& $enc $envInfo.portal) + '" style="color:#0969da;">' + (& $enc $envInfo.portal) + '</a>' } else { '' }) + '</p>'
        $r.BodyHtml = if ($r.BodyHtml -match '(?i)</body>') { [regex]::Replace($r.BodyHtml, '(?i)</body>', ($foot -replace '\$', '$$$$') + '</body>', 1) } else { $r.BodyHtml + $foot }
        $r.BodyText = "$($r.BodyText)`r`n`r`n-- Environment: $($envInfo.name)" + $(if ($envInfo.tenantName -or $envInfo.tenantId) { " | tenant $($envInfo.tenantName) ($($envInfo.tenantId))" } else { '' }) +
                      $(if ($envInfo.version) { " | PIM Manager $($envInfo.version)" } else { '' }) + $(if ($envInfo.portal) { " | $($envInfo.portal)" } else { '' })
    }
    # MAIL-2 item 4: the LOGO. A designed mail references it as cid:pim-logo; it travels as an INLINE attachment (the PNG the
    # docs already ship -- SVG is not drawn by Outlook or most webmail). No PNG in this runtime -> the text wordmark takes its
    # place, so a mail never shows a broken image. A mail that does not reference it gets no logo attachment.
    $Attachments = @(@($Attachments) | Where-Object { $_ })
    if ($r.BodyHtml -match 'cid:pim-logo') {
        $logo = if (Get-Command Get-PimMailLogoAttachment -ErrorAction SilentlyContinue) { Get-PimMailLogoAttachment } else { $null }
        if ($logo) {
            if (-not @($Attachments | Where-Object { "$($_.contentId)" -eq 'pim-logo' }).Count) { $Attachments = @($Attachments) + @($logo) }
        } else {
            $wm = if (Get-Command Get-PimMailWordmarkHtml -ErrorAction SilentlyContinue) { Get-PimMailWordmarkHtml } else { '<b>PIM Manager</b>' }
            $r.BodyHtml = [regex]::Replace($r.BodyHtml, '(?s)<!--pim-logo-->.*?<!--/pim-logo-->', ($wm -replace '\$', '$$$$'))
            $r.BodyHtml = [regex]::Replace($r.BodyHtml, '<img\b[^>]*cid:pim-logo[^>]*>', ($wm -replace '\$', '$$$$'))
        }
    }
    $r['Attachments'] = @($Attachments | ForEach-Object { "$($_.name)" })
    $sender = "$($global:PIM_MailSender)".Trim()
    # MAIL-1 (framework 12.3, owner 2026-10-08: "2 options: shared mailbox or smtp relay"): ONE setting picks the transport.
    # 'none' is checked BEFORE -WhatIf on purpose: Test-PimTapMailReady probes with -WhatIf, and a switched-off environment
    # must answer "not sent" there too (the trap that function's docstring describes for a missing sender).
    $mailMode = if (Get-Command Get-PimMailMode -ErrorAction SilentlyContinue) { Get-PimMailMode } else { 'sharedMailbox' }
    if ($mailMode -eq 'none') { return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = 'mail is switched off (Settings > Mail & alerting: mail mode none)' } }
    if ($WhatIf -or $global:WhatIfMode) { return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = 'whatif' } }
    if ($mailMode -eq 'smtp') {
        $relay = Get-PimSmtpRelayConfig
        if (-not $relay.ok) {
            $why = 'the SMTP relay is not configured correctly: ' + (@($relay.errors.Values) -join ' ')
            Write-Warning "  [Mail] $why -- rendered only, not sent."
            return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = $why; sentAs = 'smtp' }
        }
        if (-not $rcpt) { return @{ sent = $false; subject = $r.Subject; rendered = $r; reason = 'no recipient' } }
        if (-not $rcptList.Count) { $rcptList = @($rcpt) }
        $sm = Send-PimSmtpMail -Config $relay.config -Recipients $rcptList -Subject $r.Subject -BodyHtml $r.BodyHtml -BodyText $r.BodyText -Attachments $Attachments
        if (-not $sm.sent) { Write-Warning "  [Mail] send failed ($Type -> $rcpt) via SMTP relay: $($sm.reason)" }
        Save-PimMailSendProof -Ok ([bool]$sm.sent) -Reason "$($sm.reason)" -Mode 'smtp' -Sender "$($relay.config.from)"
        return @{ sent = [bool]$sm.sent; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = "$($sm.reason)"; sentAs = 'smtp' }
    }
    if (-not $sender) { Write-Warning "  [Mail] `$global:PIM_MailSender not set -- rendered only, not sent."; return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = 'no sender' } }
    if (-not $rcpt)   { return @{ sent = $false; subject = $r.Subject; rendered = $r; reason = 'no recipient' } }
    if (-not $rcptList.Count) { $rcptList = @($rcpt) }
    $body = @{ message = @{ subject = $r.Subject; body = @{ contentType = 'HTML'; content = $r.BodyHtml }
                            toRecipients = @($rcptList | ForEach-Object { @{ emailAddress = @{ address = $_ } } }) }; saveToSentItems = $false }
    $att = @(@($Attachments) | Where-Object { $_ -and $_.bytes -and "$($_.name)".Trim() } | ForEach-Object {
        $ga = @{ '@odata.type' = '#microsoft.graph.fileAttachment'; name = "$($_.name)"; contentType = $(if ("$($_.contentType)".Trim()) { "$($_.contentType)" } else { 'application/octet-stream' })
           contentBytes = [Convert]::ToBase64String([byte[]]$_.bytes) }
        # MAIL-2: an inline image (the logo) carries its Content-ID, so <img src="cid:..."> finds it
        if ("$($_.contentId)".Trim()) { $ga['contentId'] = "$($_.contentId)".Trim(); $ga['isInline'] = [bool]$_.isInline }
        $ga })
    if ($att.Count) { $body.message['attachments'] = $att }
    $sendAs = Resolve-PimMailSendIdentity
    # Splat the switch only when it is set: offline suites stub Invoke-PimGraph with a fixed
    # parameter list, and an unconditional -UseManagedIdentity would break every one of them.
    $graphArgs = @{ Method = 'POST'; Path = "/users/$sender/sendMail"; Body = $body }
    if ($sendAs.kind -eq 'managed-identity') { $graphArgs['UseManagedIdentity'] = $true }
    try {
        Invoke-PimGraph @graphArgs | Out-Null
        Save-PimMailSendProof -Ok $true -Mode 'sharedMailbox' -Sender $sender
        return @{ sent = $true; recipient = $rcpt; subject = $r.Subject; rendered = $r; sentAs = $sendAs.kind }
    }
    catch {
        $em = "$($_.Exception.Message) $($_.ErrorDetails.Message)".Trim()
        $obs = ''
        try {
            if ($sendAs.kind -eq 'managed-identity' -and (Get-Command Get-PimTokenAppId -ErrorAction SilentlyContinue)) {
                $obs = Get-PimTokenAppId -Token (Get-PimRestToken -Resource 'graph' -UseManagedIdentity)
            }
        } catch { $obs = '' }
        $denied = Get-PimMailSendDenialMessage -Identity $sendAs -Sender $sender -ErrorText $em -ObservedAppId $obs
        $why = if ($denied) { $denied } else { $em }
        Write-Warning "  [Mail] send failed ($Type -> $rcpt) as $($sendAs.label): $why"
        Save-PimMailSendProof -Ok $false -Reason "$why" -Mode 'sharedMailbox' -Sender $sender
        return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = $why; sentAs = $sendAs.kind }
    }
}

function Test-PimTapMailReady {
    <#
      Can a TAP mail actually be DELIVERED to this recipient, right now?

      🪤 THE TRAP THIS FUNCTION EXISTS TO AVOID. The obvious pre-check is to call
      Send-PimNotifyMail -WhatIf and look at the reason -- and it is WRONG. In
      PIM-Notify.ps1 the -WhatIf early-return sits BEFORE the 'no sender' and
      'no recipient' checks, so on a tenant with NO notification sender
      configured a -WhatIf probe returns reason='whatif' and looks perfectly
      healthy. That is exactly the tenant this guard is for: the one whose TAP
      mail was never going to arrive.

      So the sender and the recipient are checked EXPLICITLY here, and -WhatIf
      is used only for what it can genuinely answer (kill switch, disabled
      feature, allowlist, missing template).

      Returns @{ ok; reason }. Never throws -- a mail-readiness probe that
      throws would fail the request for a reason the operator cannot action.
    #>
    param([string]$Recipient, [string]$Reason)

    if (-not "$Recipient".Trim()) {
        # 71.19: the rule is the SPONSOR DEPARTMENT's owners, so say that -- the old text sent people to ManagerEmail,
        # which is not the mechanism any more. -Reason carries the resolver's own sentence (which admin, which
        # department, what is missing) when the caller has it.
        $why = "$Reason".Trim()
        # 2026-09-21 (operator, on the run log: "terrible error messages"): the resolver's sentence already says the
        # department rule, and this appended it AGAIN -- every refusal read the same instruction twice. Say the missing
        # thing once, then ONE fix line (which now includes the tenant's alert recipients, the last fallback).
        $fix = "Fix: set the admin's Department and give that department Owners (PIM-Definitions-Departments), or set an alert recipient (Home > Alerting), or a per-admin MailForwardAddress."
        return @{ ok = $false; reason = ("nobody to send the TAP to -- " + $(if ($why) { ($why -replace "\s*--\s*an admin's mail goes to its SPONSOR DEPARTMENT's owners, so set the admin's Department and give that department Owners\s*$", '') } else { "this admin has no resolvable recipient" }) + ". " + $fix) }
    }
    # 🔴 HYDRATE BEFORE JUDGING. Measured live on EFIF 2026-08-25: this guard refused ALL SIX admins
    # with "no notification sender is configured" while pim.Settings held a perfectly good
    # 'MailSender' (PIM-Engine@<tenant>). The sender was never missing -- it had not been READ yet.
    # Send-PimNotifyMail hydrates at L169, but this guard runs BEFORE that call and reads the raw
    # global, so on a cold engine run (the scheduled tick Job is always cold) it saw an empty value
    # and refused every account. The engine then healed nothing, every run, silently.
    # 🪤 Same shape as the trap in this function's own docstring: checking a value EARLY is right,
    # but only if what populates it ran earlier still. An "is it configured?" test that runs before
    # configuration is loaded does not report the config -- it reports its own ordering.
    # Fail-safe: Initialize-PimEmailControlsFromStore leaves the globals untouched when the store is
    # unreachable, so this can only ever ADD a sender, never clear one.
    # 🪤 ...BUT HYDRATE ONCE, NOT ONCE PER ROW. This guard is called INSIDE a per-admin loop
    # (Get-PimAdminTapState), so on a tenant with N admins it did N SQL round-trips to read the same
    # global mail configuration. Measured live 2026-09-12: /api/admin-tap timed out at 120s.
    # The sender is tenant-wide, so re-reading it per admin cannot change the answer -- it only
    # costs a round-trip each time.
    # 🔑 Still fail-safe and still ordered correctly: hydration happens on the FIRST call (the
    # original defect was that it never happened at all), and is skipped only once a sender is
    # actually populated. An unset sender re-reads every time, so a store that becomes reachable
    # mid-run is still picked up.
    if (((-not "$($global:PIM_MailSender)".Trim()) -or (-not "$($global:PIM_MailMode)".Trim())) -and (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue)) {
        # once per process (Initialize-PimEmailControlsFromStore remembers a successful read), so not once per admin row
        try { [void](Initialize-PimEmailControlsFromStore) } catch { }
    }
    # MAIL-1: an SMTP relay environment has no sender MAILBOX -- it is ready when its relay record is valid.
    $tapMode = if (Get-Command Get-PimMailMode -ErrorAction SilentlyContinue) { Get-PimMailMode } else { 'sharedMailbox' }
    if ($tapMode -eq 'none') { return @{ ok = $false; reason = 'mail is switched off for this environment (mail mode none) -- the TAP cannot be delivered' } }
    if ($tapMode -eq 'smtp') {
        $relay = Get-PimSmtpRelayConfig
        if (-not $relay.ok) { return @{ ok = $false; reason = 'the SMTP relay is not configured correctly: ' + (@($relay.errors.Values) -join ' ') } }
    }
    elseif (-not "$($global:PIM_MailSender)".Trim()) {
        return @{ ok = $false; reason = 'no notification sender is configured (PIM_MailSender) -- the tenant cannot send mail at all' }
    }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
        return @{ ok = $false; reason = 'the notification path (Send-PimNotifyMail) is not available in this runtime' }
    }
    # Everything the -WhatIf path CAN answer: kill switch, disabled feature,
    # allowlist, missing template. It renders but never sends.
    try {
        # 🪤 BUG-85 -- THE PROBE MUST CARRY EVERY TOKEN THE TEMPLATE USES, OR IT CRIES WOLF.
        # This token set was missing TapStartLocal / TapStartUtc / TapLifetimeMinutes, so each
        # readiness check rendered the real template with holes in it and warned
        #     [Mail] unknown token(s): TapStartLocal, TapStartUtc, TapLifetimeMinutes -- rendered empty.
        # Measured 2026-08-27: three admins produced three of those warnings during a run whose
        # ACTUAL TAP mails were complete and correct -- the real send at
        # PIM-EngineProviders.ps1:2450 passes all six. The warning named a live delivery defect
        # that did not exist, in the one mail where "valid until when?" is the whole point, and it
        # cost a full image-content investigation to disprove.
        # A diagnostic that reports a fault in the thing it is only pretending to do is worse than
        # no diagnostic. Keep this set in step with templates/mail/tap-delivery.mailtemplate.html.
        $probeTokens = @{
            UserPrincipalName = 'probe'; TapCode = ''; TapExpiresUtc = ''
            TapStartLocal = ''; TapStartUtc = ''; TapLifetimeMinutes = ''
        }
        $probe = Send-PimNotifyMail -Type 'tap-delivery' -Tokens $probeTokens -Recipient $Recipient -WhatIf
        $reason = "$($probe.reason)"
        if ($reason -and $reason -ne 'whatif') { return @{ ok = $false; reason = $reason } }
    } catch {
        return @{ ok = $false; reason = "mail pre-check failed: $($_.Exception.Message)" }
    }
    return @{ ok = $true; reason = '' }
}
