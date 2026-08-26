#Requires -Version 5.1
<#
  OFFLINE tests for the Accounts & TAP surface -- BUG-66.

  WHAT IT COVERS AND WHY.
  An admin whose Temporary Access Pass has EXPIRED could never get another one: the AdminTap
  scope counts ANY temporaryAccessPassMethods entry as "this account has a TAP" and its Equal is
  hardcoded $true, so a dead pass classifies the account as satisfied. Measured live on the
  master tenant 2026-08-13 -- six consecutive runs reporting ok=True while minting nothing, and
  the admin with no route to a credential. Deleting the dead method by hand re-armed it.

  This suite pins the one-click recovery that replaces that manual step, and in particular the
  three properties that are easy to get wrong and impossible to see once wrong:

    * REFUSE BEFORE MINTING when the mail cannot be delivered. Minting first and failing to send
      leaves a LIVE credential nobody received and nobody knows exists -- strictly worse than the
      expired pass it replaced, which at least did nothing.
    * THE TAP CODE NEVER LEAVES THE MAIL. Not in the HTTP response, not in the audit record, not
      in the browser.
    * THE RECIPIENT COMES FROM THE ADMIN ROW, never from the request body -- otherwise this is
      "mail a credential for any admin to any address I name".

  No live tenant, no Graph, no browser: static assertions over the shipped server + GUI, plus the
  mail-readiness helper lifted out of the server by AST and exercised for real.
#>
param()
$ErrorActionPreference = 'Stop'

$here    = $PSScriptRoot
$solRoot = Split-Path -Parent $here
$mgrDir  = Join-Path $solRoot 'tools\pim-manager'
$srvPath = Join-Path $mgrDir 'Open-PimManager.ps1'
$htmlPath= Join-Path $mgrDir 'pim-manager.html'

$script:pass = 0; $script:fail = 0
function T { param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red } }

$srv  = Get-Content -LiteralPath $srvPath  -Raw
$html = Get-Content -LiteralPath $htmlPath -Raw

Write-Host "`n== 1. THE SURFACE EXISTS ==" -ForegroundColor Cyan
T 'server exposes GET /api/admin-tap (the live TAP read-out)'   ($srv -match "'/api/admin-tap'\s+-and\s+\`$method -eq 'GET'")
T 'server exposes POST /api/admin-tap/reset (the re-issue)'     ($srv -match "'/api/admin-tap/reset'\s+-and\s+\`$method -eq 'POST'")
T 'the state reader exists'                                     ($srv -match 'function Get-PimAdminTapState')
T 'the mail-readiness guard exists (shared, in PIM-Notify.ps1)' ((Get-Content -LiteralPath (Join-Path $solRoot 'engine/_shared/PIM-Notify.ps1') -Raw) -match 'function Test-PimTapMailReady')

# Isolate the reset route so ordering assertions below cannot be satisfied by text elsewhere.
$resetBlock = ''
$m = [regex]::Match($srv, "(?s)if \(\`$path -eq '/api/admin-tap/reset'.*?\n        \}\n")
if ($m.Success) { $resetBlock = $m.Value }
T 'the reset route block is isolatable for ordering checks' ([bool]$resetBlock) 'regex did not bound the route'

Write-Host "`n== 2. IT IS GATED, SERVER-SIDE ==" -ForegroundColor Cyan
# Hiding the button client-side is not enforcing anything -- the gate that counts is this one.
T 'reset requires at least Admin'          ($resetBlock -match "Test-PimManagerRoleAtLeast -Minimum 'Admin'")
T 'and refuses with 403, not a silent skip' ($resetBlock -match '-Status 403')
T 'the read endpoint reports whether the caller may reset (so the UI can disable, not guess)' `
    ($srv -match 'canReset\s*=\s*\(Test-PimManagerRoleAtLeast')

Write-Host "`n== 3. REFUSE BEFORE MINTING (the operator decision) ==" -ForegroundColor Cyan
# 🔴 ORDERING IS THE WHOLE POINT. A mail check that runs AFTER the POST cannot prevent the
# orphan credential it exists to prevent.
$iMail = $resetBlock.IndexOf('Test-PimTapMailReady')
$iMint = $resetBlock.IndexOf('-Method POST -Path "/users/$uid/authentication/temporaryAccessPassMethods"')
T 'the mail pre-check runs BEFORE the TAP is minted' (($iMail -ge 0) -and ($iMint -ge 0) -and ($iMail -lt $iMint)) `
    "mailIdx=$iMail mintIdx=$iMint"
T 'an undeliverable re-issue is REFUSED (409), not attempted' ($resetBlock -match '-Status 409')
T 'the refusal says nothing was changed'                      ($resetBlock -match 'Nothing was changed')
T 'the refusal is audited'                                    ($resetBlock -match "tap\.reset\.refused")

Write-Host "`n== 4. THE CODE NEVER LEAVES THE MAIL ==" -ForegroundColor Cyan
# A credential in an HTTP response is a credential in a proxy log, a screenshot and a session
# history. It goes to the recorded ManagerEmail and nowhere else.
$respBlock = ''
$rm = [regex]::Match($resetBlock, '(?s)Write-JsonResponse -Response \$resp -Status 200 -Body @\{.*?\n                \}')
if ($rm.Success) { $respBlock = $rm.Value }
T 'the 200 response body is isolatable' ([bool]$respBlock)
T 'the 200 response does NOT carry the TAP code' ($respBlock -notmatch 'temporaryAccessPass|TapCode|\$tap\.temporaryAccessPass')
$auditBlock = ''
$am = [regex]::Match($resetBlock, "(?s)Write-PimManagerAuditEvent -Action 'tap\.reset' .*?\n                \}")
if ($am.Success) { $auditBlock = $am.Value }
T 'the audit record is isolatable' ([bool]$auditBlock)
T 'the audit record does NOT carry the TAP code' ($auditBlock -notmatch 'temporaryAccessPass|TapCode')
T 'the GUI never renders the code either' ($html -notmatch 'temporaryAccessPass|\.tapCode|d\.tapCode')

Write-Host "`n== 5. THE ROW IS THE AUTHORITY, NOT THE REQUEST ==" -ForegroundColor Cyan
# Taking the recipient from the body would make this "mail a credential for any admin to any
# address I name". The row decides who may get a TAP and where it goes.
T 'the target is validated against the admin rows'   ($resetBlock -match 'Get-PimAdminTapState \| Where-Object')
T 'an unmanaged account is refused with 404'         ($resetBlock -match '-Status 404')
T 'the recipient is read from the ROW (managerEmail), not the body' `
    (($resetBlock -match '\$mgr\s*=\s*"\$\(\$row\.managerEmail\)"') -and ($resetBlock -notmatch '\$body\.(managerEmail|recipient|email)'))

Write-Host "`n== 6. DELETE-THEN-CREATE, BECAUSE ENTRA ALLOWS ONE TAP ==" -ForegroundColor Cyan
# This is exactly the manual step that recovered the master tenant.
$iDel = $resetBlock.IndexOf('-Method DELETE -Path "/users/$uid/authentication/temporaryAccessPassMethods/')
T 'the existing pass is DELETED first' ($iDel -ge 0)
T 'and the new one is created after it' (($iDel -ge 0) -and ($iMint -gt $iDel)) "delIdx=$iDel mintIdx=$iMint"
# -All is load-bearing (BUG-51): without it the response WRAPPER is returned and @(wrapper).Count
# is 1 even when the user has NO TAP -- which is how this whole family of bugs started.
T 'the TAP read passes -All (a wrapper counts as 1 and hides "no TAP")' ($resetBlock -match 'Invoke-PimGraph -All -Path "/users/\$uid/authentication/temporaryAccessPassMethods"')
T 'the state reader passes -All too' ($srv -match '(?s)function Get-PimAdminTapState.*?Invoke-PimGraph -All -Path "/users/\$uid/authentication/temporaryAccessPassMethods"')

Write-Host "`n== 7. THE MAIL GUARD, EXERCISED FOR REAL ==" -ForegroundColor Cyan
# Lifted by AST from engine/_shared/PIM-Notify.ps1, its home since 2026-08-20 -- it is SHARED with
# the engine's AdminTap provider, so one guard decides credential issuance on both paths.
$notifyPath = Join-Path $solRoot 'engine/_shared/PIM-Notify.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($notifyPath, [ref]$null, [ref]$null)
$fnAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                  $n.Name -eq 'Test-PimTapMailReady' }, $true) | Select-Object -First 1
if (-not $fnAst) { T 'Test-PimTapMailReady is liftable' $false 'not found' }
else {
    . ([scriptblock]::Create($fnAst.Extent.Text))
    $global:PIM_MailSender = 'sender@example.test'
    function global:Send-PimNotifyMail { param($Type,$Tokens,$Recipient,[switch]$WhatIf) @{ sent=$false; reason='whatif' } }

    $r1 = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'a deliverable recipient passes' ([bool]$r1.ok)

    $r2 = Test-PimTapMailReady -Recipient ''
    T 'no ManagerEmail on the row => refused' (-not $r2.ok)
    T '...and it says WHY (nowhere to deliver)' ($r2.reason -match 'ManagerEmail')

    # 🔴 THE TRAP THIS GUARD EXISTS FOR. In PIM-Notify.ps1 the -WhatIf early-return sits BEFORE
    # the 'no sender' check, so a naive -WhatIf probe returns reason='whatif' and looks healthy
    # on a tenant that CANNOT SEND MAIL AT ALL -- precisely the tenant BUG-66 is about. The fake
    # above reproduces that exact ordering: it returns 'whatif' regardless of the sender. The
    # guard must still refuse, because it checks the sender ITSELF.
    $saved = $global:PIM_MailSender
    $global:PIM_MailSender = ''
    $r3 = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'NO SENDER CONFIGURED => refused, even though -WhatIf reports "whatif"' (-not $r3.ok)
    T '...and it names the missing sender' ($r3.reason -match 'PIM_MailSender|notification sender')

    # 🔴 THE ORDERING DEFECT, MEASURED LIVE ON EFIF 2026-08-25. The guard checked the sender BEFORE
    # anything hydrated it from pim.Settings, so on a cold engine run -- and the scheduled tick Job
    # is ALWAYS cold -- it read an empty global and refused all six admins with "no notification
    # sender is configured", while the store held a perfectly good PIM-Engine@<tenant>. The sender
    # was never missing; it had not been READ yet. Send-PimNotifyMail hydrates, but that runs AFTER
    # this guard, so the guard was reporting its own ordering rather than the configuration.
    # The stub stands in for the store: sender absent until hydration runs, present afterwards.
    $global:PIM_MailSender = ''
    function global:Initialize-PimEmailControlsFromStore { $global:PIM_MailSender = 'PIM-Engine@stub.test'; return $true }
    $r3b = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'a sender that lives ONLY in the store is HYDRATED before judging (cold-run defect)' ([bool]$r3b.ok) "reason=$($r3b.reason)"
    Remove-Item 'Function:\Initialize-PimEmailControlsFromStore' -ErrorAction SilentlyContinue

    # 🔒 Fail-safe direction: an unreachable store must never invent a sender, so a hydrate that
    # cannot read anything still refuses. This is what stops the fix above from becoming a mint
    # on a tenant that genuinely cannot send.
    $global:PIM_MailSender = ''
    function global:Initialize-PimEmailControlsFromStore { return $false }
    $r3c = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T '...but an unreachable store still REFUSES (hydration must not invent a sender)' (-not $r3c.ok)
    Remove-Item 'Function:\Initialize-PimEmailControlsFromStore' -ErrorAction SilentlyContinue
    $global:PIM_MailSender = $saved

    # Everything -WhatIf CAN legitimately answer still has to be honoured.
    function global:Send-PimNotifyMail { param($Type,$Tokens,$Recipient,[switch]$WhatIf) @{ sent=$false; reason='email kill switch on' } }
    $r4 = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'the email kill switch => refused' (-not $r4.ok)
    T '...and the reason is passed through verbatim' ($r4.reason -match 'kill switch')

    function global:Send-PimNotifyMail { param($Type,$Tokens,$Recipient,[switch]$WhatIf) @{ sent=$false; reason="no template 'tap-delivery'" } }
    $r5 = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'a missing mail template => refused' (-not $r5.ok)

    function global:Send-PimNotifyMail { param($Type,$Tokens,$Recipient,[switch]$WhatIf) throw 'graph exploded' }
    $r6 = Test-PimTapMailReady -Recipient 'mgr@example.test'
    T 'a throwing notify path => refused, not an unhandled 500' (-not $r6.ok)
    T '...and the failure is reported, not swallowed' ($r6.reason -match 'pre-check failed')

    Remove-Item function:global:Send-PimNotifyMail -ErrorAction SilentlyContinue
}

Write-Host "`n== 8. THE GUI IS WIRED ==" -ForegroundColor Cyan
T 'the Accounts & TAP tab button exists'      ($html -match 'data-tab="accounts"')
T 'its panel exists'                          ($html -match 'id="accountsTab" class="tab-panel"')
T 'switchTab renders it'                      ($html -match "if \(name === 'accounts'\) renderAccounts\(\);")
T 'the renderer exists'                       ($html -match 'async function renderAccounts')
T 'the reset action exists'                   ($html -match 'async function resetAdminTap')
T 'the reset asks for confirmation first (it mints a sign-in credential)' ($html -match '(?s)async function resetAdminTap.*?confirm\(')
# "unknown" is not "none": offering a one-click write on a row we could not READ either
# double-issues or hides a dead pass.
T 'an unreadable row cannot be actioned'      ($html -match "a\.status === 'unknown'")
T 'a row whose mail cannot be delivered is disabled, with the reason shown' `
    (($html -match '!a\.mailReady') -and ($html -match 'a\.mailReason'))
T 'expired passes are surfaced as a badge count' ($html -match 'tapExpiredBadge')
# 🪤 A tab in the flat strip but in NO nav group is unreachable from the PRIMARY
# navigation -- the grouped menubar is what users actually click, and the flat strip
# is hidden. The tab looked fine in the markup and could not be opened.
T 'the tab is in a NAV_GROUP (or the grouped menubar cannot reach it)' ($html -match "items: \[[^\]]*'accounts'")


Write-Host "`n== 9. THE ENGINE PATH -- the scope now HEALS an expired pass (BUG-66 proper) ==" -ForegroundColor Cyan
# The button made the condition recoverable BY HAND. This is the half that makes the engine
# correct: AdminTap counted ANY pass as satisfied, so a dead one was never replaced.
$prov = Get-Content -LiteralPath (Join-Path $solRoot 'engine/_shared/PIM-EngineProviders.ps1') -Raw
$tapProv = ''
$pm = [regex]::Match($prov, '(?s)function New-PimAdminTapProvider \{.*?\n\}\n')
if ($pm.Success) { $tapProv = $pm.Value }
T 'the AdminTap provider is isolatable' ([bool]$tapProv)

T 'GetLive counts only a USABLE pass, not merely an existing one' ($tapProv -match '\$usable\s*=\s*@\(\$taps \| Where-Object \{ "\$\(\$_\.isUsable\)" -match')
# 🪤 The direction of the fail-safe is the whole design here, and it is the OPPOSITE of the
# usual one. Everywhere else in this codebase an unreadable probe means NOT current => re-run.
# Here that would mint a fresh credential on EVERY tick for as long as the read keeps failing.
T 'an UNREADABLE probe fails CLOSED (stays satisfied), so a broken read cannot mint in a loop' `
    ($tapProv -match '(?s)catch \{.*?\$live\.Add\(\[pscustomobject\]@\{ UserPrincipalName=\$upn \}\).*?fail-closed')

T 'ApplyCreate REFUSES before minting when the mail cannot be delivered' `
    ($tapProv -match 'REFUSING to issue a TAP that cannot be delivered')
T '...using the SHARED guard, not a second copy of the decision' ($tapProv -match 'Test-PimTapMailReady')
T '...and it returns without creating anything (one admin must not fail the scope)' `
    ($tapProv -match '(?s)REFUSING to issue a TAP.*?return \[pscustomobject\]@\{ pimApplied = \$false')
# 🔴 MEASURED LIVE ON EFIF, 2026-08-25. This assertion used to require `return $null` -- it pinned
# the DEFECT. The guard refused all six admins, printed "Nothing was changed" six times, and the run
# still summarised `applied=6 errors=0 ok=True`, because BUG-35a's convention treats anything that
# is not an explicit `pimApplied=$false` as applied -- and $null is "anything". Six dead accounts
# reporting a perfect green on a 15-minute job.
# 🪤 A refusal that reports SUCCESS is worse than having no guard: without the guard you get a bad
# credential you can see; with it you get a green you trust.
T 'REFUSAL IS NOT AN APPLY -- it signals pimApplied=$false so the run cannot report a false green' `
    ($tapProv -match '(?s)REFUSING to issue a TAP.*?pimApplied = \$false')
# 🪤 Strip COMMENT lines before this one. The first version of this assertion failed against the
# fixed code, because the comment explaining the defect contains the words `return $null` -- the
# test was reading the explanation of the bug as the bug. A source-scanning assertion has to look
# at CODE, or documenting a fix is what breaks its own test.
$tapProvCode = ($tapProv -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
T '...and the refusal never returns a bare $null (which the core counts as APPLIED)' `
    (-not ($tapProvCode -match '(?s)REFUSING to issue a TAP that cannot be delivered.{0,400}?return \$null'))
T '...and it carries the reason, so the skip line says WHY' `
    ($tapProv -match '(?s)REFUSING to issue a TAP.*?pimApplied = \$false; reason =')

# Entra allows exactly one TAP per user: without the delete, the POST would fail on any account
# that still holds the dead pass -- i.e. on exactly the accounts this fix exists to rescue.
$iDel = $tapProv.IndexOf('-Method DELETE -Path "/users/$uid/authentication/temporaryAccessPassMethods/')
$iPost = $tapProv.IndexOf('-Method POST -Path "/users/$uid/authentication/temporaryAccessPassMethods"')
T 'the dead pass is DELETED before the new one is created' (($iDel -ge 0) -and ($iPost -gt $iDel)) "del=$iDel post=$iPost"
# Ordering again: the refusal must precede the delete, or a tenant that cannot mail would still
# destroy the existing pass and then decline to replace it -- strictly worse than doing nothing.
$iRefuse = $tapProv.IndexOf('Test-PimTapMailReady')
T 'and the mail refusal comes BEFORE the delete (never destroy what you cannot replace)' `
    (($iRefuse -ge 0) -and ($iDel -gt $iRefuse)) "refuse=$iRefuse del=$iDel"

# The guard above answers "may we issue?". NOTHING answered "did it actually get there?" --
# Send-PimNotifyMail returns @{ sent; reason } and never THROWS for a refused send, so piping it
# to Out-Null made an allowlist miss / kill switch / Graph 4xx invisible AFTER the credential was
# already minted and the old pass already deleted. Same class of failure as the refusal guard,
# one step later, and it reported applied=1 / ok=True over it. Added 2026-08-21.
T 'the send RESULT is inspected, not discarded (Out-Null hid a failed delivery)' `
    ((-not $tapProv.Contains('-Recipient $mgr | Out-Null')) -and $tapProv.Contains('$mailRes = Send-PimNotifyMail'))
T '...and a mint whose mail did not go out is reported LOUDLY, naming the account' `
    ($tapProv -match 'a TAP WAS MINTED but the mail to')
# It must warn on the FAILURE branch, not unconditionally: $mailRes.sent -notmatch true.
T '...on the not-sent branch specifically (a warning on every mint would be noise, not a signal)' `
    ($tapProv -match '(?s)\$mailRes = Send-PimNotifyMail.*?mailRes\.sent.*?-notmatch.*?a TAP WAS MINTED')
# Ordering: the report can only be AFTER the send, or it is reporting on nothing.

Write-Host ("`n==== admin TAP re-issue (BUG-66): {0} passed, {1} failed ====" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
