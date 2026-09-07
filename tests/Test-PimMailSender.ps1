#Requires -Version 5.1
<#
.SYNOPSIS
    IMP-06 / IMP-06b -- the mail-sender provisioning script, tested OFFLINE.

    WHY THIS SUITE EXISTS. `tools/setup/Initialize-PimMailSender.ps1` implements the IMP-06b
    decision (the ONBOARDING SPN drives Exchange; the engine SPN receives only SCOPED Mail.Send)
    and encodes every IMP-06c trap -- and until 2026-08-28 it had NO TESTS AT ALL. A provisioning
    script with no tests is exercised only against live infrastructure, one tenant at a time, by
    somebody watching; the traps it encodes were each paid for exactly once and nothing stopped
    them being un-encoded again.

    🔴 THE FAILURE THIS SCRIPT PREVENTS IS SILENT. With no sender configured the notify path
    RENDERS the mail and returns without sending, while account creation and TAP minting still
    report success. A mail-mute environment therefore looks completely healthy and the first
    symptom is a TAP that never arrives -- days later, blamed on the TAP provider. Every assertion
    below is ultimately about not shipping that state.

    HOW IT RUNS WITHOUT A TENANT. The script is a top-to-bottom provisioning run with mandatory
    parameters, so it CANNOT be dot-sourced -- doing so would try to provision. The two pure
    decision cores are therefore lifted out BY AST and defined in this session; everything else is
    asserted against the source text. No network, no tenant, no Graph, no Exchange.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root   = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimSourceScope.ps1')
$script = Join-Path $root 'tools\setup\Initialize-PimMailSender.ps1'
$src    = Get-Content -LiteralPath $script -Raw

Write-Host "=== IMP-06: mail sender provisioning (offline) ===" -ForegroundColor Cyan
Write-Host ("  (PowerShell {0})" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Lift the pure cores out by AST and define them here.
# 🔑 AST, not regex. A regex for "function X { ... }" has to guess where the body ends, and it
# guesses wrong the first time a nested brace or a here-string appears -- silently defining half a
# function, which then fails in a way that looks like the function is broken.
# ---------------------------------------------------------------------------
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$errs)
T 'the shipped script PARSES on this host' (-not ($errs -and $errs.Count))

function Get-PureFunctionText([string]$Name) {
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
    if (-not $fn -or -not @($fn).Count) { return '' }
    return @($fn)[0].Extent.Text
}
# 🪤 DOT-SOURCE AT SCRIPT SCOPE, NOT INSIDE A HELPER. The first version did the dot-sourcing inside
# Get-PureFunctionText, which defines the function in THAT FUNCTION'S scope -- it vanishes on
# return. Worse, the helper returned $true, so the two "is a liftable function" asserts PASSED
# while nothing had been defined, and the suite died on the first call instead. So these now assert
# the function is actually CALLABLE, which is the property that was being claimed all along.
$txtPlans  = Get-PureFunctionText 'Select-PimExchangeMailboxPlans'
$txtSender = Get-PureFunctionText 'Resolve-PimMailSenderAddress'
if ($txtPlans)  { . ([scriptblock]::Create($txtPlans)) }
if ($txtSender) { . ([scriptblock]::Create($txtSender)) }
T 'the Exchange-plan decision is a named function, and is CALLABLE once lifted' (
    $null -ne (Get-Command Select-PimExchangeMailboxPlans -ErrorAction SilentlyContinue))
T 'the sender-address decision is a named function, and is CALLABLE once lifted' (
    $null -ne (Get-Command Resolve-PimMailSenderAddress -ErrorAction SilentlyContinue))

# ===========================================================================
Write-Host "`n== [0] THE PRECONDITION: 'exchange = Enabled' is NOT a mailbox ==" -ForegroundColor Cyan
# ===========================================================================
# 🪤 EXCHANGE_S_FOUNDATION rides along with Entra P2 and reports exchange=Enabled while
# provisioning DIRECTORY OBJECTS ONLY. Measured on a real tenant: the org looked mail-capable,
# and New-Mailbox -Shared would still have failed. This is the assertion that keeps the script
# from being "simplified" back to trusting assignedPlans.
function New-Sku([string]$part, [string[]]$plans) {
    [pscustomobject]@{ skuPartNumber = $part; prepaidUnits = [pscustomobject]@{ enabled = 1 }
                       servicePlans = @($plans | ForEach-Object { [pscustomobject]@{ servicePlanName = $_ } }) }
}
$foundationOnly = @(New-Sku 'AAD_PREMIUM_P2' @('EXCHANGE_S_FOUNDATION','AAD_PREMIUM_P2'))
$realExchange   = @(New-Sku 'EXCHANGESTANDARD' @('EXCHANGE_S_STANDARD'))
T 'Foundation ALONE does NOT qualify (the whole trap, in one assert)' (
    @(Select-PimExchangeMailboxPlans -SubscribedSkus $foundationOnly).Count -eq 0)
T '  ...a real Exchange plan DOES qualify' (
    @(Select-PimExchangeMailboxPlans -SubscribedSkus $realExchange) -contains 'EXCHANGE_S_STANDARD')
# The mixed case is the realistic one -- P2 and Exchange side by side -- and Foundation must not
# be counted while the real plan is.
$mixed = @((New-Sku 'AAD_PREMIUM_P2' @('EXCHANGE_S_FOUNDATION','AAD_PREMIUM_P2')), (New-Sku 'EXCHANGESTANDARD' @('EXCHANGE_S_STANDARD')))
$mixedPlans = @(Select-PimExchangeMailboxPlans -SubscribedSkus $mixed)
T '  ...and in a MIXED tenant it reports the real plan and not Foundation' (
    $mixedPlans.Count -eq 1 -and $mixedPlans[0] -eq 'EXCHANGE_S_STANDARD')
T '  ...an empty tenant qualifies for nothing rather than throwing' (
    @(Select-PimExchangeMailboxPlans -SubscribedSkus @()).Count -eq 0)
# 🪤 A tenant with several Exchange-bearing SKUs must not report the same plan twice -- the value
# is rendered into the result JSON and read by a human deciding whether the tenant is ready.
$dupes = @((New-Sku 'A' @('EXCHANGE_S_ENTERPRISE')), (New-Sku 'B' @('EXCHANGE_S_ENTERPRISE')))
T '  ...and duplicate plans across SKUs collapse to one' (
    @(Select-PimExchangeMailboxPlans -SubscribedSkus $dupes).Count -eq 1)
# 🔒 The refusal must be FATAL, not a warning: continuing yields a mail-mute environment that
# reports success everywhere. Asserted on the source, because the pure core only decides.
T 'a missing Exchange plan is FATAL (Fail), never a warning' (
    $src -match "(?s)Add-Result 'precondition' 'FAILED'.{0,200}?Fail")
T '  ...and the failure explains the Foundation trap rather than just refusing' (
    $src -match 'EXCHANGE_S_FOUNDATION riding' -or $src -match 'DIRECTORY OBJECTS ONLY')

# ===========================================================================
Write-Host "`n== THE SENDER ADDRESS: a guessed domain is a mailbox nobody can receive from ==" -ForegroundColor Cyan
# ===========================================================================
function New-Org([object[]]$domains) { [pscustomobject]@{ verifiedDomains = $domains } }
$orgInitial = New-Org @(
    [pscustomobject]@{ name = 'contoso.com';            isInitial = $false }
    [pscustomobject]@{ name = 'contoso.onmicrosoft.com'; isInitial = $true  })
$r1 = Resolve-PimMailSenderAddress -Organization $orgInitial -MailboxName 'PIM-Engine' -MailDomain ''
T 'the INITIAL (onmicrosoft) domain is used, not the first verified one' ($r1.sender -eq 'PIM-Engine@contoso.onmicrosoft.com')
# 🔑 Why initial and not the custom domain: a freshly-onboarded tenant HAS no custom domain, and
# a verified one may not route mail yet. The initial domain always exists and always works.
T '  ...even though a custom domain is listed first' ($r1.domain -eq 'contoso.onmicrosoft.com' -and $r1.reason -eq '')
$r2 = Resolve-PimMailSenderAddress -Organization $orgInitial -MailboxName 'PIM-Engine' -MailDomain 'mail.contoso.com'
T '  ...and an explicit -MailDomain overrides it' ($r2.sender -eq 'PIM-Engine@mail.contoso.com')
$r3 = Resolve-PimMailSenderAddress -Organization $orgInitial -MailboxName 'Notify' -MailDomain ''
T '  ...the mailbox name is honoured' ($r3.sender -eq 'Notify@contoso.onmicrosoft.com')
# 🔒 THE REFUSAL. Inventing a domain produces an address that provisions cleanly and can never
# receive anything -- the mail-mute failure arrived at from the other direction.
$r4 = Resolve-PimMailSenderAddress -Organization (New-Org @([pscustomobject]@{ name = 'contoso.com'; isInitial = $false })) -MailboxName 'PIM-Engine' -MailDomain ''
T 'NO initial domain -> REFUSES rather than guessing one' ($r4.sender -eq '' -and $r4.reason -match 'could not resolve a mail domain')
$r5 = Resolve-PimMailSenderAddress -Organization $orgInitial -MailboxName '   ' -MailDomain ''
T '  ...and a blank mailbox name is refused too (not "@domain")' ($r5.sender -eq '' -and $r5.reason -ne '')
T '  ...whitespace around an explicit domain is trimmed, not embedded' (
    (Resolve-PimMailSenderAddress -Organization $orgInitial -MailboxName 'X' -MailDomain '  d.com  ').sender -eq 'X@d.com')
# The caller must ACT on the refusal -- a reason nobody reads is not a guard.
T 'the script FAILS on an unresolved sender rather than continuing' (
    $src -match '(?s)\$senderPlan\.reason.{0,60}?Fail')

# ===========================================================================
Write-Host "`n== IMP-06b: WHICH IDENTITY DOES THE WORK ==" -ForegroundColor Cyan
# ===========================================================================
# 🔒 The decision this script exists to implement: Exchange administration is done by the
# ONBOARDING SPN, never by the engine SPN. The obvious-looking alternative -- grant the engine
# Exchange.ManageAsApp + Exchange Administrator -- hands the LONG-LIVED RUNTIME identity
# tenant-wide Exchange administration in order to create one mailbox, a strictly BIGGER grant
# than the scoping this script exists to apply. Asserted so it cannot be "simplified" back.
T 'IMP-06b: Exchange is driven by the ONBOARDING SPN' ($src -match 'ONBOARDING SPN')
T '  ...and the engine SPN is never granted Exchange.ManageAsApp' (
    -not ($src -match "(?m)^\s*[^#]*Add-PimAppRole.*Exchange\.ManageAsApp"))
T '  ...nor the Exchange Administrator directory role' (
    -not ($src -match "(?m)^\s*[^#]*New-PimDirectoryRole.*Exchange Administrator"))
# 🔴 STEPS 2 AND 3 ARE INVERTED FROM THE FINDING, and the inversion is load-bearing: Exchange RBAC
# does not RESTRICT a tenant-wide Graph consent, it GRANTS scoped access in its own right, and a
# tenant-wide consent alongside it keeps winning. Proven both directions ~60 minutes apart.
T 'the tenant-wide Graph Mail.Send consent is REVOKED, not relied on' (
    $src -match 'ensure NO tenant-wide Graph Mail.Send' -or $src -match 'Mail.Send revocation')
T '  ...and the inversion is explained, not just performed' ($src -match 'INVERTED FROM IMP-06')
# SEC-13: a cert-only onboarding SPN must be able to run this at all.
T 'SEC-13: the onboarding credential may be a CERTIFICATE' ($src -match '\$AdminCertThumbprint')
T '  ...and both-or-neither is refused before anything is provisioned' (
    $src -match 'pass EITHER -AdminSecret OR -AdminCertThumbprint' -and $src -match 'one of -AdminSecret')

# ===========================================================================
Write-Host "`n== IMP-06c: the traps must stay ENCODED ==" -ForegroundColor Cyan
# ===========================================================================
# Each of these cost a live session once. An assertion is what stops them costing it twice.
# 🔴 `IsDehydrated=False` is NOT a readiness signal: Enable-OrganizationCustomization returns
# success immediately, the flag flips on the very next poll, and creates STILL fail as dehydrated.
# The only honest readiness test is to attempt the real operation and retry.
T 'dehydration is handled by RETRYING THE REAL OPERATION, not by reading a flag' (
    $src -match 'function Invoke-ExoWhenHydrated')
T '  ...and the script says why a flag check is not enough' (
    $src -match 'IsDehydrated' -and $src -match '(?i)not a readiness|still fail|attempt the real')
# 🔴 Graph appRoleAssignments are eventually consistent: the first live run granted Mail.Send, got
# a 2xx, and then FAILED ITS OWN verification because the assignment was not yet queryable. A
# single read-back after a write is a flaky gate.
T 'eventual consistency is POLLED, not read back once' ($src -match 'function Confirm-Eventually')
T '  ...and the scoped grant is confirmed through it' ($src -match "Confirm-Eventually -What 'scoped Mail.Send assignment'")
T '  ...as is the revocation (a revoke that did not take is worse than one never attempted)' (
    $src -match "Confirm-Eventually -What 'Mail.Send revocation'")
# 🔒 Application Access Policies could not be read back (404/400/500), and a security control that
# cannot be verified is not a control -- Exchange RBAC for Applications is used instead.
T 'Exchange RBAC for Applications is used (an AAP could not be read back)' (
    $src -match "Application Mail.Send" -and $src -match 'New-ManagementRoleAssignment')
T '  ...scoped to ONE mailbox via a management scope' ($src -match 'New-ManagementScope')

# ===========================================================================
Write-Host "`n== THE RESULT CONTRACT (how the orchestrator learns the sender) ==" -ForegroundColor Cyan
# ===========================================================================
# 🪤 Each onboarding step runs in its OWN process with stdout redirected to a log, so a return
# value cannot travel any other way -- the result FILE is the interface, not a convenience.
T 'the result carries the sender back to the orchestrator' ($src -match '\$result\.sender')
T '  ...and is written on the FAILURE path too, or a failed step reports nothing at all' (
    (Get-PimSourceFunctionBody -Text $src -Name 'Fail') -match 'Write-ResultFile')
T '  ...with ok=$false until every step has actually succeeded' ($src -match 'ok\s*=\s*\$false')

Write-Host ""
Write-Host ("==== mail sender test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
