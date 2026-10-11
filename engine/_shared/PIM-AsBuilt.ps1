#Requires -Version 5.1
<#
  PIM-AsBuilt.ps1 -- PIM REQUIREMENTS 100.61 (owner 2026-10-10, via Invardia; framework DOCS/REQUIREMENTS.md 8.12 replacement
  contract): the AS-BUILT document, rendered INSIDE the customer's environment.

  WHAT IT IS
    A plain, table-style A4 PDF that describes THIS installation as answers to the PIM Manager design configurator's questions
    (questions.json ids -- a stable contract) plus the environment facts: version, update ring, edition, MSP role, network mode,
    region, endpoints (100.56), admin model, reviews and alerting. Every value is READ from the installation; a question the
    installation cannot answer is LEFT OUT (listed by id at the end), never guessed.
    NEVER in the document: secrets (webhook URL, install key, salts, passwords), people, user names / UPNs / e-mail addresses,
    object ids. Lists of people are reduced to COUNTS before they reach the model, and every value passes one more filter
    (Test-PimAsBuiltSafeValue) that drops anything shaped like an address, a GUID or a credential.

  WHO RENDERS IT (one generator, two callers)
    * the hosted Manager:  GET /api/asbuilt/pdf (Admin+, audited) -- the "As-built document" card in Settings > Copy & tools.
    * the Container Apps job caj-pim-asbuilt (manual trigger; tools/pim-engine/asbuilt-job-entry.ps1): writes
      https://<PIM storage account>.blob.core.windows.net/asbuilt/<executionName>.pdf for Invardia support, which starts the
      job and reads that one blob with the customer's consent (tools/setup/Grant-PimSupportAccess.ps1). A lifecycle rule
      deletes the blob after 1 day (tools/setup/Deploy-PimAsBuiltJob.ps1).

  THE PDF LIBRARY
    PDFsharp + MigraDoc (MIT, empira Software GmbH), pinned in the image (tools/pim-manager/Dockerfile stage 'pdflib'),
    assemblies only -- no PowerShell module. Loaded with Add-Type -Path from $env:PIM_PDF_DLL_DIR (/opt/pdf). PDFsharp has
    no font resolver on Linux, so PIM supplies one (a small C# class compiled with Add-Type) that serves the DejaVu Sans TTF
    files the image carries in $env:PIM_PDF_FONT_DIR (/opt/pdf/fonts). Licences: tools/pim-manager/third-party/.

  PURE first (every model function is testable offline), then the PDF renderer (needs the library), then the deploy specs
  (job definition, the job's SQL view, the support grants) that tools/setup uses. Windows PowerShell 5.1 + pwsh 7. ASCII only.
#>
Set-StrictMode -Off

$script:PimAsBuiltSchema    = 'pim-manager-asbuilt/1'
$script:PimAsBuiltJobName   = 'caj-pim-asbuilt'
$script:PimAsBuiltContainer = 'asbuilt'
$script:PimAsBuiltView      = 'pim.vw_AsBuiltSettings'
$script:PimAsBuiltRoleName  = 'PIM Manager as-built runner'
# The ONLY two operations the Invardia Support app gets on the job: start it, read its executions (framework 8.12).
$script:PimAsBuiltRoleActions = @('Microsoft.App/jobs/start/action', 'Microsoft.App/jobs/executions/read')
$script:PimAsBuiltBlobReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'   # Storage Blob Data Reader (built-in)
$script:PimAsBuiltBlobWriterRole   = 'Storage Blob Data Contributor'          # the JOB's own identity, on the container only
# 100.61 fix (live 2026-10-11): the job runs as a USER-ASSIGNED identity in the PIM resource group. Its ARM properties.clientId
# IS the app id (the SID of its contained database user) and properties.principalId the object id -- both readable over ARM by
# the updater's Contributor, so the database user is made WITHOUT Graph (a system identity's app id needs Graph, which the
# updater's identity does not have: "the app id of caj-pim-asbuilt's identity could not be resolved" on every run).
$script:PimAsBuiltIdentityName = 'id-pim-asbuilt'
$script:PimAsBuiltMsiApi       = 'api-version=2023-01-31'

# ---------------------------------------------------------------------------------------------------------------------
# The pim.Settings rows the generator reads. The job's identity reads them through ONE view (Get-PimAsBuiltViewSql) that
# REDUCES the rows holding people or secrets in SQL, before they leave the database; the Manager reduces the same rows in
# PowerShell (ConvertTo-PimAsBuiltSettingValue). Either way the generator only ever sees the reduced shape.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimAsBuiltSettingNames = @(
    'FeatureGates', 'License', 'UpdateState', 'Scenario', 'PendingSecondApprover', 'GuardReleaseSecondPerson',
    'OperationalPolicy', 'AuditRetentionMonths', 'ConfigBackupRetentionDays', 'MailMode', 'ManagerUrl', 'AccessReviewRules',
    'Alerting', 'RfaSettings', 'ManagerAccess', 'BreakGlassAccounts', 'InvardiaInstallKey', 'AsBuiltInstallFacts'
)

# ---------------------------------------------------------------------------------------------------------------------
# The configurator questions (ids EXACTLY as in the PIM Manager configurator's questions.json, pimVersion 2.4.554) and the
# as-built source of each. read = the fact key Get-PimAsBuiltAnswers fills; '' = cannot be read from an installation
# (prospect-only: the design workshop answers it). Test-PimAsBuilt pins this list against questions.json when present.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimAsBuiltQuestions = @(
    # about
    @{ id = 'customerName';        section = 'about';      label = 'Organisation name';                 read = ''; source = 'none (the design workshop answers it)' }
    @{ id = 'customerShortName';   section = 'about';      label = 'Short name';                        read = ''; source = 'none' }
    @{ id = 'documentOwner';       section = 'about';      label = 'Prepared by';                       read = ''; source = 'none' }
    @{ id = 'approverName';        section = 'about';      label = 'Approver';                          read = ''; source = 'none' }
    @{ id = 'approverTitle';       section = 'about';      label = "Approver's role";                   read = ''; source = 'none' }
    @{ id = 'classification';      section = 'about';      label = 'Document classification';           read = ''; source = 'none' }
    @{ id = 'targetGoLive';        section = 'about';      label = 'Target go-live';                    read = ''; source = 'none' }
    # edition
    @{ id = 'edition';             section = 'edition';    label = 'Edition';                           read = 'edition';      source = 'the signed licence in pim.Settings License, checked for this tenant' }
    @{ id = 'adminAccountEstimate'; section = 'edition';   label = 'Admin accounts (estimate)';         read = ''; source = 'none' }
    @{ id = 'tenancy';             section = 'edition';    label = 'Tenancy';                           read = 'tenancy';      source = 'pim.Settings Scenario (the deployed scenario role)' }
    @{ id = 'managedTenantCount';  section = 'edition';    label = 'Managed tenants';                   read = ''; source = 'none' }
    @{ id = 'managingTenantName';  section = 'edition';    label = 'Managing tenant name';              read = ''; source = 'none' }
    @{ id = 'mspLink';             section = 'edition';    label = 'MSP link';                          read = ''; source = 'none' }
    @{ id = 'mspEnforced';         section = 'edition';    label = 'MSP baseline enforcement';          read = ''; source = 'none' }
    # hosting
    @{ id = 'region';              section = 'hosting';    label = 'Azure region';                      read = 'region';       source = 'recorded by the setup (Deploy-PimAsBuiltJob: the Container Apps environment location), else the environment DNS suffix' }
    @{ id = 'subscriptionModel';   section = 'hosting';    label = 'Subscription model';                read = ''; source = 'none' }
    @{ id = 'resourceGroup';       section = 'hosting';    label = 'Resource group';                    read = 'resourceGroup'; source = 'recorded by the setup (Deploy-PimAsBuiltJob)' }
    @{ id = 'sqlTier';             section = 'hosting';    label = 'SQL tier';                          read = 'sqlTier';      source = 'the store itself: DATABASEPROPERTYEX(ServiceObjective)' }
    @{ id = 'sqlBackup';           section = 'hosting';    label = 'SQL backup';                        read = ''; source = 'none' }
    # network
    @{ id = 'exposure';            section = 'network';    label = 'Exposure';                          read = 'exposure';     source = 'recorded by the setup (Deploy-PimAsBuiltJob: the Container Apps environment is internal or external)' }
    @{ id = 'denyPublicPolicy';    section = 'network';    label = 'Deny-public policy';                read = ''; source = 'none' }
    @{ id = 'signInScope';         section = 'network';    label = 'Sign-in scope';                     read = ''; source = 'none' }
    @{ id = 'managerCa';           section = 'network';    label = 'Conditional Access for the Manager'; read = ''; source = 'none' }
    @{ id = 'externalHardening';   section = 'network';    label = 'External hardening';                read = ''; source = 'none' }
    @{ id = 'ingressIps';          section = 'network';    label = 'Ingress IP allow-list';             read = ''; source = 'none' }
    @{ id = 'adminPath';           section = 'network';    label = 'Admin path';                        read = ''; source = 'none' }
    @{ id = 'hubSpoke';            section = 'network';    label = 'Hub and spoke';                     read = ''; source = 'none' }
    @{ id = 'vnetCidr';            section = 'network';    label = 'Virtual network range';             read = ''; source = 'none' }
    @{ id = 'acaSubnet';           section = 'network';    label = 'Container Apps subnet';             read = ''; source = 'none' }
    @{ id = 'peSubnet';            section = 'network';    label = 'Private endpoint subnet';           read = ''; source = 'none' }
    @{ id = 'hubCidr';             section = 'network';    label = 'Hub range';                         read = ''; source = 'none' }
    @{ id = 'dnsModel';            section = 'network';    label = 'DNS model';                         read = ''; source = 'none' }
    @{ id = 'clientDns';           section = 'network';    label = 'Client DNS';                        read = ''; source = 'none' }
    @{ id = 'egress';              section = 'network';    label = 'Egress';                            read = ''; source = 'none' }
    @{ id = 'customDomainInternal'; section = 'network';   label = 'Custom domain (internal)';          read = ''; source = 'none' }
    # workloads
    @{ id = 'workloads';           section = 'workloads';  label = 'Workloads';                         read = 'workloads';    source = 'the core engine (Entra roles, PIM for Groups) + the workload features switched on (pim.Settings FeatureGates)' }
    @{ id = 'azureWrite';          section = 'workloads';  label = 'Azure write rights';                read = ''; source = 'none' }
    @{ id = 'azureScopes';         section = 'workloads';  label = 'Azure scopes';                      read = ''; source = 'none' }
    @{ id = 'hybridPlacement';     section = 'workloads';  label = 'Hybrid worker placement';           read = ''; source = 'none' }
    @{ id = 'hybridDcReach';       section = 'workloads';  label = 'Domain controller reach';           read = ''; source = 'none' }
    @{ id = 'hybridCidr';          section = 'workloads';  label = 'Hybrid worker range';               read = ''; source = 'none' }
    @{ id = 'serverJit';           section = 'workloads';  label = 'Server just-in-time admin';         read = ''; source = 'none' }
    @{ id = 'protectedGroups';     section = 'workloads';  label = 'Protected groups';                  read = ''; source = 'none' }
    # admin
    @{ id = 'breakGlassCount';     section = 'admin';      label = 'Break-glass accounts';              read = 'breakGlassCount';  source = 'pim.Settings BreakGlassAccounts (count only)' }
    @{ id = 'superAdminCount';     section = 'admin';      label = 'SuperAdmins';                       read = 'superAdminCount';  source = 'pim.Settings ManagerAccess (count of role SuperAdmin only)' }
    @{ id = 'adminPrefix';         section = 'admin';      label = 'Admin account prefix';              read = ''; source = 'none' }
    @{ id = 'delegatedAdmin';      section = 'admin';      label = 'Delegated administration';          read = 'delegatedAdmin';   source = "feature 'access.delegated' (pim.Settings FeatureGates)" }
    @{ id = 'secondApprover';      section = 'admin';      label = 'Second approver for staged changes'; read = 'secondApprover';  source = 'pim.Settings PendingSecondApprover (off when not set)' }
    @{ id = 'makerChecker';        section = 'admin';      label = 'Maker / checker';                   read = 'makerChecker';     source = "feature 'makerchecker' (pim.Settings FeatureGates)" }
    @{ id = 'guardReleaseSecondPerson'; section = 'admin'; label = 'Guard release needs a second person'; read = 'guardRelease';   source = 'pim.Settings GuardReleaseSecondPerson (off when not set)' }
    @{ id = 'activationPolicy';    section = 'admin';      label = 'Activation policy';                 read = ''; source = 'none' }
    @{ id = 'maxActivationHours';  section = 'admin';      label = 'Longest activation (hours)';        read = 'maxActivationHours'; source = 'pim.Settings OperationalPolicy expiry.maxActivationDuration (product default P1D when not set)' }
    @{ id = 'authContext';         section = 'admin';      label = 'Authentication context';            read = ''; source = 'none' }
    @{ id = 'tapDelivery';         section = 'admin';      label = 'TAP delivery';                      read = ''; source = 'none' }
    @{ id = 'accountDisable';      section = 'admin';      label = 'Account disable';                   read = ''; source = 'none' }
    @{ id = 'reconcileStart';      section = 'admin';      label = 'Reconcile start';                   read = ''; source = 'none' }
    # reviews
    @{ id = 'accessReviews';       section = 'reviews';    label = 'Access reviews';                    read = 'accessReviews';    source = "feature 'reviews.campaigns' + pim.Settings AccessReviewRules default.enabled" }
    @{ id = 'reviewCadenceDays';   section = 'reviews';    label = 'Review cadence (days)';             read = 'reviewCadenceDays'; source = 'pim.Settings AccessReviewRules default.cadenceDays' }
    @{ id = 'reviewUndecided';     section = 'reviews';    label = 'Undecided reviews';                 read = 'reviewUndecided';  source = 'pim.Settings AccessReviewRules default.undecided' }
    @{ id = 'consultantReview';    section = 'reviews';    label = 'Consultant review';                 read = 'consultantReview'; source = "feature 'consultants.review' (pim.Settings FeatureGates)" }
    @{ id = 'rfa';                 section = 'reviews';    label = 'Request for authorization portal';  read = 'rfa';              source = "feature 'rfa.portal' (pim.Settings FeatureGates)" }
    @{ id = 'rfaPlacement';        section = 'reviews';    label = 'RFA placement';                     read = ''; source = 'none' }
    @{ id = 'rfaSubnet';           section = 'reviews';    label = 'RFA subnet';                        read = ''; source = 'none' }
    @{ id = 'rfaApi';              section = 'reviews';    label = 'Access request API';                read = 'rfaApi';           source = "feature 'api.broker' (pim.Settings FeatureGates)" }
    @{ id = 'rfaApiIps';           section = 'reviews';    label = 'API IP allow-list';                 read = ''; source = 'none' }
    @{ id = 'activator';           section = 'reviews';    label = 'PIM Activator';                     read = ''; source = 'none' }
    # alerting
    @{ id = 'mailMode';            section = 'alerting';   label = 'Mail mode';                         read = 'mailMode';         source = 'pim.Settings MailMode' }
    @{ id = 'alertRecipients';     section = 'alerting';   label = 'Alert recipients';                  read = 'alertRecipients';  source = 'pim.Settings Alerting recipients (count only)' }
    @{ id = 'webhook';             section = 'alerting';   label = 'Webhook';                           read = 'webhook';          source = 'pim.Settings Alerting webhookKind (the URL is never read)' }
    # operations
    @{ id = 'updateRing';          section = 'operations'; label = 'Update ring';                       read = 'updateRing';       source = 'PIM_UPDATE_RING, else pim.Settings UpdateState (configuredRing / ring)' }
    @{ id = 'updateWindow';        section = 'operations'; label = 'Update window';                     read = ''; source = 'none' }
    @{ id = 'updateHold';          section = 'operations'; label = 'Update held';                       read = 'updateHold';       source = 'PIM_UPDATE_HOLD, else pim.Settings UpdateState.hold' }
    @{ id = 'telemetry';           section = 'operations'; label = 'Telemetry';                         read = 'telemetry';        source = "feature 'telemetry.uplink' + whether an install key is present (never the key)" }
    @{ id = 'licenceAutoRequest';  section = 'operations'; label = 'Request the licence automatically'; read = 'licenceAutoRequest'; source = "feature 'licence.autoRequest' (pim.Settings FeatureGates)" }
    @{ id = 'supportAccess';       section = 'operations'; label = 'Support access';                    read = ''; source = 'none' }
    @{ id = 'supportCaLock';       section = 'operations'; label = 'Support Conditional Access lock';   read = ''; source = 'none' }
    @{ id = 'auditRetention';      section = 'operations'; label = 'Audit retention';                   read = 'auditRetention';   source = 'pim.Settings AuditRetentionMonths (empty or 0 = forever)' }
    @{ id = 'auditRetentionMonths'; section = 'operations'; label = 'Audit retention (months)';         read = 'auditRetentionMonths'; source = 'pim.Settings AuditRetentionMonths' }
    @{ id = 'configBackupRetentionDays'; section = 'operations'; label = 'Configuration backup retention (days)'; read = 'configBackupRetentionDays'; source = 'pim.Settings ConfigBackupRetentionDays (product default 90 when not set)' }
    @{ id = 'logAnalyticsRetentionDays'; section = 'operations'; label = 'Log Analytics retention (days)'; read = ''; source = 'none' }
    @{ id = 'sqlAuditing';         section = 'operations'; label = 'SQL auditing';                      read = ''; source = 'none' }
    @{ id = 'siem';                section = 'operations'; label = 'SIEM';                              read = ''; source = 'none' }
    @{ id = 'restoreDrill';        section = 'operations'; label = 'Restore drill';                     read = ''; source = 'none' }
)

$script:PimAsBuiltSectionTitles = [ordered]@{
    about = 'About this design'; edition = 'Edition and tenancy'; hosting = 'Hosting'; network = 'Network'; workloads = 'Workloads'
    admin = 'Administration model'; reviews = 'Reviews and access requests'; alerting = 'Alerting'; operations = 'Operations'
}

# ---------------------------------------------------------------------------------------------------------------------
# PURE helpers
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAsBuiltQuestionCatalog { return @($script:PimAsBuiltQuestions) }
function Get-PimAsBuiltSettingNames { return @($script:PimAsBuiltSettingNames) }
function Get-PimAsBuiltJobName { return $script:PimAsBuiltJobName }
function Get-PimAsBuiltContainerName { return $script:PimAsBuiltContainer }
function Get-PimAsBuiltIdentityName { return $script:PimAsBuiltIdentityName }
function Get-PimAsBuiltIdentityResourceId {
    <# PURE. The ARM id of the job's user-assigned identity id-pim-asbuilt (in the PIM resource group). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$Name = $script:PimAsBuiltIdentityName)
    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name"
}
function Get-PimAsBuiltJobIdentity {
    <#
      PURE. Which identity a caj-pim-asbuilt ARM object (GET) runs as: @{ kind = user | system | none; principalId; clientId;
      resourceId }. 'user' = id-pim-asbuilt is attached (principalId / clientId from identity.userAssignedIdentities);
      'system' = only the former system-assigned identity (an install from before the fix -- the converge switches it).
    #>
    param($Job, [string]$Name = $script:PimAsBuiltIdentityName)
    $out = @{ kind = 'none'; principalId = ''; clientId = ''; resourceId = '' }
    if (-not $Job -or -not $Job.identity) { return $out }
    $ua = $Job.identity.userAssignedIdentities
    if ($ua) {
        $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $keys) {
            if ("$k" -match ('(?i)/userAssignedIdentities/' + [regex]::Escape($Name) + '$')) {
                $v = if ($ua -is [System.Collections.IDictionary]) { $ua[$k] } else { $ua.$k }
                $out.kind = 'user'; $out.resourceId = "$k"; $out.principalId = "$($v.principalId)".Trim(); $out.clientId = "$($v.clientId)".Trim()
                return $out
            }
        }
    }
    if ("$($Job.identity.principalId)".Trim() -and "$($Job.identity.type)" -match '(?i)SystemAssigned') { $out.kind = 'system'; $out.principalId = "$($Job.identity.principalId)".Trim() }
    return $out
}

function Get-PimAsBuiltField {
    # PURE. A property of a PSCustomObject or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertFrom-PimAsBuiltJson {
    # PURE. A stored value -> object: JSON text is parsed (twice at most: a value stored as a JSON string of JSON), anything else as is.
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        $t = "$v".Trim()
        # An array stays an array (an empty or one-element list is still a list: ConvertFrom-Json would unroll it).
        # Windows PowerShell 5.1 writes the parsed array as ONE object, pwsh 7 writes its elements: piping through
        # ForEach-Object flattens both to the elements.
        if ($t.StartsWith('[')) { try { $v = @(ConvertFrom-Json -InputObject $t -ErrorAction Stop | ForEach-Object { $_ }); return , $v } catch { break } }
        if ($t.StartsWith('{') -or $t.StartsWith('"')) { try { $v = ConvertFrom-Json -InputObject $t -ErrorAction Stop } catch { break } } else { break }
    }
    return $v
}

function Test-PimAsBuiltSafeValue {
    <#
      PURE. The last filter before a value enters the document: $false for anything that LOOKS like a person or a secret --
      an e-mail address / UPN (x@y), a GUID (object / tenant / app id), a JWT, a key / SAS / connection string, a PEM block,
      a URL with a query string or credentials, or a long run of base64. Such a value is dropped (the question is then
      listed as not readable), never printed.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    $s = "$Value"
    if ($s -match '[^\s@]+@[^\s@]+') { return $false }
    if ($s -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b') { return $false }
    if ($s -match '\beyJ[A-Za-z0-9_-]{10,}\.') { return $false }
    if ($s -match '(?i)(AccountKey=|SharedAccessKey|[?&]sig=|[?&]sv=|password|secret|-----BEGIN|Bearer\s)') { return $false }
    if ($s -match '(?i)^https?://[^/\s]*@') { return $false }
    if ($s -match '(?i)^https?://[^\s]*\?') { return $false }
    if ($s -match '[A-Za-z0-9+/=_-]{48,}') { return $false }
    if ($s -match '\binv-[A-Za-z0-9_-]{20,}') { return $false }
    return $true
}

function ConvertTo-PimAsBuiltSettingValue {
    <#
      PURE. A FULL pim.Settings value (as the Manager reads it) -> the REDUCED shape the generator consumes -- the same shape
      the job's view returns (Get-PimAsBuiltViewSql), so the two callers cannot disagree. Rows that hold people or secrets
      are reduced to counts / kinds / booleans; an already-reduced value passes through unchanged.
        ManagerAccess            -> { superAdminCount }
        BreakGlassAccounts       -> { count }
        Alerting                 -> { recipientCount; webhookKind; webhookSet }      (never the URL, never an address)
        RfaSettings              -> { portalUrl }                                   (never the salt, the store or app ids)
        GuardReleaseSecondPerson -> { enabled }                                     (never who set it)
        AccessReviewRules        -> { enabled; cadenceDays; undecided }             (never the reviewers)
        InvardiaInstallKey       -> { present }                                     (never the key)
      Every other name: the value as stored.
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Value)
    $v = ConvertFrom-PimAsBuiltJson $Value
    if ($null -eq $v) { return $null }
    switch ($Name) {
        'ManagerAccess' {
            if ($null -ne (Get-PimAsBuiltField $v 'superAdminCount')) { return [pscustomobject]@{ superAdminCount = [int](Get-PimAsBuiltField $v 'superAdminCount') } }
            $list = if ($v -is [System.Array]) { @($v) } elseif ($null -ne (Get-PimAsBuiltField $v 'managerAccess')) { @(Get-PimAsBuiltField $v 'managerAccess') } else { @() }
            $n = @($list | Where-Object { $_ -and "$(Get-PimAsBuiltField $_ 'role')".Trim() -ieq 'SuperAdmin' }).Count
            return [pscustomobject]@{ superAdminCount = [int]$n }
        }
        'BreakGlassAccounts' {
            if (($v -isnot [System.Array]) -and $null -ne (Get-PimAsBuiltField $v 'count')) { return [pscustomobject]@{ count = [int](Get-PimAsBuiltField $v 'count') } }
            $n = @(@($v) | Where-Object { "$_".Trim() }).Count
            return [pscustomobject]@{ count = [int]$n }
        }
        'Alerting' {
            if ($null -ne (Get-PimAsBuiltField $v 'recipientCount')) {
                return [pscustomobject]@{ recipientCount = [int](Get-PimAsBuiltField $v 'recipientCount'); webhookKind = "$(Get-PimAsBuiltField $v 'webhookKind')".Trim(); webhookSet = [bool](Get-PimAsBuiltField $v 'webhookSet') }
            }
            $r = @(@(Get-PimAsBuiltField $v 'recipients') | Where-Object { "$_".Trim() }).Count
            return [pscustomobject]@{ recipientCount = [int]$r; webhookKind = "$(Get-PimAsBuiltField $v 'webhookKind')".Trim(); webhookSet = [bool]("$(Get-PimAsBuiltField $v 'webhookUrl')".Trim()) }
        }
        'RfaSettings' { return [pscustomobject]@{ portalUrl = "$(Get-PimAsBuiltField $v 'portalUrl')".Trim() } }
        'GuardReleaseSecondPerson' {
            $e = Get-PimAsBuiltField $v 'enabled'; if ($null -eq $e -and ($v -is [bool])) { $e = $v }
            return [pscustomobject]@{ enabled = ("$e".Trim().ToLowerInvariant() -in @('true', '1')) }
        }
        'AccessReviewRules' {
            $d = Get-PimAsBuiltField $v 'default'; if ($null -eq $d) { $d = $v }
            $en = Get-PimAsBuiltField $d 'enabled'; $cd = Get-PimAsBuiltField $d 'cadenceDays'; $un = Get-PimAsBuiltField $d 'undecided'
            $o = [ordered]@{}
            if ($null -ne $en) { $o['enabled'] = ("$en".Trim().ToLowerInvariant() -in @('true', '1')) }
            $n = 0; if ($null -ne $cd -and [int]::TryParse("$cd", [ref]$n) -and $n -gt 0) { $o['cadenceDays'] = $n }
            if ("$un".Trim().ToLowerInvariant() -in @('keep', 'remove')) { $o['undecided'] = "$un".Trim().ToLowerInvariant() }
            return [pscustomobject]$o
        }
        'InvardiaInstallKey' {
            if (($v -isnot [string]) -and $null -ne (Get-PimAsBuiltField $v 'present')) { return [pscustomobject]@{ present = [bool](Get-PimAsBuiltField $v 'present') } }
            return [pscustomobject]@{ present = ("$v".Trim() -match '^inv-[A-Za-z0-9_-]{20,100}$') }
        }
        default { return $v }
    }
}

function ConvertTo-PimAsBuiltHours {
    # PURE. An ISO-8601 duration (PT8H, P1D, PT90M, P1DT4H) -> whole hours, or $null.
    param([AllowNull()][string]$Duration)
    $d = "$Duration".Trim().ToUpperInvariant()
    if ($d -notmatch '^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$' -or $d -eq 'P' -or $d -eq 'PT') { return $null }
    $h = 0
    if ($Matches[1]) { $h += 24 * [int]$Matches[1] }
    if ($Matches[2]) { $h += [int]$Matches[2] }
    if ($Matches[3]) { $h += [int][Math]::Ceiling([int]$Matches[3] / 60.0) }
    if ($h -le 0) { return $null }
    return $h
}

function Get-PimAsBuiltRegionFromDnsSuffix {
    # PURE. A Container Apps environment DNS suffix (<name>.<region>.azurecontainerapps.io) -> the region, or ''.
    param([AllowNull()][string]$DnsSuffix)
    $s = "$DnsSuffix".Trim().ToLowerInvariant()
    if ($s -match '\.([a-z][a-z0-9]{2,30})\.azurecontainerapps\.io$') { return $Matches[1] }
    return ''
}

function Get-PimAsBuiltEdition {
    <#
      PURE. The configurator's edition value for THIS tenant: community (no Pro licence here) | pro-msp (sku Pro-MSP) |
      pro-business (a signed limits object) | pro-enterprise (Pro without limits) | pro-trial (a trial sku). '' = unknown.
    #>
    param([AllowNull()][object]$License, [AllowNull()][object]$ProHere)
    if ($null -eq $ProHere) { return '' }
    if (-not [bool]$ProHere) { return 'community' }
    $sku = "$(Get-PimAsBuiltField $License 'Sku')".Trim()
    if ($sku -match '(?i)trial') { return 'pro-trial' }
    if ($sku -match '(?i)msp') { return 'pro-msp' }
    if ($null -ne (Get-PimAsBuiltField $License 'Limits')) { return 'pro-business' }
    return 'pro-enterprise'
}

function Get-PimAsBuiltAnswers {
    <#
      PURE. -Facts (Read-PimAsBuiltFacts, or a test's hashtable) -> [ordered] question id -> @{ value; source }, ONLY for the
      questions the installation answered. Values use the configurator's option values (so the answers drop straight into
      the design templates); a fact that is $null / '' is left out.
    #>
    param([Parameter(Mandatory)][object]$Facts)
    $f = $Facts
    $out = [ordered]@{}
    $yn = { param($b) if ($null -eq $b) { $null } elseif ([bool]$b) { 'yes' } else { 'no' } }
    foreach ($q in $script:PimAsBuiltQuestions) {
        if (-not $q.read) { continue }
        $val = $null
        switch ($q.read) {
            'edition'            { $val = "$(Get-PimAsBuiltField $f 'edition')" }
            'tenancy'            { $val = "$(Get-PimAsBuiltField $f 'tenancy')" }
            'region'             { $val = "$(Get-PimAsBuiltField $f 'region')" }
            'resourceGroup'      { $val = "$(Get-PimAsBuiltField $f 'resourceGroup')" }
            'sqlTier'            { $val = "$(Get-PimAsBuiltField $f 'sqlTier')" }
            'exposure'           { $val = "$(Get-PimAsBuiltField $f 'exposure')" }
            'workloads'          { $w = @(Get-PimAsBuiltField $f 'workloads' | Where-Object { "$_".Trim() }); if ($w.Count) { $val = ($w -join ', ') } }
            'breakGlassCount'    { $val = Get-PimAsBuiltField $f 'breakGlassCount' }
            'superAdminCount'    { $val = Get-PimAsBuiltField $f 'superAdminCount' }
            'delegatedAdmin'     { $val = & $yn (Get-PimAsBuiltField $f 'delegatedAdmin') }
            'secondApprover'     { $val = "$(Get-PimAsBuiltField $f 'secondApprover')" }
            'makerChecker'       { $val = & $yn (Get-PimAsBuiltField $f 'makerChecker') }
            'guardRelease'       { $val = & $yn (Get-PimAsBuiltField $f 'guardReleaseSecondPerson') }
            'maxActivationHours' { $val = Get-PimAsBuiltField $f 'maxActivationHours' }
            'accessReviews'      { $val = & $yn (Get-PimAsBuiltField $f 'accessReviews') }
            'reviewCadenceDays'  { $val = Get-PimAsBuiltField $f 'reviewCadenceDays' }
            'reviewUndecided'    { $val = "$(Get-PimAsBuiltField $f 'reviewUndecided')" }
            'consultantReview'   { $val = & $yn (Get-PimAsBuiltField $f 'consultantReview') }
            'rfa'                { $val = & $yn (Get-PimAsBuiltField $f 'rfa') }
            'rfaApi'             { $val = & $yn (Get-PimAsBuiltField $f 'rfaApi') }
            'mailMode'           { $val = "$(Get-PimAsBuiltField $f 'mailMode')" }
            'alertRecipients'    { $n = Get-PimAsBuiltField $f 'alertRecipientCount'; if ($null -ne $n) { $val = if ([int]$n -eq 1) { '1 recipient' } else { "$([int]$n) recipients" } } }
            'webhook'            { $val = "$(Get-PimAsBuiltField $f 'webhook')" }
            'updateRing'         { $r = Get-PimAsBuiltField $f 'updateRing'; if ($null -ne $r -and "$r" -ne '') { $val = "$r" } }
            'updateHold'         { $val = & $yn (Get-PimAsBuiltField $f 'updateHold') }
            'telemetry'          { $val = "$(Get-PimAsBuiltField $f 'telemetry')" }
            'licenceAutoRequest' { $val = & $yn (Get-PimAsBuiltField $f 'licenceAutoRequest') }
            'auditRetention'     { $val = "$(Get-PimAsBuiltField $f 'auditRetention')" }
            'auditRetentionMonths' { $val = Get-PimAsBuiltField $f 'auditRetentionMonths' }
            'configBackupRetentionDays' { $val = Get-PimAsBuiltField $f 'configBackupRetentionDays' }
        }
        if ($null -eq $val -or "$val".Trim() -eq '') { continue }
        if (-not (Test-PimAsBuiltSafeValue $val)) { continue }
        $out[$q.id] = @{ value = "$val".Trim(); source = $q.source; isDefault = (@(Get-PimAsBuiltField $f 'defaults') -contains $q.id) }
    }
    return $out
}

function New-PimAsBuiltModel {
    <#
      PURE. -Facts -> the document model the PDF renders (and GET /api/asbuilt returns):
        { schema; product; generatedUtc; generatedBy; facts = @( @{ name; value } ); endpoints = @( @{ kind; label; url } );
          sections = @( @{ id; title; rows = @( @{ id; label; value; source } ) } ); omitted = @( question ids ) }
      Nothing that fails Test-PimAsBuiltSafeValue is kept.
    #>
    param([Parameter(Mandatory)][object]$Facts, [datetime]$NowUtc = [datetime]::UtcNow, [ValidateSet('manager', 'job')][string]$GeneratedBy = 'manager')
    $f = $Facts
    $ans = Get-PimAsBuiltAnswers -Facts $f
    $facts = New-Object System.Collections.Generic.List[object]
    $addFact = { param($n, $v) if ($null -ne $v -and "$v".Trim() -ne '' -and (Test-PimAsBuiltSafeValue $v)) { [void]$facts.Add([ordered]@{ name = $n; value = "$v".Trim() }) } }
    & $addFact 'Product' 'PIM Manager'
    & $addFact 'Version' (Get-PimAsBuiltField $f 'version')
    $ring = Get-PimAsBuiltField $f 'updateRing'; if ($null -ne $ring -and "$ring" -ne '') { & $addFact 'Update ring' "ring $ring" }
    $ed = "$(Get-PimAsBuiltField $f 'edition')"
    if ($ed) {
        $edText = switch ($ed) { 'community' { 'Community' } 'pro-business' { 'Pro Business' } 'pro-enterprise' { 'Pro Enterprise' } 'pro-msp' { 'Pro MSP' } 'pro-trial' { 'Pro (trial)' } default { $ed } }
        & $addFact 'Edition' $edText
    }
    $ten = "$(Get-PimAsBuiltField $f 'tenancy')"
    if ($ten) { & $addFact 'MSP role' $(switch ($ten) { 'managing' { 'managing tenant' } 'managed' { 'managed tenant' } default { 'single tenant (no MSP role)' + $(if (@(Get-PimAsBuiltField $f 'defaults') -contains 'tenancy') { ' (default)' } else { '' }) } }) }
    $exp = "$(Get-PimAsBuiltField $f 'exposure')"
    if ($exp) { & $addFact 'Network mode' $(if ($exp -eq 'internal') { 'internal (private network)' } else { 'external (public, signed-in only)' }) }
    & $addFact 'Azure region' (Get-PimAsBuiltField $f 'region')
    & $addFact 'SQL tier' (Get-PimAsBuiltField $f 'sqlTier')
    # admin model, reviews, alerting -- one line each, from the same facts as the answers
    $adm = @()
    $bg = Get-PimAsBuiltField $f 'breakGlassCount'; if ($null -ne $bg) { $adm += "$bg break-glass account(s)" }
    $sa = Get-PimAsBuiltField $f 'superAdminCount'; if ($null -ne $sa) { $adm += "$sa SuperAdmin(s)" }
    $dfl = @(Get-PimAsBuiltField $f 'defaults'); $dm = { param($id) if ($dfl -contains $id) { ' (default)' } else { '' } }
    $sp = "$(Get-PimAsBuiltField $f 'secondApprover')"; if ($sp) { $adm += "second approver: $sp$(& $dm 'secondApprover')" }
    $mc = Get-PimAsBuiltField $f 'makerChecker'; if ($null -ne $mc) { $adm += "maker / checker: $(if ([bool]$mc) { 'on' } else { 'off' })" }
    $mx = Get-PimAsBuiltField $f 'maxActivationHours'; if ($null -ne $mx) { $adm += "longest activation $mx h$(& $dm 'maxActivationHours')" }
    if ($adm.Count) { & $addFact 'Admin model' ($adm -join '; ') }
    $rv = @()
    $ar = Get-PimAsBuiltField $f 'accessReviews'; if ($null -ne $ar) { $rv += "access reviews: $(if ([bool]$ar) { 'on' } else { 'off' })" }
    $rc = Get-PimAsBuiltField $f 'reviewCadenceDays'; if ($null -ne $rc -and [bool]$ar) { $rv += "every $rc days" }
    $cr = Get-PimAsBuiltField $f 'consultantReview'; if ($null -ne $cr) { $rv += "consultant review: $(if ([bool]$cr) { 'on' } else { 'off' })" }
    if ($rv.Count) { & $addFact 'Reviews' ($rv -join '; ') }
    $al = @()
    $mm = "$(Get-PimAsBuiltField $f 'mailMode')"; if ($mm) { $al += "mail: $mm" }
    $rn = Get-PimAsBuiltField $f 'alertRecipientCount'; if ($null -ne $rn) { $al += "$rn alert recipient(s)" }
    $wh = "$(Get-PimAsBuiltField $f 'webhook')"; if ($wh) { $al += "webhook: $wh" }
    if ($al.Count) { & $addFact 'Alerting' ($al -join '; ') }

    $eps = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-PimAsBuiltField $f 'endpoints')) {
        if (-not $e) { continue }
        $u = "$(Get-PimAsBuiltField $e 'url')".Trim(); $k = "$(Get-PimAsBuiltField $e 'kind')".Trim()
        if (-not $u -or -not $k -or $u -notmatch '^https://' -or -not (Test-PimAsBuiltSafeValue $u)) { continue }
        $lab = "$(Get-PimAsBuiltField $e 'label')".Trim(); if (-not $lab) { $lab = $k }
        [void]$eps.Add([ordered]@{ kind = $k; label = $lab; url = $u })
    }

    $secs = New-Object System.Collections.Generic.List[object]
    $omitted = New-Object System.Collections.Generic.List[string]
    foreach ($sid in @($script:PimAsBuiltSectionTitles.Keys)) {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($q in @($script:PimAsBuiltQuestions | Where-Object { $_.section -eq $sid })) {
            if ($ans.Contains($q.id)) {
                $a = $ans[$q.id]
                # display = what the PDF prints: a product default is marked "(default)" so it is clear nobody chose it
                [void]$rows.Add([ordered]@{ id = $q.id; label = $q.label; value = $a.value; isDefault = [bool]$a.isDefault
                    display = $(if ($a.isDefault) { "$($a.value) (default)" } else { $a.value }); source = $a.source })
            }
            else { [void]$omitted.Add($q.id) }
        }
        if ($rows.Count) { [void]$secs.Add([ordered]@{ id = $sid; title = $script:PimAsBuiltSectionTitles[$sid]; rows = @($rows.ToArray()) }) }
    }
    return [pscustomobject][ordered]@{
        schema = $script:PimAsBuiltSchema; product = 'PIM Manager'
        generatedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); generatedBy = $GeneratedBy
        facts = @($facts.ToArray()); endpoints = @($eps.ToArray()); sections = @($secs.ToArray()); omitted = @($omitted.ToArray())
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# The fact reader: everything through -GetSetting (a name -> raw value; the Manager's store read, or the job's view) and
# -FeatureOn (a feature key -> $true / $false / $null = cannot tell). A read that throws = that fact left out.
# ---------------------------------------------------------------------------------------------------------------------
function Read-PimAsBuiltFacts {
    param(
        [Parameter(Mandatory)][scriptblock]$GetSetting,
        [Parameter(Mandatory)][scriptblock]$FeatureOn,
        [string]$Version = '',
        [AllowNull()][object]$License = $null,
        [AllowNull()][object]$ProHere = $null,
        [AllowNull()][string]$EnvRing = $env:PIM_UPDATE_RING,
        [AllowNull()][string]$EnvHold = $env:PIM_UPDATE_HOLD,
        [AllowNull()][string]$DnsSuffix = $env:CONTAINER_APP_ENV_DNS_SUFFIX,
        [scriptblock]$SqlServiceObjective = $null,
        [AllowNull()][object[]]$Endpoints = $null
    )
    $rd = { param($n) try { ConvertTo-PimAsBuiltSettingValue -Name $n -Value (& $GetSetting $n) } catch { $null } }
    $fo = { param($k) try { $r = & $FeatureOn $k; if ($null -eq $r) { $null } else { [bool]$r } } catch { $null } }
    $f = [ordered]@{}
    # answers that are the PRODUCT DEFAULT (nothing stored, so nobody chose them) -- printed marked "(default)" (owner 2026-10-10)
    $dflt = New-Object System.Collections.Generic.List[string]
    if ("$Version".Trim() -match '^[0-9A-Za-z.+-]{1,50}$') { $f['version'] = "$Version".Trim() }
    $f['edition'] = Get-PimAsBuiltEdition -License $License -ProHere $ProHere
    # tenancy (the deployed scenario's role)
    $sc = & $rd 'Scenario'
    $scId = if ($sc -is [string]) { "$sc".Trim() } else { "$(Get-PimAsBuiltField $sc 'scenario')".Trim() }
    if ($scId) {
        $role = ''
        if (Get-Command Get-PimScenario -ErrorAction SilentlyContinue) { try { $role = "$((Get-PimScenario -Id $scId).role)" } catch { $role = '' } }
        if (-not $role) { if ($scId -match '(?i)master|managing') { $role = 'msp-master' } elseif ($scId -match '(?i)managed|slave') { $role = 'msp-managed' } elseif ($scId -match '(?i)single') { $role = 'single' } }
        $f['tenancy'] = switch ($role) { 'msp-master' { 'managing' } 'msp-managed' { 'managed' } '' { '' } default { 'single' } }
    } else { $f['tenancy'] = 'single'; $dflt.Add('tenancy') }   # no scenario stored = the single-tenant default every install starts as
    # install facts recorded by the setup
    $inst = & $rd 'AsBuiltInstallFacts'
    $reg = "$(Get-PimAsBuiltField $inst 'region')".Trim().ToLowerInvariant()
    if ($reg -notmatch '^[a-z][a-z0-9]{2,30}$') { $reg = Get-PimAsBuiltRegionFromDnsSuffix $DnsSuffix }
    $f['region'] = $reg
    $rg = "$(Get-PimAsBuiltField $inst 'resourceGroup')".Trim(); if ($rg -match '^[-\w._()]{1,90}$') { $f['resourceGroup'] = $rg }
    $ex = "$(Get-PimAsBuiltField $inst 'network')".Trim().ToLowerInvariant(); if ($ex -in @('internal', 'external')) { $f['exposure'] = $ex }
    if ($SqlServiceObjective) { try { $so = "$(& $SqlServiceObjective)".Trim(); if ($so -match '^[A-Za-z0-9_]{1,40}$') { $f['sqlTier'] = $so } } catch { } }
    # workloads
    $wl = New-Object System.Collections.Generic.List[string]
    [void]$wl.Add('entra-roles'); [void]$wl.Add('pim-groups')
    if ((& $fo 'connectors.workload') -eq $true) { [void]$wl.Add('intune'); [void]$wl.Add('defender') }
    if ((& $fo 'connectors.apps') -eq $true) { [void]$wl.Add('app-connectors') }
    if ((& $fo 'connectors.powerbi') -eq $true) { [void]$wl.Add('powerbi') }
    if ((& $fo 'hybrid.ad') -eq $true -and [bool]$ProHere) { [void]$wl.Add('hybrid-ad') }
    $f['workloads'] = @($wl.ToArray())
    # admin model
    $bg = & $rd 'BreakGlassAccounts'; if ($null -ne $bg) { $f['breakGlassCount'] = [int](Get-PimAsBuiltField $bg 'count') }
    $ma = & $rd 'ManagerAccess'; if ($null -ne $ma) { $f['superAdminCount'] = [int](Get-PimAsBuiltField $ma 'superAdminCount') }
    $pro = { param($k) $o = & $fo $k; if ($null -eq $o) { return $null }; return ([bool]$o -and ($null -eq $ProHere -or [bool]$ProHere)) }
    $f['delegatedAdmin'] = & $pro 'access.delegated'
    $f['makerChecker'] = & $pro 'makerchecker'
    $sa = & $rd 'PendingSecondApprover'
    $sav = "$sa".Trim().Trim('"').ToLowerInvariant()
    $f['secondApprover'] = if ($sav -in @('sensitive', 'all')) { $sav } else { 'off' }
    if ($sav -notin @('sensitive', 'all', 'off')) { $dflt.Add('secondApprover') }   # nothing (valid) stored
    $gr = & $rd 'GuardReleaseSecondPerson'
    $f['guardReleaseSecondPerson'] = if ($null -eq $gr) { $false } else { [bool](Get-PimAsBuiltField $gr 'enabled') }
    if ($null -eq $gr) { $dflt.Add('guardReleaseSecondPerson') }
    $op = & $rd 'OperationalPolicy'
    $mad = Get-PimAsBuiltField (Get-PimAsBuiltField $op 'expiry') 'maxActivationDuration'
    $h = ConvertTo-PimAsBuiltHours "$mad"; if ($null -eq $h) { $h = ConvertTo-PimAsBuiltHours 'P1D'; $dflt.Add('maxActivationHours') }
    $f['maxActivationHours'] = $h
    # reviews
    $arr = & $rd 'AccessReviewRules'
    $camp = & $pro 'reviews.campaigns'
    if ($null -ne $camp) {
        $ren = Get-PimAsBuiltField $arr 'enabled'
        $f['accessReviews'] = [bool]$camp -and ($null -ne $ren) -and [bool]$ren
        if ($f['accessReviews']) {
            $cd = Get-PimAsBuiltField $arr 'cadenceDays'; if ($null -ne $cd) { $f['reviewCadenceDays'] = [int]$cd }
            $un = "$(Get-PimAsBuiltField $arr 'undecided')"; if ($un) { $f['reviewUndecided'] = $un }
        }
    }
    $f['consultantReview'] = & $pro 'consultants.review'
    $f['rfa'] = & $pro 'rfa.portal'
    $f['rfaApi'] = & $pro 'api.broker'
    # alerting
    $mm = "$(& $rd 'MailMode')".Trim().Trim('"').ToLowerInvariant()
    $f['mailMode'] = switch -regex ($mm) { '^(sharedmailbox|shared|mailbox)$' { 'shared-mailbox' } '^(smtp|smtprelay|relay)$' { 'smtp' } '^(none|off)$' { 'none' } default { '' } }
    $al = & $rd 'Alerting'
    if ($null -ne $al) {
        $f['alertRecipientCount'] = [int](Get-PimAsBuiltField $al 'recipientCount')
        $wk = "$(Get-PimAsBuiltField $al 'webhookKind')".Trim().ToLowerInvariant()
        $f['webhook'] = if (-not [bool](Get-PimAsBuiltField $al 'webhookSet')) { 'none' } elseif ($wk -match 'teams') { 'teams' } else { 'generic' }
    }
    # operations
    $us = & $rd 'UpdateState'
    $ring = $null
    foreach ($c in @("$EnvRing", "$(Get-PimAsBuiltField $us 'configuredRing')", "$(Get-PimAsBuiltField $us 'ring')")) {
        $n = ("$c".Trim() -replace '^(?i)ring[\s_-]*', ''); $r = 0
        if ($n -and [int]::TryParse($n, [ref]$r) -and $r -ge 0 -and $r -le 3) { $ring = $r; break }
    }
    if ($null -ne $ring) { $f['updateRing'] = $ring }
    if ("$EnvHold".Trim() -eq '1') { $f['updateHold'] = $true } elseif ($null -ne $us) { $f['updateHold'] = [bool](Get-PimAsBuiltField $us 'hold') }
    $tel = & $fo 'telemetry.uplink'
    if ($null -ne $tel) {
        if (-not $tel) { $f['telemetry'] = 'off' }
        else {
            $key = & $rd 'InvardiaInstallKey'
            $present = [bool](Get-PimAsBuiltField $key 'present') -or [bool]("$env:PIM_UPLINK_KEY".Trim())
            $f['telemetry'] = if ($present) { 'identified' } else { 'anonymous' }
        }
    }
    $f['licenceAutoRequest'] = & $fo 'licence.autoRequest'
    $arm = & $rd 'AuditRetentionMonths'; $am = 0
    if ($null -eq $arm -or "$arm".Trim() -eq '' -or ([int]::TryParse("$arm".Trim().Trim('"'), [ref]$am) -and $am -le 0)) {
        $f['auditRetention'] = 'forever'
        if ($null -eq $arm -or "$arm".Trim() -eq '') { $dflt.Add('auditRetention') }   # a stored 0 is a choice, not the default
    }
    elseif ($am -gt 0) { $f['auditRetention'] = 'months'; $f['auditRetentionMonths'] = $am }
    $cbr = & $rd 'ConfigBackupRetentionDays'; $cb = 0
    if ($null -ne $cbr -and [int]::TryParse("$cbr".Trim().Trim('"'), [ref]$cb) -and $cb -ge 1) { $f['configBackupRetentionDays'] = $cb } else { $f['configBackupRetentionDays'] = 90; $dflt.Add('configBackupRetentionDays') }
    # endpoints (100.56 -- the same list the heartbeat carries)
    if ($null -ne $Endpoints) { $f['endpoints'] = @($Endpoints) }
    else {
        $mgr = "$(& $rd 'ManagerUrl')".Trim().Trim('"'); if (-not $mgr -and "$env:PIM_MANAGER_URL".Trim()) { $mgr = "$env:PIM_MANAGER_URL".Trim() }
        $portal = "$(Get-PimAsBuiltField (& $rd 'RfaSettings') 'portalUrl')".Trim()
        if (-not (Get-Command New-PimUplinkEndpoints -ErrorAction SilentlyContinue)) { $u = Join-Path $PSScriptRoot 'PIM-Uplink.ps1'; if (Test-Path -LiteralPath $u) { . $u } }
        if (Get-Command New-PimUplinkEndpoints -ErrorAction SilentlyContinue) {
            try { $f['endpoints'] = @(New-PimUplinkEndpoints -ManagerUrl $mgr -RfaPortalUrl $portal -ApiEnabled ([bool](& $pro 'api.broker')) -McpEnabled ([bool](& $pro 'mcp.server'))) } catch { $f['endpoints'] = @() }
        }
    }
    $f['defaults'] = @($dflt.ToArray())
    return [pscustomobject]$f
}

# ---------------------------------------------------------------------------------------------------------------------
# The PDF (PDFsharp + MigraDoc, bundled in the image)
# ---------------------------------------------------------------------------------------------------------------------
$script:PimAsBuiltPdfDlls = @('Microsoft.Extensions.Logging.Abstractions.dll', 'PdfSharp.Shared.dll', 'PdfSharp.System.dll', 'PdfSharp.dll', 'PdfSharp.Charting.dll', 'MigraDoc.DocumentObjectModel.dll', 'MigraDoc.Rendering.dll')
$script:PimAsBuiltFontResolverCs = @'
using System;
using System.IO;
using PdfSharp.Fonts;
public class PimAsBuiltFontResolver : IFontResolver
{
    public static string RegularPath;
    public static string BoldPath;
    public FontResolverInfo ResolveTypeface(string familyName, bool isBold, bool isItalic)
    {
        bool haveBold = !string.IsNullOrEmpty(BoldPath) && File.Exists(BoldPath);
        if (isBold && haveBold) { return new FontResolverInfo("PimSans-Bold", false, isItalic); }
        return new FontResolverInfo("PimSans-Regular", isBold, isItalic);
    }
    public byte[] GetFont(string faceName)
    {
        string p = (faceName == "PimSans-Bold" && !string.IsNullOrEmpty(BoldPath)) ? BoldPath : RegularPath;
        return File.ReadAllBytes(p);
    }
}
'@

$script:PimAsBuiltFontResolverPs = @'
class PimAsBuiltFontResolver : PdfSharp.Fonts.IFontResolver {
    static [string] $RegularPath
    static [string] $BoldPath
    [PdfSharp.Fonts.FontResolverInfo] ResolveTypeface([string]$familyName, [bool]$isBold, [bool]$isItalic) {
        $haveBold = (-not [string]::IsNullOrEmpty([PimAsBuiltFontResolver]::BoldPath)) -and [System.IO.File]::Exists([PimAsBuiltFontResolver]::BoldPath)
        if ($isBold -and $haveBold) { return [PdfSharp.Fonts.FontResolverInfo]::new('PimSans-Bold', $false, $isItalic) }
        return [PdfSharp.Fonts.FontResolverInfo]::new('PimSans-Regular', $isBold, $isItalic)
    }
    [byte[]] GetFont([string]$faceName) {
        $p = [PimAsBuiltFontResolver]::RegularPath
        if ($faceName -eq 'PimSans-Bold' -and -not [string]::IsNullOrEmpty([PimAsBuiltFontResolver]::BoldPath)) { $p = [PimAsBuiltFontResolver]::BoldPath }
        return [System.IO.File]::ReadAllBytes($p)
    }
}
'@

function Resolve-PimAsBuiltPdfPaths {
    <# PURE (file-system read only). Where the library and the fonts are: -DllDir / $env:PIM_PDF_DLL_DIR, -FontDir / $env:PIM_PDF_FONT_DIR. #>
    param([string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    $d = "$DllDir".Trim(); if (-not $d) { $d = '/opt/pdf' }
    $fd = "$FontDir".Trim(); if (-not $fd) { $fd = Join-Path $d 'fonts' }
    $reg = @('DejaVuSans.ttf', 'LiberationSans-Regular.ttf') | ForEach-Object { Join-Path $fd $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $reg -and (Test-Path -LiteralPath $fd)) { $reg = @(Get-ChildItem -LiteralPath $fd -Filter '*.ttf' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '(?i)bold|italic|oblique' } | Select-Object -First 1 | ForEach-Object { $_.FullName }) | Select-Object -First 1 }
    $bold = @('DejaVuSans-Bold.ttf', 'LiberationSans-Bold.ttf') | ForEach-Object { Join-Path $fd $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    return [pscustomobject]@{ dllDir = $d; fontDir = $fd; regular = "$reg"; bold = "$bold"; libraryPresent = (Test-Path -LiteralPath (Join-Path $d 'MigraDoc.Rendering.dll')) }
}

function Import-PimAsBuiltPdfLibrary {
    <#
      Loads PDFsharp + MigraDoc from the image (Add-Type -Path; an assembly already loaded under that name is not loaded
      twice) and installs PIM's font resolver ONCE per process (PDFsharp refuses a resolver change after first use).
      Throws a plain message when the library or a font is missing -- the caller reports it; nothing is downloaded.
    #>
    param([string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    if ($script:PimAsBuiltPdfReady) { return }
    $p = Resolve-PimAsBuiltPdfPaths -DllDir $DllDir -FontDir $FontDir
    if (-not $p.libraryPresent) { throw "the PDF library (PDFsharp + MigraDoc) is not in this image ($($p.dllDir)) -- the as-built PDF needs an image built with the PDF library (tools/pim-manager/Dockerfile stage 'pdflib')" }
    if (-not $p.regular) { throw "no font for the PDF in $($p.fontDir) -- the image carries DejaVu Sans there" }
    $loaded = @{}; foreach ($a in [AppDomain]::CurrentDomain.GetAssemblies()) { try { $loaded[$a.GetName().Name] = $true } catch { } }
    foreach ($dll in $script:PimAsBuiltPdfDlls) {
        $path = Join-Path $p.dllDir $dll
        if (-not (Test-Path -LiteralPath $path)) { if ($dll -match '^(PdfSharp|MigraDoc)\.(dll|DocumentObjectModel|Rendering)') { throw "missing $dll in $($p.dllDir)" }; continue }
        $name = ''; try { $name = [System.Reflection.AssemblyName]::GetAssemblyName($path).Name } catch { $name = [IO.Path]::GetFileNameWithoutExtension($path) }
        if ($loaded.ContainsKey($name)) { continue }
        Add-Type -Path $path
        $loaded[$name] = $true
    }
    $rt = $script:PimAsBuiltResolverType
    if (-not $rt) { $rt = 'PimAsBuiltFontResolver' -as [type] }
    if (-not $rt) {
        $refs = @('PdfSharp.dll', 'PdfSharp.Shared.dll') | ForEach-Object { Join-Path $p.dllDir $_ } | Where-Object { Test-Path -LiteralPath $_ }
        # -IgnoreWarnings: a PowerShell on a newer .NET than the library's (8.0) reports CS1701 (assembly unification), harmless.
        try { Add-Type -TypeDefinition $script:PimAsBuiltFontResolverCs -ReferencedAssemblies @($refs) -IgnoreWarnings -WarningAction SilentlyContinue; $rt = 'PimAsBuiltFontResolver' -as [type] }
        catch { $rt = $null }
        if (-not $rt) {
            # The C# compiler of this PowerShell refused the library's reference set: the same resolver as a PowerShell class,
            # parsed only now (the interface type exists once the assembly is loaded). The script block returns the type.
            $rt = . ([scriptblock]::Create($script:PimAsBuiltFontResolverPs + "`n[PimAsBuiltFontResolver]"))
        }
        if (-not $rt) { throw 'the PDF font resolver could not be created' }
        $script:PimAsBuiltResolverType = $rt
    }
    $rt::RegularPath = $p.regular
    $rt::BoldPath = $p.bold
    $cur = [PdfSharp.Fonts.GlobalFontSettings]::FontResolver
    if ($null -eq $cur) { [PdfSharp.Fonts.GlobalFontSettings]::FontResolver = $rt::new() }
    elseif ($cur.GetType().Name -ne 'PimAsBuiltFontResolver') { throw 'another PDF font resolver is already installed in this process' }
    $script:PimAsBuiltPdfReady = $true
}

# ---------------------------------------------------------------------------------------------------------------------
# 100.89 (owner 2026-10-11: "why add this to pim manager documentation ... table also looks weird"): what the PDF prints is
# decided HERE, in a pure plan the offline suite can read -- the renderer below only draws it.
#   * The questions this installation cannot answer are NOT printed (about sixty internal field keys meant nothing to a
#     customer). They stay in the model (omitted, GET /api/asbuilt) and as a count in the job log and the audit record.
#   * A section table has no "Question id" column: the customer reads the question; the id (an internal key such as
#     configBackupRetentionDays, one unbreakable word) ran over the next column. The id stays in the model's rows.
#   * Every table is exactly as wide as the A4 text area, and a word too long for its column (an address, a key) is
#     broken onto the next line at a natural point -- the PDF library only wraps at spaces.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimAsBuiltPdfTextWidthCm = 17.8      # A4 portrait (21.0 cm) minus the 1.6 cm side margins
$script:PimAsBuiltPdfTableFontPt = 8
$script:PimAsBuiltPdfTables = [ordered]@{
    facts     = @{ widthsCm = @(5.0, 12.8);      headers = @('Fact', 'Value') }
    endpoints = @{ widthsCm = @(3.0, 4.0, 10.8); headers = @('Kind', 'Label', 'Address') }
    section   = @{ widthsCm = @(6.0, 5.0, 6.8);  headers = @('Question', 'As built', 'Source') }
}

function Get-PimAsBuiltPdfCellMaxChars {
    <#
      PURE. How many characters of ONE unbroken word are safe on a line of a column this wide. Deliberately on the low
      side (0.68 em per character -- DejaVu Sans is a wide face -- and 0.3 cm off for the cell padding and border), so a
      word that passes always fits; ordinary text wraps at its spaces and is not affected.
    #>
    param([Parameter(Mandatory)][double]$WidthCm, [double]$FontPt = 8)
    $pt = ($WidthCm - 0.3) * 28.3465
    return [Math]::Max(6, [int][Math]::Floor($pt / ($FontPt * 0.68)))
}

function Split-PimAsBuiltPdfCellText {
    <#
      PURE. -Text with a line feed put into every word longer than -MaxChars, so it cannot run over the next column. The
      break goes after the last / . - _ : ? & = or before the last capital of a camelCase word inside the limit, else at
      the limit. Nothing is added or removed besides the line feeds; text whose words all fit comes back unchanged.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][int]$MaxChars)
    if ($MaxChars -lt 2) { $MaxChars = 2 }
    $t = "$Text"
    if ($t.Length -le $MaxChars) { return $t }
    $sb = New-Object System.Text.StringBuilder
    foreach ($part in [regex]::Split($t, '(\s+)')) {
        $w = "$part"
        while ($w.Length -gt $MaxChars -and $w -notmatch '^\s') {
            $cut = 0
            for ($i = $MaxChars; $i -ge [Math]::Max(2, [int][Math]::Floor($MaxChars / 2)); $i--) {
                $prev = $w[$i - 1]
                if ('/.-_:?&='.IndexOf($prev) -ge 0) { $cut = $i; break }
                if ([char]::IsUpper($w[$i]) -and [char]::IsLower($prev)) { $cut = $i; break }
            }
            if ($cut -le 0) { $cut = $MaxChars }
            [void]$sb.Append($w.Substring(0, $cut)).Append("`n")
            $w = $w.Substring($cut)
        }
        [void]$sb.Append($w)
    }
    return $sb.ToString()
}

function Get-PimAsBuiltPdfPlan {
    <#
      PURE. The model (New-PimAsBuiltModel) -> what the customer document prints, in order:
        { title; intro; textWidthCm; blocks = @( @{ heading; kind; headers; widthsCm; rows = @( , @(cell, cell, ...) ) } ) }
      Environment (Fact | Value), Endpoints (Kind | Label | Address) when there are any, then one table per configurator
      section (Question | As built | Source). Cells are already broken for their column (Split-PimAsBuiltPdfCellText).
      The model's omitted list and the question ids are not in the plan.
    #>
    param([Parameter(Mandatory)][object]$Model)
    $blocks = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$heading, [string]$kind, [object[]]$rows)
        $def = $script:PimAsBuiltPdfTables[$kind]
        $w = @($def.widthsCm)
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($rows)) {
            $cells = @($r)
            $line = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $w.Count; $i++) {
                $max = Get-PimAsBuiltPdfCellMaxChars -WidthCm ([double]$w[$i]) -FontPt $script:PimAsBuiltPdfTableFontPt
                [void]$line.Add((Split-PimAsBuiltPdfCellText -Text "$($cells[$i])" -MaxChars $max))
            }
            [void]$out.Add($line.ToArray())
        }
        [void]$blocks.Add([ordered]@{ heading = $heading; kind = $kind; headers = @($def.headers); widthsCm = $w; rows = $out.ToArray() })
    }
    $factRows = New-Object System.Collections.Generic.List[object]
    foreach ($fa in @($Model.facts)) { if ($fa) { [void]$factRows.Add(@("$($fa.name)", "$($fa.value)")) } }
    & $add 'Environment' 'facts' $factRows.ToArray()
    $epRows = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Model.endpoints)) { if ($e) { [void]$epRows.Add(@("$($e.kind)", "$($e.label)", "$($e.url)")) } }
    if ($epRows.Count) { & $add 'Endpoints' 'endpoints' $epRows.ToArray() }
    foreach ($s in @($Model.sections)) {
        if (-not $s) { continue }
        $secRows = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($s.rows)) {
            if (-not $r) { continue }
            $shown = if ("$($r.display)".Trim()) { "$($r.display)" } elseif ($r.isDefault) { "$($r.value) (default)" } else { "$($r.value)" }
            [void]$secRows.Add(@("$($r.label)", $shown, "$($r.source)"))
        }
        & $add "$($s.title)" 'section' $secRows.ToArray()
    }
    return [pscustomobject][ordered]@{
        title       = 'PIM Manager - as-built configuration'
        intro       = "Generated $($Model.generatedUtc) inside this installation. Every value below is read from the installation; a question it cannot answer is left out, never guessed. A value marked (default) is what PIM Manager does when nothing is set -- nobody chose it. No secrets, people, user names or object ids are included."
        textWidthCm = $script:PimAsBuiltPdfTextWidthCm
        blocks      = $blocks.ToArray()
    }
}

function ConvertTo-PimAsBuiltPdf {
    <#
      The model (New-PimAsBuiltModel) -> PDF bytes: A4 portrait, a title block, then the blocks of Get-PimAsBuiltPdfPlan
      (the environment facts, the endpoints, one table per configurator section: question | as built | source). Page
      numbers in the footer. Needs Import-PimAsBuiltPdfLibrary (called here).
    #>
    param([Parameter(Mandatory)][object]$Model, [string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    Import-PimAsBuiltPdfLibrary -DllDir $DllDir -FontDir $FontDir
    $plan = Get-PimAsBuiltPdfPlan -Model $Model
    $U = [MigraDoc.DocumentObjectModel.Unit]
    $doc = New-Object MigraDoc.DocumentObjectModel.Document
    $doc.Info.Title = 'PIM Manager as-built'
    $doc.Info.Subject = 'As-built configuration of this PIM Manager installation'
    $doc.Info.Author = 'PIM Manager'
    $normal = $doc.Styles['Normal']; $normal.Font.Name = 'PimSans'; $normal.Font.Size = 8.5
    $sec = $doc.AddSection()
    # the document's default page setup as the base (instance property in MigraDoc 6; the static default as a fallback)
    $base = $null; try { $base = $doc.DefaultPageSetup } catch { $base = $null }
    if ($null -eq $base) { try { $base = [MigraDoc.DocumentObjectModel.PageSetup]::DefaultPageSetup } catch { $base = $null } }
    $ps = if ($null -ne $base) { $base.Clone() } else { $sec.PageSetup }
    $ps.PageFormat = [MigraDoc.DocumentObjectModel.PageFormat]::A4
    $ps.Orientation = [MigraDoc.DocumentObjectModel.Orientation]::Portrait
    $ps.TopMargin = $U::FromCentimeter(1.8); $ps.BottomMargin = $U::FromCentimeter(1.8)
    $ps.LeftMargin = $U::FromCentimeter(1.6); $ps.RightMargin = $U::FromCentimeter(1.6)
    $sec.PageSetup = $ps
    $foot = $sec.Footers.Primary.AddParagraph()
    $foot.Format.Font.Size = 7
    [void]$foot.AddText("PIM Manager as-built - generated $($Model.generatedUtc) - page ")
    [void]$foot.AddPageField(); [void]$foot.AddText(' of '); [void]$foot.AddNumPagesField()

    $h = $sec.AddParagraph("$($plan.title)")
    $h.Format.Font.Size = 16; $h.Format.Font.Bold = $true; $h.Format.SpaceAfter = $U::FromPoint(4)
    $sub = $sec.AddParagraph("$($plan.intro)")
    $sub.Format.Font.Size = 8; $sub.Format.SpaceAfter = $U::FromPoint(10)

    foreach ($b in @($plan.blocks)) {
        $p = $sec.AddParagraph("$($b.heading)"); $p.Format.Font.Size = 11; $p.Format.Font.Bold = $true
        $p.Format.SpaceBefore = $U::FromPoint(10); $p.Format.SpaceAfter = $U::FromPoint(4); $p.Format.KeepWithNext = $true
        $t = $sec.AddTable()
        $t.Borders.Width = 0.4
        $t.Borders.Color = [MigraDoc.DocumentObjectModel.Colors]::Gray
        $t.Format.Font.Size = $script:PimAsBuiltPdfTableFontPt
        foreach ($w in @($b.widthsCm)) { [void]$t.AddColumn($U::FromCentimeter([double]$w)) }
        $hr = $t.AddRow(); $hr.HeadingFormat = $true; $hr.Format.Font.Bold = $true
        $hr.Shading.Color = [MigraDoc.DocumentObjectModel.Colors]::LightGray
        $hd = @($b.headers)
        for ($i = 0; $i -lt $hd.Count; $i++) { [void]$hr.Cells[$i].AddParagraph("$($hd[$i])") }
        foreach ($cells in @($b.rows)) {
            $r = $t.AddRow()
            $cs = @($cells)
            for ($i = 0; $i -lt $cs.Count; $i++) {
                # a line feed in the cell text is a forced break (a word too long for the column)
                $cp = $r.Cells[$i].AddParagraph()
                $lines = @("$($cs[$i])" -split "`n")
                for ($k = 0; $k -lt $lines.Count; $k++) {
                    if ($k -gt 0) { [void]$cp.AddLineBreak() }
                    if ($lines[$k].Length) { [void]$cp.AddText($lines[$k]) }
                }
            }
        }
    }

    $renderer = New-Object MigraDoc.Rendering.PdfDocumentRenderer
    $renderer.Document = $doc
    $renderer.RenderDocument()
    $ms = New-Object System.IO.MemoryStream
    try { $renderer.PdfDocument.Save($ms, $false); return , $ms.ToArray() } finally { $ms.Dispose() }
}

function Get-PimAsBuiltFileName {
    # PURE. The download / blob file name: pim-manager-asbuilt-<yyyyMMdd-HHmmss>.pdf (no tenant, no host, no person).
    param([datetime]$NowUtc = [datetime]::UtcNow)
    return ('pim-manager-asbuilt-{0}.pdf' -f $NowUtc.ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
}

# ---------------------------------------------------------------------------------------------------------------------
# Deploy specs (PURE) -- used by tools/setup/Deploy-PimAsBuiltJob.ps1 and tools/setup/Grant-PimSupportAccess.ps1
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAsBuiltViewSql {
    <#
      PURE. Idempotent DDL for pim.vw_AsBuiltSettings -- the ONLY part of pim.Settings the job's identity may read. It lists
      exactly the names the generator needs, and REDUCES the rows that hold people or secrets IN SQL, so they never leave the
      database: ManagerAccess -> { superAdminCount }, BreakGlassAccounts -> { count }, Alerting -> { recipientCount;
      webhookKind; webhookSet }, RfaSettings -> { portalUrl }, GuardReleaseSecondPerson -> { enabled }, AccessReviewRules ->
      { enabled; cadenceDays; undecided }, InvardiaInstallKey -> { present }. The same shapes as ConvertTo-PimAsBuiltSettingValue.
    #>
    $names = (@($script:PimAsBuiltSettingNames) | ForEach-Object { "N''$_''" }) -join ', '
    $case = @"
CASE Name
 WHEN N''ManagerAccess'' THEN (SELECT COUNT(*) AS superAdminCount FROM OPENJSON(CASE WHEN LEFT(LTRIM(ValueJson), 1) = N''['' THEN ValueJson ELSE JSON_QUERY(ValueJson, N''`$.managerAccess'') END) WITH (role nvarchar(64) ''`$.role'') WHERE role = N''SuperAdmin'' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''BreakGlassAccounts'' THEN (SELECT COUNT(*) AS [count] FROM OPENJSON(ValueJson) FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''Alerting'' THEN (SELECT (SELECT COUNT(*) FROM OPENJSON(ValueJson, N''`$.recipients'')) AS recipientCount, JSON_VALUE(ValueJson, N''`$.webhookKind'') AS webhookKind, CAST(CASE WHEN LEN(ISNULL(JSON_VALUE(ValueJson, N''`$.webhookUrl''), N'''')) > 0 THEN 1 ELSE 0 END AS bit) AS webhookSet FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''RfaSettings'' THEN (SELECT JSON_VALUE(ValueJson, N''`$.portalUrl'') AS portalUrl FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''GuardReleaseSecondPerson'' THEN (SELECT CAST(CASE WHEN JSON_VALUE(ValueJson, N''`$.enabled'') = N''true'' THEN 1 ELSE 0 END AS bit) AS enabled FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''AccessReviewRules'' THEN (SELECT CAST(CASE WHEN JSON_VALUE(ValueJson, N''`$.default.enabled'') = N''true'' THEN 1 ELSE 0 END AS bit) AS enabled, TRY_CAST(JSON_VALUE(ValueJson, N''`$.default.cadenceDays'') AS int) AS cadenceDays, JSON_VALUE(ValueJson, N''`$.default.undecided'') AS undecided FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 WHEN N''InvardiaInstallKey'' THEN (SELECT CAST(CASE WHEN LEN(ISNULL(ValueJson, N'''')) > 10 THEN 1 ELSE 0 END AS bit) AS present FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
 ELSE ValueJson END
"@
    $v = "CREATE OR ALTER VIEW pim.vw_AsBuiltSettings AS SELECT Name, $($case.Trim() -replace '\r?\n', ' ') AS ValueJson FROM pim.Settings WHERE Name IN ($names)"
    return ("IF OBJECT_ID(N'pim.Settings') IS NULL THROW 50001, 'pim.Settings does not exist in this store -- the Manager has not initialised it', 1;`n" +
            "EXEC (N'$v');")
}

function Get-PimAsBuiltJobSpec {
    <#
      PURE. The Container Apps job caj-pim-asbuilt (framework 8.12): MANUAL trigger (started on demand -- by Invardia support
      with the customer's consent, or by an admin), one replica, no retry, 10 minutes. Runs the same image as the Manager with
      tools/pim-engine/asbuilt-job-entry.ps1, as the USER-ASSIGNED identity id-pim-asbuilt (-IdentityResourceId +
      -IdentityClientId; env PIM_ManagedIdentityClientId tells PIM-Rest which identity to ask the token endpoint for). The
      identity block is written on create AND update (an existing system-identity job is switched): UserAssigned (the
      registry's user-assigned identity kept beside it); SystemAssigned,UserAssigned only when the image pull uses the job's
      own system identity ('system' -- the pull must keep working). Without -IdentityResourceId: the former system-assigned
      shape (create only). Env: the store, the PIM storage account + container 'asbuilt'. REFUSED: a storage name that is not
      one, an env value that looks like a credential, a client id that is not a GUID.
      Returns @{ ok; reason; env; resource } (resource = the ARM body: create = PUT, update = PATCH).
    #>
    param(
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$RegistryServer,
        [string]$RegistryIdentity = 'system',
        [Parameter(Mandatory)][string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [Parameter(Mandatory)][string]$StorageAccount,
        [string]$Container = $script:PimAsBuiltContainer,
        [bool]$Exists = $false,
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/asbuilt-job-entry.ps1',
        [string]$IdentityResourceId = '',
        [string]$IdentityClientId = ''
    )
    $uami = "$IdentityResourceId".Trim()
    if ($uami) {
        if ($uami -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[A-Za-z0-9][A-Za-z0-9_-]{2,127}$') { return @{ ok = $false; reason = "'$uami' is not a user-assigned identity resource id" } }
        $gcid = [guid]::Empty
        if (-not [guid]::TryParse("$IdentityClientId".Trim(), [ref]$gcid)) { return @{ ok = $false; reason = "'$IdentityClientId' is not the client id of $uami" } }
    }
    if ("$StorageAccount" -notmatch '^[a-z0-9]{3,24}$') { return @{ ok = $false; reason = "'$StorageAccount' is not a storage account name" } }
    if ("$Container" -notmatch '^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$') { return @{ ok = $false; reason = "'$Container' is not a blob container name" } }
    if ("$SqlServerFqdn" -notmatch '^[a-z0-9-]+\.database\.(windows\.net|chinacloudapi\.cn|usgovcloudapi\.net)$') { return @{ ok = $false; reason = "'$SqlServerFqdn' is not an Azure SQL server name" } }
    $env = [ordered]@{
        PIM_HOSTED          = '1'
        PIM_UseGraphSdk     = 'false'
        PIM_StorageBackend  = 'sql'
        PIM_SqlServer       = "$SqlServerFqdn"
        PIM_SqlDatabase     = "$SqlDatabase"
        PIM_ASBUILT_STORAGE = "$StorageAccount"
        PIM_ASBUILT_CONTAINER = "$Container"
    }
    if ($uami) { $env['PIM_ManagedIdentityClientId'] = "$IdentityClientId".Trim().ToLowerInvariant() }
    foreach ($k in @($env.Keys)) {
        $v = "$($env[$k])"
        if ($k -match '(?i)secret|password|thumbprint|sas|accountkey|connectionstring|privatekey' -or $v -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN|secretref:)') {
            return @{ ok = $false; reason = "REFUSED: env '$k' looks like a credential -- the as-built job runs as its managed identity and carries none" }
        }
    }
    $regId = "$RegistryIdentity".Trim(); if (-not $regId) { $regId = 'system' }
    $identity = if ($uami) {
        if ($regId -eq 'system') { @{ type = 'SystemAssigned,UserAssigned'; userAssignedIdentities = @{ $uami = @{} } } }
        elseif ($regId -ieq $uami) { @{ type = 'UserAssigned'; userAssignedIdentities = @{ $uami = @{} } } }
        else { @{ type = 'UserAssigned'; userAssignedIdentities = @{ $regId = @{}; $uami = @{} } } }
    } elseif ($regId -ne 'system') { @{ type = 'SystemAssigned,UserAssigned'; userAssignedIdentities = @{ $regId = @{} } } } else { @{ type = 'SystemAssigned' } }
    $envList = @(foreach ($k in @($env.Keys)) { @{ name = $k; value = "$($env[$k])" } })
    $props = @{
        environmentId = $EnvironmentId
        configuration = @{
            triggerType         = 'Manual'
            replicaTimeout      = 600
            replicaRetryLimit   = 0
            manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 }
            registries          = @(@{ server = $RegistryServer; identity = $regId })
        }
        template      = @{
            containers = @(@{
                name      = $JobName
                image     = $Image
                command   = @('pwsh')
                args      = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $EntryPath)
                env       = $envList
                resources = @{ cpu = 0.5; memory = '1Gi' }
            })
        }
    }
    $res = @{ location = $Location; properties = $props }
    if (-not $Exists -or $uami) { $res['identity'] = $identity }
    return @{ ok = $true; reason = ''; env = $env; resource = $res }
}

function Get-PimAsBuiltStorageAccountName {
    <# PURE. The default PIM storage account for the as-built blobs: 'stpimab' + 12 hex of SHA-256(subscription/resourceGroup) (3-24 lower-case). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hx = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(("$SubscriptionId/$ResourceGroup").ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    return ('stpimab' + $hx.Substring(0, 12))
}

function Get-PimAsBuiltReaderUserSql {
    <#
      PURE. The job identity's contained database user, created from its APP ID as a SID (never FROM EXTERNAL PROVIDER),
      with SELECT on pim.vw_AsBuiltSettings ONLY (no fixed role; any a former run left is dropped). Idempotent; a user of
      that name with another SID (a rebuilt identity) is dropped and recreated. The same shape as tools/setup's
      Get-PimSqlContainedUserSql, kept here so the in-cloud updater needs nothing from tools/setup.
    #>
    param([Parameter(Mandatory)][string]$DbUserName, [Parameter(Mandatory)][string]$AppId)
    if ("$DbUserName" -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw "'$DbUserName' is not a safe database user name" }
    $g = [guid]::Empty
    if (-not [guid]::TryParse("$AppId", [ref]$g)) { throw "'$AppId' is not an application id" }
    $sid = '0x' + (($g.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $n = $DbUserName; $q = "[$DbUserName]"
    return (@(
        "IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n' AND sid = $sid)",
        'BEGIN',
        "    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n') DROP USER $q;",
        "    CREATE USER $q WITH SID = $sid, TYPE = E;",
        'END',
        "IF IS_ROLEMEMBER('db_datareader', N'$n') = 1 ALTER ROLE [db_datareader] DROP MEMBER $q;",
        "IF IS_ROLEMEMBER('db_datawriter', N'$n') = 1 ALTER ROLE [db_datawriter] DROP MEMBER $q;",
        "IF IS_ROLEMEMBER('db_ddladmin', N'$n') = 1 ALTER ROLE [db_ddladmin] DROP MEMBER $q;",
        "IF IS_ROLEMEMBER('db_owner', N'$n') = 1 ALTER ROLE [db_owner] DROP MEMBER $q;",
        "IF OBJECT_ID(N'pim.vw_AsBuiltSettings') IS NOT NULL GRANT SELECT ON OBJECT::[pim].[vw_AsBuiltSettings] TO $q;"
    ) -join "`n")
}

function Test-PimAsBuiltRollSkip {
    <#
      PURE. Does the updater's generic job roll (update-job-entry 2b) SKIP this job? Only caj-pim-asbuilt, and only when the
      as-built converge of THIS run already left it on exactly the target image (Invoke-PimAsBuiltConverge's jobImage). A
      second PATCH seconds after the converge's was refused 409 ContainerAppsJobOperationInProgress (live 2026-10-11) and
      reported the job as "still on the previous build". Any other case: roll it as before.
    #>
    param([AllowEmptyString()][string]$JobName, [AllowEmptyString()][string]$ConvergedImage, [AllowEmptyString()][string]$TargetImage)
    $c = "$ConvergedImage".Trim(); $t = "$TargetImage".Trim()
    return ([bool]("$JobName".Trim() -eq $script:PimAsBuiltJobName -and $c -and $t -and $c -ieq $t))
}

function Get-PimAsBuiltStoreReadFailureText {
    <#
      PURE. The job's exit-4 line when the store cannot be read through the view -- worded as WHAT TO RUN. A login failure
      ("Login failed for user '<token-identified principal>'") means the job's identity has no contained database user (yet):
      the as-built converge of the next PIM update creates it (from id-pim-asbuilt's client id), or Deploy-PimAsBuiltJob.ps1
      once. A missing view / denied SELECT: the same two fixes. Anything else: the message as it came.
    #>
    param([AllowEmptyString()][string]$Message, [string]$View = $script:PimAsBuiltView, [AllowEmptyString()][string]$ClientId = '')
    $m = ("$Message" -split "`n")[0].Trim()
    $fix = 'the as-built converge of the next PIM update creates it (the nightly update, or start the update job ca-pim-update once), or run tools/setup/Deploy-PimAsBuiltJob.ps1 once'
    $who = if ("$ClientId".Trim()) { "the job's identity id-pim-asbuilt (client id $("$ClientId".Trim()))" } else { "the job's identity (system-assigned -- the next PIM update switches it to id-pim-asbuilt)" }
    if ($m -match '(?i)Login failed|token-identified principal|18456') { return "the store cannot be read: $who has no database user yet ($m) -- $fix" }
    if ($m -match "(?i)Invalid object name|SELECT permission was denied|permission was denied on the object") { return "the store cannot be read through $View as $who ($m) -- the view or its SELECT grant is missing: $fix" }
    return "the store cannot be read through $View as $who`: $m -- $fix"
}

function Invoke-PimAsBuiltConverge {
    <#
      PIM 100.61 ("build all", owner 2026-10-10): the in-cloud UPDATER brings an EXISTING environment to the as-built setup
      without anyone running Deploy-PimAsBuiltJob.ps1. It runs as the updater's identity -- Contributor on the resource group
      and a member of the SQL admin group -- so it does what that identity can, and REPORTS (never fails) what needs an Owner:
        * the storage account (default name, or the one the job already names): created / hardened -- StorageV2, TLS 1.2,
          HTTPS only, no shared key, no anonymous blob, an Entra-only public endpoint (the only reader is the Support app,
          after the customer's grant);
        * the private container 'asbuilt' and the 1-day lifecycle rule (other rules kept);
        * the job's USER-ASSIGNED identity id-pim-asbuilt (created when missing; Contributor may) -- its clientId (= app id)
          and principalId come from ARM, so nothing here needs Graph (live 2026-10-11: the former system identity's app id
          could not be read by the updater, so the job's database user was never made and every run failed to log in);
        * the job caj-pim-asbuilt (manual trigger) on the Manager's CURRENT image, as id-pim-asbuilt; an existing job is moved
          to that image (so it rolls with every update) and a former system-identity job is SWITCHED to id-pim-asbuilt. The
          job's existing registry identity is kept (else the Manager's). A write refused "OperationInProgress" is waited out
          (bounded). The image the job is on afterwards is returned (jobImage) so the generic roll does not PATCH it again;
        * SQL (works for a private SQL server too -- the updater is inside the network): the view pim.vw_AsBuiltSettings, the
          job identity's reader user (SID from id-pim-asbuilt's clientId, never FROM EXTERNAL PROVIDER), pim.Settings
          'AsBuiltInstallFacts';
        * REPORT ONLY (Contributor cannot write role assignments / definitions): id-pim-asbuilt's Storage Blob Data
          Contributor on the container and the support custom role -- fix: Initialize-PimHostingAccess.ps1 as an Owner.
      Seams: -Arm { param($method, $path, $body) } (path WITH api-version; a GET of an absent resource may throw or return
      $null), -Sql { param($sql, $parameters) } (one batch; $null = no store), -Sleep { param($seconds) } (busy waits),
      -BusyWaits (seconds between the attempts of a busy job write).
      Returns @{ lines = @(@{ id; level = info | changed | warn; text }); changed; warnings; jobImage; identity }. NEVER throws.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [string]$JobName = $script:PimAsBuiltJobName,
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Sql = $null,
          [scriptblock]$Sleep = $null, [int[]]$BusyWaits = @(10, 20, 30, 30, 30))
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { $null } }
    # A job write that arrives while the job's previous operation is still provisioning is refused 409
    # ContainerAppsJobOperationInProgress -- a WAIT, never a failure (same rule as Invoke-PimArmBusyRetry; kept local so this
    # file needs nothing else). Any other failure is rethrown at once.
    $busyWrite = {
        param($bm, $bp, $bb)
        $bn = 0
        while ($true) {
            try { return (& $Arm $bm $bp $bb) }
            catch {
                if ("$($_.Exception.Message)" -notmatch '(?i)OperationInProgress|active provisioning operation' -or $bn -ge @($BusyWaits).Count) { throw }
                $bw = [int]@($BusyWaits)[$bn]; $bn++
                if ($bw -gt 0) { & $Sleep $bw }
            }
        }
    }
    $jobImage = ''; $idOut = @{ kind = 'none'; principalId = ''; clientId = ''; resourceId = '' }
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $aca = 'api-version=2024-03-01'; $st = 'api-version=2023-01-01'; $az = 'api-version=2022-04-01'
    $ownerFix = "run tools/setup/Initialize-PimHostingAccess.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup (an Owner / User Access Administrator of the resource group) -- or Deploy-PimAsBuiltJob.ps1"
    try {
        $mgr = & $get "$rg/providers/Microsoft.App/containerApps/$ManagerApp`?$aca"
        if (-not $mgr) { & $add 'asbuilt' 'warn' "as-built: the Manager app '$ManagerApp' could not be read -- nothing converged"; return (& { [pscustomobject]@{ lines = @($lines.ToArray()); changed = 0; warnings = 1; jobImage = ''; identity = $idOut } }) }
        $mc = @($mgr.properties.template.containers)[0]
        $image = "$($mc.image)".Trim()
        $menv = @{}; foreach ($e in @($mc.env)) { if ($e -and "$($e.name)") { $menv["$($e.name)"] = "$($e.value)" } }
        $reg = @($mgr.properties.configuration.registries)[0]
        $envId = "$($mgr.properties.environmentId)".Trim(); if (-not $envId) { $envId = "$($mgr.properties.managedEnvironmentId)".Trim() }
        $location = "$($mgr.location)".Trim()
        $sqlSrv = "$($menv['PIM_SqlServer'])".Trim(); $sqlDb = $(if ("$($menv['PIM_SqlDatabase'])".Trim()) { "$($menv['PIM_SqlDatabase'])".Trim() } else { 'PimPlatform' })
        $job = & $get "$rg/providers/Microsoft.App/jobs/$JobName`?$aca"
        $jenv = @{}; if ($job) { foreach ($c in @($job.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and "$($e.name)") { $jenv["$($e.name)"] = "$($e.value)" } } } }
        $acct = "$($jenv['PIM_ASBUILT_STORAGE'])".Trim(); if ($acct -notmatch '^[a-z0-9]{3,24}$') { $acct = Get-PimAsBuiltStorageAccountName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup }
        $cont = $script:PimAsBuiltContainer
        $saPath = "$rg/providers/Microsoft.Storage/storageAccounts/$acct"

        # ---- storage account -------------------------------------------------------------------------------------------
        $sa = & $get "$saPath`?$st"
        if (-not $sa) {
            [void](& $Arm 'PUT' "$saPath`?$st" @{ location = $location; sku = @{ name = 'Standard_LRS' }; kind = 'StorageV2'
                properties = @{ allowBlobPublicAccess = $false; allowSharedKeyAccess = $false; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $true; publicNetworkAccess = 'Enabled' } })
            & $add 'asbuilt-storage' 'changed' "as-built: storage account $acct created (Entra-only)"
            $sa = & $get "$saPath`?$st"
        }
        if (-not $sa -or "$($sa.properties.provisioningState)" -notmatch '^(?i)Succeeded$') {
            & $add 'asbuilt-storage' 'info' "as-built: storage account $acct is still being created -- the next update run continues"
        } else {
            $fix = @{}
            if ($sa.properties.allowSharedKeyAccess -ne $false) { $fix['allowSharedKeyAccess'] = $false }
            if ($sa.properties.allowBlobPublicAccess -ne $false) { $fix['allowBlobPublicAccess'] = $false }
            if ("$($sa.properties.minimumTlsVersion)" -ne 'TLS1_2') { $fix['minimumTlsVersion'] = 'TLS1_2' }
            if ("$($sa.properties.publicNetworkAccess)" -notin @('', 'Enabled')) { $fix['publicNetworkAccess'] = 'Enabled' }
            if ($fix.Count) { [void](& $Arm 'PATCH' "$saPath`?$st" @{ properties = $fix }); & $add 'asbuilt-storage' 'changed' "as-built: $acct hardened ($(@($fix.Keys) -join ', '))" }
            # ---- container + lifecycle rule (both idempotent PUTs) ------------------------------------------------------
            [void](& $Arm 'PUT' "$saPath/blobServices/default/containers/$cont`?$st" @{ properties = @{ publicAccess = 'None' } })
            $pol = Get-PimAsBuiltLifecyclePolicy -Container $cont
            $cur = & $get "$saPath/managementPolicies/default`?$st"
            $keep = @(@($cur.properties.policy.rules) | Where-Object { $_ -and "$($_.name)" -ne 'pim-asbuilt-delete-after-1-day' })
            $mine = @(@($cur.properties.policy.rules) | Where-Object { $_ -and "$($_.name)" -eq 'pim-asbuilt-delete-after-1-day' })
            if (-not $mine.Count -or [int]$mine[0].definition.actions.baseBlob.delete.daysAfterModificationGreaterThan -ne 1) {
                $pol.properties.policy.rules = @($keep) + @($pol.properties.policy.rules)
                [void](& $Arm 'PUT' "$saPath/managementPolicies/default`?$st" $pol)
                & $add 'asbuilt-lifecycle' 'changed' "as-built: container '$cont' + the 1-day delete rule in place"
            }
        }

        # ---- the job's user-assigned identity id-pim-asbuilt (clientId = app id, principalId = object id; both over ARM) ----
        $uamiName = $script:PimAsBuiltIdentityName
        $uamiId = Get-PimAsBuiltIdentityResourceId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $uamiName
        $uami = & $get "$uamiId`?$($script:PimAsBuiltMsiApi)"
        if (-not $uami -and $location) {
            try {
                [void](& $Arm 'PUT' "$uamiId`?$($script:PimAsBuiltMsiApi)" @{ location = $location; tags = @{ 'pim-component' = 'asbuilt' } })
                & $add 'asbuilt-identity' 'changed' "as-built: user-assigned identity $uamiName created (the job's identity for SQL + storage)"
            } catch { & $add 'asbuilt-identity' 'warn' "as-built: the user-assigned identity $uamiName could not be created: $(("$($_.Exception.Message)" -split "`n")[0])" }
            $uami = & $get "$uamiId`?$($script:PimAsBuiltMsiApi)"
        }
        $uamiCid = "$($uami.properties.clientId)".Trim(); $uamiOid = "$($uami.properties.principalId)".Trim()
        $gtmp = [guid]::Empty
        if (-not [guid]::TryParse($uamiCid, [ref]$gtmp)) { $uamiCid = '' }
        if ($uamiCid) { $idOut = @{ kind = 'user'; principalId = $uamiOid; clientId = $uamiCid; resourceId = $uamiId } }
        elseif ($uami) { & $add 'asbuilt-identity' 'warn' "as-built: $uamiName exists but its client id is not readable yet -- the job keeps its identity this run" }

        # ---- the job, on the Manager's current image, as id-pim-asbuilt -------------------------------------------------
        $jobReg = if ($job) { @($job.properties.configuration.registries)[0] } else { $null }
        $regIdentity = if ($jobReg -and "$($jobReg.identity)".Trim()) { "$($jobReg.identity)".Trim() } elseif ("$($reg.identity)".Trim()) { "$($reg.identity)".Trim() } else { 'system' }
        $regServer = if ($jobReg -and "$($jobReg.server)".Trim()) { "$($jobReg.server)".Trim() } else { "$($reg.server)" }
        if (-not $image -or -not $envId -or -not $reg -or $sqlSrv -notmatch '\.database\.') {
            & $add 'asbuilt-job' 'warn' "as-built: the Manager's image / environment / registry / SQL server could not be read -- the job was not converged ($ownerFix)"
        } else {
            $specArgs = @{ JobName = $JobName; Image = $image; EnvironmentId = $envId; Location = $location; RegistryServer = $regServer; RegistryIdentity = $regIdentity
                           SqlServerFqdn = $sqlSrv; SqlDatabase = $sqlDb; StorageAccount = $acct; Container = $cont; Exists = [bool]$job }
            if ($uamiCid) { $specArgs['IdentityResourceId'] = $uamiId; $specArgs['IdentityClientId'] = $uamiCid }
            $spec = Get-PimAsBuiltJobSpec @specArgs
            $cur = Get-PimAsBuiltJobIdentity -Job $job -Name $uamiName
            $why = @()
            if ($job) {
                if ("$(@($job.properties.template.containers)[0].image)" -ne $image) { $why += "moved to $image" }
                if ("$($jenv['PIM_ASBUILT_STORAGE'])" -ne $acct) { $why += "store $acct" }
                if ($uamiCid -and ($cur.kind -ne 'user' -or "$($jenv['PIM_ManagedIdentityClientId'])".Trim() -ine $uamiCid -or ("$($job.identity.type)" -replace '\s', '') -ne "$($spec.resource.identity.type)")) {
                    $why += "switched to the user-assigned identity $uamiName (was: $(if ($cur.kind -eq 'none') { 'none' } else { "$($job.identity.type)" }))"
                }
            }
            try {
                if (-not $spec.ok) { & $add 'asbuilt-job' 'warn' "as-built: job not converged ($($spec.reason))" }
                elseif (-not $job) { [void](& $busyWrite 'PUT' "$rg/providers/Microsoft.App/jobs/$JobName`?$aca" $spec.resource); $jobImage = $image; & $add 'asbuilt-job' 'changed' "as-built: job $JobName created (manual trigger) on $image$(if ($uamiCid) { " as $uamiName" })" }
                elseif ($why.Count) {
                    [void](& $busyWrite 'PATCH' "$rg/providers/Microsoft.App/jobs/$JobName`?$aca" $spec.resource); $jobImage = $image
                    & $add 'asbuilt-job' 'changed' "as-built: job $JobName $($why -join '; ')"
                } else { $jobImage = $image; & $add 'asbuilt-job' 'info' "as-built: job $JobName current ($image$(if ($cur.kind -eq 'user') { ", $uamiName" }))" }
            } catch { & $add 'asbuilt-job' 'warn' "as-built: job $JobName not converged: $(("$($_.Exception.Message)" -split "`n")[0]) -- the next update run retries" }
        }

        # ---- report only: the rights an Owner gives (the updater's Contributor cannot write them) ----------------------
        # The principal that writes the PDF is id-pim-asbuilt; the job's own (former system) identity only until it is switched.
        $oid = $uamiOid
        if (-not $oid) { $job2 = & $get "$rg/providers/Microsoft.App/jobs/$JobName`?$aca"; $oid = "$((Get-PimAsBuiltJobIdentity -Job $job2 -Name $uamiName).principalId)".Trim() }
        $contScope = "$saPath/blobServices/default/containers/$cont"
        if ($oid) {
            $ra = & $get ("$contScope/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{0}')&{1}" -f $oid, $az)
            $has = @(@($ra.value) | Where-Object { $_ -and ("$($_.properties.roleDefinitionId)" -split '/')[-1] -eq 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' }).Count -gt 0
            if (-not $has) { & $add 'asbuilt-write-right' 'warn' "as-built: the job's identity$(if ($uamiOid) { " $uamiName" }) has no Storage Blob Data Contributor on $acct/$cont -- the job cannot write the PDF until $ownerFix" }
        } else { & $add 'asbuilt-write-right' 'info' 'as-built: the job identity is not readable yet (just created) -- checked on the next run' }
        $rdef = Get-PimAsBuiltRoleDefinition -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        if (-not (& $get "$($rdef.path)?$az")) { & $add 'asbuilt-support-role' 'warn' "as-built: the support custom role '$($rdef.body.properties.roleName)' does not exist -- Grant-PimSupportAccess.ps1 -Level asbuilt (or $ownerFix) creates it" }

        # ---- SQL: the view, the reader user, the install facts --------------------------------------------------------
        if ($Sql) {
            [void](& $Sql (Get-PimAsBuiltViewSql) @{})
            # The reader user's SID is id-pim-asbuilt's clientId (= its app id), read over ARM above -- no Graph.
            $appId = $uamiCid
            if ($appId) { [void](& $Sql (Get-PimAsBuiltReaderUserSql -DbUserName $JobName -AppId $appId) @{}) }
            else { & $add 'asbuilt-sql-user' 'warn' "as-built: the user-assigned identity $uamiName (the job's identity) is not readable -- $JobName's database user was not made this run; the next update retries, or run tools/setup/Deploy-PimAsBuiltJob.ps1 once" }
            $envObj = if ($envId) { & $get "$envId`?$aca" } else { $null }
            $facts = [ordered]@{ region = ("$location" -replace '\s', '').ToLowerInvariant(); resourceGroup = $ResourceGroup; recordedUtc = [datetime]::UtcNow.ToString('o') }
            if ($envObj) { $facts['network'] = $(if ([bool]$envObj.properties.vnetConfiguration.internal) { 'internal' } else { 'external' }) }
            [void](& $Sql "MERGE pim.Settings AS t USING (SELECT N'AsBuiltInstallFacts' AS Name, @v AS V) AS s ON t.Name = s.Name WHEN MATCHED AND ISNULL(JSON_VALUE(t.ValueJson, '$.region'), N'') + N'|' + ISNULL(JSON_VALUE(t.ValueJson, '$.network'), N'') <> ISNULL(JSON_VALUE(s.V, '$.region'), N'') + N'|' + ISNULL(JSON_VALUE(s.V, '$.network'), N'') THEN UPDATE SET ValueJson = s.V, UpdatedUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (s.Name, s.V, SYSUTCDATETIME());" @{ v = ($facts | ConvertTo-Json -Compress) })
            & $add 'asbuilt-sql' 'info' "as-built: view pim.vw_AsBuiltSettings$(if ($appId) { ', the job''s reader user' }) and the install facts converged"
        } else { & $add 'asbuilt-sql' 'warn' 'as-built: no SQL store in this run -- the view and the job''s reader user were not converged' }
    } catch { & $add 'asbuilt' 'warn' "as-built: converge stopped: $(("$($_.Exception.Message)" -split "`n")[0])" }
    $arr = @($lines.ToArray())
    return [pscustomobject]@{ lines = $arr; changed = @($arr | Where-Object { $_.level -eq 'changed' }).Count; warnings = @($arr | Where-Object { $_.level -eq 'warn' }).Count; jobImage = $jobImage; identity = $idOut }
}

function Get-PimAsBuiltLifecyclePolicy {
    <# PURE. The storage management policy body: delete block blobs under asbuilt/ one day after they were written. #>
    param([string]$Container = $script:PimAsBuiltContainer, [int]$Days = 1)
    return @{ properties = @{ policy = @{ rules = @(@{
        name = 'pim-asbuilt-delete-after-1-day'; enabled = $true; type = 'Lifecycle'
        definition = @{ filters = @{ blobTypes = @('blockBlob'); prefixMatch = @("$Container/") }
                        actions = @{ baseBlob = @{ delete = @{ daysAfterModificationGreaterThan = $Days } } } }
    }) } } }
}

function Get-PimAsBuiltRoleDefinition {
    <#
      PURE. The custom role the Invardia Support app gets on the ONE job: start it and read its executions -- nothing else
      (no job read, no logs, no secrets, no stop). Assignable at the resource group (ARM does not take a resource as an
      assignable scope); ASSIGNED at the job only. The definition id is stable per resource group (a name-based GUID).
      Returns @{ id (guid); path; body }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $b = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes(("pim-asbuilt-runner|$rgId").ToLowerInvariant())) } finally { $md5.Dispose() }
    $b[6] = ($b[6] -band 0x0f) -bor 0x30; $b[8] = ($b[8] -band 0x3f) -bor 0x80
    $hx = ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant()
    $g = '{0}-{1}-{2}-{3}-{4}' -f $hx.Substring(0, 8), $hx.Substring(8, 4), $hx.Substring(12, 4), $hx.Substring(16, 4), $hx.Substring(20, 12)
    $body = @{ properties = @{
        roleName = "$script:PimAsBuiltRoleName ($ResourceGroup)"
        description = 'PIM Manager: start the as-built job (caj-pim-asbuilt) and read its executions. Nothing else.'
        type = 'CustomRole'
        permissions = @(@{ actions = @($script:PimAsBuiltRoleActions); notActions = @(); dataActions = @(); notDataActions = @() })
        assignableScopes = @($rgId)
    } }
    return @{ id = $g; path = "$rgId/providers/Microsoft.Authorization/roleDefinitions/$g"; body = $body }
}

function Get-PimAsBuiltSupportGrants {
    <#
      PURE. What the Invardia Support app gets for the as-built document (framework 8.12) -- exactly two assignments:
        * the custom role (start + read executions) on the job caj-pim-asbuilt;
        * Storage Blob Data Reader on the ONE container 'asbuilt' of the PIM storage account.
      Returns @( @{ what; roleDefinitionId; scope } ).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$StorageAccount,
          [string]$JobName = $script:PimAsBuiltJobName, [string]$Container = $script:PimAsBuiltContainer, [string]$StorageResourceGroup = '')
    $srg = if ("$StorageResourceGroup".Trim()) { "$StorageResourceGroup".Trim() } else { $ResourceGroup }
    $rd = Get-PimAsBuiltRoleDefinition -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    return @(
        @{ what = 'start the as-built job and read its executions'; roleDefinitionId = $rd.path
           scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName" }
        @{ what = 'read the as-built PDFs (Storage Blob Data Reader)'; roleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$script:PimAsBuiltBlobReaderRoleId"
           scope = "/subscriptions/$SubscriptionId/resourceGroups/$srg/providers/Microsoft.Storage/storageAccounts/$StorageAccount/blobServices/default/containers/$Container" }
    )
}
