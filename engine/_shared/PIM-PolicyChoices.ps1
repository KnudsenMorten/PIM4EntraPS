<#
  PIM Manager -- PIM 100.93 POLICY CHOICES: the customer decides every policy setting.

  Owner 2026-10-12: "we will newer force a policy chg on a customer. for policies we must let customer decide ... customer
  must choose per setting and select use ms default, use recommendation, keep current ... it must still be approved as guard".

  THE RULE. The engine never writes a PIM policy rule on its own. A rule is written only when a CHOICE exists for that
  rule's field and the choice is not 'keep'. A field without a choice is not touched and is reported as "waiting for your
  choice" -- never an error, never a failure, never drift. There is NO tenant-wide mode and no "use default for all".

    one choice     per FIELD per POLICY TYPE (directoryRole | groupMember | groupOwner | azureRole); a single role / group /
                   Azure scope+role can carry an OVERRIDE for a field
    choice values  microsoft (Microsoft default) | recommendation (what the bound policy template gives, after the
                   operational floors) | keep (leave as it is)
    resolution     local override > local type choice > managing-tenant override > managing-tenant type choice > none
    advisory       every template field carries an advisory number; a SHIPPED template change that changes the recommended
                   value of a field raises it (a customer's own template edit never does). A choice made on an older number
                   is "asked again" (needsReview): until answered, NOTHING is written for that field.
    guard          every change set that comes from choices is HELD until a SuperAdmin approves that exact plan hash
                   (Test-PimPolicyBreaker in PIM-EngineProviders.ps1) -- whatever its size.

  STORES (pim.Settings, JSON):
    PolicyChoices             { schema; types: { <type>: { <fieldId>: { choice, by, utc, advisory, source } } };
                                overrides: { '<type>|<object key>': { <fieldId>: {...} } };
                                managingTenant: { types: {...}; overrides: {...}; receivedUtc } }   (source 'local' | 'managing-tenant')
                              managingTenant is what a MANAGED tenant pulled from its managing tenant (the signed downlink;
                              engine\msp\PIM-PolicyChoicesMsp.ps1 replaces that block and nothing else). A local choice
                              always wins; a local 'keep' = do not follow the managing tenant for that setting.
    PolicyAdvisories          { schema; templates: { <templateId>: { <type>: { <fieldId>: { hash, advisory } } } } }
    PolicyAdvisories also keeps  microsoft: { <type>: { <fieldId>: { hash, advisory } } }  (a shipped Microsoft-default change)
    MicrosoftPolicyDefaults   the tenant CROSS-CHECK of the shipped table templates/policy/microsoft-defaults.json:
                              { schema; refreshedUtc; types: { <type>: { <fieldId>: { value, source, readUtc, policies,
                                matchesShipped (true | false | 'unknown') } } } } -- reported, never what is written
    PolicyLiveValuesGroups / PolicyLiveValuesEntraRoles / PolicyLiveValuesAzureRoles
                              the last policy run's live read per field (what the page shows as "current"), written by
                              the engine's policy providers -- one setting per provider, so two jobs never write the same row.

  This file has NO dependency on PIM-EngineProviders.ps1 (PIM Manager loads it without the engine). The tenant readers
  take script-block seams; their defaults use Invoke-PimGraph / Invoke-PimArm (REST only -- no module, no az).
  PS 5.1; ASCII only (no BOM).
#>

Set-StrictMode -Off

$script:PimPolicyChoiceTypes  = @('directoryRole', 'groupMember', 'groupOwner', 'azureRole')
$script:PimPolicyChoiceValues = @('microsoft', 'recommendation', 'keep')
$script:PimPolicyChoiceLabels = @{ microsoft = 'Microsoft default'; recommendation = 'PIM Manager recommendation'; keep = 'Keep current' }
$script:PimPolicyChoiceTypeLabels = @{ directoryRole = 'Entra roles'; groupMember = 'Groups (members)'; groupOwner = 'Groups (owners)'; azureRole = 'Azure roles' }
$script:PimPolicyChoiceProviderTypes = @{ GroupsPolicies = @('groupMember', 'groupOwner'); EntraRolePolicies = @('directoryRole'); AzResPolicies = @('azureRole') }
$script:PimPolicyLiveValueSettings = @{ GroupsPolicies = 'PolicyLiveValuesGroups'; EntraRolePolicies = 'PolicyLiveValuesEntraRoles'; AzResPolicies = 'PolicyLiveValuesAzureRoles' }
$script:PimPolicyChoiceTokens = @('MultiFactorAuthentication', 'Justification', 'Ticketing')

function Get-PimPolicyChoicesSettingName { 'PolicyChoices' }
function Get-PimPolicyAdvisoriesSettingName { 'PolicyAdvisories' }
function Get-PimMicrosoftPolicyDefaultsSettingName { 'MicrosoftPolicyDefaults' }
function Get-PimPolicyChoiceTypes { @($script:PimPolicyChoiceTypes) }
function Get-PimPolicyChoiceValues { @($script:PimPolicyChoiceValues) }
function Get-PimPolicyChoiceLabel { param([string]$Choice) $c = "$Choice".Trim().ToLowerInvariant(); if ($script:PimPolicyChoiceLabels.ContainsKey($c)) { $script:PimPolicyChoiceLabels[$c] } else { '' } }
function Get-PimPolicyChoiceTypeLabel { param([string]$Type) if ($script:PimPolicyChoiceTypeLabels.ContainsKey("$Type")) { $script:PimPolicyChoiceTypeLabels["$Type"] } else { "$Type" } }
function Get-PimPolicyLiveValuesSettingName { param([Parameter(Mandatory)][string]$Provider) "$($script:PimPolicyLiveValueSettings[$Provider])" }

# ---------------------------------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPcProp {
    # One property of a hashtable / ordered dictionary / PSObject; $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}
function Test-PimPcHas {
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return [bool]$Object.Contains($Name) }
    return [bool]$Object.PSObject.Properties[$Name]
}
function Get-PimPcList {
    # A list-valued property without the $null a missing property would put in @(...).
    param([AllowNull()][object]$Object, [string]$Name)
    @(@(Get-PimPcProp $Object $Name) | Where-Object { $null -ne $_ })
}
function Get-PimPcNames {
    param([AllowNull()][object]$Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { "$_" }) }
    if ($Object -is [string] -or $Object -is [ValueType]) { return @() }
    return @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}
function ConvertFrom-PimPcSetting {
    # A pim.Settings value may arrive as a JSON string or as an already parsed object.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $v = $Value
    foreach ($pass in 1, 2) {      # twice: a JSON text that was itself stored as a JSON string
        if (-not ($v -is [string])) { break }
        $s = $v.Trim(); if (-not $s) { return $null }
        try { $v = ($s | ConvertFrom-Json) } catch { return $null }
    }
    if ($v -is [string]) { return $null }
    return $v
}
function ConvertTo-PimPcUtcText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    return "$Value"
}
function Get-PimPcHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Text")) } finally { $sha.Dispose() }
    (-join ($b | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)
}
function ConvertTo-PimPcSortedText {
    param([AllowNull()][object]$Values)
    @(@($Values) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique) -join ','
}
function Test-PimPcNeverModified {
    # The same rule as Test-PimGraphPolicyNeverModified: the object CARRIES lastModifiedDateTime and it is empty.
    param([AllowNull()][object]$Policy)
    if ($null -eq $Policy) { return $false }
    if (-not (Test-PimPcHas $Policy 'lastModifiedDateTime')) { return $false }
    return (-not "$(Get-PimPcProp $Policy 'lastModifiedDateTime')".Trim())
}

# ---------------------------------------------------------------------------------------------------------------------
# THE FIELD CATALOG
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPolicyFieldCatalog {
    <#
      PURE. Every policy setting the customer chooses: stable id, plain label + one-sentence help, the policy types it
      applies to, and the rule id(s) + property it is stored in.
        kind  expiration   one Expiration_* rule (maximumDuration + isExpirationRequired)
              token        ONE entry of Enablement_EndUser_Assignment.enabledRules (the rule carries three fields: a write
                           changes only the decided entry and keeps the live value of the others)
              ruleset      a whole Enablement_Admin_* rule (enabledRules)
              approval     Approval_EndUser_Assignment (setting.isApprovalRequired; the approvers stay on the delegation row)
              notification the three Notification_<audience>_* rules
    #>
    $all = @('directoryRole', 'groupMember', 'groupOwner', 'azureRole')
    $notify = {
        param($aud)
        @("Notification_${aud}_EndUser_Assignment", "Notification_${aud}_Admin_Assignment", "Notification_${aud}_Admin_Eligibility")
    }
    @(
        [pscustomobject]@{ id = 'activationMaxDuration'; label = 'Longest activation'; help = 'How long one activation can last at most.'
            kind = 'expiration'; types = $all; ruleIds = @('Expiration_EndUser_Assignment'); target = 'EndUser_Assignment'; property = 'maximumDuration'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'activationRequireMfa'; label = 'Activation needs multifactor authentication'; help = 'The person must sign in with multifactor authentication to activate.'
            kind = 'token'; types = $all; ruleIds = @('Enablement_EndUser_Assignment'); target = 'EndUser_Assignment'; property = 'enabledRules'; token = 'MultiFactorAuthentication'; audience = '' }
        [pscustomobject]@{ id = 'activationRequireJustification'; label = 'Activation needs a reason'; help = 'The person must write why they activate.'
            kind = 'token'; types = $all; ruleIds = @('Enablement_EndUser_Assignment'); target = 'EndUser_Assignment'; property = 'enabledRules'; token = 'Justification'; audience = '' }
        [pscustomobject]@{ id = 'activationRequireTicket'; label = 'Activation needs a ticket'; help = 'The person must give a ticket number to activate.'
            kind = 'token'; types = $all; ruleIds = @('Enablement_EndUser_Assignment'); target = 'EndUser_Assignment'; property = 'enabledRules'; token = 'Ticketing'; audience = '' }
        [pscustomobject]@{ id = 'approvalRequired'; label = 'Approval needed to activate'; help = 'Somebody must approve an activation before it starts. Who approves stays on the delegation.'
            kind = 'approval'; types = @('directoryRole', 'groupMember', 'azureRole'); ruleIds = @('Approval_EndUser_Assignment'); target = 'EndUser_Assignment'; property = 'setting.isApprovalRequired'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'eligibleAssignmentExpiry'; label = 'Eligible assignment must expire, and the longest it can last'; help = 'Whether an eligible assignment must have an end date, and the longest it may run.'
            kind = 'expiration'; types = $all; ruleIds = @('Expiration_Admin_Eligibility'); target = 'Admin_Eligibility'; property = 'isExpirationRequired, maximumDuration'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'activeAssignmentExpiry'; label = 'Active assignment must expire, and the longest it can last'; help = 'Whether an active (always-on) assignment must have an end date, and the longest it may run.'
            kind = 'expiration'; types = $all; ruleIds = @('Expiration_Admin_Assignment'); target = 'Admin_Assignment'; property = 'isExpirationRequired, maximumDuration'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'adminEligibleAssignmentChecks'; label = 'Checks when an admin makes an eligible assignment'; help = 'What an administrator must provide when making somebody eligible.'
            kind = 'ruleset'; types = $all; ruleIds = @('Enablement_Admin_Eligibility'); target = 'Admin_Eligibility'; property = 'enabledRules'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'adminActiveAssignmentChecks'; label = 'Checks when an admin makes an active assignment'; help = 'What an administrator must provide when making an active assignment.'
            kind = 'ruleset'; types = $all; ruleIds = @('Enablement_Admin_Assignment'); target = 'Admin_Assignment'; property = 'enabledRules'; token = ''; audience = '' }
        [pscustomobject]@{ id = 'notifyAdmins'; label = 'Notification mails to administrators'; help = 'The mails administrators get when somebody is assigned or activates.'
            kind = 'notification'; types = $all; ruleIds = @(& $notify 'Admin'); target = ''; property = 'notificationLevel, isDefaultRecipientsEnabled, notificationRecipients'; token = ''; audience = 'Admin' }
        [pscustomobject]@{ id = 'notifyRequester'; label = 'Notification mails to the person'; help = 'The mails the assigned or activating person gets.'
            kind = 'notification'; types = $all; ruleIds = @(& $notify 'Requestor'); target = ''; property = 'notificationLevel, isDefaultRecipientsEnabled, notificationRecipients'; token = ''; audience = 'Requestor' }
        [pscustomobject]@{ id = 'notifyApprovers'; label = 'Notification mails to approvers'; help = 'The mails approvers get about a request.'
            kind = 'notification'; types = $all; ruleIds = @(& $notify 'Approver'); target = ''; property = 'notificationLevel, isDefaultRecipientsEnabled, notificationRecipients'; token = ''; audience = 'Approver' }
    )
}
function Get-PimPolicyField {
    param([string]$Id)
    if (-not $script:PimPolicyFieldIndex) { $script:PimPolicyFieldIndex = @{}; foreach ($f in @(Get-PimPolicyFieldCatalog)) { $script:PimPolicyFieldIndex["$($f.id)".ToLowerInvariant()] = $f } }
    $script:PimPolicyFieldIndex["$Id".Trim().ToLowerInvariant()]
}
function Get-PimPolicyFieldsForType {
    param([Parameter(Mandatory)][string]$Type)
    @(Get-PimPolicyFieldCatalog | Where-Object { @($_.types) -contains $Type })
}
function Get-PimPolicyChoiceObjectKey {
    # PURE. The key an OVERRIDE is stored under for one policy: '<type>|<object key>' (lower-case).
    param([Parameter(Mandatory)][string]$Type, [string]$ObjectKey)
    ("{0}|{1}" -f "$Type".Trim(), "$ObjectKey".Trim().ToLowerInvariant())
}
function Get-PimPolicyChoiceRowIdentity {
    <# PURE. Which policy type and object a provider's desired row is: GroupsPolicies -> groupMember / groupOwner + the
       group name; EntraRolePolicies -> directoryRole + the role name; AzResPolicies -> azureRole + '<scope>|<role>'. #>
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Row)
    switch ("$Provider".Trim().ToLowerInvariant()) {
        'groupspolicies' {
            $n = "$(Get-PimPcProp $Row 'GroupName')".Trim()
            $t = if ("$(Get-PimPcProp $Row 'PolicyRole')" -eq 'owner') { 'groupOwner' } else { 'groupMember' }
            return [pscustomobject]@{ type = $t; objectKey = $n.ToLowerInvariant(); name = $(if ($t -eq 'groupOwner') { "$n (owner)" } else { $n }) }
        }
        'entrarolepolicies' {
            $n = "$(Get-PimPcProp $Row 'RoleDefinitionName')".Trim(); if (-not $n) { $n = "$(Get-PimPcProp $Row 'GroupName')".Trim() }
            return [pscustomobject]@{ type = 'directoryRole'; objectKey = $n.ToLowerInvariant(); name = $n }
        }
        'azrespolicies' {
            $s = "$(Get-PimPcProp $Row 'AzScope')".Trim().TrimEnd('/'); $r = "$(Get-PimPcProp $Row 'RoleName')".Trim()
            return [pscustomobject]@{ type = 'azureRole'; objectKey = ("{0}|{1}" -f $s, $r).ToLowerInvariant(); name = "$r @ $s" }
        }
    }
    throw "policy choices: unknown provider '$Provider' (known: GroupsPolicies, EntraRolePolicies, AzResPolicies)"
}

# ---------------------------------------------------------------------------------------------------------------------
# FIELD VALUES -- one shape per kind, read the same way from a live rule set, a template row and a stored default
#   expiration    @{ maximumDuration; isExpirationRequired }
#   token         @{ required }
#   approval      @{ required }
#   ruleset       @{ enabledRules = @(...) }
#   notification  @{ rules = @{ <ruleId> = @{ notificationLevel; isDefaultRecipientsEnabled; notificationRecipients } } }
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimPolicyRuleMap {
    # PURE. A rules collection (Graph `rules` / ARM `effectiveRules`) -> rule id -> rule.
    param([AllowNull()][object[]]$Rules)
    $m = @{}
    foreach ($r in @($Rules)) { if ($null -eq $r) { continue }; $id = "$(Get-PimPcProp $r 'id')"; if ($id) { $m[$id] = $r } }
    $m
}
function Get-PimPolicyLiveFieldValue {
    # PURE. The value ONE field holds in a rule map; $null when the rule(s) it lives in are not there.
    param([Parameter(Mandatory)][object]$Field, [hashtable]$RuleMap = @{})
    switch ("$($Field.kind)") {
        'expiration' {
            $r = $RuleMap["$($Field.ruleIds[0])"]; if ($null -eq $r) { return $null }
            return @{ maximumDuration = "$(Get-PimPcProp $r 'maximumDuration')".Trim(); isExpirationRequired = [bool](Get-PimPcProp $r 'isExpirationRequired') }
        }
        'token' {
            $r = $RuleMap["$($Field.ruleIds[0])"]; if ($null -eq $r) { return $null }
            return @{ required = [bool](@(@(Get-PimPcProp $r 'enabledRules') | ForEach-Object { "$_" }) -contains "$($Field.token)") }
        }
        'ruleset' {
            $r = $RuleMap["$($Field.ruleIds[0])"]; if ($null -eq $r) { return $null }
            return @{ enabledRules = @(@(Get-PimPcProp $r 'enabledRules') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique) }
        }
        'approval' {
            # A policy that carries rules but NO approval rule has approval off (the same reading Test-PimGroupPolicyInSync makes).
            if (-not $RuleMap.Count) { return $null }
            $r = $RuleMap['Approval_EndUser_Assignment']; if ($null -eq $r) { return @{ required = $false } }
            $s = Get-PimPcProp $r 'setting'
            return @{ required = [bool]$(if ($s) { Get-PimPcProp $s 'isApprovalRequired' } else { $false }) }
        }
        'notification' {
            $rules = @{}
            foreach ($rid in @($Field.ruleIds)) {
                $r = $RuleMap["$rid"]; if ($null -eq $r) { continue }
                $lvl = "$(Get-PimPcProp $r 'notificationLevel')"; if (-not $lvl) { $lvl = 'All' }
                $rules["$rid"] = @{ notificationLevel = $lvl; isDefaultRecipientsEnabled = [bool](Get-PimPcProp $r 'isDefaultRecipientsEnabled')
                                    notificationRecipients = @(Get-PimPcList $r 'notificationRecipients' | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
            }
            if (-not $rules.Count) { return $null }
            return @{ rules = $rules }
        }
    }
    return $null
}
function Get-PimPolicyRowFieldValue {
    <#
      PURE. The value a TEMPLATE gives ONE field -- read from a provider's desired row (Expiration / Enablement /
      EnablementLegacy / Notification / Approval, the shape Get-PimGroupsPolicyDesiredSet, Get-PimEntraRolePolicyDesiredSet
      and Get-PimAzResPolicyDesiredSet emit) or from a template's own `rules` block (same member names). $null = the
      template says nothing about this field (there is then no recommendation for it).
    #>
    param([Parameter(Mandatory)][object]$Field, [AllowNull()][object]$Row)
    if ($null -eq $Row) { return $null }
    switch ("$($Field.kind)") {
        'expiration' {
            $ex = Get-PimPcProp $Row 'Expiration'; if ($null -eq $ex) { return $null }
            if ($ex -is [string]) {
                if ("$($Field.target)" -ne 'EndUser_Assignment' -or -not $ex.Trim()) { return $null }
                return @{ maximumDuration = $ex.Trim(); isExpirationRequired = $true }
            }
            if (-not (Test-PimPcHas $ex "$($Field.target)")) { return $null }
            $v = Get-PimPcProp $ex "$($Field.target)"; if ($null -eq $v) { return $null }
            if ($v -is [string]) { if (-not $v.Trim()) { return $null }; return @{ maximumDuration = $v.Trim(); isExpirationRequired = $true } }
            $dur = "$(Get-PimPcProp $v 'maximumDuration')".Trim(); if (-not $dur) { return $null }
            $req = $true; if (Test-PimPcHas $v 'isExpirationRequired') { $req = [bool](Get-PimPcProp $v 'isExpirationRequired') }
            return @{ maximumDuration = $dur; isExpirationRequired = $req }
        }
        { $_ -in 'token', 'ruleset' } {
            $en = Get-PimPcProp $Row 'Enablement'; $set = $null
            if ($null -ne $en) { if (Test-PimPcHas $en "$($Field.target)") { $set = @(Get-PimPcProp $en "$($Field.target)") } else { return $null } }
            elseif ("$($Field.target)" -eq 'EndUser_Assignment') {
                $leg = Get-PimPcProp $Row 'EnablementLegacy'
                if ($null -eq $leg) { $leg = Get-PimPcProp $Row 'Member_Enablement_EndUser_Assignment_enabledRules' }
                if ($null -eq $leg) { return $null }
                $set = @($leg)
            } else { return $null }
            $set = @($set | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
            if ("$($Field.kind)" -eq 'token') { return @{ required = [bool]($set -contains "$($Field.token)") } }
            return @{ enabledRules = @($set | Sort-Object -Unique) }
        }
        'approval' {
            # A template WITH an Approval block asks for approval; one without asks for none. A row the engine does not
            # manage approval on (an owner policy, ManageApproval = false) has no recommendation.
            if ((Test-PimPcHas $Row 'ManageApproval') -and -not [bool](Get-PimPcProp $Row 'ManageApproval')) { return $null }
            return @{ required = [bool]($null -ne (Get-PimPcProp $Row 'Approval')) }
        }
        'notification' {
            $rules = @{}
            foreach ($n in @(Get-PimPcProp $Row 'Notification')) {
                if ($null -eq $n) { continue }
                $rt = "$(Get-PimPcProp $n 'recipientType')"; $lvl = "$(Get-PimPcProp $n 'level')"
                if (-not $rt -or -not $lvl -or $rt -ne "$($Field.audience)") { continue }
                $caller = "$(Get-PimPcProp $n 'caller')".Trim(); if (-not $caller) { $caller = 'EndUser' }
                $nl = "$(Get-PimPcProp $n 'notificationLevel')"; if (-not $nl) { $nl = 'All' }
                $defRaw = Get-PimPcProp $n 'defaultRecipientsEnabled'
                $rules["Notification_${rt}_${caller}_${lvl}"] = @{ notificationLevel = $nl; isDefaultRecipientsEnabled = $(if ($null -eq $defRaw) { $true } else { [bool]$defRaw })
                    notificationRecipients = @(@(Get-PimPcProp $n 'recipients') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
            }
            if (-not $rules.Count) { return $null }
            return @{ rules = $rules }
        }
    }
    return $null
}
function Get-PimPolicyFieldValueKey {
    # PURE. One canonical line for a field value -- what two values are compared by and what a spread is grouped on.
    param([Parameter(Mandatory)][object]$Field, [AllowNull()][object]$Value, [string[]]$OnlyRuleIds)
    if ($null -eq $Value) { return '' }
    switch ("$($Field.kind)") {
        'expiration' { return ("dur={0}|req={1}" -f "$(Get-PimPcProp $Value 'maximumDuration')".Trim(), [bool](Get-PimPcProp $Value 'isExpirationRequired')) }
        'token'      { return ("required={0}" -f [bool](Get-PimPcProp $Value 'required')) }
        'approval'   { return ("required={0}" -f [bool](Get-PimPcProp $Value 'required')) }
        'ruleset'    { return ("rules={0}" -f (ConvertTo-PimPcSortedText (Get-PimPcProp $Value 'enabledRules'))) }
        'notification' {
            $rules = Get-PimPcProp $Value 'rules'; $parts = @()
            foreach ($rid in @(Get-PimPcNames $rules | Sort-Object)) {
                if ($OnlyRuleIds -and @($OnlyRuleIds) -notcontains $rid) { continue }
                $r = Get-PimPcProp $rules $rid
                $lvl = "$(Get-PimPcProp $r 'notificationLevel')"; if (-not $lvl) { $lvl = 'All' }
                $parts += ("{0}:lvl={1}|def={2}|recips={3}" -f $rid, $lvl, [bool](Get-PimPcProp $r 'isDefaultRecipientsEnabled'), (ConvertTo-PimPcSortedText (Get-PimPcProp $r 'notificationRecipients')).ToLowerInvariant())
            }
            return ($parts -join ';')
        }
    }
    return ''
}
function Test-PimPolicyFieldValueMatch {
    <# PURE. Does the LIVE value already hold the TARGET? A notification target is compared on the rules the target names
       only (a target that says nothing about one of the three mails does not ask for a change of it). #>
    param([Parameter(Mandatory)][object]$Field, [AllowNull()][object]$Live, [AllowNull()][object]$Target)
    if ($null -eq $Target) { return $true }
    if ($null -eq $Live) { return $false }
    if ("$($Field.kind)" -eq 'notification') {
        $ids = @(Get-PimPcNames (Get-PimPcProp $Target 'rules'))
        return ((Get-PimPolicyFieldValueKey -Field $Field -Value $Live -OnlyRuleIds $ids) -eq (Get-PimPolicyFieldValueKey -Field $Field -Value $Target -OnlyRuleIds $ids))
    }
    return ((Get-PimPolicyFieldValueKey -Field $Field -Value $Live) -eq (Get-PimPolicyFieldValueKey -Field $Field -Value $Target))
}
function ConvertTo-PimPolicyDurationWords {
    # PURE. 'PT8H' -> '8 hours', 'P365D' -> '365 days'. An unreadable duration is shown as it is.
    param([string]$Duration)
    $d = "$Duration".Trim(); if (-not $d) { return 'no limit set' }
    try {
        $ts = [System.Xml.XmlConvert]::ToTimeSpan($d)
        if ($ts.TotalDays -ge 1 -and ($ts.TotalHours % 24) -eq 0) { $n = [int]$ts.TotalDays; return ("{0} day{1}" -f $n, $(if ($n -eq 1) { '' } else { 's' })) }
        if ($ts.TotalHours -ge 1 -and ($ts.TotalMinutes % 60) -eq 0) { $n = [int]$ts.TotalHours; return ("{0} hour{1}" -f $n, $(if ($n -eq 1) { '' } else { 's' })) }
        $n = [int]$ts.TotalMinutes; return ("{0} minute{1}" -f $n, $(if ($n -eq 1) { '' } else { 's' }))
    } catch { return $d }
}
function Format-PimPolicyFieldValue {
    # PURE. A field value in plain words, for a button or a list.
    param([Parameter(Mandatory)][object]$Field, [AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'Not set' }
    $tokenWords = @{ MultiFactorAuthentication = 'multifactor authentication'; Justification = 'a reason'; Ticketing = 'a ticket' }
    switch ("$($Field.kind)") {
        'expiration' {
            $dur = ConvertTo-PimPolicyDurationWords "$(Get-PimPcProp $Value 'maximumDuration')"
            if ("$($Field.id)" -eq 'activationMaxDuration') { return $dur }
            if ([bool](Get-PimPcProp $Value 'isExpirationRequired')) { return "Must expire, longest $dur" }
            return 'May be permanent'
        }
        { $_ -in 'token', 'approval' } { if ([bool](Get-PimPcProp $Value 'required')) { return 'Yes' } else { return 'No' } }
        'ruleset' {
            $set = @(@(Get-PimPcProp $Value 'enabledRules') | Where-Object { "$_".Trim() })
            if (-not $set.Count) { return 'Nothing' }
            return (Format-PimPolicyRuleSetText (@($set | ForEach-Object { if ($tokenWords.ContainsKey("$_")) { $tokenWords["$_"] } else { "$_" } }) -join ' and '))
        }
        'notification' {
            $rules = Get-PimPcProp $Value 'rules'; $on = 0; $all = 0; $extra = 0
            foreach ($rid in @(Get-PimPcNames $rules)) {
                $r = Get-PimPcProp $rules $rid; $all++
                if ([bool](Get-PimPcProp $r 'isDefaultRecipientsEnabled')) { $on++ }
                $extra += @(@(Get-PimPcProp $r 'notificationRecipients') | Where-Object { "$_".Trim() }).Count
            }
            $t = if ($on -eq $all) { 'On' } elseif ($on -eq 0) { 'Off' } else { "On for $on of $all mails" }
            if ($extra) { $t += ", $extra extra recipient$(if ($extra -eq 1) { '' } else { 's' })" }
            return $t
        }
    }
    return ''
}
function Format-PimPolicyRuleSetText {
    # PS 5.1 has no script-block -replace: capitalise the first letter the plain way.
    param([string]$Text)
    $t = "$Text"; if (-not $t) { return $t }
    return ($t.Substring(0, 1).ToUpperInvariant() + $t.Substring(1))
}

# ---------------------------------------------------------------------------------------------------------------------
# THE CHOICES STORE
# ---------------------------------------------------------------------------------------------------------------------
function New-PimPolicyChoicesStore {
    @{ schema = 1; types = @{}; overrides = @{}; managingTenant = @{ types = @{}; overrides = @{} } }
}
function ConvertTo-PimPolicyChoiceEntry {
    # PURE. One stored choice, normalised; $null when it is not a valid choice.
    param([AllowNull()][object]$Entry, [string]$DefaultSource = 'local')
    if ($null -eq $Entry) { return $null }
    $c = "$(Get-PimPcProp $Entry 'choice')".Trim().ToLowerInvariant()
    if ($script:PimPolicyChoiceValues -notcontains $c) { return $null }
    $adv = 0; [void][int]::TryParse("$(Get-PimPcProp $Entry 'advisory')", [ref]$adv)
    $src = "$(Get-PimPcProp $Entry 'source')".Trim(); if ($src -notin @('local', 'managing-tenant')) { $src = $DefaultSource }
    @{ choice = $c; by = "$(Get-PimPcProp $Entry 'by')"; utc = (ConvertTo-PimPcUtcText (Get-PimPcProp $Entry 'utc')); advisory = $adv; source = $src }
}
function ConvertTo-PimPolicyChoicesStore {
    <# PURE. Whatever is stored (a JSON string, a parsed object, a hashtable, nothing) -> the normalised store. An unknown
       type, an unknown field, a field that does not apply to the type and an invalid choice are DROPPED (-Dropped lists
       them): a choice that cannot be understood decides nothing, so the field is back on "waiting for your choice". #>
    param([AllowNull()][object]$Value, [System.Collections.Generic.List[string]]$Dropped)
    $out = New-PimPolicyChoicesStore
    $v = ConvertFrom-PimPcSetting $Value
    if ($null -eq $v) { return $out }
    $readTypes = {
        param($src, $dst, $defSource, $where)
        foreach ($t in @(Get-PimPcNames $src)) {
            if ($script:PimPolicyChoiceTypes -notcontains $t) { if ($null -ne $Dropped) { $Dropped.Add("$where type '$t' is not a policy type") }; continue }
            foreach ($f in @(Get-PimPcNames (Get-PimPcProp $src $t))) {
                $fd = Get-PimPolicyField -Id $f
                if (-not $fd -or @($fd.types) -notcontains $t) { if ($null -ne $Dropped) { $Dropped.Add("$where $t/$f is not a setting of that policy type") }; continue }
                $e = ConvertTo-PimPolicyChoiceEntry -Entry (Get-PimPcProp (Get-PimPcProp $src $t) $f) -DefaultSource $defSource
                if (-not $e) { if ($null -ne $Dropped) { $Dropped.Add("$where $t/$f has no valid choice") }; continue }
                $e.source = $defSource
                if (-not $dst.ContainsKey($t)) { $dst[$t] = @{} }
                $dst[$t]["$($fd.id)"] = $e
            }
        }
    }
    $readOverrides = {
        param($src, $dst, $defSource, $where)
        foreach ($k in @(Get-PimPcNames $src)) {
            $i = "$k".IndexOf('|'); if ($i -lt 1) { if ($null -ne $Dropped) { $Dropped.Add("$where override '$k' has no '<type>|<object>' key") }; continue }
            $t = "$k".Substring(0, $i); $obj = "$k".Substring($i + 1).Trim().ToLowerInvariant()
            if ($script:PimPolicyChoiceTypes -notcontains $t -or -not $obj) { if ($null -ne $Dropped) { $Dropped.Add("$where override '$k' names no policy type / object") }; continue }
            foreach ($f in @(Get-PimPcNames (Get-PimPcProp $src $k))) {
                $fd = Get-PimPolicyField -Id $f
                if (-not $fd -or @($fd.types) -notcontains $t) { if ($null -ne $Dropped) { $Dropped.Add("$where override $k/$f is not a setting of that policy type") }; continue }
                $e = ConvertTo-PimPolicyChoiceEntry -Entry (Get-PimPcProp (Get-PimPcProp $src $k) $f) -DefaultSource $defSource
                if (-not $e) { if ($null -ne $Dropped) { $Dropped.Add("$where override $k/$f has no valid choice") }; continue }
                $e.source = $defSource
                $nk = "$t|$obj"
                if (-not $dst.ContainsKey($nk)) { $dst[$nk] = @{} }
                $dst[$nk]["$($fd.id)"] = $e
            }
        }
    }
    & $readTypes (Get-PimPcProp $v 'types') $out.types 'local' 'local'
    & $readOverrides (Get-PimPcProp $v 'overrides') $out.overrides 'local' 'local'
    $mt = Get-PimPcProp $v 'managingTenant'
    if ($null -ne $mt) {
        & $readTypes (Get-PimPcProp $mt 'types') $out.managingTenant.types 'managing-tenant' 'managing tenant'
        & $readOverrides (Get-PimPcProp $mt 'overrides') $out.managingTenant.overrides 'managing-tenant' 'managing tenant'
        if (Test-PimPcHas $mt 'receivedUtc') { $out.managingTenant['receivedUtc'] = ConvertTo-PimPcUtcText (Get-PimPcProp $mt 'receivedUtc') }
    }
    $out
}
function Test-PimPolicyChoiceAllowed {
    <#
      PURE. May this choice be SAVED for this field of this type? @{ ok; reason }. Refused:
        * an unknown type / field / choice, or a field that does not apply to the type;
        * 'microsoft' for approval on an Azure role: PIM Manager never switches approval off on an Azure role policy;
        * 'microsoft' for an admin-assignment check when Microsoft's default asks for multifactor authentication there --
          PIM Manager's own identity cannot present it, so it could no longer assign anyone (BUG-21).
    #>
    param([string]$Type, [string]$FieldId, [string]$Choice, [AllowNull()][object]$Defaults)
    $c = "$Choice".Trim().ToLowerInvariant()
    if ($script:PimPolicyChoiceTypes -notcontains "$Type") { return @{ ok = $false; reason = "'$Type' is not a policy type (directoryRole, groupMember, groupOwner, azureRole)." } }
    $fd = Get-PimPolicyField -Id $FieldId
    if (-not $fd) { return @{ ok = $false; reason = "'$FieldId' is not a policy setting." } }
    if (@($fd.types) -notcontains "$Type") { return @{ ok = $false; reason = "'$($fd.label)' is not a setting of $(Get-PimPolicyChoiceTypeLabel $Type)." } }
    if ($c -ne 'none' -and $script:PimPolicyChoiceValues -notcontains $c) { return @{ ok = $false; reason = "Choose Microsoft default, PIM Manager recommendation or Keep current." } }
    if ($c -eq 'microsoft') {
        $block = Get-PimPolicyChoiceTargetBlock -Type $Type -Field $fd -Target (Get-PimPcProp (Get-PimMicrosoftPolicyDefaultEntry -Defaults $Defaults -Type $Type -FieldId $fd.id) 'value')
        $me = Get-PimMicrosoftPolicyDefaultEntry -Defaults $Defaults -Type $Type -FieldId $fd.id
        if ($me -and -not [bool](Get-PimPcProp $me 'verified')) { return @{ ok = $false; reason = (Get-PimMicrosoftPolicyDefaultUnverifiedText) } }
        if ($block) { return @{ ok = $false; reason = $block } }
    }
    @{ ok = $true; reason = '' }
}
function Get-PimPolicyChoiceTargetBlock {
    # PURE. Why a target value must never be written ('' = it may). The two cases Test-PimPolicyChoiceAllowed names.
    param([string]$Type, [Parameter(Mandatory)][object]$Field, [AllowNull()][object]$Target)
    if ($null -eq $Target) { return '' }
    if ("$($Field.kind)" -eq 'approval' -and "$Type" -eq 'azureRole' -and -not [bool](Get-PimPcProp $Target 'required')) {
        return 'PIM Manager never switches approval off on an Azure role policy. Choose Keep current, or change it in Azure.'
    }
    if ("$($Field.kind)" -eq 'ruleset' -and @(@(Get-PimPcProp $Target 'enabledRules') | ForEach-Object { "$_" }) -contains 'MultiFactorAuthentication') {
        return 'This value asks an administrator for multifactor authentication when assigning. PIM Manager signs in as an app and cannot do that, so it could no longer assign anyone. Choose Keep current or PIM Manager recommendation.'
    }
    ''
}
function Set-PimPolicyChoiceInStore {
    <#
      PURE. One choice written into a normalised store; returns @{ store; before; after; changed }.
        -ObjectKey ''  = the choice for the whole policy TYPE;  a value = an OVERRIDE for that one role / group / Azure
                         scope+role ('<scope>|<role>' for Azure).
        -Choice 'none' = take the choice away again (the field is back on "waiting for your choice", or an override falls
                         back to the type's choice).
      Records who, when and the field's CURRENT advisory number. WHO may call this is the caller's job (SuperAdmin).
      -Source 'managing-tenant' writes the managing tenant's block (tests; the MSP pull replaces that block as a whole --
      engine\msp\PIM-PolicyChoicesMsp.ps1).
    #>
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$FieldId, [Parameter(Mandatory)][string]$Choice,
          [string]$ObjectKey = '', [Parameter(Mandatory)][string]$By, [int]$Advisory = 1, [ValidateSet('local', 'managing-tenant')][string]$Source = 'local', [datetime]$NowUtc = [datetime]::UtcNow)
    $fd = Get-PimPolicyField -Id $FieldId
    if (-not $fd -or @($fd.types) -notcontains $Type) { throw "policy choices: '$FieldId' is not a setting of policy type '$Type'." }
    $c = "$Choice".Trim().ToLowerInvariant()
    if ($c -ne 'none' -and $script:PimPolicyChoiceValues -notcontains $c) { throw "policy choices: '$Choice' is not a choice (microsoft, recommendation, keep)." }
    if (-not "$By".Trim()) { throw 'policy choices: who made the choice (-By) is required.' }
    $root = if ($Source -eq 'managing-tenant') { $Store.managingTenant } else { $Store }
    $obj = "$ObjectKey".Trim().ToLowerInvariant()
    $map = if ($obj) { $root.overrides } else { $root.types }
    $key = if ($obj) { "$Type|$obj" } else { $Type }
    $before = $null
    if ($map.ContainsKey($key) -and $map[$key].ContainsKey($fd.id)) { $before = $map[$key][$fd.id] }
    $after = $null
    if ($c -eq 'none') {
        if ($map.ContainsKey($key)) { [void]$map[$key].Remove($fd.id); if (-not $map[$key].Count) { [void]$map.Remove($key) } }
    } else {
        if (-not $map.ContainsKey($key)) { $map[$key] = @{} }
        $after = @{ choice = $c; by = "$By".Trim(); utc = $NowUtc.ToUniversalTime().ToString('o'); advisory = [int]$Advisory; source = $Source }
        $map[$key][$fd.id] = $after
    }
    $changed = ("$(if ($before) { $before.choice })|$(if ($before) { $before.advisory })" -ne "$(if ($after) { $after.choice })|$(if ($after) { $after.advisory })")
    @{ store = $Store; before = $before; after = $after; changed = [bool]$changed }
}
function Resolve-PimPolicyChoice {
    <#
      PURE. THE RESOLVER -- the choice that stands for ONE field of ONE policy:
        local override for the single object > local type choice > managing-tenant override > managing-tenant type choice > none.
      Returns @{ choice ('' = none); origin ('override' | 'type' | ''); source ('local' | 'managing-tenant' | ''); by; utc;
                 advisory (the number the choice was made on); currentAdvisory; needsReview }.
      needsReview = the choice was made on an OLDER advisory number than the field has now: it is asked again, and until
      it is answered nothing is written for the field.
    #>
    param([AllowNull()][hashtable]$Store, [Parameter(Mandatory)][string]$Type, [string]$ObjectKey = '', [Parameter(Mandatory)][string]$FieldId, [AllowNull()][object]$Advisories)
    $fd = Get-PimPolicyField -Id $FieldId
    $cur = Get-PimPolicyFieldAdvisory -Advisories $Advisories -Type $Type -FieldId $FieldId
    $none = @{ choice = ''; origin = ''; source = ''; by = ''; utc = ''; advisory = 0; currentAdvisory = $cur; needsReview = $false }
    if (-not $fd -or $null -eq $Store) { return $none }
    $obj = "$ObjectKey".Trim().ToLowerInvariant()
    $mt = if ($Store.ContainsKey('managingTenant') -and $Store.managingTenant) { $Store.managingTenant } else { @{ types = @{}; overrides = @{} } }
    $steps = @(
        @{ map = $Store.overrides; key = "$Type|$obj"; origin = 'override'; use = [bool]$obj }
        @{ map = $Store.types;     key = $Type;        origin = 'type';     use = $true }
        @{ map = $mt.overrides;    key = "$Type|$obj"; origin = 'override'; use = [bool]$obj }
        @{ map = $mt.types;        key = $Type;        origin = 'type';     use = $true }
    )
    foreach ($s in $steps) {
        if (-not $s.use -or $null -eq $s.map -or -not $s.map.ContainsKey($s.key)) { continue }
        $e = $s.map[$s.key][$fd.id]
        if ($null -eq $e -or $script:PimPolicyChoiceValues -notcontains "$($e.choice)") { continue }
        return @{ choice = "$($e.choice)"; origin = $s.origin; source = "$($e.source)"; by = "$($e.by)"; utc = (ConvertTo-PimPcUtcText $e.utc); advisory = [int]$e.advisory
                  currentAdvisory = $cur; needsReview = ([int]$e.advisory -lt [int]$cur) }
    }
    $none
}

# ---------------------------------------------------------------------------------------------------------------------
# ADVISORY NUMBERS -- derived, so nobody has to remember to raise one
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPolicyTemplateKindName {
    # PURE. The kind of policy a template is written for, from its appliesTo: DirectoryRole -> 'directoryRole';
    # AzureRole / AzureResourceRole -> 'azureRole'; anything else -> 'group'.
    param([string]$AppliesTo)
    $ap = "$AppliesTo".Trim()
    if ($ap -ieq 'DirectoryRole') { return 'directoryRole' }
    if ($ap -ieq 'AzureRole' -or $ap -ieq 'AzureResourceRole') { return 'azureRole' }
    return 'group'
}
function Get-PimPolicyTemplateTypeRows {
    <# PURE. ONE template's merged rules as the rows Get-PimPolicyRowFieldValue reads, per policy type: a group template
       gives groupMember (its rules) and groupOwner (its Owner block, when it has one); a directoryRole / azureRole
       template gives that one type. Shared by the advisory numbers (the SHIPPED files) and the value view (the STORED
       templates), so both read a template the same way. #>
    param([AllowNull()][object]$Rules, [Parameter(Mandatory)][string]$Kind)
    $mk = { param($src, $manageApproval) @{ Expiration = (Get-PimPcProp $src 'Expiration'); Enablement = (Get-PimPcProp $src 'Enablement')
                EnablementLegacy = (Get-PimPcProp $src 'Member_Enablement_EndUser_Assignment_enabledRules'); Notification = @(Get-PimPcProp $src 'Notification')
                Approval = (Get-PimPcProp $src 'Approval'); ManageApproval = $manageApproval } }
    $rows = @{}
    if ("$Kind" -eq 'group') {
        $rows['groupMember'] = & $mk $Rules $true
        $own = Get-PimPcProp $Rules 'Owner'
        if ($null -ne $own) { $rows['groupOwner'] = & $mk $own $false }
    } else { $rows["$Kind"] = & $mk $Rules $true }
    $rows
}
function Get-PimPolicyTemplateShortLabel {
    <# PURE. What a template is called next to a value on a button: its display name without the policy-type lead-in the
       shipped names carry ('PIM for Groups -- standard' -> 'Standard'); a template without a name -> its id without the
       type prefix ('Groups_RequireApproval' -> 'Require approval'). #>
    param([string]$Id, [string]$Name)
    $n = "$Name".Trim()
    if ($n) {
        $i = $n.IndexOf(' -- ')
        if ($i -ge 0 -and $n.Length -gt ($i + 4)) { $n = $n.Substring($i + 4).Trim() }
    } else {
        $n = "$Id".Trim()
        $u = $n.IndexOf('_'); if ($u -ge 0 -and $n.Length -gt ($u + 1)) { $n = $n.Substring($u + 1) }
        $n = ($n -creplace '([a-z0-9])([A-Z])', '$1 $2').Replace('_', ' ').Trim()
        if ($n.Length -gt 1) { $n = $n.Substring(0, 1) + $n.Substring(1).ToLowerInvariant() }
    }
    if (-not $n) { return "$Id" }
    return ($n.Substring(0, 1).ToUpperInvariant() + $n.Substring(1))
}
function Get-PimPolicyRecommendationTemplates {
    <#
      PURE. What the PIM Manager RECOMMENDATION is read from when no policy run has read the tenant yet: the STORED policy
      templates (pim.Settings['PolicyTemplates'], a customer's own edits included), as the ENGINE applies them
      (Get-PimEnginePolicyTemplates): single-level 'extends' merged per top-level key, then the operational floors
      (-OperationalPolicy: the normalised Settings > Operational policy; $null = no floors applied).
        -DefaultsSetting  pim.Settings['PolicyTemplateDefaults'] (which template a blank PolicyTemplate means, per kind)
      Returns @( @{ id; name; label; kind ('group' | 'directoryRole' | 'azureRole'); isDefault; rows = @{ <type> = row } } ),
      per kind the default template first, then by id. Needs PIM-PolicyTemplateStore.ps1 (and PIM-OperationalPolicy.ps1
      for the floors) loaded -- without the template store library there is nothing to read and the list is empty.
    #>
    param([AllowNull()][object]$Stored, [AllowNull()][object]$DefaultsSetting, [AllowNull()][object]$OperationalPolicy)
    if (-not (Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue)) { return @() }
    # (a pim.Settings value may arrive as JSON text, or as JSON text stored as a JSON string)
    if ($Stored -is [string]) { $Stored = ConvertFrom-PimPcSetting $Stored }
    if ($DefaultsSetting -is [string]) { $DefaultsSetting = ConvertFrom-PimPcSetting $DefaultsSetting }
    $map = ConvertTo-PimPolicyTemplateMap -Value $Stored
    if (-not $map.Count) { return @() }
    $haveResolver = [bool](Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue)
    $defaults = @{ group = 'Groups_Standard'; directoryRole = 'EntraIDRoles_Standard'; azureRole = 'AzureRoles_Standard' }
    if (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue) {
        $rd = (Resolve-PimPolicyTemplateTypeDefaults -Setting $DefaultsSetting -Map $map).defaults
        foreach ($k in @('group', 'directoryRole', 'azureRole')) { if ("$($rd[$k])".Trim()) { $defaults[$k] = "$($rd[$k])" } }
    }
    $floor = ($null -ne $OperationalPolicy) -and [bool](Get-Command ConvertTo-PimOperationalFloorRules -ErrorAction SilentlyContinue)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($map.Keys | ForEach-Object { "$_" } | Sort-Object)) {
        $tpl = $map[$id]
        # 'extends' resolves the way the engine resolves it: the id, the current name, a former id
        $ext = "$(Get-PimPcProp $tpl 'extends')".Trim(); $baseKey = ''
        if ($ext) {
            if ($haveResolver) { $baseKey = "$(Resolve-PimPolicyTemplateKey -Map $map -Id $ext)" }
            else { foreach ($k in @($map.Keys)) { if ("$k" -ieq $ext) { $baseKey = "$k"; break } } }
        }
        $base = if ($baseKey) { $map[$baseKey] } else { $null }
        $rules = @{}
        foreach ($src in @($base, $tpl)) {
            if ($null -eq $src) { continue }
            $r = Get-PimPcProp $src 'rules'
            foreach ($n in @(Get-PimPcNames $r)) { $rules[$n] = Get-PimPcProp $r $n }
        }
        if ($floor) { try { $rules = (ConvertTo-PimOperationalFloorRules -Rules $rules -Policy $OperationalPolicy).rules } catch { } }
        $ap = "$(Get-PimPcProp $tpl 'appliesTo')".Trim(); if (-not $ap -and $base) { $ap = "$(Get-PimPcProp $base 'appliesTo')".Trim() }
        $kind = Get-PimPolicyTemplateKindName -AppliesTo $ap
        $name = "$(Get-PimPcProp $tpl 'name')".Trim()
        $list.Add(@{ id = $id; name = $name; label = (Get-PimPolicyTemplateShortLabel -Id $id -Name $name); kind = $kind
                     isDefault = [bool]("$($defaults[$kind])" -ieq $id); rows = (Get-PimPolicyTemplateTypeRows -Rules $rules -Kind $kind) })
    }
    @($list.ToArray() | Sort-Object @{ e = { "$($_.kind)" } }, @{ e = { if ($_.isDefault) { 0 } else { 1 } } }, @{ e = { "$($_.id)" } })
}
function Get-PimPolicyShippedFieldKeys {
    <#
      PURE. From the SHIPPED templates (Read-PimShippedPolicyTemplates: id -> parsed file): template id -> policy type ->
      field id -> one canonical line of what the template recommends for that field ('(none)' when it says nothing).
      Single-level 'extends' is merged the way the engine merges it. A group template gives groupMember (its rules) and
      groupOwner (its Owner block); appliesTo DirectoryRole -> directoryRole; AzureRole / AzureResourceRole -> azureRole.
    #>
    param([AllowNull()][object]$Shipped)
    $out = @{}
    $ids = @(Get-PimPcNames $Shipped)
    $find = { param($id) foreach ($k in $ids) { if ("$k" -ieq "$id") { return (Get-PimPcProp $Shipped $k) } }; $null }
    foreach ($id in $ids) {
        $tpl = Get-PimPcProp $Shipped $id; if ($null -eq $tpl) { continue }
        $base = $null; $ext = "$(Get-PimPcProp $tpl 'extends')".Trim(); if ($ext) { $base = & $find $ext }
        $rules = @{}
        foreach ($src in @($base, $tpl)) {
            if ($null -eq $src) { continue }
            $r = Get-PimPcProp $src 'rules'
            foreach ($n in @(Get-PimPcNames $r)) { if ("$n".StartsWith('_')) { continue }; $rules[$n] = Get-PimPcProp $r $n }
        }
        $ap = "$(Get-PimPcProp $tpl 'appliesTo')".Trim(); if (-not $ap -and $base) { $ap = "$(Get-PimPcProp $base 'appliesTo')".Trim() }
        $kind = Get-PimPolicyTemplateKindName -AppliesTo $ap
        $rows = Get-PimPolicyTemplateTypeRows -Rules $rules -Kind $kind
        $out["$id"] = @{}
        foreach ($t in @($rows.Keys)) {
            $out["$id"][$t] = @{}
            foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
                $key = ''
                if ("$($fd.kind)" -eq 'notification') {
                    # the RAW entries of this audience (a redirect's recipientsSource included): any shipped change shows
                    $parts = @()
                    foreach ($n in @($rows[$t].Notification)) {
                        if ($null -eq $n -or "$(Get-PimPcProp $n 'recipientType')" -ne "$($fd.audience)") { continue }
                        $parts += ("{0}/{1}/{2}/{3}/{4}/{5}" -f "$(Get-PimPcProp $n 'caller')", "$(Get-PimPcProp $n 'level')", "$(Get-PimPcProp $n 'notificationLevel')", "$(Get-PimPcProp $n 'defaultRecipientsEnabled')", "$(Get-PimPcProp $n 'recipientsSource')", (ConvertTo-PimPcSortedText (Get-PimPcProp $n 'recipients')))
                    }
                    $key = (@($parts | Sort-Object) -join ';')
                } else {
                    $key = Get-PimPolicyFieldValueKey -Field $fd -Value (Get-PimPolicyRowFieldValue -Field $fd -Row $rows[$t])
                }
                if (-not $key) { $key = '(none)' }
                $out["$id"][$t]["$($fd.id)"] = $key
            }
        }
    }
    $out
}
function Update-PimPolicyAdvisories {
    <#
      PURE. The advisory record brought up to what is SHIPPED. It keeps { hash, advisory } per template, type and field
      (the recommendation) and per type and field under 'microsoft' (the shipped Microsoft default, -MicrosoftKeys):
        * first time a field is seen               -> advisory 0 (a new template or a new field asks nobody again);
        * the shipped value of the field CHANGED   -> advisory + 1, the new hash is kept.
      Only the SHIPPED files are read, so a customer's own template edit is never an advisory.
      Returns @{ store; changed; raised = @( @{ template ('' for a Microsoft default); type; field; advisory } ) }.
    #>
    param([AllowNull()][object]$Existing, [Parameter(Mandatory)][hashtable]$ShippedKeys, [AllowNull()][hashtable]$MicrosoftKeys)
    $ex = ConvertFrom-PimPcSetting $Existing
    $store = @{ schema = 1; templates = @{}; microsoft = @{} }
    $copy = {
        param($src, $dst)
        foreach ($t in @(Get-PimPcNames $src)) {
            $dst[$t] = @{}
            foreach ($f in @(Get-PimPcNames (Get-PimPcProp $src $t))) {
                $r = Get-PimPcProp (Get-PimPcProp $src $t) $f
                $a = 0; [void][int]::TryParse("$(Get-PimPcProp $r 'advisory')", [ref]$a)
                $dst[$t][$f] = @{ hash = "$(Get-PimPcProp $r 'hash')"; advisory = $a }
            }
        }
    }
    $exT = Get-PimPcProp $ex 'templates'
    foreach ($tid in @(Get-PimPcNames $exT)) { $store.templates[$tid] = @{}; & $copy (Get-PimPcProp $exT $tid) $store.templates[$tid] }
    & $copy (Get-PimPcProp $ex 'microsoft') $store.microsoft
    $state = @{ changed = $false }; $raised = New-Object System.Collections.Generic.List[object]
    $bring = {
        param($keys, $dst, $tid)
        foreach ($t in @($keys.Keys)) {
            if (-not $dst.ContainsKey($t)) { $dst[$t] = @{} }
            foreach ($f in @($keys[$t].Keys)) {
                $h = Get-PimPcHash "$($keys[$t][$f])"
                $rec = $dst[$t][$f]
                if ($null -eq $rec) { $dst[$t][$f] = @{ hash = $h; advisory = 0 }; $state.changed = $true; continue }
                if ("$($rec.hash)" -ne $h) {
                    $rec.advisory = [int]$rec.advisory + 1; $rec.hash = $h; $state.changed = $true
                    $raised.Add(@{ template = $tid; type = $t; field = $f; advisory = [int]$rec.advisory })
                }
            }
        }
    }
    foreach ($tid in @($ShippedKeys.Keys)) {
        if (-not $store.templates.ContainsKey($tid)) { $store.templates[$tid] = @{} }
        & $bring $ShippedKeys[$tid] $store.templates[$tid] $tid
    }
    if ($MicrosoftKeys) { & $bring $MicrosoftKeys $store.microsoft '' }
    @{ store = $store; changed = [bool]$state.changed; raised = @($raised.ToArray()) }
}
function Get-PimPolicyFieldAdvisory {
    # PURE. The advisory number of ONE field of ONE policy type: 1 + every raise recorded for it -- in any template of that
    # type (a changed recommendation) and for the shipped Microsoft default.
    param([AllowNull()][object]$Advisories, [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$FieldId)
    $n = 1
    $a = ConvertFrom-PimPcSetting $Advisories
    $tpls = Get-PimPcProp $a 'templates'
    $fd = Get-PimPolicyField -Id $FieldId; $fid = if ($fd) { "$($fd.id)" } else { "$FieldId" }
    $recs = @(foreach ($tid in @(Get-PimPcNames $tpls)) { Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tpls $tid) $Type) $fid }) + @(Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $a 'microsoft') $Type) $fid)
    foreach ($rec in $recs) {
        if ($null -eq $rec) { continue }
        $x = 0; [void][int]::TryParse("$(Get-PimPcProp $rec 'advisory')", [ref]$x); $n += $x
    }
    [int]$n
}
function Get-PimPolicyFieldAdvisoryBasis {
    <# PURE. What the advisory number of ONE setting of ONE policy type RESTS ON in this tenant: the hash of the shipped value
       per template ('<template id, lower-case>' = hash) and of the shipped Microsoft default ('(microsoft)' = hash), in
       ordinal key order. An advisory NUMBER counts the changes THIS tenant has seen, so two tenants can stand on different
       numbers for the same shipped values; this is the part that CAN be compared between tenants (the managing tenant
       sends it with its policy choices). Empty = the advisory record has nothing for the setting yet. #>
    param([AllowNull()][object]$Advisories, [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$FieldId)
    $a = ConvertFrom-PimPcSetting $Advisories
    $fd = Get-PimPolicyField -Id $FieldId; $fid = if ($fd) { "$($fd.id)" } else { "$FieldId" }
    $pairs = @{}
    $tpls = Get-PimPcProp $a 'templates'
    foreach ($tid in @(Get-PimPcNames $tpls)) {
        $h = "$(Get-PimPcProp (Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tpls $tid) $Type) $fid) 'hash')".Trim()
        if ($h) { $pairs["$tid".Trim().ToLowerInvariant()] = $h }
    }
    $mh = "$(Get-PimPcProp (Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $a 'microsoft') $Type) $fid) 'hash')".Trim()
    if ($mh) { $pairs['(microsoft)'] = $mh }
    $keys = [string[]]@($pairs.Keys | ForEach-Object { "$_" }); [Array]::Sort($keys, [StringComparer]::Ordinal)
    $out = [ordered]@{}
    foreach ($k in $keys) { $out[$k] = $pairs[$k] }
    $out
}
function Update-PimPolicyAdvisoryStore {
    <# SQL: bring pim.Settings['PolicyAdvisories'] up to the shipped templates AND the shipped Microsoft-default table
       (called where the template store is seeded / upgraded: Initialize-PimPolicyTemplateStore). Returns
       Update-PimPolicyAdvisories' result. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$TemplateDir)
    if (-not (Get-Command Read-PimShippedPolicyTemplates -ErrorAction SilentlyContinue)) { throw 'the policy template store library is not loaded' }
    $shipped = Read-PimShippedPolicyTemplates -TemplateDir $TemplateDir
    if (-not @(Get-PimPcNames $shipped).Count) { return @{ store = $null; changed = $false; raised = @() } }
    $msPath = Join-Path $TemplateDir 'microsoft-defaults.json'
    $msKeys = if (Test-Path -LiteralPath $msPath) { Get-PimMicrosoftPolicyDefaultAdvisoryKeys -Defaults (Get-PimMicrosoftPolicyDefaultsTable -Path $msPath) } else { $null }
    $name = Get-PimPolicyAdvisoriesSettingName
    $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name $name
    $r = Update-PimPolicyAdvisories -Existing $existing -ShippedKeys (Get-PimPolicyShippedFieldKeys -Shipped $shipped) -MicrosoftKeys $msKeys
    if ($r.changed) { Set-PimSqlSetting -ConnectionString $ConnectionString -Name $name -ValueJson (ConvertTo-Json -InputObject $r.store -Depth 8 -Compress) }
    foreach ($x in @($r.raised)) { Write-Host ("  [policy] new advisory {0} for '{1}' on {2} ({3}) -- choices made earlier are asked again" -f $x.advisory, $x.field, $x.type, $(if ("$($x.template)") { "template $($x.template) changed its recommended value" } else { 'the shipped Microsoft default changed' })) -ForegroundColor Yellow }
    $r
}

# ---------------------------------------------------------------------------------------------------------------------
# MICROSOFT'S DEFAULTS -- the SHIPPED table is the source; the tenant read is a cross-check
#   Owner 2026-10-12: "why dont you just pul ms defaut values from the docs". Microsoft's documentation does not state the
#   defaults, so the table (templates/policy/microsoft-defaults.json) is CAPTURED FROM AN UNTOUCHED TENANT and shipped:
#   "Microsoft default" is the same value in every tenant and always available. Entra roles do not all share one default
#   (activation asks some roles for multifactor authentication), so a type carries per-object EXCEPTIONS keyed by the
#   object's id (the role definition / role template id): the write target for a role is that role's own default.
#   The job policy-defaults reads this tenant's untouched policies only to CHECK the table (matchesShipped per setting); a
#   difference is reported and never changes what is written. A change of a shipped value is an ADVISORY for the setting.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimMicrosoftPolicyDefaultsTablePath {
    if ($PSScriptRoot) { return (Join-Path (Join-Path (Join-Path $PSScriptRoot '..\..') 'templates\policy') 'microsoft-defaults.json') }
    return ''
}
function ConvertTo-PimMicrosoftPolicyDefaultsTable {
    <# PURE. The shipped table (JSON text / parsed object / hashtable) ->
         @{ schema; types = @{ <type> = @{ fields = @{ <fieldId> = @{ value; source; capturedDate; verified } };
                                           exceptions = @{ <object id, lower-case> = @{ <fieldId> = value } } } } }
       A type written without a 'fields' wrapper (its settings directly under the type) is read the same way. #>
    param([AllowNull()][object]$Value)
    $out = @{ schema = 2; types = @{} }
    foreach ($t in $script:PimPolicyChoiceTypes) { $out.types[$t] = @{ fields = @{}; exceptions = @{} } }
    $v = ConvertFrom-PimPcSetting $Value
    if ($null -eq $v) { return $out }
    $types = Get-PimPcProp $v 'types'
    foreach ($t in @(Get-PimPcNames $types)) {
        if ($script:PimPolicyChoiceTypes -notcontains $t) { continue }
        $tv = Get-PimPcProp $types $t
        $fsrc = if (Test-PimPcHas $tv 'fields') { Get-PimPcProp $tv 'fields' } else { $tv }
        foreach ($f in @(Get-PimPcNames $fsrc)) {
            $fd = Get-PimPolicyField -Id $f; if (-not $fd -or @($fd.types) -notcontains $t) { continue }
            $e = Get-PimPcProp $fsrc $f; if ($null -eq $e -or $null -eq (Get-PimPcProp $e 'value')) { continue }
            $out.types[$t].fields["$($fd.id)"] = @{ value = (Get-PimPcProp $e 'value'); source = "$(Get-PimPcProp $e 'source')"; capturedDate = (ConvertTo-PimPcUtcText (Get-PimPcProp $e 'capturedDate')); verified = [bool](Get-PimPcProp $e 'verified') }
        }
        $ex = Get-PimPcProp $tv 'exceptions'
        foreach ($o in @(Get-PimPcNames $ex)) {
            $ok = "$o".Trim().ToLowerInvariant(); if (-not $ok) { continue }
            foreach ($f in @(Get-PimPcNames (Get-PimPcProp $ex $o))) {
                $fd = Get-PimPolicyField -Id $f; if (-not $fd -or @($fd.types) -notcontains $t) { continue }
                $val = Get-PimPcProp (Get-PimPcProp $ex $o) $f; if ($null -eq $val) { continue }
                if (-not $out.types[$t].exceptions.ContainsKey($ok)) { $out.types[$t].exceptions[$ok] = @{} }
                $out.types[$t].exceptions[$ok]["$($fd.id)"] = $val
            }
        }
    }
    $out
}
function Get-PimMicrosoftPolicyDefaultsTable {
    # The shipped table from disk. An unreadable / missing file gives an EMPTY table: "Microsoft default" then has no
    # value, so a setting on that choice is not written (state noDefault) -- never a guess.
    param([string]$Path = '')
    if (-not $Path) { $Path = Get-PimMicrosoftPolicyDefaultsTablePath }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return (ConvertTo-PimMicrosoftPolicyDefaultsTable -Value $null) }
    try { return (ConvertTo-PimMicrosoftPolicyDefaultsTable -Value (Get-Content -LiteralPath $Path -Raw -Encoding UTF8)) }
    catch { Write-Warning "  [policy] the Microsoft-default table could not be read: $($_.Exception.Message)"; return (ConvertTo-PimMicrosoftPolicyDefaultsTable -Value $null) }
}
function Get-PimMicrosoftPolicyDefaultEntry {
    # The table's entry for a setting of a type: @{ value; source; capturedDate; verified } or $null.
    param([AllowNull()][object]$Defaults, [string]$Type, [string]$FieldId)
    $tv = Get-PimPcProp (Get-PimPcProp $Defaults 'types') $Type
    Get-PimPcProp (Get-PimPcProp $tv 'fields') $FieldId
}
function Get-PimMicrosoftPolicyDefaultUnverifiedText {
    'Microsoft''s default for this setting has not been confirmed for this kind of policy yet, so it cannot be chosen. Choose Keep current or PIM Manager recommendation.'
}
function Get-PimMicrosoftPolicyDefaultValue {
    # PURE. Microsoft's default for ONE object: its own exception when the table has one for -ObjectId, else the type's value.
    param([AllowNull()][object]$Defaults, [string]$Type, [string]$FieldId, [string]$ObjectId = '')
    $tv = Get-PimPcProp (Get-PimPcProp $Defaults 'types') $Type
    # A value nobody verified against an untouched tenant is NEVER a write target (100.93 review): the setting is then
    # 'noDefault' -- not touched -- until the table's entry says verified.
    if (-not [bool](Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tv 'fields') $FieldId) 'verified')) { return $null }
    $oid = "$ObjectId".Trim().ToLowerInvariant()
    if ($oid) {
        $x = Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tv 'exceptions') $oid) $FieldId
        if ($null -ne $x) { return $x }
    }
    Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tv 'fields') $FieldId) 'value'
}
function Test-PimMicrosoftPolicyDefaultHasExceptions {
    param([AllowNull()][object]$Defaults, [string]$Type)
    [bool]@(Get-PimPcNames (Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $Defaults 'types') $Type) 'exceptions')).Count
}
function Get-PimMicrosoftPolicyDefaultKeys {
    # PURE. Every value the table holds for one setting of a type (the type's value and each exception), as canonical lines.
    param([AllowNull()][object]$Defaults, [string]$Type, [Parameter(Mandatory)][object]$Field)
    $tv = Get-PimPcProp (Get-PimPcProp $Defaults 'types') $Type
    $keys = New-Object System.Collections.Generic.List[string]
    $base = Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tv 'fields') "$($Field.id)") 'value'
    if ($null -ne $base) { $keys.Add((Get-PimPolicyFieldValueKey -Field $Field -Value $base)) }
    $ex = Get-PimPcProp $tv 'exceptions'
    foreach ($o in @(Get-PimPcNames $ex)) {
        $x = Get-PimPcProp (Get-PimPcProp $ex $o) "$($Field.id)"; if ($null -eq $x) { continue }
        $k = Get-PimPolicyFieldValueKey -Field $Field -Value $x
        if (-not $keys.Contains($k)) { $keys.Add($k) }
    }
    @($keys.ToArray())
}
function Get-PimMicrosoftPolicyDefaultAdvisoryKeys {
    # PURE. type -> setting id -> ONE line of everything the shipped table says for it (value + each object's exception):
    # what Update-PimPolicyAdvisories hashes, so a shipped change of a Microsoft default raises that setting's number.
    param([AllowNull()][object]$Defaults)
    $out = @{}
    foreach ($t in $script:PimPolicyChoiceTypes) {
        $out[$t] = @{}
        $tv = Get-PimPcProp (Get-PimPcProp $Defaults 'types') $t
        $ex = Get-PimPcProp $tv 'exceptions'
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
            $base = Get-PimPcProp (Get-PimPcProp (Get-PimPcProp $tv 'fields') "$($fd.id)") 'value'
            $parts = @($(if ($null -ne $base) { Get-PimPolicyFieldValueKey -Field $fd -Value $base } else { '(none)' }))
            foreach ($o in @(Get-PimPcNames $ex | Sort-Object)) {
                $x = Get-PimPcProp (Get-PimPcProp $ex $o) "$($fd.id)"
                if ($null -ne $x) { $parts += ("{0}={1}" -f $o, (Get-PimPolicyFieldValueKey -Field $fd -Value $x)) }
            }
            $out[$t]["$($fd.id)"] = ($parts -join ' || ')
        }
    }
    $out
}
function ConvertTo-PimMicrosoftPolicyTenantRead {
    # PURE. pim.Settings['MicrosoftPolicyDefaults'] (the tenant cross-check; JSON / object) ->
    #   @{ schema; refreshedUtc; types = @{ <type> = @{ <fieldId> = @{ value; source; readUtc; policies; matchesShipped } } } }
    param([AllowNull()][object]$Value)
    $out = @{ schema = 2; refreshedUtc = ''; types = @{} }
    $v = ConvertFrom-PimPcSetting $Value
    if ($null -eq $v) { return $out }
    $out.refreshedUtc = ConvertTo-PimPcUtcText (Get-PimPcProp $v 'refreshedUtc')
    $types = Get-PimPcProp $v 'types'
    foreach ($t in @(Get-PimPcNames $types)) {
        if ($script:PimPolicyChoiceTypes -notcontains $t) { continue }
        $out.types[$t] = @{}
        foreach ($f in @(Get-PimPcNames (Get-PimPcProp $types $t))) {
            $fd = Get-PimPolicyField -Id $f; if (-not $fd) { continue }
            $e = Get-PimPcProp (Get-PimPcProp $types $t) $f; if ($null -eq $e -or $null -eq (Get-PimPcProp $e 'value')) { continue }
            $m = Get-PimPcProp $e 'matchesShipped'; $n = 0; [void][int]::TryParse("$(Get-PimPcProp $e 'policies')", [ref]$n)
            $out.types[$t]["$($fd.id)"] = @{ value = (Get-PimPcProp $e 'value'); source = "$(Get-PimPcProp $e 'source')"; readUtc = (ConvertTo-PimPcUtcText (Get-PimPcProp $e 'readUtc')); policies = $n
                                             matchesShipped = $(if ($m -is [bool]) { $m } else { 'unknown' }) }
        }
    }
    $out
}
function Read-PimMicrosoftPolicyDefaultsEntra {
    <# READ-ONLY. Microsoft's default for ENTRA ROLES: the rules of a directory-role policy nobody ever changed
       (lastModifiedDateTime empty). -List returns the tenant's directory-role policies with their rules (default: ONE
       Graph list call). Returns @{ found; policyId; rules; error }. #>
    param([scriptblock]$List)
    if (-not $List) { $List = { @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=rules") } }
    $res = @{ found = $false; policyId = ''; rules = @(); error = '' }
    # ruleSets is handed out as a plain ARRAY (one rule set per untouched policy), never as the list itself: on Windows
    # PowerShell 5.1 @( ) around a generic list that came from New-Object throws "Argument types do not match", which
    # is what every reader of this result does with it.
    $sets = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($p in @(& $List)) {
            if (-not (Test-PimPcNeverModified $p)) { continue }
            $rules = @(Get-PimPcProp $p 'rules' | Where-Object { $null -ne $_ }); if (-not $rules.Count) { continue }
            # EVERY untouched policy is kept (ruleSets): Entra roles do not all share one default, so the cross-check
            # compares the MOST COMMON value. policyId / rules name the first one found.
            if (-not $res.found) { $res.found = $true; $res.policyId = "$(Get-PimPcProp $p 'id')"; $res.rules = $rules }
            $sets.Add($rules)
        }
    } catch { $res.error = "$($_.Exception.Message)" }
    if ($res.found) { $res['ruleSets'] = $sets.ToArray() }
    $res
}
function Read-PimMicrosoftPolicyDefaultsGroup {
    <# READ-ONLY. Microsoft's default for a GROUP's member or owner policy: the first of -CandidatePolicyIds (the policies
       the last policy run saw as never modified come first) that, read again NOW, still has an empty lastModifiedDateTime.
       At most -Max reads. -Read reads one policy with its rules. Returns @{ found; policyId; rules; error; tried }. #>
    param([string[]]$CandidatePolicyIds = @(), [scriptblock]$Read, [int]$Max = 25)
    if (-not $Read) { $Read = { param($id) Invoke-PimGraph -Path "/policies/roleManagementPolicies/$id`?`$expand=rules" } }
    $res = @{ found = $false; policyId = ''; rules = @(); error = ''; tried = 0 }
    foreach ($id in @($CandidatePolicyIds | Where-Object { "$_".Trim() } | Select-Object -Unique -First $Max)) {
        $res.tried++
        try {
            $p = & $Read $id
            if (-not (Test-PimPcNeverModified $p)) { continue }
            $rules = @(Get-PimPcProp $p 'rules' | Where-Object { $null -ne $_ }); if (-not $rules.Count) { continue }
            $res.found = $true; $res.policyId = "$id"; $res.rules = $rules; break
        } catch { $res.error = "$($_.Exception.Message)" }
    }
    $res
}
function Read-PimMicrosoftPolicyDefaultsAzure {
    <# READ-ONLY. Microsoft's default for AZURE ROLES: the effective rules of a role whose policy is still the SYSTEM
       DEFAULT one (the policy id's last segment equals the role definition id) at one of -Scopes. -List returns a scope's
       role policy assignments (default: one ARM list call per scope, at most -MaxScopes scopes).
       Returns @{ found; policyId; rules; error; tried }. #>
    param([string[]]$Scopes = @(), [scriptblock]$List, [int]$MaxScopes = 5)
    if (-not $List) { $List = { param($scope) @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleManagementPolicyAssignments" -ApiVersion '2020-10-01' -All) } }
    $res = @{ found = $false; policyId = ''; rules = @(); error = ''; tried = 0 }
    foreach ($s in @($Scopes | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().TrimEnd('/') } | Select-Object -Unique -First $MaxScopes)) {
        $res.tried++
        try {
            foreach ($a in @(& $List $s)) {
                $pr = Get-PimPcProp $a 'properties'; if ($null -eq $pr) { continue }
                $pol = (("$(Get-PimPcProp $pr 'policyId')").TrimEnd('/') -split '/')[-1]
                $rol = (("$(Get-PimPcProp $pr 'roleDefinitionId')").TrimEnd('/') -split '/')[-1]
                if (-not $pol -or $pol -ine $rol) { continue }
                $rules = @(Get-PimPcProp $pr 'effectiveRules' | Where-Object { $null -ne $_ }); if (-not $rules.Count) { continue }
                $res.found = $true; $res.policyId = "$(Get-PimPcProp $pr 'policyId')"; $res.rules = $rules; break
            }
        } catch { $res.error = "$($_.Exception.Message)" }
        if ($res.found) { break }
    }
    $res
}
function Invoke-PimPolicyDefaultsRefresh {
    <#
      The tenant CROSS-CHECK of the shipped table (READ-ONLY towards the tenant). -Reads = policy type -> a reader's result
      (@{ found; policyId; rules; ruleSets?; error }). For a type whose reader found an untouched policy, every setting gets
      { value (what the tenant's untouched policy says -- the most common value when several were read), source, readUtc,
      policies (how many were read), matchesShipped }. matchesShipped = $true / $false against the shipped value (a value
      that equals one of the type's per-object exceptions also matches), 'unknown' when the table has no value for it.
      A type whose reader found none KEEPS what was read earlier; never read = nothing stored = unknown. NEVER an error:
      a mismatch is reported, and it never changes what is written.
      Returns @{ store; changed; mismatches = @( @{ type; field; tenant; shipped } ); detail;
                 perType = @{ type = 'read' | 'kept' | 'unknown' } }.
    #>
    param([AllowNull()][object]$Existing, [Parameter(Mandatory)][hashtable]$Reads, [AllowNull()][object]$Shipped, [datetime]$NowUtc = [datetime]::UtcNow)
    $s = ConvertTo-PimMicrosoftPolicyTenantRead -Value $Existing
    $now = $NowUtc.ToUniversalTime().ToString('o')
    $per = @{}; $changed = $false; $notes = New-Object System.Collections.Generic.List[string]; $mis = New-Object System.Collections.Generic.List[object]
    foreach ($t in $script:PimPolicyChoiceTypes) {
        $r = $Reads[$t]
        $sets = @()
        if ($r -and $r.found) { $sets = @(if ($r.ContainsKey('ruleSets') -and @($r.ruleSets).Count) { @($r.ruleSets) } elseif (@($r.rules).Count) { , @($r.rules) }) }
        if ($sets.Count) {
            $fields = @{}
            foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
                # the most common value over the untouched policies that were read
                $tally = @{}
                foreach ($rs in $sets) {
                    $v = Get-PimPolicyLiveFieldValue -Field $fd -RuleMap (ConvertTo-PimPolicyRuleMap -Rules @($rs)); if ($null -eq $v) { continue }
                    $k = Get-PimPolicyFieldValueKey -Field $fd -Value $v
                    if (-not $tally.ContainsKey($k)) { $tally[$k] = @{ value = $v; n = 0 } }
                    $tally[$k].n++
                }
                if (-not $tally.Count) { continue }
                $top = @($tally.Keys | Sort-Object @{ e = { $tally[$_].n }; Descending = $true }, @{ e = { $_ } })[0]
                $val = $tally[$top].value
                $shipKeys = @(Get-PimMicrosoftPolicyDefaultKeys -Defaults $Shipped -Type $t -Field $fd)
                $match = if (-not $shipKeys.Count) { 'unknown' } else { [bool]($shipKeys -contains $top) }
                $fields["$($fd.id)"] = @{ value = $val; source = ("policy {0}" -f "$($r.policyId)"); readUtc = $now; policies = $sets.Count; matchesShipped = $match }
                if ($match -is [bool] -and -not $match) { $mis.Add(@{ type = $t; field = "$($fd.id)"; tenant = $val; shipped = (Get-PimMicrosoftPolicyDefaultValue -Defaults $Shipped -Type $t -FieldId $fd.id) }) }
                $old = if ($s.types.ContainsKey($t) -and $s.types[$t].ContainsKey($fd.id)) { Get-PimPolicyFieldValueKey -Field $fd -Value $s.types[$t][$fd.id].value } else { '' }
                if ($old -ne $top) { $changed = $true }
            }
            $s.types[$t] = $fields; $per[$t] = 'read'
            $bad = @($fields.Keys | Where-Object { $fields[$_].matchesShipped -is [bool] -and -not $fields[$_].matchesShipped })
            $notes.Add("$(Get-PimPolicyChoiceTypeLabel $t): $($sets.Count) untouched polic$(if ($sets.Count -eq 1) { 'y' } else { 'ies' }) read, $(if ($bad.Count) { "$($bad.Count) setting$(if ($bad.Count -eq 1) { '' } else { 's' }) differ from the shipped Microsoft default ($($bad -join ', '))" } else { 'all settings match the shipped Microsoft default' })")
        }
        elseif ($s.types.ContainsKey($t) -and $s.types[$t].Count) { $per[$t] = 'kept'; $notes.Add("$(Get-PimPolicyChoiceTypeLabel $t): no untouched policy found now, what was read earlier is kept$(if ($r -and $r.error) { " ($($r.error))" })") }
        else { $per[$t] = 'unknown'; $notes.Add("$(Get-PimPolicyChoiceTypeLabel $t): no untouched policy in this tenant -- not checked$(if ($r -and $r.error) { " ($($r.error))" })") }
    }
    $s.refreshedUtc = $now
    @{ store = $s; changed = [bool]$changed; perType = $per; mismatches = @($mis.ToArray()); detail = ("policy-defaults: " + ($notes -join '; ')) }
}

# ---------------------------------------------------------------------------------------------------------------------
# ENGINE ACCESSORS (the stores as the engine and PIM Manager read them)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPcSettingRaw {
    # $global:<Seam> (tests, or a host that already read it) -> the settings store -> the hydrated pim.Settings mirror.
    param([string]$Name, [string]$Seam)
    if ($Seam) { $g = Get-Variable -Name $Seam -Scope Global -ErrorAction SilentlyContinue; if ($g -and $null -ne $g.Value) { return $g.Value } }
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $v = Get-PimSetting -Name $Name; if ($null -ne $v -and "$v".Trim()) { return $v } } catch { Write-Verbose "policy choices: pim.Settings['$Name'] could not be read: $($_.Exception.Message)" } }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) { return $global:PIM_NamingConventions[$Name] }
    return $null
}
function Reset-PimPolicyChoiceCache { $script:PimPolicyChoiceCache = $null }
function Get-PimPolicyChoiceState {
    <# The three stores one policy run decides with -- @{ choices; advisories; defaults } -- read once and kept for 60
       seconds (Reset-PimPolicyChoiceCache at the start of every provider run). A test seam ($global:PIM_PolicyChoices /
       PIM_PolicyAdvisories / PIM_MicrosoftPolicyDefaults) is never cached. #>
    $seamed = ($null -ne $global:PIM_PolicyChoices -or $null -ne $global:PIM_PolicyAdvisories -or $null -ne $global:PIM_MicrosoftPolicyDefaults)
    $c = $script:PimPolicyChoiceCache
    if (-not $seamed -and $c -and ([datetime]::UtcNow - [datetime]$c.atUtc).TotalSeconds -lt 60) { return $c.state }
    $shipped = $null
    if ($null -ne $global:PIM_MicrosoftPolicyDefaults) { $shipped = ConvertTo-PimMicrosoftPolicyDefaultsTable -Value $global:PIM_MicrosoftPolicyDefaults }
    else { try { $shipped = Get-PimMicrosoftPolicyDefaultsTable } catch { $shipped = ConvertTo-PimMicrosoftPolicyDefaultsTable -Value $null } }
    $state = @{
        choices    = ConvertTo-PimPolicyChoicesStore -Value (Get-PimPcSettingRaw -Name (Get-PimPolicyChoicesSettingName) -Seam 'PIM_PolicyChoices')
        advisories = ConvertFrom-PimPcSetting (Get-PimPcSettingRaw -Name (Get-PimPolicyAdvisoriesSettingName) -Seam 'PIM_PolicyAdvisories')
        defaults   = $shipped     # the SHIPPED table -- what "Microsoft default" means; the tenant read is a cross-check only
    }
    if (-not $seamed) { $script:PimPolicyChoiceCache = @{ atUtc = [datetime]::UtcNow; state = $state } }
    $state
}

# ---------------------------------------------------------------------------------------------------------------------
# THE ENGINE RULE -- desired state = live state for every undecided / keep field
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPolicyChoiceObjectId {
    <# The id Microsoft's per-object defaults are keyed by, for one desired row: an Entra role's role definition (template)
       id -- from the row when it carries one (RoleDefinitionId), else from the engine's role catalog (name -> id, read
       once per state). '' when it is not known: the type's general default then applies. Other types have no id yet. #>
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Row, [AllowNull()][hashtable]$State)
    if ("$Provider".Trim().ToLowerInvariant() -ne 'entrarolepolicies') { return '' }
    $rid = "$(Get-PimPcProp $Row 'RoleDefinitionId')".Trim()
    if ($rid) { return $rid.ToLowerInvariant() }
    $name = "$(Get-PimPcProp $Row 'RoleDefinitionName')".Trim().ToLowerInvariant(); if (-not $name) { return '' }
    $map = $null
    if ($State -and $State.ContainsKey('roleIds')) { $map = $State['roleIds'] }
    elseif (Get-Command Get-PimEntraRoleNameMap -ErrorAction SilentlyContinue) {
        try { $map = Get-PimEntraRoleNameMap } catch { $map = $null }
        if ($State) { $State['roleIds'] = $map }
    }
    if ($map -is [System.Collections.IDictionary] -and $map.Contains($name)) { return "$($map[$name])".Trim().ToLowerInvariant() }
    ''
}
function ConvertTo-PimPolicyChoiceDesired {
    <#
      PURE (with -State). ONE provider desired row (what the bound TEMPLATE says) -> the row the engine may act on: it
      carries ONLY the rules of the fields the customer DECIDED, each on its target value (Microsoft's default or the
      template's), and for a rule that several fields share (Enablement_EndUser_Assignment: multifactor authentication,
      reason, ticket) the LIVE value of every part nobody decided. Everything else is taken off the row, so the provider's
      own compare / plan / apply never sees it: not compared, not planned, not written.

      Per field the outcome is recorded on the row (PolicyChoice.fields[<id>].state):
        waiting          no choice exists                                   -> not touched ("waiting for your choice")
        keep             the choice is Keep current                         -> not touched
        review           the choice was made on an older advisory number    -> not touched until it is answered again
        noRecommendation 'recommendation', but the template says nothing    -> not touched
        noDefault        'microsoft', but no default value is known         -> not touched
        blocked          the target must never be written (see Get-PimPolicyChoiceTargetBlock) -> not touched
        noLive           decided, but the policy (or the shared rule) was not read in this run -> not touched this run
        active           decided and written when live differs (through the held, approved change set)
      PolicyChoice.active = number of active fields; .decided = active + noLive (a choice that WOULD write).
      A row that already carries PolicyChoice is returned as it is. An emergency-override row (BUG-185) keeps ONLY its
      approval-off part: nothing a choice decides is ever written outside the approved change set.
    #>
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][object]$Desired, [AllowNull()][object[]]$LiveRules, [AllowNull()][hashtable]$State)
    if ((Test-PimPcHas $Desired 'PolicyChoice') -and $null -ne (Get-PimPcProp $Desired 'PolicyChoice')) { return $Desired }
    if ($null -eq $State) { $State = Get-PimPolicyChoiceState }
    $ident = Get-PimPolicyChoiceRowIdentity -Provider $Provider -Row $Desired
    $type = $ident.type
    $liveMap = ConvertTo-PimPolicyRuleMap -Rules $LiveRules
    $hasLive = [bool]$liveMap.Count
    $isOverride = [bool]((Test-PimPcHas $Desired 'EmergencyOverride') -and (Get-PimPcProp $Desired 'EmergencyOverride'))
    # Microsoft's default can differ per object (an Entra role's own default): the table keys such exceptions by the
    # object's id. Looked up only when the table HAS exceptions for this type.
    $objectId = ''
    if (Test-PimMicrosoftPolicyDefaultHasExceptions -Defaults $State.defaults -Type $type) { $objectId = Get-PimPolicyChoiceObjectId -Provider $Provider -Row $Desired -State $State }
    $fields = [ordered]@{}; $targets = @{}
    foreach ($fd in @(Get-PimPolicyFieldsForType -Type $type)) {
        $res = Resolve-PimPolicyChoice -Store $State.choices -Type $type -ObjectKey $ident.objectKey -FieldId $fd.id -Advisories $State.advisories
        $st = 'waiting'; $target = $null; $why = ''
        if ($res.choice) {
            if ($res.needsReview) { $st = 'review' }
            elseif ($res.choice -eq 'keep') { $st = 'keep' }
            else {
                if ($res.choice -eq 'microsoft') { $target = Get-PimMicrosoftPolicyDefaultValue -Defaults $State.defaults -Type $type -FieldId $fd.id -ObjectId $objectId; if ($null -eq $target) { $st = 'noDefault' } }
                else { $target = Get-PimPolicyRowFieldValue -Field $fd -Row $Desired; if ($null -eq $target) { $st = 'noRecommendation' } }
                if ($null -ne $target) {
                    # Only a MICROSOFT value is refused here. What a TEMPLATE asks for keeps the provider's own, older
                    # handling: an Azure role's live approval is KEPT when the template has none (reported, never
                    # written), and a template that demands multifactor authentication on the admin path is refused by
                    # the Azure provider with its own message (BUG-21).
                    $why = if ($res.choice -eq 'microsoft') { Get-PimPolicyChoiceTargetBlock -Type $type -Field $fd -Target $target } else { '' }
                    if ($why) { $st = 'blocked' } elseif (-not $hasLive -or $isOverride) { $st = 'noLive' } else { $st = 'active' }
                }
            }
        }
        $fields["$($fd.id)"] = @{ state = $st; choice = "$($res.choice)"; origin = "$($res.origin)"; source = "$($res.source)"; needsReview = [bool]$res.needsReview; advisory = [int]$res.currentAdvisory; reason = $why }
        if ($st -eq 'active') { $targets["$($fd.id)"] = $target }
    }
    # The shared activation rule: all three parts decided -> fully known; else the undecided parts come from LIVE.
    $tok = @(Get-PimPolicyFieldsForType -Type $type | Where-Object { $_.kind -eq 'token' })
    $tokActive = @($tok | Where-Object { $targets.ContainsKey("$($_.id)") })
    $enablement = @{}
    if ($tokActive.Count) {
        $liveRule = $liveMap['Enablement_EndUser_Assignment']
        if ($null -eq $liveRule -and $tokActive.Count -lt $tok.Count) {
            foreach ($f in $tokActive) { $fields["$($f.id)"].state = 'noLive'; [void]$targets.Remove("$($f.id)") }
        } else {
            $set = New-Object System.Collections.Generic.List[string]
            if ($null -ne $liveRule) { foreach ($x in @(Get-PimPcProp $liveRule 'enabledRules')) { if ("$x".Trim() -and -not $set.Contains("$x".Trim())) { $set.Add("$x".Trim()) } } }
            foreach ($f in $tokActive) {
                [void]$set.Remove("$($f.token)")
                if ([bool](Get-PimPcProp $targets["$($f.id)"] 'required')) { $set.Add("$($f.token)") }
            }
            $ordered = @($script:PimPolicyChoiceTokens | Where-Object { $set.Contains($_) }) + @($set | Where-Object { $script:PimPolicyChoiceTokens -notcontains $_ })
            $enablement['EndUser_Assignment'] = @($ordered)
        }
    }
    $expiration = @{}; $notification = New-Object System.Collections.Generic.List[object]
    $approvalActive = $false; $approvalOn = $false
    foreach ($fd in @(Get-PimPolicyFieldsForType -Type $type)) {
        if (-not $targets.ContainsKey("$($fd.id)")) { continue }
        $t = $targets["$($fd.id)"]
        switch ("$($fd.kind)") {
            'expiration' { $expiration["$($fd.target)"] = @{ maximumDuration = "$(Get-PimPcProp $t 'maximumDuration')"; isExpirationRequired = [bool](Get-PimPcProp $t 'isExpirationRequired') } }
            'ruleset'    { $enablement["$($fd.target)"] = @(@(Get-PimPcProp $t 'enabledRules') | Where-Object { "$_".Trim() }) }
            'approval'   { $approvalActive = $true; $approvalOn = [bool](Get-PimPcProp $t 'required') }
            'notification' {
                $rules = Get-PimPcProp $t 'rules'
                foreach ($rid in @(Get-PimPcNames $rules | Sort-Object)) {
                    $p = "$rid" -split '_'; if ($p.Count -ne 4) { continue }
                    $r = Get-PimPcProp $rules $rid
                    $lvl = "$(Get-PimPcProp $r 'notificationLevel')"; if (-not $lvl) { $lvl = 'All' }
                    $notification.Add([pscustomobject]@{ recipientType = $p[1]; caller = $p[2]; level = $p[3]; notificationLevel = $lvl
                        defaultRecipientsEnabled = [bool](Get-PimPcProp $r 'isDefaultRecipientsEnabled'); recipients = @(@(Get-PimPcProp $r 'notificationRecipients') | Where-Object { "$_".Trim() }) })
                }
            }
        }
    }
    $manageWas = $true; if (Test-PimPcHas $Desired 'ManageApproval') { $manageWas = [bool](Get-PimPcProp $Desired 'ManageApproval') }
    $c = if ($Desired -is [System.Collections.IDictionary]) { [pscustomobject]$Desired } else { $Desired.PSObject.Copy() }
    $set = { param($n, $v) $c | Add-Member -NotePropertyName $n -NotePropertyValue $v -Force }
    & $set 'Expiration' $(if ($expiration.Count) { $expiration } else { $null })
    & $set 'Enablement' $(if ($enablement.Count) { $enablement } else { $null })
    & $set 'EnablementLegacy' $null
    & $set 'Notification' $(if ($notification.Count) { @($notification.ToArray()) } else { $null })
    if ($isOverride) {
        # BUG-185: the authorised break-glass switch-off is the ONLY thing this row carries.
        & $set 'Approval' $null; & $set 'ApproverIds' @(); & $set 'ManageApproval' $true
    } elseif ($approvalActive -and $manageWas -and (-not $approvalOn -or $null -ne (Get-PimPcProp $Desired 'Approval'))) {
        # ON needs the template's Approval block (who approves, how); OFF needs nothing.
        if (-not $approvalOn) { & $set 'Approval' $null; & $set 'ApproverIds' @() }
        & $set 'ManageApproval' $true
    } else {
        & $set 'Approval' $null; & $set 'ManageApproval' $false
        if ($approvalActive) { $fields['approvalRequired'].state = 'noRecommendation' }
    }
    $count = { param($s) @($fields.Keys | Where-Object { $fields[$_].state -eq $s }).Count }
    $active = (& $count 'active')
    & $set 'PolicyChoice' ([pscustomobject]@{ type = $type; objectKey = $ident.objectKey; name = $ident.name; hasLive = $hasLive; fields = $fields
        active = $active; decided = ($active + (& $count 'noLive')); waiting = (& $count 'waiting'); keep = (& $count 'keep'); review = (& $count 'review')
        blocked = ((& $count 'blocked') + (& $count 'noDefault') + (& $count 'noRecommendation')); emergencyOverride = $isOverride })
    $c
}
function Get-PimPolicyChoiceRunSummary {
    <# PURE. What ONE provider run decided, from its effective rows: per FIELD OF A POLICY TYPE (not per policy) how many
       settings wait for a choice, are kept, are decided, and are asked again -- the numbers the job line says. #>
    param([AllowNull()][object[]]$Effective, [int]$Changes = 0, [bool]$Held = $false)
    $seen = @{}
    foreach ($e in @($Effective)) {
        $pc = Get-PimPcProp $e 'PolicyChoice'; if ($null -eq $pc) { continue }
        foreach ($f in @($pc.fields.Keys)) {
            $k = "$($pc.type)|$f"; $s = "$($pc.fields[$f].state)"
            $rank = @{ waiting = 4; review = 3; active = 2; noLive = 2; keep = 1 }
            $new = if ($rank.ContainsKey($s)) { $s } else { 'other' }
            if (-not $seen.ContainsKey($k) -or ($rank[$new] -gt $rank["$($seen[$k])"])) { $seen[$k] = $new }
        }
    }
    $n = { param($s) @($seen.Keys | Where-Object { $seen[$_] -in $s }).Count }
    [pscustomobject]@{ waiting = (& $n @('waiting')); review = (& $n @('review')); decided = (& $n @('active', 'noLive')); keep = (& $n @('keep')); other = (& $n @('other'))
                       policies = @($Effective).Count; changes = [int]$Changes; held = [bool]$Held }
}
function Format-PimPolicyChoiceRunSummary {
    # PURE. The plain line a job / log shows, e.g. "12 settings wait for your choice; 0 changes".
    param([Parameter(Mandatory)][object]$Summary)
    $s = { param($n) if ([int]$n -eq 1) { '' } else { 's' } }
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add(("{0} setting{1} wait{2} for your choice" -f $Summary.waiting, (& $s $Summary.waiting), $(if ([int]$Summary.waiting -eq 1) { 's' } else { '' })))
    if ([int]$Summary.review) { $parts.Add(("{0} setting{1} asked again after a new recommendation" -f $Summary.review, (& $s $Summary.review))) }
    if ([int]$Summary.changes -and $Summary.held) { $parts.Add(("{0} policy change{1} wait{2} for a SuperAdmin's approval" -f $Summary.changes, (& $s $Summary.changes), $(if ([int]$Summary.changes -eq 1) { 's' } else { '' }))) }
    else { $parts.Add(("{0} change{1}" -f $Summary.changes, (& $s $Summary.changes))) }
    ($parts -join '; ')
}

# ---------------------------------------------------------------------------------------------------------------------
# THE LIVE READ OF THE LAST POLICY RUN (what the page shows as "current")
# ---------------------------------------------------------------------------------------------------------------------
function New-PimPolicyLiveValuesSnapshot {
    <#
      PURE. One provider run's read, kept small: per policy type the policies, and per field the SPREAD of the live value
      and of the template's recommendation (each distinct value once, with the indexes of the policies holding it).
        -Rows = @( @{ desired = <the TEMPLATE row>; liveRules = <rules or $null>; policyId; neverModified } )
      A policy that could not be read is listed without a live value.
    #>
    param([Parameter(Mandatory)][string]$Provider, [AllowNull()][object[]]$Rows, [AllowNull()][object]$Summary, [datetime]$NowUtc = [datetime]::UtcNow)
    $types = [ordered]@{}
    foreach ($t in @($script:PimPolicyChoiceProviderTypes[$Provider])) { $types[$t] = @{ policies = (New-Object System.Collections.Generic.List[object]); live = @{}; rec = @{} } }
    foreach ($row in @($Rows)) {
        if ($null -eq $row -or $null -eq $row.desired) { continue }
        $id = Get-PimPolicyChoiceRowIdentity -Provider $Provider -Row $row.desired
        if (-not $types.Contains($id.type)) { continue }
        $b = $types[$id.type]; $idx = $b.policies.Count
        $map = ConvertTo-PimPolicyRuleMap -Rules $row.liveRules
        $b.policies.Add([ordered]@{ key = $id.objectKey; name = $id.name; template = "$(Get-PimPcProp $row.desired 'TemplateId')"; policyId = "$($row.policyId)"; objectId = "$($row.objectId)".ToLowerInvariant(); neverModified = [bool]$row.neverModified; read = [bool]$map.Count })
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $id.type)) {
            foreach ($side in 'live', 'rec') {
                $v = if ($side -eq 'live') { if ($map.Count) { Get-PimPolicyLiveFieldValue -Field $fd -RuleMap $map } else { $null } } else { Get-PimPolicyRowFieldValue -Field $fd -Row $row.desired }
                if ($null -eq $v) { continue }
                $k = Get-PimPolicyFieldValueKey -Field $fd -Value $v
                if (-not $b[$side].ContainsKey($fd.id)) { $b[$side][$fd.id] = [ordered]@{} }
                if (-not $b[$side][$fd.id].Contains($k)) { $b[$side][$fd.id][$k] = @{ value = $v; policies = (New-Object System.Collections.Generic.List[int]) } }
                $b[$side][$fd.id][$k].policies.Add($idx)
            }
        }
    }
    $outTypes = [ordered]@{}
    foreach ($t in @($types.Keys)) {
        $b = $types[$t]; $fields = [ordered]@{}
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
            $mk = { param($m) @(foreach ($k in @($(if ($m) { $m.Keys } else { @() }))) { [ordered]@{ key = "$k"; value = $m[$k].value; policies = @($m[$k].policies.ToArray()) } }) }
            $fields["$($fd.id)"] = [ordered]@{ live = @(& $mk $b.live[$fd.id]); recommendation = @(& $mk $b.rec[$fd.id]) }
        }
        $outTypes[$t] = [ordered]@{ policies = @($b.policies.ToArray()); fields = $fields }
    }
    [ordered]@{ schema = 1; provider = $Provider; readUtc = $NowUtc.ToUniversalTime().ToString('o'); types = $outTypes
                summary = $(if ($Summary) { [ordered]@{ waiting = [int]$Summary.waiting; review = [int]$Summary.review; decided = [int]$Summary.decided; keep = [int]$Summary.keep; changes = [int]$Summary.changes; held = [bool]$Summary.held; text = (Format-PimPolicyChoiceRunSummary -Summary $Summary) } } else { $null }) }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE VALUE VIEW (GET /api/policy-choices) and the change preview (PUT)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimPolicyChoiceWouldChange {
    <# PURE. The policies of ONE type a choice for ONE field would change, from the last live read: every policy that does
       not carry its own (local) override for the field -- or, with -ObjectKey, only that policy -- whose live value is
       not already the target (Microsoft default = that object's own default from the shipped table).
       @{ count; policies = @(names, at most -Max); more; known } (known = false: no live read yet). #>
    param([Parameter(Mandatory)][object]$Field, [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Choice, [AllowNull()][object]$TypeSnapshot,
          [AllowNull()][hashtable]$Store, [AllowNull()][object]$Defaults, [string]$ObjectKey = '', [int]$Max = 50)
    # indexes (lane policy-page): EVERY policy that would change, as its position in the type's policy list (the view's
    # `objects`) -- so a page can count the distinct policies several settings change together without double counting.
    $res = [ordered]@{ count = 0; policies = @(); more = 0; known = $false; indexes = @() }
    if ($null -eq $TypeSnapshot) { return $res }
    $pols = @(Get-PimPcList $TypeSnapshot 'policies'); $fs = Get-PimPcProp (Get-PimPcProp $TypeSnapshot 'fields') "$($Field.id)"
    $res.known = $true
    if ("$Choice" -notin @('microsoft', 'recommendation')) { return $res }
    $liveBy = @{}; foreach ($e in @(Get-PimPcList $fs 'live')) { foreach ($i in @(Get-PimPcList $e 'policies')) { $liveBy[[int]$i] = (Get-PimPcProp $e 'value') } }
    $recBy = @{};  foreach ($e in @(Get-PimPcList $fs 'recommendation')) { foreach ($i in @(Get-PimPcList $e 'policies')) { $recBy[[int]$i] = (Get-PimPcProp $e 'value') } }
    $names = New-Object System.Collections.Generic.List[string]
    $hit = New-Object System.Collections.Generic.List[int]
    $only = "$ObjectKey".Trim().ToLowerInvariant()
    for ($i = 0; $i -lt $pols.Count; $i++) {
        $key = "$(Get-PimPcProp $pols[$i] 'key')".ToLowerInvariant()
        if ($only) { if ($key -ne $only) { continue } }
        elseif ($Store -and $Store.overrides.ContainsKey("$Type|$key") -and $Store.overrides["$Type|$key"].ContainsKey("$($Field.id)")) { continue }
        if (-not $liveBy.ContainsKey($i)) { continue }
        $target = if ($Choice -eq 'microsoft') { Get-PimMicrosoftPolicyDefaultValue -Defaults $Defaults -Type $Type -FieldId $Field.id -ObjectId "$(Get-PimPcProp $pols[$i] 'objectId')" } else { $recBy[$i] }
        if ($null -eq $target) { continue }
        if ($Choice -eq 'microsoft' -and (Get-PimPolicyChoiceTargetBlock -Type $Type -Field $Field -Target $target)) { continue }
        # an Azure role's approval is never switched off, whatever asks for it: no change
        if ("$($Field.kind)" -eq 'approval' -and $Type -eq 'azureRole' -and -not [bool](Get-PimPcProp $target 'required')) { continue }
        if (Test-PimPolicyFieldValueMatch -Field $Field -Live $liveBy[$i] -Target $target) { continue }
        $names.Add("$(Get-PimPcProp $pols[$i] 'name')"); $hit.Add($i)
    }
    $res.count = $names.Count; $res.policies = @($names | Select-Object -First $Max); $res.more = [Math]::Max(0, $names.Count - $Max)
    $res.indexes = @($hit.ToArray())
    $res
}
function Get-PimPolicyChoicesView {
    <#
      PURE. THE VALUE VIEW the Policies page is built on. Per policy type and field:
        microsoft       Microsoft's default from the SHIPPED table (value, source, capturedDate, verified) -- and, when the
                        objects of the type do not all share it (Entra roles), the SPREAD over the policies read
                        ("Yes on 19, No on 126"); `tenant` = what THIS tenant's untouched policies say (the cross-check):
                        value, matchesShipped (true / false / 'unknown') and, on a mismatch, a plain note
        recommendation  the PIM Manager recommendation per bound template value, with counts
        current         the SPREAD of the live values (value + count + up to -Examples names)
        choice, waiting, needsReview, advisory, overrides, wouldChange (per choice: the policies it would change)
        local           this tenant's OWN choice for the policy type (or $null)      } shown next to each other on a
        managingTenant  the managing tenant's choice for the policy type (or $null)  } managed tenant; each carries
                        { choice, label, by, utc, advisory, needsReview }
        follows         $true = the choice that stands comes from the managing tenant (choice.source 'managing-tenant'):
                        this tenant chose nothing itself. A local choice always wins; local 'keep' = do not follow.
      Top level: managingTenant { present; receivedUtc; settings; followed; needsReview } (what was pulled, in numbers).
        -Choices / -Advisories   the stores      -Defaults   the shipped table (ConvertTo-PimMicrosoftPolicyDefaultsTable)
        -TenantRead              pim.Settings['MicrosoftPolicyDefaults'] (the cross-check; may be empty = unknown)
        -Snapshots               provider -> the last policy run's live read (New-PimPolicyLiveValuesSnapshot)
        -Templates               the stored policy templates as the engine applies them (Get-PimPolicyRecommendationTemplates)
      Live values are AS FRESH AS THAT RUN (liveReadUtc per type; '' = no policy run has read this type yet).
      THE RECOMMENDATION NEVER WAITS FOR A TENANT READ: it is what the policy templates say. A type with policies read shows
      it as the spread over the bound templates (with counts); a type nothing was read for yet shows one entry per template
      of the type that says something about the setting ({ value; text; count 0; examples (); templates; isDefaultTemplate }),
      the type's default template first, equal values merged. `recommendationText` is the plain line for the button
      ('8 hours', or '8 hours (Standard), 4 hours (Require approval)' when the templates differ); `recommendationReason`
      says why there is none. Only `current` and `wouldChange` need the read.
    #>
    param([AllowNull()][hashtable]$Choices, [AllowNull()][object]$Advisories, [AllowNull()][object]$Defaults, [AllowNull()][hashtable]$Snapshots, [AllowNull()][object]$TenantRead, [int]$Examples = 5, [AllowNull()][object[]]$Templates)
    if ($null -eq $Choices) { $Choices = New-PimPolicyChoicesStore }
    $tenant = ConvertTo-PimMicrosoftPolicyTenantRead -Value $TenantRead
    $typeOut = New-Object System.Collections.Generic.List[object]
    $totWaiting = 0; $totReview = 0; $totMismatch = 0
    # what a managed tenant pulled from its managing tenant (empty everywhere else)
    $mtRoot = if ($Choices.ContainsKey('managingTenant') -and $Choices.managingTenant) { $Choices.managingTenant } else { @{ types = @{}; overrides = @{} } }
    $mtFollowed = 0; $mtReview = 0; $mtSettings = 0
    foreach ($mm in @($mtRoot.types, $mtRoot.overrides)) { if ($mm) { foreach ($mk in @($mm.Keys)) { $mtSettings += @($mm[$mk].Keys).Count } } }
    foreach ($t in $script:PimPolicyChoiceTypes) {
        $prov = @($script:PimPolicyChoiceProviderTypes.Keys | Where-Object { @($script:PimPolicyChoiceProviderTypes[$_]) -contains $t })[0]
        $snap = if ($Snapshots) { ConvertFrom-PimPcSetting $Snapshots[$prov] } else { $null }
        $ts = Get-PimPcProp (Get-PimPcProp $snap 'types') $t
        $pols = @(Get-PimPcList $ts 'policies')
        $spread = {
            param($entries, $fd)
            @(foreach ($e in @($entries | Where-Object { $null -ne $_ } | Sort-Object @{ e = { @(Get-PimPcList $_ 'policies').Count }; Descending = $true })) {
                $ix = @(Get-PimPcList $e 'policies')
                [ordered]@{ value = (Get-PimPcProp $e 'value'); text = (Format-PimPolicyRuleSetText (Format-PimPolicyFieldValue -Field $fd -Value (Get-PimPcProp $e 'value'))); count = $ix.Count
                            examples = @($ix | Select-Object -First $Examples | ForEach-Object { "$(Get-PimPcProp $pols[[int]$_] 'name')" })
                            templates = @($ix | ForEach-Object { "$(Get-PimPcProp $pols[[int]$_] 'template')" } | Where-Object { $_ } | Sort-Object -Unique) }
            })
        }
        $hasEx = Test-PimMicrosoftPolicyDefaultHasExceptions -Defaults $Defaults -Type $t
        # the templates of this policy type (the default one first) -- what the recommendation is when nothing was read yet
        $tplKind = if ($t -eq 'groupMember' -or $t -eq 'groupOwner') { 'group' } else { $t }
        $tplOfType = @(@($Templates) | Where-Object { $null -ne $_ -and "$(Get-PimPcProp $_ 'kind')" -eq $tplKind -and $null -ne (Get-PimPcProp (Get-PimPcProp $_ 'rows') $t) })
        $tplLabel = @{}; foreach ($tp in @($Templates)) { if ($null -ne $tp) { $tplLabel["$(Get-PimPcProp $tp 'id')".ToLowerInvariant()] = "$(Get-PimPcProp $tp 'label')" } }
        $fieldOut = New-Object System.Collections.Generic.List[object]
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
            $res = Resolve-PimPolicyChoice -Store $Choices -Type $t -FieldId $fd.id -Advisories $Advisories
            # the two type choices the resolver picked from, side by side (a managed tenant shows both)
            $locE = if ($Choices.types -and $Choices.types.ContainsKey($t)) { $Choices.types[$t]["$($fd.id)"] } else { $null }
            $mtE = if ($mtRoot.types -and $mtRoot.types.ContainsKey($t)) { $mtRoot.types[$t]["$($fd.id)"] } else { $null }
            $sideOut = {
                param($e)
                if ($null -eq $e -or $script:PimPolicyChoiceValues -notcontains "$($e.choice)") { return $null }
                [ordered]@{ choice = "$($e.choice)"; label = (Get-PimPolicyChoiceLabel $e.choice); by = "$($e.by)"; utc = (ConvertTo-PimPcUtcText $e.utc); advisory = [int]$e.advisory; needsReview = ([int]$e.advisory -lt [int]$res.currentAdvisory) }
            }
            if ("$($res.source)" -eq 'managing-tenant') { $mtFollowed++; if ($res.needsReview) { $mtReview++ } }
            $me = Get-PimMicrosoftPolicyDefaultEntry -Defaults $Defaults -Type $t -FieldId $fd.id
            $msVal = Get-PimPcProp $me 'value'
            $msBlock = Get-PimPolicyChoiceTargetBlock -Type $t -Field $fd -Target $msVal
            if (-not $msBlock -and $me -and -not [bool](Get-PimPcProp $me 'verified')) { $msBlock = (Get-PimMicrosoftPolicyDefaultUnverifiedText) }
            $fsnap = Get-PimPcProp (Get-PimPcProp $ts 'fields') "$($fd.id)"
            # Microsoft's default per policy read (its own exception, else the type's value), as a spread
            $msSpread = @()
            if ($null -ne $msVal -and $hasEx -and $pols.Count) {
                $g = [ordered]@{}
                for ($i = 0; $i -lt $pols.Count; $i++) {
                    $v = Get-PimMicrosoftPolicyDefaultValue -Defaults $Defaults -Type $t -FieldId $fd.id -ObjectId "$(Get-PimPcProp $pols[$i] 'objectId')"
                    $k = Get-PimPolicyFieldValueKey -Field $fd -Value $v
                    if (-not $g.Contains($k)) { $g[$k] = @{ value = $v; policies = (New-Object System.Collections.Generic.List[int]) } }
                    $g[$k].policies.Add($i)
                }
                $msSpread = @(& $spread @(foreach ($k in @($g.Keys)) { @{ value = $g[$k].value; policies = @($g[$k].policies.ToArray()) } }) $fd)
            }
            # the cross-check: what this tenant's untouched policies say
            $te = if ($tenant.types.ContainsKey($t)) { $tenant.types[$t]["$($fd.id)"] } else { $null }
            $tenantOut = [ordered]@{ known = $false; matchesShipped = 'unknown'; value = $null; text = ''; source = ''; readUtc = ''; policies = 0; note = '' }
            if ($te) {
                $tText = Format-PimPolicyRuleSetText (Format-PimPolicyFieldValue -Field $fd -Value $te.value)
                $tenantOut.known = $true; $tenantOut.matchesShipped = $te.matchesShipped; $tenantOut.value = $te.value; $tenantOut.text = $tText
                $tenantOut.source = "$($te.source)"; $tenantOut.readUtc = (ConvertTo-PimPcUtcText $te.readUtc); $tenantOut.policies = [int]$te.policies
                if ($te.matchesShipped -is [bool] -and -not $te.matchesShipped) {
                    $totMismatch++
                    $tenantOut.note = ("This tenant's untouched policy says '{0}'; the Microsoft default PIM Manager ships says '{1}'. Nothing is changed because of this -- 'Microsoft default' writes the shipped value." -f $tText, (Format-PimPolicyRuleSetText (Format-PimPolicyFieldValue -Field $fd -Value $msVal)))
                }
            }
            $ovr = New-Object System.Collections.Generic.List[object]
            foreach ($blk in @(@{ m = $Choices.overrides; s = 'local' }, @{ m = $mtRoot.overrides; s = 'managing-tenant' })) {
                if ($null -eq $blk.m) { continue }
                foreach ($k in @($blk.m.Keys | Sort-Object)) {
                    if (-not "$k".StartsWith("$t|") -or -not $blk.m[$k].ContainsKey($fd.id)) { continue }
                    $e = $blk.m[$k][$fd.id]; $obj = "$k".Substring($t.Length + 1)
                    $nm = @($pols | Where-Object { "$(Get-PimPcProp $_ 'key')" -eq $obj } | ForEach-Object { "$(Get-PimPcProp $_ 'name')" } | Select-Object -First 1)
                    $ovr.Add([ordered]@{ objectKey = $obj; name = $(if ($nm.Count) { $nm[0] } else { $obj }); choice = "$($e.choice)"; choiceLabel = (Get-PimPolicyChoiceLabel $e.choice); by = "$($e.by)"; utc = (ConvertTo-PimPcUtcText $e.utc)
                                         advisory = [int]$e.advisory; needsReview = ([int]$e.advisory -lt [int]$res.currentAdvisory); source = $blk.s })
                }
            }
            $would = [ordered]@{}
            foreach ($c in $script:PimPolicyChoiceValues) { $would[$c] = Get-PimPolicyChoiceWouldChange -Field $fd -Type $t -Choice $c -TypeSnapshot $ts -Store $Choices -Defaults $Defaults -Max $Examples }
            if (-not $res.choice) { $totWaiting++ } elseif ($res.needsReview) { $totReview++ }
            # THE RECOMMENDATION: policies read -> the spread over the bound templates; nothing read -> the templates themselves
            $recOut = @(& $spread @(Get-PimPcProp $fsnap 'recommendation') $fd)
            if (-not $pols.Count -and $tplOfType.Count) {
                $g = [ordered]@{}
                foreach ($tp in $tplOfType) {
                    $tv = Get-PimPolicyRowFieldValue -Field $fd -Row (Get-PimPcProp (Get-PimPcProp $tp 'rows') $t)
                    if ($null -eq $tv) { continue }
                    $tk = Get-PimPolicyFieldValueKey -Field $fd -Value $tv
                    if (-not $g.Contains($tk)) { $g[$tk] = @{ value = $tv; templates = (New-Object System.Collections.Generic.List[string]); isDefault = $false } }
                    $g[$tk].templates.Add("$(Get-PimPcProp $tp 'id')")
                    if ([bool](Get-PimPcProp $tp 'isDefault')) { $g[$tk].isDefault = $true }
                }
                $recOut = @(foreach ($tk in @($g.Keys)) {
                    [ordered]@{ value = $g[$tk].value; text = (Format-PimPolicyRuleSetText (Format-PimPolicyFieldValue -Field $fd -Value $g[$tk].value)); count = 0
                                examples = @(); templates = $g[$tk].templates.ToArray(); isDefaultTemplate = [bool]$g[$tk].isDefault }
                })
            }
            $recText = ''
            if ($recOut.Count -eq 1) { $recText = "$($recOut[0].text)" }
            elseif ($recOut.Count -gt 1) {
                $recText = (@(foreach ($re in $recOut) {
                    $labs = @(@($re.templates) | Where-Object { "$_".Trim() } | ForEach-Object { $lk = "$_".ToLowerInvariant(); if ($tplLabel.ContainsKey($lk) -and $tplLabel[$lk]) { $tplLabel[$lk] } else { Get-PimPolicyTemplateShortLabel -Id "$_" -Name '' } })
                    if ($labs.Count) { "{0} ({1})" -f $re.text, ($labs -join ', ') } else { "$($re.text)" }
                }) -join ', ')
            }
            $recReason = ''
            if (-not $recOut.Count) {
                if ($pols.Count) { $recReason = 'The policy template gives no recommendation for this setting.' }
                elseif ($tplOfType.Count) { $recReason = 'The policy templates say nothing about this setting, so there is no recommendation for it.' }
            }
            $fieldOut.Add([ordered]@{
                id = "$($fd.id)"; label = "$($fd.label)"; help = "$($fd.help)"; kind = "$($fd.kind)"; ruleIds = @($fd.ruleIds)
                choice = $(if ($res.choice) { [ordered]@{ choice = $res.choice; label = (Get-PimPolicyChoiceLabel $res.choice); by = $res.by; utc = $res.utc; advisory = [int]$res.advisory; source = $res.source; origin = $res.origin } } else { $null })
                waiting = [bool](-not $res.choice); needsReview = [bool]$res.needsReview; advisory = [int]$res.currentAdvisory
                local = (& $sideOut $locE); managingTenant = (& $sideOut $mtE); follows = [bool]("$($res.source)" -eq 'managing-tenant')
                microsoft = $(if ($null -ne $msVal) { [ordered]@{ value = $msVal; text = (Format-PimPolicyRuleSetText (Format-PimPolicyFieldValue -Field $fd -Value $msVal))
                                source = "$(Get-PimPcProp $me 'source')"; capturedDate = "$(Get-PimPcProp $me 'capturedDate')"; verified = [bool](Get-PimPcProp $me 'verified')
                                selectable = [bool](-not $msBlock); blockedReason = "$msBlock"; differsPerObject = [bool](@($msSpread).Count -gt 1); spread = @($msSpread); tenant = $tenantOut } } else { $null })
                recommendation = @($recOut)
                recommendationText = "$recText"; recommendationReason = "$recReason"
                current =@(& $spread @(Get-PimPcProp $fsnap 'live') $fd)
                wouldChange = $would
                overrides = @($ovr.ToArray())
            })
        }
        $typeOut.Add([ordered]@{ id = $t; label = (Get-PimPolicyChoiceTypeLabel $t); provider = $prov; liveReadUtc = (ConvertTo-PimPcUtcText (Get-PimPcProp $snap 'readUtc'))   # PowerShell 7 reads the stored ISO text as a [datetime]: always ISO to the page (first seen in the fast gate, 2026-10-12)
                                 policies = $pols.Count; policiesRead = @($pols | Where-Object { [bool](Get-PimPcProp $_ 'read') }).Count
                                 # objects (lane policy-page): every policy of the type in the order `wouldChange.indexes` counts in --
                                 # the key an override is saved under and the name a person picks it by
                                 objects = @($pols | ForEach-Object { [ordered]@{ key = "$(Get-PimPcProp $_ 'key')"; name = "$(Get-PimPcProp $_ 'name')" } })
                                 fields = @($fieldOut.ToArray()) })
    }
    [ordered]@{
        schema = 1
        choices = @($script:PimPolicyChoiceValues | ForEach-Object { [ordered]@{ id = $_; label = (Get-PimPolicyChoiceLabel $_) } })
        waiting = $totWaiting; needsReview = $totReview
        managingTenant = [ordered]@{ present = [bool]($mtSettings -gt 0); receivedUtc = "$(if ($mtRoot.ContainsKey('receivedUtc')) { $mtRoot['receivedUtc'] })"; settings = $mtSettings; followed = $mtFollowed; needsReview = $mtReview }
        microsoftDefaultsCheckedUtc = "$($tenant.refreshedUtc)"; microsoftDefaultMismatches = $totMismatch
        liveSource = 'The PIM Manager recommendation is what your policy templates say. The current values are what the last policy run read from the tenant (jobs delta-policies and delta-pim-azure-policies, every 30 minutes).'
        types = @($typeOut.ToArray())
    }
}
function Format-PimPolicyChoiceAuditText {
    # PURE. One plain sentence for the audit list: who chose what for which setting.
    param([string]$By, [string]$Type, [string]$FieldId, [string]$Choice, [string]$ObjectName = '')
    $fd = Get-PimPolicyField -Id $FieldId
    $lab = if ($fd) { "$($fd.label)" } else { "$FieldId" }
    $where = if ("$ObjectName".Trim()) { "'$ObjectName' ($(Get-PimPolicyChoiceTypeLabel $Type))" } else { (Get-PimPolicyChoiceTypeLabel $Type) }
    if ("$Choice".Trim().ToLowerInvariant() -eq 'none') { return ("{0} took back the choice for '{1}' on {2}" -f $By, $lab, $where) }
    ("{0} chose '{1}' for '{2}' on {3}" -f $By, (Get-PimPolicyChoiceLabel $Choice), $lab, $where)
}
function Set-PimPolicyChoices {
    <#
      Save one or several choices (the store write behind PUT /api/policy-choices). WHO may call it is the caller's job
      (SuperAdmin). All items are validated first -- one refused item saves NOTHING. Seams: -Read returns the stored
      PolicyChoices value, -Write stores the new one (an object).
        -Items = @( @{ type; field; choice ('microsoft' | 'recommendation' | 'keep' | 'none'); objectKey? } )
      Returns @{ ok; errors; saved = @( @{ type; field; fieldLabel; objectKey; choice; choiceLabel; before; advisory; text;
                 wouldChange } ); changes (policies the saved choices would change, as far as the last live read knows) }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items, [Parameter(Mandatory)][string]$By, [Parameter(Mandatory)][scriptblock]$Read, [Parameter(Mandatory)][scriptblock]$Write,
          [AllowNull()][object]$Advisories, [AllowNull()][object]$Defaults, [AllowNull()][hashtable]$Snapshots, [datetime]$NowUtc = [datetime]::UtcNow)
    $errors = New-Object System.Collections.Generic.List[string]
    $norm = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        $t = "$(Get-PimPcProp $it 'type')".Trim(); $f = "$(Get-PimPcProp $it 'field')".Trim(); $c = "$(Get-PimPcProp $it 'choice')".Trim().ToLowerInvariant(); $o = "$(Get-PimPcProp $it 'objectKey')".Trim().ToLowerInvariant()
        $ok = Test-PimPolicyChoiceAllowed -Type $t -FieldId $f -Choice $c -Defaults $Defaults
        if (-not $ok.ok) { $errors.Add("$t / $f`: $($ok.reason)"); continue }
        $norm.Add(@{ type = $t; field = "$((Get-PimPolicyField -Id $f).id)"; choice = $c; objectKey = $o })
    }
    if (-not @($Items).Count) { $errors.Add('No choice was sent.') }
    if ($errors.Count) { return @{ ok = $false; errors = @($errors.ToArray()); saved = @(); changes = 0 } }
    $store = ConvertTo-PimPolicyChoicesStore -Value (& $Read)
    $saved = New-Object System.Collections.Generic.List[object]; $total = 0
    foreach ($n in $norm) {
        $fd = Get-PimPolicyField -Id $n.field
        $adv = Get-PimPolicyFieldAdvisory -Advisories $Advisories -Type $n.type -FieldId $n.field
        $r = Set-PimPolicyChoiceInStore -Store $store -Type $n.type -FieldId $n.field -Choice $n.choice -ObjectKey $n.objectKey -By $By -Advisory $adv -NowUtc $NowUtc
        $prov = @($script:PimPolicyChoiceProviderTypes.Keys | Where-Object { @($script:PimPolicyChoiceProviderTypes[$_]) -contains $n.type })[0]
        $ts = if ($Snapshots) { Get-PimPcProp (Get-PimPcProp (ConvertFrom-PimPcSetting $Snapshots[$prov]) 'types') $n.type } else { $null }
        $name = ''
        if ($n.objectKey) { $name = "$(@(@(Get-PimPcList $ts 'policies') | Where-Object { "$(Get-PimPcProp $_ 'key')" -eq $n.objectKey } | ForEach-Object { "$(Get-PimPcProp $_ 'name')" } | Select-Object -First 1))"; if (-not $name) { $name = $n.objectKey } }
        # what stands for the field after this save decides the preview ('none' on an override falls back to the type's choice)
        $eff = if ($n.choice -eq 'none') { (Resolve-PimPolicyChoice -Store $store -Type $n.type -ObjectKey $n.objectKey -FieldId $n.field -Advisories $Advisories).choice } else { $n.choice }
        $wc = Get-PimPolicyChoiceWouldChange -Field $fd -Type $n.type -Choice "$eff" -TypeSnapshot $ts -Store $store -Defaults $Defaults -ObjectKey $n.objectKey
        $total += [int]$wc.count
        $saved.Add([ordered]@{ type = $n.type; typeLabel = (Get-PimPolicyChoiceTypeLabel $n.type); field = $n.field; fieldLabel = "$($fd.label)"; objectKey = $n.objectKey; objectName = $name
            choice = $n.choice; choiceLabel = $(if ($n.choice -eq 'none') { 'No choice' } else { Get-PimPolicyChoiceLabel $n.choice }); before = $(if ($r.before) { "$($r.before.choice)" } else { '' }); advisory = [int]$adv
            text = (Format-PimPolicyChoiceAuditText -By $By -Type $n.type -FieldId $n.field -Choice $n.choice -ObjectName $name); wouldChange = $wc })
    }
    [void](& $Write ([ordered]@{ schema = 1; types = $store.types; overrides = $store.overrides; managingTenant = $store.managingTenant }))
    Reset-PimPolicyChoiceCache
    @{ ok = $true; errors = @(); saved = @($saved.ToArray()); changes = $total }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE 'policy-defaults' JOB (daily, read-only towards the tenant)
# ---------------------------------------------------------------------------------------------------------------------
function Invoke-PimPolicyDefaultsJob {
    <#
      The scheduler handler for 'policy-defaults' (registered by tools\pim-scheduler\Start-PimScheduler.ps1): the tenant
      CROSS-CHECK of the shipped Microsoft-default table. It reads this tenant's untouched policies per policy type,
      compares them with the table and stores what it read + matchesShipped in pim.Settings['MicrosoftPolicyDefaults'].
      A mismatch is REPORTED (the run's detail, the value view) and changes nothing that is written; no untouched policy
      = unknown, not an error.
        Entra roles   a directory-role policy with an empty lastModifiedDateTime (one Graph list call)
        groups        a member / owner policy the last policy run saw as never modified, read again now
        Azure roles   a role still on the system default policy at one of the scopes the last policy run covered
      It only READS the tenant and writes one settings row. -ReadSetting / -WriteSetting / -Readers are the test seams.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [scriptblock]$ReadSetting, [scriptblock]$WriteSetting, [hashtable]$Readers, [AllowNull()][object]$Shipped)
    if (-not $ReadSetting) {
        if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { throw '[policy-defaults] no settings store is wired in this process -- nothing was read' }
        $ReadSetting = { param($n) Get-PimSetting -Name $n }
    }
    if (-not $WriteSetting) {
        if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw '[policy-defaults] no settings store is wired in this process -- nothing was read' }
        $WriteSetting = { param($n, $v) Set-PimSetting -Name $n -Value $v }
    }
    $snap = { param($prov) ConvertFrom-PimPcSetting (& $ReadSetting (Get-PimPolicyLiveValuesSettingName -Provider $prov)) }
    $candidates = {
        param($type)
        $ts = Get-PimPcProp (Get-PimPcProp (& $snap 'GroupsPolicies') 'types') $type
        $p = @(Get-PimPcList $ts 'policies' | Where-Object { "$(Get-PimPcProp $_ 'policyId')".Trim() })
        @(@($p | Where-Object { [bool](Get-PimPcProp $_ 'neverModified') }) + @($p | Where-Object { -not [bool](Get-PimPcProp $_ 'neverModified') }) | ForEach-Object { "$(Get-PimPcProp $_ 'policyId')" })
    }
    $reads = @{}
    if ($Readers -and $Readers.ContainsKey('directoryRole')) { $reads['directoryRole'] = & $Readers['directoryRole'] } else { $reads['directoryRole'] = Read-PimMicrosoftPolicyDefaultsEntra }
    foreach ($gt in 'groupMember', 'groupOwner') {
        if ($Readers -and $Readers.ContainsKey($gt)) { $reads[$gt] = & $Readers[$gt] } else { $reads[$gt] = Read-PimMicrosoftPolicyDefaultsGroup -CandidatePolicyIds @(& $candidates $gt) }
    }
    if ($Readers -and $Readers.ContainsKey('azureRole')) { $reads['azureRole'] = & $Readers['azureRole'] }
    else {
        $az = Get-PimPcProp (Get-PimPcProp (& $snap 'AzResPolicies') 'types') 'azureRole'
        $scopes = @(Get-PimPcList $az 'policies' | ForEach-Object { ("$(Get-PimPcProp $_ 'key')" -split '\|')[0] } | Where-Object { $_ } | Select-Object -Unique)
        $reads['azureRole'] = Read-PimMicrosoftPolicyDefaultsAzure -Scopes $scopes
    }
    if ($null -eq $Shipped) { $Shipped = Get-PimMicrosoftPolicyDefaultsTable }
    $name = Get-PimMicrosoftPolicyDefaultsSettingName
    $r = Invoke-PimPolicyDefaultsRefresh -Existing (& $ReadSetting $name) -Reads $reads -Shipped $Shipped -NowUtc $NowUtc
    foreach ($x in @($r.mismatches)) {
        $fdx = Get-PimPolicyField -Id $x.field
        Write-Host ("  [policy-defaults] {0} / '{1}': this tenant's untouched policy says '{2}'; the shipped Microsoft default says '{3}' -- reported only, nothing is changed" -f (Get-PimPolicyChoiceTypeLabel $x.type), $fdx.label, (Format-PimPolicyFieldValue -Field $fdx -Value $x.tenant), (Format-PimPolicyFieldValue -Field $fdx -Value $x.shipped)) -ForegroundColor Yellow
    }
    if (-not $WhatIf) { [void](& $WriteSetting $name $r.store); Reset-PimPolicyChoiceCache }
    [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; detail = "$($r.detail)$(if ($WhatIf) { ' (what-if: nothing written)' })"; perType = $r.perType; mismatches = @($r.mismatches) }
}
