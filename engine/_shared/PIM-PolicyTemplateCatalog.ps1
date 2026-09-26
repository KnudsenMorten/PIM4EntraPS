#Requires -Version 5.1
<#
  PIM4EntraPS -- REQ-L (operator 2026-09-19): the read-only POLICY TEMPLATES page, in plain words.

  "i dont see the different policies anymore nor do i see the wizard asking for the poicy to link, where is that"

  The templates live in pim.Settings['PolicyTemplates'] (PIM-PolicyTemplateStore.ps1). Until now they
  reached the Manager only as a dropdown of ids, so nobody could see what a choice MEANS. This module
  turns the stored templates into:
    * a plain-words description of what each one sets -- activation maximum, MFA / justification /
      ticket / authentication context, approval + approvers, eligible and active assignment expiry,
      the admin-path checks, notifications, the owner-role policy, and every other rule it carries;
    * which delegations use it: the rows whose PolicyTemplate column names it, per entity, plus how
      many rows leave the column blank and so get it as their type's STANDARD template;
    * rows that name a template the store does not have (the engine skips their policy).

  It reads exactly what the engine reads and resolves exactly the way the engine resolves:
    * single-level 'extends' merged by top-level rule key (Get-PimEnginePolicyTemplates);
    * a template reference resolves by id, then current name, then former id (Resolve-PimPolicyTemplateKey:
      'default' -> Groups_Standard, 'approval-required' -> Groups_RequireApproval) -- a row naming a former id is
      counted under the template it resolves to, and the page lists the former ids as "also accepted";
    * blank PolicyTemplate = the type's DEFAULT template (2026-09-19: settable per kind in
      pim.Settings['PolicyTemplateDefaults']; built-in Groups_Standard for a group definition row
      (Get-PimEnginePolicyTemplate), EntraIDRoles_Standard for an Entra role row
      (Get-PimManagedRolePolicyTargets), AzureRoles_Standard for an Azure resource role row
      (Get-PimAzResPolicyTargets) -- all through Get-PimEnginePolicyTemplateDefaultId).
      tests/Test-PimPolicyTemplatesPage.ps1 pins these three against the engine, so the page cannot drift from
      what the engine does;
    * three kinds, one Standard + one RequireApproval each: appliesTo absent = PIM for Groups ('group'),
      'DirectoryRole' = Entra ID roles ('directoryRole'), 'AzureRole' = Azure resource roles ('azureRole');
    * the entities the engine reads PolicyTemplate from (Get-PimGroupPolicyDefinitionRows,
      Get-PimManagedRolePolicyTargets, Get-PimAzResPolicyTargets); Action=Remove and
      Lifecycle=Retire rows are ignored there, so they are not counted here either.

  READ-ONLY by design: templates are not edited in the Manager. PURE (no SQL, no Graph); the Manager
  (Open-PimManager.ps1 Get-PimManagerPolicyTemplatesPage) supplies the stored value and the rows.
  PS 5.1; ASCII only.
#>

Set-StrictMode -Off

function Get-PimPolicyTemplateTypeDefaults {
    <# The DEFAULT template per delegation type -- what a BLANK PolicyTemplate resolves to in the engine
       (Get-PimEnginePolicyTemplateDefaultId). -Setting = pim.Settings['PolicyTemplateDefaults'], -Map = the stored
       templates; both optional. Without them: the built-in defaults (today's behaviour). #>
    param([AllowNull()][object]$Setting, [AllowNull()][System.Collections.IDictionary]$Map)
    if (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue) {
        return (Resolve-PimPolicyTemplateTypeDefaults -Setting $Setting -Map $Map).defaults
    }
    [ordered]@{ group = 'Groups_Standard'; directoryRole = 'EntraIDRoles_Standard'; azureRole = 'AzureRoles_Standard' }
}

function Resolve-PimPolicyTplKey {
    # A template reference -> the key the map holds it under (id, current name, former id); '' when none.
    param([System.Collections.IDictionary]$Map, [string]$Id)
    if (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) { return (Resolve-PimPolicyTemplateKey -Map $Map -Id $Id) }
    $t = "$Id".Trim(); if ($t -and $Map -and $Map.Contains($t)) { return $t }
    return ''
}

function Get-PimPolicyTemplateUsageEntities {
    <# The entities whose PolicyTemplate column the engine reads, with the policy kind each drives. #>
    $defs = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
              'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg',
              'PIM-Definitions-Resources')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $defs) { [void]$out.Add([ordered]@{ entity = $e; kind = 'group' }) }
    foreach ($e in @('PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Roles-Direct')) { [void]$out.Add([ordered]@{ entity = $e; kind = 'directoryRole' }) }
    [void]$out.Add([ordered]@{ entity = 'PIM-Assignments-Azure-Resources'; kind = 'azureRole' })
    return $out.ToArray()
}

function Get-PimPolicyTemplateKindLabel {
    param([string]$Kind)
    switch ($Kind) {
        'group'         { return 'PIM for Groups (a delegation group''s member and owner policy)' }
        'directoryRole' { return 'Entra ID role policy' }
        'azureRole'     { return 'Azure resource role policy' }
        default         { return "$Kind" }
    }
}

function Get-PimPolicyTplProp {
    # Read a property from a JSON-shaped node (PSCustomObject or IDictionary); $null when absent.
    param([AllowNull()][object]$Node, [string]$Name)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) { if ($Node.Contains($Name)) { return $Node[$Name] }; return $null }
    $p = $Node.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PimPolicyTplKeys {
    param([AllowNull()][object]$Node)
    if ($null -eq $Node) { return @() }
    if ($Node -is [System.Collections.IDictionary]) { return @($Node.Keys | ForEach-Object { "$_" }) }
    return @($Node.PSObject.Properties | ForEach-Object { "$($_.Name)" })
}

function Get-PimPolicyTemplateEffectiveRules {
    <#
      The rules the ENGINE applies for one template id: single-level 'extends' -- the base's rules first,
      then the template's own, per top-level key (Get-PimEnginePolicyTemplates). Returns an ordered
      hashtable, or $null when the id is not in the map.
    #>
    param([Parameter(Mandatory)][hashtable]$Map, [Parameter(Mandatory)][string]$Id)
    $key = Resolve-PimPolicyTplKey -Map $Map -Id $Id
    if (-not $key) { return $null }
    $j = $Map[$key]
    $rules = [ordered]@{}
    $ext = Resolve-PimPolicyTplKey -Map $Map -Id "$(Get-PimPolicyTplProp $j 'extends')"
    if ($ext) {
        $br = Get-PimPolicyTplProp $Map[$ext] 'rules'
        foreach ($k in @(Get-PimPolicyTplKeys $br)) { $rules[$k] = Get-PimPolicyTplProp $br $k }
    }
    $own = Get-PimPolicyTplProp $j 'rules'
    foreach ($k in @(Get-PimPolicyTplKeys $own)) { $rules[$k] = Get-PimPolicyTplProp $own $k }
    return $rules
}

function Get-PimPolicyTemplateKind {
    <# The kind of policy a template is written for (its own appliesTo, else its base's):
         'DirectoryRole' -> 'directoryRole' (Entra ID roles); 'AzureRole' / 'AzureResourceRole' -> 'azureRole'
         (Azure resource roles, 2026-09-19); anything else -> 'group' (PIM for Groups). '' = not in the map. #>
    param([Parameter(Mandatory)][hashtable]$Map, [Parameter(Mandatory)][string]$Id)
    $key = Resolve-PimPolicyTplKey -Map $Map -Id $Id
    if (-not $key) { return '' }
    $ap = "$(Get-PimPolicyTplProp $Map[$key] 'appliesTo')".Trim()
    if (-not $ap) {
        $ext = Resolve-PimPolicyTplKey -Map $Map -Id "$(Get-PimPolicyTplProp $Map[$key] 'extends')"
        if ($ext) { $ap = "$(Get-PimPolicyTplProp $Map[$ext] 'appliesTo')".Trim() }
    }
    if ($ap -ieq 'DirectoryRole') { return 'directoryRole' }
    if ($ap -ieq 'AzureRole' -or $ap -ieq 'AzureResourceRole') { return 'azureRole' }
    return 'group'
}

function Test-PimPolicyTemplateFitsKind {
    <# A template fits the rows of ITS kind: group -> group definitions, directoryRole -> Entra role rows,
       azureRole -> Azure resource role rows (2026-09-19). A misfit is REPORTED, never blocking: an Azure row that
       still names EntraIDRoles_Standard (the Azure default until 2026-09-19) keeps working -- same rules. #>
    param([string]$TemplateKind, [string]$RowKind)
    if (-not $TemplateKind) { return $false }
    return ($TemplateKind -eq $RowKind)
}

function ConvertTo-PimPolicyDurationText {
    <# ISO-8601 duration -> plain words: PT8H -> '8 hours', P365D -> '365 days', P1D -> '1 day'. Unparsable -> as given. #>
    param([AllowNull()][object]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    $m = [regex]::Match($v, '^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$', 'IgnoreCase')
    if (-not $m.Success -or $v -match '^PT?$') { return $v }
    $units = @('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
    $parts = New-Object System.Collections.Generic.List[string]
    for ($i = 1; $i -le 7; $i++) {
        $g = $m.Groups[$i]
        if ($g.Success -and "$($g.Value)" -ne '') {
            $n = [int]$g.Value
            [void]$parts.Add(("{0} {1}{2}" -f $n, $units[$i - 1], $(if ($n -eq 1) { '' } else { 's' })))
        }
    }
    if (-not $parts.Count) { return $v }
    return ($parts -join ' ')
}

function ConvertTo-PimPolicyEnablementText {
    <# An enabledRules list -> '' (nothing asked) or 'MFA and a justification'. #>
    param([AllowNull()][object]$List)
    $names = @{ 'MultiFactorAuthentication' = 'MFA'; 'Justification' = 'a justification'; 'Ticketing' = 'a ticket number'; 'AuthenticationContext' = 'an authentication context' }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($List)) {
        $s = "$x".Trim(); if (-not $s) { continue }
        if ($names.ContainsKey($s)) { [void]$out.Add($names[$s]) } else { [void]$out.Add($s) }
    }
    if (-not $out.Count) { return '' }
    if ($out.Count -eq 1) { return $out[0] }
    return ((@($out)[0..($out.Count - 2)] -join ', ') + ' and ' + $out[$out.Count - 1])
}

function Get-PimPolicyNotificationText {
    <# One Notification entry -> @{ recipient; event; on; line }. caller defaults to EndUser (ConvertTo-PimNotificationRuleBody). #>
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry) { return $null }
    $rt = "$(Get-PimPolicyTplProp $Entry 'recipientType')".Trim()
    $lvl = "$(Get-PimPolicyTplProp $Entry 'level')".Trim()
    if (-not $rt -or -not $lvl) { return $null }
    $caller = "$(Get-PimPolicyTplProp $Entry 'caller')".Trim(); if (-not $caller) { $caller = 'EndUser' }
    $defRaw = Get-PimPolicyTplProp $Entry 'defaultRecipientsEnabled'
    $on = if ($null -eq $defRaw) { $true } else { [bool]$defRaw }
    $src = "$(Get-PimPolicyTplProp $Entry 'recipientsSource')".Trim()
    $who = switch ($rt) { 'Admin' { 'Admins are' } 'Requestor' { 'The person assigned (or activating) is' } 'Approver' { 'Approvers are' } default { "$rt is" } }
    $mail = switch ($rt) { 'Admin' { 'Admin' } 'Requestor' { 'Requestor' } 'Approver' { 'Approver' } default { $rt } }
    $evt = if ($caller -ieq 'Admin' -and $lvl -ieq 'Eligibility') { 'someone is made eligible' }
           elseif ($caller -ieq 'Admin' -and $lvl -ieq 'Assignment') { 'someone is given an active assignment' }
           elseif ($caller -ieq 'EndUser' -and $lvl -ieq 'Assignment') { 'someone activates' }
           else { "$caller / $lvl" }
    $line = if ($src) {
        "$mail mail when $evt goes to the people in the row's $src column when that is set (otherwise the rule above applies)"
    } else {
        "$who mailed when ${evt}: $(if ($on) { 'on' } else { 'off' })"
    }
    return [ordered]@{ recipient = $rt; caller = $caller; level = $lvl; on = $on; recipientsSource = $src; line = $line }
}

function Get-PimPolicyApproversText {
    param([string]$Source)
    switch -regex ("$Source".Trim()) {
        '^(?i)Owners$'       { return "the delegation group's Owners (else its sponsor, else its department's owners)" }
        '^(?i)ApproverUpns$' { return "the people in the ApproverUpns column on the role-assignment row (for an Azure role: else the owners of the groups assigned that role)" }
        '^$'                 { return 'not named in the template' }
        default              { return "the '$Source' source" }
    }
}

function Get-PimPolicyRoleSection {
    <# The activation / assignment half of a rule set (member policy, or the Owner block) in plain words. #>
    param([AllowNull()][object]$Expiration, [AllowNull()][object]$Enablement, [AllowNull()][object]$LegacyEndUser)
    $o = [ordered]@{ activation = $null; eligible = $null; active = $null; activationChecks = ''; eligibleChecks = ''; activeChecks = ''; lines = @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $expText = {
        param($node)
        if ($null -eq $node) { return $null }
        $d = Get-PimPolicyTplProp $node 'maximumDuration'; $r = Get-PimPolicyTplProp $node 'isExpirationRequired'
        return [ordered]@{ maximumDuration = "$d"; text = (ConvertTo-PimPolicyDurationText $d); required = $(if ($null -eq $r) { $null } else { [bool]$r }) }
    }
    $o.activation = & $expText (Get-PimPolicyTplProp $Expiration 'EndUser_Assignment')
    $o.eligible   = & $expText (Get-PimPolicyTplProp $Expiration 'Admin_Eligibility')
    $o.active     = & $expText (Get-PimPolicyTplProp $Expiration 'Admin_Assignment')
    if ($o.activation) {
        $lines.Add("An activation lasts at most $($o.activation.text)$(if ($o.activation.required -eq $false) { ' (the limit is not enforced)' })." )
    } else { $lines.Add('The activation length is not set by this template (the tenant''s current value stays).') }
    $act = Get-PimPolicyTplProp $Enablement 'EndUser_Assignment'
    if ($null -eq $act -and $null -ne $LegacyEndUser) { $act = $LegacyEndUser }
    if ($null -ne $act -or $null -ne $Enablement) {
        $o.activationChecks = ConvertTo-PimPolicyEnablementText $act
        $lines.Add($(if ($o.activationChecks) { "To activate: $($o.activationChecks) required." } else { 'To activate: nothing extra is asked (no MFA, justification or ticket).' }))
    } else { $lines.Add('What activation asks for (MFA, justification, ticket) is not set by this template.') }
    foreach ($pair in @(@('eligible', 'An eligible assignment'), @('active', 'An active assignment'))) {
        $e = $o[$pair[0]]
        if (-not $e) { continue }
        if ($e.required -eq $false) { $lines.Add("$($pair[1]) may be permanent (no expiry required); when an end date is set it is at most $($e.text).") }
        else { $lines.Add("$($pair[1]) lasts at most $($e.text) (an end date is required).") }
    }
    if ($null -ne $Enablement) {
        $o.eligibleChecks = ConvertTo-PimPolicyEnablementText (Get-PimPolicyTplProp $Enablement 'Admin_Eligibility')
        $o.activeChecks   = ConvertTo-PimPolicyEnablementText (Get-PimPolicyTplProp $Enablement 'Admin_Assignment')
        $lines.Add("Making someone eligible: $(if ($o.eligibleChecks) { $o.eligibleChecks + ' required' } else { 'nothing extra is asked' }).")
        $lines.Add("Giving an active assignment: $(if ($o.activeChecks) { $o.activeChecks + ' required' } else { 'nothing extra is asked' }).")
    }
    $o.lines = $lines.ToArray()
    return $o
}

function Get-PimPolicyTemplateDescription {
    <#
      One template, in plain words, from its EFFECTIVE rules. Returns an ordered hashtable:
        id, name, description, extends, appliesTo, kind, kindLabel, activation{maxDuration,text,required},
        activationChecks, mfa, justification, ticket, authenticationContext, approval{required,mode,
        approversSource,approversText,escalationHours}, eligible{..}, active{..}, eligibleChecks, activeChecks,
        notifications[{line,on,..}], owner{lines..}|$null, otherRules[{key,value}], lines[] (the summary).
    #>
    param([Parameter(Mandatory)][hashtable]$Map, [Parameter(Mandatory)][string]$Id)
    $j = $Map[$Id]
    $rules = Get-PimPolicyTemplateEffectiveRules -Map $Map -Id $Id
    if ($null -eq $rules) { return $null }
    $kind = Get-PimPolicyTemplateKind -Map $Map -Id $Id
    $rn = Get-PimPolicyTplProp $j '_renamed'
    $d = [ordered]@{
        id = $Id; name = "$(Get-PimPolicyTplProp $j 'name')"; description = "$(Get-PimPolicyTplProp $j 'description')"
        extends = "$(Get-PimPolicyTplProp $j 'extends')"; appliesTo = "$(Get-PimPolicyTplProp $j 'appliesTo')"
        # 2026-09-19: former ids that still resolve to this template ('default' for Groups_Standard), and the operator's rename.
        aliases = @(if (Get-Command Get-PimPolicyTemplateAliasNames -ErrorAction SilentlyContinue) { @(Get-PimPolicyTemplateAliasNames $Id) | Where-Object { -not $Map.ContainsKey("$_") } })
        renamed = $(if ($null -ne $rn) { [ordered]@{ from = "$(Get-PimPolicyTplProp $rn 'from')"; by = "$(Get-PimPolicyTplProp $rn 'by')"; utc = "$(Get-PimPolicyTplProp $rn 'utc')" } } else { $null })
        kind = $kind; kindLabel = (Get-PimPolicyTemplateKindLabel $kind)
        activation = $null; activationChecks = ''; mfa = $false; justification = $false; ticket = $false; authenticationContext = ''
        approval = [ordered]@{ required = $false; mode = ''; approversSource = ''; approversText = ''; escalationHours = $null }
        eligible = $null; active = $null; eligibleChecks = ''; activeChecks = ''
        notifications = @(); owner = $null; otherRules = @(); lines = @()
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $en = if ($rules.Contains('Enablement')) { $rules['Enablement'] } else { $null }
    $legacy = if ($rules.Contains('Member_Enablement_EndUser_Assignment_enabledRules')) { $rules['Member_Enablement_EndUser_Assignment_enabledRules'] } else { $null }
    $sec = Get-PimPolicyRoleSection -Expiration $(if ($rules.Contains('Expiration')) { $rules['Expiration'] } else { $null }) -Enablement $en -LegacyEndUser $legacy
    $d.activation = $sec.activation; $d.eligible = $sec.eligible; $d.active = $sec.active
    $d.activationChecks = $sec.activationChecks; $d.eligibleChecks = $sec.eligibleChecks; $d.activeChecks = $sec.activeChecks
    $actList = @(@(Get-PimPolicyTplProp $en 'EndUser_Assignment') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $actList.Count -and $null -ne $legacy) { $actList = @(@($legacy) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
    $d.mfa = [bool](@($actList) -contains 'MultiFactorAuthentication')
    $d.justification = [bool](@($actList) -contains 'Justification')
    $d.ticket = [bool](@($actList) -contains 'Ticketing')
    foreach ($l in $sec.lines) { $lines.Add($l) }

    # Authentication context: a rule key or an Enablement value -- none of the shipped templates carries one.
    $ac = $null
    foreach ($k in @('AuthenticationContext', 'AuthenticationContext_EndUser_Assignment')) { if ($rules.Contains($k)) { $ac = $rules[$k] } }
    if ($null -ne $ac) {
        $claim = "$(Get-PimPolicyTplProp $ac 'claimValue')"; if (-not $claim) { $claim = "$(Get-PimPolicyTplProp $ac 'id')" }
        if (-not $claim -and $ac -is [string]) { $claim = $ac }
        $d.authenticationContext = $(if ($claim) { $claim } else { (ConvertTo-Json -InputObject $ac -Depth 6 -Compress) })
        $lines.Add("Activation needs Conditional Access authentication context '$($d.authenticationContext)'.")
    } elseif (@($actList) -contains 'AuthenticationContext') { $d.authenticationContext = '(named in the activation checks)' }
    else { $lines.Add('No Conditional Access authentication context is set.') }

    if ($rules.Contains('Approval') -and $null -ne $rules['Approval']) {
        $ap = $rules['Approval']
        $d.approval.required = $true
        $d.approval.mode = "$(Get-PimPolicyTplProp $ap 'mode')"
        $d.approval.approversSource = "$(Get-PimPolicyTplProp $ap 'approversSource')"
        $d.approval.approversText = Get-PimPolicyApproversText $d.approval.approversSource
        $eh = Get-PimPolicyTplProp $ap 'escalationHours'; if ($null -ne $eh -and "$eh" -ne '') { $d.approval.escalationHours = [int]$eh }
        $modeText = if ($d.approval.mode -ieq 'Serial') { "serial: the first approver decides$(if ($null -ne $d.approval.escalationHours) { ", and after $($d.approval.escalationHours) hour(s) it escalates to the next" })" }
                    elseif ($d.approval.mode -ieq 'Parallel') { 'parallel: any one approver decides' }
                    elseif ($d.approval.mode) { $d.approval.mode } else { 'mode not set' }
        $lines.Add("Activation needs APPROVAL ($modeText). Approvers: $($d.approval.approversText).")
    } else {
        $lines.Add('No approval is needed to activate. On the delegations that use it the engine switches an approval it finds on the policy OFF; groups and roles covered only by the baseline sweep keep whatever approval they have.')
    }

    if ($rules.Contains('Notification') -and $null -ne $rules['Notification']) {
        $nl = New-Object System.Collections.Generic.List[object]
        foreach ($n in @($rules['Notification'])) { $t = Get-PimPolicyNotificationText $n; if ($t) { $nl.Add($t) } }
        $d.notifications = $nl.ToArray()
        $onN = @($nl | Where-Object { $_.on -and -not $_.recipientsSource }).Count
        $offN = @($nl | Where-Object { -not $_.on -and -not $_.recipientsSource }).Count
        $lines.Add("Notifications: $($nl.Count) rule(s) -- $onN on, $offN off$(if (@($nl | Where-Object { $_.recipientsSource }).Count) { ', plus a redirect to named people' }).")
    } else { $lines.Add('Notifications are not set by this template (the tenant''s current settings stay).') }

    if ($rules.Contains('Owner') -and $null -ne $rules['Owner']) {
        $ob = $rules['Owner']
        $osec = Get-PimPolicyRoleSection -Expiration (Get-PimPolicyTplProp $ob 'Expiration') -Enablement (Get-PimPolicyTplProp $ob 'Enablement') -LegacyEndUser $null
        $on = New-Object System.Collections.Generic.List[object]
        foreach ($n in @(Get-PimPolicyTplProp $ob 'Notification')) { $t = Get-PimPolicyNotificationText $n; if ($t) { $on.Add($t) } }
        $d.owner = [ordered]@{ activation = $osec.activation; eligible = $osec.eligible; active = $osec.active; activationChecks = $osec.activationChecks
                               eligibleChecks = $osec.eligibleChecks; activeChecks = $osec.activeChecks; notifications = $on.ToArray(); lines = $osec.lines }
        $lines.Add("The group's OWNER role gets its own policy too: activation at most $(if ($osec.activation) { $osec.activation.text } else { '(not set)' })$(if ($osec.activationChecks) { ", $($osec.activationChecks) required" }). Approval is never managed on the owner policy.")
    }

    # 2026-09-21 (operator: "i need a edit button ... so i can finetune the templates"): the EFFECTIVE raw values the
    # Manager's template editor starts from -- per policy part (member; owner for a group template). Only what
    # Set-PimPolicyTemplateRules may change: the three expirations, what ACTIVATION asks for, and the default-recipient
    # switch of each notification rule that is not a named-people redirect. The admin-path enablement is not here.
    $editPart = {
        param($exp, $enab, $notif, $legacyAct)
        $e = [ordered]@{}
        foreach ($k in @('EndUser_Assignment', 'Admin_Eligibility', 'Admin_Assignment')) {
            $nd = Get-PimPolicyTplProp $exp $k
            if ($null -ne $nd) { $e[$k] = [ordered]@{ maximumDuration = "$(Get-PimPolicyTplProp $nd 'maximumDuration')"; isExpirationRequired = [bool](Get-PimPolicyTplProp $nd 'isExpirationRequired') } }
        }
        $chk = @(@(Get-PimPolicyTplProp $enab 'EndUser_Assignment') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if (-not $chk.Count -and $null -ne $legacyAct) { $chk = @(@($legacyAct) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
        $ns = @(foreach ($n in @($notif)) {
            if ($null -eq $n -or "$(Get-PimPolicyTplProp $n 'recipientsSource')".Trim()) { continue }
            [ordered]@{ recipientType = "$(Get-PimPolicyTplProp $n 'recipientType')"; caller = "$(Get-PimPolicyTplProp $n 'caller')"; level = "$(Get-PimPolicyTplProp $n 'level')"
                        defaultRecipientsEnabled = [bool](Get-PimPolicyTplProp $n 'defaultRecipientsEnabled') }
        })
        [ordered]@{ expiration = $e; activationChecks = @($chk); notifications = @($ns) }
    }
    $d.edit = [ordered]@{
        member = (& $editPart $(if ($rules.Contains('Expiration')) { $rules['Expiration'] } else { $null }) $en $(if ($rules.Contains('Notification')) { $rules['Notification'] } else { $null }) $legacy)
        owner  = $(if ($rules.Contains('Owner') -and $null -ne $rules['Owner']) { & $editPart (Get-PimPolicyTplProp $rules['Owner'] 'Expiration') (Get-PimPolicyTplProp $rules['Owner'] 'Enablement') (Get-PimPolicyTplProp $rules['Owner'] 'Notification') $null } else { $null })
    }

    $known = @('Expiration', 'Enablement', 'Approval', 'Notification', 'Owner', 'Member_Enablement_EndUser_Assignment_enabledRules', 'AuthenticationContext', 'AuthenticationContext_EndUser_Assignment')
    $other = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($rules.Keys)) {
        if ("$k".StartsWith('_') -or $known -contains "$k") { continue }
        $val = $rules[$k]
        $txt = if ($val -is [string] -or $val -is [ValueType]) { "$val" } else { ConvertTo-Json -InputObject $val -Depth 6 -Compress }
        [void]$other.Add([ordered]@{ key = "$k"; value = $txt })
        $lines.Add("Also carries rule '$k': $txt")
    }
    $d.otherRules = $other.ToArray()
    if ($d.extends) { $lines.Add("Builds on '$($d.extends)': it takes that template's rules and replaces the ones it sets itself.") }
    $d.lines = $lines.ToArray()
    return $d
}

function Get-PimPolicyTemplateRowLabel {
    <# How one delegation row is named on the page. #>
    param([Parameter(Mandatory)][string]$Entity, [AllowNull()][object]$Row)
    $g = { param($n) "$(Get-PimPolicyTplProp $Row $n)".Trim() }
    switch -regex ($Entity) {
        '^PIM-Definitions-' { $n = & $g 'GroupName'; if (-not $n) { $n = & $g 'GroupTag' }; return "group $n" }
        '^PIM-Assignments-Roles-Groups$' { return "role '$(& $g 'RoleDefinitionName')' <- group $(& $g 'GroupTag') (tenant-wide)" }
        '^PIM-Assignments-Roles-AUs$' { return "role '$(& $g 'RoleDefinitionName')' <- group $(& $g 'GroupTag') in AU $(& $g 'AdministrativeUnitTag')" }
        '^PIM-Assignments-Roles-Direct$' { $p = & $g 'UserPrincipalName'; if (-not $p) { $p = & $g 'Username' }; return "role '$(& $g 'RoleDefinitionName')' <- $p (direct)" }
        '^PIM-Assignments-Azure-Resources$' { return "Azure role '$(& $g 'AzScopePermission')' at $(& $g 'AzScope') <- group $(& $g 'GroupTag')" }
        default { return "$Entity row" }
    }
}

function Test-PimPolicyTemplateRowCounts {
    <# Does the ENGINE read this row's PolicyTemplate? Same filters as its readers. #>
    param([Parameter(Mandatory)][string]$Entity, [AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    if ($Entity -like 'PIM-Definitions-*') {
        if (-not "$(Get-PimPolicyTplProp $Row 'GroupName')".Trim()) { return $false }
        if ("$(Get-PimPolicyTplProp $Row 'Lifecycle')".Trim() -match '(?i)^retire') { return $false }
        return $true
    }
    if ("$(Get-PimPolicyTplProp $Row 'Action')".Trim() -eq 'Remove') { return $false }
    if ($Entity -eq 'PIM-Assignments-Azure-Resources') {
        return [bool]("$(Get-PimPolicyTplProp $Row 'AzScope')".Trim() -and "$(Get-PimPolicyTplProp $Row 'AzScopePermission')".Trim())
    }
    $rn = "$(Get-PimPolicyTplProp $Row 'RoleDefinitionName')".Trim(); if (-not $rn) { $rn = "$(Get-PimPolicyTplProp $Row 'RoleName')".Trim() }
    return [bool]$rn
}

function Get-PimPolicyTemplatesView {
    <#
      The whole read-only page model. PURE.
        -Value         the stored pim.Settings 'PolicyTemplates' value (object / JSON / id->template map)
        -StoreError    why the store could not be read ('' when it was)
        -RowsByEntity  entity -> rows the caller may see
        -ReadErrors    entity -> why its rows could not be read
      Returns @{ readable; reason; defaults; entities; templates[]; unknownTemplates[]; notChecked[]; totals }.
      A store that cannot be read is NOT an empty store: readable=$false with the reason.
    #>
    param([AllowNull()][object]$Value, [string]$StoreError = '', [hashtable]$RowsByEntity = @{}, [hashtable]$ReadErrors = @{}, [int]$MaxRowsPerTemplate = 500,
          # 2026-09-19 ("set default in settings"): the stored pim.Settings['PolicyTemplateDefaults'] value.
          [AllowNull()][object]$DefaultsSetting = $null)
    $defaults = Get-PimPolicyTemplateTypeDefaults
    $ents = @(Get-PimPolicyTemplateUsageEntities)
    $codeDefaults = if (Get-Command Get-PimPolicyTemplateCodeDefaults -ErrorAction SilentlyContinue) { Get-PimPolicyTemplateCodeDefaults } else { $defaults }
    $view = [ordered]@{ readable = $true; reason = ''; defaults = $defaults; defaultsSource = [ordered]@{}; defaultsWarnings = @(); codeDefaults = $codeDefaults
                        entities = $ents; templates = @(); unknownTemplates = @(); notChecked = @(); storeSource = ''; storeSeededUtc = '' }
    $notChecked = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($ReadErrors.Keys)) { [void]$notChecked.Add([ordered]@{ entity = "$e"; reason = "$($ReadErrors[$e])" }) }
    $view.notChecked = @($notChecked.ToArray() | Sort-Object { $_.entity })

    if ("$StoreError".Trim()) { $view.readable = $false; $view.reason = "The template store could not be read: $StoreError"; return $view }
    $map = @{}
    if (Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue) { $map = ConvertTo-PimPolicyTemplateMap -Value $Value }
    else { $view.readable = $false; $view.reason = 'The template store reader is not loaded in this Manager.'; return $view }
    if ($map.Count -eq 0) {
        $view.readable = $false
        $view.reason = "The template store is EMPTY (pim.Settings 'PolicyTemplates' holds no template). The engine then has nothing to apply; the Manager and the db-init job seed it on start."
        return $view
    }
    # The per-kind defaults as the ENGINE resolves them against THIS store (setting, else built-in, as stored keys).
    if (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue) {
        $rd = Resolve-PimPolicyTemplateTypeDefaults -Setting $DefaultsSetting -Map $map
        $defaults = $rd.defaults; $view.defaults = $defaults; $view.defaultsSource = $rd.source; $view.defaultsWarnings = @($rd.warnings)
    }
    $meta = $null; $upg = @{}
    if (Get-Command Get-PimPolicyTemplateStoreMeta -ErrorAction SilentlyContinue) { $meta = Get-PimPolicyTemplateStoreMeta -Value $Value }
    if ($meta) { $view.storeSource = "$($meta.source)"; $view.storeSeededUtc = "$($meta.seededUtc)" }
    $pv = $Value; if ($pv -is [string]) { try { $pv = $pv | ConvertFrom-Json } catch { $pv = $null } }
    foreach ($u in @(Get-PimPolicyTplProp $pv 'upgradeAvailable')) {
        if ($null -eq $u) { continue }
        $uid = "$(Get-PimPolicyTplProp $u 'id')"; if ($uid) { $upg[$uid] = @(@(Get-PimPolicyTplProp $u 'changes') | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
    }

    # Usage: explicit (the row names it) and by-default (blank -> the type's standard), per template id.
    $explicit = @{}; $byDefault = @{}; $unknown = @{}
    # 2026-09-21 (operator: "i must see exactly where the policy is linked in the used by"): the delegations that get a
    # template through the default (blank PolicyTemplate) are LISTED too, not only counted.
    $defaultRows = @{}
    foreach ($ent in $ents) {
        $e = $ent.entity
        if (-not $RowsByEntity.ContainsKey($e)) { continue }
        foreach ($r in @($RowsByEntity[$e])) {
            if (-not (Test-PimPolicyTemplateRowCounts -Entity $e -Row $r)) { continue }
            $tv = "$(Get-PimPolicyTplProp $r 'PolicyTemplate')".Trim()
            if (-not $tv) {
                $did = "$($defaults[$ent.kind])"
                if (-not $byDefault.ContainsKey($did)) { $byDefault[$did] = [ordered]@{} }
                if (-not $byDefault[$did].Contains($e)) { $byDefault[$did][$e] = 0 }
                $byDefault[$did][$e]++
                if (-not $defaultRows.ContainsKey($did)) { $defaultRows[$did] = New-Object System.Collections.Generic.List[object] }
                [void]$defaultRows[$did].Add([ordered]@{ entity = $e; kind = $ent.kind; label = (Get-PimPolicyTemplateRowLabel -Entity $e -Row $r); fits = $true; byDefault = $true })
                continue
            }
            $item = [ordered]@{ entity = $e; kind = $ent.kind; label = (Get-PimPolicyTemplateRowLabel -Entity $e -Row $r); fits = $true }
            # Resolved like the engine: id, current name, former id -- a row naming 'approval-required' uses Groups_RequireApproval.
            $tk = Resolve-PimPolicyTplKey -Map $map -Id $tv
            if (-not $tk) {
                if (-not $unknown.ContainsKey($tv)) { $unknown[$tv] = New-Object System.Collections.Generic.List[object] }
                [void]$unknown[$tv].Add($item); continue
            }
            if ($tk -cne $tv) { $item['namedAs'] = $tv }
            $item.fits = Test-PimPolicyTemplateFitsKind -TemplateKind (Get-PimPolicyTemplateKind -Map $map -Id $tk) -RowKind $ent.kind
            if (-not $explicit.ContainsKey($tk)) { $explicit[$tk] = New-Object System.Collections.Generic.List[object] }
            [void]$explicit[$tk].Add($item)
        }
    }

    # Order: the three kinds' defaults first (group, Entra role, Azure role), then every other template by id.
    $defOrder = @(@($defaults.Values) | ForEach-Object { "$_" })
    $ids = @(@($map.Keys) | Sort-Object { $k = "$_"; $i = [array]::IndexOf($defOrder, $k); if ($i -ge 0) { $i } else { 99 } }, { "$_" })
    $tpls = New-Object System.Collections.Generic.List[object]
    foreach ($id in $ids) {
        $desc = Get-PimPolicyTemplateDescription -Map $map -Id "$id"
        if ($null -eq $desc) { continue }
        $standardFor = @(@($defaults.Keys) | Where-Object { "$($defaults[$_])" -eq "$id" } | ForEach-Object { "$_" })
        # @(...) around the whole if: a one-row result would otherwise unwrap to the row itself (whose .Count is its key count).
        $rows = @(if ($explicit.ContainsKey("$id")) { $explicit["$id"].ToArray() })
        $bd = if ($byDefault.ContainsKey("$id")) { $byDefault["$id"] } else { [ordered]@{} }
        $bdTotal = 0; foreach ($k in @($bd.Keys)) { $bdTotal += [int]$bd[$k] }
        $desc['standardFor'] = $standardFor
        $desc['standardForText'] = @($standardFor | ForEach-Object { switch ($_) { 'group' { 'group definitions' } 'directoryRole' { 'Entra ID role rows' } 'azureRole' { 'Azure resource role rows' } default { "$_" } } })
        $desc['shipped'] = [bool]($meta -and $meta.shipped.ContainsKey("$id"))
        $desc['upgradeAvailable'] = $upg.ContainsKey("$id")
        # @(...) not $(...): a subexpression unwraps a one-item list to a scalar, and the page then gets a string.
        $desc['upgradeChanges'] = @(if ($upg.ContainsKey("$id")) { $upg["$id"] })
        $desc['usage'] = [ordered]@{
            count = $rows.Count
            rows = @($rows | Select-Object -First $MaxRowsPerTemplate)
            truncated = ($rows.Count -gt $MaxRowsPerTemplate)
            misfits = @($rows | Where-Object { -not $_.fits }).Count
            byDefault = $bd
            byDefaultTotal = $bdTotal
            defaultRows = @(if ($defaultRows.ContainsKey("$id")) { $defaultRows["$id"].ToArray() | Select-Object -First $MaxRowsPerTemplate })
            defaultRowsTruncated = [bool]($defaultRows.ContainsKey("$id") -and $defaultRows["$id"].Count -gt $MaxRowsPerTemplate)
        }
        [void]$tpls.Add($desc)
    }
    $view.templates = $tpls.ToArray()
    $unk = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($unknown.Keys | Sort-Object)) { [void]$unk.Add([ordered]@{ id = "$k"; count = $unknown[$k].Count; rows = @($unknown[$k].ToArray() | Select-Object -First $MaxRowsPerTemplate) }) }
    $view.unknownTemplates = $unk.ToArray()
    return $view
}
