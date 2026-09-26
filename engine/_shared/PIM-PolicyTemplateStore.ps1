#Requires -Version 5.1
<#
  PIM4EntraPS -- PIM POLICY TEMPLATES LIVE IN SQL (operator, 2026-09-12: "move templates to sql").

  The engine used to read templates/policy/*.policytemplate.json (+ *.policytemplate.custom.json
  overrides) from disk on every run. Now:
    * the SHIPPED templates are the BASELINE in pim.Settings['PolicyTemplates'];
    * every reader (engine providers, Manager validator) reads SQL only;
    * the .custom.json override files are gone (no file overrides).

  Storage shape (pim.Settings, not a new table, because that is where every other shipped default is
  seeded and hydrated from -- Get-PimAllSqlSettings -> $global:PIM_NamingConventions):
      PolicyTemplates = {
        source; seededUtc; updatedUtc; fingerprint;          # fingerprint = BUG-55 hash of the STORED content
        fileNames = { <id> = <file> };
        templates = { <id> = <template> };
        shipped   = { <id> = { fingerprint; file; recordedUtc } }   # the shipped content each template CAME FROM
        upgradeAvailable = [ { id; storedFingerprint; shippedFingerprint; recordedShippedFingerprint; changes[] } ]
      }

  SHIPPED UPGRADES WITH BUG-55 SEMANTICS (coordinator, 2026-09-12). Seeding once and never touching
  the store again meant an existing store would never receive new shipped content (the Owner block,
  v1's notification rules). Update-PimPolicyTemplateStore runs at db-init / Manager boot / migration:
    * a shipped template NOT in the store is seeded;
    * a stored template that is UNMODIFIED (its hash == the recorded shipped fingerprint) is upgraded
      to the new shipped content, logged and audited ('policy.template.upgraded');
    * a stored template that was CUSTOMISED (hash != recorded shipped fingerprint, or no record) is
      KEPT and flagged in upgradeAvailable -- the validator reports TEMPLATE-UPGRADE-AVAILABLE naming
      what the new shipped version changes. Never overwritten silently;
    * templates only in the store are kept;
    * a run that changes nothing writes nothing (idempotent).
  An upgrade DOES change what the engine wants; that is deliberate for unmodified baselines (a shipped
  fix), and the Azure policy mass-change breaker and the BUG-55 fingerprint still gate what a change
  may do to the tenant.

  LEGACY STORES (seeded before the 'shipped' record existed): when the store's recorded fingerprint
  equals the hash of its current content, nothing was edited since the seed, so every template's
  recorded shipped fingerprint is its current hash. Otherwise nothing is assumed: every template is
  treated as customised (kept + flagged).

  PURE except the functions that take a -ConnectionString. PS 5.1; ASCII only (no BOM).
#>

Set-StrictMode -Off

function Read-PimShippedPolicyTemplates {
    <# The SEED source: shipped templates/policy/*.policytemplate.json, id -> parsed object.
       *.custom.* files are ignored by design (no file overrides). -FileNames receives id -> file name,
       kept on the stored value so the SQL fingerprint keys exactly like the directory fingerprint. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$TemplateDir, [hashtable]$FileNames)
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $TemplateDir)) { return $map }
    foreach ($f in @(Get-ChildItem -LiteralPath $TemplateDir -Filter '*.policytemplate.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.custom\.' } | Sort-Object Name)) {
        try {
            $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            if ("$($j.id)".Trim()) { $map["$($j.id)"] = $j; if ($null -ne $FileNames) { $FileNames["$($j.id)"] = $f.Name } }
        } catch { Write-Warning "  [policy] shipped template '$($f.Name)' unreadable: $($_.Exception.Message)" }
    }
    return $map
}

function ConvertTo-PimPolicyTemplateMap {
    <# Normalise a stored/hydrated PolicyTemplates value (object, JSON string, or a bare id->template
       map) to a hashtable id -> template object. $null/empty -> empty hashtable. #>
    param([AllowNull()][object]$Value)
    $out = @{}
    if ($null -eq $Value) { return $out }
    $v = $Value
    if ($v -is [string]) { if (-not "$v".Trim()) { return $out }; try { $v = $v | ConvertFrom-Json } catch { return $out } }
    $tpls = $null
    if ($v -is [System.Collections.IDictionary]) { $tpls = if ($v.Contains('templates')) { $v['templates'] } else { $v } }
    elseif ($v.PSObject.Properties['templates']) { $tpls = $v.templates }
    else { $tpls = $v }
    if ($null -eq $tpls) { return $out }
    if ($tpls -is [System.Collections.IDictionary]) { foreach ($k in @($tpls.Keys)) { if ($null -ne $tpls[$k]) { $out["$k"] = $tpls[$k] } } }
    else { foreach ($p in $tpls.PSObject.Properties) { if ($null -ne $p.Value) { $out["$($p.Name)"] = $p.Value } } }
    return $out
}

# ---- TEMPLATE ID, NAME, ALIAS, PER-KIND DEFAULT (operator 2026-09-19) ------------------------------------------
# "why dont we have 2 policy template for azure" / "and why not 2 for PIM4Groups" / "give policies an id so we can
# rename them" / "set default in settings".
#   * ID    -- the template's key in pim.Settings['PolicyTemplates'] (and its 'id' property). IMMUTABLE: a row's
#              PolicyTemplate, a template's 'extends' and the per-kind defaults point at it. Shipped ids:
#              Groups_Standard, Groups_RequireApproval, EntraIDRoles_Standard, EntraIDRoles_RequireApproval,
#              AzureRoles_Standard, AzureRoles_RequireApproval.
#   * NAME  -- the display label ('name'). Editable (Set-PimPolicyTemplateName, from the Policy templates page); a
#              rename changes nothing a row points at, and is not desired state (the BUG-55 hash ignores it).
#   * ALIAS -- a former id, still accepted (Get-PimPolicyTemplateAliases, PIM-PolicyBaseline.ps1):
#              'default' -> Groups_Standard, 'approval-required' -> Groups_RequireApproval.
# RESOLUTION ORDER (Resolve-PimPolicyTemplateKey; the engine, the validator, the catalog and the GUI resolve alike):
#   1. the id (the stored key, case-insensitive); 2. the current name of exactly ONE stored template; 3. the alias
#   twin -- former -> current, and current -> former for a store that was not renamed yet (an engine newer than its
#   store), so a blank group PolicyTemplate keeps working in that window too.
# Update-PimPolicyTemplateStore renames a stored former key to its current id ONCE (content and customisations kept,
# audited 'policy.template.renamed') and gives every stored template that lacks one an 'id' equal to its key.
# PER-KIND DEFAULTS: pim.Settings['PolicyTemplateDefaults'] = { group; directoryRole; azureRole } -- the template a
# BLANK PolicyTemplate means for that kind of policy (Resolve-PimPolicyTemplateTypeDefaults). Unset = the built-in
# defaults below, which ARE today's behaviour, so an environment that never sets it changes nothing.
if (-not (Get-Command Get-PimPolicyTemplateAliases -ErrorAction SilentlyContinue)) {
    $__ptBaselineLib = Join-Path $PSScriptRoot 'PIM-PolicyBaseline.ps1'
    if (Test-Path -LiteralPath $__ptBaselineLib) { . $__ptBaselineLib }
}

function Resolve-PimPolicyTemplateKey {
    <# PURE: the key under which -Map holds the template -Id names, in the order above: the id, then the current name
       of exactly one template, then the alias twin. '' when none. Case-insensitive, like the engine's own lookup. #>
    param([AllowNull()][System.Collections.IDictionary]$Map, [AllowNull()][string]$Id)
    $t = "$Id".Trim()
    if (-not $t -or $null -eq $Map) { return '' }
    $keys = @(@($Map.Keys) | ForEach-Object { "$_" })
    foreach ($k in $keys) { if ($k -ieq $t) { return $k } }
    $byName = @($keys | Where-Object { "$(Get-PimTemplateProp $Map[$_] 'name')".Trim() -ieq $t })
    if ($byName.Count -eq 1) { return $byName[0] }
    if (Get-Command Get-PimPolicyTemplateAliasNames -ErrorAction SilentlyContinue) {
        foreach ($n in @(Get-PimPolicyTemplateAliasNames $t)) { foreach ($k in $keys) { if ($k -ieq $n) { return $k } } }
    }
    return ''
}

function Get-PimPolicyTemplateDefaultsSettingName { return 'PolicyTemplateDefaults' }

function Get-PimPolicyTemplateCodeDefaults {
    <# PURE: the per-kind default when pim.Settings['PolicyTemplateDefaults'] sets none -- today's effective
       behaviour (AzureRoles_Standard carries exactly the rules Azure policies had from EntraIDRoles_Standard). #>
    return [ordered]@{ group = 'Groups_Standard'; directoryRole = 'EntraIDRoles_Standard'; azureRole = 'AzureRoles_Standard' }
}

function Resolve-PimPolicyTemplateTypeDefaults {
    <#
      PURE. What a BLANK PolicyTemplate means, per kind of policy.
        -Setting  the stored pim.Settings['PolicyTemplateDefaults'] ({ group; directoryRole; azureRole }), or $null
        -Map      the stored templates (id -> template). Optional: without it the ids are returned as named.
      Per kind: the setting's value when set and (with a map) it resolves to a stored template; otherwise the built-in
      default. With a map the answer is the STORED key it resolves to ('default' in a store not yet renamed). azureRole
      falls back to EntraIDRoles_Standard when the store has no AzureRoles_Standard yet (an engine newer than its
      store) -- the template Azure policies used until 2026-09-19, with identical rules.
      Returns @{ defaults = [ordered]@{ group; directoryRole; azureRole }; source = @{ <kind> = setting|code|fallback };
                 warnings = @() } -- a setting that names a template the store lacks is a WARNING, never silent.
    #>
    param([AllowNull()][object]$Setting, [AllowNull()][System.Collections.IDictionary]$Map)
    $code = Get-PimPolicyTemplateCodeDefaults
    $set = $Setting
    if ($set -is [string]) { if ("$set".Trim()) { try { $set = $set | ConvertFrom-Json } catch { $set = $null } } else { $set = $null } }
    $out = [ordered]@{}; $src = [ordered]@{}
    $warn = New-Object System.Collections.Generic.List[string]
    foreach ($kind in @($code.Keys)) {
        $want = "$(Get-PimTemplateProp $set $kind)".Trim()
        $pick = ''; $how = ''
        if ($want) {
            if ($null -eq $Map) { $pick = $want; $how = 'setting' }
            else {
                $k = Resolve-PimPolicyTemplateKey -Map $Map -Id $want
                if ($k) { $pick = $k; $how = 'setting' }
                else { [void]$warn.Add("pim.Settings 'PolicyTemplateDefaults' names '$want' as the $kind default, but the template store has no such template -- the built-in default '$($code[$kind])' is used instead") }
            }
        }
        if (-not $pick) {
            $cd = "$($code[$kind])"
            $pick = $cd; $how = 'code'
            if ($null -ne $Map) {
                $k = Resolve-PimPolicyTemplateKey -Map $Map -Id $cd
                if ($k) { $pick = $k }
                elseif ($kind -eq 'azureRole') {
                    $k2 = Resolve-PimPolicyTemplateKey -Map $Map -Id 'EntraIDRoles_Standard'
                    if ($k2) { $pick = $k2; $how = 'fallback' }
                }
            }
        }
        $out[$kind] = $pick; $src[$kind] = $how
    }
    return @{ defaults = $out; source = $src; warnings = @($warn.ToArray()) }
}

function Set-PimPolicyTemplateName {
    <#
      RENAME a stored template: changes its display NAME only (operator 2026-09-19: "give policies an id so we can
      rename them"). The id -- what every row, 'extends' and the per-kind defaults point at -- never changes, so no
      reference moves and no rule changes: the BUG-55 fingerprint of the store is the same before and after (the hash
      ignores 'name'). The template records '_renamed' { from; by; utc } so a later shipped upgrade keeps the name.
      Refused (throws, nothing written): an unknown id, an empty / over-long / control-character name, or a name that
      is already another template's id or name (a name is also accepted where an id is -- it must stay unambiguous).
      Read back after the write. Returns @{ id; before; after; fingerprintBefore; fingerprintAfter }.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [string]$Actor = 'system:policy-template-store',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $new = "$Name".Trim()
    if (-not $new) { throw 'Set-PimPolicyTemplateName: the name is empty.' }
    if ($new.Length -gt 80) { throw "Set-PimPolicyTemplateName: the name is $($new.Length) characters; at most 80." }
    if ($new -match '[\x00-\x1f\x7f]') { throw 'Set-PimPolicyTemplateName: the name contains a control character.' }
    $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    $v = $existing; if ($v -is [string]) { $v = $v | ConvertFrom-Json }
    $map = ConvertTo-PimPolicyTemplateMap -Value $v
    if (-not $map.Count) { throw 'Set-PimPolicyTemplateName: the template store is empty or unreadable -- nothing to rename.' }
    $key = ''; foreach ($k in @($map.Keys)) { if ("$k" -ieq "$Id".Trim()) { $key = "$k" } }
    if (-not $key) { throw "Set-PimPolicyTemplateName: no template with id '$Id' in the store (rename by id, never by name)." }
    foreach ($k in @($map.Keys)) {
        if ("$k" -ieq $key) { continue }
        if ("$k" -ieq $new -or "$(Get-PimTemplateProp $map[$k] 'name')".Trim() -ieq $new) { throw "Set-PimPolicyTemplateName: '$new' is already the id or name of template '$k' -- a name must be unambiguous." }
        if (@(Get-PimPolicyTemplateAliasNames "$k") -icontains $new) { throw "Set-PimPolicyTemplateName: '$new' is a former id of template '$k' and still resolves to it." }
    }
    $before = "$(Get-PimTemplateProp $map[$key] 'name')"
    $fpBefore = (Get-PimPolicyTemplateStoreFingerprint -Value $v).hash
    $tplObj = if ($v -is [System.Collections.IDictionary]) { $v['templates'] } else { $v.templates }
    $t = if ($tplObj -is [System.Collections.IDictionary]) { $tplObj[$key] } else { $tplObj.PSObject.Properties[$key].Value }
    if ($t -is [System.Collections.IDictionary]) { $t['name'] = $new; $t['_renamed'] = [ordered]@{ from = $before; by = $Actor; utc = $NowUtc.ToUniversalTime().ToString('o') } }
    else {
        $t | Add-Member -NotePropertyName name -NotePropertyValue $new -Force
        $t | Add-Member -NotePropertyName _renamed -NotePropertyValue ([pscustomobject][ordered]@{ from = $before; by = $Actor; utc = $NowUtc.ToUniversalTime().ToString('o') }) -Force
    }
    if ($v -is [System.Collections.IDictionary]) { $v['updatedUtc'] = $NowUtc.ToUniversalTime().ToString('o') }
    elseif ($v.PSObject.Properties['updatedUtc']) { $v.updatedUtc = $NowUtc.ToUniversalTime().ToString('o') }
    Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates' -Value $v
    # Read back: a write that did not land must not report success.
    $back = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    $bm = ConvertTo-PimPolicyTemplateMap -Value $back
    $bk = ''; foreach ($k in @($bm.Keys)) { if ("$k" -ieq $key) { $bk = "$k" } }
    if (-not $bk -or "$(Get-PimTemplateProp $bm[$bk] 'name')" -cne $new -or $bm.Count -ne $map.Count) { throw "Set-PimPolicyTemplateName: read-back mismatch -- the store does not hold the new name for '$key'." }
    $fpAfter = (Get-PimPolicyTemplateStoreFingerprint -Value $back).hash
    return [ordered]@{ id = $key; before = $before; after = $new; fingerprintBefore = $fpBefore; fingerprintAfter = $fpAfter }
}

function Test-PimIso8601Duration {
    <#
      PURE. Is this an ISO-8601 duration Entra will accept for a PIM policy ceiling (PT8H / P1D / P365D)?
      Deliberately NARROW: days and hours/minutes only, positive, no years/months (Entra rejects them on
      these rules and "P1M" reads as one month to a human and one minute to nobody). '' is legal and means
      "no rule" -- the caller decides whether blank is allowed, not this function.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $true }
    return [bool]($v -match '^P(?!$)(\d+D)?(T(?!$)(\d+H)?(\d+M)?)?$')
}

function Set-PimPolicyTemplateExpiration {
    <#
      REQ-GRID (operator 2026-09-20: "where can i modify the policy templates"). The Policy templates page
      was READ-ONLY: the store had a renamer and a per-kind default picker, and NOTHING that could change a
      rule. So the one thing customers most want to tune -- how long an assignment or eligibility may last
      -- could not be touched from the Manager at all.

      Changes the Expiration ceilings of ONE template: EndUser_Assignment (activation), Admin_Assignment,
      Admin_Eligibility. Only the keys passed are touched; the rest of the template is left byte-identical.

      LOCKED -- IT WILL NOT TOUCH `Enablement`, AND THAT IS DELIBERATE. BUG-21: Admin_Eligibility must NEVER require
      MultiFactorAuthentication -- the "admin" making that request is the engine's own app-only certificate
      SPN, whose token can never carry an MFA claim, so Entra rejects EVERY eligibility the engine creates
      (400 RoleAssignmentRequestPolicyValidationFailed / MfaRule). A/B tested live 2026-08-10. Exposing that
      array to a GUI is how a tenant's core delegation path gets switched off by a well-meaning edit, so this
      writer has no parameter for it.

      WARNING -- THIS CHANGES DESIRED STATE. The engine converges every managed scope onto the template, and the
      store fingerprint moves -- which is exactly what the BUG-55 gate refuses on the next update until an
      operator accepts it. The caller is handed both fingerprints so it can say so rather than surprise
      someone. Read back after the write; a write that did not land is not reported as success.
      Returns @{ id; changed; before; after; fingerprintBefore; fingerprintAfter }.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Id,
        [hashtable]$Durations = @{},
        [string]$Actor = 'system:policy-template-store',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $allowed = @('EndUser_Assignment', 'Admin_Assignment', 'Admin_Eligibility')
    $want = [ordered]@{}
    foreach ($k in @($Durations.Keys)) {
        $kk = "$k".Trim()
        if ($allowed -notcontains $kk) { throw "Set-PimPolicyTemplateExpiration: '$kk' is not an expiration rule this writer may change (allowed: $($allowed -join ', ')). The sign-in and approval rules are deliberately not editable here: requiring multi-factor authentication on the eligible path makes Entra reject every eligibility this product creates." }
        $dv = "$($Durations[$k])".Trim()
        if (-not $dv) { throw "Set-PimPolicyTemplateExpiration: '$kk' is blank. A ceiling of 'no rule' is not set from here; leave the key out to keep the current value." }
        if (-not (Test-PimIso8601Duration -Value $dv)) { throw "Set-PimPolicyTemplateExpiration: '$dv' is not a supported ISO-8601 duration for '$kk'. Use days and/or hours, e.g. P90D, P365D, PT8H." }
        $want[$kk] = $dv
    }
    if (-not $want.Count) { throw 'Set-PimPolicyTemplateExpiration: nothing to change.' }

    $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    $v = $existing; if ($v -is [string]) { $v = $v | ConvertFrom-Json }
    $map = ConvertTo-PimPolicyTemplateMap -Value $v
    if (-not $map.Count) { throw 'Set-PimPolicyTemplateExpiration: the template store is empty or unreadable -- nothing to change.' }
    $key = ''; foreach ($k in @($map.Keys)) { if ("$k" -ieq "$Id".Trim()) { $key = "$k" } }
    if (-not $key) { throw "Set-PimPolicyTemplateExpiration: no template with id '$Id' in the store." }

    $fpBefore = (Get-PimPolicyTemplateStoreFingerprint -Value $v).hash
    $tplObj = if ($v -is [System.Collections.IDictionary]) { $v['templates'] } else { $v.templates }
    $t = if ($tplObj -is [System.Collections.IDictionary]) { $tplObj[$key] } else { $tplObj.PSObject.Properties[$key].Value }
    $rules = if ($t -is [System.Collections.IDictionary]) { $t['rules'] } else { $t.rules }
    if (-not $rules) { throw "Set-PimPolicyTemplateExpiration: template '$key' has no rules block." }
    $exp = if ($rules -is [System.Collections.IDictionary]) { $rules['Expiration'] } else { $rules.Expiration }
    if (-not $exp) { throw "Set-PimPolicyTemplateExpiration: template '$key' has no Expiration rules." }

    $before = [ordered]@{}; $after = [ordered]@{}; $changed = @()
    foreach ($kk in @($want.Keys)) {
        $node = if ($exp -is [System.Collections.IDictionary]) { $exp[$kk] } else { $exp.PSObject.Properties[$kk].Value }
        if (-not $node) { throw "Set-PimPolicyTemplateExpiration: template '$key' has no '$kk' expiration rule to change." }
        $cur = if ($node -is [System.Collections.IDictionary]) { "$($node['maximumDuration'])" } else { "$($node.maximumDuration)" }
        $before[$kk] = $cur
        $after[$kk] = $want[$kk]
        if ($cur -cne $want[$kk]) {
            if ($node -is [System.Collections.IDictionary]) { $node['maximumDuration'] = $want[$kk] }
            else { $node | Add-Member -NotePropertyName maximumDuration -NotePropertyValue $want[$kk] -Force }
            $changed += $kk
        }
    }
    if (-not $changed.Count) {
        return [ordered]@{ id = $key; changed = @(); before = $before; after = $after; fingerprintBefore = $fpBefore; fingerprintAfter = $fpBefore }
    }
    $stamp = [ordered]@{ by = $Actor; utc = $NowUtc.ToUniversalTime().ToString('o'); changed = @($changed) }
    if ($t -is [System.Collections.IDictionary]) { $t['_editedExpiration'] = $stamp }
    else { $t | Add-Member -NotePropertyName _editedExpiration -NotePropertyValue ([pscustomobject]$stamp) -Force }
    if ($v -is [System.Collections.IDictionary]) { $v['updatedUtc'] = $NowUtc.ToUniversalTime().ToString('o') }
    elseif ($v.PSObject.Properties['updatedUtc']) { $v.updatedUtc = $NowUtc.ToUniversalTime().ToString('o') }

    Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates' -Value $v
    $back = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    $bm = ConvertTo-PimPolicyTemplateMap -Value $back
    $bk = ''; foreach ($k in @($bm.Keys)) { if ("$k" -ieq $key) { $bk = "$k" } }
    if (-not $bk -or $bm.Count -ne $map.Count) { throw "Set-PimPolicyTemplateExpiration: read-back mismatch -- the store does not hold template '$key' as expected." }
    $bRules = Get-PimTemplateProp $bm[$bk] 'rules'
    $bExp = if ($bRules -is [System.Collections.IDictionary]) { $bRules['Expiration'] } else { $bRules.Expiration }
    foreach ($kk in @($changed)) {
        $n = if ($bExp -is [System.Collections.IDictionary]) { $bExp[$kk] } else { $bExp.PSObject.Properties[$kk].Value }
        $got = if ($n -is [System.Collections.IDictionary]) { "$($n['maximumDuration'])" } else { "$($n.maximumDuration)" }
        if ($got -cne $want[$kk]) { throw "Set-PimPolicyTemplateExpiration: read-back mismatch on '$kk' -- store holds '$got', expected '$($want[$kk])'." }
    }
    $fpAfter = (Get-PimPolicyTemplateStoreFingerprint -Value $back).hash
    return [ordered]@{ id = $key; changed = @($changed); before = $before; after = $after; fingerprintBefore = $fpBefore; fingerprintAfter = $fpAfter }
}
function ConvertTo-PimTplTree {
    # PURE. A JSON-shaped value (PSCustomObject / dictionary / array / scalar) as ordered hashtables + arrays, so an
    # edit can change it in place whatever shape the store handed back.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) { $o = [ordered]@{}; foreach ($k in @($Value.Keys)) { $o["$k"] = ConvertTo-PimTplTree $Value[$k] }; return $o }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { $o = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = ConvertTo-PimTplTree $p.Value }; return $o }
    if ($Value -is [System.Collections.IEnumerable]) { return ,@(foreach ($x in $Value) { ConvertTo-PimTplTree $x }) }
    return $Value
}

function Set-PimPolicyTemplateRules {
    <#
      Operator 2026-09-21: "i need a edit button ... so i can finetune the templates" / "use dropdown in the fields".
      Changes ONE template's rules, for one policy PART ('member' = the template's own rules; 'owner' = a group
      template's Owner block). What may change -- and nothing else:
        -Expiration        @{ <EndUser_Assignment|Admin_Eligibility|Admin_Assignment> = @{ maximumDuration; isExpirationRequired } }
                           Activation (EndUser_Assignment) must stay required to expire.
        -ActivationChecks  what ACTIVATION asks for: any of MultiFactorAuthentication, Justification, Ticketing
                           ($null = leave as is). The ADMIN-path enablement is NOT reachable: BUG-21 -- MFA on
                           Admin_Eligibility makes Entra reject every eligibility the engine creates.
        -Notifications     @( @{ recipientType; caller; level; defaultRecipientsEnabled } ) -- each must name an existing
                           rule of this part that is not a named-people redirect; only its default-recipient switch moves.
      An INHERITED block (a RequireApproval template extends its Standard one per top-level key) is copied from the base
      into this template the first time it is edited, so the edit applies to this template only.
      Desired state moves (the engine converges onto it; the policy breakers still hold a mass change for approval).
      Read back after the write. Returns @{ id; part; changed[]; fingerprintBefore; fingerprintAfter }.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$Id,
        [ValidateSet('member', 'owner')][string]$Part = 'member',
        [hashtable]$Expiration = @{},
        [AllowNull()][string[]]$ActivationChecks = $null,
        [object[]]$Notifications = @(),
        [string]$Actor = 'system:policy-template-store',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $fn = 'Set-PimPolicyTemplateRules'
    $expKeys = @('EndUser_Assignment', 'Admin_Eligibility', 'Admin_Assignment')
    $checkOk = @('MultiFactorAuthentication', 'Justification', 'Ticketing')
    foreach ($k in @($Expiration.Keys)) {
        if ($expKeys -notcontains "$k") { throw "${fn}: '$k' is not an expiration rule that may be changed (allowed: $($expKeys -join ', '))." }
        $n = $Expiration[$k]; $dv = "$($n.maximumDuration)".Trim()
        if (-not $dv -or -not (Test-PimIso8601Duration -Value $dv)) { throw "${fn}: '$dv' is not a supported duration for '$k' (days and/or hours, e.g. PT8H, P90D, P365D)." }
        if ("$k" -eq 'EndUser_Assignment' -and $null -ne $n.isExpirationRequired -and -not [bool]$n.isExpirationRequired) { throw "${fn}: an activation must always end -- EndUser_Assignment stays required to expire." }
    }
    if ($null -ne $ActivationChecks) { foreach ($c in @($ActivationChecks)) { if ($checkOk -notcontains "$c") { throw "${fn}: '$c' is not something activation may ask for here (allowed: $($checkOk -join ', '))." } } }

    $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    $raw = $existing; if ($raw -is [string]) { $raw = $raw | ConvertFrom-Json }
    $map = ConvertTo-PimPolicyTemplateMap -Value $raw
    if (-not $map.Count) { throw "${fn}: the template store is empty or unreadable -- nothing to change." }
    $key = ''; foreach ($k in @($map.Keys)) { if ("$k" -ieq "$Id".Trim()) { $key = "$k" } }
    if (-not $key) { throw "${fn}: no template with id '$Id' in the store." }
    $fpBefore = (Get-PimPolicyTemplateStoreFingerprint -Value $raw).hash
    $v = ConvertTo-PimTplTree $raw
    $tpls = $v['templates']; $t = $tpls[$key]
    if (-not $t.Contains('rules') -or $null -eq $t['rules']) { $t['rules'] = [ordered]@{} }
    $rules = $t['rules']
    $baseKey = ''; $ext = "$($t['extends'])".Trim()
    if ($ext) { foreach ($k in @($tpls.Keys)) { if ("$k" -ieq $ext) { $baseKey = "$k" } } }
    $baseRules = if ($baseKey -and $tpls[$baseKey].Contains('rules')) { $tpls[$baseKey]['rules'] } else { $null }
    # the block to edit, copied down from the base when this template only inherits it
    $own = {
        param([string]$Name)
        if ($rules.Contains($Name) -and $null -ne $rules[$Name]) { return $rules[$Name] }
        if ($null -ne $baseRules -and $baseRules.Contains($Name) -and $null -ne $baseRules[$Name]) { $rules[$Name] = ConvertTo-PimTplTree $baseRules[$Name]; return $rules[$Name] }
        return $null
    }
    $scope = $rules
    if ($Part -eq 'owner') {
        $ob = & $own 'Owner'
        if ($null -eq $ob) { throw "${fn}: template '$key' has no OWNER policy (only PIM for Groups templates do)." }
        $scope = $ob
    }
    $blk = {
        param([string]$Name)
        if ($Part -eq 'owner') { if (-not $scope.Contains($Name) -or $null -eq $scope[$Name]) { $scope[$Name] = [ordered]@{} }; return $scope[$Name] }
        $b = & $own $Name; if ($null -eq $b) { $rules[$Name] = [ordered]@{}; $b = $rules[$Name] }; return $b
    }
    $changed = New-Object System.Collections.Generic.List[string]
    if ($Expiration.Count) {
        $ex = & $blk 'Expiration'
        foreach ($k in @($Expiration.Keys)) {
            $n = $Expiration[$k]
            if (-not $ex.Contains("$k") -or $null -eq $ex["$k"]) { $ex["$k"] = [ordered]@{ maximumDuration = ''; isExpirationRequired = $true } }
            $node = $ex["$k"]
            $dv = "$($n.maximumDuration)".Trim()
            if ("$($node['maximumDuration'])" -cne $dv) { $node['maximumDuration'] = $dv; $changed.Add("$k.maximumDuration") }
            if ($null -ne $n.isExpirationRequired -and [bool]$node['isExpirationRequired'] -ne [bool]$n.isExpirationRequired) { $node['isExpirationRequired'] = [bool]$n.isExpirationRequired; $changed.Add("$k.isExpirationRequired") }
        }
    }
    if ($null -ne $ActivationChecks) {
        $en = & $blk 'Enablement'
        $cur = @(@($en['EndUser_Assignment']) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
        $new = @($checkOk | Where-Object { @($ActivationChecks) -contains $_ })
        if ((($cur | Sort-Object) -join ',') -ne (($new | Sort-Object) -join ',')) { $en['EndUser_Assignment'] = @($new); $changed.Add('Enablement.EndUser_Assignment') }
    }
    if (@($Notifications).Count) {
        $list = if ($Part -eq 'owner') { $scope['Notification'] } else { & $own 'Notification' }
        if ($null -eq $list) { throw "${fn}: template '$key' ($Part) has no notification rules to change." }
        foreach ($want in @($Notifications)) {
            $hit = @(@($list) | Where-Object { $_ -and "$($_['recipientType'])" -ieq "$($want.recipientType)" -and "$($_['caller'])" -ieq "$($want.caller)" -and "$($_['level'])" -ieq "$($want.level)" -and -not "$($_['recipientsSource'])".Trim() })
            if (-not $hit.Count) { throw "${fn}: template '$key' ($Part) has no notification rule $($want.recipientType)/$($want.caller)/$($want.level) that may be switched." }
            foreach ($h in $hit) { if ([bool]$h['defaultRecipientsEnabled'] -ne [bool]$want.defaultRecipientsEnabled) { $h['defaultRecipientsEnabled'] = [bool]$want.defaultRecipientsEnabled; $changed.Add("Notification.$($want.recipientType)_$($want.caller)_$($want.level)") } }
        }
    }
    if (-not $changed.Count) { return [ordered]@{ id = $key; part = $Part; changed = @(); fingerprintBefore = $fpBefore; fingerprintAfter = $fpBefore } }
    $t['_editedRules'] = [ordered]@{ by = $Actor; utc = $NowUtc.ToUniversalTime().ToString('o'); part = $Part; changed = @($changed.ToArray()) }
    $v['updatedUtc'] = $NowUtc.ToUniversalTime().ToString('o')
    Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates' -Value $v
    $back = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    $bm = ConvertTo-PimPolicyTemplateMap -Value $back
    if ($bm.Count -ne $map.Count) { throw "${fn}: read-back mismatch -- the store holds $($bm.Count) template(s), expected $($map.Count)." }
    $fpAfter = (Get-PimPolicyTemplateStoreFingerprint -Value $back).hash
    if ($fpAfter -eq $fpBefore) { throw "${fn}: read-back mismatch -- the store did not change although $($changed.Count) setting(s) did." }
    return [ordered]@{ id = $key; part = $Part; changed = @($changed.ToArray()); fingerprintBefore = $fpBefore; fingerprintAfter = $fpAfter }
}

function Get-PimPolicyTemplateStoreMeta {
    <# PURE: the metadata half of a stored PolicyTemplates value as plain hashtables:
       @{ source; seededUtc; fingerprint; fileNames = @{id=file}; shipped = @{id=@{fingerprint;file;recordedUtc}}; hasShippedRecord } #>
    param([AllowNull()][object]$Value)
    $meta = @{ source = ''; seededUtc = ''; fingerprint = ''; fileNames = @{}; shipped = @{}; hasShippedRecord = $false; additiveMerge = $null }
    if ($null -eq $Value) { return $meta }
    $v = $Value
    if ($v -is [string]) { if (-not "$v".Trim()) { return $meta }; try { $v = $v | ConvertFrom-Json } catch { return $meta } }
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.PSObject.Properties[$n].Value } else { $null } }
    $pairs = { param($o) if ($null -eq $o) { @() } elseif ($o -is [System.Collections.IDictionary]) { @($o.Keys | ForEach-Object { ,@("$_", $o[$_]) }) } else { @($o.PSObject.Properties | ForEach-Object { ,@("$($_.Name)", $_.Value) }) } }
    # pwsh 7's ConvertFrom-Json turns the ISO stamps into [datetime]; "$x" would then render them in the
    # host's CULTURE format, so every re-run looked changed (a write per boot) on pwsh -- never on 5.1.
    $iso = { param($x) if ($x -is [datetime]) { $x.ToUniversalTime().ToString('o') } else { "$x" } }
    $meta.source = "$(& $get $v 'source')"; $meta.seededUtc = & $iso (& $get $v 'seededUtc'); $meta.fingerprint = "$(& $get $v 'fingerprint')"
    $meta.additiveMerge = & $get $v 'additiveMerge'
    foreach ($kv in @(& $pairs (& $get $v 'fileNames'))) { if ($kv) { $meta.fileNames["$($kv[0])"] = "$($kv[1])" } }
    $sh = & $get $v 'shipped'
    if ($null -ne $sh) {
        $meta.hasShippedRecord = $true
        foreach ($kv in @(& $pairs $sh)) {
            if (-not $kv) { continue }
            $meta.shipped["$($kv[0])"] = @{ fingerprint = "$(& $get $kv[1] 'fingerprint')"; file = "$(& $get $kv[1] 'file')"; recordedUtc = (& $iso (& $get $kv[1] 'recordedUtc')) }
        }
    }
    return $meta
}

function Get-PimPolicyTemplateStoreFingerprint {
    <# BUG-55 fingerprint of the SQL copy, identical in value to Get-PimPolicyBaselineFingerprint over the
       directory the store was seeded from (same normalisation, same per-file keys via fileNames).
       -Value: the stored PolicyTemplates value; or -Templates id -> template with optional -FileNames. #>
    param([object]$Value, [hashtable]$Templates, [hashtable]$FileNames = @{})
    if (-not (Get-Command Get-PimPolicyBaselineFingerprint -ErrorAction SilentlyContinue)) {
        $lib = Join-Path $PSScriptRoot 'PIM-PolicyBaseline.ps1'
        if (Test-Path -LiteralPath $lib) { . $lib }
    }
    if ($null -ne $Value) {
        $Templates = ConvertTo-PimPolicyTemplateMap -Value $Value
        $m = Get-PimPolicyTemplateStoreMeta -Value $Value
        foreach ($k in @($m.fileNames.Keys)) { $FileNames[$k] = $m.fileNames[$k] }
    }
    if (-not $Templates) { $Templates = @{} }
    $byName = @{}
    foreach ($id in @($Templates.Keys)) { $byName[$(if ($FileNames.ContainsKey("$id")) { $FileNames["$id"] } else { "$id" })] = $Templates[$id] }
    return (Get-PimPolicyBaselineFingerprint -Templates $byName)
}

function Get-PimPolicyTemplateChangeSummary {
    <# PURE: what the SHIPPED template changes relative to the STORED one, as short JSON paths:
       '+rules.Notification_Admin_Admin_Eligibility' (added), '~rules.Expiration_Admin_Eligibility.maximumDuration'
       (changed), '-owner' (only in the stored copy). Annotations (_*, description) are ignored, as in the
       BUG-55 hash. Capped at -Max entries. #>
    param([AllowNull()][object]$Stored, [AllowNull()][object]$Shipped, [int]$Max = 25)
    if (-not (Get-Command Remove-PimTemplateAnnotation -ErrorAction SilentlyContinue)) {
        $lib = Join-Path $PSScriptRoot 'PIM-PolicyBaseline.ps1'
        if (Test-Path -LiteralPath $lib) { . $lib }
    }
    # id + name are identity / label, not content (as in Get-PimPolicyTemplateHash); 'extends' compares by current id.
    $norm = { param($o) if ($null -eq $o) { $null } else {
        $n = Remove-PimTemplateAnnotation -Node (($o | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
        if ($n -is [System.Management.Automation.PSCustomObject]) {
            foreach ($x in @('id', 'name')) { if ($n.PSObject.Properties[$x]) { $n.PSObject.Properties.Remove($x) } }
            if ($n.PSObject.Properties['extends'] -and (Get-Command Get-PimPolicyTemplateCanonicalId -ErrorAction SilentlyContinue)) { $n.extends = Get-PimPolicyTemplateCanonicalId -Id "$($n.extends)" }
        }
        $n } }
    $a = & $norm $Stored; $b = & $norm $Shipped
    $out = New-Object System.Collections.Generic.List[string]
    $walk = $null
    $walk = {
        param($x, $y, $prefix)
        if ($out.Count -ge $Max) { return }
        $isObj = { param($n) $n -is [System.Management.Automation.PSCustomObject] }
        if ((& $isObj $x) -and (& $isObj $y)) {
            $names = @(@($x.PSObject.Properties | ForEach-Object Name) + @($y.PSObject.Properties | ForEach-Object Name) | Sort-Object -Unique)
            foreach ($n in $names) {
                if ($out.Count -ge $Max) { return }
                $p = if ($prefix) { "$prefix.$n" } else { "$n" }
                $hx = [bool]$x.PSObject.Properties[$n]; $hy = [bool]$y.PSObject.Properties[$n]
                if ($hy -and -not $hx) { [void]$out.Add("+$p") }
                elseif ($hx -and -not $hy) { [void]$out.Add("-$p") }
                else { & $walk $x.PSObject.Properties[$n].Value $y.PSObject.Properties[$n].Value $p }
            }
            return
        }
        $jx = $x | ConvertTo-Json -Depth 30 -Compress; $jy = $y | ConvertTo-Json -Depth 30 -Compress
        if ($jx -ne $jy) { [void]$out.Add("~$prefix") }
    }
    & $walk $a $b ''
    return @($out.ToArray())
}

# ---- ADDITIVE MERGE (68.6 "Live / data", 2026-09-13) --------------------------------------------
# A CUSTOMISED stored template (and a template the operator created, which has no shipped twin) never
# received new shipped content -- the Owner block, v1's nine notification rules -- because the upgrade
# above only replaces UNMODIFIED templates. The additive merge closes that gap without touching anything
# the operator decided:
#   * only under 'rules'; only what is MISSING is added -- a block (Expiration / Enablement / Notification
#     / Owner), a level inside Expiration or Enablement (added whole), a notification rule (identity =
#     recipientType|caller|level), and the same inside Owner;
#   * never a value inside an existing rule, never an Enablement list merged, never a removal;
#   * 'Approval' is skipped at every depth (the engine never manages an approval it did not apply);
#   * annotations (_* keys) are not copied -- they are not part of the BUG-55 hash;
#   * once per shipped version: the store records the shipped fingerprint it merged against, so a block
#     the operator deletes AFTER the merge is not re-added on every boot.

function Copy-PimTemplateNode {
    # Deep copy of a JSON-shaped node, so a merge never aliases shipped objects into the store copy.
    param([AllowNull()][object]$Node)
    if ($null -eq $Node) { return $null }
    return (($Node | ConvertTo-Json -Depth 40 -Compress) | ConvertFrom-Json)
}

function Get-PimNotificationRuleIdentity {
    param([object]$Rule)
    if ($null -eq $Rule) { return '' }
    $g = { param($n) if ($Rule -is [System.Collections.IDictionary]) { if ($Rule.Contains($n)) { "$($Rule[$n])" } else { '' } } elseif ($Rule.PSObject.Properties[$n]) { "$($Rule.PSObject.Properties[$n].Value)" } else { '' } }
    return ("{0}|{1}|{2}" -f (& $g 'recipientType'), (& $g 'caller'), (& $g 'level')).ToLowerInvariant()
}

function Merge-PimPolicyRulesAdditive {
    <# PURE (mutates -Stored only). Adds to the -Stored rules object what -Shipped has and it lacks, by the
       rules in the header above. Returns the added paths ('+rules.Owner', '+rules.Notification[admin|admin|eligibility]').
       -OnlyBlocks limits the TOP-level blocks considered (used for operator-created templates). #>
    param([Parameter(Mandatory)][object]$Stored, [Parameter(Mandatory)][object]$Shipped, [string]$Prefix = 'rules', [string[]]$OnlyBlocks = @())
    $added = New-Object System.Collections.Generic.List[string]
    if (-not ($Stored -is [System.Management.Automation.PSCustomObject]) -or -not ($Shipped -is [System.Management.Automation.PSCustomObject])) { return @() }
    foreach ($p in @($Shipped.PSObject.Properties)) {
        $n = "$($p.Name)"
        if ($n -like '_*' -or $n -ieq 'Approval') { continue }
        if (@($OnlyBlocks).Count -and (@($OnlyBlocks) -notcontains $n)) { continue }
        $path = "$Prefix.$n"
        $sp = $Stored.PSObject.Properties[$n]
        if (-not $sp) {
            $val = Copy-PimTemplateNode $p.Value
            # A missing Owner block arrives without any Approval it might carry.
            if ($val -is [System.Management.Automation.PSCustomObject] -and $val.PSObject.Properties['Approval']) { $val.PSObject.Properties.Remove('Approval') }
            $Stored | Add-Member -NotePropertyName $n -NotePropertyValue $val
            [void]$added.Add("+$path")
            continue
        }
        if ($n -ieq 'Owner') {
            foreach ($x in @(Merge-PimPolicyRulesAdditive -Stored $sp.Value -Shipped $p.Value -Prefix $path)) { [void]$added.Add($x) }
            continue
        }
        if ($n -ieq 'Notification') {
            $have = @{}
            $cur = @($sp.Value | Where-Object { $null -ne $_ })
            foreach ($r in $cur) { $have[(Get-PimNotificationRuleIdentity $r)] = $true }
            $new = New-Object System.Collections.Generic.List[object]
            foreach ($r in $cur) { [void]$new.Add($r) }
            foreach ($r in @($p.Value | Where-Object { $null -ne $_ })) {
                $id = Get-PimNotificationRuleIdentity $r
                if (-not $id.Trim('|') -or $have.ContainsKey($id)) { continue }
                [void]$new.Add((Copy-PimTemplateNode $r)); $have[$id] = $true
                [void]$added.Add("+$path[$id]")
            }
            if ($new.Count -ne $cur.Count) { $sp.Value = $new.ToArray() }
            continue
        }
        if (($n -ieq 'Expiration' -or $n -ieq 'Enablement') -and ($sp.Value -is [System.Management.Automation.PSCustomObject]) -and ($p.Value -is [System.Management.Automation.PSCustomObject])) {
            foreach ($lv in @($p.Value.PSObject.Properties)) {
                if ("$($lv.Name)" -like '_*' -or "$($lv.Name)" -ieq 'Approval') { continue }
                if ($sp.Value.PSObject.Properties[$lv.Name]) { continue }     # an existing level is the operator's -- never merged into
                $sp.Value | Add-Member -NotePropertyName $lv.Name -NotePropertyValue (Copy-PimTemplateNode $lv.Value)
                [void]$added.Add("+$path.$($lv.Name)")
            }
        }
        # Anything else that exists (a scalar, an Enablement list, an unknown block) is left exactly as stored.
    }
    return @($added.ToArray())
}

function Get-PimTemplateProp {
    param([object]$Node, [string]$Name)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) { if ($Node.Contains($Name)) { return $Node[$Name] } else { return $null } }
    if ($Node.PSObject.Properties[$Name]) { return $Node.PSObject.Properties[$Name].Value }
    return $null
}

function Resolve-PimPolicyTemplateMergeBase {
    <# PURE: for an operator-created template (no shipped twin), the shipped template its missing blocks come
       from. 'extends' -> none (it inherits them). Same appliesTo as a shipped root template -> that one.
       Otherwise the shipped Groups_Standard (formerly 'default'). Returns @{ baseId; reason } (baseId '' = nothing to merge). #>
    param([Parameter(Mandatory)][object]$Template, [Parameter(Mandatory)][System.Collections.IDictionary]$Shipped)
    $ext = "$(Get-PimTemplateProp $Template 'extends')".Trim()
    if ($ext) { return @{ baseId = ''; reason = "extends '$ext' -- inherits its blocks" } }
    $ap = "$(Get-PimTemplateProp $Template 'appliesTo')".Trim()
    if ($ap) {
        foreach ($id in @($Shipped.Keys | Sort-Object)) {
            $s = $Shipped[$id]
            if ("$(Get-PimTemplateProp $s 'appliesTo')".Trim() -ieq $ap -and -not "$(Get-PimTemplateProp $s 'extends')".Trim()) { return @{ baseId = "$id"; reason = "same appliesTo '$ap'" } }
        }
    }
    $gs = Resolve-PimPolicyTemplateKey -Map $Shipped -Id 'Groups_Standard'
    if ($gs) { return @{ baseId = $gs; reason = 'shipped group standard' } }
    return @{ baseId = ''; reason = 'no shipped base available' }
}

function Update-PimPolicyTemplateStore {
    <#
      Seed / upgrade pim.Settings['PolicyTemplates'] from the shipped templates (see the header).
      Returns @{ seeded; changed; count; fingerprint; added=@(ids); upgraded=@(ids); customised=@(findings);
                 current=@(ids); storeOnly=@(ids); reason }.
      -Actor names who is recorded on the audit events ('system:<host>' by default).
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$TemplateDir,
        [string]$Actor = 'system:policy-template-store',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not (Get-Command Get-PimPolicyTemplateHash -ErrorAction SilentlyContinue)) {
        $lib = Join-Path $PSScriptRoot 'PIM-PolicyBaseline.ps1'
        if (Test-Path -LiteralPath $lib) { . $lib }
    }
    $names = @{}
    $shipped = Read-PimShippedPolicyTemplates -TemplateDir $TemplateDir -FileNames $names
    $existing = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates'
    $cur = ConvertTo-PimPolicyTemplateMap -Value $existing
    $nowS = $NowUtc.ToUniversalTime().ToString('o')
    $result = @{ seeded = $false; changed = $false; count = $cur.Count; fingerprint = ''; added = @(); upgraded = @(); customised = @(); current = @(); storeOnly = @(); reason = '' }
    if ($shipped.Count -eq 0) {
        $result.fingerprint = $(if ($cur.Count) { (Get-PimPolicyTemplateStoreFingerprint -Value $existing).hash } else { '' })
        $result.reason = "no shipped policy templates found under $TemplateDir -- store left as it is"
        return $result
    }

    $meta = Get-PimPolicyTemplateStoreMeta -Value $existing
    $fresh = ($cur.Count -eq 0)
    $recorded = @{}
    foreach ($k in @($meta.shipped.Keys)) { $recorded[$k] = "$($meta.shipped[$k].fingerprint)" }
    $legacyNote = ''
    if (-not $fresh -and -not $meta.hasShippedRecord) {
        $nowFp = (Get-PimPolicyTemplateStoreFingerprint -Value $existing).hash
        if ($meta.fingerprint -and $meta.fingerprint -eq $nowFp) {
            foreach ($id in @($cur.Keys)) { $recorded[$id] = Get-PimPolicyTemplateHash -Template $cur[$id] }
            $legacyNote = 'legacy store unmodified since its seed -- shipped record reconstructed'
        } else {
            $legacyNote = 'legacy store without a shipped record and not provably unmodified -- every differing template is treated as customised'
        }
    }

    # Additive merge runs once per shipped version (see the ADDITIVE MERGE block above).
    $shipTplHt = @{}; foreach ($k in @($shipped.Keys)) { $shipTplHt["$k"] = $shipped[$k] }
    $namesCopy = @{}; foreach ($k in @($names.Keys)) { $namesCopy["$k"] = $names[$k] }
    $shipFp = (Get-PimPolicyTemplateStoreFingerprint -Templates $shipTplHt -FileNames $namesCopy).hash
    $mergedFp = "$(Get-PimTemplateProp $meta.additiveMerge 'shippedFingerprint')"
    $doMerge = (-not $fresh) -and ($mergedFp -ne $shipFp)
    $merged = New-Object System.Collections.Generic.List[object]
    $mergeOne = {
        param([string]$Id, [object]$Base, [string]$BaseId, [string[]]$Only, [string]$Kind)
        $copy = Copy-PimTemplateNode $newTpl[$Id]
        $baseRules = Get-PimTemplateProp $Base 'rules'
        if ($null -eq $copy -or $null -eq $baseRules) { return }
        if (-not $copy.PSObject.Properties['rules'] -or $null -eq $copy.rules) { $copy | Add-Member -NotePropertyName rules -NotePropertyValue ([pscustomobject]@{}) -Force }
        $paths = @(Merge-PimPolicyRulesAdditive -Stored $copy.rules -Shipped $baseRules -OnlyBlocks $Only)
        if (-not $paths.Count) { return }
        $before = Get-PimPolicyTemplateHash -Template $newTpl[$Id]
        $newTpl[$Id] = $copy
        $after = Get-PimPolicyTemplateHash -Template $copy
        [void]$merged.Add([ordered]@{ id = $Id; kind = $Kind; base = $BaseId; added = @($paths) })
        Write-Host ("  [policy] template '{0}' ({1}): added what the shipped '{2}' has and it lacked -- {3}" -f $Id, $Kind, $BaseId, (($paths | Select-Object -First 8) -join ', '))
        if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
            try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'system' -Action 'policy.template.merged' -Target "policytemplate:$Id" -Before ([ordered]@{ fingerprint = $before }) -After ([ordered]@{ fingerprint = $after; kind = $Kind; base = $BaseId; added = @($paths) }) -Result 'ok' }
            catch { Write-Warning "  [policy] template '$Id' merged, but the audit event could not be written: $($_.Exception.Message)" }
        }
    }

    $newTpl = @{}; foreach ($id in @($cur.Keys)) { $newTpl[$id] = $cur[$id] }
    $newShipped = [ordered]@{}
    $fileNames = @{}; foreach ($k in @($meta.fileNames.Keys)) { $fileNames[$k] = $meta.fileNames[$k] }
    $added = New-Object System.Collections.Generic.List[string]
    $upgraded = New-Object System.Collections.Generic.List[string]
    $currentIds = New-Object System.Collections.Generic.List[string]
    $customised = New-Object System.Collections.Generic.List[object]

    # 2026-09-19 -- FORMER IDS (operator: "and why not 2 for PIM4Groups"). A store seeded before the PIM-for-Groups
    # pair was renamed holds 'default' / 'approval-required'. Each is renamed to its current id ONCE, BEFORE the
    # compare below, so the shipped Groups_* template is recognised as the SAME template -- never seeded next to it as
    # a duplicate -- and a customised one keeps every rule the operator set (only its key and 'id' move; the BUG-55
    # hash ignores both, so an unmodified one is simply "current"). Rows naming the former id keep resolving (alias).
    $renamedIds = New-Object System.Collections.Generic.List[string]
    $renamedFrom = @{}
    $aliasTbl = Get-PimPolicyTemplateAliases
    foreach ($old in @($aliasTbl.Keys)) {
        $newId = "$($aliasTbl[$old])"
        if (-not $shipped.Contains($newId)) { continue }
        $oldKey = ''; $hasNew = $false
        foreach ($k in @($newTpl.Keys)) { if ("$k" -ieq $old) { $oldKey = "$k" }; if ("$k" -ieq $newId) { $hasNew = $true } }
        if (-not $oldKey) { continue }
        if ($hasNew) { Write-Warning "  [policy] the store holds BOTH '$oldKey' and '$newId' -- '$oldKey' is left as its own template (a lookup of '$oldKey' finds it; '$newId' is the current id)."; continue }
        $copy = Copy-PimTemplateNode $newTpl[$oldKey]
        if ($copy -is [System.Management.Automation.PSCustomObject]) { $copy | Add-Member -NotePropertyName id -NotePropertyValue $newId -Force }
        [void]$newTpl.Remove($oldKey); $newTpl[$newId] = $copy
        if ($recorded.ContainsKey($oldKey)) { $recorded[$newId] = $recorded[$oldKey]; [void]$recorded.Remove($oldKey) }
        if ($meta.shipped.ContainsKey($oldKey)) { $meta.shipped[$newId] = $meta.shipped[$oldKey]; [void]$meta.shipped.Remove($oldKey) }
        if ($fileNames.ContainsKey($oldKey)) { [void]$fileNames.Remove($oldKey) }
        [void]$renamedIds.Add("$oldKey -> $newId"); $renamedFrom[$newId] = $oldKey
        Write-Host ("  [policy] template '{0}' renamed to its current id '{1}' (content kept; rows naming '{0}' keep resolving to it)" -f $oldKey, $newId)
        if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
            try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'system' -Action 'policy.template.renamed' -Target "policytemplate:$newId" -Before ([ordered]@{ id = $oldKey }) -After ([ordered]@{ id = $newId; contentKept = $true; alias = $oldKey }) -Result 'ok' }
            catch { Write-Warning "  [policy] template '$oldKey' renamed to '$newId', but the audit event could not be written: $($_.Exception.Message)" }
        }
    }
    # An operator's rename (Set-PimPolicyTemplateName, recorded in '_renamed') survives a shipped upgrade: the new
    # shipped content is taken, with the operator's NAME on it.
    $keepName = {
        param($Stored, $Incoming)
        $rn = Get-PimTemplateProp $Stored '_renamed'
        if ($null -eq $rn) { return $Incoming }
        $c = Copy-PimTemplateNode $Incoming
        $c | Add-Member -NotePropertyName name -NotePropertyValue "$(Get-PimTemplateProp $Stored 'name')" -Force
        $c | Add-Member -NotePropertyName _renamed -NotePropertyValue (Copy-PimTemplateNode $rn) -Force
        return $c
    }

    foreach ($id in @($shipped.Keys | Sort-Object)) {
        $shipHash = Get-PimPolicyTemplateHash -Template $shipped[$id]
        $fileNames[$id] = $names[$id]
        if (-not $newTpl.ContainsKey($id)) {
            $newTpl[$id] = $shipped[$id]
            $newShipped[$id] = [ordered]@{ fingerprint = $shipHash; file = "$($names[$id])"; recordedUtc = $nowS }
            [void]$added.Add($id)
            continue
        }
        $storedHash = Get-PimPolicyTemplateHash -Template $newTpl[$id]
        $rec = if ($recorded.ContainsKey($id)) { "$($recorded[$id])" } else { '' }
        if ($storedHash -eq $shipHash) {
            $keepUtc = if ($meta.shipped.ContainsKey($id) -and $rec -eq $shipHash -and "$($meta.shipped[$id].recordedUtc)") { "$($meta.shipped[$id].recordedUtc)" } else { $nowS }
            $newShipped[$id] = [ordered]@{ fingerprint = $shipHash; file = "$($names[$id])"; recordedUtc = $keepUtc }
            # Renamed from a former id: same desired state, so its obsolete metadata (old name / description) is
            # replaced by the shipped one -- an operator's own rename excepted.
            if ($renamedFrom.ContainsKey($id)) { $newTpl[$id] = & $keepName $newTpl[$id] $shipped[$id] }
            [void]$currentIds.Add($id)
        } elseif ($rec -and $storedHash -eq $rec) {
            # UNMODIFIED since the shipped version it came from -> take the new shipped content.
            $changes = @(Get-PimPolicyTemplateChangeSummary -Stored $newTpl[$id] -Shipped $shipped[$id])
            $newTpl[$id] = & $keepName $newTpl[$id] $shipped[$id]
            $newShipped[$id] = [ordered]@{ fingerprint = $shipHash; file = "$($names[$id])"; recordedUtc = $nowS }
            [void]$upgraded.Add($id)
            Write-Host ("  [policy] template '{0}' upgraded to the shipped version ({1} -> {2}): {3}" -f $id, $storedHash.Substring(0,12), $shipHash.Substring(0,12), (($changes | Select-Object -First 8) -join ', '))
            if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
                try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'system' -Action 'policy.template.upgraded' -Target "policytemplate:$id" -Before ([ordered]@{ fingerprint = $storedHash }) -After ([ordered]@{ fingerprint = $shipHash; changes = @($changes) }) -Result 'ok' }
                catch { Write-Warning "  [policy] template '$id' upgraded, but the audit event could not be written: $($_.Exception.Message)" }
            }
        } else {
            # CUSTOMISED (or no provable origin): keep it, keep the record it had, flag the upgrade.
            if ($rec) { $newShipped[$id] = [ordered]@{ fingerprint = $rec; file = "$($names[$id])"; recordedUtc = $(if ($meta.shipped.ContainsKey($id)) { "$($meta.shipped[$id].recordedUtc)" } else { $nowS }) } }
            # ...but still ADD what the shipped version has and this copy lacks (never overwrite, never remove).
            if ($doMerge) { & $mergeOne $id $shipped[$id] $id @() 'customised'; $storedHash = Get-PimPolicyTemplateHash -Template $newTpl[$id] }
            $changes = @(Get-PimPolicyTemplateChangeSummary -Stored $newTpl[$id] -Shipped $shipped[$id])
            [void]$customised.Add([ordered]@{ id = $id; storedFingerprint = $storedHash; shippedFingerprint = $shipHash; recordedShippedFingerprint = $rec; changes = @($changes) })
        }
    }
    $storeOnly = @($newTpl.Keys | Where-Object { -not $shipped.Contains($_) } | Sort-Object)
    foreach ($id in $storeOnly) { if ($meta.shipped.ContainsKey($id)) { $newShipped[$id] = [ordered]@{ fingerprint = "$($meta.shipped[$id].fingerprint)"; file = "$($meta.shipped[$id].file)"; recordedUtc = "$($meta.shipped[$id].recordedUtc)" } } }
    # Operator-created templates: only the NEW shipped content (Owner, Notification) comes from a base --
    # a block such a template leaves out on purpose (e.g. no Expiration) stays out.
    $inherits = New-Object System.Collections.Generic.List[string]
    if ($doMerge) {
        foreach ($id in $storeOnly) {
            $b = Resolve-PimPolicyTemplateMergeBase -Template $newTpl[$id] -Shipped $shipped
            if (-not $b.baseId) { [void]$inherits.Add("$id ($($b.reason))"); continue }
            & $mergeOne $id $shipped[$b.baseId] $b.baseId @('Owner', 'Notification') 'operator-created'
        }
    }
    foreach ($c in $customised) {
        Write-Warning ("  [policy] TEMPLATE-UPGRADE-AVAILABLE: template '{0}' was customised in the store, so the new shipped version was NOT applied. It changes: {1}" -f $c.id, $(if (@($c.changes).Count) { (@($c.changes) | Select-Object -First 8) -join ', ' } else { '(annotations only)' }))
    }

    # 2026-09-19 ("give policies an id so we can rename them"): every stored template carries an 'id' equal to its
    # key -- the immutable reference rows use. One that lacks it (an operator-created template) is given it; one
    # that carries a DIFFERENT id is left as the operator wrote it (the key is what every reader resolves by).
    $idsAssigned = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($newTpl.Keys)) {
        $t = $newTpl[$id]
        if ($t -isnot [System.Management.Automation.PSCustomObject]) { continue }
        if ("$(Get-PimTemplateProp $t 'id')".Trim()) { continue }
        $c = Copy-PimTemplateNode $t
        $c | Add-Member -NotePropertyName id -NotePropertyValue "$id" -Force
        $newTpl[$id] = $c
        [void]$idsAssigned.Add("$id")
    }

    $fp = (Get-PimPolicyTemplateStoreFingerprint -Templates $newTpl -FileNames $fileNames).hash
    $tplOrdered = [ordered]@{}; foreach ($id in @($newTpl.Keys | Sort-Object)) { $tplOrdered[$id] = $newTpl[$id] }
    $fnOrdered = [ordered]@{}; foreach ($id in @($fileNames.Keys | Sort-Object)) { $fnOrdered[$id] = $fileNames[$id] }
    $value = [ordered]@{
        source           = $(if ($fresh) { 'shipped-seed' } elseif ("$($meta.source)") { "$($meta.source)" } else { 'shipped-seed' })
        seededUtc        = $(if ($fresh -or -not "$($meta.seededUtc)") { $nowS } else { "$($meta.seededUtc)" })
        updatedUtc       = $nowS
        fingerprint      = $fp
        fileNames        = $fnOrdered
        shipped          = $newShipped
        upgradeAvailable = @($customised.ToArray())
        additiveMerge    = $(if ($fresh -or $doMerge) { [ordered]@{ shippedFingerprint = $shipFp; appliedUtc = $nowS; merged = @($merged.ToArray()) } } else { $meta.additiveMerge })
        templates        = $tplOrdered
    }
    # Idempotent: compare everything except the timestamps with what is stored.
    $sig = { param($o) if ($null -eq $o) { '' } else { $c = ($o | ConvertTo-Json -Depth 40 -Compress) | ConvertFrom-Json; foreach ($n in 'updatedUtc') { if ($c.PSObject.Properties[$n]) { $c.PSObject.Properties.Remove($n) } }; $c | ConvertTo-Json -Depth 40 -Compress } }
    $oldObj = $existing; if ($oldObj -is [string]) { try { $oldObj = $oldObj | ConvertFrom-Json } catch { $oldObj = $null } }
    $changed = $fresh -or ((& $sig $oldObj) -ne (& $sig $value))
    if ($changed) {
        Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates' -Value $value
        # Read back: a write that did not land must not report success.
        $back = ConvertTo-PimPolicyTemplateMap -Value (Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'PolicyTemplates')
        if ($back.Count -ne $newTpl.Count) { throw "Update-PimPolicyTemplateStore: read-back mismatch (wrote $($newTpl.Count) template(s), store holds $($back.Count))" }
        if ($fresh -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'system' -Action 'policy.template.seeded' -Target 'settings:PolicyTemplates' -After ([ordered]@{ count = $newTpl.Count; fingerprint = $fp }) -Result 'ok' } catch {}
        } elseif ($added.Count -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $Actor -ActorSource 'system' -Action 'policy.template.added' -Target 'settings:PolicyTemplates' -After ([ordered]@{ added = @($added.ToArray()) }) -Result 'ok' } catch {}
        }
    }
    $parts = @()
    if ($fresh) { $parts += 'seeded from the shipped templates' }
    else {
        if ($renamedIds.Count) { $parts += ("renamed to the current id (content kept, the former id still resolves): {0}" -f ($renamedIds -join ', ')) }
        if ($idsAssigned.Count) { $parts += ("id assigned (= its key): {0}" -f ($idsAssigned -join ', ')) }
        if ($added.Count)      { $parts += ("new shipped template(s) seeded: {0}" -f ($added -join ', ')) }
        if ($upgraded.Count)   { $parts += ("upgraded to the shipped version: {0}" -f ($upgraded -join ', ')) }
        if ($merged.Count)     { $parts += ("missing shipped blocks/rules ADDED (nothing overwritten): {0}" -f (@($merged | ForEach-Object { "$($_.id) +$(@($_.added).Count)" }) -join ', ')) }
        if ($inherits.Count)   { $parts += ("not merged (inherits): {0}" -f ($inherits -join ', ')) }
        if ($customised.Count) { $parts += ("TEMPLATE-UPGRADE-AVAILABLE for customised: {0} (kept)" -f (@($customised | ForEach-Object { $_.id }) -join ', ')) }
        if (-not $parts.Count) { $parts += 'up to date with the shipped templates' }
        if ($legacyNote) { $parts += $legacyNote }
    }
    $result.seeded = $fresh; $result.changed = [bool]$changed; $result.count = $newTpl.Count; $result.fingerprint = $fp
    $result.added = @($(if ($fresh) { @() } else { $added.ToArray() })); $result.upgraded = @($upgraded.ToArray()); $result.customised = @($customised.ToArray())
    $result.current = @($currentIds.ToArray()); $result.storeOnly = @($storeOnly); $result.reason = ($parts -join '; ')
    $result.merged = @($merged.ToArray()); $result.mergeRan = [bool]$doMerge; $result.shippedFingerprint = $shipFp
    $result.renamed = @($renamedIds.ToArray()); $result.idsAssigned = @($idsAssigned.ToArray())
    return $result
}

function Initialize-PimPolicyTemplateStore {
    <# Kept name for every existing caller (db-init, Manager boot, Migrate-PimToSql, the scenario harness):
       seeds a fresh store and applies shipped upgrades with BUG-55 semantics (Update-PimPolicyTemplateStore). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$TemplateDir, [string]$Actor = 'system:policy-template-store')
    return (Update-PimPolicyTemplateStore -ConnectionString $ConnectionString -TemplateDir $TemplateDir -Actor $Actor)
}
