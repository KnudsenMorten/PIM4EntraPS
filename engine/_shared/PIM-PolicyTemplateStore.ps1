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
    $norm = { param($o) if ($null -eq $o) { $null } else { Remove-PimTemplateAnnotation -Node (($o | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json) } }
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
       Otherwise the shipped 'default'. Returns @{ baseId; reason } (baseId '' = nothing to merge). #>
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
    if ($Shipped.Contains('default')) { return @{ baseId = 'default'; reason = 'shipped default' } }
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
            [void]$currentIds.Add($id)
        } elseif ($rec -and $storedHash -eq $rec) {
            # UNMODIFIED since the shipped version it came from -> take the new shipped content.
            $changes = @(Get-PimPolicyTemplateChangeSummary -Stored $newTpl[$id] -Shipped $shipped[$id])
            $newTpl[$id] = $shipped[$id]
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
    return $result
}

function Initialize-PimPolicyTemplateStore {
    <# Kept name for every existing caller (db-init, Manager boot, Migrate-PimToSql, the scenario harness):
       seeds a fresh store and applies shipped upgrades with BUG-55 semantics (Update-PimPolicyTemplateStore). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$TemplateDir, [string]$Actor = 'system:policy-template-store')
    return (Update-PimPolicyTemplateStore -ConnectionString $ConnectionString -TemplateDir $TemplateDir -Actor $Actor)
}
