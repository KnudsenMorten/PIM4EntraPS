<#
  PIM4EntraPS -- copy settings from one PIM environment to another (export on the master, import on a slave).

  Operator 2026-09-21: "how can i export settings and import them into slave from master fx naming".
  Each environment keeps its OWN settings (a slave's ring and settings are local -- DESIGN), so this is a deliberate,
  operator-driven copy: Settings > Copy settings > Export writes ONE JSON file with the sections picked; on the other
  environment Settings > Copy settings > Import shows every setting as current -> new and writes only the ticked ones.

  What is NEVER copied (tenant-specific or security-relevant): who may use the Manager (ManagerAccess), approvers,
  break-glass accounts, the licence / edition, the deployment scenario and rings, the MSP link, secrets. Inside Naming,
  the admin account DOMAIN (AdminAccountUpnSuffix) is this tenant's verified domain, so an import keeps the target's.

  PURE except for the -Reader scriptblock ({ param($Name) <stored value or $null> }). PS 5.1-safe.
#>
Set-StrictMode -Off

$script:PimSettingsTransferFormat = 'pim4entraps-settings'
$script:PimSettingsTransferSections = [ordered]@{
    naming          = @{ label = 'Naming conventions, admin prefixes and environment suffixes'; names = @('NamingConventions') }
    filters         = @{ label = 'Filters';                                                       names = @('Filters') }
    alerting        = @{ label = 'Alerting (recipients and events)';                              names = @('Alerting') }
    email           = @{ label = 'Email controls';                                                names = @('EmailControls') }
    features        = @{ label = 'Features (feature customization and Manager tabs)';             names = @('FeatureGates', 'FeatureFlags') }
    policyTemplates = @{ label = 'Policy templates and their defaults';                           names = @('PolicyTemplates', 'PolicyTemplateDefaults') }
    mailTemplates   = @{ label = 'Mail templates';                                                names = @('MailTemplates') }
    jobSchedule     = @{ label = 'Job schedule';                                                  names = @('JobSchedule') }
    operational     = @{ label = 'Operational policy, governance preview, discovery auto-create'; names = @('OperationalPolicy', 'GovernancePreview', 'DiscoveryAutoCreate') }
    templatePacks   = @{ label = 'Permission template packs (active / disabled)';                 names = @('TemplateState') }
}
# Keys inside a copied setting that belong to the TARGET tenant and are kept on import.
$script:PimSettingsTransferLocalKeys = @{ NamingConventions = @('AdminAccountUpnSuffix', 'DirectGroupDimension') }

function Get-PimSettingsTransferCatalog {
    @($script:PimSettingsTransferSections.Keys | ForEach-Object {
        [pscustomobject]@{ id = "$_"; label = "$($script:PimSettingsTransferSections[$_].label)"; settings = @($script:PimSettingsTransferSections[$_].names) }
    })
}

function ConvertTo-PimSettingsTransferValue {
    # PURE. A stored value as a plain object (JSON round-trip), so export / compare / import see one shape.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $s = "$Value".Trim()
        if ($s -match '^[\[{"]') { try { return ($s | ConvertFrom-Json) } catch { return $Value } }
        return $Value
    }
    try { return (($Value | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json) } catch { return $Value }
}

function Remove-PimSettingsTransferLocalKeys {
    # PURE. Drops the target-tenant keys (see $PimSettingsTransferLocalKeys) from a setting value.
    param([string]$Name, [AllowNull()][object]$Value)
    $drop = @($script:PimSettingsTransferLocalKeys[$Name] | Where-Object { $_ })
    if (-not $drop.Count -or $null -eq $Value -or $Value -is [string]) { return $Value }
    $o = [ordered]@{}
    foreach ($p in $Value.PSObject.Properties) { if ($p.Name -notin $drop) { $o[$p.Name] = $p.Value } }
    return [pscustomobject]$o
}

function New-PimSettingsExport {
    # The export document for the given sections (all when none). Unknown section ids are reported, never guessed.
    param([string[]]$Sections, [Parameter(Mandatory)][scriptblock]$Reader, [string]$ProductVersion = '', [string]$Source = '')
    $want = @($Sections | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $want.Count) { $want = @($script:PimSettingsTransferSections.Keys) }
    $unknown = @($want | Where-Object { -not $script:PimSettingsTransferSections.Contains($_) })
    $out = [ordered]@{}
    foreach ($sec in @($want | Where-Object { $script:PimSettingsTransferSections.Contains($_) })) {
        $vals = [ordered]@{}
        foreach ($n in $script:PimSettingsTransferSections[$sec].names) {
            $v = ConvertTo-PimSettingsTransferValue -Value (& $Reader $n)
            if ($null -ne $v) { $vals[$n] = Remove-PimSettingsTransferLocalKeys -Name $n -Value $v }
        }
        $out[$sec] = $vals
    }
    [pscustomobject]@{
        format = $script:PimSettingsTransferFormat; formatVersion = 1; productVersion = "$ProductVersion"; source = "$Source"
        exportedUtc = [datetime]::UtcNow.ToString('o'); sections = [pscustomobject]$out; unknownSections = $unknown
    }
}

function Get-PimSettingsTransferDiff {
    # PURE. Top-level keys whose value differs between current and incoming (sorted); '*' when either is not an object.
    param([AllowNull()][object]$Current, [AllowNull()][object]$Incoming)
    $j = { param($x) if ($null -eq $x) { '' } else { ($x | ConvertTo-Json -Depth 30 -Compress) } }
    if ((& $j $Current) -eq (& $j $Incoming)) { return @() }
    $isObj = { param($x) $null -ne $x -and -not ($x -is [string]) -and -not ($x -is [ValueType]) -and -not ($x -is [array]) }
    if (-not (& $isObj $Current) -or -not (& $isObj $Incoming)) { return @('*') }
    $keys = @(@($Current.PSObject.Properties | ForEach-Object { $_.Name }) + @($Incoming.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object -Unique)
    @($keys | Where-Object {
        $c = $Current.PSObject.Properties[$_]; $i = $Incoming.PSObject.Properties[$_]
        (& $j $(if ($c) { $c.Value } else { $null })) -ne (& $j $(if ($i) { $i.Value } else { $null }))
    })
}

function Get-PimSettingsImportPlan {
    <#
      What an import would write. Returns @{ ok; error; source; exportedUtc; items = @({ section; label; name; state; changedKeys;
      current; incoming; value }) } where state = 'new' | 'changed' | 'same', and value = what WOULD be stored (the incoming
      value with the target's local keys put back). A document that is not an export is refused (ok=$false).
    #>
    param([AllowNull()][object]$Document, [string[]]$Sections, [Parameter(Mandatory)][scriptblock]$Reader)
    $doc = $Document
    if ($doc -is [string]) { try { $doc = $doc | ConvertFrom-Json } catch { return [pscustomobject]@{ ok = $false; error = 'the file is not valid JSON'; items = @() } } }
    if ($null -eq $doc -or "$($doc.format)" -ne $script:PimSettingsTransferFormat -or -not $doc.PSObject.Properties['sections']) {
        return [pscustomobject]@{ ok = $false; error = 'this is not a PIM settings export (Settings > Copy settings > Export)'; items = @() }
    }
    $want = @($Sections | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($sp in $doc.sections.PSObject.Properties) {
        $sec = "$($sp.Name)"
        if (-not $script:PimSettingsTransferSections.Contains($sec)) { continue }     # an unknown / never-copied section is ignored
        if ($want.Count -and $sec -notin $want) { continue }
        $allowed = @($script:PimSettingsTransferSections[$sec].names)
        foreach ($np in $sp.Value.PSObject.Properties) {
            $name = "$($np.Name)"
            if ($name -notin $allowed) { continue }                                    # only the names this section owns
            $cur = ConvertTo-PimSettingsTransferValue -Value (& $Reader $name)
            $inc = Remove-PimSettingsTransferLocalKeys -Name $name -Value (ConvertTo-PimSettingsTransferValue -Value $np.Value)
            # put the TARGET's own local keys back, so the import never changes them
            $val = $inc
            $keep = @($script:PimSettingsTransferLocalKeys[$name] | Where-Object { $_ })
            if ($keep.Count -and $null -ne $cur -and $null -ne $inc -and -not ($inc -is [string])) {
                $o = [ordered]@{}; foreach ($p in $inc.PSObject.Properties) { $o[$p.Name] = $p.Value }
                foreach ($k in $keep) { $cp = $cur.PSObject.Properties[$k]; if ($cp -and $null -ne $cp.Value -and "$($cp.Value)" -ne '') { $o[$k] = $cp.Value } }
                $val = [pscustomobject]$o
            }
            $diff = @(Get-PimSettingsTransferDiff -Current $cur -Incoming $val)
            $state = if ($null -eq $cur) { 'new' } elseif ($diff.Count) { 'changed' } else { 'same' }
            $items.Add([pscustomobject]@{ section = $sec; label = "$($script:PimSettingsTransferSections[$sec].label)"; name = $name; state = $state
                                          changedKeys = $diff; current = $cur; incoming = $inc; value = $val })
        }
    }
    [pscustomobject]@{ ok = $true; error = ''; source = "$($doc.source)"; productVersion = "$($doc.productVersion)"; exportedUtc = "$($doc.exportedUtc)"; items = $items.ToArray() }
}
