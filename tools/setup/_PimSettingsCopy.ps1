#Requires -Version 5.1
<#
  The PURE merge rule of Copy-PimSettings.ps1 -MergeKeys (2026-10-03), offline-tested in tests/Test-PimCopySettings.ps1.

  Found building the ring-1 estate: copying NamingConventions from an environment set up on an older release REPLACED the
  new environment's document and silently dropped the keys the newer release added (GroupTypePrefixes, ServiceNames,
  PermissionGroupAdminUnits, ...). -MergeKeys keeps them: for an OBJECT document the source's top-level keys win and keys
  only the target has stay. Anything that is not an object on both sides (an array, a string, a number) is replaced
  exactly as without -MergeKeys -- a half-merged list is a shape no reader expects.
#>

function Merge-PimSettingKeys {
    param([AllowNull()][object]$Target, [AllowNull()][object]$Source)
    $isObj = { param($o) $null -ne $o -and $o -is [System.Management.Automation.PSCustomObject] }
    if (-not (& $isObj $Source) -or -not (& $isObj $Target)) { return $Source }
    $m = [ordered]@{}
    foreach ($p in $Target.PSObject.Properties) { $m[$p.Name] = $p.Value }
    foreach ($p in $Source.PSObject.Properties) { $m[$p.Name] = $p.Value }
    return [pscustomobject]$m
}

function Get-PimSettingKeyDiff {
    <# PURE. What -MergeKeys keeps from the target: the top-level keys the source lacks. #>
    param([AllowNull()][object]$Target, [AllowNull()][object]$Source)
    if ($null -eq $Target -or $Target -isnot [System.Management.Automation.PSCustomObject] -or $null -eq $Source -or $Source -isnot [System.Management.Automation.PSCustomObject]) { return @() }
    $src = @($Source.PSObject.Properties.Name)
    return @($Target.PSObject.Properties.Name | Where-Object { $src -notcontains $_ })
}
