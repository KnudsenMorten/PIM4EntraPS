# =====================================================================================================================
#  PIM Activator for Microsoft Edge and Google Chrome -- settings + "repair on request"   Intune Remediation: DETECTION
# =====================================================================================================================
#
#  WHAT IT DOES
#    Checks this device -- it only READS, nothing is changed:
#      1. the PIM Activator settings are exactly as in the SETTINGS block below, for every browser in $Browsers
#            Edge:    HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extension id>\policy
#            Chrome:  HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extension id>\policy
#            (tenantCatalog for the extension of $Channel; autoActivateMaxGroups + bulkActivateConfirmThreshold + activationEndTime with the
#             SAME values for BOTH PIM Activator extensions -- production and test behave the same)
#      2. nobody has asked for a repair -- the RepairStuck flag is not set, neither by a user
#            HKCU\Software\PIM4EntraPS\PimActivator  RepairStuck = 1   (any signed-in user)
#         nor by an admin for the whole device
#            HKLM\SOFTWARE\PIM4EntraPS\PimActivator  RepairStuck = 1
#
#  RESULT CODES (Intune acts on these)
#    exit 0 = OK -- nothing to do
#    exit 1 = not OK -- a setting is missing or different, or a repair was requested (the output says which);
#             Intune then runs Remediate-PimActivator.ps1
#
#  IMPORTANT
#    Keep the SETTINGS block IDENTICAL to the one in Remediate-PimActivator.ps1. If they differ, this script reports
#    "not OK" after every fix and the Remediation runs again and again.
#    Every setting, the repair, and how to set up the Remediation are explained in Remediate-PimActivator.ps1.
# =====================================================================================================================

# ================================================ SETTINGS -- edit these ================================================

# Which extension: 'Released' = production (id eheocihmlppcophaeakmdenhgcookkab)
#                  'Test'     = test build   (id glldnbmjpdkjemcnficagdhgienfdpoo)
$Channel = 'Released'

# Which browsers get the settings (and the repair): 'Edge', 'Chrome', or both. Same extension id in both.
$Browsers = @('Edge', 'Chrome')

# The tenants users can sign in to -- every field is explained in Remediate-PimActivator.ps1.
$TenantCatalog = @'
[
  { "name": "Contoso", "tenantId": "00000000-0000-0000-0000-000000000000", "clientId": "00000000-0000-0000-0000-000000000000",
    "defaultJustification": "Change in infrastructure", "defaultDurationHours": 8 }
]
'@

# Auto-activate cap:   $null = no limit | 0 = auto-activation OFF | 1-100 = max groups a user may tick as "auto"
$AutoActivateMaxGroups = $null

# Confirm threshold:   $null = default (5) | 1-100 = the Activate button asks for a 2nd click at this many roles
$BulkActivateConfirmThreshold = $null

# End-of-day time:     $null = none | 'HH:MM' = activations end no later than this local time today
$ActivationEndTime = $null

# Repair on request, when the browser is open:   $false = wait until it is closed | $true = close Edge/Chrome   (used by Remediate)
$CloseEdge = $false

# ========================================================================================================================

# --- nothing to edit below this line ---
# The channel picks ONLY which extension this is (its id); everything it checks is the same for both.
$ExtensionId = if ($Channel -eq 'Test') { 'glldnbmjpdkjemcnficagdhgienfdpoo' } else { 'eheocihmlppcophaeakmdenhgcookkab' }
$AllExtensions = [ordered]@{ 'eheocihmlppcophaeakmdenhgcookkab' = 'production'; 'glldnbmjpdkjemcnficagdhgienfdpoo' = 'test' }
$PolicyRoots = @{ Edge = 'SOFTWARE\Policies\Microsoft\Edge'; Chrome = 'SOFTWARE\Policies\Google\Chrome' }
$Selected    = @($Browsers | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
# The same compact list form the Remediate script writes (see the note there about Windows PowerShell 5.1).
$Catalog     = ConvertTo-Json -InputObject @($TenantCatalog | ConvertFrom-Json | ForEach-Object { $_ }) -Depth 10 -Compress
$FlagKeys    = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\PIM4EntraPS\PimActivator') +
               @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                 Where-Object { $_.PSChildName -like 'S-1-*' -and $_.PSChildName -notlike '*_Classes' } |
                 ForEach-Object { "Registry::$($_.Name)\Software\PIM4EntraPS\PimActivator" })

try {
    $problems = @()
    $unknown = @($Selected | Where-Object { -not $PolicyRoots.ContainsKey($_) })
    if (-not $Selected.Count -or $unknown.Count) { $problems += "`$Browsers must be 'Edge', 'Chrome' or both (got '$($Browsers -join "', '")')" }
    if ($null -ne $ActivationEndTime -and "$ActivationEndTime" -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$') { $problems += "`$ActivationEndTime must be 'HH:MM' between 00:00 and 23:59 (got '$ActivationEndTime')" }
    # 1. the settings, per browser (64-bit registry, as the browsers read it)
    foreach ($b in @($Selected | Where-Object { $PolicyRoots.ContainsKey($_) })) {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
        $key = $hklm.OpenSubKey("$($PolicyRoots[$b])\3rdparty\extensions\$ExtensionId\policy")
        if (-not $key) { $problems += "$b has no PIM Activator settings on this device yet" }
        else {
            if ("$($key.GetValue('tenantCatalog'))" -ne $Catalog) { $problems += "$b`: the tenant catalog differs" }
            $key.Close()
        }
        # the limits: the SAME values for both PIM Activator extensions (production and test behave the same)
        foreach ($id in $AllExtensions.Keys) {
            $which = if ($id -eq $ExtensionId) { '' } else { " for the $($AllExtensions[$id]) extension too (production and test get the same limits -- if another PIM Activator Remediation sets other values, give both the same)" }
            $key = $hklm.OpenSubKey("$($PolicyRoots[$b])\3rdparty\extensions\$id\policy")
            if (-not $key) { if ($id -ne $ExtensionId) { $problems += "$b`: the limits are not set$which" }; continue }
            if ("$($key.GetValue('autoActivateMaxGroups'))" -ne "$AutoActivateMaxGroups") { $problems += "$b`: the auto-activate cap differs (device '$($key.GetValue('autoActivateMaxGroups'))', wanted '$AutoActivateMaxGroups')$which" }
            if ("$($key.GetValue('bulkActivateConfirmThreshold'))" -ne "$BulkActivateConfirmThreshold") { $problems += "$b`: the confirm threshold differs (device '$($key.GetValue('bulkActivateConfirmThreshold'))', wanted '$BulkActivateConfirmThreshold')$which" }
            if ("$($key.GetValue('activationEndTime'))" -ne "$ActivationEndTime") { $problems += "$b`: the end-of-day time differs (device '$($key.GetValue('activationEndTime'))', wanted '$ActivationEndTime')$which" }
            $key.Close()
        }
        $hklm.Close()
    }
    # 2. a repair request
    foreach ($k in $FlagKeys) {
        if ((Get-ItemProperty -Path $k -Name RepairStuck -ErrorAction SilentlyContinue).RepairStuck -eq 1) { $problems += "a repair was requested ($($k -replace '^Registry::', ''))"; break }
    }
    if ($problems) { Write-Output "Not OK: $($problems -join '; ')."; exit 1 }
    Write-Output "OK: the PIM Activator settings are current ($($Selected -join ' + ')) and no repair is requested."
    exit 0
} catch {
    Write-Output "Not OK: could not check the PIM Activator settings: $($_.Exception.Message)"
    exit 1
}
