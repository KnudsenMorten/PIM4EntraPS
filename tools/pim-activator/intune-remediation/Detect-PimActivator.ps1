# =====================================================================================================================
#  PIM Activator for Microsoft Edge and Google Chrome -- settings + "repair on request"   Intune Remediation: DETECTION
# =====================================================================================================================
#
#  WHAT IT DOES
#    Checks this device -- it only READS, nothing is changed:
#      1. the PIM Activator settings are exactly as in the SETTINGS block below, for every browser in $Browsers
#            Edge:    HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extension id>\policy
#            Chrome:  HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extension id>\policy
#            (tenantCatalog, autoActivateMaxGroups, bulkActivateConfirmThreshold)
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

# Repair on request, when the browser is open:   $false = wait until it is closed | $true = close Edge/Chrome   (used by Remediate)
$CloseEdge = $false

# ========================================================================================================================

# --- nothing to edit below this line ---
$ExtensionId = if ($Channel -eq 'Test') { 'glldnbmjpdkjemcnficagdhgienfdpoo' } else { 'eheocihmlppcophaeakmdenhgcookkab' }
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
    # 1. the settings, per browser (64-bit registry, as the browsers read it)
    foreach ($b in @($Selected | Where-Object { $PolicyRoots.ContainsKey($_) })) {
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64').OpenSubKey("$($PolicyRoots[$b])\3rdparty\extensions\$ExtensionId\policy")
        if (-not $key) { $problems += "$b has no PIM Activator settings on this device yet"; continue }
        if ("$($key.GetValue('tenantCatalog'))" -ne $Catalog) { $problems += "$b`: the tenant catalog differs" }
        if ("$($key.GetValue('autoActivateMaxGroups'))" -ne "$AutoActivateMaxGroups") { $problems += "$b`: the auto-activate cap differs (device '$($key.GetValue('autoActivateMaxGroups'))', wanted '$AutoActivateMaxGroups')" }
        if ("$($key.GetValue('bulkActivateConfirmThreshold'))" -ne "$BulkActivateConfirmThreshold") { $problems += "$b`: the confirm threshold differs (device '$($key.GetValue('bulkActivateConfirmThreshold'))', wanted '$BulkActivateConfirmThreshold')" }
        $key.Close()
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
