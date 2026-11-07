#Requires -Version 5.1
# PIM-SqlBuildWindow.ps1 -- FREE (owner 2026-11-07, OPEN-23 / §84: Set-PimSqlBuildWindow.ps1 is free, so tenant prep works in
# the Community copy). The PURE check of the database build window, moved here unchanged from engine/msp/PIM-MspBuild.ps1
# (Pro), which now dot-sources this file. PURE: no network. ASCII only; PS 5.1 + 7; no modules.
Set-StrictMode -Off

function Test-PimSqlBuildWindowState {
    <#
      PURE. 71.36 -- is the store's build window CLOSED, as read back from ARM?
      -State @{ publicNetworkAccess; firewallRules[]; vnetRules[]; privateEndpoints[] }.
        private-endpoint shape (privateEndpoints non-empty): publicNetworkAccess must be Disabled.
        VNet-only shape: NO firewall rule at all (no AllowSetupHost, no AllowAzureServices, nothing else) and at least one
        virtual network rule (the environment's own subnet) -- the public endpoint then admits that subnet only.
      Returns @{ ok; reasons[]; summary }.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [ValidateSet('Closed')][string]$Want = 'Closed')
    $r = New-Object System.Collections.Generic.List[string]
    $pes = @($State.privateEndpoints | Where-Object { "$_".Trim() }); $fw = @($State.firewallRules | Where-Object { "$_".Trim() }); $vr = @($State.vnetRules | Where-Object { "$_".Trim() })
    if ($pes.Count) {
        if ("$($State.publicNetworkAccess)" -ne 'Disabled') { $r.Add("publicNetworkAccess is '$($State.publicNetworkAccess)', want Disabled (the server has a private endpoint)") }
        $sum = 'private endpoint only (public network access Disabled)'
    } else {
        if ($fw.Count) { $r.Add("firewall rule(s) still present: $($fw -join ', ')") }
        if (-not $vr.Count) { $r.Add('no virtual network rule -- the environment could not reach its own database') }
        $sum = "public endpoint admits ONLY the virtual network rule(s) $($vr -join ', ') (no IP rule, no Azure-services rule)"
    }
    return @{ ok = ($r.Count -eq 0); reasons = @($r.ToArray()); summary = $sum }
}
