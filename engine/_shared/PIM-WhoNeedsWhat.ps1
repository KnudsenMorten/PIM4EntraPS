#Requires -Version 5.1
<#
.SYNOPSIS
    GS-WHO-NEEDS-WHAT (owner 2026-11-10, at a customer: "i cannot see which id to give what permissions") -- WHICH identity
    gets WHICH right, by display name AND object id, for Get Started's "Who needs what" table and every right the steps show.

.DESCRIPTION
    PURE: no network, no Graph, no Azure, no SQL. The caller (tools\pim-manager\Open-PimManager.ps1, GET /api/permissions-health)
    hands in what it already knows from its existing sources -- the engine identity the permission check resolved (the engine
    job's sign-in identity / the engine's recorded 'pim-identities' book), the web app's own identity (its token,
    Get-PimManagerMailIdentities) -- never a new Graph call from the web app (WEB-GRAPH-MIN-1).

    The rights come from the code's own grant sets (engine\_shared\PIM-RightsList.ps1: Get-PimRightsCodeGraphSets +
    Get-PimRightsAzureTable), so the table and the grants cannot drift. Only rights that apply to THIS install are listed:
      * Graph application permissions: the identity's code set (count + the list behind More info);
      * Azure roles: the 'always' rows of the identity, plus -- for the engine, ONLY when Azure resource delegations are
        defined -- User Access Administrator at each defined scope (UAA-QUIET, owner 2026-11-10);
      * Exchange: the scoped send right on the shared mailbox (both identities send), only in shared-mailbox mode.
    An identity whose id is not known yet says so ("not known yet -- the engine records it on its next run"), never blank.
#>
Set-StrictMode -Off

function Get-PimWhoNeedsWhatUnknownText { 'not known yet -- the engine records it on its next run' }

function Format-PimIdentityLabel {
    <# PURE. "Engine identity id-pim-engine (object id 242d...)"; an unknown name / id says so, never blank. #>
    param([Parameter(Mandatory)][string]$Label, [string]$Name = '', [string]$ObjectId = '')
    $n = "$Name".Trim(); $o = "$ObjectId".Trim()
    if (-not $n -and -not $o) { return "$Label -- $(Get-PimWhoNeedsWhatUnknownText)" }
    $t = $Label
    if ($n) { $t += " $n" }
    $t += $(if ($o) { " (object id $o)" } else { " (object id $(Get-PimWhoNeedsWhatUnknownText))" })
    return $t
}

function Get-PimWhoNeedsWhat {
    <#
      PURE. One entry per identity (engine first, then the web app):
        [ordered]@{ role; label; name; objectId; known; text; graph = @{ count; roles }; azure = @( @{ role; scope } );
                    exchange; unknownText }
      -GraphSets   = @{ engine = <ordered name -> id>; web = ... } (Get-PimRightsCodeGraphSets), or $null when not readable
                     (then graph.count = $null and graph.roles = @() -- the page says the list could not be read).
      -AzureTable  = Get-PimRightsAzureTable rows (identity / kind / role / scope / scopeNote / when / key).
      -AzureScopes = the Azure scopes the store's delegations name (Get-PimAzureManagedScopes) -- UAA only when non-empty.
      -MailMode    = 'sharedMailbox' | 'smtp' | 'none' | ''; -MailSender = the shared mailbox address.
    #>
    param(
        [string]$EngineName = '', [string]$EngineObjectId = '',
        [string]$WebName = '', [string]$WebObjectId = '',
        [object]$GraphSets = $null,
        [object[]]$AzureTable = @(),
        [string[]]$AzureScopes = @(),
        [string]$MailMode = '', [string]$MailSender = ''
    )
    $ids = @(
        [ordered]@{ role = 'engine'; label = 'Engine identity';  name = "$EngineName".Trim(); objectId = "$EngineObjectId".Trim() }
        [ordered]@{ role = 'web';    label = 'Web app identity'; name = "$WebName".Trim();    objectId = "$WebObjectId".Trim() }
    )
    $scopes = @(@($AzureScopes) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $sender = "$MailSender".Trim()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in $ids) {
        $g = $null
        if ($GraphSets) {
            $set = $null
            if ($GraphSets -is [System.Collections.IDictionary]) { if ($GraphSets.Contains($i.role)) { $set = $GraphSets[$i.role] } }
            elseif ($GraphSets.PSObject.Properties[$i.role]) { $set = $GraphSets.($i.role) }
            $names = @()
            if ($set -is [System.Collections.IDictionary]) { $names = @($set.Keys | ForEach-Object { "$_" }) }
            elseif ($set) { $names = @(@($set) | ForEach-Object { "$_" } | Where-Object { $_ }) }
            $g = $(if ($null -eq $set) { [ordered]@{ count = $null; roles = @() } } else { [ordered]@{ count = $names.Count; roles = @($names | Sort-Object) } })
        } else { $g = [ordered]@{ count = $null; roles = @() } }
        $az = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($AzureTable)) {
            if (-not $r) { continue }
            if ("$($r.identity)" -ne $i.role -or "$($r.kind)" -ne 'azure-rbac' -or "$($r.when)" -ne 'always') { continue }
            $az.Add([ordered]@{ role = "$($r.role)"; scope = $(if ("$($r.scopeNote)".Trim()) { "$($r.scopeNote)" } else { "$($r.scope)" }) })
        }
        if ($i.role -eq 'engine') {
            foreach ($s in $scopes) { $az.Add([ordered]@{ role = 'User Access Administrator'; scope = $s }) }
        }
        $ex = ''
        if ("$MailMode" -eq 'sharedMailbox') {
            $ex = $(if ($sender) { "Send mail as $sender only (Exchange application role, scoped to that one mailbox)" } else { 'Send mail as the PIM shared mailbox only, once it is set up (Mail sender step)' })
        }
        $known = [bool]($i.objectId)
        $out.Add([ordered]@{
            role = $i.role; label = $i.label; name = $i.name; objectId = $i.objectId; known = $known
            text = (Format-PimIdentityLabel -Label $i.label -Name $i.name -ObjectId $i.objectId)
            graph = $g; azure = @($az.ToArray()); exchange = $ex
            unknownText = (Get-PimWhoNeedsWhatUnknownText)
        })
    }
    return $out.ToArray()
}
