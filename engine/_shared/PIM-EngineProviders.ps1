<#
  PIM4EntraPS -- NEW engine scope providers (REST + SQL). Each provider plugs into
  PIM-EngineCore.ps1. Add a scope by registering a provider here.

  Implemented now:
    * Admins  -- ensure the admin accounts (Account-Definitions-Admins) exist + enabled
                 in Entra, fully over Graph REST.

  Contract for the remaining scopes (EntraRoles, AzRes, GroupsAssignment, GroupsPolicies,
  AdministrativeUnits, Workloads) is the same hashtable shape; they are added
  incrementally (their PIM REST apply workflows are larger). Until a provider is
  registered, Invoke-PimEngineScope returns "no provider" for that scope (handled
  gracefully by the scheduler).
#>

Set-StrictMode -Off

function Get-PimRowProp {
    param([object]$Row, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
    }
    return ''
}

function New-PimAdminsProvider {
    @{
        scope  = 'Admins'
        entity = 'Account-Definitions-Admins'
        GetDesired = { param($ctx) Get-PimDesiredRows -Entity 'Account-Definitions-Admins' }
        GetLive    = {
            param($ctx)
            @(Invoke-PimGraph -Path "/users?`$select=id,userPrincipalName,displayName,accountEnabled" -All)
        }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('userPrincipalName','UserPrincipalName','UPN','upn') }
        # desired = account should EXIST and be ENABLED. (Equality is against live.)
        Equal = { param($d,$l) [bool]$l.accountEnabled }
        ApplyCreate = {
            param($item,$ctx)
            $upn  = "$($item.key)"
            $disp = Get-PimRowProp -Row $item.desired -Names @('DisplayName','displayName')
            if (-not $disp) { $disp = $upn }
            $nick = ($upn -split '@')[0]
            $pw   = ([guid]::NewGuid().ToString('N').Substring(0,12)) + '!Aa9'
            Invoke-PimGraph -Method POST -Path '/users' -Body @{
                accountEnabled=$true; displayName=$disp; mailNickname=$nick; userPrincipalName=$upn
                passwordProfile=@{ forceChangePasswordNextSignIn=$true; password=$pw }
            }
        }
        ApplyUpdate = {
            param($item,$ctx)
            # exists but disabled -> enable
            Invoke-PimGraph -Method PATCH -Path "/users/$($item.live.id)" -Body @{ accountEnabled=$true }
        }
        ApplyRemove = {
            param($item,$ctx)
            # Full reconcile: disable (never delete) an admin account not in desired.
            Invoke-PimGraph -Method PATCH -Path "/users/$($item.live.id)" -Body @{ accountEnabled=$false }
        }
    }
}

function Register-PimDefaultEngineProviders {
    if (-not (Get-Command Register-PimEngineProvider -ErrorAction SilentlyContinue)) { throw 'PIM-EngineCore.ps1 not loaded.' }
    Register-PimEngineProvider -Provider (New-PimAdminsProvider)
    # TODO (incremental): EntraRoles, AzRes, GroupsAssignment, GroupsPolicies,
    # AdministrativeUnits, Workloads -- same contract, REST live + apply.
}
