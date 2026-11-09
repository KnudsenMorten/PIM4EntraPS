#Requires -Version 5.1
<#
  _PimSignInIdentity.ps1 -- THE identity a PIM container app / job SIGNS IN AS, for every setup / repair script
  (framework IDENTITY-MOVE-1 line 8, owner 2026-11-09: "code is not reflecting the identity chg").

  Since the identity move (NAM-03, 2026-11-08) an app / job signs in as its USER-ASSIGNED identity id-pim-<role>, named by
  the container's PIM_ManagedIdentityClientId; its system-assigned identity stays attached but holds nothing. Reading
  `identity.principalId` (the SYSTEM identity) therefore names a retired identity: grants, checks and printed fix
  commands went to it (the engine's mail broke that way). The rule, the same as the engine's token call
  (PIM-Rest.ps1 Get-PimManagedIdentityToken) and PIM-ConvergeDefaults' Resolve-PimConvergeSignInOid:
    PIM_ManagedIdentityClientId set -> the attached user-assigned identity with that client id; none matches -> ''
                                       (NEVER the system identity: the caller says "could not be read")
    not set                         -> the system-assigned identity (an install not moved, or a fresh deploy)
  PURE. PS 5.1 + 7. ASCII. A tools\setup helper (dot-sourced via $PSScriptRoot) so the published standalone scripts
  inline it.
#>
Set-StrictMode -Off

function Get-PimSignInField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimSignInIdentity {
    <#
      PURE. -Resource = the ARM object of a container app or job (GET). Returns
      @{ principalId; clientId; kind = user|system|''; name; resourceId (user-assigned only); reason } -- principalId '' with a reason when it cannot be decided.
    #>
    param($Resource)
    $o = [ordered]@{ principalId = ''; clientId = ''; kind = ''; name = ''; resourceId = ''; reason = '' }
    if ($null -eq $Resource) { $o.reason = 'no resource'; return [pscustomobject]$o }
    $cid = ''
    foreach ($c in @(Get-PimSignInField (Get-PimSignInField (Get-PimSignInField $Resource 'properties') 'template') 'containers')) {
        if (-not $c -or "$(Get-PimSignInField $c 'name')" -eq 'signin-front') { continue }
        foreach ($e in @(Get-PimSignInField $c 'env')) {
            if ($e -and "$(Get-PimSignInField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimSignInField $e 'value')".Trim()) { $cid = "$(Get-PimSignInField $e 'value')".Trim() }
        }
        if ($cid) { break }
    }
    $idn = Get-PimSignInField $Resource 'identity'
    if ($cid) {
        $ua = Get-PimSignInField $idn 'userAssignedIdentities'
        $pairs = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys | ForEach-Object { @{ k = "$_"; v = $ua[$_] } }) } elseif ($ua) { @($ua.PSObject.Properties | ForEach-Object { @{ k = $_.Name; v = $_.Value } }) } else { @() }
        foreach ($p in $pairs) {
            if ("$(Get-PimSignInField $p.v 'clientId')".Trim() -ieq $cid -and "$(Get-PimSignInField $p.v 'principalId')".Trim()) {
                $o.principalId = "$(Get-PimSignInField $p.v 'principalId')".Trim(); $o.clientId = $cid; $o.kind = 'user'; $o.name = @("$($p.k)" -split '/')[-1]; $o.resourceId = "$($p.k)"
                return [pscustomobject]$o
            }
        }
        $o.reason = "it signs in with client id $cid, but no attached user-assigned identity has that client id"
        return [pscustomobject]$o
    }
    $sp = "$(Get-PimSignInField $idn 'principalId')".Trim()
    if ($sp) { $o.principalId = $sp; $o.kind = 'system'; $o.name = "$(Get-PimSignInField $Resource 'name') (system-assigned)"; return [pscustomobject]$o }
    $o.reason = 'it has no managed identity it signs in with'
    return [pscustomobject]$o
}

function Get-PimSignInPrincipalId {
    <# PURE. Just the object id (Get-PimSignInIdentity), '' when it cannot be decided. #>
    param($Resource)
    return "$((Get-PimSignInIdentity -Resource $Resource).principalId)"
}
