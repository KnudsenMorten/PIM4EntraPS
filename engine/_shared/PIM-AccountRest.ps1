<#
  PIM4EntraPS -- pure-REST admin-account write path (NO Microsoft.Graph / Az.* modules).

  This is the REST counterpart of the legacy engine function
  CreateUpdate-Accounts-From-file-CSV (PIM-Functions.psm1) for the Entra-ID
  ("TargetPlatform = ID") branch -- the only branch the MSP fan-out
  (Invoke-PimMspFanout.ps1) and the local apply (Invoke-PimLocalApply.ps1)
  ever drive (both call the engine with -OnlyID). It creates / updates the
  cloud admin user object, links the manager, and (best-effort) sets mail
  forwarding, entirely through Invoke-PimGraph -- so the fan-out / apply
  launchers no longer need Connect-MgGraph, Get-MgDomain, New-MgBetaUser,
  Update-MgBetaUser, Set-MgUserManagerByRef or the Graph SDK at all.

  Constraints honoured:
    * REST + certificate app-only auth via PIM-Rest.ps1 (Invoke-PimGraph).
    * PS 5.1-safe: no ?./??, no RSA.ImportFromPem, no ternary; null-guarded.
    * No new module dependencies; no device-code; never writes back to any CSV.
    * On-prem AD ("TargetPlatform = AD") is deliberately OUT of scope here --
      it is a hybrid path that uses the ActiveDirectory module + an explicit
      credential, not a Microsoft REST API. The legacy engine still owns it
      and the $global:PIM_UseGraphSdk opt-in falls back to it.

  Depends on: PIM-Rest.ps1 (must be dot-sourced first by the caller).
#>

Set-StrictMode -Off

# --- helpers ---------------------------------------------------------------

function Get-PimRestDefaultDomain {
  <#
  .SYNOPSIS
    Resolve a tenant's default (or initial) verified domain over Graph REST.
    Replacement for (Get-MgDomain -All | ? IsDefault).Id.
  #>
  [CmdletBinding()]
  param()
  # /domains carries isDefault + isInitial; prefer the default, fall back to the
  # initial .onmicrosoft.com domain (matches the SDK's resolution intent).
  $domains = @(Invoke-PimGraph -All -Path '/domains?$select=id,isDefault,isInitial')
  if (-not $domains.Count) { return $null }
  $def = $domains | Where-Object { $_.isDefault } | Select-Object -First 1
  if ($def) { return $def.id }
  $init = $domains | Where-Object { $_.isInitial } | Select-Object -First 1
  if ($init) { return $init.id }
  return $domains[0].id
}

function New-PimRestPassword {
  <#
  .SYNOPSIS
    Strong random password for a freshly-created cloud admin account.
    Self-contained (no engine-module dependency) so the REST writer works
    even when PIM-Functions.psm1 isn't imported. Mirrors New-PimRandomPassword.
  #>
  [CmdletBinding()] param([ValidateRange(16,128)][int]$Length = 24)
  $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
  $lower   = [char[]]'abcdefghijkmnpqrstuvwxyz'
  $digits  = [char[]]'23456789'
  $symbols = [char[]]'!@#$%^&*-_=+?'
  $all = $upper + $lower + $digits + $symbols
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $pick = {
      param($set)
      $buf = New-Object byte[] 4
      $rng.GetBytes($buf)
      $set[ ([BitConverter]::ToUInt32($buf,0) % $set.Length) ]
    }
    # guarantee one of each class, then fill, then shuffle
    $chars = New-Object System.Collections.Generic.List[char]
    $chars.Add((& $pick $upper)); $chars.Add((& $pick $lower))
    $chars.Add((& $pick $digits)); $chars.Add((& $pick $symbols))
    while ($chars.Count -lt $Length) { $chars.Add((& $pick $all)) }
    # Fisher-Yates shuffle (crypto rng)
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
      $b = New-Object byte[] 4; $rng.GetBytes($b)
      $j = [int]([BitConverter]::ToUInt32($b,0) % ($i + 1))
      $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return (-join $chars)
  } finally { $rng.Dispose() }
}

function Get-PimRowValue {
  # PS 5.1-safe accessor that works for both hashtables and PSCustomObjects.
  param($Row,[string]$Name)
  if ($null -eq $Row) { return '' }
  if ($Row -is [hashtable]) { if ($Row.ContainsKey($Name)) { return "$($Row[$Name])" } else { return '' } }
  $p = $Row.PSObject.Properties[$Name]
  if ($p) { return "$($p.Value)" } else { return '' }
}

# --- the ID create/update path over REST ------------------------------------

function New-PimRestAdminAccount {
  <#
  .SYNOPSIS
    Create or update ONE Entra-ID admin user over Graph REST (idempotent),
    optionally link a manager and set mail forwarding. Pure REST -- the
    Invoke-PimMspFanout / Invoke-PimLocalApply replacement for the ID branch
    of CreateUpdate-Accounts-From-file-CSV.

  .PARAMETER Row
    A PSCustomObject / hashtable carrying the same column set the engine CSV
    uses: FirstName, LastName, Initials, UserName, DisplayName,
    UserPrincipalName, UsageLocation, Company, Notes, ManagerEmail, StartDate,
    ForwardMailsToContact, MailForwardAddress, AccountStatus, TargetPlatform.

  .PARAMETER NoMailForward
    Suppress the mail-forwarding attempt entirely.

  .OUTPUTS
    PSCustomObject { Upn; Action = created|updated|whatif|failed; Password }
    (Password is non-empty only when a new account was created.)
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][object]$Row,
    [switch]$NoMailForward
  )

  $upn          = Get-PimRowValue $Row 'UserPrincipalName'
  $userName     = Get-PimRowValue $Row 'UserName'
  $first        = Get-PimRowValue $Row 'FirstName'
  $last         = Get-PimRowValue $Row 'LastName'
  $display      = Get-PimRowValue $Row 'DisplayName'
  $usageLoc     = Get-PimRowValue $Row 'UsageLocation'
  $company      = Get-PimRowValue $Row 'Company'
  $managerEmail = Get-PimRowValue $Row 'ManagerEmail'
  $jobTitle     = $display      # legacy engine sets JobTitle = DisplayName for ID rows
  $fwdFlag      = (Get-PimRowValue $Row 'ForwardMailsToContact').Trim()
  if (-not $fwdFlag) { $fwdFlag = (Get-PimRowValue $Row 'ForwardMails').Trim() }
  $fwdAddr      = (Get-PimRowValue $Row 'MailForwardAddress').Trim()
  if (-not $fwdAddr) { $fwdAddr = (Get-PimRowValue $Row 'MailForwardToAddress').Trim() }
  $wantForward  = (-not $NoMailForward) -and ($fwdFlag -eq 'TRUE') -and $fwdAddr

  if (-not $upn) { throw "New-PimRestAdminAccount: row has no UserPrincipalName." }

  # Does the user already exist? (404 -> create). Use GET by UPN.
  $existing = $null
  try {
    $existing = Invoke-PimGraph -Path ("/users/{0}?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($upn))
  } catch {
    # a real 404 means "create"; anything else (403/5xx) is a genuine failure
    if ("$($_.Exception.Message)" -notmatch 'HTTP 404|Request_ResourceNotFound|does not exist') { throw }
  }

  if ($existing -and $existing.id) {
    if (-not $PSCmdlet.ShouldProcess($upn, 'Update Entra user (REST)')) {
      return [pscustomobject]@{ Upn = $upn; Action = 'whatif'; Password = '' }
    }
    $patch = @{
      givenName         = $first
      surname           = $last
      displayName       = $display
      mailNickname      = $userName
      jobTitle          = $jobTitle
      usageLocation     = $usageLoc
      passwordPolicies  = 'DisablePasswordExpiration'
    }
    Invoke-PimGraph -Method PATCH -Path "/users/$($existing.id)" -Body $patch | Out-Null
    if ($wantForward) { Set-PimRestMailForward -UserId $upn -ForwardTo $fwdAddr }
    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
      Write-PimAuditEvent -Action 'account.update' -Target $upn -After @{ displayName = $display; platform = 'ID'; transport = 'rest' }
    }
    return [pscustomobject]@{ Upn = $upn; Action = 'updated'; Password = '' }
  }

  # --- create ---
  if (-not $PSCmdlet.ShouldProcess($upn, 'Create Entra user (REST)')) {
    return [pscustomobject]@{ Upn = $upn; Action = 'whatif'; Password = '' }
  }
  $pw = New-PimRestPassword
  $body = @{
    accountEnabled    = $true
    givenName         = $first
    surname           = $last
    displayName       = $display
    mailNickname      = $userName
    userPrincipalName = $upn
    jobTitle          = $jobTitle
    usageLocation     = $usageLoc
    passwordProfile   = @{ password = $pw; forceChangePasswordNextSignIn = $false }
  }
  if ($company) { $body['companyName'] = $company }
  $created = Invoke-PimGraph -Method POST -Path '/users' -Body $body
  $newId = if ($created) { $created.id } else { $null }

  # Read replicas can lag the create -- retry the password-policy PATCH so the
  # account isn't left without DisablePasswordExpiration (same guard the SDK path has).
  for ($try = 1; $try -le 5; $try++) {
    try {
      Invoke-PimGraph -Method PATCH -Path "/users/$([uri]::EscapeDataString($upn))" -Body @{ passwordPolicies = 'DisablePasswordExpiration' } | Out-Null
      break
    } catch {
      if ("$($_.Exception.Message)" -match 'Request_ResourceNotFound|HTTP 404|does not exist' -and $try -lt 5) {
        Start-Sleep -Seconds ($try * 3); continue
      }
      if ($try -ge 5) { Write-Warning "  could not set DisablePasswordExpiration on $upn after retries." }
      else { throw }
    }
  }

  # manager link (best-effort -- never fail the create on a missing manager)
  if ($managerEmail) {
    try {
      $mgr = Invoke-PimGraph -Path ("/users/{0}?`$select=id" -f [uri]::EscapeDataString($managerEmail))
      if ($mgr -and $mgr.id) {
        Invoke-PimGraph -Method PUT -Path "/users/$([uri]::EscapeDataString($upn))/manager/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.id)" } | Out-Null
      }
    } catch {
      Write-Host "  manager link skipped for $upn -> $managerEmail ($($_.Exception.Message))" -ForegroundColor Yellow
    }
  }

  if ($wantForward) { Set-PimRestMailForward -UserId $upn -ForwardTo $fwdAddr }

  # persist the generated password (engine helper when available, else a local note)
  if (Get-Command Write-PimAdminPassword -ErrorAction SilentlyContinue) {
    Write-PimAdminPassword -UserPrincipalName $upn -Password $pw -Platform 'ID'
  } else {
    Write-Host "  -> initial password for $upn (ID): $pw" -ForegroundColor Cyan
  }
  if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
    Write-PimAuditEvent -Action 'account.create' -Target $upn -After @{ displayName = $display; platform = 'ID'; transport = 'rest' }
  }
  return [pscustomobject]@{ Upn = $upn; Action = 'created'; Password = $pw }
}

function Set-PimRestMailForward {
  <#
  .SYNOPSIS
    Set mailbox forwarding over PURE REST, delegating to the canonical
    Set-PimMailboxForwarding (PIM-Rest.ps1) -- the app-only Exchange Online
    InvokeCommand path that exactly mirrors
    "Set-Mailbox -ForwardingSmtpAddress <smtp> -DeliverToMailboxAndForward:$false".
    Best-effort: mail forwarding is informational; a failure (no Exchange
    license, mailbox not provisioned yet, EXO ManageAsApp not consented) is
    logged, not fatal -- the account create/update still succeeds.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$UserId,[Parameter(Mandatory)][string]$ForwardTo)
  if (-not (Get-Command Set-PimMailboxForwarding -ErrorAction SilentlyContinue)) {
    Write-Host "  [warn] Set-PimMailboxForwarding not available (PIM-Rest not loaded) -- skipping mail forwarding for $UserId." -ForegroundColor Yellow
    return
  }
  try {
    Set-PimMailboxForwarding -Identity $UserId -ForwardingSmtpAddress $ForwardTo -DeliverToMailboxAndForward $false
    Write-Host "  mail-forward set for $UserId -> $ForwardTo (EXO REST)" -ForegroundColor DarkGray
  } catch {
    Write-Host "  [warn] could not set mail forwarding for $UserId (EXO REST): $($_.Exception.Message). Check Exchange license / mailbox provisioning / Exchange.ManageAsApp consent." -ForegroundColor Yellow
  }
}

function Invoke-PimRestAccountApply {
  <#
  .SYNOPSIS
    Apply a set of admin-account rows (the ID branch only) over pure Graph REST.
    Drop-in replacement for CreateUpdate-Accounts-From-file-CSV -OnlyID in the
    fan-out / local-apply launchers.

  .PARAMETER Rows
    Array of account rows (PSCustomObject) -- same shape the engine CSV uses.

  .PARAMETER WhatIfMode
    Plan only.

  .OUTPUTS
    Array of per-row result objects { Upn; Action; Password }.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$Rows,
    [switch]$WhatIfMode
  )
  $results = New-Object System.Collections.Generic.List[object]
  foreach ($r in $Rows) {
    $platform = Get-PimRowValue $r 'TargetPlatform'
    $rowUpn   = Get-PimRowValue $r 'UserPrincipalName'
    if (-not $rowUpn) { $rowUpn = '<row>' }
    if ($platform -and $platform -ne 'ID') {
      # AD / other platforms are out of REST scope (hybrid path) -- skip here.
      Write-Host "  [skip] $rowUpn TargetPlatform='$platform' -- not an ID row (AD/hybrid uses the SDK engine path)." -ForegroundColor DarkGray
      continue
    }
    try {
      if ($WhatIfMode) {
        $results.Add((New-PimRestAdminAccount -Row $r -WhatIf))
      } else {
        $results.Add((New-PimRestAdminAccount -Row $r))
      }
    } catch {
      Write-Host "  [fail] ${rowUpn}: $($_.Exception.Message)" -ForegroundColor Red
      $results.Add([pscustomobject]@{ Upn = $rowUpn; Action = "failed: $($_.Exception.Message)"; Password = '' })
    }
  }
  return $results.ToArray()
}

# --- pure-REST blob upload (drops Az.Storage from the baseline courier) ------

function Send-PimRestBlob {
  <#
  .SYNOPSIS
    Upload a file to Azure Blob storage over the REST Put Blob API using an
    OAuth bearer token (storage audience) from PIM-Rest -- no Az.Storage module,
    no account key. Replacement for New-AzStorageContext + Set-AzStorageBlobContent.

  .PARAMETER StorageAccount
    Storage account name (without the .blob.core.windows.net suffix).

  .PARAMETER Container
    Blob container name (must already exist).

  .PARAMETER Blob
    Target blob name.

  .PARAMETER FilePath
    Local file to upload (read as raw bytes).
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [Parameter(Mandatory)][string]$Container,
    [Parameter(Mandatory)][string]$Blob,
    [Parameter(Mandatory)][string]$FilePath
  )
  $token = Get-PimRestToken -Resource 'https://storage.azure.com'
  $bytes = [System.IO.File]::ReadAllBytes($FilePath)
  $url   = "https://$StorageAccount.blob.core.windows.net/$Container/$([uri]::EscapeUriString($Blob))"
  $headers = @{
    Authorization    = "Bearer $token"
    'x-ms-blob-type' = 'BlockBlob'
    'x-ms-version'   = '2021-08-06'
    'x-ms-date'      = ([DateTime]::UtcNow.ToString('R'))
  }
  Invoke-RestMethod -Method PUT -Uri $url -Headers $headers -Body $bytes -ContentType 'application/json' | Out-Null
}
