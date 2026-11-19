#Requires -Version 5.1
<#
.SYNOPSIS
  The install's OWN Key Vault step (BUILT-IN-AUTH-1, owner 2026-11-14) and the installer's REST I/O (New-PimInstallIo).

.DESCRIPTION
  Install-PimManager.ps1 runs Invoke-PimInstallKeyVault after the deploy, the licence and the support access: ONE step,
  'install-keyvault' -- the install's own vault (Standard, RBAC, soft delete 90 days, purge protection; private on a
  private install, framework installer rule 11), the place PIM's secrets go (SEC-10). No key, no role on a key.
  The sign-in is Microsoft's built-in sign-in (the deploy's 'easyauth' step). The shared sign-in front is RETIRED
  (framework SECURE-WEB-1 ONE STANDARD (a), owner 2026-11-14 / 2026-11-19): nothing here installs, builds or moves to it.
  This file replaces tools/setup/_PimInstallSigninFront.ps1 (its front steps were removed 2026-11-19).

  PURE functions are offline-tested (tests/Test-PimInstallKeyVault.ps1); the I/O is injected (-Io), so the step runs with
  no Azure at all. PS 5.1 + 7, REST / .NET only, no modules.
#>

function Test-PimInstallKeyVaultName {
    <# PURE. A Key Vault name Azure accepts: 3-24 letters, digits and dashes, starts with a letter, ends with a letter or digit, no '--'. #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    return ($n -match '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -and $n -notmatch '--')
}

function Get-PimInstallKeyVaultName {
    <#
      PURE. The install's vault name: -Configured (config 'keyVaultName', the customer's own naming) when it is a valid name,
      else 'kv-pim-<token>' (the install's name token, so it is globally unique like the registry and the SQL server).
      @{ ok; name; reason }.
    #>
    param([AllowEmptyString()][string]$Configured = '', [Parameter(Mandatory)][string]$Token)
    $c = "$Configured".Trim()
    if ($c) {
        if (Test-PimInstallKeyVaultName $c) { return @{ ok = $true; name = $c.ToLowerInvariant(); reason = 'the name from the answers (keyVaultName)' } }
        return @{ ok = $false; name = ''; reason = "keyVaultName '$c' is not a valid Key Vault name (3-24 letters, digits and dashes; starts with a letter; no '--')" }
    }
    $t = ("$Token".Trim().ToLowerInvariant() -replace '[^a-z0-9]', '')
    if (-not $t) { return @{ ok = $false; name = ''; reason = 'no name token to derive the Key Vault name from' } }
    $n = "kv-pim-$t"
    if ($n.Length -gt 24) { $n = $n.Substring(0, 24).TrimEnd('-') }
    return @{ ok = $true; name = $n; reason = 'derived from the install''s name token' }
}

function New-PimInstallKeyVaultBody {
    <# PURE. The vault: Standard (no monthly fee), RBAC, soft delete 90 days, purge protection (owner 2026-10-21: "A vault per install"). #>
    # KV-POLICY-DENIED-PRIVATE / framework installer rule 11: a PRIVATE install's vault is private FROM BIRTH (Disabled + Deny +
    # bypass AzureServices -- never None -- + no rules); Invoke-PimKeyVaultRule11 then adds the endpoint and reads it back.
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$TenantId, [switch]$Private)
    $p = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true
                     enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true; publicNetworkAccess = 'Enabled' }
    if ($Private) {
        $p['publicNetworkAccess'] = 'Disabled'
        $p['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() }
    }
    return [ordered]@{ location = $Location; tags = [ordered]@{ product = 'pim-manager'; purpose = 'pim-secrets' }; properties = $p }
}

function Invoke-PimInstallVaultCore {
    <#
      The install's OWN Key Vault (no key, no role): found, or made (name checked first -- a deleted vault keeps its name for 90
      days), Azure RBAC required, and on a private install made private and READ BACK private with its endpoint (framework
      installer rule 11). The install's 'install-keyvault' step.
      -OnLine { param($State, $Message) }. Returns @{ vault; customerTasks }. Throws on a refusal (the caller names its step).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$VaultPath, [Parameter(Mandatory)][string]$KeyVaultName, [AllowEmptyString()][string]$SqlServer = '',
          [Parameter(Mandatory)][string]$SolutionRoot, [bool]$PrivateNetwork = $false, [Parameter(Mandatory)][hashtable]$Io,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$OnLine)
    $kvApi = '2023-07-01'
    $tasks = @()
    $vault = & $Io.Arm 'GET' $VaultPath $null $kvApi
    if (-not $vault) {
        $avail = & $Io.Arm 'POST' "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/checkNameAvailability" @{ name = $KeyVaultName; type = 'Microsoft.KeyVault/vaults' } $kvApi
        if ($avail -and $avail.PSObject.Properties['nameAvailable'] -and -not [bool]$avail.nameAvailable) {
            throw ("the Key Vault name '$KeyVaultName' is taken ($($avail.reason)) -- a deleted vault keeps its name for 90 days. " +
                   "Set another name in the answers (keyVaultName) and resume the installation")
        }
        $vault = & $Io.Arm 'PUT' $VaultPath (New-PimInstallKeyVaultBody -Location $Location -TenantId $TenantId -Private:$PrivateNetwork) $kvApi
        for ($i = 0; $i -lt 36 -and "$($vault.properties.provisioningState)" -notin 'Succeeded', ''; $i++) { & $Sleep 5; $vault = & $Io.Arm 'GET' $VaultPath $null $kvApi }
        if (-not $vault) { throw "the Key Vault $KeyVaultName was not created" }
    }
    if (-not [bool]$vault.properties.enableRbacAuthorization) { throw "the Key Vault $KeyVaultName does not use Azure RBAC -- the install's vault must (it was not made by this install)" }
    if ($PrivateNetwork) {
        # rule 11: PATCH to the shape + READ BACK + the endpoint in the zone, BEFORE any key (a recovered vault ignores
        # networkAcls and comes back with bypass None -> the ARM key calls answer 400 ForbiddenByConnection)
        if (-not (Get-Command Invoke-PimKeyVaultRule11 -ErrorAction SilentlyContinue)) { . (Join-Path $SolutionRoot 'engine\_shared\PIM-KeyVaultPrivate.ps1') }
        # no GetNewClosure() (see New-PimInstallIo): $Io / $kvApi are found through the call chain
        $kvArm = { param($m, $p, $b) $pp, $q = "$p" -split '\?api-version=', 2; & $Io.Arm $m $pp $b $(if ($q) { $q } else { $kvApi }) }
        $kv11 = Invoke-PimKeyVaultRule11 -Arm $kvArm -VaultId $VaultPath -SqlServerName (("$SqlServer" -split '\.')[0]) -Sleep $Sleep
        foreach ($l in @($kv11.lines)) { if ($OnLine) { & $OnLine $(if ("$($l.level)" -eq 'warn') { 'warning' } else { 'waiting' }) "$($l.text)" } }
        if ($kv11.ok -and "$($kv11.customerTask)".Trim()) { $tasks += "$($kv11.customerTask)" }
        if (-not $kv11.ok) { throw "the install is private, so its Key Vault must be too -- $($kv11.reason). Nothing was stored in the vault; resume the installation once it is fixed" }
    }
    return @{ vault = $vault; customerTasks = @($tasks) }
}

function Get-PimInstallKeyVaultStepId { <# PURE. LITERAL. The install's Key Vault step (BUILT-IN-AUTH-1: no sign-in front steps any more). #> return 'install-keyvault' }

function Invoke-PimInstallKeyVault {
    <#
      BUILT-IN-AUTH-1 (owner 2026-11-14): a NEW install ends on Microsoft's built-in sign-in (the deploy's 'easyauth' step --
      secretless, read back), so the sign-in front is NOT installed: no 'signin-front' key, no
      role on any key, no front state, no front image, no front container. What the install still needs from this file is
      its OWN Key Vault (Standard, RBAC, soft delete 90 days, purge protection; private on a private install) -- the place
      PIM's secrets go (SEC-10). ONE step, id 'install-keyvault'; -Done = step ids already completed (resume).
      -OnStep { param($Id, $State, $Message) }; -Io = New-PimInstallIo (Arm; Sleep).
      Returns @{ ok; failedStep; reason; completed[]; keyVaultId; customerTasks }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$ManagerApp, [Parameter(Mandatory)][string]$KeyVaultName,
          [Parameter(Mandatory)][string]$SolutionRoot, [string[]]$Done = @(), [scriptblock]$OnStep, [Parameter(Mandatory)][hashtable]$Io,
          [bool]$PrivateNetwork = $false)
    $step = Get-PimInstallKeyVaultStepId
    $res = @{ ok = $false; failedStep = ''; reason = ''; completed = (New-Object System.Collections.Generic.List[string]); keyVaultId = ''; customerTasks = @() }
    $say = { param($id, $st, $msg) if ($OnStep) { try { & $OnStep $id $st $msg } catch { } } }
    $sleep = if ($Io.Sleep) { $Io.Sleep } else { { param($s) Start-Sleep -Seconds $s } }
    $vaultPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    $res.keyVaultId = $vaultPath
    if ($Done -contains $step) { & $say $step 'skipped' 'already done (resume)'; $res.completed.Add($step) | Out-Null; $res.ok = $true; $res.reason = 'already done'; return $res }
    try {
        & $say $step 'started' "the install's own Key Vault $KeyVaultName (the place PIM keeps its secrets)"
        $sqlServer = ''
        if ($PrivateNetwork) {
            $app = & $Io.Arm 'GET' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerApp" $null '2024-03-01'
            foreach ($c in @($app.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -eq 'PIM_SqlServer' -and "$($e.value)".Trim()) { $sqlServer = "$($e.value)".Trim() } } }
        }
        $core = Invoke-PimInstallVaultCore -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location -VaultPath $vaultPath -KeyVaultName $KeyVaultName `
                    -SqlServer $sqlServer -SolutionRoot $SolutionRoot -PrivateNetwork $PrivateNetwork -Io $Io -Sleep $sleep -OnLine { param($st, $msg) & $say $step $st $msg }
        $res.customerTasks = @($core.customerTasks)
        & $say $step 'ok' "Key Vault $KeyVaultName (Azure RBAC, soft delete 90 days, purge protection$(if ($PrivateNetwork) { ', private' })) -- no sign-in key and no role on it: the sign-in is Microsoft's built-in sign-in"
        $res.completed.Add($step) | Out-Null
        $res.ok = $true; $res.reason = 'the install''s Key Vault is in place'
    } catch {
        $res.ok = $false; $res.failedStep = $step
        $res.reason = "$((("$($_.Exception.Message)") -split "`n")[0])"
        & $say $step 'failed' $res.reason
    }
    return $res
}

function New-PimInstallIo {
    <#
      The real I/O for the install's steps: ARM / Graph over PIM-ArmSetup (the installer's own sign-in) and the PIM database
      as the signed-in installer (-SqlServerFqdn / -SqlDatabase). The caller loads PIM-ArmSetup and PIM-SqlStore at ITS file
      scope (Install-PimManager does).
      🪤 NO GetNewClosure(): a closure is bound to a module of its own and does not see the installer's dot-sourced
      functions (Invoke-PimSetupArm, ...). Each block reads its context from $Io.Ctx -- $Io being the hashtable the step
      receives, found through the call chain when the block runs there.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$SqlServerFqdn, [Parameter(Mandatory)][string]$SqlDatabase)
    return @{
        Ctx = @{ sub = $SubscriptionId; rg = $ResourceGroup; fqdn = $SqlServerFqdn; db = $SqlDatabase; tid = $TenantId }
        Arm = {
            param($Method, $Path, $Body, $ApiVersion)
            if ($Method -eq 'GET') { return (Invoke-PimSetupArm -Path $Path -ApiVersion $ApiVersion -NotFoundOk) }
            return (Invoke-PimSetupArm -Method $Method -Path $Path -Body $Body -ApiVersion $ApiVersion)
        }
        Graph = {
            param($Method, $Path, $Body)
            # a filtered list answers { value = @(...) } -- whatever paging PIM-Rest did
            if ($Method -eq 'GET' -and $Path -match '\?\$filter=') { return @{ value = @(Invoke-PimSetupGraph -Path $Path -All -NotFoundOk | Where-Object { $_ }) } }
            if ($Method -eq 'GET') { return (Invoke-PimSetupGraph -Path $Path -NotFoundOk) }
            return (Invoke-PimSetupGraph -Method $Method -Path $Path -Body $Body)
        }
        Sql = {
            param($Sql)
            $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $Io.Ctx.tid)".Trim()
            $c = New-Object (Resolve-PimSqlClientType).FullName "Server=tcp:$($Io.Ctx.fqdn),1433;Database=$($Io.Ctx.db);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Pooling=False"
            $c.AccessToken = $tok
            try { $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 60; return "$($cmd.ExecuteScalar())" } finally { try { $c.Close() } catch { } }
        }
        Sleep = { param($s) Start-Sleep -Seconds $s }
    }
}
