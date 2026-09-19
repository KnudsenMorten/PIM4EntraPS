#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-U (IaC import) -- prepare MANY environments from one config: per environment, the workload prerequisites
    (Initialize-PimWorkloadPrereqs.ps1) and the permission template packs (Import-PimPermissionTemplate.ps1), inside the
    SQL build window.

.DESCRIPTION
    Operator, 2026-09-19: "can you import with script" / "iac" / "so 25 tenants can be prepped".

    -Config is a JSON file (sample: config\tenant-prep.custom.sample.json; copy it to tenant-prep.custom.json, which is
    gitignored -- real values are never committed). Either a list of environments, or { "environments": [ ... ] }.
    Each environment:
      name            unique; -Only selects by it
      tenantId        tenant GUID
      subscriptionId  the HOSTING subscription (where the store and ca-pim-tick run)
      resourceGroup   the hosting resource group
      sqlServerFqdn   <server>.database.windows.net
      sqlDatabase     optional, default PimPlatform
      tickJobName     optional, default ca-pim-tick
      privateStore    optional, default false. How the SQL build window is CLOSED, as the MSP build does it: false =
                      tools\setup\Close-PimSqlSetupHostRule.ps1 (removes only this host's AllowSetupHost rule); true =
                      tools\setup\Set-PimSqlBuildWindow.ps1 -Mode Close (the environment's subnet / private endpoint only).
      buildWindow     optional, default true. false = this host already reaches the store; no window is opened or closed.
      identity        EITHER { "clientId", "certThumbprint" } (certificate in LocalMachine\My)
                      OR     { "keyVault", "clientIdSecret", "certThumbprintSecret" } -- secret NAMES, read at run time with
                             Get-AzKeyVaultSecret -AsPlainText (needs Az.KeyVault and a Connect-AzAccount session that can
                             read the vault). Secret VALUES are never stored in the config.
      prereqs         [ { "workload": DefenderXdr|Intune|PowerBI|AzureRbac|EntraRoles,
                          "options": { EnableSentinel, GrantAzureUserAccessAdministrator, SkipDataOperations (booleans),
                                       ConfirmPortalStep: [ids], SentinelWorkspaceId, AzureScope: [scopes] } } ]
      templates       [ pack ids, or "all-active" ]

    Per environment, in config order:
      1. open the SQL build window (Set-PimSqlBuildWindow.ps1 -Mode Open) -- and ALWAYS close it again in finally,
         whatever failed in between;
      2. Initialize-PimWorkloadPrereqs.ps1 once per prereq entry, with its options (a workload that is not green is
         recorded, not an error: groups are always deployable, only the workload ASSIGNMENT waits);
      3. Import-PimPermissionTemplate.ps1 for the templates.
    A failure in one environment is recorded and the run continues with the next. The run ends with a summary table
    (prerequisite state per workload, rows imported per pack, held workloads) and exits 1 when any environment errored.

    -WhatIf passes through to both scripts and opens no build window (so a plan works only where this host already
    reaches the store). Run under Windows PowerShell 5.1, like the scripts it drives. The az CLI (signed in, able to see
    each subscription) is used only for the build window; every az call names its subscription.

.EXAMPLE
    .\tools\setup\Invoke-PimTenantPrep.ps1 -Config .\config\tenant-prep.custom.json
.EXAMPLE
    .\tools\setup\Invoke-PimTenantPrep.ps1 -Config .\config\tenant-prep.custom.json -Only example-a,example-b -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Config,
    [string[]]$Only = @(),
    [switch]$PassThru,
    # TEST SEAM (tests\Test-PimTemplateImport.ps1): the folder holding the four scripts this driver runs. Default: here.
    [string]$ToolRoot
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-WorkloadPrereqs.ps1')   # the workload names (Get-PimWorkloadPrereqWorkloads)
$tools = if ("$ToolRoot".Trim()) { "$ToolRoot".Trim() } else { $PSScriptRoot }
$scr = @{
    prereq = Join-Path $tools 'Initialize-PimWorkloadPrereqs.ps1'
    import = Join-Path $tools 'Import-PimPermissionTemplate.ps1'
    window = Join-Path $tools 'Set-PimSqlBuildWindow.ps1'
    close  = Join-Path $tools 'Close-PimSqlSetupHostRule.ps1'
}
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

# The prereq options the config may carry -> how they are passed (a typo must not silently do nothing).
$prereqOptionKinds = [ordered]@{
    EnableSentinel = 'switch'; GrantAzureUserAccessAdministrator = 'switch'; SkipDataOperations = 'switch'
    ConfirmPortalStep = 'list'; AzureScope = 'list'; SentinelWorkspaceId = 'string'
}

function Get-PimTenantPrepValue {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimTenantPrepEnvErrors {
    # PURE. What is wrong with one environment entry ('' list = nothing). Checked before anything runs for it.
    param([object]$EnvCfg)
    $e = New-Object System.Collections.Generic.List[string]
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    foreach ($k in 'tenantId', 'subscriptionId') { if ("$(Get-PimTenantPrepValue $EnvCfg $k)".Trim() -notmatch $guid) { $e.Add("$k must be a GUID") } }
    foreach ($k in 'resourceGroup', 'sqlServerFqdn') { if (-not "$(Get-PimTenantPrepValue $EnvCfg $k)".Trim()) { $e.Add("$k is required") } }
    $id = Get-PimTenantPrepValue $EnvCfg 'identity'
    $direct = "$(Get-PimTenantPrepValue $id 'clientId')".Trim() -and "$(Get-PimTenantPrepValue $id 'certThumbprint')".Trim()
    $kv = "$(Get-PimTenantPrepValue $id 'keyVault')".Trim() -and "$(Get-PimTenantPrepValue $id 'clientIdSecret')".Trim() -and "$(Get-PimTenantPrepValue $id 'certThumbprintSecret')".Trim()
    if ($direct -and $kv) { $e.Add('identity: give clientId + certThumbprint OR keyVault + clientIdSecret + certThumbprintSecret, not both') }
    elseif (-not $direct -and -not $kv) { $e.Add('identity: give clientId + certThumbprint, or keyVault + clientIdSecret + certThumbprintSecret') }
    $known = @(Get-PimWorkloadPrereqWorkloads)
    foreach ($p in @(Get-PimTenantPrepValue $EnvCfg 'prereqs')) {
        if ($null -eq $p) { continue }
        $w = "$(Get-PimTenantPrepValue $p 'workload')".Trim()
        if ($known -notcontains $w) { $e.Add("prereqs: unknown workload '$w' (known: $($known -join ', '))") }
        $o = Get-PimTenantPrepValue $p 'options'
        if ($null -ne $o) {
            $names = if ($o -is [System.Collections.IDictionary]) { @($o.Keys) } else { @($o.PSObject.Properties | ForEach-Object { $_.Name }) }
            foreach ($n in $names) { if (-not $prereqOptionKinds.Contains("$n")) { $e.Add("prereqs[$w]: unknown option '$n' (known: $(@($prereqOptionKinds.Keys) -join ', '))") } }
        }
    }
    $tpls = @(@(Get-PimTenantPrepValue $EnvCfg 'templates') | Where-Object { "$_".Trim() })
    $pres = @(@(Get-PimTenantPrepValue $EnvCfg 'prereqs') | Where-Object { $null -ne $_ })
    if (-not $tpls.Count -and -not $pres.Count) { $e.Add('nothing to do: no prereqs and no templates') }
    return @($e.ToArray())
}

function Resolve-PimTenantPrepIdentity {
    # -> @{ clientId; certThumbprint; source }. Key Vault refs are read NOW, never stored.
    param([Parameter(Mandatory)][object]$Identity)
    $cid = "$(Get-PimTenantPrepValue $Identity 'clientId')".Trim(); $thumb = "$(Get-PimTenantPrepValue $Identity 'certThumbprint')".Trim()
    if ($cid -and $thumb) { return @{ clientId = $cid; certThumbprint = $thumb; source = 'config' } }
    $vault = "$(Get-PimTenantPrepValue $Identity 'keyVault')".Trim()
    $cidName = "$(Get-PimTenantPrepValue $Identity 'clientIdSecret')".Trim(); $thumbName = "$(Get-PimTenantPrepValue $Identity 'certThumbprintSecret')".Trim()
    if (-not (Get-Command Get-AzKeyVaultSecret -ErrorAction SilentlyContinue)) {
        throw "identity: Key Vault '$vault' is referenced, but Get-AzKeyVaultSecret is not available -- install Az.KeyVault and Connect-AzAccount as an identity that can read the vault first."
    }
    $cid = "$(Get-AzKeyVaultSecret -VaultName $vault -Name $cidName -AsPlainText)".Trim()
    $thumb = "$(Get-AzKeyVaultSecret -VaultName $vault -Name $thumbName -AsPlainText)".Trim()
    if (-not $cid -or -not $thumb) { throw "identity: Key Vault '$vault' returned an empty value for '$cidName' or '$thumbName'." }
    return @{ clientId = $cid; certThumbprint = $thumb; source = "keyVault $vault ($cidName, $thumbName)" }
}

# --- the config ------------------------------------------------------------------------------------------------------
$summary = New-Object System.Collections.Generic.List[object]
$configErr = ''
$envs = @()
try {
    if (-not (Test-Path -LiteralPath $Config)) { throw "config not found: $Config" }
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Config).Path, (New-Object System.Text.UTF8Encoding($false)))
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    $doc = $raw | ConvertFrom-Json
    # TRAP: pwsh 7 ENUMERATES a top-level JSON array (a one-element list arrives as the element itself); 5.1 does not.
    if ($doc -is [System.Array] -or $raw.TrimStart().StartsWith('[')) { $envs = @($doc) }
    elseif ($doc.PSObject.Properties['environments']) { $envs = @($doc.environments) }
    else { throw 'config: expected a list of environments, or { "environments": [ ... ] }' }
    $envs = @($envs | Where-Object { $null -ne $_ })
    if (-not $envs.Count) { throw 'config: no environments' }
    $names = @($envs | ForEach-Object { "$(Get-PimTenantPrepValue $_ 'name')".Trim() })
    if (@($names | Where-Object { -not $_ }).Count) { throw 'config: every environment needs a name' }
    $dup = @($names | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($dup.Count) { throw "config: duplicate environment name(s): $($dup -join ', ')" }
    $sel = @($Only | Where-Object { "$_".Trim() })
    if ($sel.Count) {
        $unknown = @($sel | Where-Object { $names -notcontains "$_".Trim() })
        if ($unknown.Count) { throw "-Only: unknown environment(s) $($unknown -join ', ') (config has: $($names -join ', '))" }
        $envs = @($envs | Where-Object { $sel -contains "$(Get-PimTenantPrepValue $_ 'name')".Trim() })
    }
} catch {
    # A config error runs NOTHING -- not even the environments that parsed (a half-applied selection is worse than none).
    $configErr = "$($_.Exception.Message)"; $envs = @()
    Write-Host "ERROR: $configErr" -ForegroundColor Red
}

# --- per environment ---------------------------------------------------------------------------------------------------
foreach ($ec in $envs) {
    $name = "$(Get-PimTenantPrepValue $ec 'name')".Trim()
    $rec = [ordered]@{ name = $name; ok = $false; errors = @(); prereqs = [ordered]@{}; packs = [ordered]@{}; held = @(); addedTotal = 0
                       windowOpened = $false; windowClosed = $false; identitySource = '' }
    $errs = New-Object System.Collections.Generic.List[string]
    $windowTried = $false
    $sub = "$(Get-PimTenantPrepValue $ec 'subscriptionId')".Trim(); $rg = "$(Get-PimTenantPrepValue $ec 'resourceGroup')".Trim()
    $fqdn = "$(Get-PimTenantPrepValue $ec 'sqlServerFqdn')".Trim()
    $db = "$(Get-PimTenantPrepValue $ec 'sqlDatabase')".Trim(); if (-not $db) { $db = 'PimPlatform' }
    $private = [bool](Get-PimTenantPrepValue $ec 'privateStore')
    $bw = Get-PimTenantPrepValue $ec 'buildWindow'; $useWindow = ($null -eq $bw) -or [bool]$bw
    Write-Host ''
    Step "environment '$name' (tenant $("$(Get-PimTenantPrepValue $ec 'tenantId')".Trim()))"
    # Nothing from the previous environment may reach this one (Connect-PimSetupStore sets these again).
    # (-WhatIf:$false: Set-Variable honours -WhatIf, and a plan run must not inherit the previous environment either.)
    foreach ($g in 'PIM_TenantId', 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_SqlClientId', 'PIM_SqlCertThumbprint', 'PIM_SqlServer', 'PIM_SqlDatabase', 'PIM_SetupActor') { Set-Variable -Scope Global -Name $g -Value $null -WhatIf:$false }
    try {
        $bad = @(Get-PimTenantPrepEnvErrors -EnvCfg $ec)
        if ($bad.Count) { throw "config: $($bad -join '; ')" }
        $tid = "$(Get-PimTenantPrepValue $ec 'tenantId')".Trim()
        $ident = Resolve-PimTenantPrepIdentity -Identity (Get-PimTenantPrepValue $ec 'identity')
        $rec.identitySource = $ident.source
        Note "identity: app $($ident.clientId) ($($ident.source))"
        $common = @{ TenantId = $tid; SqlServerFqdn = $fqdn; SqlDatabase = $db; ClientId = $ident.clientId; CertThumbprint = $ident.certThumbprint }

        # 1) the SQL build window
        if (-not $useWindow) { Note 'build window: off for this environment (buildWindow = false)' }
        elseif ($WhatIfPreference) { Note 'build window: NOT opened under -WhatIf (the plan reads only where this host already reaches the store)' }
        else {
            $windowTried = $true
            & $scr.window -SubscriptionId $sub -ResourceGroup $rg -SqlServerName $fqdn -Mode Open
            $rec.windowOpened = $true
        }

        # 2) workload prerequisites -- recorded per workload; not green is NOT an error
        foreach ($p in @(Get-PimTenantPrepValue $ec 'prereqs')) {
            if ($null -eq $p) { continue }
            $w = "$(Get-PimTenantPrepValue $p 'workload')".Trim()
            $pa = @{ Workload = $w; SubscriptionId = $sub; ResourceGroup = $rg } + $common
            $tj = "$(Get-PimTenantPrepValue $ec 'tickJobName')".Trim(); if ($tj) { $pa['TickJobName'] = $tj }
            $o = Get-PimTenantPrepValue $p 'options'
            foreach ($on in @($prereqOptionKinds.Keys)) {
                $ov = Get-PimTenantPrepValue $o $on
                if ($null -eq $ov) { continue }
                switch ($prereqOptionKinds[$on]) {
                    'switch' { if ([bool]$ov) { $pa[$on] = $true } }
                    'list'   { $l = @(@($ov) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }); if ($l.Count) { $pa[$on] = [string[]]$l } }
                    default  { if ("$ov".Trim()) { $pa[$on] = "$ov".Trim() } }
                }
            }
            Step "[$name] prerequisites: $w"
            try {
                $global:LASTEXITCODE = 0
                & $scr.prereq @pa -WhatIf:$WhatIfPreference | Out-Host
                $code = [int]$LASTEXITCODE
                $rec.prereqs[$w] = switch ($code) { 0 { 'ok' } 1 { 'failed' } 2 { 'incomplete' } default { "exit $code" } }
            } catch {
                $rec.prereqs[$w] = 'error'
                $errs.Add("prereqs ${w}: $($_.Exception.Message)")
                Write-Host "    ERROR (prereqs $w): $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # 3) the permission templates
        $tpls = @(@(Get-PimTenantPrepValue $ec 'templates') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($tpls.Count) {
            Step "[$name] permission templates: $($tpls -join ', ')"
            $global:LASTEXITCODE = 0
            $out = @(& $scr.import -Template ([string[]]$tpls) @common -PassThru -WhatIf:$WhatIfPreference)
            $code = [int]$LASTEXITCODE
            $res = @($out | Where-Object { $null -ne $_ -and $_.PSObject.Properties['packs'] }) | Select-Object -Last 1
            if ($res) {
                foreach ($pk in @($res.packs)) {
                    $rec.packs["$($pk.id)"] = $(if ("$($pk.status)" -eq 'imported') { "+$([int]$pk.addedCount)" } elseif ("$($pk.status)" -eq 'alreadyImported') { '+0' } else { "$($pk.status)" })
                    foreach ($h in @($pk.held)) { if ("$h" -and @($rec.held) -notcontains "$h") { $rec.held = @($rec.held) + @("$h") } }
                }
                $rec.addedTotal = [int]$res.addedTotal
            }
            if ($code -ne 0) {
                $why = if ($res -and @($res.errors).Count) { @($res.errors) -join ' | ' } else { "exit $code" }
                $errs.Add("templates: $why")
            }
        }
    } catch {
        $errs.Add("$($_.Exception.Message)")
        Write-Host "    ERROR ($name): $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        # ALWAYS close what was opened -- also after a failed open (a half-open window is still a hole).
        if ($windowTried) {
            try {
                if ($private) { & $scr.window -SubscriptionId $sub -ResourceGroup $rg -SqlServerName $fqdn -Mode Close }
                else { & $scr.close -SubscriptionId $sub -ResourceGroup $rg -SqlServerName $fqdn }
                $rec.windowClosed = $true
            } catch {
                $errs.Add("build window NOT closed -- close it by hand: $($_.Exception.Message)")
                Write-Host "    ERROR ($name): the SQL build window could NOT be closed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    $rec.errors = @($errs.ToArray())
    $rec.ok = ($errs.Count -eq 0)
    $summary.Add([pscustomobject]$rec)
}

# --- summary -----------------------------------------------------------------------------------------------------------
Write-Host ''
Step 'Summary'
$table = New-Object System.Collections.Generic.List[object]
foreach ($s in $summary) {
    $table.Add([pscustomobject]@{
        Environment = $s.name
        Result      = $(if ($s.ok) { 'ok' } else { 'ERROR' })
        Prereqs     = (@(@($s.prereqs.Keys) | ForEach-Object { "$_=$($s.prereqs[$_])" }) -join ' ')
        Templates   = (@(@($s.packs.Keys) | ForEach-Object { "$_ $($s.packs[$_])" }) -join ', ')
        Held        = (@($s.held) -join ', ')
        Error       = (@($s.errors) -join ' | ')
    })
}
if ($table.Count) { Write-Host (($table | Format-Table -AutoSize -Wrap | Out-String -Width 220).TrimEnd()) }
$failed = @($summary | Where-Object { -not $_.ok })
if ($configErr) { Write-Host "CONFIG ERROR: $configErr" -ForegroundColor Red }
Write-Host ("{0} environment(s): {1} ok, {2} with errors{3}" -f $summary.Count, ($summary.Count - $failed.Count), $failed.Count, $(if ($failed.Count) { ' -- ' + (@($failed | ForEach-Object { $_.name }) -join ', ') })) -ForegroundColor $(if ($failed.Count -or $configErr) { 'Red' } else { 'Green' })
if ($PassThru) { $summary.ToArray() }
if ($failed.Count -or $configErr) { exit 1 }
exit 0
