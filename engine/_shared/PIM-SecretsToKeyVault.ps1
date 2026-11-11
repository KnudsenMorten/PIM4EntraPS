#Requires -Version 5.1
<#
.SYNOPSIS
  SEC-10 mover (framework 4 "secrets in Key Vault only", owner batch 2026-11-03; Invardia ruling 2026-11-11): moves the
  Container Apps secrets of ONE PIM install that are not Key Vault references -- and plain container env values that are
  secrets -- into the install's OWN Key Vault, and switches each app / job to a Key Vault reference (keyVaultUrl +
  its user-assigned identity id-pim-<role>).

.DESCRIPTION
  THE LIMITS (the approval; nothing in this file goes beyond them):
    * the right: 'Key Vault Secrets User' (4633458b-17de-408a-b874-0445c86b69e6) ONLY, ONLY on the install's own vault, at
      RESOURCE scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault> -- never the
      resource group, never the subscription (Assert-PimSkvVaultScope refuses anything else) -- and ONLY for the identity
      the app / job reads the reference with (its attached id-pim-<role>), and only for the roles of
      Get-PimSkvReaderRoles (the rights list is generated from that same function: engine\_shared\PIM-RightsList.ps1).
    * per install: a PLAN (names only), APPLY, READ-BACK (the app / job secret has its keyVaultUrl + identity, the vault
      secret holds the same value -- compared by SHA-256, never printed -- and the role assignment exists at the vault),
      and a ROLLBACK RECORD (the previous app / job secret definitions WITHOUT values; the values stay in the vault).
    * the old value is never dropped before the vault read-back passed; a switch whose read-back fails is put back (the
      previous definitions, values held in memory only) and the record says so.
    * no secret value is ever printed, logged or written: every error text is scrubbed (Protect-PimSkvText).
    * a JOB's secret change applies to its NEXT execution (a running one keeps its definition); the Manager APP gets a new
      revision. -WaitForIdleRuns waits (bounded) until a job has no running execution before it is switched
      (engine\_shared\PIM-SchemaQuiesce.ps1 Get-PimSchemaQuiesceState / Get-PimSchemaQuiesceDecision -- the updater's rule).

  PURE except the Invoke-/Read- functions, whose I/O goes through seams:
    -Arm { param($Method, $Path, $Body) }          ARM (Path carries its api-version)
    -Kv  { param($Method, $Url, $Body) }           Key Vault data plane (GET / PUT of https://<vault>/secrets/<name>...)
    -Sleep { param($Seconds) }
  ASCII; PowerShell 5.1 + 7; no modules.
#>
Set-StrictMode -Off

# the identity standard (Get-PimIdentityRoleOf / Get-PimIdentityRoleWords) and the updater's quiesce rule
if (-not (Get-Command Get-PimIdentityRoleOf -ErrorAction SilentlyContinue)) {
    $__pimSkvIdSplit = Join-Path $PSScriptRoot 'PIM-IdentitySplit.ps1'
    if (Test-Path -LiteralPath $__pimSkvIdSplit) { . $__pimSkvIdSplit }
}
if (-not (Get-Command Get-PimSchemaQuiesceDecision -ErrorAction SilentlyContinue)) {
    $__pimSkvQuiesce = Join-Path $PSScriptRoot 'PIM-SchemaQuiesce.ps1'
    if (Test-Path -LiteralPath $__pimSkvQuiesce) { . $__pimSkvQuiesce }
}

# ---------------------------------------------------------------------------------------------------- constants (literals)
function Get-PimSkvApi { <# PURE. LITERAL. The api-versions. #> return @{ aca = '2024-03-01'; kv = '2023-07-01'; auth = '2022-04-01'; kvData = '7.4' } }
function Get-PimSkvRoleId { <# PURE. LITERAL. Key Vault Secrets User (built-in role definition id). #> return '4633458b-17de-408a-b874-0445c86b69e6' }
function Get-PimSkvRoleName { <# PURE. LITERAL. #> return 'Key Vault Secrets User' }
function Get-PimSkvFeatureKey { <# PURE. LITERAL. The rights list's featureKey of the right this mover grants. #> return 'secrets-in-keyvault' }
function Get-PimSkvIdleWaitMinutes { <# PURE. LITERAL. The default bound of -WaitForIdleRuns per job. #> return 20 }
function Get-PimSkvOfficerRoleId { <# PURE. LITERAL. Key Vault Secrets Officer (built-in role definition id): the WRITER's right. #> return 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' }
function Get-PimSkvOfficerRoleName { <# PURE. LITERAL. #> return 'Key Vault Secrets Officer' }
function Get-PimSkvWriterRole {
    <#
      PURE. LITERAL. Invardia decision 2026-11-11: the install's own UPDATER writes the secrets and switches the definitions
      (inside its update run) -- it holds Key Vault Secrets Officer at the install's vault, granted ONCE by the Support app
      (Move-PimSecretsToKeyVault.ps1 -GrantOnly). The updater never grants a role itself (P9, SETUPSTEPS-TRUTH).
    #>
    return 'updater'
}
function Get-PimSkvUpdaterSwitchName { <# PURE. LITERAL. The updater job's setting that switches the step off ('0'). #> return 'PIM_UPDATE_SECRETS_TO_KV' }
function Test-PimSkvUpdaterEnabled {
    <# PURE. The updater step's switch: ON by default; '0' / 'false' / 'off' / 'no' switches it off. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    return -not ("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}
function Get-PimSkvAllowedRoleIds {
    <# PURE. LITERAL. The ONLY two roles this file ever assigns (and only through the Support-app / manual path). #>
    return @((Get-PimSkvRoleId), (Get-PimSkvOfficerRoleId))
}

function Get-PimSkvReaderRoles {
    <#
      PURE. LITERAL. THE identities (code role keys, engine\_shared\PIM-IdentitySplit.ps1) that read a secret this mover may
      move -- and so the ONLY ones it grants Key Vault Secrets User to. engine\_shared\PIM-RightsList.ps1 generates the rights
      list rows from this function, and engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds carries the same
      role for exactly these (tests\Test-PimSecretsToKeyVault.ps1 + tests\Test-PimRightsList.ps1 hold the three together).
      Code-read 2026-11-11, which workload carries a secret today:
        engine    AZURE_CLIENT_SECRET (Setup-PimContainers.ps1, engine client secret), PIM_UPLINK_KEY (the uplink job)
        web       AZURE_CLIENT_SECRET, PIM_UPLINK_KEY (support tickets), easyauth-client-secret (Set-PimManagerEasyAuth.ps1)
        updater   PIM_UPLINK_KEY (Invardia updates)
        asbuilt   PIM_UPLINK_KEY (the as-built push)              (identity id-pim-docs)
        downlink  pim-engine-client-secret (Deploy-PimDownlinkJob.ps1)
      Any other role holding a secret is REFUSED by the plan (a new reader is a rights decision, never silent).
    #>
    return @('engine', 'web', 'updater', 'asbuilt', 'downlink')
}

# ---------------------------------------------------------------------------------------------------------- small pure
function Get-PimSkvField {
    <# PURE. A field of a hashtable or an object ($null when absent). #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimSkvMapPairs {
    <# PURE. The key/value pairs of a hashtable or an object (ARM userAssignedIdentities). #>
    param([AllowNull()][object]$Map)
    if ($null -eq $Map) { return @() }
    if ($Map -is [System.Collections.IDictionary]) { return @($Map.Keys | ForEach-Object { @{ key = "$_"; value = $Map[$_] } }) }
    return @($Map.PSObject.Properties | ForEach-Object { @{ key = "$($_.Name)"; value = $_.Value } })
}

function ConvertTo-PimSkvHash {
    <# PURE. An object / hashtable as an ordered hashtable (one level; the values are kept as they are). #>
    param([AllowNull()][object]$Object)
    $h = [ordered]@{}
    if ($null -eq $Object) { return $h }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in @($Object.Keys)) { $h["$k"] = $Object[$k] } }
    else { foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    return $h
}

function Get-PimSkvIdentityName {
    <# PURE. The standard identity of a role: id-pim-<role>; the docs job (role key asbuilt) wears id-pim-docs. #>
    param([Parameter(Mandatory)][string]$Role)
    if ($Role -in @('asbuilt', 'docs')) { return 'id-pim-docs' }
    return "id-pim-$Role"
}

function Get-PimSkvRoleOfIdentityName {
    <# PURE. id-pim-<role> -> the role key ('' when not a standard name); id-pim-docs -> asbuilt. #>
    param([AllowEmptyString()][string]$Name)
    if ("$Name".Trim() -notmatch '^(?i)id-pim-([a-z0-9]+)$') { return '' }
    $w = $Matches[1].ToLowerInvariant()
    if ($w -eq 'docs') { return 'asbuilt' }
    $words = if (Get-Command Get-PimIdentityRoleWords -ErrorAction SilentlyContinue) { @(Get-PimIdentityRoleWords) } else { @('engine', 'web', 'updater', 'mcp', 'downlink', 'publish', 'requests', 'dbinit', 'asbuilt') }
    if ($words -contains $w) { return $w }
    return ''
}

function Test-PimSkvSecretEnvName {
    <#
      PURE. Does a container environment variable NAME say it carries a secret? The SAME rule as the setup step
      'keyvault-secrets-only' (PIM-SetupSteps.ps1 Test-PimSetupSecretEnvName): password, client secret, API / account /
      install / uplink / signing / private key, connection string, SAS. ..._URL / ..._NAME / ..._ID never match.
    #>
    param([AllowNull()][string]$Name)
    return [bool]("$Name".Trim() -match '(?i)(SECRET|PASSWORD|PASSWD|(^|_)PWD($|_)|API_?KEY|ACCOUNT_?KEY|CONNECTION_?STRING|(^|_)SAS($|_)|PRIVATE_?KEY|INSTALL_?KEY|UPLINK_?KEY|SIGNING_?KEY)')
}

function Test-PimSkvSecretText {
    <# PURE. Does a value LOOK like a secret? (the setup step's Test-PimSetupStepSecretText rule). #>
    param([AllowNull()][string]$Text)
    $t = "$Text"
    if (-not $t) { return $false }
    return [bool]($t -match '(?i)(\bsig=|\bsv=\d|SharedAccessSignature|AccountKey=|password\s*[=:]|pwd\s*=|client_secret|secret\s*[=:]|\bBearer\s+[A-Za-z0-9._-]{8,}|\beyJ[A-Za-z0-9_-]{10,}|-----BEGIN|\binv-[A-Za-z0-9_-]{20,})')
}

function Get-PimSkvVaultScope {
    <# PURE. The vault's RESOURCE scope (the one scope this mover ever grants at). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VaultName)
    return "/subscriptions/$("$SubscriptionId".Trim())/resourceGroups/$("$ResourceGroup".Trim())/providers/Microsoft.KeyVault/vaults/$("$VaultName".Trim())"
}

function Assert-PimSkvVaultScope {
    <#
      PURE. THROWS unless -Scope is EXACTLY the install's own vault at resource scope (case-insensitive, no trailing part):
      the resource group, the subscription, a management group, the tenant root, another vault, a secret / key under the
      vault -- all refused. Returns the scope when it passes.
    #>
    param([AllowEmptyString()][string]$Scope, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VaultName)
    $want = Get-PimSkvVaultScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $VaultName
    $s = "$Scope".Trim()
    if ($s -notmatch '^(?i)/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[^/]+$') {
        throw "REFUSED: '$s' is not a Key Vault resource scope -- Key Vault Secrets User is granted ONLY on the install's own vault ($want), never on a resource group, a subscription or wider"
    }
    if ($s -ine $want) { throw "REFUSED: '$s' is not the install's own vault ($want)" }
    return $s
}

function ConvertTo-PimSkvAcaSecretName {
    <# PURE. A Container Apps secret name from an env name: lower case, '_' -> '-', only [a-z0-9-.], no leading/trailing '-'. #>
    param([Parameter(Mandatory)][string]$Name)
    $n = ("$Name".Trim().ToLowerInvariant() -replace '_', '-' -replace '[^a-z0-9.-]', '-' -replace '-{2,}', '-').Trim('-', '.')
    if (-not $n) { $n = 'secret' }
    if ($n.Length -gt 253) { $n = $n.Substring(0, 253).Trim('-', '.') }
    return $n
}

function ConvertTo-PimSkvVaultSecretName {
    <# PURE. The vault secret name for one app / job secret: <resource>-<secret>, only [0-9A-Za-z-], at most 127. #>
    param([Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][string]$Secret)
    $n = ("$Resource-$Secret" -replace '[^0-9A-Za-z-]', '-' -replace '-{2,}', '-').Trim('-')
    if ($n.Length -gt 127) { $n = $n.Substring(0, 127).Trim('-') }
    return $n
}

function Get-PimSkvSha256 {
    <# PURE. The lower-case SHA-256 hex of a text's UTF-8 bytes (for COMPARING a value; never printed, never recorded). #>
    param([AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = ''
    try { $hex = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Text"))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    return $hex
}

function Protect-PimSkvText {
    <# PURE. A text with every one of -Values (the secret values this run holds) replaced by <withheld>; one line. #>
    param([AllowNull()][string]$Text, [AllowEmptyCollection()][string[]]$Values = @())
    $t = "$Text"
    foreach ($v in @($Values | Where-Object { "$_".Length -ge 4 } | Sort-Object { $_.Length } -Descending)) { $t = $t.Replace("$v", '<withheld>') }
    if (Test-PimSkvSecretText -Text $t) { $t = ($t -replace '(?i)(\bsig=|AccountKey=|password\s*[=:]|secret\s*[=:])\S+', '$1<withheld>' -replace '\beyJ[A-Za-z0-9_.-]{10,}', '<withheld>' -replace '\binv-[A-Za-z0-9_-]{20,}', '<withheld>') }
    return (($t -replace '[\r\n\t]+', ' ').Trim())
}

function ConvertTo-PimSkvExecutions {
    <# PURE. ARM executions (value[] or a list) -> @{ name; status; startUtc } (the shape Get-PimSchemaQuiesceState reads). #>
    param([AllowNull()][object]$Items)
    if ($null -eq $Items) { return $null }
    $list = @(if (Get-PimSkvField $Items 'value') { Get-PimSkvField $Items 'value' } elseif ($Items -is [System.Array]) { $Items } else { @() })
    return @(foreach ($x in @($list | Where-Object { $null -ne $_ })) {
        $p = Get-PimSkvField $x 'properties'
        $t = Get-PimSkvField $p 'startTime'
        $utc = $null
        if ($t -is [datetime]) { $utc = $t.ToUniversalTime() }
        elseif ("$t".Trim()) { try { $utc = [DateTimeOffset]::Parse("$t", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime } catch { $utc = $null } }
        [pscustomobject]@{ name = "$(Get-PimSkvField $x 'name')"; status = "$(Get-PimSkvField $p 'status')"; startUtc = $utc }
    })
}

# ------------------------------------------------------------------------------------------------------------ the plan
function Get-PimSkvResourceIdentity {
    <#
      PURE. The identity an app / job reads a Key Vault reference with: its attached user-assigned id-pim-<role>.
      Returns @{ role; name; id; principalId; reason } -- reason set when there is none to use. The role comes from the
      resource name (Get-PimIdentityRoleOf) or, for a customer-named resource, from the ONE attached standard identity.
    #>
    param([Parameter(Mandatory)][object]$Resource)
    $name = "$(Get-PimSkvField $Resource 'name')"
    $ua = @(Get-PimSkvMapPairs (Get-PimSkvField (Get-PimSkvField $Resource 'identity') 'userAssignedIdentities'))
    $std = @($ua | Where-Object { Get-PimSkvRoleOfIdentityName -Name (@("$($_.key)" -split '/')[-1]) })
    $role = if (Get-Command Get-PimIdentityRoleOf -ErrorAction SilentlyContinue) { "$(Get-PimIdentityRoleOf -Name $name)" } else { '' }
    if (-not $role -and $std.Count -eq 1) { $role = Get-PimSkvRoleOfIdentityName -Name (@("$($std[0].key)" -split '/')[-1]) }
    $out = @{ role = $role; name = ''; id = ''; principalId = ''; reason = '' }
    if (-not $role) { $out.reason = 'not a PIM app or job (no PIM name, no id-pim-<role> identity) -- never touched'; return $out }
    $want = Get-PimSkvIdentityName -Role $role
    $hit = @($ua | Where-Object { (@("$($_.key)" -split '/')[-1]) -ieq $want })
    if (-not $hit.Count) { $out.name = $want; $out.reason = "its own identity $want is not attached (it signs in as another identity) -- move the identities first (Move-PimIdentities.ps1), then run this again"; return $out }
    $out.name = $want; $out.id = "$($hit[0].key)"; $out.principalId = "$(Get-PimSkvField $hit[0].value 'principalId')".Trim()
    if (-not $out.principalId) { $out.reason = "the principal id of $want is not readable on this resource -- refusing to grant blind" }
    return $out
}

function Get-PimSkvResourcePlan {
    <#
      PURE. What moves on ONE app / job (names only -- this function never sees a value):
        secrets  configuration.secrets[] WITHOUT a keyVaultUrl         -> vault secret <resource>-<secret>, then keyVaultUrl
        envs     container env entries with a PLAIN value that is a secret (secret-named variable, or a secret-looking value)
                 -> a NEW app / job secret (keyVaultUrl) and the env entry becomes a secretRef to it
        kept     secrets that are already Key Vault references
      -Kind app|job, -VaultUri (https://<vault>.vault.azure.net/). -Only (resource names) limits the plan; a resource not in it
      is 'skipped'. State: move | nothing-to-do | refused | not-pim | skipped.
    #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)][ValidateSet('app', 'job')][string]$Kind, [Parameter(Mandatory)][string]$VaultUri,
          [AllowEmptyCollection()][string[]]$Only = @())
    $name = "$(Get-PimSkvField $Resource 'name')"
    $p = Get-PimSkvField $Resource 'properties'
    $cfg = Get-PimSkvField $p 'configuration'
    $vu = "$VaultUri".Trim().TrimEnd('/')
    $plan = [ordered]@{ name = $name; kind = $Kind; id = "$(Get-PimSkvField $Resource 'id')"; role = ''; identityName = ''; identityId = ''; principalId = ''
                        state = 'nothing-to-do'; reason = ''; secrets = @(); envs = @(); kept = @()
                        effect = $(if ($Kind -eq 'app') { 'the app gets a NEW REVISION (single revision mode: traffic moves to it once it is healthy)' } else { 'applies to the NEXT execution only -- a running execution keeps its old definition' }) }
    $secs = @(@(Get-PimSkvField $cfg 'secrets') | Where-Object { $null -ne $_ })
    $taken = @{}; foreach ($s in $secs) { $taken["$(Get-PimSkvField $s 'name')".ToLowerInvariant()] = $true }
    $secList = [System.Collections.Generic.List[object]]::new(); $envList = [System.Collections.Generic.List[object]]::new(); $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $secs) {
        $sn = "$(Get-PimSkvField $s 'name')"
        if ("$(Get-PimSkvField $s 'keyVaultUrl')".Trim()) { $kept.Add($sn); continue }
        $vs = ConvertTo-PimSkvVaultSecretName -Resource $name -Secret $sn
        $secList.Add([pscustomobject]@{ source = 'secret'; acaSecret = $sn; vaultSecret = $vs; vaultUrl = "$vu/secrets/$vs"; previous = 'value' })
    }
    $tpl = Get-PimSkvField $p 'template'
    foreach ($c in @(@(Get-PimSkvField $tpl 'containers') + @(Get-PimSkvField $tpl 'initContainers'))) {
        if ($null -eq $c) { continue }
        $cn = "$(Get-PimSkvField $c 'name')"
        foreach ($e in @(Get-PimSkvField $c 'env')) {
            if ($null -eq $e -or "$(Get-PimSkvField $e 'secretRef')".Trim()) { continue }
            $en = "$(Get-PimSkvField $e 'name')"; $ev = "$(Get-PimSkvField $e 'value')"
            if (-not $ev.Trim()) { continue }
            if (-not ((Test-PimSkvSecretEnvName -Name $en) -or (Test-PimSkvSecretText -Text $ev))) { continue }
            $base = ConvertTo-PimSkvAcaSecretName -Name $en; $an = $base; $i = 2
            while ($taken.ContainsKey($an)) { $an = "$base-kv$(if ($i -gt 2) { $i - 1 })"; $i++ }
            $taken[$an] = $true
            $vs = ConvertTo-PimSkvVaultSecretName -Resource $name -Secret $an
            $envList.Add([pscustomobject]@{ source = 'env'; container = $cn; env = $en; acaSecret = $an; vaultSecret = $vs; vaultUrl = "$vu/secrets/$vs"; previous = 'plain value' })
        }
    }
    $plan.secrets = @($secList.ToArray()); $plan.envs = @($envList.ToArray()); $plan.kept = @($kept.ToArray())
    $idn = Get-PimSkvResourceIdentity -Resource $Resource
    $plan.role = $idn.role; $plan.identityName = $idn.name; $plan.identityId = $idn.id; $plan.principalId = $idn.principalId
    if (@($Only).Count -and -not @($Only | Where-Object { "$_".Trim() -ieq $name }).Count) { $plan.state = 'skipped'; $plan.reason = 'not named in -Only'; return [pscustomobject]$plan }
    if (-not $idn.role) { $plan.state = 'not-pim'; $plan.reason = $idn.reason; return [pscustomobject]$plan }
    if (-not ($secList.Count + $envList.Count)) { $plan.state = 'nothing-to-do'; $plan.reason = 'every secret is a Key Vault reference; no plain secret in its settings'; return [pscustomobject]$plan }
    if (@(Get-PimSkvReaderRoles) -notcontains $idn.role) {
        $plan.state = 'refused'; $plan.reason = "role '$($idn.role)' is not an approved reader of Key Vault secrets (Get-PimSkvReaderRoles / the rights list) -- a new reader is a rights decision"; return [pscustomobject]$plan
    }
    if ($idn.reason) { $plan.state = 'refused'; $plan.reason = $idn.reason; return [pscustomobject]$plan }
    $plan.state = 'move'
    return [pscustomobject]$plan
}

function Get-PimSkvVaultChoice {
    <#
      PURE. The install's OWN vault: -VaultName when given (it must be one of the resource group's vaults), else the ONE vault
      of the resource group. @{ ok; name; id; uri; rbac; reason }. A vault outside the resource group is never used.
    #>
    param([AllowEmptyCollection()][object[]]$Vaults = @(), [AllowEmptyString()][string]$VaultName = '')
    $vs = @($Vaults | Where-Object { $null -ne $_ })
    $out = @{ ok = $false; name = ''; id = ''; uri = ''; rbac = $false; reason = '' }
    $pick = $null
    if ("$VaultName".Trim()) {
        $pick = @($vs | Where-Object { "$(Get-PimSkvField $_ 'name')" -ieq "$VaultName".Trim() })[0]
        if (-not $pick) { $out.reason = "key vault '$VaultName' is not in the install's resource group -- only the install's own vault is used"; return $out }
    } elseif ($vs.Count -eq 1) { $pick = $vs[0] }
    elseif (-not $vs.Count) { $out.reason = 'the install''s resource group has no key vault -- create the install''s vault first (New-PimTenantKeyVault.ps1)'; return $out }
    else { $out.reason = "the install's resource group has $($vs.Count) key vaults ($((@($vs | ForEach-Object { "$(Get-PimSkvField $_ 'name')" })) -join ', ')) -- name the install's own one with -VaultName"; return $out }
    $pp = Get-PimSkvField $pick 'properties'
    $out.name = "$(Get-PimSkvField $pick 'name')"; $out.id = "$(Get-PimSkvField $pick 'id')"
    $out.uri = "$(Get-PimSkvField $pp 'vaultUri')".Trim()
    if (-not $out.uri) { $out.uri = "https://$($out.name).vault.azure.net/" }
    $out.rbac = [bool](Get-PimSkvField $pp 'enableRbacAuthorization')
    if (-not $out.rbac) { $out.reason = "key vault '$($out.name)' uses access policies, not Azure RBAC -- this mover grants an Azure role only; switch the vault to Azure RBAC authorization first"; return $out }
    $out.ok = $true
    return $out
}

function Get-PimSkvPlan {
    <#
      PURE. The whole plan of one install from what was read (Read-PimSkvInstall):
        @{ subscriptionId; resourceGroup; vault; refusal; resources[]; grants[]; counts }
      grants: one per identity that reads a moved secret -- @{ identityName; identityId; principalId; scope (the vault, checked
      by Assert-PimSkvVaultScope); roleId; roleName; exists }. -Assignments are the vault's role assignments (atScope()).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][hashtable]$Install,
          [AllowEmptyString()][string]$VaultName = '', [AllowEmptyCollection()][object[]]$Assignments = @(), [AllowEmptyCollection()][string[]]$Only = @(),
          # -WithWriter: also plan the WRITER's (the updater's) Key Vault Secrets Officer at the vault (plan.writer); -WriterJob names
          # the updater job (default: the job whose role is updater and that wears id-pim-updater)
          [switch]$WithWriter, [AllowEmptyString()][string]$WriterJob = '')
    $v = Get-PimSkvVaultChoice -Vaults @($Install.vaults) -VaultName $VaultName
    $plan = [ordered]@{ subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroup; vault = $v; refusal = ''; resources = @(); grants = @(); writer = $null; counts = @{ secrets = 0; grants = 0; switches = 0; refused = 0 } }
    if (-not $v.ok) { $plan.refusal = $v.reason; return $plan }
    $scope = Assert-PimSkvVaultScope -Scope (Get-PimSkvVaultScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $v.name) -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $v.name
    if ("$($v.id)".Trim() -and "$($v.id)".Trim() -ine $scope) { $plan.refusal = "the vault's id '$($v.id)' is not $scope -- refusing"; return $plan }
    $res = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Install.apps | Where-Object { $null -ne $_ })) { $res.Add((Get-PimSkvResourcePlan -Resource $a -Kind app -VaultUri $v.uri -Only $Only)) }
    foreach ($j in @($Install.jobs | Where-Object { $null -ne $_ })) { $res.Add((Get-PimSkvResourcePlan -Resource $j -Kind job -VaultUri $v.uri -Only $Only)) }
    $plan.resources = @($res.ToArray())
    $rid = (Get-PimSkvRoleId).ToLowerInvariant()
    $grants = [ordered]@{}
    foreach ($r in @($plan.resources | Where-Object { $_.state -eq 'move' })) {
        $k = "$($r.principalId)".ToLowerInvariant()
        if ($grants.Contains($k)) { continue }
        $has = @($Assignments | Where-Object { $_ -and "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'principalId')" -ieq $r.principalId -and
                    "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'roleDefinitionId')".ToLowerInvariant().EndsWith("/$rid") -and
                    "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'scope')".TrimEnd('/') -ieq $scope })
        $grants[$k] = [pscustomobject]@{ identityName = $r.identityName; identityId = $r.identityId; principalId = $r.principalId; scope = $scope; roleId = $rid; roleName = (Get-PimSkvRoleName); exists = [bool]$has.Count }
    }
    $plan.grants = @($grants.Values)
    # the WRITER (the updater): its own Key Vault Secrets Officer at the vault -- planned only with -WithWriter
    $plan.writer = Get-PimSkvWriterGrant -Install $Install -Assignments $Assignments -Scope $scope -WriterJob $WriterJob
    if (-not $WithWriter) { $plan.writer = $null }
    $mv = @($plan.resources | Where-Object { $_.state -eq 'move' })
    $plan.counts = @{ secrets = (@($mv | ForEach-Object { @($_.secrets).Count + @($_.envs).Count }) | Measure-Object -Sum).Sum; grants = @(@($plan.grants) + @($plan.writer) | Where-Object { $_ -and -not $_.exists -and -not $_.reason }).Count
                      switches = $mv.Count; refused = @($plan.resources | Where-Object { $_.state -eq 'refused' }).Count }
    if ($null -eq $plan.counts.secrets) { $plan.counts.secrets = 0 }
    return $plan
}

function Test-PimSkvHeld {
    <# PURE. Does -PrincipalId hold -RoleId EXACTLY at -Scope (the vault; an assignment at a wider scope does not count)? #>
    param([AllowEmptyCollection()][object[]]$Assignments = @(), [AllowEmptyString()][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleId, [Parameter(Mandatory)][string]$Scope)
    if (-not "$PrincipalId".Trim()) { return $false }
    $r = "$RoleId".ToLowerInvariant()
    return [bool]@($Assignments | Where-Object { $_ -and "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'principalId')" -ieq "$PrincipalId" -and
                "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'roleDefinitionId')".ToLowerInvariant().EndsWith("/$r") -and
                "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'scope')".TrimEnd('/') -ieq $Scope }).Count
}

function Get-PimSkvWriterGrant {
    <#
      PURE. The WRITER's grant: Key Vault Secrets Officer at the vault for the updater job's own id-pim-updater.
      @{ identityName; identityId; principalId; job; scope; roleId; roleName; exists; reason } -- reason set when the updater job
      or its own identity is not there (nothing is granted then).
    #>
    param([Parameter(Mandatory)][hashtable]$Install, [AllowEmptyCollection()][object[]]$Assignments = @(), [Parameter(Mandatory)][string]$Scope, [AllowEmptyString()][string]$WriterJob = '')
    $role = Get-PimSkvWriterRole
    $jobs = @($Install.jobs | Where-Object { $null -ne $_ })
    $pick = $null
    if ("$WriterJob".Trim()) { $pick = @($jobs | Where-Object { "$(Get-PimSkvField $_ 'name')" -ieq "$WriterJob".Trim() })[0] }
    if (-not $pick) {
        # the updater job that wears its own id-pim-updater first; else any updater job (then the reason says why it cannot hold it)
        $cands = @($jobs | Where-Object { (Get-PimSkvResourceIdentity -Resource $_).role -eq $role })
        $pick = @(@($cands | Where-Object { -not (Get-PimSkvResourceIdentity -Resource $_).reason }) + @($cands))[0]
    }
    $g = [pscustomobject][ordered]@{ identityName = (Get-PimSkvIdentityName -Role $role); identityId = ''; principalId = ''; job = ''; scope = $Scope
                                     roleId = (Get-PimSkvOfficerRoleId); roleName = (Get-PimSkvOfficerRoleName); exists = $false; reason = '' }
    if (-not $pick) { $g.reason = 'no updater job in the install''s resource group'; return $g }
    $g.job = "$(Get-PimSkvField $pick 'name')"
    $idn = Get-PimSkvResourceIdentity -Resource $pick
    if ($idn.role -ne $role -or $idn.reason) { $g.reason = "the updater job $($g.job) does not run as its own $($g.identityName)$(if ($idn.reason) { " ($($idn.reason))" })"; return $g }
    $g.identityId = $idn.id; $g.principalId = $idn.principalId
    $g.exists = Test-PimSkvHeld -Assignments $Assignments -PrincipalId $idn.principalId -RoleId (Get-PimSkvOfficerRoleId) -Scope $Scope
    return $g
}

function Format-PimSkvPlanLines {
    <#
      PURE. The plan as lines a person reads (NAMES ONLY -- the plan holds no value). -WhatIfPrefix prefixes each change with
      'What if: would '. -WaitForIdleRuns / -IdleWaitMinutes change the job effect line.
    #>
    param([Parameter(Mandatory)]$Plan, [switch]$WhatIfPrefix, [switch]$WaitForIdleRuns, [int]$IdleWaitMinutes = (Get-PimSkvIdleWaitMinutes))
    $L = [System.Collections.Generic.List[string]]::new()
    $w = if ($WhatIfPrefix) { 'What if: would ' } else { '' }
    if ($Plan.refusal) { $L.Add("REFUSED: $($Plan.refusal)"); return @($L.ToArray()) }
    $v = $Plan.vault
    $L.Add("vault: $($v.name) ($(Get-PimSkvVaultScope -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup -VaultName $v.name)), Azure RBAC authorization: yes")
    foreach ($r in @($Plan.resources)) {
        if ($r.state -in @('not-pim', 'skipped')) { $L.Add("[$($r.kind)] $($r.name): $($r.state) -- $($r.reason)"); continue }
        $L.Add("[$($r.kind)] $($r.name) (role $($r.role)$(if ($r.identityName) { ", reads as $($r.identityName)" })): $($r.state)$(if ($r.reason) { ' -- ' + $r.reason })")
        if ($r.state -ne 'move' -and $r.state -ne 'refused') { continue }
        foreach ($s in @($r.secrets)) { $L.Add("    $(if ($r.state -eq 'move') { $w })MOVE secret $($s.acaSecret) (a value in the $($r.kind) definition) -> vault secret $($s.vaultSecret) -> keyVaultUrl $($s.vaultUrl) + identity $($r.identityName)") }
        foreach ($e in @($r.envs)) { $L.Add("    $(if ($r.state -eq 'move') { $w })MOVE env $($e.container)/$($e.env) (a plain value) -> vault secret $($e.vaultSecret) -> new $($r.kind) secret $($e.acaSecret) (keyVaultUrl + identity $($r.identityName)); the env entry becomes secretRef $($e.acaSecret)") }
        foreach ($k in @($r.kept)) { $L.Add("    kept: secret $k is already a Key Vault reference") }
        if ($r.state -eq 'move') {
            $eff = $r.effect
            if ($r.kind -eq 'job' -and $WaitForIdleRuns) { $eff += "; -WaitForIdleRuns: switched only when no execution of it runs (waits at most $IdleWaitMinutes min, then it is deferred -- nothing is stopped)" }
            $L.Add("    effect: $eff")
        }
    }
    foreach ($g in @($Plan.grants)) {
        if ($g.exists) { $L.Add("present: $($g.roleName) for $($g.identityName) ($($g.principalId)) at $($g.scope)") }
        else { $L.Add("$($w)GRANT $($g.roleName) ($($g.roleId)) to $($g.identityName) (principal $($g.principalId)) at $($g.scope) (resource scope: the vault only)") }
    }
    $wg = $Plan.writer
    if ($wg) {
        if ($wg.reason) { $L.Add("writer: NOT granted -- $($wg.reason)") }
        elseif ($wg.exists) { $L.Add("present: $($wg.roleName) for $($wg.identityName) (the updater, $($wg.principalId)) at $($wg.scope)") }
        else { $L.Add("$($w)GRANT $($wg.roleName) ($($wg.roleId)) to $($wg.identityName) (the updater job $($wg.job), principal $($wg.principalId)) at $($wg.scope) (resource scope: the vault only) -- it writes the secrets in its update run") }
    }
    $c = $Plan.counts
    $L.Add("summary: $($c.secrets) secret(s) to move, $($c.grants) role assignment(s) to add, $($c.switches) app / job definition(s) to switch, $($c.refused) refused")
    return @($L.ToArray())
}

# ------------------------------------------------------------------------------------------------------------- reads
function Invoke-PimSkvGet {
    <# A GET through a seam; an absent object (404 / NotFound, or $null) -> $null. Any other error throws. #>
    param([Parameter(Mandatory)][scriptblock]$Seam, [Parameter(Mandatory)][string]$Path)
    # no 'return' inside try / catch (Windows PowerShell 5.1's compiled form fails such a body: "Argument types do not match")
    $res = $null; $err = $null
    try { $res = & $Seam 'GET' $Path $null } catch { $err = $_ }
    if ($err) { if ("$($err.Exception.Message)" -match '(?i)\b404\b|NotFound|does not exist|SecretNotFound') { $res = $null } else { throw $err } }
    return $res
}

function Get-PimSkvList {
    <# A list GET through a seam: .value unwrapped, nextLink followed. Absent -> empty. #>
    param([Parameter(Mandatory)][scriptblock]$Seam, [Parameter(Mandatory)][string]$Path)
    $out = [System.Collections.Generic.List[object]]::new(); $next = $Path; $guard = 0
    while ($next -and $guard -lt 50) {
        $guard++
        $r = Invoke-PimSkvGet -Seam $Seam -Path $next; $next = $null
        if ($null -eq $r) { break }
        $vv = Get-PimSkvField $r 'value'
        if ($null -ne $vv -or ($r -isnot [System.Array] -and (Get-PimSkvField $r 'nextLink'))) { foreach ($x in @($vv)) { if ($null -ne $x) { $out.Add($x) } } }
        elseif ($r -is [System.Array]) { foreach ($x in $r) { if ($null -ne $x) { $out.Add($x) } } }
        $nl = Get-PimSkvField $r 'nextLink'; if ($nl) { $next = "$nl" }
    }
    return @($out.ToArray())
}

function Read-PimSkvInstall {
    <# READ (ARM GET only). The install's container apps, jobs and key vaults (its resource group). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $api = Get-PimSkvApi; $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    return @{
        apps   = @(Get-PimSkvList -Seam $Arm -Path "$rg/providers/Microsoft.App/containerApps?api-version=$($api.aca)")
        jobs   = @(Get-PimSkvList -Seam $Arm -Path "$rg/providers/Microsoft.App/jobs?api-version=$($api.aca)")
        vaults = @(Get-PimSkvList -Seam $Arm -Path "$rg/providers/Microsoft.KeyVault/vaults?api-version=$($api.kv)")
    }
}

function Read-PimSkvVaultAssignments {
    <# READ. The role assignments AT the vault (atScope(): the vault's own and the inherited ones; the plan counts only the vault's own). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Scope)
    return @(Get-PimSkvList -Seam $Arm -Path "$Scope/providers/Microsoft.Authorization/roleAssignments?api-version=$((Get-PimSkvApi).auth)&`$filter=atScope()")
}

function Test-PimSkvVaultReadable {
    <#
      READ. Can the signed-in identity reach the vault's DATA plane? One list of a secret's versions (no value is returned by
      that call). @{ ok; reason }. A 403 names the role the apply needs.
    #>
    param([Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)][string]$VaultUri, [string]$Probe = 'pim-skv-probe')
    $m = ''
    try { [void](& $Kv 'GET' ("$("$VaultUri".TrimEnd('/'))/secrets/$Probe/versions?maxresults=1&api-version=$((Get-PimSkvApi).kvData)") $null) } catch { $m = "$($_.Exception.Message)" }
    if (-not $m -or $m -match '(?i)\b404\b|NotFound|SecretNotFound') { return @{ ok = $true; reason = '' } }
    if ($m -match '(?i)\b403\b|Forbidden') { return @{ ok = $false; reason = 'the identity may not use the vault''s secrets (403) -- writing them needs Key Vault Secrets Officer on the vault' } }
    return @{ ok = $false; reason = "the vault's data plane did not answer ($(Protect-PimSkvText -Text $m))" }
}

# -------------------------------------------------------------------------------------------------------------- apply
function Get-PimSkvSecretValues {
    <# READ (POST listSecrets: a read action). name -> @{ value; keyVaultUrl; identity }. The values stay in memory only. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceId, [int]$Declared = 0)
    $ls = & $Arm 'POST' "$ResourceId/listSecrets?api-version=$((Get-PimSkvApi).aca)" @{}
    $map = [ordered]@{}
    foreach ($s in @(Get-PimSkvField $ls 'value')) { if ($s) { $map["$(Get-PimSkvField $s 'name')"] = @{ value = "$(Get-PimSkvField $s 'value')"; keyVaultUrl = "$(Get-PimSkvField $s 'keyVaultUrl')"; identity = "$(Get-PimSkvField $s 'identity')" } } }
    if ($map.Count -lt $Declared) { throw "listSecrets returned $($map.Count) secret(s) but $(@($ResourceId -split '/')[-1]) declares $Declared -- refusing to write a configuration that would drop secrets" }
    return $map
}

function Invoke-PimSkvVaultPut {
    <#
      The vault secret for one moved value: the current value read (GET) and compared by SHA-256 -- the same value is reused
      (no new version), otherwise PUT; then READ BACK and compared by SHA-256. Returns @{ vaultSecret; action = reused|written;
      id }. THROWS (scrubbed) on any failure. The value is never returned.
    #>
    param([Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)][string]$VaultUri, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value, [string]$Resource = '')
    $u = "$("$VaultUri".TrimEnd('/'))/secrets/$Name`?api-version=$((Get-PimSkvApi).kvData)"
    $want = Get-PimSkvSha256 -Text $Value
    $action = 'written'
    try {
        $cur = Invoke-PimSkvGet -Seam $Kv -Path $u
        if ($cur -and (Get-PimSkvSha256 -Text "$(Get-PimSkvField $cur 'value')") -eq $want) { $action = 'reused' }
        else { [void](& $Kv 'PUT' $u @{ value = $Value; contentType = 'PIM Manager secret (moved from the Container Apps definition)'; tags = @{ 'pim-moved-from' = "$Resource"; purpose = 'PIM Manager' } }) }
        $back = & $Kv 'GET' $u $null
    } catch { throw "vault secret $Name`: $(Protect-PimSkvText -Text "$($_.Exception.Message)" -Values @($Value))" }
    $ok = (Get-PimSkvSha256 -Text "$(Get-PimSkvField $back 'value')") -eq $want
    $id = "$(Get-PimSkvField $back 'id')"
    $back = $null
    if (-not $ok) { throw "read-back of vault secret $Name`: it does not hold the value of $Resource (compared by SHA-256) -- nothing was switched" }
    return @{ vaultSecret = $Name; action = $action; id = $id }
}

function Invoke-PimSkvGrant {
    <#
      Key Vault Secrets User for ONE identity at the vault (resource scope; Assert-PimSkvVaultScope first). Idempotent:
      present -> left alone. A deterministic assignment name. READ BACK (atScope list) until it shows. @{ action; id }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Grant, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$VaultName, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 6, [int]$WaitSeconds = 10)
    $scope = Assert-PimSkvVaultScope -Scope "$($Grant.scope)" -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $VaultName
    # the grant's role: Key Vault Secrets User (a reader) or Key Vault Secrets Officer (the writer) -- NOTHING else
    $rid = "$(if ("$($Grant.roleId)".Trim()) { "$($Grant.roleId)".Trim() } else { Get-PimSkvRoleId })".ToLowerInvariant()
    if (@(Get-PimSkvAllowedRoleIds) -notcontains $rid) { throw "REFUSED: role $rid is not Key Vault Secrets User or Key Vault Secrets Officer -- this file assigns no other role" }
    $find = { @(Read-PimSkvVaultAssignments -Arm $Arm -Scope $scope | Where-Object { $_ -and "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'principalId')" -ieq "$($Grant.principalId)" -and
                "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'roleDefinitionId')".ToLowerInvariant().EndsWith("/$rid") -and "$(Get-PimSkvField (Get-PimSkvField $_ 'properties') 'scope')".TrimEnd('/') -ieq $scope }) }
    $have = @(& $find)
    if ($have.Count) { return @{ action = 'present'; id = "$(Get-PimSkvField $have[0] 'id')" } }
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $b = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$scope|$($Grant.principalId)|$rid".ToLowerInvariant())) } finally { $md5.Dispose() }
    $b[6] = ($b[6] -band 0x0f) -bor 0x30; $b[8] = ($b[8] -band 0x3f) -bor 0x80
    $h = -join @($b | ForEach-Object { $_.ToString('x2') })
    $an = $h.Substring(0, 8) + '-' + $h.Substring(8, 4) + '-' + $h.Substring(12, 4) + '-' + $h.Substring(16, 4) + '-' + $h.Substring(20, 12)
    $path = "$scope/providers/Microsoft.Authorization/roleAssignments/$an`?api-version=$((Get-PimSkvApi).auth)"
    try { [void](& $Arm 'PUT' $path @{ properties = @{ roleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$rid"; principalId = "$($Grant.principalId)"; principalType = 'ServicePrincipal' } }) }
    catch { if ("$($_.Exception.Message)" -notmatch '(?i)RoleAssignmentExists|\b409\b') { throw } }
    for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
        if ($i -gt 1) { & $Sleep $WaitSeconds }
        $have = @(& $find)
        if ($have.Count) { return @{ action = 'granted'; id = "$scope/providers/Microsoft.Authorization/roleAssignments/$an" } }
    }
    throw "read-back: $(if ($rid -eq (Get-PimSkvOfficerRoleId)) { Get-PimSkvOfficerRoleName } else { Get-PimSkvRoleName }) for $($Grant.identityName) at $scope is not visible after $Tries read(s) -- nothing was switched"
}

function Wait-PimSkvJobIdle {
    <#
      -WaitForIdleRuns: until the job has no running execution (Get-PimSchemaQuiesceState + Get-PimSchemaQuiesceDecision, the
      updater's rule; executions NOT readable count as running). @{ action = go|defer; line }. Never stops an execution.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][string]$JobName,
          [int]$MaxWaitSeconds = ((Get-PimSkvIdleWaitMinutes) * 60), [int]$PollSeconds = 30, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $waited = 0
    while ($true) {
        $ex = $null; $err = ''
        try { $ex = ConvertTo-PimSkvExecutions (& $Arm 'GET' "$JobId/executions?api-version=$((Get-PimSkvApi).aca)" $null); if ($null -eq $ex) { $ex = @() } } catch { $ex = $null; $err = "$($_.Exception.Message)" }
        $st = Get-PimSchemaQuiesceState -Reads @(@{ job = $JobName; absent = $false; executions = $ex; error = $err })
        $d = Get-PimSchemaQuiesceDecision -State $st -WaitedSeconds $waited -MaxWaitSeconds $MaxWaitSeconds
        if ($d.action -eq 'go') { return @{ action = 'go'; line = "$JobName has no running execution$(if ($waited) { " (after $([math]::Round($waited / 60.0, 1)) min)" })" } }
        if ($d.action -eq 'defer') { return @{ action = 'defer'; line = "$JobName still busy after $([math]::Round($waited / 60.0, 1)) min ($($d.reason)) -- not switched this run (nothing was stopped); run again later" } }
        & $Sleep $PollSeconds; $waited += $PollSeconds
    }
}

function New-PimSkvSwitchBody {
    <#
      PURE (the values come in -Values, from listSecrets, and go out only in the ARM body). The PATCH body that switches one
      app / job: configuration.secrets = every secret (moved -> keyVaultUrl + identity; a Key Vault reference kept; a value kept
      WITH its value -- a configuration written without them would delete them) + the new env secrets; template only when an
      env entry changes (-> secretRef).
    #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)]$ResourcePlan, [Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    $p = Get-PimSkvField $Resource 'properties'
    $cfgH = ConvertTo-PimSkvHash (Get-PimSkvField $p 'configuration')
    $moved = @{}; foreach ($s in @($ResourcePlan.secrets)) { $moved["$($s.acaSecret)".ToLowerInvariant()] = $s }
    $secs = [System.Collections.Generic.List[object]]::new()
    foreach ($k in @($Values.Keys)) {
        $v = $Values[$k]
        if ($moved.ContainsKey("$k".ToLowerInvariant())) { $secs.Add([pscustomobject][ordered]@{ name = "$k"; keyVaultUrl = "$($moved["$k".ToLowerInvariant()].vaultUrl)"; identity = "$($ResourcePlan.identityId)" }); continue }
        if ("$($v.keyVaultUrl)".Trim()) { $secs.Add([pscustomobject][ordered]@{ name = "$k"; keyVaultUrl = "$($v.keyVaultUrl)"; identity = "$($v.identity)" }); continue }
        $secs.Add([pscustomobject][ordered]@{ name = "$k"; value = "$($v.value)" })
    }
    foreach ($e in @($ResourcePlan.envs)) { $secs.Add([pscustomobject][ordered]@{ name = "$($e.acaSecret)"; keyVaultUrl = "$($e.vaultUrl)"; identity = "$($ResourcePlan.identityId)" }) }
    $cfgH['secrets'] = @($secs.ToArray())
    $props = [ordered]@{ configuration = [pscustomobject]$cfgH }
    if (@($ResourcePlan.envs).Count) { $props['template'] = (New-PimSkvTemplate -Template (Get-PimSkvField $p 'template') -ResourcePlan $ResourcePlan) }
    return @{ properties = $props }
}

function New-PimSkvTemplate {
    <# PURE. The template with each moved env entry turned into a secretRef (every other entry and field as it was). #>
    param([AllowNull()][object]$Template, [Parameter(Mandatory)]$ResourcePlan)
    $tH = ConvertTo-PimSkvHash $Template
    $map = @{}; foreach ($e in @($ResourcePlan.envs)) { $map["$($e.container)|$($e.env)"] = $e.acaSecret }
    foreach ($key in @('containers', 'initContainers')) {
        if (-not $tH.Contains($key) -or $null -eq $tH[$key]) { continue }
        $tH[$key] = @(foreach ($c in @($tH[$key])) {
            if ($null -eq $c) { continue }
            $cH = ConvertTo-PimSkvHash $c; $cn = "$($cH['name'])"
            if ($cH.Contains('env')) {
                $cH['env'] = @(foreach ($e in @($cH['env'])) {
                    if ($null -eq $e) { continue }
                    $en = "$(Get-PimSkvField $e 'name')"
                    if ($map.ContainsKey("$cn|$en")) { [pscustomobject][ordered]@{ name = $en; secretRef = "$($map["$cn|$en"])" } } else { $e }
                })
            }
            [pscustomobject]$cH
        })
    }
    return [pscustomobject]$tH
}

function New-PimSkvRestoreBody {
    <# PURE. The body that puts the PREVIOUS definitions back (the values held in memory from listSecrets) -- the automatic undo. #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)][System.Collections.IDictionary]$Values, [switch]$WithTemplate)
    $p = Get-PimSkvField $Resource 'properties'
    $cfgH = ConvertTo-PimSkvHash (Get-PimSkvField $p 'configuration')
    $cfgH['secrets'] = @(foreach ($k in @($Values.Keys)) { $v = $Values[$k]; if ("$($v.keyVaultUrl)".Trim()) { [pscustomobject][ordered]@{ name = "$k"; keyVaultUrl = "$($v.keyVaultUrl)"; identity = "$($v.identity)" } } else { [pscustomobject][ordered]@{ name = "$k"; value = "$($v.value)" } } })
    $props = [ordered]@{ configuration = [pscustomobject]$cfgH }
    if ($WithTemplate) { $props['template'] = Get-PimSkvField $p 'template' }
    return @{ properties = $props }
}

function Test-PimSkvSwitched {
    <# PURE. Read-back of one switched app / job: every moved secret is a keyVaultUrl + the identity, every moved env a secretRef. @() = good. #>
    param([AllowNull()][object]$After, [Parameter(Mandatory)]$ResourcePlan)
    $bad = [System.Collections.Generic.List[string]]::new()
    $p = Get-PimSkvField $After 'properties'
    $secs = @{}; foreach ($s in @(Get-PimSkvField (Get-PimSkvField $p 'configuration') 'secrets')) { if ($s) { $secs["$(Get-PimSkvField $s 'name')".ToLowerInvariant()] = $s } }
    foreach ($m in @(@($ResourcePlan.secrets) + @($ResourcePlan.envs))) {
        $s = $secs["$($m.acaSecret)".ToLowerInvariant()]
        if (-not $s) { $bad.Add("secret $($m.acaSecret) is missing"); continue }
        if ("$(Get-PimSkvField $s 'keyVaultUrl')".TrimEnd('/') -ine "$($m.vaultUrl)".TrimEnd('/')) { $bad.Add("secret $($m.acaSecret) is not the Key Vault reference $($m.vaultUrl)") }
        if ("$(Get-PimSkvField $s 'identity')" -ine "$($ResourcePlan.identityId)") { $bad.Add("secret $($m.acaSecret) does not read as $($ResourcePlan.identityName)") }
    }
    $tpl = Get-PimSkvField $p 'template'
    foreach ($e in @($ResourcePlan.envs)) {
        $c = @(@(@(Get-PimSkvField $tpl 'containers') + @(Get-PimSkvField $tpl 'initContainers')) | Where-Object { $_ -and "$(Get-PimSkvField $_ 'name')" -eq $e.container })[0]
        $en = @(@(Get-PimSkvField $c 'env') | Where-Object { $_ -and "$(Get-PimSkvField $_ 'name')" -eq $e.env })[0]
        if (-not $en -or "$(Get-PimSkvField $en 'secretRef')" -ne $e.acaSecret -or "$(Get-PimSkvField $en 'value')".Trim()) { $bad.Add("env $($e.container)/$($e.env) is not secretRef $($e.acaSecret)") }
    }
    return @($bad.ToArray())
}

function New-PimSkvRollbackEntry {
    <#
      PURE. The rollback record of one app / job -- the PREVIOUS definitions WITHOUT values (the values are in the vault now):
      each previous secret (name; value | Key Vault reference), each previous env entry (plain value | secretRef) and how to
      switch back. Nothing in it is a secret value.
    #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)]$ResourcePlan)
    $p = Get-PimSkvField $Resource 'properties'
    $prevSecrets = @(foreach ($s in @(Get-PimSkvField (Get-PimSkvField $p 'configuration') 'secrets')) {
        if (-not $s) { continue }
        $kvu = "$(Get-PimSkvField $s 'keyVaultUrl')".Trim()
        if ($kvu) { [ordered]@{ name = "$(Get-PimSkvField $s 'name')"; kind = 'keyvault'; keyVaultUrl = $kvu; identity = "$(Get-PimSkvField $s 'identity')" } }
        else { [ordered]@{ name = "$(Get-PimSkvField $s 'name')"; kind = 'value'; valueNow = "in the vault: $(@($ResourcePlan.secrets | Where-Object { $_.acaSecret -eq "$(Get-PimSkvField $s 'name')" } | ForEach-Object { $_.vaultUrl })[0])" } }
    })
    $prevEnv = @(foreach ($e in @($ResourcePlan.envs)) { [ordered]@{ container = $e.container; name = $e.env; kind = 'plain value'; valueNow = "in the vault: $($e.vaultUrl)"; secretAdded = $e.acaSecret } })
    $how = @(
        "1. read each value from its vault secret (Azure portal > key vault > Secrets, or GET <vaultUrl>?api-version=7.4 with Key Vault Secrets User / Officer) -- the values were moved, never deleted",
        "2. ARM PATCH $($ResourcePlan.id)?api-version=$((Get-PimSkvApi).aca) with properties.configuration.secrets = every secret: the ones listed under previousSecrets as kind 'value' back to { name; value }, every other as it is now (listSecrets gives the current ones)",
        $(if (@($ResourcePlan.envs).Count) { "3. in the same PATCH, properties.template: each env entry under previousEnv back to { name; value } (a plain value) and the added secret(s) left out" } else { '' }),
        "4. the vault secrets and the Key Vault Secrets User assignment(s) may stay (harmless); remove an assignment with ARM DELETE <assignment id>?api-version=$((Get-PimSkvApi).auth)"
    ) | Where-Object { $_ }
    return [ordered]@{ resource = $ResourcePlan.name; kind = $ResourcePlan.kind; id = $ResourcePlan.id; identity = $ResourcePlan.identityName; previousSecrets = $prevSecrets; previousEnv = $prevEnv; howToSwitchBack = @($how) }
}

function Invoke-PimSkvResourceApply {
    <#
      APPLY one app / job, in this order, each step read back before the next:
        1. listSecrets (values in memory only)  2. each value -> its vault secret (PUT unless the same value is there), READ
        BACK by SHA-256  3. (the grant was made and read back by the caller)  4. -WaitForIdleRuns for a job  5. ONE PATCH of the
        configuration (+ template)  6. READ BACK (keyVaultUrl + identity, secretRef) until no longer in progress; the vault
        secrets read back by SHA-256 once more  7. a failed read-back PUTS THE PREVIOUS DEFINITIONS BACK (from memory) and
        says so. -DryRun: only what would happen. Returns the record entry; never a value.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)]$ResourcePlan, [Parameter(Mandatory)][string]$VaultUri,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [switch]$DryRun, [switch]$WaitForIdleRuns, [int]$IdleWaitMinutes = (Get-PimSkvIdleWaitMinutes),
          [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10, [int]$SwitchTries = 4, [int]$SwitchWaitSeconds = 60)
    $api = Get-PimSkvApi
    $rp = $ResourcePlan
    $rec = [ordered]@{ resource = $rp.name; kind = $rp.kind; state = 'started'; steps = ([System.Collections.Generic.List[object]]::new()); rollback = $null; error = '' }
    $step = { param($s, $what, $rb = '') $rec.steps.Add([ordered]@{ step = $s; what = $what; readBack = $rb }) }
    $path = "$($rp.id)?api-version=$($api.aca)"
    $before = Invoke-PimSkvGet -Seam $Arm -Path $path
    if (-not $before) { $rec.state = 'failed'; $rec.error = "$($rp.name) was not found"; return $rec }
    $rec.rollback = New-PimSkvRollbackEntry -Resource $before -ResourcePlan $rp
    if ($DryRun) {
        foreach ($s in @($rp.secrets)) { & $step 'vault' "would write vault secret $($s.vaultSecret) from secret $($s.acaSecret) and read it back (SHA-256)" }
        foreach ($e in @($rp.envs)) { & $step 'vault' "would write vault secret $($e.vaultSecret) from env $($e.container)/$($e.env) and read it back (SHA-256)" }
        if ($rp.kind -eq 'job' -and $WaitForIdleRuns) { & $step 'wait' "would wait (at most $IdleWaitMinutes min) until $($rp.name) has no running execution" }
        & $step 'switch' "would switch $($rp.name): $(@($rp.secrets).Count + @($rp.envs).Count) secret(s) to keyVaultUrl + $($rp.identityName) ($($rp.effect))"
        $rec.state = 'dry-run'; return $rec
    }
    $vals = $null; $held = @()
    try {
        $declared = @(@(Get-PimSkvField (Get-PimSkvField (Get-PimSkvField $before 'properties') 'configuration') 'secrets') | Where-Object { $_ }).Count
        $vals = Get-PimSkvSecretValues -Arm $Arm -ResourceId $rp.id -Declared $declared
        $held = @(@($vals.Values | ForEach-Object { "$($_.value)" }) + @(foreach ($e in @($rp.envs)) { Get-PimSkvEnvValue -Resource $before -Container $e.container -Env $e.env }))
        # 2. the vault secrets
        $toVault = @(foreach ($s in @($rp.secrets)) { @{ name = $s.vaultSecret; value = "$($vals[$s.acaSecret].value)"; from = "secret $($s.acaSecret)" } }) +
                   @(foreach ($e in @($rp.envs)) { @{ name = $e.vaultSecret; value = (Get-PimSkvEnvValue -Resource $before -Container $e.container -Env $e.env); from = "env $($e.container)/$($e.env)" } })
        foreach ($t in $toVault) {
            if (-not "$($t.value)".Length) { throw "$($t.from) of $($rp.name) has no value to move (listSecrets / the definition returned none) -- nothing was switched" }
            $vr = Invoke-PimSkvVaultPut -Kv $Kv -VaultUri $VaultUri -Name $t.name -Value "$($t.value)" -Resource $rp.name
            & $step 'vault' "vault secret $($t.name) $($vr.action) from $($t.from)" 'same value (SHA-256)'
        }
        # 4. a job: between its runs
        if ($rp.kind -eq 'job' -and $WaitForIdleRuns) {
            $wi = Wait-PimSkvJobIdle -Arm $Arm -JobId $rp.id -JobName $rp.name -MaxWaitSeconds ($IdleWaitMinutes * 60) -Sleep $Sleep
            & $step 'wait' $wi.line
            if ($wi.action -ne 'go') { throw 'SKV-DEFERRED' }   # (no 'return' inside try: Windows PowerShell 5.1)
        }
        # 5. ONE switch (a grant that has not reached Container Apps yet fails it: tried again, the definition is unchanged then)
        $body = New-PimSkvSwitchBody -Resource $before -ResourcePlan $rp -Values $vals
        $done = $false; $lastErr = ''
        for ($i = 1; $i -le [Math]::Max(1, $SwitchTries) -and -not $done; $i++) {
            if ($i -gt 1) { & $Sleep $SwitchWaitSeconds }
            try { [void](& $Arm 'PATCH' $path $body); $done = $true }
            catch { $lastErr = Protect-PimSkvText -Text "$($_.Exception.Message)" -Values $held; if ($lastErr -notmatch '(?i)vault|secret|forbidden|403|access|identity') { break } }
        }
        $body = $null
        if (-not $done) { throw "switch of $($rp.name) refused: $lastErr -- the definition is unchanged" }
        # 6. READ BACK
        $bad = @(); $ps = ''
        for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) {
            if ($i -gt 1) { & $Sleep $ReadBackWaitSeconds }
            $after = Invoke-PimSkvGet -Seam $Arm -Path $path
            $ps = "$(Get-PimSkvField (Get-PimSkvField $after 'properties') 'provisioningState')"
            $bad = @(Test-PimSkvSwitched -After $after -ResourcePlan $rp)
            if ($ps -match '^(?i)Failed$') { $bad += "its update ended in provisioning state Failed" }
            if (-not $bad.Count -and $ps -notmatch '^(?i)(InProgress|Updating|Pending|Accepted|Provisioning|Creating)$') { break }
        }
        if (-not $bad.Count -and $ps -match '^(?i)(InProgress|Updating|Pending|Accepted|Provisioning|Creating)$') { $bad += "still '$ps' after $ReadBackTries read(s) -- not confirmed" }
        if (-not $bad.Count) {
            foreach ($t in $toVault) {
                $b2 = & $Kv 'GET' ("$("$VaultUri".TrimEnd('/'))/secrets/$($t.name)?api-version=$($api.kvData)") $null
                if ((Get-PimSkvSha256 -Text "$(Get-PimSkvField $b2 'value')") -ne (Get-PimSkvSha256 -Text "$($t.value)")) { $bad += "vault secret $($t.name) no longer holds the moved value" }
                $b2 = $null
            }
        }
        if ($bad.Count) {
            # 7. the previous definitions back, from memory
            $undo = 'put back'
            try { [void](& $Arm 'PATCH' $path (New-PimSkvRestoreBody -Resource $before -Values $vals -WithTemplate:([bool]@($rp.envs).Count))) } catch { $undo = "NOT put back ($(Protect-PimSkvText -Text "$($_.Exception.Message)" -Values $held)) -- use the rollback record" }
            throw "read-back of $($rp.name): $($bad -join '; ') -- the previous definitions were $undo"
        }
        & $step 'switch' "switched $($rp.name): $(@($rp.secrets).Count + @($rp.envs).Count) secret(s) now keyVaultUrl + $($rp.identityName) ($($rp.effect))" 'keyVaultUrl + identity on the resource; vault values match (SHA-256)'
        $rec.state = 'done'
    } catch {
        if ("$($_.Exception.Message)" -eq 'SKV-DEFERRED') { $rec.state = 'deferred' }
        else { $rec.state = 'failed'; $rec.error = Protect-PimSkvText -Text "$($_.Exception.Message)" -Values $held }
    } finally { $vals = $null; $held = $null }
    return $rec
}

function Get-PimSkvEnvValue {
    <# PURE. The plain value of one env entry (from the resource as read). #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Env)
    $tpl = Get-PimSkvField (Get-PimSkvField $Resource 'properties') 'template'
    $c = @(@(@(Get-PimSkvField $tpl 'containers') + @(Get-PimSkvField $tpl 'initContainers')) | Where-Object { $_ -and "$(Get-PimSkvField $_ 'name')" -eq $Container })[0]
    $e = @(@(Get-PimSkvField $c 'env') | Where-Object { $_ -and "$(Get-PimSkvField $_ 'name')" -eq $Env })[0]
    return "$(Get-PimSkvField $e 'value')"
}

function Invoke-PimSkvApply {
    <#
      APPLY the plan: the grants first (each read back at the vault), then every app / job (Invoke-PimSkvResourceApply).
      A failed grant stops before ANY switch. A failed app / job stops the run (the next is not touched). Returns
      @{ state; grants[]; resources[]; rollback[] } -- the rollback record holds no value.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)]$Plan, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [switch]$DryRun, [switch]$WaitForIdleRuns, [int]$IdleWaitMinutes = (Get-PimSkvIdleWaitMinutes), [int]$RbacWaitSeconds = 60,
          [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10, [int]$SwitchTries = 4, [int]$SwitchWaitSeconds = 60,
          # -GrantOnly: THE SUPPORT-APP GRANT STEP (Invardia 2026-11-11) -- the readers' Key Vault Secrets User and (plan.writer)
          # the updater's Key Vault Secrets Officer at the vault, read back; no secret is read, written or switched
          [switch]$GrantOnly)
    $out = [ordered]@{ state = 'done'; generatedUtc = [datetime]::UtcNow.ToString('o'); subscriptionId = $Plan.subscriptionId; resourceGroup = $Plan.resourceGroup
                       vault = "$($Plan.vault.name)"; grants = ([System.Collections.Generic.List[object]]::new()); resources = ([System.Collections.Generic.List[object]]::new())
                       rollback = ([System.Collections.Generic.List[object]]::new()); error = '' }
    if ($Plan.refusal) { $out.state = 'refused'; $out.error = $Plan.refusal; return $out }
    $mv = @($Plan.resources | Where-Object { $_.state -eq 'move' })
    $all = @(@($Plan.grants) + @(if ($GrantOnly -and $Plan.writer -and -not $Plan.writer.reason) { $Plan.writer }) | Where-Object { $_ })
    if (-not $mv.Count -and -not ($GrantOnly -and $all.Count)) { $out.state = 'nothing-to-do'; return $out }
    $newGrant = $false; $gErr = ''
    foreach ($g in $all) {
        if ($DryRun) { $out.grants.Add([ordered]@{ identity = $g.identityName; scope = $g.scope; role = $g.roleName; action = $(if ($g.exists) { 'present' } else { 'would grant' }); id = '' }); continue }
        $gr = $null
        try { $gr = Invoke-PimSkvGrant -Arm $Arm -Grant $g -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup -VaultName $Plan.vault.name -Sleep $Sleep }
        catch { $gErr = "grant of $($g.roleName) for $($g.identityName): $(Protect-PimSkvText -Text "$($_.Exception.Message)") -- no app / job was switched" }
        if ($gErr) { break }
        if ($gr.action -eq 'granted') { $newGrant = $true }
        $out.grants.Add([ordered]@{ identity = $g.identityName; principalId = $g.principalId; scope = $g.scope; role = $g.roleName; action = $gr.action; id = $gr.id })
    }
    if ($gErr) { $out.state = 'failed'; $out.error = $gErr; return $out }
    if ($GrantOnly) {
        if ($Plan.writer -and $Plan.writer.reason) { $out.state = 'partial'; $out.error = "the updater's Key Vault Secrets Officer was not granted: $($Plan.writer.reason)" }
        if ($DryRun -and $out.state -eq 'done') { $out.state = 'dry-run' }
        return $out
    }
    # a new role assignment takes a while to reach Container Apps
    if ($newGrant -and $RbacWaitSeconds -gt 0) { & $Sleep $RbacWaitSeconds }
    foreach ($r in $mv) {
        $rr = Invoke-PimSkvResourceApply -Arm $Arm -Kv $Kv -ResourcePlan $r -VaultUri $Plan.vault.uri -Sleep $Sleep -DryRun:$DryRun -WaitForIdleRuns:$WaitForIdleRuns -IdleWaitMinutes $IdleWaitMinutes `
                -ReadBackTries $ReadBackTries -ReadBackWaitSeconds $ReadBackWaitSeconds -SwitchTries $SwitchTries -SwitchWaitSeconds $SwitchWaitSeconds
        $out.resources.Add($rr)
        if ($rr.rollback) { $out.rollback.Add($rr.rollback) }
        if ($rr.state -eq 'failed') { $out.state = 'failed'; $out.error = "$($r.name): $($rr.error)"; break }
        if ($rr.state -eq 'deferred' -and $out.state -eq 'done') { $out.state = 'partial' }
    }
    if ($DryRun -and $out.state -eq 'done') { $out.state = 'dry-run' }
    return $out
}

# ======================================================================================================================
# THE UPDATER'S STEP (Invardia decision 2026-11-11): the install's own updater (id-pim-updater) moves the secrets INSIDE its
# update run. It WRITES secrets and SWITCHES definitions only -- it never assigns a role (P9, SETUPSTEPS-TRUTH): its own Key
# Vault Secrets Officer and the readers' Key Vault Secrets User are granted ONCE by the Support-app step
# (Move-PimSecretsToKeyVault.ps1 -GrantOnly, Invoke-PimSkvApply -GrantOnly). Missing rights = skipped, said, and the fact says
# missing / support-app. Never throws, never fails the update.
# ======================================================================================================================
function Get-PimSkvGrantCommand {
    <# PURE. The Support-app grant command for this install (the readers' Secrets User + the updater's Secrets Officer). #>
    param([AllowEmptyString()][string]$TenantId = '', [AllowEmptyString()][string]$SubscriptionId = '', [AllowEmptyString()][string]$ResourceGroup = '')
    $t = $(if ("$TenantId".Trim()) { "$TenantId".Trim() } else { '<tenant id>' }); $s = $(if ("$SubscriptionId".Trim()) { "$SubscriptionId".Trim() } else { '<subscription id>' })
    $g = $(if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { '<resource group>' })
    return ".\Move-PimSecretsToKeyVault.ps1 -TenantId $t -SubscriptionId $s -ResourceGroup $g -UseSignedInAccount -GrantOnly"
}

function Invoke-PimSkvUpdaterStep {
    <#
      The updater's step: plan -> per app / job, ONE AT A TIME: (its reader right held? else skipped) vault write + read-back ->
      -WaitForIdleRuns quiesce (never for its OWN job: that one is running now, its change applies to its next execution) ->
      one switch -> read-back -> automatic put-back on a failed read-back. -Switch = the job's PIM_UPDATE_SECRETS_TO_KV (ON unless
      0 / false / off / no). Returns @{ enabled; state = ok | missing | n/a | unknown | off; how = updater | support-app; detail;
      lines[] (@{ level = info|changed|warn; text }); moved; deferred; failed; skipped; rollback[] (no values) }.
      THE ROLE GUARD: every ARM call goes through a seam that REFUSES any write under Microsoft.Authorization.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Kv, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [AllowEmptyString()][string]$SelfJob = '', [AllowEmptyString()][string]$TenantId = '', [AllowNull()][AllowEmptyString()][string]$Switch = '',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$IdleWaitMinutes = (Get-PimSkvIdleWaitMinutes),
          [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10, [int]$SwitchTries = 4, [int]$SwitchWaitSeconds = 60)
    $out = [ordered]@{ enabled = $true; state = 'unknown'; how = 'updater'; detail = ''; lines = ([System.Collections.Generic.List[object]]::new())
                       moved = 0; deferred = 0; failed = 0; skipped = 0; rollback = ([System.Collections.Generic.List[object]]::new()) }
    $cmd = Get-PimSkvGrantCommand -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    if (-not (Test-PimSkvUpdaterEnabled -Value $Switch)) {
        $out.enabled = $false; $out.state = 'off'; $out.detail = "switched off ($(Get-PimSkvUpdaterSwitchName)=$("$Switch".Trim())) -- nothing read, nothing moved"
        $out.lines.Add([pscustomobject]@{ level = 'info'; text = $out.detail }); return $out
    }
    # the role guard (a uniquely named variable: the seam below is reached by dynamic scope from the functions it is handed to)
    $skvUpdInnerArm = $Arm
    $armNoGrant = { param($m, $p, $b)
        if ("$m".ToUpperInvariant() -ne 'GET' -and "$p" -match '(?i)/providers/Microsoft\.Authorization/') { throw "REFUSED: the updater may not assign roles (P9) -- $m $p" }
        & $skvUpdInnerArm $m $p $b }
    $plan = $null; $err = ''
    try {
        $inst = Read-PimSkvInstall -Arm $armNoGrant -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $ch = Get-PimSkvVaultChoice -Vaults @($inst.vaults)
        $asg = @()
        if ($ch.ok) { $asg = @(Read-PimSkvVaultAssignments -Arm $armNoGrant -Scope (Get-PimSkvVaultScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $ch.name)) }
        $plan = Get-PimSkvPlan -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Install $inst -Assignments $asg -WithWriter -WriterJob $SelfJob
    } catch { $err = Protect-PimSkvText -Text "$($_.Exception.Message)" }
    if ($err) { $out.state = 'unknown'; $out.detail = "not read: $err"; $out.lines.Add([pscustomobject]@{ level = 'warn'; text = $out.detail }); return $out }
    if ($plan.refusal) {
        $out.state = 'missing'; $out.how = 'support-app'; $out.detail = "nothing moved: $($plan.refusal)"
        $out.lines.Add([pscustomobject]@{ level = 'warn'; text = $out.detail }); return $out
    }
    $mv = @($plan.resources | Where-Object { $_.state -eq 'move' }); $ref = @($plan.resources | Where-Object { $_.state -eq 'refused' })
    foreach ($r in $ref) { $out.lines.Add([pscustomobject]@{ level = 'warn'; text = "$($r.name): not moved -- $($r.reason)" }) }
    $pim = @($plan.resources | Where-Object { $_.state -ne 'not-pim' })
    if (-not $mv.Count) {
        if ($ref.Count) { $out.state = 'missing'; $out.how = 'support-app'; $out.detail = "$($ref.Count) app / job(s) hold secrets outside Key Vault that the updater may not move: $((@($ref | ForEach-Object { $_.name })) -join ', ')" }
        elseif (-not $pim.Count) { $out.state = 'n/a'; $out.detail = 'no PIM app or job in the resource group' }
        else { $out.state = 'ok'; $out.detail = "every secret of the $($pim.Count) PIM app(s) / job(s) is a Key Vault reference" }
        $out.lines.Add([pscustomobject]@{ level = $(if ($out.state -eq 'missing') { 'warn' } else { 'info' }); text = $out.detail }); return $out
    }
    $w = $plan.writer
    if (-not $w -or $w.reason -or -not $w.exists) {
        $why = if ($w -and $w.reason) { $w.reason } else { "the updater ($($w.identityName)) holds no $(Get-PimSkvOfficerRoleName) on $($plan.vault.name)" }
        $out.state = 'missing'; $out.how = 'support-app'; $out.skipped = $mv.Count
        $out.detail = "$why -- the updater may not grant it (P9); the Support app grants it once: $cmd. Nothing moved ($($plan.counts.secrets) secret(s) wait)"
        $out.lines.Add([pscustomobject]@{ level = 'warn'; text = $out.detail }); return $out
    }
    $grantOf = @{}; foreach ($g in @($plan.grants)) { $grantOf["$($g.principalId)".ToLowerInvariant()] = $g }
    foreach ($r in $mv) {
        $g = $grantOf["$($r.principalId)".ToLowerInvariant()]
        if (-not $g -or -not $g.exists) {
            $out.skipped++
            $out.lines.Add([pscustomobject]@{ level = 'warn'; text = "$($r.name): not moved -- its identity $($r.identityName) has no $(Get-PimSkvRoleName) on $($plan.vault.name); the Support app grants it ($cmd)" })
            continue
        }
        $rr = Invoke-PimSkvResourceApply -Arm $armNoGrant -Kv $Kv -ResourcePlan $r -VaultUri $plan.vault.uri -Sleep $Sleep -WaitForIdleRuns:($r.kind -eq 'job' -and $r.name -ine "$SelfJob".Trim()) `
                  -IdleWaitMinutes $IdleWaitMinutes -ReadBackTries $ReadBackTries -ReadBackWaitSeconds $ReadBackWaitSeconds -SwitchTries $SwitchTries -SwitchWaitSeconds $SwitchWaitSeconds
        if ($rr.rollback) { $out.rollback.Add($rr.rollback) }
        foreach ($s in @($rr.steps)) { $out.lines.Add([pscustomobject]@{ level = $(if ($s.step -eq 'switch') { 'changed' } else { 'info' }); text = "$($r.name): $($s.what)" }) }
        $rrState = "$($rr['state'])"
        if ($rrState -eq 'done') { $out['moved'] = [int]$out['moved'] + 1 }
        elseif ($rrState -eq 'deferred') { $out['deferred'] = [int]$out['deferred'] + 1; $out.lines.Add([pscustomobject]@{ level = 'warn'; text = "$($r.name): deferred to the next update run (a run of it was still going)" }) }
        else { $out['failed'] = [int]$out['failed'] + 1; $out.lines.Add([pscustomobject]@{ level = 'warn'; text = "$($r.name): NOT moved ($rrState) -- $($rr['error'])" }) }
    }
    $open = $out.skipped + $out.deferred + $out.failed + $ref.Count
    if (-not $open) { $out.state = 'ok'; $out.detail = "moved: $($out.moved) app / job(s) now read their secrets as Key Vault references" }
    else {
        $out.state = 'missing'; $out.how = $(if ($out.skipped -or $ref.Count) { 'support-app' } else { 'updater' })
        $out.detail = "moved $($out.moved); open: $($out.skipped) without the reader right, $($out.deferred) deferred, $($out.failed) failed, $($ref.Count) refused$(if ($out.how -eq 'support-app') { " -- the Support app: $cmd" } else { ' -- the next update run tries again' })"
    }
    $out.lines.Add([pscustomobject]@{ level = $(if ($out.state -eq 'ok') { 'changed' } else { 'warn' }); text = $out.detail })
    return $out
}

function Get-PimSkvSetupFact {
    <#
      PURE. The run record's facts from the updater step (UpdateState.setupFacts): secretsToKeyVault = ok | missing | n/a |
      unknown | off; secretsToKeyVaultHow = updater | support-app; secretsToKeyVaultDetail (<= 200 characters, scrubbed).
    #>
    param([AllowNull()]$Result)
    if ($null -eq $Result) { return [ordered]@{ secretsToKeyVault = 'unknown'; secretsToKeyVaultHow = 'updater'; secretsToKeyVaultDetail = 'the step did not run' } }
    $d = Protect-PimSkvText -Text "$($Result.detail)"
    if ($d.Length -gt 200) { $d = $d.Substring(0, 197) + '...' }
    return [ordered]@{ secretsToKeyVault = "$($Result.state)"; secretsToKeyVaultHow = "$($Result.how)"; secretsToKeyVaultDetail = $d }
}

function Get-PimSkvSetupStepState {
    <#
      PURE. What the setup step 'keyvault-secrets-only' says from these facts: @{ state; how; detail }. The step itself (its key
      and the plain-secret count) is the SEC-10 step lane's; this mapper is the half that says WHO fixes it: rights missing ->
      missing / support-app (the updater may not grant, P9); a move still open -> missing / updater; switched off -> unknown.
    #>
    param([AllowNull()]$Facts)
    $s = "$(if ($Facts -is [System.Collections.IDictionary]) { $Facts['secretsToKeyVault'] } elseif ($Facts) { $Facts.secretsToKeyVault })".Trim()
    $h = "$(if ($Facts -is [System.Collections.IDictionary]) { $Facts['secretsToKeyVaultHow'] } elseif ($Facts) { $Facts.secretsToKeyVaultHow })".Trim()
    $d = "$(if ($Facts -is [System.Collections.IDictionary]) { $Facts['secretsToKeyVaultDetail'] } elseif ($Facts) { $Facts.secretsToKeyVaultDetail })".Trim()
    switch ($s) {
        'ok'      { return @{ state = 'ok'; how = 'updater'; detail = $d } }
        'n/a'     { return @{ state = 'n/a'; how = 'updater'; detail = $d } }
        'missing' { return @{ state = 'missing'; how = $(if ($h -eq 'support-app') { 'support-app' } else { 'updater' }); detail = $d } }
        'off'     { return @{ state = 'unknown'; how = 'updater'; detail = "the updater's move is switched off ($(Get-PimSkvUpdaterSwitchName))" } }
        default   { return @{ state = 'unknown'; how = 'updater'; detail = $(if ($d) { $d } else { 'not read' }) } }
    }
}
