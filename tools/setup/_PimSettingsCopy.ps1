#Requires -Version 5.1
<#
  The shared code of the three scripts that carry pim.Settings between environments:
    * Copy-PimSettings.ps1   -- store to store (2026-09-22)
    * Export-PimSettings.ps1 -- store to a settings document (a JSON file)        (77.13 REQ-NAMING-IAC + 72.4, 2026-10-29)
    * Import-PimSettings.ps1 -- a settings document to a named environment's store (77.13 REQ-NAMING-IAC + 72.4, 2026-10-29)
  Offline-tested in tests/Test-PimCopySettings.ps1 and tests/Test-PimSettingsIac.ps1.

  What is here:
    * the never-copy list ($script:PimSettingsNeverCopy) and the file-transfer refusal (Get-PimSettingTransferRefusal),
    * the -MergeKeys rule (Merge-PimSettingKeys / Get-PimSettingKeyDiff),
    * the store plumbing every script shares: which store (Use-PimSettingsStore), the backup folder and file
      (Resolve-PimSettingsBackupDir / Save-PimSettingsBackup), the write with its read-back (Write-PimSettingWithReadBack),
      the list of setting names (Get-PimStoreSettingNames),
    * the settings document (PURE): New-PimSettingsDocument, Test-PimSettingsDocument, Get-PimSettingsImportItems.

  The file-transfer functions need engine\_shared\PIM-ConfigBackup.ps1 (the backup's deny list, secret rules and canonical
  compare) and tools\setup\_PimEnvironmentImport.ps1 (the environment import's never-copy list) loaded first; without
  them Get-PimSettingTransferRefusal REFUSES every name (fail closed). PS 5.1 + 7. ASCII only.
#>

# ---------------------------------------------------------------------------------------------------------------------
# What never travels between environments
# ---------------------------------------------------------------------------------------------------------------------
# Settings that describe WHO this environment is, or WHO may act in it. Copying one of these between tenants does not
# configure the target -- it points the target at the source's identities. (Moved here from Copy-PimSettings.ps1,
# 2026-10-29, so the export / import scripts refuse the same list.)
$script:PimSettingsNeverCopy = @(
    'ManagerAccess',            # who may use the Manager here
    'PortalAdmins',
    'EmergencyOverride',        # break-glass state
    'EmergencyPassphrase',
    'DownlinkTrust',            # which master signing keys this tenant trusts
    'BaselineTrustedKeys',
    'MspRegistry', 'MspTenants', 'CentralAdmins',
    'SqlStore', 'StorePointer', 'Instances',
    'Licence', 'License',
    'EnvironmentName',          # this environment's own display name (operator 2026-10-04) -- names THIS one
    'DemoMode', 'DemoGuestGroup', # s98: who may act here (a live demo); carried elsewhere it would cap that tenant's people
    'AdminDeletePins',   # review 1 fixes 2026-10-13 (decision 54): another environment's pinned account deletes are never this one's
    'GuardApprovals', 'GuardReleases', 'GuardHolds', 'GuardLimits', 'HybridAdCleanupApproval', 'HybridAdServerAutoGroupsApproval', 'AdServerAutoGroups', 'AdServerAutoGroupsWaiting', 'AdServerAutoGroupsProgress', 'AdCleanupResult', 'AdCleanupLocalAdmin',   # PIM 100.119 B1: who approved what HERE, and this tenant's guard limits (set by its SuperAdmin, audited)
    'ReconcileRemovalMode', 'EnableAutomaticOffboarding'   # REVIEW FIXES 2026-10-13: this environment's own protection switches -- set on ITS Settings page (confirmation + the count shown), never carried in from another environment
)

function Test-PimSettingNeverCopy {
    <# PURE. True for a name on $script:PimSettingsNeverCopy (case-insensitive, trimmed). #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    foreach ($b in $script:PimSettingsNeverCopy) { if ($n -ieq $b) { return $true } }
    return $false
}

# 72.4: settings as code "never edits definitions, never moves a ring, never changes a credential". On top of the lists the
# other tools already keep, a settings DOCUMENT never carries: who may approve or break glass, where the store / mail / RFA
# / Manager live, the deployment scenario and the ring, the install's Invardia identity, signed-request state.
$script:PimSettingsFileNeverExact = @(
    'BreakGlassAccounts', 'Approvers', 'Scenario', 'RingOrder', 'RingPlan', 'ReleaseWave', 'StorageBackend', 'MailSender',
    'ManagerUrl', 'RfaSettings', 'InvardiaEnvironmentId', 'InstallNames', 'LicenceRequestBaseUrl', 'AdminTapIssuance',
    'WorkloadPrereqs', 'SignedRequests', 'SignedRequestStats', 'MailSendProof', 'MailReportLastSent', 'PimActivityReadUtc',
    'JobAcknowledgements', 'MspMasterName', 'CentralKillSource'
)
$script:PimSettingsFileNeverPrefix = @('Msp', 'Ring', 'Update', 'Release', 'Downlink', 'Uplink', 'Licen', 'Install', 'Invardia',
                                       'Emergency', 'BreakGlass', 'Telemetry', 'Guard', 'Demo')

function Get-PimSettingTransferRefusal {
    <#
      PURE. Why ONE setting name may not be exported to or imported from a settings document; '' = it may.
      The union of every list the product keeps (fail closed -- a name on any of them is refused):
        1. the never-copy list of Copy-PimSettings ($script:PimSettingsNeverCopy),
        2. the configuration backup's deny list + secret-name rule (Test-PimConfigBackupSettingExcluded: secrets, this
           install's identity / licence, runtime state),
        3. the environment import's never-copy list (Test-PimImportSettingNeverCopy),
        4. the settings-document list above (access, rings, scenario, store / mail / Manager location, Invardia identity).
      A blank name, or a name with a character a setting name never has, is refused too.
    #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    if (-not $n) { return 'a blank setting name' }
    if ($n -notmatch '^[A-Za-z0-9_.:-]{1,128}$') { return 'not a setting name (letters, digits, _ . : - only)' }
    if (-not (Get-Command Test-PimConfigBackupSettingExcluded -ErrorAction SilentlyContinue) -or
        -not (Get-Command Test-PimImportSettingNeverCopy -ErrorAction SilentlyContinue)) {
        return 'the deny lists are not loaded (PIM-ConfigBackup.ps1 / _PimEnvironmentImport.ps1) -- refusing every name'
    }
    if (Test-PimSettingNeverCopy -Name $n) { return "identity / access of the environment it is stored in (it names who may act there, or where it is)" }
    $ex = Test-PimConfigBackupSettingExcluded -Name $n
    if ($ex.excluded) {
        switch ("$($ex.reason)") {
            'secret'   { return 'a secret (a key, token, password or connection string lives in it)' }
            'identity' { return "this install's own identity, licence or protection switch" }
            default    { return 'runtime state the product writes itself, not configuration' }
        }
    }
    if (Test-PimImportSettingNeverCopy -Name $n) { return "the environment's own identity or runtime state" }
    foreach ($x in $script:PimSettingsFileNeverExact) { if ($n -ieq $x) { return 'access, ring, scenario or location of this environment -- set it with the tool that owns it' } }
    foreach ($p in $script:PimSettingsFileNeverPrefix) { if ($n.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return "access, ring, update, licence or install state ($p...) -- set it with the tool that owns it" } }
    return ''
}

# ---------------------------------------------------------------------------------------------------------------------
# The -MergeKeys rule (2026-10-03)
# ---------------------------------------------------------------------------------------------------------------------
<#
  Found building the ring-1 estate: copying NamingConventions from an environment set up on an older release REPLACED the
  new environment's document and silently dropped the keys the newer release added (GroupTypePrefixes, ServiceNames,
  PermissionGroupAdminUnits, ...). -MergeKeys keeps them: for an OBJECT document the source's top-level keys win and keys
  only the target has stay. Anything that is not an object on both sides (an array, a string, a number) is replaced
  exactly as without -MergeKeys -- a half-merged list is a shape no reader expects.
#>
function Merge-PimSettingKeys {
    param([AllowNull()][object]$Target, [AllowNull()][object]$Source)
    $isObj = { param($o) $null -ne $o -and $o -is [System.Management.Automation.PSCustomObject] }
    if (-not (& $isObj $Source) -or -not (& $isObj $Target)) { return $Source }
    $m = [ordered]@{}
    foreach ($p in $Target.PSObject.Properties) { $m[$p.Name] = $p.Value }
    foreach ($p in $Source.PSObject.Properties) { $m[$p.Name] = $p.Value }
    return [pscustomobject]$m
}

function Get-PimSettingKeyDiff {
    <# PURE. What -MergeKeys keeps from the target: the top-level keys the source lacks. #>
    param([AllowNull()][object]$Target, [AllowNull()][object]$Source)
    if ($null -eq $Target -or $Target -isnot [System.Management.Automation.PSCustomObject] -or $null -eq $Source -or $Source -isnot [System.Management.Automation.PSCustomObject]) { return @() }
    $src = @($Source.PSObject.Properties.Name)
    return @($Target.PSObject.Properties.Name | Where-Object { $src -notcontains $_ })
}

# ---------------------------------------------------------------------------------------------------------------------
# Store plumbing (shared by Copy / Export / Import)
# ---------------------------------------------------------------------------------------------------------------------
function Use-PimSettingsStore {
    <# Points the SQL layer at one environment's store (its SPN + certificate) and returns its connection string. #>
    param([string]$TenantId, [string]$ClientId, [string]$Thumbprint, [string]$Server, [string]$Database)
    $global:PIM_TenantId          = $TenantId
    $global:PIM_SqlClientId       = $ClientId
    $global:PIM_SqlCertThumbprint = $Thumbprint
    return (Get-PimSqlConnectionString -Server $Server -Database $Database)
}

function Get-PimStoreSettingNames {
    <# Every pim.Settings name in a store, sorted. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT Name FROM pim.Settings ORDER BY Name' |
        ForEach-Object { "$($_.Name)" } | Where-Object { $_.Trim() })
}

function Read-PimSettingValue {
    <#
      ONE setting's stored value, parsed -- $null when it is not set. Unlike Get-PimSqlSetting, a JSON ARRAY comes back as an
      array even when it has one element (ConvertFrom-Json and a function's return both unroll it, so a one-element list
      would be read -- and then written back -- as a bare object; IMP-39). Call it as `$v = Read-PimSettingValue ...`.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT ValueJson FROM pim.Settings WHERE Name=@n" -Parameters @{ n = $Name }
    if ($null -eq $j -or $j -is [DBNull] -or "$j".Trim() -eq '') { return $null }
    $t = "$j"
    try { $v = ConvertFrom-PimSettingJsonText -Json $t } catch { return $t }
    if ($t.TrimStart().StartsWith('[')) { return , $v }
    return $v
}

function ConvertFrom-PimSettingJsonText {
    <#
      PURE. JSON text -> value with a top-level ARRAY kept as exactly that array on PS 5.1 AND 7. (PS 7's ConvertFrom-Json
      enumerates a top-level array unless -NoEnumerate; PS 5.1's never does and has no such switch -- and @(ConvertFrom-Json
      ...) on 5.1 NESTS it, [[x]], the 3.0.5 VM red of 2026-10-29.) Assign the result: `$v = ConvertFrom-PimSettingJsonText ...`
      -- an array is returned with the unary comma, so the caller gets the array itself.
    #>
    param([Parameter(Mandatory)][string]$Json)
    $ne = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('NoEnumerate')) { $ne['NoEnumerate'] = $true }
    $v = ConvertFrom-Json -InputObject $Json @ne
    if ($Json.TrimStart().StartsWith('[')) {
        if ($null -eq $v) { return , @() }
        return , $v
    }
    return $v
}

function Resolve-PimSettingsBackupDir {
    <#
      Where the backups go and whether they are written. 12.7: -WhatIf writes nothing outside the temp folder. A backup in
      the temp folder (the default) is still taken -- it is what makes a dry run's diff restorable -- and a backup anywhere
      else is only announced. Creates the folder when it will be written. Returns @{ dir; writes }.
    #>
    param([string]$BackupDir, [Parameter(Mandatory)][string]$DefaultLeaf, [bool]$DryRun = $false)
    if (-not "$BackupDir".Trim()) { $BackupDir = Join-Path ([IO.Path]::GetTempPath()) $DefaultLeaf }
    $inTemp = ([IO.Path]::GetFullPath($BackupDir)).StartsWith(([IO.Path]::GetFullPath([IO.Path]::GetTempPath())), [StringComparison]::OrdinalIgnoreCase)
    $writes = $inTemp -or -not $DryRun
    if ($writes -and -not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir -WhatIf:$false -Confirm:$false | Out-Null }
    return @{ dir = $BackupDir; writes = [bool]$writes }
}

function Save-PimSettingsBackup {
    param([string]$Path, [AllowEmptyString()][string]$Value, [bool]$Writes = $true)
    if (-not $Writes) { Write-Host "  What if: would write the backup $Path" -ForegroundColor Yellow; return }
    Set-Content -Path $Path -Value $Value -Encoding UTF8 -WhatIf:$false -Confirm:$false
}

function ConvertTo-PimSettingJsonText {
    <#
      PURE. A value as JSON text, written by hand at every level -- NOT ConvertTo-Json on the whole value. On Windows
      PowerShell 5.1 an array that has passed through the pipeline (any function's output, ConvertFrom-Json's own output)
      carries a PSObject wrapper, and ConvertTo-Json writes such an array as {"value":[...],"Count":n} -- even with
      -InputObject (the 3.0.5 VM red of 2026-10-29: Filters written as an object, read back as an array). Here every level
      is unwrapped first; ConvertTo-Json is used only for a single string or number. -SortKeys = the canonical form used to
      compare (key order does not count); -Indent n = pretty-printed for a document a person reads (-1 = compact).
    #>
    param([AllowNull()][object]$Value, [switch]$SortKeys, [int]$Indent = -1, [int]$Level = 0)
    if ($null -eq $Value -or $Value -is [DBNull]) { return 'null' }
    $pretty = $Indent -ge 0
    $b = $Value.PSObject.BaseObject
    $isObj = ($b -is [System.Management.Automation.PSCustomObject])
    if (-not $isObj) { $Value = $b }
    $nl = if ($pretty) { "`n" } else { '' }
    $pad = if ($pretty) { ' ' * ($Indent * ($Level + 1)) } else { '' }
    $padEnd = if ($pretty) { ' ' * ($Indent * $Level) } else { '' }
    $colon = if ($pretty) { ': ' } else { ':' }
    $kv = {
        param($pairs)   # @(@(key, value))
        if (-not @($pairs).Count) { return '{}' }
        $parts = @(foreach ($p in $pairs) { $pad + (ConvertTo-Json -InputObject ([string]$p[0]) -Compress) + $colon + (ConvertTo-PimSettingJsonText -Value $p[1] -SortKeys:$SortKeys -Indent $Indent -Level ($Level + 1)) })
        return ('{' + $nl + ($parts -join (',' + $nl)) + $nl + $padEnd + '}')
    }
    if ($isObj) {
        $names = @($Value.PSObject.Properties | ForEach-Object { "$($_.Name)" })
        if ($SortKeys) { [Array]::Sort($names, [StringComparer]::Ordinal) }
        return (& $kv @(foreach ($n in $names) { , @($n, $Value.PSObject.Properties[$n].Value) }))
    }
    if ($Value -is [string] -or $Value -is [char]) { return (ConvertTo-Json -InputObject ([string]$Value) -Compress) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return ('"' + $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture) + '"') }
    if ($Value -is [enum]) { return (ConvertTo-Json -InputObject ([string]$Value) -Compress) }
    if ($Value -is [ValueType]) { return (ConvertTo-Json -InputObject $Value -Compress) }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { "$_" })
        if ($SortKeys) { [Array]::Sort($keys, [StringComparer]::Ordinal) }
        return (& $kv @(foreach ($k in $keys) { , @($k, $Value[$k]) }))
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($e in $Value) { $pad + (ConvertTo-PimSettingJsonText -Value $e -SortKeys:$SortKeys -Indent $Indent -Level ($Level + 1)) })
        if (-not $items.Count) { return '[]' }
        return ('[' + $nl + ($items -join (',' + $nl)) + $nl + $padEnd + ']')
    }
    return (ConvertTo-Json -InputObject ([string]$Value) -Compress)
}

function ConvertTo-PimSettingValueJson {
    <# The exact JSON text a value is stored as ($null when there is none). A one-element array stays an array (IMP-39), on 5.1 too. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    return (ConvertTo-PimSettingJsonText -Value $Value)
}

function Write-PimSettingWithReadBack {
    <#
      Writes ONE setting and reads it back. Throws when the read-back differs from what was written (compared in canonical
      form, Test-PimSettingValueSame -- key order and whitespace do not count).
      -BackupFile is named in the error so the operator knows what to restore.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Value, [string]$BackupFile = '')
    Set-PimSqlSetting -ConnectionString $ConnectionString -Name $Name -ValueJson (ConvertTo-PimSettingValueJson -Value $Value)
    $after = Read-PimSettingValue -ConnectionString $ConnectionString -Name $Name
    if (-not (Test-PimSettingValueSame -A $Value -B $after)) {
        throw ("read-back of '$Name' does not match what was written -- the target may hold a partial value." +
               $(if ($BackupFile) { " Restore from $BackupFile before continuing." } else { '' }))
    }
}

function Test-PimSettingValueSame {
    <# PURE. Two setting values are the same (canonical form: key order, whitespace and date offsets do not count; a
       PSObject-wrapped array is still the array -- ConvertTo-PimSettingJsonText -SortKeys, not ConvertTo-Json). #>
    param([AllowNull()][object]$A, [AllowNull()][object]$B)
    return ((ConvertTo-PimSettingJsonText -Value $A -SortKeys) -ceq (ConvertTo-PimSettingJsonText -Value $B -SortKeys))
}

# ---------------------------------------------------------------------------------------------------------------------
# The settings document (77.13 REQ-NAMING-IAC + 72.4) -- PURE
# ---------------------------------------------------------------------------------------------------------------------
$script:PimSettingsDocumentFormat = 'pim-manager-settings'
$script:PimSettingsDocumentFormatVersion = 1     # the newest version this code reads and writes

function New-PimSettingsDocument {
    <#
      PURE. The settings document for -Values (@{ name = value }, as read from the store). Every name is checked with
      Get-PimSettingTransferRefusal: with -Strict (names the operator listed) a refused name THROWS; without it (an
      export of everything) it is left out and listed in skipped. Inside a kept value every property whose NAME or VALUE
      looks like a secret is removed (Remove-PimConfigBackupSecrets) and its path recorded in redacted -- an import puts
      the TARGET's current value back on those paths, so a document never blanks a webhook or a key. A value that is
      itself a secret is left out (skipped). Returns the document as an ordered hashtable:
        format, formatVersion, productVersion, exportedUtc, source { tenantId; environmentName }, settings { name = value },
        redacted { name = @(paths) }, skipped @( { name; reason } )
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values, [string]$ProductVersion = '', [string]$SourceTenantId = '',
          [string]$SourceEnvironmentName = '', [switch]$Strict, [datetime]$Now = [datetime]::UtcNow)
    $settings = [ordered]@{}; $redacted = [ordered]@{}; $skipped = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($Values.Keys | ForEach-Object { "$_" } | Sort-Object)) {
        $why = Get-PimSettingTransferRefusal -Name $n
        if ($why) {
            if ($Strict) { throw ("REFUSING to export '$n': $why. A settings document never carries it.") }
            $skipped.Add([ordered]@{ name = $n; reason = $why }); continue
        }
        $v = $Values[$n]
        if ($null -eq $v) { $skipped.Add([ordered]@{ name = $n; reason = 'not set in this store' }); continue }
        $rs = Remove-PimConfigBackupSecrets -Value $v
        if ($rs.dropAll) {
            if ($Strict) { throw ("REFUSING to export '$n': its value is a secret.") }
            $skipped.Add([ordered]@{ name = $n; reason = 'its value is a secret' }); continue
        }
        # A part removed INSIDE A LIST ("[0].key") is not exported -- the 2026-10-29 VM run exported Filters [{key,label}]
        # as [{label}] (the secret-NAME rule matches a property called exactly "key"). BUG-BACKUP-LIST-KEY (2026-10-29)
        # taught the configuration-backup restore to put such a path back BY INDEX from the current value of the SAME
        # environment; a settings document goes to ANOTHER environment, whose list item [i] is not the source's item [i]
        # (and a fresh target has no list at all), so an import would pair the target's key with the source's label --
        # inventing a value. Kept refused on purpose: -Name refuses it, -All lists it as skipped.
        $inList = @($rs.redacted | Where-Object { "$_" -match '\[' })
        if ($inList.Count) {
            $why = "a field inside a list looks like a secret ($($inList -join ', ')) and an import could not put it back -- the setting would lose it"
            if ($Strict) { throw ("REFUSING to export '$n': $why.") }
            $skipped.Add([ordered]@{ name = $n; reason = $why }); continue
        }
        $settings[$n] = $rs.value
        if (@($rs.redacted).Count) { $redacted[$n] = @($rs.redacted) }
    }
    return [ordered]@{
        format         = $script:PimSettingsDocumentFormat
        formatVersion  = $script:PimSettingsDocumentFormatVersion
        productVersion = "$ProductVersion"
        exportedUtc    = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        source         = [ordered]@{ tenantId = "$SourceTenantId"; environmentName = "$SourceEnvironmentName" }
        settings       = $settings
        redacted       = $redacted
        skipped        = @($skipped.ToArray())
    }
}

function Test-PimSettingsDocument {
    <#
      PURE. Is -Document (parsed JSON, or the JSON text) a settings document this code may import? Returns
      @{ ok; error; document; names }. Refused, with one clear line and NOTHING written:
        * not JSON / not a PIM Manager settings document (format),
        * a format version newer than this code reads (written by a newer PIM Manager -- update the scripts first),
        * no settings object,
        * ANY setting the deny lists refuse (the whole document is refused -- fix the file, nothing is half-applied),
        * a setting with no value (JSON null -- an import never clears a setting),
        * ANY value that carries a secret (a property named like one, or a value shaped like one).
    #>
    param([AllowNull()][object]$Document)
    $bad = { param($e) return @{ ok = $false; error = "$e"; document = $null; names = @() } }
    $doc = $Document
    if ($doc -is [string]) { try { $doc = ConvertFrom-Json -InputObject $doc } catch { return (& $bad 'the file is not valid JSON') } }
    if ($null -eq $doc -or $doc -isnot [System.Management.Automation.PSCustomObject] -or "$($doc.format)" -ne $script:PimSettingsDocumentFormat) {
        return (& $bad "this is not a PIM Manager settings document (format '$script:PimSettingsDocumentFormat' -- write one with Export-PimSettings.ps1)")
    }
    $fv = 0
    if (-not [int]::TryParse("$($doc.formatVersion)", [ref]$fv) -or $fv -lt 1) { return (& $bad "the document has no valid formatVersion ('$($doc.formatVersion)')") }
    if ($fv -gt $script:PimSettingsDocumentFormatVersion) {
        return (& $bad ("REFUSED: the document is format version $fv (written by PIM Manager $($doc.productVersion)); this script reads format version " +
                        "$script:PimSettingsDocumentFormatVersion or older. Update the PIM Manager scripts first -- nothing was written."))
    }
    if (-not $doc.PSObject.Properties['settings'] -or $doc.settings -isnot [System.Management.Automation.PSCustomObject]) {
        return (& $bad 'the document has no settings object')
    }
    $names = @($doc.settings.PSObject.Properties | ForEach-Object { "$($_.Name)" })
    $refused = @(foreach ($n in $names) { $w = Get-PimSettingTransferRefusal -Name $n; if ($w) { "$n ($w)" } })
    if ($refused.Count) {
        return (& $bad ("REFUSED: the document carries setting(s) a settings document may never set: " + ($refused -join '; ') +
                        '. Remove them from the file -- nothing was written.'))
    }
    $empty = @($names | Where-Object { $null -eq $doc.settings.$_ })
    if ($empty.Count) {
        return (& $bad ("REFUSED: setting(s) with no value: " + ($empty -join ', ') + '. An import never clears a setting -- remove them from the file; nothing was written.'))
    }
    $secret = @(foreach ($n in $names) {
        $rs = Remove-PimConfigBackupSecrets -Value $doc.settings.$n
        if ($rs.dropAll) { "$n (the value itself)" } elseif (@($rs.redacted).Count) { "$n ($(@($rs.redacted) -join ', '))" }
    })
    if ($secret.Count) {
        return (& $bad ("REFUSED: the document carries secret(s): " + ($secret -join '; ') + '. A settings document never holds a secret -- nothing was written.'))
    }
    return @{ ok = $true; error = ''; document = $doc; names = $names }
}

function Get-PimSettingsImportItems {
    <#
      PURE except for -Reader ({ param($Name) <stored value or $null> }). The plan of an import: one item per setting of
      the (already validated) document, or of -Names when given (a name the document lacks is reported, never guessed):
        @{ name; state = add | change | same | missing; current; desired; changedKeys; keptKeys }
      desired = the document's value, with the TARGET's current value put back on every redacted path (secrets stay the
      target's) and, with -MergeKeys, the target's extra top-level keys kept (Merge-PimSettingKeys).
    #>
    param([Parameter(Mandatory)][object]$Document, [string[]]$Names = @(), [Parameter(Mandatory)][scriptblock]$Reader, [switch]$MergeKeys)
    $docNames = @($Document.settings.PSObject.Properties | ForEach-Object { "$($_.Name)" })
    $want = @($Names | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $want.Count) { $want = $docNames }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($n in $want) {
        $dn = @($docNames | Where-Object { $_ -ieq $n })
        if (-not $dn.Count) { $items.Add(@{ name = $n; state = 'missing'; current = $null; desired = $null; changedKeys = @(); keptKeys = @() }); continue }
        $n = $dn[0]
        $cur = & $Reader $n
        $paths = @()
        if ($Document.PSObject.Properties['redacted'] -and $Document.redacted -and $Document.redacted.PSObject.Properties[$n]) { $paths = @($Document.redacted.$n | ForEach-Object { "$_" }) }
        # the document's value as it is (an array stays an array) -- with the target's secrets put back where the export removed them
        $desired = $Document.settings.$n
        # only an OBJECT goes through the restore helper (it returned a plain `return` that unrolled a one-element array on
        # PS 5.1 -- Filters [{...}] came out as {...}, the 2026-10-29 VM red); and only object paths: the export never
        # carries a path inside a list (New-PimSettingsDocument refuses it -- see there why)
        $paths = @($paths | Where-Object { "$_" -notmatch '\[' })
        if ($paths.Count -and $desired -is [System.Management.Automation.PSCustomObject]) { $desired = Get-PimConfigBackupSettingRestoreValue -Backup $Document.settings.$n -Current $cur -RedactedPaths $paths }
        $kept = @()
        if ($MergeKeys -and $cur -is [System.Management.Automation.PSCustomObject] -and $desired -is [System.Management.Automation.PSCustomObject]) { $kept = @(Get-PimSettingKeyDiff -Target $cur -Source $desired); $desired = Merge-PimSettingKeys -Target $cur -Source $desired }
        $state = if ($null -eq $cur) { 'add' } elseif (Test-PimSettingValueSame -A $cur -B $desired) { 'same' } else { 'change' }
        $ck = @()
        if ($state -eq 'change') {
            if ($cur -is [System.Management.Automation.PSCustomObject] -and $desired -is [System.Management.Automation.PSCustomObject]) {
                $keys = @(@($cur.PSObject.Properties.Name) + @($desired.PSObject.Properties.Name) | Sort-Object -Unique)
                $ck = @($keys | Where-Object {
                    $a = $cur.PSObject.Properties[$_]; $b = $desired.PSObject.Properties[$_]
                    -not (Test-PimSettingValueSame -A $(if ($a) { $a.Value } else { $null }) -B $(if ($b) { $b.Value } else { $null }))
                })
            } else { $ck = @('*') }
        }
        $items.Add(@{ name = $n; state = $state; current = $cur; desired = $desired; changedKeys = $ck; keptKeys = $kept })
    }
    return @($items.ToArray())
}
