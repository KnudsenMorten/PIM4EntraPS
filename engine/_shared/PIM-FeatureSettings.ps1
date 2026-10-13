<#
  PIM 100.121 (owner 2026-10-13, decision 10) -- THE FEATURE SETTINGS: one catalog, one reader.

  The sweep of 100.121 found settings the code reads that no person could set in a hosted install: several were read
  from a process variable ONLY ($global:PIM_<Name>), which nothing sets in a container. This file gives each of them

    * ONE definition (Get-PimFeatureSettingCatalog): name, type, the REAL default (what the code did before this file
      existed), the range the reader accepts, the range Settings offers, and whether Settings shows it;
    * ONE reader (Get-PimFeatureSetting -Name): $global:PIM_<Name>  ->  the process environment PIM_<Name>  ->  the store
      (pim.Settings, hydrated into $global:PIM_NamingConventions by Import-PimSettingsFromStore)  ->  the default.
      The process variable still wins, so nothing that set one behaves differently. A value that is set but not usable
      (a word where a number belongs, a number outside the range) gives the DEFAULT -- never a guess.

  WITH NOTHING STORED AND NOTHING SET, EVERY NAME READS ITS OLD VALUE. tests/Test-PimFeatureSettings.ps1 holds that per name.

  THE [bool] TRAP: a switch was read as [bool]$global:PIM_RequireGroupOwners. The store hands back text for some writers,
  and [bool]'false' is TRUE. ConvertTo-PimFeatureSettingValue reads a switch as text: only true / 1 / yes / on is on.

  NOT HERE, ON PURPOSE: guard limits and the alert recipient (PIM-Guard*.ps1, PIM-DisableGuard.ps1), the hybrid Active
  Directory naming settings (engine/hybrid-ad), platform / hosting values (never a setting in the page -- owner
  2026-10-13: "settings is only tings about features and configurations"), and the two protection switches (automatic
  offboarding, reconcile-removal mode): those keep their own readers (Test-PimAutoOffboardingEnabled,
  Get-PimReconcileRemovalMode) and are written by tools/pim-manager/_settings.ps1.

  PURE except for the three reads in Get-PimFeatureSettingSource. No module, no SQL, no file. Windows PowerShell 5.1 and
  pwsh 7. Literals come from functions: a $script: variable is $null in a child scope behind a load guard.
#>

Set-StrictMode -Off

function Get-PimFeatureSettingCatalog {
    <#
      PURE. Every feature setting this file reads. Fields:
        name      the store name (pim.Settings) and the suffix of $global:PIM_<name> / the environment PIM_<name>
        type      'bool' | 'int' | 'list' | 'text' | 'json'
        default   what the code did before the reader existed (the value when nothing is set anywhere)
        readMin / readMax   what the READER accepts (the old code's own bounds; $null = no bound)
        min / max           what SETTINGS accepts on a write (never wider than the reader)
        inMenu    shown and changeable under Settings (a SuperAdmin); $false = read through the reader only
        group     the Settings card it belongs to
        readBy    'reader' = a call site asks Get-PimFeatureSetting; 'own' = the code already read the store by itself
                  (its own reader is unchanged; Settings only writes the value it reads)
      Every entry is handed out with EVERY field (a field a setting does not use is $null; fromStore is $true unless the
      entry says otherwise), so a caller running in strict mode can read any of them.
    #>
    $all = @(
        # REVIEW FIXES 2026-10-13: every number has an UPPER bound on a read too, equal to what Settings offers (readMax =
        # max). It was $null for four of them: a stored / environment value of 100000 was honoured (an approval request
        # that never expires, an owner extension of 273 years). Above the range = the default, with one warning.
        [ordered]@{ name = 'ApprovalRequestTtlHours';   type = 'int';  default = 72;    readMin = 1; readMax = 720;   min = 1;  max = 720;  inMenu = $true;  group = 'approvals'; readBy = 'reader'; unit = 'hours' }
        [ordered]@{ name = 'BreakGlassChangeTtlHours';  type = 'int';  default = 72;    readMin = 1; readMax = 168;   min = 1;  max = 168;  inMenu = $true;  group = 'approvals'; readBy = 'reader'; unit = 'hours' }
        [ordered]@{ name = 'OwnerExtendMaxDays';        type = 'int';  default = 365;   readMin = 1; readMax = 3650;  min = 1;  max = 3650; inMenu = $true;  group = 'approvals'; readBy = 'own';    unit = 'days' }
        [ordered]@{ name = 'RequireGroupOwners';        type = 'bool'; default = $false; inMenu = $true;  group = 'groups';    readBy = 'reader' }
        [ordered]@{ name = 'StaleGroupDays';            type = 'int';  default = 90;    readMin = 1; readMax = 3650;  min = 7;  max = 3650; inMenu = $true;  group = 'groups';    readBy = 'reader'; unit = 'days' }
        [ordered]@{ name = 'RequiredAuthMethods';       type = 'list'; default = @('microsoftAuthenticator', 'passkey', 'fido2', 'windowsHelloForBusiness', 'certificate'); inMenu = $true; group = 'accounts'; readBy = 'reader'
                    itemPattern = '^[A-Za-z][A-Za-z0-9]{1,49}$'; maxItems = 12; refuse = @('sms', 'voice', 'phone', 'email') }
        [ordered]@{ name = 'TapCreateLeadHours';        type = 'int';  default = 48;    readMin = 0; readMax = 720;   min = 0;  max = 720;  inMenu = $true;  group = 'accounts';  readBy = 'own';    unit = 'hours' }
        [ordered]@{ name = 'TapReissueUntilOnboarded';  type = 'bool'; default = $false; inMenu = $true;  group = 'accounts';  readBy = 'own' }
        # storeExact (REVIEW FIXES 2026-10-13): before 100.121 the store was never read for this name, so a row somebody
        # wrote by hand (the documented name is PIM_AdminMailboxForwarding) or carried in with a settings copy / an
        # environment import did nothing. From the STORE only the real JSON boolean the Settings route writes counts;
        # the text "true", 1 or "on" there = not usable, the default (off) applies. The process variable and the process
        # environment read as before.
        [ordered]@{ name = 'AdminMailboxForwarding';    type = 'bool'; default = $false; inMenu = $true;  group = 'accounts';  readBy = 'reader'; storeExact = $true }
        [ordered]@{ name = 'DiscoveryNotifyRecipients'; type = 'text'; default = '';    inMenu = $true;  group = 'discovery'; readBy = 'reader'; format = 'emails'; maxItems = 20 }
        [ordered]@{ name = 'IntakeEnabled';             type = 'bool'; default = $false; inMenu = $true;  group = 'discovery'; readBy = 'own' }
        # Read through the reader, NOT in Settings, NOT from the store and NOT from the process environment (fromStore =
        # $false, fromEnvironment = $false: the process variable ONLY -- exactly what the scheduler read before 100.121,
        # $global:PIM_DiscoveryAutoImportRules / $global:PIM_DiscoveryAutoImportPowerBi). Both make the discovery sweep
        # CREATE delegations without a person: neither a row in the store that no page validates nor an environment
        # variable of the job may switch that on -- no new source (REVIEW FIXES 2026-10-13: the environment was one).
        # What a customer chooses is the discovery policy per resource type (Settings > Automation > Discovery: new
        # resources), which has its own checked route.
        [ordered]@{ name = 'DiscoveryAutoImportPowerBi'; type = 'bool'; default = $false; inMenu = $false; group = 'discovery'; readBy = 'reader'; fromStore = $false; fromEnvironment = $false }
        [ordered]@{ name = 'DiscoveryAutoImportRules';   type = 'json'; default = @();    inMenu = $false; group = 'discovery'; readBy = 'reader'; fromStore = $false; fromEnvironment = $false }
    )
    foreach ($e in $all) {
        foreach ($k in @('readMin', 'readMax', 'min', 'max', 'unit', 'format', 'itemPattern', 'maxItems', 'refuse')) { if (-not $e.Contains($k)) { $e[$k] = $null } }
        if (-not $e.Contains('fromStore')) { $e['fromStore'] = $true }
        if (-not $e.Contains('fromEnvironment')) { $e['fromEnvironment'] = $true }
        if (-not $e.Contains('storeExact')) { $e['storeExact'] = $false }
    }
    return $all
}

function Get-PimFeatureSettingDefinition {
    <# PURE. The definition of -Name (case-insensitive), or $null. #>
    param([Parameter(Mandatory)][string]$Name)
    $n = "$Name".Trim()
    foreach ($d in @(Get-PimFeatureSettingCatalog)) { if ("$($d.name)" -ieq $n) { return $d } }
    return $null
}

function Test-PimFeatureSettingBlank {
    <# PURE. Is this value "not set"? $null, blank text, an empty list. (false and 0 ARE set.) #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool] -or $Value -is [ValueType]) { return $false }
    if ($Value -is [string]) { return (-not $Value.Trim()) }
    if ($Value -is [System.Collections.IDictionary]) { return ($Value.Count -eq 0) }
    if ($Value -is [System.Collections.IEnumerable]) { foreach ($x in $Value) { return $false }; return $true }
    return (-not "$Value".Trim())
}

function ConvertTo-PimFeatureSettingValue {
    <#
      PURE. One raw value -> @{ set; valid; value; error } for the definition.
        set    the value is not blank
        valid  it is usable as this setting (always $true when not set: the default applies)
        value  the typed value -- the DEFAULT when not set or not valid
      -ForWrite applies the range Settings offers (min / max, the list rules) and requires a real JSON type for a switch
      and a number; without it the reader's own bounds apply (readMin / readMax) and text is read leniently.
    #>
    param([Parameter(Mandatory)][object]$Definition, [AllowNull()][object]$Value, [switch]$ForWrite)
    $d = $Definition
    $def = $d.default
    $bad = { param($why) return [pscustomobject]@{ set = $true; valid = $false; value = $def; error = "$why" } }
    if (Test-PimFeatureSettingBlank -Value $Value) {
        if ($ForWrite -and "$($d.type)" -in @('bool', 'int')) { return (& $bad 'a value is required') }
        if ("$($d.type)" -in @('list', 'json')) { return [pscustomobject]@{ set = $false; valid = $true; value = @($def); error = '' } }
        return [pscustomobject]@{ set = $false; valid = $true; value = $def; error = '' }
    }
    switch ("$($d.type)") {
        'bool' {
            if ($Value -is [bool]) { return [pscustomobject]@{ set = $true; valid = $true; value = [bool]$Value; error = '' } }
            if ($ForWrite) { return (& $bad 'true or false (a JSON boolean) is required -- the text "false" is not a boolean') }
            if ($Value -is [ValueType]) {
                $num = 0.0
                if ([double]::TryParse("$Value", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$num)) {
                    return [pscustomobject]@{ set = $true; valid = $true; value = ($num -ne 0); error = '' }
                }
            }
            $s = "$Value".Trim().ToLowerInvariant()
            if ($s -in @('true', '1', 'yes', 'on')) { return [pscustomobject]@{ set = $true; valid = $true; value = $true; error = '' } }
            if ($s -in @('false', '0', 'no', 'off')) { return [pscustomobject]@{ set = $true; valid = $true; value = $false; error = '' } }
            return (& $bad "'$s' is neither on nor off")
        }
        'int' {
            $n = 0
            $isNum = $false
            if ($Value -is [bool]) { $isNum = $false }
            elseif ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { $n = [long]$Value; $isNum = $true }
            elseif ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
                if ([math]::Floor([double]$Value) -eq [double]$Value -and [math]::Abs([double]$Value) -lt 2000000000) { $n = [long]$Value; $isNum = $true }
            }
            elseif (-not $ForWrite -and "$Value".Trim() -match '^\d{1,9}$') { $n = [long]("$Value".Trim()); $isNum = $true }
            if (-not $isNum) { return (& $bad $(if ($ForWrite) { 'a whole number (a JSON number) is required' } else { 'not a whole number' })) }
            $lo = if ($ForWrite) { $d.min } else { $d.readMin }
            $hi = if ($ForWrite) { $d.max } else { $d.readMax }
            if ($null -ne $lo -and $n -lt [long]$lo) { return (& $bad "must be at least $lo") }
            if ($null -ne $hi -and $n -gt [long]$hi) { return (& $bad "must be at most $hi") }
            if ([math]::Abs($n) -gt 2000000000) { return (& $bad 'the number is too large') }
            return [pscustomobject]@{ set = $true; valid = $true; value = [int]$n; error = '' }
        }
        'list' {
            $items = New-Object System.Collections.Generic.List[string]
            $seen = @{}
            $src = if ($Value -is [string]) { @("$Value" -split '[,;\s]+') } else { @($Value) }
            foreach ($x in $src) {
                if ($null -eq $x) { continue }
                if ($ForWrite -and -not ($x -is [string])) { return (& $bad 'every entry must be text') }
                $t = "$x".Trim()
                if (-not $t) { continue }
                $k = $t.ToLowerInvariant()
                if ($seen.ContainsKey($k)) { continue }
                $seen[$k] = $true
                $items.Add($t)
            }
            if ($items.Count -eq 0) { return [pscustomobject]@{ set = $false; valid = $true; value = @($def); error = '' } }
            if ($ForWrite) {
                if ($null -ne $d.maxItems -and $items.Count -gt [int]$d.maxItems) { return (& $bad "at most $([int]$d.maxItems) entries") }
                foreach ($t in $items) {
                    if ("$($d.itemPattern)" -and $t -notmatch "$($d.itemPattern)") { return (& $bad "'$t' is not a method name (letters and digits only)") }
                    if (@($d.refuse | ForEach-Object { "$_".ToLowerInvariant() }) -contains $t.ToLowerInvariant()) { return (& $bad "'$t' is a weak method and cannot be a required one") }
                }
            }
            return [pscustomobject]@{ set = $true; valid = $true; value = @($items.ToArray()); error = '' }
        }
        'text' {
            $t = if ($Value -is [string]) { $Value.Trim() } elseif ($Value -is [System.Collections.IEnumerable]) { (@($Value | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join '; ') } else { "$Value".Trim() }
            if (-not $t) { return [pscustomobject]@{ set = $false; valid = $true; value = $def; error = '' } }
            if ($ForWrite) {
                if (-not ($Value -is [string])) { return (& $bad 'text is required') }
                if ("$($d.format)" -eq 'emails') {
                    $parts = @($t -split '[,;\s]+' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
                    if ($null -ne $d.maxItems -and $parts.Count -gt [int]$d.maxItems) { return (& $bad "at most $([int]$d.maxItems) addresses") }
                    foreach ($p in $parts) { if ($p -notmatch '^[^@\s<>"'',;]+@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') { return (& $bad "'$p' is not an e-mail address") } }
                    $t = ($parts -join '; ')
                }
                if ($t.Length -gt 2000) { return (& $bad 'the text is too long') }
            }
            return [pscustomobject]@{ set = $true; valid = $true; value = $t; error = '' }
        }
        'json' {
            $v = $Value
            if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { return (& $bad 'not readable as a list') } }
            $arr = @(@($v) | Where-Object { $null -ne $_ -and -not ($_ -is [string]) -and -not ($_ -is [ValueType]) })
            if ($arr.Count -eq 0) { return [pscustomobject]@{ set = $false; valid = $true; value = @($def); error = '' } }
            return [pscustomobject]@{ set = $true; valid = $true; value = $arr; error = '' }
        }
    }
    return (& $bad "unknown type '$($d.type)'")
}

function ConvertTo-PimFeatureSettingStoredValue {
    <#
      PURE. A value that came from the STORE -> @{ set; valid; value; error }, as ConvertTo-PimFeatureSettingValue reads it,
      plus the rule of a definition with storeExact = $true: for such a switch only the real JSON boolean counts (what
      the Settings route writes). Any other stored shape -- the text "true", 1, "on" -- is set but NOT usable: the
      default applies. The engine's reader and the Settings page both read a stored value through this one function.
    #>
    param([Parameter(Mandatory)][object]$Definition, [AllowNull()][object]$Value)
    $c = ConvertTo-PimFeatureSettingValue -Definition $Definition -Value $Value
    if ($Definition['storeExact'] -eq $true -and "$($Definition.type)" -eq 'bool' -and $c.set -and -not ($Value -is [bool])) {
        return [pscustomobject]@{ set = $true; valid = $false; value = $Definition.default; error = 'the stored value is not the true / false that Settings writes (a JSON boolean)' }
    }
    return $c
}

function Get-PimFeatureSettingSource {
    <#
      Where the value of -Name comes from in THIS process: the first that is not blank of
        'process'      $global:PIM_<Name>
        'environment'  the process environment variable PIM_<Name>
        'store'        $global:PIM_NamingConventions[<Name>] (pim.Settings, hydrated by Import-PimSettingsFromStore)
                       -- skipped with -NoStore (a definition with fromStore = $false)
        'default'      nothing is set
      Returns @{ source; raw }.
    #>
    param([Parameter(Mandatory)][string]$Name, [switch]$NoStore, [switch]$NoEnvironment)
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if (-not (Test-PimFeatureSettingBlank -Value $g)) { return [pscustomobject]@{ source = 'process'; raw = $g } }
    if (-not $NoEnvironment) {   # -NoEnvironment: a definition with fromEnvironment = $false (the process variable only)
        $e = [Environment]::GetEnvironmentVariable("PIM_$Name", 'Process')
        if (-not (Test-PimFeatureSettingBlank -Value $e)) { return [pscustomobject]@{ source = 'environment'; raw = $e } }
    }
    if (-not $NoStore -and $global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        $s = $global:PIM_NamingConventions[$Name]
        if (-not (Test-PimFeatureSettingBlank -Value $s)) { return [pscustomobject]@{ source = 'store'; raw = $s } }
    }
    return [pscustomobject]@{ source = 'default'; raw = $null }
}

function Get-PimFeatureSettingState {
    <# The value in effect in THIS process, with where it comes from: @{ name; value; source; set; valid; error; default }. THROWS on a name that is not in the catalog. #>
    param([Parameter(Mandatory)][string]$Name)
    $d = Get-PimFeatureSettingDefinition -Name $Name
    if ($null -eq $d) { throw "Get-PimFeatureSetting: '$Name' is not a feature setting (engine/_shared/PIM-FeatureSettings.ps1 has no definition for it)" }
    $noStore = ($d['fromStore'] -eq $false)
    $noEnv = ($d['fromEnvironment'] -eq $false)
    $src = Get-PimFeatureSettingSource -Name "$($d.name)" -NoStore:$noStore -NoEnvironment:$noEnv
    $c = if ("$($src.source)" -eq 'store') { ConvertTo-PimFeatureSettingStoredValue -Definition $d -Value $src.raw } else { ConvertTo-PimFeatureSettingValue -Definition $d -Value $src.raw }
    $from = if (-not $c.set) { 'default' } else { "$($src.source)" }
    return [pscustomobject]@{ name = "$($d.name)"; value = $c.value; source = $from; set = [bool]$c.set; valid = [bool]$c.valid; error = "$($c.error)"; default = $d.default }
}

function Get-PimFeatureSetting {
    <#
      THE READER. The typed value of -Name in this process: a [bool], an [int], a string, or the entries of a list
      (list / json: wrap the call in @( ) -- a list of one arrives as one item, an empty list as nothing).
      Not set anywhere, or set to something unusable = the default of the catalog (what the code did before).
      THROWS on a name that is not in the catalog (a programming error; the test suite holds every call site's name).
    #>
    param([Parameter(Mandatory)][string]$Name)
    $st = Get-PimFeatureSettingState -Name $Name
    if (-not $st.valid) {
        # said once per name and process: a call site may ask on every row
        if (-not ($global:PIM_FeatureSettingWarned -is [hashtable])) { $global:PIM_FeatureSettingWarned = @{} }
        if (-not $global:PIM_FeatureSettingWarned.ContainsKey($st.name)) {
            $global:PIM_FeatureSettingWarned[$st.name] = $true
            Write-Warning ("[settings] '{0}' is set but not usable ({1}) -- the default applies." -f $st.name, $st.error)
        }
    }
    return $st.value
}
