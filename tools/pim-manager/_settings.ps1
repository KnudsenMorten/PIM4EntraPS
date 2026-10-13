<#
  PIM 100.121 (owner 2026-10-13, decision 10) -- THE SETTINGS THE CODE READ AND THE SETTINGS MENU DID NOT SHOW.
  Dot-sourced by Open-PimManager.ps1 (one line) and served by one route block. Functions only: nothing runs at load.

  THREE THINGS LIVE HERE.

  1. THE FEATURE SETTINGS (GET / PUT /api/settings/feature-settings). The names of engine/_shared/PIM-FeatureSettings.ps1
     that are marked inMenu: each with its default and its allowed range. A SuperAdmin changes one value at a time; the
     value is checked on the SERVER against the range, written to the store setting the code reads (JSON), mirrored into
     the running Manager (Update-PimManagerSettingMirror), read back and audited. "Back to the default" writes JSON null,
     which every reader takes as "not set". With nothing stored every name behaves as it did before this file existed.

  2. AUTOMATIC OFFBOARDING (GET / PUT /api/settings/auto-offboarding) -- pim.Settings 'EnableAutomaticOffboarding', the
     setting the engine's own Test-PimAutoOffboardingEnabled reads. Not set = on in a test tenant, off in a production
     tenant (unchanged).

  3. THE REMOVAL MODE OF THE DAILY RECONCILE (GET / PUT /api/settings/reconcile-removal) -- pim.Settings
     'ReconcileRemovalMode', read by the engine's own Get-PimReconcileRemovalMode. Not set = enforce (unchanged).

  2 and 3 are PROTECTION SWITCHES: a SuperAdmin only (an Admin is refused with the reason, on the server), every change
  needs the confirmation that says what switching does, and every change is audited. Nothing here changes what the engine
  removes while nobody changes the setting: this file never writes on a read, never writes a blank value to the removal
  mode (a blank row would make the engine enforce whatever its environment says), and writes the word enforce only on a
  SuperAdmin's confirmed request.

  NOT HERE: guard limits and the alert recipient (the Guards page), hybrid Active Directory naming, and every platform /
  hosting value (owner 2026-10-13: Settings carries features and configuration only).

  What PIM Manager cannot know is SAID, not guessed: hosted, the engine job is another container and its environment
  cannot be read from here. Literals come from functions (a $script: variable is $null in a child scope behind a load
  guard). ASCII only. Windows PowerShell 5.1 and pwsh 7.
#>

if (-not (Get-Command Get-PimFeatureSetting -ErrorAction SilentlyContinue)) {
    $__pimFeatSetLib = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-FeatureSettings.ps1'
    if (Test-Path -LiteralPath $__pimFeatSetLib) { . $__pimFeatSetLib }
}

# ---- shared small helpers ---------------------------------------------------------------------------------------------
function Get-PimManagerSettingsBodyValue {
    <# PURE. One property of a request body (a dictionary or the object Read-RequestJson hands over); $null when absent. #>
    param([AllowNull()][object]$Body, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Body) { return $null }
    if ($Body -is [System.Collections.IDictionary]) { if ($Body.Contains($Name)) { return $Body[$Name] }; return $null }
    $p = $Body.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}
function Test-PimManagerSettingsBodyHas {
    <# PURE. Does the request body carry the property at all (also when its value is null)? #>
    param([AllowNull()][object]$Body, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Body) { return $false }
    if ($Body -is [System.Collections.IDictionary]) { return [bool]$Body.Contains($Name) }
    return [bool]$Body.PSObject.Properties[$Name]
}
function ConvertFrom-PimManagerSettingsRaw {
    <# PURE. The stored text of a pim.Settings row -> @{ exists; blank; value }. exists = a row is there; blank = the row holds null / "" / nothing. #>
    param([AllowNull()][object]$Raw)
    if ($null -eq $Raw) { return [pscustomobject]@{ exists = $false; blank = $true; value = $null } }
    $t = "$Raw"
    if (-not $t.Trim()) { return [pscustomobject]@{ exists = $true; blank = $true; value = $null } }
    $v = $null
    try { $v = $t | ConvertFrom-Json } catch { $v = $t }
    $isBlank = ($null -eq $v) -or (($v -is [string]) -and -not $v.Trim())
    return [pscustomobject]@{ exists = $true; blank = [bool]$isBlank; value = $v }
}
function Read-PimManagerSettingsRaw {
    <# The stored text of one setting, or $null when there is no row. THROWS when the store cannot be read. -ReadSetting { param($name) } is the test seam. #>
    param([Parameter(Mandatory)][string]$Name, [scriptblock]$ReadSetting)
    if ($ReadSetting) { return (& $ReadSetting $Name) }
    return (Get-PimSqlSettingRaw -ConnectionString (Get-PimManagerSettingCs) -Name $Name)
}
function Write-PimManagerSettingsJson {
    <# Writes the exact JSON text to the store setting and refreshes the running Manager's copy. THROWS on a store error. -WriteSetting { param($name, $json) } is the test seam. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json, [AllowNull()][object]$MirrorValue, [scriptblock]$WriteSetting)
    if ($WriteSetting) { & $WriteSetting $Name $Json; return }
    Set-PimSqlSetting -ConnectionString (Get-PimManagerSettingCs) -Name $Name -ValueJson $Json
    if (Get-Command Update-PimManagerSettingMirror -ErrorAction SilentlyContinue) { Update-PimManagerSettingMirror -Name $Name -Value $MirrorValue }
}
function Test-PimManagerSettingsHosted {
    <# Is the engine another process whose environment this one cannot read? -Hosted overrides (tests). #>
    param([Nullable[bool]]$Hosted = $null)
    if ($null -ne $Hosted) { return [bool]$Hosted }
    return [bool]$script:PimHosted
}
function Get-PimManagerSettingsTenantClass {
    <# 'test' | 'production' | 'unknown', read by the function the engine uses (Resolve-PimEnvironmentClass). -TenantClass overrides (tests). #>
    param([string]$TenantClass)
    $cls = "$TenantClass".Trim().ToLowerInvariant()
    if (-not $cls) {
        $cls = 'unknown'
        if (Get-Command Resolve-PimEnvironmentClass -ErrorAction SilentlyContinue) {
            try { $cls = if ((Resolve-PimEnvironmentClass) -eq 'test') { 'test' } else { 'production' } } catch { $cls = 'unknown' }
        }
    }
    if ($cls -eq 'protected') { $cls = 'production' }
    return $cls
}

# =======================================================================================================================
# 1. THE FEATURE SETTINGS
# =======================================================================================================================
function Get-PimManagerFeatureSettingTexts {
    <#
      PURE. What the Settings cards say per feature setting: the card it sits on, its label, one line of help, and WHERE it
      is read ('manager' = this process; 'engine' = the engine / scheduler at its next run). The long explanation is the
      More info panel (settings-catalog.json).
    #>
    [ordered]@{
        ApprovalRequestTtlHours   = @{ label = 'An approval request expires after'; help = 'A request nobody decided in this time is closed as expired and can no longer be approved.'; readIn = 'manager' }
        BreakGlassChangeTtlHours  = @{ label = 'A change to the emergency access list waits for its second SuperAdmin for at most'; help = 'After this time the request expires and must be raised again.'; readIn = 'manager' }
        OwnerExtendMaxDays        = @{ label = 'Longest extension a department owner may give'; help = 'A department owner cannot move an end date further into the future than this many days from today.'; readIn = 'manager' }
        RequireGroupOwners        = @{ label = 'Refuse to create a group that has no owner'; help = 'Off: the group is created and the missing owner is reported as a warning on every run.'; readIn = 'engine'; envWins = $true }
        StaleGroupDays            = @{ label = 'Report a group as unused when nobody activated it for'; help = 'Shown as a note by the validation; nothing is removed.'; readIn = 'manager' }
        RequiredAuthMethods       = @{ label = 'Sign-in methods an admin account must have (at least one of them)'; help = 'An admin with none of these is reported as a warning by the validation.'; readIn = 'manager' }
        TapCreateLeadHours        = @{ label = 'Issue a Temporary Access Pass this long before its start time'; help = 'A pass that starts later than this is issued by a later run.'; readIn = 'engine'; envWins = $true }
        TapReissueUntilOnboarded  = @{ label = 'Issue a new Temporary Access Pass every time the last one ran out'; help = 'Off: a pass is issued once; a new one is sent with Reset TAP.'; readIn = 'engine'; envWins = $true }
        AdminMailboxForwarding    = @{ label = 'Manage mail forwarding on the mailboxes of admin accounts'; help = 'On: an admin row that asks for forwarding gets it, and forwarding found on a row that does not ask for it is cleared. Needs the Exchange Online permission for the engine.'; readIn = 'engine'; envWins = $true }
        DiscoveryNotifyRecipients = @{ label = 'Send a mail about newly discovered resources to'; help = 'One or more addresses, separated by a semicolon. Empty: no mail.'; readIn = 'engine'; envWins = $true }
        IntakeEnabled             = @{ label = 'Read access requests from the ServiceNow drop store'; help = 'Requests become proposals in Pending changes; nothing is applied without a commit.'; readIn = 'engine' }
    }
}
function Get-PimManagerOwnerExtendMaxDays {
    <#
      REVIEW FIXES 2026-10-13. The stored OwnerExtendMaxDays as the Manager may use it (-Stored = what
      Get-PimManagerSettingObject handed over). A whole number inside the range Settings offers (the catalog's readMin to
      readMax, 1 to 3650) = that number. Nothing stored, not a number, or OUTSIDE the range = 0, which every caller reads
      as "the default" (365 days) -- a stored 100000 used to be honoured (an owner could extend 273 years ahead). One
      warning per process for a value that is set but not usable. Never throws; the catalog not loaded = 0.
    #>
    param([AllowNull()][object]$Stored)
    try {
        if ("$Stored" -notmatch '^\d+$') { return 0 }   # the reading the three call sites always had: digits only
        $d = Get-PimFeatureSettingDefinition -Name 'OwnerExtendMaxDays'
        if ($null -eq $d) { return 0 }
        $c = ConvertTo-PimFeatureSettingStoredValue -Definition $d -Value "$Stored"
        if ($c.set -and $c.valid) { return [int]$c.value }
        if (-not ($global:PIM_FeatureSettingWarned -is [hashtable])) { $global:PIM_FeatureSettingWarned = @{} }
        if (-not $global:PIM_FeatureSettingWarned.ContainsKey('OwnerExtendMaxDays')) {
            $global:PIM_FeatureSettingWarned['OwnerExtendMaxDays'] = $true
            Write-Warning ("[settings] 'OwnerExtendMaxDays' is set but not usable ({0}) -- the default applies." -f $c.error)
        }
        return 0
    } catch { return 0 }
}
function Get-PimManagerFeatureSettingGroups {
    <# PURE. The cards, in page order: key, title, the Settings category, the place the page shows. #>
    @(
        [ordered]@{ key = 'approvals'; title = 'Approval and request limits'; category = 'approvals';  place = 'Settings > Approvals & policy > Approval and request limits' }
        [ordered]@{ key = 'groups';    title = 'Groups';                      category = 'approvals';  place = 'Settings > Approvals & policy > Groups' }
        [ordered]@{ key = 'accounts';  title = 'Admin accounts';              category = 'automation'; place = 'Settings > Automation > Admin accounts' }
        [ordered]@{ key = 'discovery'; title = 'Discovery and intake';        category = 'automation'; place = 'Settings > Automation > Discovery and intake' }
    )
}
function ConvertTo-PimManagerFeatureSettingJson {
    <# PURE. A checked value -> the exact JSON text stored (a list is always a JSON array, also with one entry). #>
    param([Parameter(Mandatory)][object]$Definition, [AllowNull()][object]$Value)
    switch ("$($Definition.type)") {
        'bool' { if ([bool]$Value) { return 'true' } else { return 'false' } }
        'int'  { return ([int]$Value).ToString([Globalization.CultureInfo]::InvariantCulture) }
        'list' { return ('[' + (@(@($Value) | ForEach-Object { ConvertTo-Json -InputObject "$_" -Compress }) -join ',') + ']') }
        default { return (ConvertTo-Json -InputObject "$Value" -Compress) }
    }
}
function Get-PimManagerFeatureSettingItem {
    <#
      One feature setting as the page shows it:
        stored     'set' | 'unset' | 'invalid' (a row is there but its value is not usable: the default applies) |
                   'unknown' (the store could not be read)
        value      the stored value when usable, else the default -- what the store gives a reader
        inEffect   what THIS process reads right now (value + source), for a setting the Manager itself reads
        note       what the page must say besides the value (another source wins; the engine reads it at its next run)
    #>
    param([Parameter(Mandatory)][object]$Definition, [scriptblock]$ReadSetting, [Nullable[bool]]$Hosted = $null)
    $d = $Definition
    $name = "$($d.name)"
    $texts = (Get-PimManagerFeatureSettingTexts)[$name]
    $readIn = if ($texts) { "$($texts.readIn)" } else { 'engine' }
    $stored = 'unknown'; $err = ''; $val = $d.default
    try {
        $raw = ConvertFrom-PimManagerSettingsRaw -Raw (Read-PimManagerSettingsRaw -Name $name -ReadSetting $ReadSetting)
        if (-not $raw.exists -or $raw.blank) { $stored = 'unset' }
        else {
            $c = ConvertTo-PimFeatureSettingStoredValue -Definition $d -Value $raw.value   # the engine's own reading of a STORED value (review fixes 2026-10-13)
            if (-not $c.set) { $stored = 'unset' }
            elseif ($c.valid) { $stored = 'set'; $val = $c.value }
            else { $stored = 'invalid'; $err = "$($c.error)" }
        }
    } catch { $stored = 'unknown'; $err = "$($_.Exception.Message)" }
    $note = ''
    $eff = $null
    if ($readIn -eq 'manager' -and "$($d.readBy)" -eq 'reader') {
        try {
            $s = Get-PimFeatureSettingState -Name $name
            $eff = [ordered]@{ value = $s.value; source = "$($s.source)" }
            if ("$($s.source)" -in @('process', 'environment')) { $note = 'A value set in the environment of PIM Manager itself is in effect and wins over this setting.' }
        } catch { $eff = $null }
    } elseif ($readIn -eq 'engine') {
        $note = 'The engine reads this at its next run.'
        # only where the engine's own reader puts its environment BEFORE the store (not for a name it reads from the store first)
        if ($texts -and $texts.ContainsKey('envWins') -and $texts['envWins'] -and (Test-PimManagerSettingsHosted -Hosted $Hosted)) {
            $note += ' A value set in the environment of the engine job wins over this setting; PIM Manager cannot read that environment from here.'
        }
    }
    if ($stored -eq 'invalid') { $note = ("The stored value is not usable ($err), so the default applies. " + $note).Trim() }
    if ($stored -eq 'unknown') { $note = "The setting could not be read: $err" }
    $isList = ("$($d.type)" -eq 'list')
    return [ordered]@{
        name = $name; type = "$($d.type)"; group = "$($d.group)"; unit = "$($d.unit)"; format = "$($d.format)"
        label = $(if ($texts) { "$($texts.label)" } else { $name }); help = $(if ($texts) { "$($texts.help)" } else { '' }); readIn = $readIn
        default = $(if ($isList) { , @($d.default) } else { $d.default }); min = $d.min; max = $d.max; maxItems = $d.maxItems
        stored = $stored; storedError = $err
        value = $(if ($isList) { , @($val) } else { $val })
        isDefault = [bool]($stored -ne 'set')
        inEffect = $eff; note = $note
    }
}
function Get-PimManagerFeatureSettingsState {
    <# GET /api/settings/feature-settings: the cards and every feature setting shown in Settings. Reads only. #>
    param([scriptblock]$ReadSetting, [Nullable[bool]]$Hosted = $null)
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($d in @(Get-PimFeatureSettingCatalog)) {
        if (-not $d.inMenu) { continue }
        $items.Add((Get-PimManagerFeatureSettingItem -Definition $d -ReadSetting $ReadSetting -Hosted $Hosted))
    }
    return [ordered]@{ groups = @(Get-PimManagerFeatureSettingGroups); settings = @($items.ToArray()) }
}
function Invoke-PimManagerFeatureSettingChange {
    <#
      PUT /api/settings/feature-settings { name, value }  or  { name, reset: true }. Returns @{ status; body }.
      SuperAdmin only (403, said before anything is read). The name must be a feature setting shown in Settings (400: a
      platform value, a guard limit or any other name is refused -- this route can write nothing else). The value must be
      of the setting's type and inside its range (400 with the reason; nothing is saved). reset writes "not set": the
      default applies again. Written as JSON, read back, audited ('settings.feature-setting', before / after).
    #>
    param([AllowNull()][object]$Body, [scriptblock]$ReadSetting, [scriptblock]$WriteSetting, [Nullable[bool]]$Hosted = $null)
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = 'SuperAdmin role required to change a setting. Nothing was saved.' } }
    }
    $name = "$(Get-PimManagerSettingsBodyValue -Body $Body -Name 'name')".Trim()
    $d = if ($name) { Get-PimFeatureSettingDefinition -Name $name } else { $null }
    if ($null -eq $d -or -not $d.inMenu) {
        return @{ status = 400; body = [ordered]@{ ok = $false; error = "'$name' is not a setting that can be changed here. Nothing was saved." } }
    }
    $name = "$($d.name)"
    $reset = ((Get-PimManagerSettingsBodyValue -Body $Body -Name 'reset') -is [bool]) -and [bool](Get-PimManagerSettingsBodyValue -Body $Body -Name 'reset')
    $json = 'null'; $typed = $null
    if (-not $reset) {
        if (-not (Test-PimManagerSettingsBodyHas -Body $Body -Name 'value')) {
            return @{ status = 400; body = [ordered]@{ ok = $false; error = 'value is required (or reset: true to go back to the default). Nothing was saved.' } }
        }
        $v = Get-PimManagerSettingsBodyValue -Body $Body -Name 'value'
        $c = ConvertTo-PimFeatureSettingValue -Definition $d -Value $v -ForWrite
        if (-not $c.valid) { return @{ status = 400; body = [ordered]@{ ok = $false; error = "$name`: $($c.error). Nothing was saved." } } }
        if (-not $c.set) { $reset = $true }   # an empty list / empty text IS "not set": the default applies
        else { $typed = $c.value; $json = ConvertTo-PimManagerFeatureSettingJson -Definition $d -Value $c.value }
    }
    $before = Get-PimManagerFeatureSettingItem -Definition $d -ReadSetting $ReadSetting -Hosted $Hosted
    if ("$($before.stored)" -eq 'unknown') {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting could not be read, so it was NOT changed: $($before.storedError)" } }
    }
    try { Write-PimManagerSettingsJson -Name $name -Json $json -MirrorValue $typed -WriteSetting $WriteSetting }
    catch { return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was NOT saved: $($_.Exception.Message)" } } }
    $after = Get-PimManagerFeatureSettingItem -Definition $d -ReadSetting $ReadSetting -Hosted $Hosted
    $want = if ($reset) { 'unset' } else { 'set' }
    $same = ("$($after.stored)" -eq $want)
    if ($same -and -not $reset) { $same = ((ConvertTo-PimManagerFeatureSettingJson -Definition $d -Value $after.value) -ceq $json) }
    if (-not $same) {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was written but does not read back as saved. Treat it as NOT saved." } }
    }
    Write-PimManagerAuditEvent -Action 'settings.feature-setting' -Target $name `
        -Before ([ordered]@{ stored = "$($before.stored)"; value = $before.value }) `
        -After ([ordered]@{ stored = "$($after.stored)"; value = $after.value }) -Result 'ok'
    $note = if ($reset) { 'Back to the default.' } else { 'Saved.' }
    if ("$($after.note)") { $note += " $($after.note)" }
    return @{ status = 200; body = [ordered]@{ ok = $true; name = $name; note = $note; setting = $after } }
}

# =======================================================================================================================
# 2. AUTOMATIC OFFBOARDING (a protection switch)
# =======================================================================================================================
function Get-PimManagerAutoOffboardingSettingName { 'EnableAutomaticOffboarding' }
function Get-PimManagerAutoOffboardingEnvName     { 'PIM_EnableAutomaticOffboarding' }
function Get-PimManagerAutoOffboardingJobId       { 'admin-offboarding' }
function Get-PimManagerAutoOffboardingPlace       { 'Settings > Approvals & policy > Automatic offboarding' }
function ConvertTo-PimManagerSwitchFlag {
    <# PURE. One value -> $true / $false / $null (not set), in the engine's own vocabulary when it is loaded (Test-PimExplicitFlagValue). #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value".Trim() -eq '') { return $null }
    if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) { return (Test-PimExplicitFlagValue -Value $Value) }
    return ("$Value".Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'y', 'on', 'enable', 'enabled'))
}
function Get-PimManagerAutoOffboardingConfirmText {
    <# PURE. What a SuperAdmin agrees to, per direction. #>
    param([Parameter(Mandatory)][bool]$Enable)
    $job = Get-PimManagerAutoOffboardingJobId
    if ($Enable) {
        return ("Switch automatic offboarding ON? From its next run (the job '$job') the engine acts, without asking again, on every admin account whose offboard date has passed, " +
                "that is marked Retire, or whose status is Revoked: it disables the account, signs it out everywhere, REMOVES its group memberships and eligibilities, and sends the offboarding notice. " +
                "The account itself is never deleted. The account-disable guard still applies and cannot be switched off here. Switching this off again later does not put removed access back.")
    }
    return ("Switch automatic offboarding OFF? The job '$job' will then do nothing for an admin account whose offboard date has passed, that is marked Retire, or whose status is Revoked: " +
            "the group memberships and eligibilities such an account holds STAY until this is switched on again or somebody removes them by hand.")
}
function Get-PimManagerAutoOffboardingState {
    <#
      Everything the card shows:
        stored      'on' | 'off' | 'unset' | 'unknown' (the store could not be read)
        tenantClass 'test' | 'production' | 'unknown'
        env         @{ known; set; value }   known = the engine runs with this process's environment (not hosted)
        effective   'on' | 'off' | 'unknown', source 'environment' | 'setting' | 'default' | 'unknown', text (one line)
      The engine's order is its own process value / environment first, then this setting, then the default of the kind of
      tenant (Test-PimAutoOffboardingEnabled). Seams: -ReadSetting { param($name) }, -TenantClass, -Hosted, -EnvValue, -NoEnvRead.
    #>
    param([scriptblock]$ReadSetting, [string]$TenantClass, [Nullable[bool]]$Hosted = $null, [AllowNull()][object]$EnvValue = $null, [switch]$NoEnvRead)
    $name = Get-PimManagerAutoOffboardingSettingName; $envName = Get-PimManagerAutoOffboardingEnvName
    $stored = 'unknown'; $storedErr = ''
    try {
        $raw = ConvertFrom-PimManagerSettingsRaw -Raw (Read-PimManagerSettingsRaw -Name $name -ReadSetting $ReadSetting)
        $f = if ($raw.exists -and -not $raw.blank) { ConvertTo-PimManagerSwitchFlag -Value $raw.value } else { $null }
        $stored = if ($null -eq $f) { 'unset' } elseif ($f) { 'on' } else { 'off' }
    } catch { $stored = 'unknown'; $storedErr = "$($_.Exception.Message)" }
    $cls = Get-PimManagerSettingsTenantClass -TenantClass $TenantClass
    $isHosted = Test-PimManagerSettingsHosted -Hosted $Hosted
    $ev = $EnvValue
    if ($null -eq $ev -and -not $NoEnvRead) {
        $ev = Get-Variable -Name $envName -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $ev -or "$ev".Trim() -eq '') { $ev = [Environment]::GetEnvironmentVariable($envName, 'Process') }
    }
    $envSet = ($null -ne $ev -and "$ev".Trim() -ne '')
    $envKnown = -not $isHosted
    $eff = 'unknown'; $src = 'unknown'; $text = ''
    if ($envKnown -and $envSet) {
        $ef = ConvertTo-PimManagerSwitchFlag -Value $ev
        $eff = if ($ef) { 'on' } else { 'off' }; $src = 'environment'
        $text = "$eff -- set by the engine's environment ($envName = $("$ev".Trim())), which wins over this setting"
    } elseif ($stored -eq 'unknown') {
        $text = "not known -- the setting could not be read: $storedErr"
    } elseif ($stored -in @('on', 'off')) {
        $eff = $stored; $src = 'setting'; $text = "$stored (set here)"
    } elseif ($cls -eq 'test') {
        $eff = 'on'; $src = 'default'; $text = 'on -- not set; this is a test tenant'
    } elseif ($cls -eq 'production') {
        $eff = 'off'; $src = 'default'; $text = 'off -- not set; this is a production tenant'
    } else {
        $text = 'not known -- not set, and whether this is a test or a production tenant could not be read'
    }
    $envNote = ''
    if (-not $envKnown) { $envNote = "PIM Manager cannot read the environment of the engine job from here. If $envName is set on that job, it wins over this setting." }
    return [ordered]@{
        setting = $name; envName = $envName; place = (Get-PimManagerAutoOffboardingPlace); job = (Get-PimManagerAutoOffboardingJobId)
        stored = $stored; storedError = $storedErr; tenantClass = $cls
        env = [ordered]@{ known = [bool]$envKnown; set = [bool]($envKnown -and $envSet); value = $(if ($envKnown -and $envSet) { "$ev".Trim() } else { '' }) }
        effective = $eff; source = $src; text = $text; envNote = $envNote
        confirmOn = (Get-PimManagerAutoOffboardingConfirmText -Enable $true); confirmOff = (Get-PimManagerAutoOffboardingConfirmText -Enable $false)
    }
}
function Invoke-PimManagerAutoOffboardingChange {
    <#
      PUT /api/settings/auto-offboarding { enabled: true|false, confirm: true }. Returns @{ status; body }.
      SuperAdmin only (403, before anything is read). enabled must be a real JSON boolean (400: the text "false" would read
      as true). EVERY change needs confirm = true (409 with the sentence that says what switching does, per direction).
      Written as JSON true / false to the setting the engine reads, read back, audited ('settings.auto-offboarding').
    #>
    param([AllowNull()][object]$Body, [scriptblock]$ReadSetting, [scriptblock]$WriteSetting, [string]$TenantClass, [Nullable[bool]]$Hosted = $null, [switch]$NoEnvRead)
    $name = Get-PimManagerAutoOffboardingSettingName
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = 'SuperAdmin role required to switch automatic offboarding on or off. Nothing was saved.' } }
    }
    $en = Get-PimManagerSettingsBodyValue -Body $Body -Name 'enabled'
    if (-not ($en -is [bool])) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'enabled (true / false, a JSON boolean) is required. Nothing was saved.' } } }
    $sp = @{ ReadSetting = $ReadSetting; TenantClass = $TenantClass; Hosted = $Hosted; NoEnvRead = [bool]$NoEnvRead }
    $before = Get-PimManagerAutoOffboardingState @sp
    if ("$($before.stored)" -eq 'unknown') {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting could not be read, so it was NOT changed: $($before.storedError)" } }
    }
    $cf = Get-PimManagerSettingsBodyValue -Body $Body -Name 'confirm'
    if (-not (($cf -is [bool]) -and [bool]$cf)) {
        return @{ status = 409; body = [ordered]@{ ok = $false; needsConfirm = $true; enabled = [bool]$en
            confirmText = (Get-PimManagerAutoOffboardingConfirmText -Enable ([bool]$en))
            error = 'Switching automatic offboarding needs your confirmation. Nothing was saved.' } }
    }
    $json = if ($en) { 'true' } else { 'false' }
    try { Write-PimManagerSettingsJson -Name $name -Json $json -MirrorValue ([bool]$en) -WriteSetting $WriteSetting }
    catch { return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was NOT saved: $($_.Exception.Message)" } } }
    $after = Get-PimManagerAutoOffboardingState @sp
    $want = if ($en) { 'on' } else { 'off' }
    if ("$($after.stored)" -ne $want) {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was written but reads back as '$($after.stored)', not '$want'. Treat it as NOT saved." } }
    }
    Write-PimManagerAuditEvent -Action 'settings.auto-offboarding' -Target $name `
        -Before ([ordered]@{ stored = "$($before.stored)"; effective = "$($before.effective)" }) `
        -After ([ordered]@{ stored = "$($after.stored)"; effective = "$($after.effective)" }) -Result 'ok'
    $note = if ($en) { "Automatic offboarding is ON: the job '$(Get-PimManagerAutoOffboardingJobId)' acts on offboarded admin accounts from its next run." }
            else { 'Automatic offboarding is OFF: an offboarded admin account keeps its memberships and eligibilities until this is switched on.' }
    if ("$($after.source)" -eq 'environment') { $note += " The engine's environment ($($after.envName)) still decides: $($after.text)." }
    return @{ status = 200; body = [ordered]@{ ok = $true; enabled = [bool]$en; note = $note; state = $after } }
}

# =======================================================================================================================
# 3. THE REMOVAL MODE OF THE DAILY RECONCILE (a protection switch)
# =======================================================================================================================
function Get-PimManagerReconcileRemovalSettingName { 'ReconcileRemovalMode' }
function Get-PimManagerReconcileRemovalEnvName     { 'PIM_ReconcileRemovalMode' }
function Get-PimManagerReconcileRemovalJobId       { 'full-reconcile' }
function Get-PimManagerReconcileRemovalPlace       { 'Settings > Approvals & policy > Daily reconcile: removal of leftovers' }
function ConvertTo-PimManagerReconcileMode {
    <# PURE. A stored / environment word -> the mode the ENGINE takes from it (its own ConvertTo-PimReconcileRemovalMode when loaded): blank or the word that enforces = 'enforce'; ANY other word = 'report'. #>
    param([AllowNull()][object]$Value)
    if (Get-Command ConvertTo-PimReconcileRemovalMode -ErrorAction SilentlyContinue) { return "$(ConvertTo-PimReconcileRemovalMode -Value $Value)" }
    $s = "$Value".Trim().ToLowerInvariant()
    if (-not $s -or $s -eq 'enforce') { return 'enforce' }
    return 'report'
}
function Get-PimManagerReconcileRemovalLastReport {
    <# The last daily run's own count: @{ known; wouldRemove; mode; atUtc; error }. known = $false when no report could be read -- never a count of 0. -ReadReport { } is the test seam. #>
    param([scriptblock]$ReadReport)
    try {
        $rep = if ($ReadReport) { & $ReadReport } else { Get-PimReconcileRemovalReport -ConnectionString (Get-PimManagerSettingCs) }
        if ($rep -is [string]) { $rep = $rep | ConvertFrom-Json }
        if ($null -eq $rep) { return [ordered]@{ known = $false; wouldRemove = 0; mode = ''; atUtc = ''; error = 'no daily run has reported yet' } }
        $get = { param($n) if ($rep -is [System.Collections.IDictionary]) { $rep[$n] } elseif ($rep.PSObject.Properties[$n]) { $rep.PSObject.Properties[$n].Value } else { $null } }
        $n = 0
        if (-not [int]::TryParse("$(& $get 'wouldRemove')".Trim(), [ref]$n)) { return [ordered]@{ known = $false; wouldRemove = 0; mode = ''; atUtc = ''; error = 'the last report carries no count' } }
        $when = & $get 'generatedUtc'
        if ($when -is [datetime]) { $when = $when.ToUniversalTime().ToString('o') }
        return [ordered]@{ known = $true; wouldRemove = [int]$n; mode = "$(& $get 'mode')"; atUtc = "$when"; error = '' }
    } catch {
        return [ordered]@{ known = $false; wouldRemove = 0; mode = ''; atUtc = ''; error = "$($_.Exception.Message)" }
    }
}
function Get-PimManagerReconcileRemovalConfirmText {
    <# PURE. What a SuperAdmin agrees to, per mode -- with the last daily run's own count when it is known. #>
    param([Parameter(Mandatory)][string]$Mode, [AllowNull()][object]$LastReport)
    $job = Get-PimManagerReconcileRemovalJobId
    if ("$Mode" -eq 'enforce') {
        $cnt = if ($LastReport -and $LastReport.known) {
            if ([int]$LastReport.wouldRemove -eq 1) { 'The last daily run counted 1 item it would remove.' } else { "The last daily run counted $([int]$LastReport.wouldRemove) items it would remove." }
        } else { "How many items the next run would remove is NOT known ($(if ($LastReport) { "$($LastReport.error)" } else { 'no report' }))." }
        return ("Let the daily reconcile REMOVE leftovers? On its next daily run (the job '$job') the engine removes, in your tenant, every live assignment or membership that PIM Manager put there " +
                "and whose definition was removed by a PIM Manager commit, when nothing similar is configured any more. It never disables or deletes an admin account, never removes a shared Defender XDR or Intune assignment, " +
                "and never removes anything that existed before PIM Manager recorded its changes. The removal guard still applies and cannot be switched off here. A removal cannot be undone from this page. $cnt")
    }
    return ("Let the daily reconcile only REPORT leftovers? The engine then removes none of them: an assignment or membership that PIM Manager put in your tenant and whose definition was removed " +
            "STAYS live there until this is set back or somebody removes it by hand. The Jobs page keeps listing what the run would remove.")
}
function Get-PimManagerReconcileRemovalState {
    <#
      Everything the card shows:
        stored      'enforce' | 'report' | 'unset' (no row) | 'blank' (a row with no value) | 'unknown' (not readable);
                    storedWord = the word in the row when it is neither of the two (the engine reads any other word as report)
        effective   'enforce' | 'report' | 'unknown', source 'setting' | 'environment' | 'default' | 'unknown', text
      The engine's order (Get-PimReconcileRemovalMode): a row in the store decides, whatever it holds -- a row with no
      value reads as enforce; only with NO row do the engine's own process value and environment count; then enforce.
      Seams: -ReadSetting { param($name) }, -ReadReport { }, -Hosted, -EnvValue, -NoEnvRead.
    #>
    param([scriptblock]$ReadSetting, [scriptblock]$ReadReport, [Nullable[bool]]$Hosted = $null, [AllowNull()][object]$EnvValue = $null, [switch]$NoEnvRead)
    $name = Get-PimManagerReconcileRemovalSettingName; $envName = Get-PimManagerReconcileRemovalEnvName
    $stored = 'unknown'; $storedErr = ''; $word = ''
    try {
        $raw = ConvertFrom-PimManagerSettingsRaw -Raw (Read-PimManagerSettingsRaw -Name $name -ReadSetting $ReadSetting)
        if (-not $raw.exists) { $stored = 'unset' }
        elseif ($raw.blank) { $stored = 'blank' }
        else {
            $stored = ConvertTo-PimManagerReconcileMode -Value $raw.value
            $w = "$($raw.value)".Trim()
            if ($w.ToLowerInvariant() -notin @('enforce', 'report')) { $word = $w }
        }
    } catch { $stored = 'unknown'; $storedErr = "$($_.Exception.Message)" }
    $isHosted = Test-PimManagerSettingsHosted -Hosted $Hosted
    $ev = $EnvValue
    if ($null -eq $ev -and -not $NoEnvRead) {
        $ev = Get-Variable -Name $envName -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $ev -or "$ev".Trim() -eq '') { $ev = [Environment]::GetEnvironmentVariable($envName, 'Process') }
    }
    $envSet = ($null -ne $ev -and "$ev".Trim() -ne '')
    $envKnown = -not $isHosted
    $eff = 'unknown'; $src = 'unknown'; $text = ''; $envNote = ''
    if ($stored -eq 'unknown') {
        $text = "not known -- the setting could not be read: $storedErr"
    } elseif ($stored -in @('enforce', 'report')) {
        $eff = $stored; $src = 'setting'
        $text = if ($word) { "report only -- the stored word '$word' is not one of the two modes, and the engine reads any other word as report only" }
                elseif ($stored -eq 'enforce') { 'leftovers are removed (set here)' } else { 'report only (set here)' }
    } elseif ($stored -eq 'blank') {
        $eff = 'enforce'; $src = 'setting'; $text = 'leftovers are removed -- the stored value is empty, which the engine reads as the default'
    } elseif ($envKnown -and $envSet) {
        $eff = ConvertTo-PimManagerReconcileMode -Value $ev; $src = 'environment'
        $text = "$(if ($eff -eq 'enforce') { 'leftovers are removed' } else { 'report only' }) -- not set here; the engine's environment says $envName = $("$ev".Trim())"
    } else {
        $eff = 'enforce'; $src = 'default'; $text = 'leftovers are removed -- not set; this is the default'
        if (-not $envKnown) { $envNote = "PIM Manager cannot read the environment of the engine job from here. While nothing is set here, a value of $envName on that job decides." }
    }
    $rep = Get-PimManagerReconcileRemovalLastReport -ReadReport $ReadReport
    return [ordered]@{
        setting = $name; envName = $envName; place = (Get-PimManagerReconcileRemovalPlace); job = (Get-PimManagerReconcileRemovalJobId)
        stored = $stored; storedWord = $word; storedError = $storedErr
        env = [ordered]@{ known = [bool]$envKnown; set = [bool]($envKnown -and $envSet); value = $(if ($envKnown -and $envSet) { "$ev".Trim() } else { '' }) }
        effective = $eff; source = $src; text = $text; envNote = $envNote
        lastReport = $rep
        confirmEnforce = (Get-PimManagerReconcileRemovalConfirmText -Mode 'enforce' -LastReport $rep)
        confirmReport = (Get-PimManagerReconcileRemovalConfirmText -Mode 'report' -LastReport $rep)
    }
}
function Invoke-PimManagerReconcileRemovalChange {
    <#
      PUT /api/settings/reconcile-removal { mode: 'report' | 'enforce', confirm: true, wouldRemove?: <the count the confirmation showed> }.
      Returns @{ status; body }. SuperAdmin only (403, before anything is read). mode must be exactly one of the two words
      (400 -- no other word, no blank and no "back to not set" can be written here: a blank row makes the engine remove
      whatever its environment says). EVERY change needs confirm = true (409 with the sentence). Removing ALSO needs the
      count the person saw to still be the count of the last daily run (409 with the current sentence otherwise) -- nobody
      agrees to "0 items" while the run would remove 40. Written as the JSON word, read back, audited
      ('settings.reconcile-removal-mode').
    #>
    param([AllowNull()][object]$Body, [scriptblock]$ReadSetting, [scriptblock]$WriteSetting, [scriptblock]$ReadReport, [Nullable[bool]]$Hosted = $null, [switch]$NoEnvRead)
    $name = Get-PimManagerReconcileRemovalSettingName
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = 'SuperAdmin role required to change what the daily reconcile removes. Nothing was saved.' } }
    }
    $mv = Get-PimManagerSettingsBodyValue -Body $Body -Name 'mode'
    $mode = if ($mv -is [string]) { $mv.Trim().ToLowerInvariant() } else { '' }
    if ($mode -notin @('report', 'enforce')) {
        return @{ status = 400; body = [ordered]@{ ok = $false; error = "mode must be 'report' or 'enforce'. Nothing was saved." } }
    }
    $sp = @{ ReadSetting = $ReadSetting; ReadReport = $ReadReport; Hosted = $Hosted; NoEnvRead = [bool]$NoEnvRead }
    $before = Get-PimManagerReconcileRemovalState @sp
    if ("$($before.stored)" -eq 'unknown') {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting could not be read, so it was NOT changed: $($before.storedError)" } }
    }
    $cf = Get-PimManagerSettingsBodyValue -Body $Body -Name 'confirm'
    $confirmed = ($cf -is [bool]) -and [bool]$cf
    $now = if ($before.lastReport.known) { [int]$before.lastReport.wouldRemove } else { -1 }
    $text = if ($mode -eq 'enforce') { "$($before.confirmEnforce)" } else { "$($before.confirmReport)" }
    if (-not $confirmed) {
        return @{ status = 409; body = [ordered]@{ ok = $false; needsConfirm = $true; mode = $mode; wouldRemove = $now; confirmText = $text
            error = 'Changing what the daily reconcile removes needs your confirmation. Nothing was saved.' } }
    }
    if ($mode -eq 'enforce') {
        # a count that was not sent (or is no number) matches nothing -- not even "0 items" or "not known" (-1)
        $seen = 0; if (-not [int]::TryParse("$(Get-PimManagerSettingsBodyValue -Body $Body -Name 'wouldRemove')".Trim(), [ref]$seen)) { $seen = -2 }
        if ($seen -ne $now) {
            return @{ status = 409; body = [ordered]@{ ok = $false; needsConfirm = $true; mode = $mode; wouldRemove = $now; confirmText = $text
                error = 'The number of items the daily run would remove changed since you were asked. Read the confirmation again. Nothing was saved.' } }
        }
    }
    $json = ConvertTo-Json -InputObject $mode -Compress
    try { Write-PimManagerSettingsJson -Name $name -Json $json -MirrorValue $mode -WriteSetting $WriteSetting }
    catch { return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was NOT saved: $($_.Exception.Message)" } } }
    $after = Get-PimManagerReconcileRemovalState @sp
    if ("$($after.stored)" -ne $mode -or "$($after.storedWord)") {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the setting was written but reads back as '$($after.stored)', not '$mode'. Treat it as NOT saved." } }
    }
    Write-PimManagerAuditEvent -Action 'settings.reconcile-removal-mode' -Target $name `
        -Before ([ordered]@{ stored = "$($before.stored)"; effective = "$($before.effective)" }) `
        -After ([ordered]@{ stored = "$($after.stored)"; effective = "$($after.effective)"; lastRunWouldRemove = $(if ($after.lastReport.known) { [int]$after.lastReport.wouldRemove } else { $null }) }) -Result 'ok'
    $note = if ($mode -eq 'enforce') { "The daily reconcile REMOVES leftovers from its next run (the job '$(Get-PimManagerReconcileRemovalJobId)'), within the removal guard." }
            else { 'The daily reconcile only REPORTS leftovers: nothing is removed by it until this is changed.' }
    return @{ status = 200; body = [ordered]@{ ok = $true; mode = $mode; note = $note; state = $after } }
}

# =======================================================================================================================
# THE ROUTES (called from the one route block in Open-PimManager.ps1)
# =======================================================================================================================
function Get-PimManagerSettingsRoutePaths {
    <# PURE. The three paths this file serves (GET and PUT each). #>
    @('/api/settings/feature-settings', '/api/settings/auto-offboarding', '/api/settings/reconcile-removal')
}
function Invoke-PimManagerSettingsRoute {
    <#
      One request to one of the three paths -> @{ status; body }. GET (any signed-in role) answers the state with
      canWrite; PUT goes through the change function of that path, which checks the role itself. Anything else = 405.
      -Body is the parsed request body of a PUT.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Method, [AllowNull()][object]$Body)
    $canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
    $m = "$Method".ToUpperInvariant()
    try {
        switch ("$Path") {
            '/api/settings/feature-settings' {
                if ($m -eq 'GET') { $s = Get-PimManagerFeatureSettingsState; $s['canWrite'] = $canWrite; return @{ status = 200; body = $s } }
                if ($m -eq 'PUT') { return (Invoke-PimManagerFeatureSettingChange -Body $Body) }
            }
            '/api/settings/auto-offboarding' {
                if ($m -eq 'GET') { $s = Get-PimManagerAutoOffboardingState; $s['canWrite'] = $canWrite; return @{ status = 200; body = $s } }
                if ($m -eq 'PUT') { return (Invoke-PimManagerAutoOffboardingChange -Body $Body) }
            }
            '/api/settings/reconcile-removal' {
                if ($m -eq 'GET') { $s = Get-PimManagerReconcileRemovalState; $s['canWrite'] = $canWrite; return @{ status = 200; body = $s } }
                if ($m -eq 'PUT') { return (Invoke-PimManagerReconcileRemovalChange -Body $Body) }
            }
        }
    } catch {
        return @{ status = 500; body = [ordered]@{ ok = $false; error = "the request failed. Reload the page to see what is stored before trying again: $($_.Exception.Message)" } }
    }
    return @{ status = 405; body = [ordered]@{ ok = $false; error = 'method not allowed' } }
}
