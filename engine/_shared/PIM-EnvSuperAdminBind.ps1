# PIM-EnvSuperAdminBind.ps1 -- ENV-SUPERADMIN-BIND-1 (Invardia 2026-11-22, security): a SuperAdmin named in the Manager's
# container setting PIM_SuperAdmins is matched by its Entra OBJECT ID, never by its sign-in name alone.
#   1. The UPDATER (Invoke-PimEsbUpdaterStep, update-job-entry.ps1 step 2d-esb) reads PIM_SuperAdmins on the Manager app (ARM)
#      and resolves each entry ONCE through Microsoft Graph (its User.ReadBasic.All: GET /users/{name}) to exactly one user
#      whose userPrincipalName IS that name. It records pim.Settings 'EnvSuperAdminBinding' { v; source; readUtc; entries[] =
#      { identity; objectId; state = bound | unresolved; code; boundUtc } }. A BOUND entry is never resolved again (a sign-in
#      name re-used for someone else later inherits nothing). An entry that does not resolve to exactly one user is
#      'unresolved' and is tried again on the next run. A name taken out of the setting leaves the record.
#   2. The MANAGER (Open-PimManager.ps1, Resolve role) grants SuperAdmin from PIM_SuperAdmins ONLY when the hosted request's
#      verified object id equals the bound object id of that name (Test-PimEsbGrant). No binding, unresolved, another object
#      id, or a request without an object id = NOT granted (the sign-in name alone never grants SuperAdmin).
#   3. The HEARTBEAT reports the counts only (Get-PimEsbCounts -> FirstAdminSeed.settingSuperAdmins { viaSetting; bound;
#      unresolved }) and counts a bound one as "a SuperAdmin exists" (BUG-FAS-ENV-1). Never a name, never an object id.
# Everything is PURE except Invoke-PimEsbUpdaterStep, whose I/O goes through seams (-Arm, -Graph, -GetSetting, -SetSetting).

function Get-PimEsbSettingName { <# PURE. LITERAL. #> return 'EnvSuperAdminBinding' }
function Get-PimEsbEnvName { <# PURE. LITERAL. The Manager's container setting. #> return 'PIM_SuperAdmins' }

function Get-PimEsbField {
    <# PURE. A field of a hashtable or an object ($null when absent). #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Test-PimEsbGuid { <# PURE. #> param([AllowNull()][string]$Value) return ("$Value".Trim() -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') }

function ConvertTo-PimEsbNames {
    <# PURE. The PIM_SuperAdmins value (names split on , or ;) -> distinct lower-case names, in order. #>
    param([AllowNull()][AllowEmptyString()][string]$Raw)
    $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @("$Raw" -split '[,;]+')) { $k = "$n".Trim().ToLowerInvariant(); if ($k -and -not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add($k) } }
    return @($out.ToArray())
}

function ConvertFrom-PimEsbStored {
    <# PURE. The stored record (JSON text, an object, $null) -> its entries (identity lower-case). Unreadable text = THROWS. #>
    param([AllowNull()][object]$Stored)
    if ($null -eq $Stored) { return @() }
    $v = $Stored
    if ($v -is [string]) { if (-not "$v".Trim()) { return @() }; $v = "$v" | ConvertFrom-Json -ErrorAction Stop }
    return @(@(Get-PimEsbField $v 'entries') | Where-Object { $null -ne $_ -and "$(Get-PimEsbField $_ 'identity')".Trim() })
}

function Test-PimEsbSignInName { <# PURE. Looks like a sign-in name (user@domain.tld) -- the only thing the directory resolves. #> param([string]$Name) return ("$Name" -match '^[^@\s;,''/\\?#]+@[^@\s;,''/\\?#]+\.[^@\s;,''/\\?#]+$') }

function Get-PimEsbLookupPath {
    <# PURE. The ONE directory read of a name (Graph v1.0, relative; basic profile only). #>
    param([Parameter(Mandatory)][string]$Name)
    return ('/users/' + [uri]::EscapeDataString("$Name".Trim()) + '?$select=id,userPrincipalName')
}

function Resolve-PimEsbAnswer {
    <#
      PURE. One directory answer for -Name -> @{ ok; objectId; code }. ok only when the answer is ONE user with a GUID id and
      its userPrincipalName IS the name (case-insensitive): a mail alias or another account is not that person.
      -Answer: the user object, $null (= not found), or @{ error = '<text>' } (= the lookup failed).
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Answer)
    if ($null -eq $Answer) { return @{ ok = $false; objectId = ''; code = 'not-found' } }
    if ("$(Get-PimEsbField $Answer 'error')".Trim()) { return @{ ok = $false; objectId = ''; code = 'lookup-failed' } }
    $hasList = if ($Answer -is [System.Collections.IDictionary]) { $Answer.Contains('value') } else { [bool]$Answer.PSObject.Properties['value'] }
    $vals = Get-PimEsbField $Answer 'value'
    if ($hasList) { $list = @($vals | Where-Object { $_ }); if ($list.Count -ne 1) { return @{ ok = $false; objectId = ''; code = $(if ($list.Count) { 'ambiguous' } else { 'not-found' }) } }; $Answer = $list[0] }
    $id = "$(Get-PimEsbField $Answer 'id')".Trim(); $upn = "$(Get-PimEsbField $Answer 'userPrincipalName')".Trim()
    if (-not (Test-PimEsbGuid $id)) { return @{ ok = $false; objectId = ''; code = 'no-id' } }
    if ($upn -ine "$Name".Trim()) { return @{ ok = $false; objectId = ''; code = 'other-account' } }
    return @{ ok = $true; objectId = $id.ToLowerInvariant(); code = '' }
}

function Get-PimEsbPlan {
    <#
      PURE. The new record for -Names (the setting today) against -Stored (the record). -Found: name -> Resolve-PimEsbAnswer
      for every name that was looked up this run. A BOUND stored entry for a name still in the setting is KEPT as it is
      (never resolved again). A name not bound: bound when -Found says ok, else unresolved with the code ('not-looked-up'
      when it was not looked up, 'not-a-sign-in-name' for anything that is not user@domain). Names gone from the setting drop
      out. Returns @{ record; changed; toLookUp = @(names that need a lookup) }.
    #>
    param([AllowEmptyCollection()][string[]]$Names = @(), [AllowNull()][object]$Stored = $null, [hashtable]$Found = @{}, [string]$NowUtc = ([datetime]::UtcNow.ToString('o')))
    $old = @{}; foreach ($e in @(ConvertFrom-PimEsbStored -Stored $Stored)) { $old["$(Get-PimEsbField $e 'identity')".Trim().ToLowerInvariant()] = $e }
    $entries = New-Object System.Collections.Generic.List[object]; $look = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names)) {
        $k = "$n".Trim().ToLowerInvariant(); if (-not $k) { continue }
        $o = $old[$k]
        if ($o -and "$(Get-PimEsbField $o 'state')" -ceq 'bound' -and (Test-PimEsbGuid "$(Get-PimEsbField $o 'objectId')")) {
            # boundUtc kept as ISO text (ConvertFrom-Json turns an ISO string into a DateTime)
            $bu = Get-PimEsbField $o 'boundUtc'; $bu = if ($bu -is [datetime]) { $bu.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { "$bu" }
            $entries.Add([ordered]@{ identity = $k; objectId = "$(Get-PimEsbField $o 'objectId')".ToLowerInvariant(); state = 'bound'; code = ''; boundUtc = $bu }); continue
        }
        if (-not (Test-PimEsbSignInName $k)) { $entries.Add([ordered]@{ identity = $k; objectId = ''; state = 'unresolved'; code = 'not-a-sign-in-name'; boundUtc = '' }); continue }
        if ($Found -and $Found.ContainsKey($k)) {
            $f = $Found[$k]
            if ([bool](Get-PimEsbField $f 'ok')) { $entries.Add([ordered]@{ identity = $k; objectId = "$(Get-PimEsbField $f 'objectId')"; state = 'bound'; code = ''; boundUtc = $NowUtc }) }
            else { $entries.Add([ordered]@{ identity = $k; objectId = ''; state = 'unresolved'; code = "$(Get-PimEsbField $f 'code')"; boundUtc = '' }) }
        } else { $look.Add($k); $entries.Add([ordered]@{ identity = $k; objectId = ''; state = 'unresolved'; code = 'not-looked-up'; boundUtc = '' }) }
    }
    $rec = [ordered]@{ v = 1; source = (Get-PimEsbEnvName); readUtc = $NowUtc; entries = @($entries.ToArray()) }
    $sig = { param($list) (@($list | ForEach-Object { "$(Get-PimEsbField $_ 'identity')|$(Get-PimEsbField $_ 'objectId')|$(Get-PimEsbField $_ 'state')|$(Get-PimEsbField $_ 'code')" }) -join ';') }
    $changed = ((& $sig @($old.Values | Sort-Object { "$(Get-PimEsbField $_ 'identity')" })) -ne (& $sig @($rec.entries | Sort-Object { "$($_.identity)" })))
    return @{ record = $rec; changed = $changed; toLookUp = @($look.ToArray()) }
}

function Test-PimEsbGrant {
    <#
      PURE. May -Identity (a name in PIM_SuperAdmins) be SuperAdmin on THIS request? Only when -Binding holds that name BOUND
      and -ObjectId (the request's VERIFIED oid) is that bound object id. Returns @{ grant; reason }.
    #>
    param([AllowNull()][object]$Binding, [AllowEmptyString()][string]$Identity = '', [AllowEmptyString()][string]$ObjectId = '')
    $k = "$Identity".Trim().ToLowerInvariant()
    $entries = @(); try { $entries = @(ConvertFrom-PimEsbStored -Stored $Binding) } catch { return @{ grant = $false; reason = 'the SuperAdmin binding is not readable' } }
    $e = @($entries | Where-Object { "$(Get-PimEsbField $_ 'identity')".Trim().ToLowerInvariant() -eq $k }) | Select-Object -First 1
    if (-not $e) { return @{ grant = $false; reason = 'not bound to an Entra object id yet (the next update binds it)' } }
    if ("$(Get-PimEsbField $e 'state')" -cne 'bound') { return @{ grant = $false; reason = "not resolved to exactly one user ($(Get-PimEsbField $e 'code'))" } }
    if (-not (Test-PimEsbGuid $ObjectId)) { return @{ grant = $false; reason = 'this request carries no verified object id' } }
    if ("$ObjectId".Trim().ToLowerInvariant() -ne "$(Get-PimEsbField $e 'objectId')".Trim().ToLowerInvariant()) { return @{ grant = $false; reason = 'bound to a different Entra object (a re-used sign-in name)' } }
    return @{ grant = $true; reason = '' }
}

function Get-PimEsbCounts {
    <# PURE. The heartbeat's counts: @{ viaSetting; bound; unresolved } (no names). $null when the record is unreadable. #>
    param([AllowNull()][object]$Binding)
    $entries = @(); try { $entries = @(ConvertFrom-PimEsbStored -Stored $Binding) } catch { return $null }
    $b = @($entries | Where-Object { "$(Get-PimEsbField $_ 'state')" -ceq 'bound' }).Count
    return [ordered]@{ viaSetting = $entries.Count; bound = $b; unresolved = ($entries.Count - $b) }
}

function Invoke-PimEsbUpdaterStep {
    <#
      THE UPDATER'S STEP. Reads PIM_SuperAdmins on the Manager app (-Arm GET -AppPath), resolves the names not yet bound
      (-Graph GET; a 404 or $null = not found), writes the record when it changed and READS IT BACK. Never throws, never
      changes a role, never writes the Manager app. Returns @{ ok; counts; lines[] (@{ level; text }) } -- names never in a line.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][scriptblock]$GetSetting,
          [Parameter(Mandatory)][scriptblock]$SetSetting, [Parameter(Mandatory)][string]$AppPath, [string]$NowUtc = ([datetime]::UtcNow.ToString('o')))
    $out = [ordered]@{ ok = $false; counts = $null; lines = ([System.Collections.Generic.List[object]]::new()) }
    $say = { param($l, $t) $out.lines.Add([pscustomobject]@{ level = $l; text = $t }) }
    try {
        $app = & $Arm 'GET' $AppPath $null
        $raw = ''
        foreach ($c in @(Get-PimEsbField (Get-PimEsbField (Get-PimEsbField $app 'properties') 'template') 'containers')) {
            foreach ($e in @(Get-PimEsbField $c 'env')) { if ("$(Get-PimEsbField $e 'name')" -ceq (Get-PimEsbEnvName)) { $raw = "$(Get-PimEsbField $e 'value')" } }
        }
        $names = @(ConvertTo-PimEsbNames -Raw $raw)
        $stored = & $GetSetting (Get-PimEsbSettingName)
        if (-not $names.Count -and -not @(ConvertFrom-PimEsbStored -Stored $stored).Count) {
            $out.ok = $true; $out.counts = [ordered]@{ viaSetting = 0; bound = 0; unresolved = 0 }
            & $say 'info' 'SuperAdmins in the Manager setting: none (nothing to bind)'; return $out
        }
        $plan = Get-PimEsbPlan -Names $names -Stored $stored -NowUtc $NowUtc
        $found = @{}
        foreach ($n in @($plan.toLookUp)) {
            $ans = $null
            try { $ans = & $Graph 'GET' (Get-PimEsbLookupPath -Name $n) $null }
            catch { $m = "$($_.Exception.Message)"; $ans = $(if ($m -match '(?i)\b404\b|NotFound|Request_ResourceNotFound') { $null } else { @{ error = 'lookup failed' } }) }
            $found[$n] = Resolve-PimEsbAnswer -Name $n -Answer $ans
        }
        if ($found.Count) { $plan = Get-PimEsbPlan -Names $names -Stored $stored -Found $found -NowUtc $NowUtc }
        $counts = Get-PimEsbCounts -Binding $plan.record
        if ($plan.changed) {
            & $SetSetting (Get-PimEsbSettingName) (ConvertTo-Json -InputObject $plan.record -Depth 6 -Compress)
            $back = Get-PimEsbCounts -Binding (& $GetSetting (Get-PimEsbSettingName))
            if ($null -eq $back -or $back.viaSetting -ne $counts.viaSetting -or $back.bound -ne $counts.bound) { & $say 'warn' 'the SuperAdmin binding did not read back -- nobody from the Manager setting is granted until it does'; $out.counts = $back; return $out }
            & $say 'changed' "SuperAdmins in the Manager setting bound to their Entra object id: $($counts.bound) of $($counts.viaSetting) (read back)"
        } else { & $say 'info' "SuperAdmins in the Manager setting: $($counts.bound) of $($counts.viaSetting) bound (unchanged)" }
        if ([int]$counts.unresolved) { & $say 'warn' "$($counts.unresolved) SuperAdmin entr$(if ($counts.unresolved -eq 1) { 'y' } else { 'ies' }) in the Manager setting did not resolve to exactly one user -- NOT granted; a SuperAdmin adds them in PIM Manager > Settings > Manager access & roles, or corrects the setting" }
        $out.ok = $true; $out.counts = $counts; return $out
    } catch { & $say 'warn' "the SuperAdmin binding was not checked: $((("$($_.Exception.Message)") -split "`n")[0])"; return $out }
}
