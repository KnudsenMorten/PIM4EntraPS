#Requires -Version 5.1
######################################################################################################################
# Increase PowerShell function table limit before loading modules.
# Default is 4096 which is too low for multiple large Graph SDK modules in a single session.
# Maximum allowed value in PowerShell 5.1 is 32768.
######################################################################################################################

$MaximumFunctionCount = 32768

######################################################################################################################
# Strip PowerShell 7 module paths from PSModulePath when running in PS 5.1.
#
# Why: PS7's PackageManagement folder under '<Program Files>\PowerShell\7\Modules\' contains a
# 'fullclr' subfolder that PS 5.1 will eagerly probe -- but the matching DLL is missing in PS7's
# distribution (PS7 only ships 'coreclr'). Result: any module that pulls PackageManagement (e.g.
# ExchangeOnlineManagement) fails to load with "no valid module file was found".
######################################################################################################################

if ($PSVersionTable.PSVersion.Major -lt 7) {
    $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -and ($_ -notmatch '\\PowerShell\\7\\') }) -join ';'
}

######################################################################################################################
# Module-level imports — loaded ONCE when the module is imported, never inside functions or loops.
# This prevents the PowerShell function table (4096 limit) from overflowing.
######################################################################################################################

$_PIM_ModulesToLoad = @(
    'Microsoft.Graph.DeviceManagement.Enrollment',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Identity.SignIns',              # Update-MgPolicyRoleManagementPolicyRule
    'Microsoft.Graph.Groups',
    'AzLogDcrIngestPS'
)

ForEach ($_mod in $_PIM_ModulesToLoad) {
    If (-not (Get-Module -Name $_mod -ErrorAction SilentlyContinue)) {
        Import-Module $_mod -Global -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }
}

function Ensure-DateTime {
    <#
        .SYNOPSIS
        Converts many date/time inputs to [datetime], regardless of regional format. Works in Windows PowerShell 5.1.

        .NOTES
        - Tries CurrentCulture first (so de-DE, da-DK, en-GB, etc. just work).
        - Falls back to InvariantCulture and en-US.
        - Supports ISO 8601, RFC 1123, common US & EU patterns, 24h variants.
        - Supports Unix epoch (10-digit seconds, 13-digit milliseconds).
        - Accepts [datetime], [datetimeoffset], and strings.
    #>
    param(
        # NOTE: NOT Mandatory + NOT a strict [datetime] type so $null upstream
        # values fall through to the "treat as far-future" branch below instead
        # of triggering a "Cannot bind argument to parameter 'InputObject' because
        # it is null" parameter-binding error. The upstream code path is the
        # (Get-Date)..(Ensure-DateTime $ExpirationDate) pipeline where
        # CorrelateDateTimeLanguage returns $null on an unparseable date --
        # without this we crash the engine at line 1196 of the baseline engine.
        [Parameter(ValueFromPipeline = $true)]
        [object]$InputObject,
        [switch]$AssumeLocal
    )

    # Null / empty / unparseable upstream -> return a far-future date so any
    # downstream `(New-TimeSpan -End ...).TotalDays` returns a large number,
    # and the typical "is this expiring in <30 days?" check is just false.
    # Upstream is expected to have already emitted its own warning explaining
    # WHY the date was unparseable; we don't double-warn here.
    if ($null -eq $InputObject) { return (Get-Date).AddYears(99) }

    # Pass through
    if ($InputObject -is [datetime]) { return $InputObject }
    if ($InputObject -is [datetimeoffset]) {
        if ($AssumeLocal) {
            return ($InputObject).LocalDateTime
        } else {
            return ($InputObject).UtcDateTime
        }
    }

    # Normalize string
    $s = [string]$InputObject
    if ([string]::IsNullOrWhiteSpace($s)) {
        # Same defensive return as the null branch above -- empty strings
        # come from blank CSV cells and should not crash the engine.
        return (Get-Date).AddYears(99)
    }
    $s = $s.Trim()

    # Epoch detection (numbers only)
    if ($s -match '^\d{10}$') {
        # seconds since 1970-01-01 UTC
        $epochBase = [datetime]::SpecifyKind([datetime]::ParseExact('1970-01-01','yyyy-MM-dd',[System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc)
        $epoch = $epochBase.AddSeconds([int64]$s).ToLocalTime()
        return $epoch
    }
    if ($s -match '^\d{13}$') {
        # milliseconds since 1970-01-01 UTC
        $epochBase = [datetime]::SpecifyKind([datetime]::ParseExact('1970-01-01','yyyy-MM-dd',[System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc)
        $epoch = $epochBase.AddMilliseconds([int64]$s).ToLocalTime()
        return $epoch
    }

    $stylesCommon = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
    $stylesLocal  = [System.Globalization.DateTimeStyles]::AssumeLocal
    $cur  = [System.Globalization.CultureInfo]::CurrentCulture
    $inv  = [System.Globalization.CultureInfo]::InvariantCulture
    $enUS = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')

    # If contains timezone/offset or 'T', try DateTimeOffset first (more forgiving for offsets)
    $dto = [datetimeoffset]::MinValue
    if ($s -match 'Z|[+-]\d{2}:\d{2}|T') {
        if ([datetimeoffset]::TryParse($s, $inv, $stylesCommon, [ref]$dto)) {
            if ($AssumeLocal) {
                return $dto.LocalDateTime
            } else {
                return $dto.UtcDateTime
            }
        }
        if ([datetimeoffset]::TryParse($s, $cur, $stylesCommon, [ref]$dto)) {
            if ($AssumeLocal) {
                return $dto.LocalDateTime
            } else {
                return $dto.UtcDateTime
            }
        }
    }

    # Broad tries with CurrentCulture / Invariant / en-US
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($s, $cur, $stylesCommon, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse($s, $inv, $stylesCommon, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse($s, $enUS, $stylesCommon, [ref]$parsed)) { return $parsed }

    # Comprehensive exact formats (US + EU + ISO + common logs)
    $formats = @(
        # ISO 8601 variants
        'o','yyyy-MM-ddTHH:mm:ssK','yyyy-MM-ddTHH:mm:ss.fffK','yyyy-MM-ddTHH:mm:ss','yyyy-MM-ddTHH:mm:ss.fff',
        'yyyy-MM-dd HH:mm:ss','yyyy-MM-dd',
        # RFC1123 / RFC850 / asctime
        'r','R','ddd, dd MMM yyyy HH:mm:ss GMT','dddd, dd-MMM-yy HH:mm:ss GMT','ddd MMM  d HH:mm:ss yyyy',
        # US
        'M/d/yyyy h:mm:ss tt','M/d/yyyy h:mm tt','M/d/yyyy','MM/dd/yyyy HH:mm:ss','MM/dd/yyyy',
        # EU day-first with dots/slashes/spaces
        'dd/MM/yyyy HH:mm:ss','dd/MM/yyyy','d/M/yyyy HH:mm','d/M/yyyy',
        'dd.MM.yyyy HH:mm:ss','dd.MM.yyyy','d.M.yyyy HH:mm','d.M.yyyy',
        'dd-MM-yyyy HH:mm:ss','dd-MM-yyyy','d-M-yyyy HH:mm','d-M-yyyy',
        # 24h with minutes only
        'yyyy-MM-dd HH:mm','dd/MM/yyyy HH:mm','dd.MM.yyyy HH:mm','dd-MM-yyyy HH:mm','M/d/yyyy H:mm','MM/dd/yyyy H:mm'
    )

    if ([datetime]::TryParseExact($s, $formats, $cur, $stylesLocal, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParseExact($s, $formats, $inv, $stylesLocal, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParseExact($s, $formats, $enUS, $stylesLocal, [ref]$parsed)) { return $parsed }

    throw "Ensure-DateTime: Could not parse value '$InputObject' into a DateTime with CurrentCulture '$($cur.Name)'."
}

function Get-AzPimTokenCached {
    <#
    .SYNOPSIS
        Returns a cached ARM bearer-token header hashtable, refreshing
        only when expired or on a forced refresh. Drop-in replacement
        for Get-AzAccessTokenManagement inside loops.

    .DESCRIPTION
        ARM tokens are valid 60-90 min. Calling Get-AzAccessToken inside
        a per-scope loop refreshes the MSAL cache hit ~50ms x N times for
        no reason. This helper holds the last-issued token in a script-
        scoped cache + refreshes when:
          * cache is empty (first call)
          * token expires within ExpiryBufferSeconds (default 300)
          * caller passes -Force
          * caller passes -RefreshOn401 after seeing a 401 in a downstream call

        Shape is identical to Get-AzAccessTokenManagement so it is a true
        drop-in replacement (Content-Type/Accept/Authorization keys).

    .PARAMETER ExpiryBufferSeconds
        Refresh if the cached token expires within this many seconds.
        Default 300 (5 min) -- long enough that a loop won't see the token
        expire mid-iteration but short enough that we don't sit on an
        expired token.

    .PARAMETER Force
        Always refresh, ignore the cache.

    .PARAMETER RefreshOn401
        Refresh the cache. Use this when a downstream call returned 401
        Unauthorized -- forces re-mint before the next call.

    .OUTPUTS
        [hashtable]@{ 'Content-Type'='application/json'; 'Accept'='application/json'; 'Authorization'="Bearer <token>" }
        Identical shape to what Get-AzAccessTokenManagement returns today.
    #>
    [CmdletBinding()]
    param(
        [int]$ExpiryBufferSeconds = 300,
        [switch]$Force,
        [switch]$RefreshOn401
    )

    # Decide whether the cache is still good.
    $needRefresh = $false
    if ($Force -or $RefreshOn401) {
        $needRefresh = $true
    }
    elseif (-not $script:AzPimTokenCache) {
        $needRefresh = $true
    }
    elseif (-not $script:AzPimTokenCache.Headers) {
        $needRefresh = $true
    }
    elseif (-not $script:AzPimTokenCache.ExpiresOn) {
        # Unknown expiry (older Az.Accounts shape) -- treat as expired to be safe.
        $needRefresh = $true
    }
    else {
        $now = Get-Date
        $expires = $script:AzPimTokenCache.ExpiresOn
        $secondsLeft = ($expires - $now).TotalSeconds
        if ($secondsLeft -le $ExpiryBufferSeconds) {
            $needRefresh = $true
        }
    }

    if (-not $needRefresh) {
        return $script:AzPimTokenCache.Headers
    }

    # Mint a fresh token. Az.Accounts 2.13+ returns PSAccessToken with .Token (string) + .ExpiresOn.
    # Older versions return .Token as SecureString and may not expose ExpiresOn. Handle both.
    $tokenObj = $null
    try {
        $tokenObj = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    } catch {
        # If the modern parameter is rejected (older Az.Accounts), fall back to -Resource.
        try {
            $tokenObj = Get-AzAccessToken -Resource 'https://management.azure.com' -ErrorAction Stop
        } catch {
            throw "Get-AzPimTokenCached: Get-AzAccessToken failed: $($_.Exception.Message)"
        }
    }

    # Extract token string (handle both string and SecureString shapes).
    $tokenString = $null
    if ($tokenObj -and $tokenObj.Token) {
        if ($tokenObj.Token -is [string]) {
            $tokenString = $tokenObj.Token
        }
        elseif ($tokenObj.Token -is [System.Security.SecureString]) {
            # PS 5.1 has no -AsPlainText on ConvertFrom-SecureString; round-trip via PSCredential.
            $cred = New-Object System.Management.Automation.PSCredential('x', $tokenObj.Token)
            $tokenString = $cred.GetNetworkCredential().Password
        }
        else {
            $tokenString = [string]$tokenObj.Token
        }
    }

    if ([string]::IsNullOrEmpty($tokenString)) {
        throw "Get-AzPimTokenCached: Get-AzAccessToken returned an empty token."
    }

    # Resolve expiry. ExpiresOn is DateTimeOffset on modern Az.Accounts; older versions may not expose it.
    $expiresOnDt = $null
    if ($tokenObj -and ($tokenObj.PSObject.Properties.Name -contains 'ExpiresOn')) {
        $exp = $tokenObj.ExpiresOn
        if ($exp -is [System.DateTimeOffset]) {
            $expiresOnDt = $exp.LocalDateTime
        }
        elseif ($exp -is [datetime]) {
            $expiresOnDt = $exp
        }
    }
    if (-not $expiresOnDt) {
        # Conservative fallback: assume a 50-minute lifetime so we still benefit from caching
        # without sitting on a stale token across a long batch.
        $expiresOnDt = (Get-Date).AddMinutes(50)
    }

    $headers = @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $tokenString"
    }

    $script:AzPimTokenCache = @{
        Headers   = $headers
        ExpiresOn = $expiresOnDt
        IssuedAt  = Get-Date
    }

    return $headers
}

Function CorrelateDateTimeLanguage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$DateInput
    )

    if ($DateInput -is [datetime]) {
        Write-Verbose "Input already a DateTime object"
        return $DateInput
    }

    $DateInput = $DateInput.ToString().Trim()

    # Generic, culture-agnostic parse. Tries a broad set of cultures with TryParse first
    # (handles virtually every well-formed timestamp .NET can recognize regardless of
    # 12/24h, separator, ordering, or zone suffix), then falls back to a small list of
    # explicit ParseExact formats for any oddball strings .NET can't auto-detect.
    $cultures = @(
        [CultureInfo]::InvariantCulture,
        [CultureInfo]::GetCultureInfo("en-US"),
        [CultureInfo]::GetCultureInfo("en-GB"),
        [CultureInfo]::GetCultureInfo("da-DK"),
        [CultureInfo]::CurrentCulture
    ) | Select-Object -Unique

    # AssumeUniversal=64 + AdjustToUniversal=16 -> 80; AssumeLocal=32; None=0.
    # Listed as int to avoid PS7-strict-mode enum -bor issues.
    $styles = @(
        [System.Globalization.DateTimeStyles]([int]([System.Globalization.DateTimeStyles]::AssumeUniversal) -bor [int]([System.Globalization.DateTimeStyles]::AdjustToUniversal)),
        [System.Globalization.DateTimeStyles]::AssumeLocal,
        [System.Globalization.DateTimeStyles]::None
    )

    foreach ($culture in $cultures) {
        foreach ($style in $styles) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse($DateInput, $culture, $style, [ref]$parsed)) {
                Write-Debug "Parsed via TryParse culture='$($culture.Name)' style=$style"
                return $parsed
            }
        }
    }

    # Explicit fallbacks for formats .NET's auto-detect rejects in some cultures
    $formats = @(
        "M/d/yyyy h:mm:ss tt",
        "M/d/yyyy H:mm:ss",
        "MM/dd/yyyy HH:mm:ss",
        "MM/dd/yyyy H:mm:ss",
        "dd-MM-yyyy HH:mm:ss",
        "dd-MM-yyyy H:mm:ss",
        "yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-ddTHH:mm:ss.fffffffZ",
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        "yyyy-MM-ddTHH:mm:ssK",
        "yyyy-MM-ddTHH:mm:ss",
        "yyyy-MM-dd",
        "MM/dd/yyyy"
    )
    foreach ($culture in $cultures) {
        foreach ($fmt in $formats) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParseExact($DateInput, $fmt, $culture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
                Write-Debug "Parsed via ParseExact fmt='$fmt' culture='$($culture.Name)'"
                return $parsed
            }
        }
    }

    Write-Warning "❗ Unable to parse datetime: '$DateInput'"
    return $null
}



Function Get-GMSACredential{
    <#
    .SYNOPSIS
    Given a GMSA account, will return a usable PSCredential object
     
    .DESCRIPTION
    Checks AD for the GMSA account information and returns a usable credential. Must be run with an account that has permissions to the password
     
    .PARAMETER GMSAName
    Identity of the GMSA account
     
    .PARAMETER Domain
    Domain logon name of the account
     
    .PARAMETER SearchRoot
    Root to search for the account (most cases can be omitted)
     
    .EXAMPLE
    Get-GMSACredential -GMSAName 'gmsaUser$' -Domain 'Home.Lab'
     
    .NOTES
    .Author: Ryan Ephgrave
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GMSAName,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$false)]
        [string]$SearchRoot = $(([adsisearcher]"").Searchroot.path)
    )

    $dEntryRoot = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $SearchRoot

    $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $dEntryRoot
    
    $searcher.Filter = "(&(name=$($GMSAName.TrimEnd('$')))(ObjectCategory=msDS-GroupManagedServiceAccount))"
    [void]$searcher.PropertiesToLoad.Add('Name')
    [void]$searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
   
    $searcher.SearchRoot.AuthenticationType = 'Sealing'
    
    $Accounts = $searcher.FindAll()
    foreach($a in $accounts){
        if($a.Properties.'msds-managedpassword'){
            $pw = $a.Properties.'msds-managedpassword'
            [Byte[]]$byteBlob = $pw.Foreach({$PSItem})
            $MemoryStream = New-Object System.IO.MemoryStream -ArgumentList (,$byteBlob)
            $Reader = New-Object System.IO.BinaryReader -ArgumentList $MemoryStream
            
            # have to move the reader to the pw offset
            $null = $Reader.ReadInt16()
            $null = $Reader.ReadInt16()
            $null = $Reader.ReadInt32()

            $PWOffset = $Reader.ReadInt16()
            $Length = $byteBlob.Length - $PWOffset
            $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length
            for($i = $PWOffset; $i -le $byteBlob.Length; $i += [System.Text.UnicodeEncoding]::CharSize){
                $currentChar = [System.BitConverter]::ToChar($byteBlob, $i)
                if($currentChar -eq [char]::MinValue) { break; }
                [void]$stringBuilder.Append($currentChar)
            }
            return ( New-Object PSCredential -ArgumentList @(
                                    "$($Domain)\$($GMSAName)",
                                    (ConvertTo-SecureString $stringBuilder.ToString() -AsPlainText -Force)
                                    ))
        }
    }
}

Function Add-Exchange-Role-to-PAG-Group
{
   [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$RoleName,
            [Parameter(mandatory)]
                [string]$GroupTag
         )

    $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }
            
    If ($Group)
        {
            $GroupName = $Group.GroupName
            Add-RoleGroupMember "$($RoleName)" -Member $GroupName
        }
    Else
        {
            Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
        }

}

Function Assign-User-PIM-PAG-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [Object]$UserInfo,
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [array]$GroupAllArray,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                [string]$AssignmentType
         )

    #####################################
    # Add User to PIM Group
    #####################################

<#
    $UserInfo = $UserInfo
    $GroupArray = $GroupArray
    $GroupAllArray = $EntraID_Groups
    $AssignmentType = $AssignmentType
    $NumOfDaysWhenExpire = $NumOfDaysWhenExpire
    $Permanent = $Permanent
    $GroupName = $ScopedAdminResourceServerPermissionGroupName_ID
#>

#    $GroupList = $GroupArray.split(",")

    $UserId = $UserInfo.UserPrincipalName

    $GroupInfo = $GroupAllArray | Where-Object { $_.DisplayName -eq $GroupName }

    If ($GroupInfo)
        {

            # Check if group already exist
            # $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'"

            $Justification = "IAC: Assigning access to group $($GroupName) for user $($UserId)"

                $params = @{
	                accessId = "member"
	                groupId = $GroupInfo.Id
	                action = "AdminAssign"
	                justification = $Justification
	                directoryScopeId = "/"
                    principalId = $UserInfo.Id
                }

                If (!($Permanent))
                    {
                        $startDateTimeObj = [datetime]::UtcNow

                        $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                        $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                            $params += @{
	                                        scheduleInfo = @{
		                                                        startDateTime = $startDateTime
		                                                        expiration = @{
			                                                                    type = "AfterDateTime"
			                                                                    endDateTime = $endDateTime
		                                                        }
                                                            }
                                        }
                    }


                    ElseIf ($Permanent)
                        {
                            $startDateTimeObj = [datetime]::UtcNow

                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                            type = "noExpiration"
		                                                                            }
                                                                }
                                            }
                        }


                If ($AssignmentType -eq "Eligible")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning Admin $($Userid) as Eligible"
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try {
                            New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                        }
                        Catch {
                            Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        }

                    }
                ElseIf ($AssignmentType -eq "Active")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning Admin $($Userid) as Active "
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try {
                            New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                        }
                        Catch {
                            Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
        }
}

Function Remove-User-PIM-PAG-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [Object]$UserInfo,
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [array]$GroupAllArray,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                [string]$AssignmentType
         )

    #####################################
    # Remove User to PIM Group
    #####################################

<#
    $UserInfo = $UserInfo
    $GroupArray = $GroupArray
    $GroupAllArray = $EntraID_Groups
    $AssignmentType = $AssignmentType
    $NumOfDaysWhenExpire = $NumOfDaysWhenExpire
    $Permanent = $Permanent
#>

#    $GroupList = $GroupArray.split(",")

    $UserId = $UserInfo.UserPrincipalName

    $GroupInfo = $GroupAllArray | Where-Object { $_.DisplayName -eq $GroupName }

    If ($GroupInfo)
        {

            # Check if group already exist
            # $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'"

            $Justification = "IAC: Removing access to group $($GroupName) for user $($UserId)"

                $params = @{
	                accessId = "member"
	                groupId = $GroupInfo.Id
	                action = "AdminRemove"
	                justification = $Justification
	                directoryScopeId = "/"
                    principalId = $UserInfo.Id
                }

                If (!($Permanent))
                    {
                        $startDateTimeObj = [datetime]::UtcNow

                        $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                        $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                            $params += @{
	                                        scheduleInfo = @{
		                                                        startDateTime = $startDateTime
		                                                        expiration = @{
			                                                                    type = "AfterDateTime"
			                                                                    endDateTime = $endDateTime
		                                                        }
                                                            }
                                        }
                    }


                    ElseIf ($Permanent)
                        {
                            $startDateTimeObj = [datetime]::UtcNow

                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                            type = "noExpiration"
		                                                                            }
                                                                }
                                            }
                        }


                If ($AssignmentType -eq "Eligible")
                    {
                        Write-Host ""
                        Write-Host "PIM - Removing Admin $($Userid) as Eligible"
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try {
                            New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                        }
                        Catch {
                            Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        }

                    }
                ElseIf ($AssignmentType -eq "Active")
                    {
                        Write-Host ""
                        Write-Host "PIM - Removing Admin $($Userid) as Active "
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try {
                            New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                        }
                        Catch {
                            Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
        }
}


Function Create-AdministrativeUnit
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$DisplayName,
            [Parameter(mandatory)]
                [string]$Description,
            [Parameter()]
                [ValidateSet("HiddenMembership", "Public")]
                $Visibility = "Public",
            [Parameter()]
                [ValidateSet("Authentication Administrator", "Cloud Device Administrator","Groups Administrator","Helpdesk Administrator","License Administrator","Password Administrator","Printer Administrator","SharePoint Administrator","Teams Administrator","Teams Devices Administrator","User Administrator")]
                [string]$RoleAssignment = $null
         )



    $params = @{
	              displayName = $DisplayName
	              description = $Description
	              visibility  = $Visibility
               }

        $Au = Get-MgDirectoryAdministrativeUnit -All:$true
        $Au = $AU | Where-Object { $_.DisplayName -eq $DisplayName }
        If ($Au)
            {
                write-host ""
                Write-host "Updating Administrative Unit (AU) $($DisplayName)"
                $Au = Update-MgDirectoryAdministrativeUnit -AdministrativeUnitId $AU.id -BodyParameter $params
            }
        Else
            {
                write-host ""
                Write-host "Creating Administrative Unit (AU) $($DisplayName)"
                $Au = New-MgDirectoryAdministrativeUnit  -BodyParameter $params
            }
}


Function Add-AdministrativeUnit-Member
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$AuId,
            [Parameter(mandatory)]
                [string]$ObjectId,
            [Parameter()]
                [ValidateSet("Group", "User")]
                $AddType
         )


    If ($AddType -eq "Group")
        {
            $params = @{
	                     "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($ObjectId)"
                       }
        }
    If ($AddType -eq "User")
        {
            $params = @{
	                     "@odata.id" = "https://graph.microsoft.com/v1.0/user/$($ObjectId)"
                       }
        }


    $Members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $AuId
    If ($ObjectId -in $Members.id)
        {
            Write-host "OK - Group is already in Administrative Unit" -ForegroundColor Green
        }
    Else
        {
            Write-host "Adding [$($AddType)] with $($ObjectId) to Administrative Unit (AU) with id $($AuId)" -ForegroundColor Yellow
            $Result = New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $AuId -BodyParameter $params -ErrorAction SilentlyContinue
        }
}



Function Create-PIM-Group-Role
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$RoleDefinitionName,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                $AssignmentType
         )

<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = $Role_GroupName
    $GroupDescription    = $Role_GroupDescription
    $RoleDefinitionName  = $RoleDefinitionName
    $NumOfDaysWhenExpire = 365
    $AssignmentType      = "Eligible"
    $Permanent           = $false

    $GroupName           = $TargetSelected
    $RoleDefinitionName  = $RoleSelected
    $AssignmentType      = $Assignment_Type
    $NumOfDaysWhenExpire = $Assignment_NumOfDaysWhenExpire
    $Permanent           = $Assignment_Permanent
#>


    # Check if group already exist (PERF: cached lookup via $Global:Groups_All_ID; v2.4.0)
    $Group = $null
    Try {
        $Group = Resolve-PimGroupCached -DisplayName $Groupname
    } Catch {
        Write-Warning "  [Create-PIM-Group-Role] group lookup for '$Groupname' failed: $($_.Exception.Message) -- treating as MISSING; will attempt create (may fail with UniqueValueViolated if the group really exists)."
    }

    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$true `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -mailNickname:$GroupName.Substring(0,64)
                }
            Else
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$true `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -mailNickname:$GroupName

                }

            # Waiting to let it sync
            Start-Sleep -Seconds 3
            # PERF: just-created group is NOT in cache yet; force Graph fetch then add to cache for subsequent same-run lookups (v2.4.0).
            $Group = Resolve-PimGroupCached -DisplayName $Groupname -NoCache
        }

    If ($Group)
        {

            # Search for RoleDefinition in array list of Role Definitions
            $roleDefinition = $Global:Role_Group_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
            $roleDefinitionId = $roleDefinition.Id

            # Get Id of new group created
            $principalId = $Group.Id

            $Justification = "IAC: Assigning role $($RoleDefinitionName) to role group $($Group.DisplayName)"

            If ($roleDefinitionId)
                {
                    $params = @{
	                             action = "AdminAssign"
	                             justification = $Justification
	                             directoryScopeId = "/"
                                 roleDefinitionId = $roleDefinitionId
                                 principalId = $principalId
                               }

                    If (!($Permanent))
                        {
                            $startDateTimeObj = [datetime]::UtcNow

                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
		                                                            startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                        type = "AfterDateTime"
			                                                                        endDateTime = $endDateTime
		                                                            }
                                                                }
                                            }
                        }


                    ElseIf ($Permanent)
                        {
                            $startDateTimeObj = [datetime]::UtcNow

                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                            type = "noExpiration"
		                                                                            }
                                                                }
                                            }
                        }
                    
                    If ($AssignmentType -eq "Eligible")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as eligible"
                            Write-host "      for role $($GroupName)"

                            Try {
                                New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                            }
                            Catch {
                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                            }
<#
                            $BodyJson = $params | ConvertTo-Json -Depth 20
                            $Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
                            $result = Invoke-MgGraphRequestPS -Uri $Uri -Method POST -OutputType PSObject -Body $BodyJson
#>
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as active"
                            write-host "      for role $($GroupName)"
                            Try {
                                New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                            }
                            Catch {
                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }
                }
        }
}


Function Assign-PIM-Group-Resource
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$AzScope,
            [Parameter(mandatory)]
                [string]$AzScopePermission,
            [Parameter(mandatory)]
                [array]$ResourceInfoArray,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                $AssignmentType
         )


<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = "PAG-Role-PlatformOps-L3-Admin-ID"
    $NumOfDaysWhenExpire = 365
    $AssignmentType      = "Eligible"
    $Permanent           = $false

    $AzScope             = "/providers/Microsoft.Management/managementGroups/f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"
    $AzScopePermission   = "Owner"
#>

    # Check if group already exist (PERF: cached lookup; v2.4.0)
    $Group = Resolve-PimGroupCached -DisplayName $Groupname

    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$false `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -mailNickname:$GroupName.Substring(0,64)
                }
            Else
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$false `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -mailNickname:$GroupName

                }

            # Waiting to let it sync
            Start-Sleep -Seconds 3
            # PERF: just-created group; force Graph fetch + cache-add (v2.4.0).
            $Group = Resolve-PimGroupCached -DisplayName $Groupname -NoCache
        }

    If ($Group)
        {

            # Search for AzScopePermission in array list of Role Definitions
            $roleDefinition = Get-AzRoleDefinition $AzScopePermission -Erroraction SilentlyContinue

            $roleDefinitionId = $AzScope + "/providers/Microsoft.Authorization/roleDefinitions/" + $roleDefinition.Id

            # Get Id of new group created
            $principalId = $Group.Id

            $Justification = "IAC: Assigning role $($AzScopePermission) to group $($Group.DisplayName)"

            If (!($Permanent))
                {
                    $startDateTimeObj = [datetime]::UtcNow

                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                    $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                properties = @{
                                                                    principalId = $principalId
                                                                    roleDefinitionId = $roleDefinitionId
	                                                                requestType = "AdminAssign"
                                                                    justification = $Justification
                                                                    scheduleInfo = @{
                                                                                    startDateTime = $startDateTime
                                                                                    expiration = @{
			                                                                                            type = "AfterDateTime"
			                                                                                            endDateTime = $endDateTime
                                                                                                    }
                                                                                }
                                                                }
                                            }
                }
            ElseIf ($Permanent)
                {
                    $startDateTimeObj = [datetime]::UtcNow

                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                    $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                properties = @{
                                                                    principalId = $principalId
                                                                    roleDefinitionId = $roleDefinitionId
                                                                    justification = $Justification
	                                                                requestType = "AdminAssign"
                                                                    scheduleInfo = @{
                                                                                        startDateTime = $startDateTime
                                                                                        expiration = @{
			                                                                                                type = "noExpiration"
                                                                                                      }
                                                                                    }
                                                              }
                                            }
                }

            $Headers = Get-AzPimTokenCached

            $Guid = (new-guid).Guid

            $AzRoleAssignmentBodyJson = $AzRoleAssignmentBody | ConvertTo-Json -Depth 20

            $AzDisplayName = ($ResourceInfoArray | Where-Object { $_.Id -eq $AzScope }).DisplayName
            If ($AssignmentType -eq "Eligible")
                {
                    Write-Host ""
                    Write-Host "PIM - Assigning $($AzScopePermission) role as eligible"
                    Write-host "      for group $($GroupName)"
                    Write-Host "      on scope [ $($AzDisplayName) ]"
                    Write-host "      $($AzScope) "

                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                    invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson | Out-Null

<#
                    Try
                        {
                            $Response   = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                        }
                    Catch
                        {
                        }
#>
                }
            ElseIf ($AssignmentType -eq "Active")
                {
                    Write-Host ""
                    Write-Host "PIM - Assigning $($AzScopePermission) role as active"
                    Write-host "      for group $($GroupName)"
                    Write-Host "      on scope [ $($AzDisplayName) ]"
                    Write-host "      $($AzScope) "

                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                    invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson | Out-Null

<#
                    Try
                        {
                            $Response   = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                        }
                    Catch
                        {
                        }
#>
                }
        }
}


Function CreateUpdate-PIM-Group
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$GroupDescription,
            [Parameter(mandatory)]
                [string]$IsRoleAssignable,
            [Parameter()]
                [string]$Owners = ""

         )


<#  TROUBLESHOOTING
    $GroupName = $ScopedAdminL3ResourceServerPermissionGroupName_ID
    $GroupDescription = $GroupDescription
    $IsRoleAssignable = $IsRoleAssignable
#>
    
    If ($IsRoleAssignable -eq "FALSE")
        {
            $IsAssignableToRole = $FALSE
        }
    ElseIf ($IsRoleAssignable -eq "TRUE")
        {
            $IsAssignableToRole = $TRUE
        }
    Else
        {
            $IsAssignableToRole = $FALSE
        }


    # Check if group already exist (cache lookup with Graph fallback).
    # BUG (pre-v2.4.69): used bare `$Global:Groups_All_ID | where-object` here,
    # which only checks the cache populated by Get-PimGroupsFiltered. If the
    # customer's naming-convention filter (PIM4EntraPS.NamingConventions.custom.ps1)
    # doesn't match the actual group prefix in the tenant (e.g. filter says
    # 'PIM_*' but groups are 'PIM-*'), the cache is empty, the cache lookup
    # returns $null, and the engine creates a DUPLICATE for every group on
    # every run. Aligned with the other create-group sites (lines 819, 989,
    # 3248) that use Resolve-PimGroupCached -- which falls back to Graph
    # when the cache misses, catching the existing group regardless of
    # whether the convention filter pre-loaded it.
    $Group = $null
    Try {
        $Group = Resolve-PimGroupCached -DisplayName $Groupname
    } Catch {
        Write-Warning "  [CreateUpdate-PIM-Group] group lookup for '$Groupname' failed: $($_.Exception.Message) -- treating as MISSING; create attempt below may emit UniqueValueViolated if the group really exists."
    }

    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$IsAssignableToRole `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -description:$GroupDescription `
                                -mailNickname:$GroupName.Substring(0,64)
                }
            Else
                {
                    Write-Host ""
                    Write-Host "Creating group $($GroupName)"

                    New-MgGroup -SecurityEnabled:$true `
                                -MailEnabled:$false `
                                -isAssignableToRole:$IsAssignableToRole `
                                -groupTypes:@() `
                                -displayName:$GroupName `
                                -description:$GroupDescription `
                                -mailNickname:$GroupName

                }

            # Waiting to let it sync
            Start-Sleep -Seconds 5
            # PERF: just-created group; force Graph fetch + cache-add (v2.4.0).
            $Group = Resolve-PimGroupCached -DisplayName $Groupname -NoCache
        }
    Else
        {
            Write-host "Checking Group Owners"
            If ($Owners)
                {
                    # $Owners = "ADMIN-JT-L0-T0-ID@2linkit.net,x-Admin-MOK-L0-T0-ID@2linkit.net,mok@2linkit.net"

                    # Build Owner array
                    $DesiredOwnersUPN = $Owners.Split(",")

                    $OwnerInfo = @()
                    ForEach ($Entry in $DesiredOwnersUPN)
                        {
                            $EntryTrimmed = $Entry.Trim()
                            If ([string]::IsNullOrWhiteSpace($EntryTrimmed)) { Continue }

                            $Object = [PSCustomObject]@{}
                            $Object | Add-Member -MemberType NoteProperty -Name 'UPN' -Value $EntryTrimmed

                            $User = $Global:Users_All_ID | Where-Object { $_.UserPrincipalName -eq $EntryTrimmed }
                            If ($User)
                                {
                                    $Object | Add-Member -MemberType NoteProperty -Name 'ObjectID' -Value $User.Id
                                }
                            Else
                                {
                                    Write-host "WARNING: Owner UPN [$($EntryTrimmed)] not found in Entra ID — skipping" -ForegroundColor Yellow
                                    $Object | Add-Member -MemberType NoteProperty -Name 'ObjectID' -Value $null
                                }
                            $OwnerInfo += $Object
                        }

                    # Get Owners
                    $CurrentOwners = Get-MgGroupOwner -GroupId $Group.id

                    ForEach ($Entry in $OwnerInfo)
                        {
                            If ([string]::IsNullOrWhiteSpace($Entry.ObjectID)) { Continue }

                            If ($Entry.ObjectId -notin $CurrentOwners.id)
                                {
                                    Write-host "Adding $($Entry.UPN) as Group Owner"
                                    $OwnerRef = @{
                                        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($Entry.ObjectId)"
                                    }
                                    Try {
                                        New-MgGroupOwnerByRef -GroupId $Group.Id -BodyParameter $OwnerRef -ErrorAction Stop
                                    }
                                    Catch {
                                        If ($_.FullyQualifiedErrorId -like "*Request_BadRequest*")
                                            { Write-host "WARNING: Could not add owner $($Entry.UPN) — $($_.Exception.Message)" -ForegroundColor Yellow }
                                        Else
                                            { Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
                                    }
                                }
                        }
                }

            If ($Group.Description -eq $GroupDescription)
                {
                    Write-Host "OK - Group $($GroupName) exists with correct data" -ForegroundColor Green
                }
            Else
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $true
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName
                    }

                    Write-Host "Updating group $($GroupName)" -ForegroundColor Yellow
                    $Result = Update-MgGroup -GroupId $Group.Id -BodyParameter $params -Erroraction SilentlyContinue
                }
        }
}

# Back-compat alias: v2.4.69 renamed CreateUpdate-PIM-PAG-Group -> CreateUpdate-PIM-Group
# ('PAG' = the old 'Privileged Access Group' label; the product is just called
# 'PIM group' now). Keeps any out-of-tree caller that still uses the old name
# working without surprise breakage; remove in a future major when all engines
# have been swept.
Set-Alias -Name CreateUpdate-PIM-PAG-Group -Value CreateUpdate-PIM-Group -Scope Global -ErrorAction SilentlyContinue


Function Create-PIM-PAG-Assignment
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$PAG_GroupName,
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                [string]$AssignmentType
         )

<#
    TROUBLESHOOTING ONLY !!

            $GroupName            = "DREG-AzRes-Platform-Management-Global-Sentinel-LogAnalytics-Reader-MP-T1-ID"
            $PAG_GroupName        = "PAG-Role-SecOps-L2-Operator-ID"
            $AssignmentType       = "Active"
            $NumOfDaysWhenExpire  = 180
            $Permanent            = $false
#>

    # Check if group already exist (PERF: cached lookups; v2.4.0)
    $Group = Resolve-PimGroupCached -DisplayName $Groupname

    # Check if group already exist
    $PAGGroup = Resolve-PimGroupCached -DisplayName $PAG_GroupName


    If ( ($Group) -and ($PAGGroup) )
        {

            $Justification = "IAC: Assigning access to group $($GroupName) for PIM group $($PAG_GroupName)"

                $params = @{
	                accessId = "member"
	                groupId = $Group.Id
	                action = "AdminAssign"
	                justification = $Justification
	                directoryScopeId = "/"
                    principalId = $PAGGroup.Id
                }

                If (!($Permanent))
                    {
                        $startDateTimeObj = [datetime]::UtcNow

                        $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                        $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                            $params += @{
	                                        scheduleInfo = @{
		                                                        startDateTime = $startDateTime
		                                                        expiration = @{
			                                                                    type = "AfterDateTime"
			                                                                    endDateTime = $endDateTime
		                                                        }
                                                            }
                                        }
                    }


                    ElseIf ($Permanent)
                        {
                            $startDateTimeObj = [datetime]::UtcNow

                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                         type = "noExpiration"
		                                                                          }
                                                                }
                                            }
                        }

                 # Import-Module Microsoft.Graph.Beta.Identity.Governance -Global -WarningAction SilentlyContinue

                If ($AssignmentType -eq "Eligible")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning PIM Group $($PAG_GroupName) as Eligible "
                        Write-host "      to group $($Groupname)"

                        $Result = New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -Erroraction SilentlyContinue
                    }
                ElseIf ($AssignmentType -eq "Active")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning PIM Group $($PAG_GroupName) as Active to group $($Groupname)"

                        $Result = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -Erroraction SilentlyContinue
                    }
        }
}


Function Update-PIM-Policy-Resource
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [ValidateSet("RoleManagementPolicyEnablementRule","RoleManagementPolicyExpirationRule","RoleManagementPolicyNotificationRule")]
                $RuleType,
            [Parameter(mandatory)]
                [ValidateSet("Assignment","Eligibility")]
                $AssignmentType,
            [Parameter(mandatory)]
                [string]$RuleId,
            [Parameter()]
                [ValidateSet("Admin_EndUser_Assignment","Admin_Admin_Eligibility","Requestor_EndUser_Assignment","Requestor_Admin_Eligibility")]
                $NotificationType,
            [Parameter()]
                [ValidateSet("Admin_Assignment","Admin_Eligibility","EndUser_Assignment")]
                $enabledRules,
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


    $Headers = Get-AzPimTokenCached

    write-host ""
    Write-host "  Processing PIM policy $($ruleId)"
    $Guid = (new-guid).Guid

    If ($RuleType -eq "RoleManagementPolicyExpirationRule")
        {
            $PolicyBody = [pscustomobject][ordered]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired
                                                    maximumDuration = $Expiration_EndUser_Assignment_maximumDuration
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                }
                                            )
                             }
            }
        }

    #---------------------------------------------------------------------------------------------------------------------

    If ($RuleType -eq "RoleManagementPolicyEnablementRule")
        {
            $PolicyBody = [PSCustomObject]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                }
                                            )
                             }
            }

            #-------------------------------------------
            If ($enabledRules -eq "Admin_Assignment")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                }
            #-------------------------------------------
            If ($enabledRules -eq "Admin_Eligibility")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_Admin_Eligibility_enabledRules}
                }
            #-------------------------------------------
            If ($enabledRules -eq "EndUser_Assignment")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_EndUser_Assignment_enabledRules}
                }
            #-------------------------------------------
            If ($AssignmentType -eq "Eligibility")
                {
                    $PolicyBody.properties.rules += @{isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired}
                    $PolicyBody.properties.rules += @{maximumDuration = $Expiration_EndUser_Assignment_maximumDuration}
                }
            #-------------------------------------------
        }

    #---------------------------------------------------------------------------------------------------------------------

    If ($RuleType -eq "RoleManagementPolicyNotificationRule")
        {
            $PolicyBody = [pscustomobject][ordered]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                 }
                                             )
                              }
            }
        }

        #-------------------------------------------------

        If ($NotificationType -eq "Admin_EndUser_Assignment")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Admin_EndUser_Assignment_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Admin_EndUser_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Admin_EndUser_notificationLevel}
                If ($Notification_Admin_EndUser_notificationRecipients -ne "")
                    {
                        $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Admin_EndUser_notificationRecipients}
                    }
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Admin_Admin_Eligibility")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Admin_Admin_Eligibility_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Admin_Admin_Eligibility_recipientType_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel}
                If ($Notification_Admin_Admin_Eligibility_notificationRecipients -ne "")
                    {
                        $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients}
                    }
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Requestor_EndUser_Assignment")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Requestor_EndUser_Assignment_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Requestor_EndUser_Assignment_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel}
                If ($Notification_Requestor_EndUser_Assignment_notificationRecipients -ne "")
                    {
                        $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients}
                    }
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Requestor_Admin_Eligibility")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Requestor_Admin_Eligibility_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Requestor_Admin_Eligibility_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel}
                If ($Notification_Requestor_Admin_Eligibility_notificationRecipients -ne "")
                    {
                        $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients}
                    }
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

    $PolicyBodyJson = $PolicyBody | ConvertTo-Json -Depth 20

    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
    $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $PolicyBodyJson
}


Function Update-PIM-Policy-Role
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [ValidateSet("PolicyEnablementRule","PolicyExpirationRule","PolicyAuthenticationContextRule","PolicyNotificationRule","PolicyApprovalRule")]
                $RuleType,
            [Parameter(mandatory)]
                [string]$PolicyId,
            [Parameter(mandatory)]
                [string]$RuleId,
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


    write-host ""
    Write-host "Processing PIM policy $($RuleId)"
    $Guid = (new-guid).Guid

    # Baseline policy for Roles
    $odataType = "#microsoft.graph.unifiedRoleManagement" + $RuleType
    $PolicyBody = @{
        '@odata.type' = $odataType
        id = $ruleId
        target = @{
                    '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                    operations = @(
			                        "All"
                                  )
                  }
        inheritableSettings = $null
        enforcedSettings = $null
    }

    #---------------------------------------------------------------------------------------------------------------------

    # Expiration
        If ($RuleId -eq "Expiration_EndUser_Assignment")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_EndUser_Assignment_maximumDuration}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "EndUser"}
            }
        If ($RuleId -eq "Expiration_Admin_Eligibility")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_Admin_Eligibility_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_Admin_Eligibility_maximumDuration}
                $PolicyBody.target += @{level = "Eligbility"}
                $PolicyBody.target += @{caller = "Admin"}
            }
        If ($RuleId -eq "Expiration_Admin_Assignment")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_Admin_Assignment_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_Admin_Assignment_maximumDuration}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "Admin"}
            }

    # Activation
        If ($RuleId -eq "Enablement_EndUser_Assignment")
            {
                If ($Enablement_EndUser_Assignment_enabledRules)
                    {
                        $PolicyBody += @{enabledRules = $Enablement_EndUser_Assignment_enabledRules}
                    }
                Else
                    {
                        $PolicyBody += @{enabledRules = @()}
                    }
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "EndUser"}
            }
        If ($RuleId -eq "Enablement_Admin_Assignment")
            {
                If ($Enablement_Admin_Assignment_enabledRules)
                    {
                        $PolicyBody += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                    }
                Else
                    {
                        $PolicyBody += @{enabledRules = @()}
                    }
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "Admin"}
            }
        If ($RuleId -eq "$Enablement_Admin_Eligibility")
            {
                If ($Enablement_Admin_Eligibility_enabledRules)
                    {
                        $PolicyBody += @{enabledRules = $Enablement_Admin_Eligibility_enabledRules}
                    }
                Else
                    {
                        $PolicyBody += @{enabledRules = @()}
                    }
                $PolicyBody.target += @{level = "Eligibility"}
                $PolicyBody.target += @{caller = "Admin"}
            }

<#
        If ($RuleId -eq "AuthenticationContext_EndUser_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                $PolicyBody += @{level = "Assignment"}
                $PolicyBody += @{caller = "EndUser"}
            }
#>

    # Approval
<#
        If ($RuleId -eq "Approval_EndUser_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_Admin_Eligibility_enabledRules}
                $PolicyBody += @{level = "Assignment"}
                $PolicyBody += @{caller = "EndUser"}
            }
#>

    # Notification
        If ($RuleId -eq "Notification_Admin_EndUser_Assignment")
            {
                $PolicyBody += @{notificationType = $Notification_Admin_EndUser_Assignment_notificationType}
                $PolicyBody += @{recipientType = $Notification_Admin_EndUser_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Admin_EndUser_notificationLevel}
                If ($Notification_Admin_EndUser_notificationRecipients -ne "")
                    {
                        $PolicyBody += @{notificationRecipients = $Notification_Admin_EndUser_notificationRecipients}
                    }
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Admin_Admin_Eligibility")
            {
                $PolicyBody += @{notificationType = $Notification_Admin_Admin_Eligibility_notificationType}
                $PolicyBody += @{recipientType = $Notification_Admin_Admin_Eligibility_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel}
                If ($Notification_Admin_Admin_Eligibility_notificationRecipients -ne "")
                    {
                        $PolicyBody += @{notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients}
                    }
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Requestor_EndUser_Assignment")
            {
                $PolicyBody += @{notificationType = $Notification_Requestor_EndUser_Assignment_notificationType}
                $PolicyBody += @{recipientType = $Notification_Requestor_EndUser_Assignment_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel}
                If ($Notification_Requestor_EndUser_Assignment_notificationRecipients -ne "")
                    {
                        $PolicyBody += @{notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients}
                    }
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Requestor_Admin_Eligibility")
            {
                $PolicyBody += @{notificationType = $Notification_Requestor_Admin_Eligibility_notificationType}
                $PolicyBody += @{recipientType = $Notification_Requestor_Admin_Eligibility_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel}
                If ($Notification_Requestor_Admin_Eligibility_notificationRecipients -ne "")
                    {
                        $PolicyBody += @{notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients}
                    }
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

    # Update policy
        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $PolicyId `
                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                -BodyParameter $PolicyBody
}


######################################################################################################
# DROG | PIM for Role Groups | Creation & Delegation
######################################################################################################

<#  DISBALED to assign Roles directly to PAG groups - due to missing nesting support

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Role Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $EntraID_Role_Data = Import-csv -Path $EntraID_Roles_DataFile -Delimiter ";" -Encoding UTF8


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # create Role Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        ForEach ($Entry in $EntraID_Role_Data)
            {
                $GroupName           = $Entry.GroupName
                $GroupDescription    = $Entry.GroupDescription
                $AdministrativeUnit  = $Entry.AdministrativeUnit
                $RoleDefinitionName  = $Entry.RoleDefinitionName
                $AssignmentType      = $Entry.AssignmentType
                $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
                $Permanent           = $Entry.Permanent

                If ($Permanent -eq "TRUE")
                    {
                        $Permanent = $TRUE
                    }
                Else
                    {
                        $Permanent = $FALSE
                    }

                Create-PIM-Group-Role -GroupName $GroupName `
                                        -RoleDefinitionName $RoleDefinitionName `
                                        -AssignmentType $AssignmentType `
                                        -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                        -Permanent:$Permanent

                    
                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
                $AU = Get-MgDirectoryAdministrativeUnit -All:$true
                $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
                Add-AdministrativeUnit-Member -AuId $AU.Id -AddType Group -ObjectId $GroupInfo.Id
            }
#>


######################################################################################################
# DREG | PIM for Azure Resources | Resource Groups | Creation & Delegation
######################################################################################################
<#
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Resource Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $Azure_Resources_Data = Import-csv -Path $Azure_Resources_DataFile -Delimiter ";" -Encoding UTF8

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # create resource groups - contains resource assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        ForEach ($Entry in $Azure_Resources_Data)
            {
                $GroupName           = $Entry.GroupName
                $GroupDescription    = $Entry.GroupDescription
                $AdministrativeUnit  = $Entry.AdministrativeUnit
                $AzScope             = $Entry.AzScope
                $AzScopePermission   = $Entry.AzScopePermission
                $AssignmentType      = $Entry.AssignmentType
                $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
                $Permanent           = $Entry.Permanent

                If ($Permanent -eq "TRUE")
                    {
                        $Permanent = $TRUE
                    }
                Else
                    {
                        $Permanent = $FALSE
                    }

                Assign-PIM-Group-Resource -GroupName $GroupName `
                                            -AzScope $AzScope `
                                            -AzScopePermission $AzScopePermission `
                                            -AssignmentType $AssignmentType `
                                            -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                            -Permanent:$Permanent

                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
                $AU = Get-MgDirectoryAdministrativeUnit -All:$true
                $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
                Add-AdministrativeUnit-Member -AuId $AU.Id -AddType Group -ObjectId $GroupInfo.Id
            }
#>



Function CreateUpdate-PIM-for-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$DeptGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$RoleGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$TaskGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ServiceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ProcessGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ResourceGroupsDefinitionFile
         )

######################################################################################################
# PAG | PIM for Groups | Privileged Access Group (PAG) - Creation
######################################################################################################

<#
    $DeptGroupsDefinitionFile = $DeptGroupsDefinitionFile
    $RoleGroupsDefinitionFile = $RoleGroupsDefinitionFile
    $TaskGroupsDefinitionFile = $TaskGroupsDefinitionFile
    $ServiceGroupsDefinitionFile = $ServiceGroupsDefinitionFile
    $ProcessGroupsDefinitionFile = $ProcessGroupsDefinitionFile
    $ResourceGroupsDefinitionFile = $ResourceGroupsDefinitionFile
#>

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Import-csv -Path $DeptGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $RoleGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $TaskGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ProcessGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ServiceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ResourceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create AUs for Privileged Access Groups (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
<#
        $AUs = $PAG_Groups_Data | select-object -property AdministrativeUnit -unique

        ForEach ($AU in $AUs)
            {
                $AdministrativeUnit = $AU.AdministrativeUnit
                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
            }
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true
#>

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create Privileged Access Group (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # Build list of all Administrative Units
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true

        ForEach ($Entry in $PAG_Groups_Data)
            {
                $GroupName             = $Entry.GroupName
                $GroupDescription      = $Entry.GroupDescription
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $Owners                = $Entry.Owners
                $IsRoleAssignable      = $Entry.IsRoleAssignable

                write-host ""
                Write-host "Processing group $($GroupName)"
                CreateUpdate-PIM-Group -GroupName $GroupName `
                                           -GroupDescription $GroupDescription `
                                           -IsRoleAssignable $IsRoleAssignable `
                                           -Owners $Owners

                # Get actual au, based on tags
                $AU = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }

                If ($AU)
                    {
                        $AUName = $AU.AUDisplayName
                    }
                Else
                    {
                        Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                    }

                $AUInfo = $AU_ALL | Where-Object { $_.DisplayName -eq $AUName }

                # PERF: cached lookup; this group was just created by CreateUpdate-PIM-Group, so allow cache (which the create-path populated via -NoCache) or fall back to Graph (v2.4.0).
                $GroupInfo = Resolve-PimGroupCached -DisplayName $GroupName
                Add-AdministrativeUnit-Member -AuId $AUInfo.Id -AddType Group -ObjectId $GroupInfo.Id
            }
}


Function CreateUpdate-PIM-for-Groups-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$DeptGroupsDefinitionSQLTable,
            [Parameter(mandatory)]
                [string]$RoleGroupsDefinitionSQLTable,
            [Parameter(mandatory)]
                [string]$TaskGroupsDefinitionSQLTable,
            [Parameter(mandatory)]
                [string]$ServiceGroupsDefinitionSQLTable,
            [Parameter(mandatory)]
                [string]$ProcessGroupsDefinitionSQLTable,
            [Parameter(mandatory)]
                [string]$ResourceGroupsDefinitionSQLTable
         )

######################################################################################################
# PAG | PIM for Groups | Privileged Access Group (PAG) - Creation
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($DeptGroupsDefinitionSQLTable)"
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($RoleGroupsDefinitionSQLTable)"
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($TaskGroupsDefinitionSQLTable)"
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($ProcessGroupsDefinitionSQLTable)"
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($ServiceGroupsDefinitionSQLTable)"
        $PAG_Groups_Data += Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($ResourceGroupsDefinitionSQLTable)"

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create AUs for Privileged Access Groups (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
<#
        $AUs = $PAG_Groups_Data | select-object -property AdministrativeUnit -unique

        ForEach ($AU in $AUs)
            {
                $AdministrativeUnit = $AU.AdministrativeUnit
                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
            }
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true
#>

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create Privileged Access Group (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # Build list of all Administrative Units
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true

        ForEach ($Entry in $PAG_Groups_Data)
            {
                $GroupName             = $Entry.GroupName
                $GroupDescription      = $Entry.GroupDescription
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $IsRoleAssignable      = $Entry.IsRoleAssignable

                write-host ""
                Write-host "Processing group $($GroupName)"
                CreateUpdate-PIM-Group -GroupName $GroupName `
                                           -GroupDescription $GroupDescription `
                                           -IsRoleAssignable $IsRoleAssignable

                # Get actual au, based on tags
                $AU = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }

                If ($AU)
                    {
                        $AUName = $AU.AUDisplayName
                    }
                Else
                    {
                        Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                    }

                $AUInfo = $AU_ALL | Where-Object { $_.DisplayName -eq $AUName }

                # PERF: cached lookup; v2.4.0
                $GroupInfo = Resolve-PimGroupCached -DisplayName $GroupName
                Add-AdministrativeUnit-Member -AuId $AUInfo.Id -AddType Group -ObjectId $GroupInfo.Id
            }
}


Function Build-List-of-Definitions
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$DeptGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$RoleGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$TaskGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ServiceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ProcessGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ResourceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$AdministrativeUnitDefinitionFile,
            [Parameter(mandatory)]
                [string]$AccountsDefinitionFile
         )


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PAG Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Import-csv -Path $DeptGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $RoleGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $TaskGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ProcessGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ServiceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ResourceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Administrative Units
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $AU_Data = Import-csv -Path $AdministrativeUnitDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $AU_Data = $AU_Data | Where { $_.AUDisplayName -ne "" }

        # Build global variable
        $Global:AU_Definitions = $AU_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Admin Accounts
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $AdminAccounts_Data = Import-csv -Path $AccountsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

        # Build global variable
        $Global:Accounts_Definitions = $AdminAccounts_Data
}

Function Build-List-of-Assignments
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitRoleAssignmentsFile,
            [Parameter(mandatory)]
                [string]$GroupRoleAssignmentsFile,
            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile,
            [Parameter(mandatory)]
                [string]$PIMForGroupsAssignmentsFile,
            [Parameter(mandatory)]
                [string]$AccountsAssignmentFile
         )


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Administrative Units Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $AdministrativeUnitRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.AdministrativeUnitTag -ne "" })

        # build global array
        $Global:AdministrativeUnitRoleAssignments = $Assignments

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Group Role Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $GroupRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:GroupRoleAssignments = $Assignments

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Group Azure Resources Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:GroupAzResourcesAssignments = $Assignments


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PIM for Groups Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $PIMForGroupsAssignmentFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:PIMForGroupsAssignment = $Assignments


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Admin Accounts Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $AccountsAssignmentFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:AccountsAssignment = $Assignments

}


Function CreateUpdate-AdministrativeUnits-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitDefinitionFile
         )

######################################################################################################################
# AU | Administrative Units | Creation
######################################################################################################################

    $AU_Data = Import-csv -Path $AdministrativeUnitDefinitionFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AU_Data = $AU_Data | Where { $_.AUDisplayName -ne "" }

    # Build global variable
    $Global:AU_Definitions = $AU_Data

        ForEach ($Entry in $AU_Data)
            {
                $AUDisplayName         = $Entry.AUDisplayName
                $AUDescription         = $Entry.AUDescription
                # BUG FIX 7: was $Entry.AUDescription (wrong column) - now reads correct AdministrativeUnitTag column
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $Visibility            = $Entry.Visibility

                Create-AdministrativeUnit -DisplayName $AUDisplayName `
                                          -Description $AUDescription `
                                          -Visibility $Visibility

               # $AU = Get-MgDirectoryAdministrativeUnit -All:$true
               # $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
            }
}

Function CreateUpdate-AdministrativeUnits-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$SQLTable
         )

######################################################################################################################
# AU | Administrative Units | Creation
######################################################################################################################

    $AU_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    # remove empty lines
    $AU_Data = $AU_Data | Where { $_.AUDisplayName -ne "" }

    # Build global variable
    $Global:AU_Definitions = $AU_Data

        ForEach ($Entry in $AU_Data)
            {
                $AUDisplayName         = $Entry.AUDisplayName
                $AUDescription         = $Entry.AUDescription
                # BUG FIX 7: was $Entry.AUDescription (wrong column) - now reads correct AdministrativeUnitTag column
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $Visibility            = $Entry.Visibility

                Create-AdministrativeUnit -DisplayName $AUDisplayName `
                                          -Description $AUDescription `
                                          -Visibility $Visibility

               # $AU = Get-MgDirectoryAdministrativeUnit -All:$true
               # $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
            }
}


Function Assign-Roles-AdministrativeUnits-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitRoleAssignmentsFile
         )

######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }

######################################################################################################################
# Assignment of Roles to Administrative Units
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to Administrative Unit
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $AdministrativeUnitRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            # BUG FIX 1: Reset $PIMAction at the start of every iteration to prevent stale values
            # carrying over and causing RoleAssignmentExists errors on already-existing assignments.
            $PIMAction = "NoAction"

            $GroupTag              = $Entry.GroupTag
            $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
            $RoleDefinitionName    = $Entry.RoleDefinitionName
            $Action                = $Entry.Action
            $AutoExtend            = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting        = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            # Get actual group & au, based on tags
            $PAG_Group             = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }
            $AU                    = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }
            
            If ($GroupTag)
                {
                    If ($PAG_Group)
                        {
                            $PAG_GroupName = $PAG_Group.GroupName
                        }
                    Else
                        {
                            Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                        }

                    If ($AU)
                        {
                            $AUName = $AU.AUDisplayName
                        }
                    Else
                        {
                            Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                        }

                    write-host ""
                    Write-host "Processing AU Role $($RoleDefinitionName) on AU $($AUName)"

                    If ($Permanent -eq "TRUE")
                        {
                            $Permanent = $TRUE
                        }
                    Else
                        {
                            $Permanent = $FALSE
                        }

                    If ($AutoExtend -eq "TRUE")
                        {
                            $AutoExtend = $TRUE
                        }
                    Else
                        {
                            $AutoExtend = $FALSE
                        }

                    If ($UpdateExisting -eq "TRUE")
                        {
                            $UpdateExisting = $TRUE
                        }
                    Else
                        {
                            $UpdateExisting = $FALSE
                        }

                    # Get AU scope Id — must use -All:$true or paging will miss AUs beyond default page size
                        $AUs = Get-MgDirectoryAdministrativeUnit -All:$true

                        $AUId = ($AUs | Where-Object { $_.DisplayName -eq $AUName }).id

                    # Get Role definition Id
                        $roleDefinition = $Global:Role_AU_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
                        $roleDefinitionId = $roleDefinition.Id

                    # Get Group Principal Id (PERF: cached lookup; v2.4.0)
                        $Group = Resolve-PimGroupCached -DisplayName $PAG_Groupname
                        $GroupName = $Group.DisplayName
                        $principalId = $Group.Id

                    If ( ($AUId) -and ($RoleDefinitionId) -and ($PrincipalId) )
                        {
                            # Map input CSV values to snapshot CSV values before lookup.
                            # Snapshot stores "Eligible" (not changed) and "Assigned" (Active -> Assigned).
                            $AssignmentTypeLookup = $AssignmentType
                            If ($AssignmentType -eq 'Active') { $AssignmentTypeLookup = 'Assigned' }

                            $CheckExistingAssignment = $CurrentAssignments_EntraIDRoles | where-object { ($_.AssignmentType -eq $AssignmentTypeLookup) -and ($_.PrincipalId -eq $Group.Id) -and ($_.RoleId -eq $roleDefinitionId) -and ($_.DirectoryScopeId -eq "/administrativeUnits/$($AUId)" ) }

                            # For Active (Assigned) AU-scoped assignments the snapshot CSV may not capture
                            # all rows (MicrosoftGraphPS exporter limitations). When the snapshot returns
                            # nothing for an Active assignment, verify directly against Graph before
                            # concluding it doesn't exist — prevents false AdminAssign -> RoleAssignmentExists.
                            If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Active') )
                                {
                                    # Try AU-scoped filter first
                                    $GraphCheck = Get-MgRoleManagementDirectoryRoleAssignmentSchedule `
                                                    -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/administrativeUnits/$AUId'" `
                                                    -ErrorAction SilentlyContinue
                                    # If scoped filter returns nothing, try without scope (Graph inconsistency with AU scope format)
                                    If (!$GraphCheck)
                                        {
                                            $GraphCheck = Get-MgRoleManagementDirectoryRoleAssignmentSchedule `
                                                            -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId'" `
                                                            -ErrorAction SilentlyContinue
                                            # Filter to AU scope matches only
                                            $GraphCheck = $GraphCheck | Where-Object { $_.DirectoryScopeId -like "*$AUId*" }
                                        }
                                    # Third fallback: check non-scheduled (direct) role assignments at AU scope
                                    If (!$GraphCheck)
                                        {
                                            $GraphCheckDirect = Get-MgRoleManagementDirectoryRoleAssignment `
                                                            -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/administrativeUnits/$AUId'" `
                                                            -ErrorAction SilentlyContinue
                                            If (!$GraphCheckDirect)
                                                {
                                                    $GraphCheckDirect = Get-MgRoleManagementDirectoryRoleAssignment `
                                                                    -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId'" `
                                                                    -ErrorAction SilentlyContinue
                                                    $GraphCheckDirect = $GraphCheckDirect | Where-Object { $_.DirectoryScopeId -like "*$AUId*" }
                                                }
                                            If ($GraphCheckDirect)
                                                {
                                                    # Wrap as synthetic schedule object so downstream logic works
                                                    $GraphCheck = [PSCustomObject]@{
                                                        ScheduleInfo = [PSCustomObject]@{ Expiration = [PSCustomObject]@{ Type = "noExpiration"; EndDateTime = $null } }
                                                    }
                                                }
                                        }
                                    If ($GraphCheck)
                                        {
                                            write-host ""
                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                            $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                            # Graph returns "noExpiration" or "afterDateTime"; EndDateTime is null when permanent
                                            $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                            $CheckExistingAssignment = [PSCustomObject]@{
                                                AssignmentType            = 'Assigned'
                                                RoleId                    = $roleDefinitionId
                                                PrincipalId               = $Group.Id
                                                DirectoryScopeId          = "/administrativeUnits/$AUId"
                                                ScheduleExpirationType    = $GraphExpirationType
                                                ScheduleExpirationEndDateTime = $GraphEndDateTime
                                            }
                                        }
                                }

                            # Same fallback for Eligible assignments — snapshot may also miss some AU-scoped entries.
                            If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Eligible') )
                                {
                                    # Try AU-scoped filter first
                                    $GraphCheck = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
                                                    -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/administrativeUnits/$AUId'" `
                                                    -ErrorAction SilentlyContinue
                                    # If scoped filter returns nothing, try without scope
                                    If (!$GraphCheck)
                                        {
                                            $GraphCheck = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
                                                            -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId'" `
                                                            -ErrorAction SilentlyContinue
                                            $GraphCheck = $GraphCheck | Where-Object { $_.DirectoryScopeId -like "*$AUId*" }
                                        }
                                    If ($GraphCheck)
                                        {
                                            write-host ""
                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                            $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                            $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                            $CheckExistingAssignment = [PSCustomObject]@{
                                                AssignmentType            = 'Eligible'
                                                RoleId                    = $roleDefinitionId
                                                PrincipalId               = $Group.Id
                                                DirectoryScopeId          = "/administrativeUnits/$AUId"
                                                ScheduleExpirationType    = $GraphExpirationType
                                                ScheduleExpirationEndDateTime = $GraphEndDateTime
                                            }
                                        }
                                }

                            If ($CheckExistingAssignment)
                                {
                                    $CheckExistingAssignment = $CheckExistingAssignment[0]

                                    # Check if assignment is Permanent/noExpiration
                                    If ($CheckExistingAssignment.ScheduleExpirationType -ieq "noExpiration")
                                        {
                                            If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                {
                                                    Write-host "UPDATE: $RoleDefinitionName -> $($Group.DisplayName) (refreshing assignment details)" -ForegroundColor Yellow
                                                    $PIMAction = "AdminUpdate"
                                                }
                                            Else
                                                {
                                                    # BUG FIX 3: Permanent assignment exists and no update requested - explicitly NoAction
                                                    Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Green
                                                    $PIMAction = "NoAction"
                                                }
                                        }
                                    Else
                                        {
                                            # not permanent - check expiry
                                            $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime

                                            # Guard: if EndDateTime is null/empty despite not being noExpiration
                                            # (can happen with live Graph data), treat as permanent to avoid crash
                                            If ([string]::IsNullOrWhiteSpace($ValueChk))
                                                {
                                                    Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Green
                                                    $PIMAction = "NoAction"
                                                }
                                            Else
                                                {
                                                    $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                                    If (-not $ExpirationDate)
                                                        {
                                                            write-host ""
                                                            Write-host "OK - Exists (unparseable expiry '$ValueChk'): $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Yellow
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                    Else
                                                        {
                                                            # Calculate and round the number of days
                                                            $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End $ExpirationDate).TotalDays
                                                            $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)

                                                            If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                                                {
                                                                    # change action from AdminAssign to AdminExtend
                                                                    write-host ""
                                                                    Write-host "EXTEND: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days)" -ForegroundColor Yellow
                                                                    write-host "Assignment will be extended as AutoExtend=TRUE"
                                                                    write-host ""
                                                                    $PIMAction = "AdminExtend"
                                                                }
                                                            ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                                {
                                                                    write-host ""
                                                                    Write-host "Existing Assignment will be updated with assignment details"
                                                                    Write-host "Mode: AdminUpdate"
                                                                    write-host ""
                                                                    $PIMAction = "AdminUpdate"
                                                                }
                                                            Else
                                                                {
                                                                    write-host ""
                                                                    Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                                    write-host ""
                                                                    $PIMAction = "NoAction"
                                                                }
                                                        }
                                                }
                                        }
                                }

                            # new installation
                            ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                                {
                                    write-host ""
                                    $PIMAction = "AdminAssign"
                                }
                            
                            If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                                {
                                    Write-host "REMOVE: $RoleDefinitionName -> $($Group.DisplayName)" -ForegroundColor Red
                                    $PIMAction = "AdminRemove"
                                }

                            ################################################################################################################
                            If ($PIMaction -ne "NoAction")
                                {
                                # Print action summary - only for AdminAssign (not for Extend/Update)
                                If ($PIMAction -eq "AdminAssign")
                                    {
                                        Write-host "ASSIGN: $RoleDefinitionName -> $($Group.DisplayName) (new assignment)" -ForegroundColor Cyan
                                    }
                                    $Justification = "IAC: Assigning role $($RoleDefinitionName) to role group $($Group.DisplayName)"

                                    If ($roleDefinitionId)
                                        {
                                            $params = @{
	                                                        action = $PIMAction
	                                                        justification = $Justification
                                                            roleDefinitionId = $roleDefinitionId
                                                            principalId = $principalId
	                                                        directoryScopeId = "/administrativeUnits/$($AUId)"
                                                        }

                                            If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Compute start/end using a single UTC base object (no double Get-Date conversion)
                                                    $startDateTimeObj = [datetime]::UtcNow
                                                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")
                                                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
		                                                                                    startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                type = "AfterDateTime"
			                                                                                                endDateTime = $endDateTime
		                                                                                    }
                                                                                        }
                                                                    }
                                                }


                                            ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Removed dead $endDateTime calculation for permanent assignments
                                                    $startDateTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
   	                                                                                        startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                    type = "noExpiration"
		                                                                                                    }
                                                                                        }
                                                                    }
                                                }
                    
                                            If ($AssignmentType -eq "Eligible")
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($RoleDefinitionName) role as eligible"
                                                    Write-host "      for group $($GroupName)"

                                                    Try {
                                                        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                                    }
                                                    Catch {
                                                        If ($_.FullyQualifiedErrorId -like "*RoleAssignmentExists*")
                                                            { Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (Graph confirmed, skipping)" -ForegroundColor Green }
                                                        ElseIf ($_.FullyQualifiedErrorId -like "*RoleAssignmentDoesNotExist*")
                                                            { Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green }
                                                        Else
                                                            { Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
                                                    }
                                                }
                                            ElseIf ($AssignmentType -eq "Active")
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($RoleDefinitionName) role as active"
                                                    write-host "      for group $($GroupName)"
                                                    Try {
                                                        New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                                    }
                                                    Catch {
                                                        If ($_.FullyQualifiedErrorId -like "*RoleAssignmentExists*")
                                                            { Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (Graph confirmed, skipping)" -ForegroundColor Green }
                                                        ElseIf ($_.FullyQualifiedErrorId -like "*RoleAssignmentDoesNotExist*")
                                                            { Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green }
                                                        Else
                                                            { Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
                                                    }
                                                }
                                        }
                                }
                        }
                }
        }
}


Function Assign-Roles-AdministrativeUnits-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$SQLTable
         )

######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }


######################################################################################################################
# Assignment of Roles to Administrative Units
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to Administrative Unit
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            # BUG FIX 1: Reset $PIMAction at the start of every iteration
            $PIMAction = "NoAction"

            $GroupTag              = $Entry.GroupTag
            $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
            $RoleDefinitionName    = $Entry.RoleDefinitionName
            $Action                = $Entry.Action
            $AutoExtend            = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting        = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            # Get actual group & au, based on tags
            $PAG_Group             = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }
            $AU                    = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }
            
            If ($PAG_Group)
                {
                    $PAG_GroupName = $PAG_Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            If ($AU)
                {
                    $AUName = $AU.AUDisplayName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                }

            write-host ""
            Write-host "Processing AU Role $($RoleDefinitionName) on AU $($AUName)"

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            If ($AutoExtend -eq "TRUE")
                {
                    $AutoExtend = $TRUE
                }
            Else
                {
                    $AutoExtend = $FALSE
                }

            If ($UpdateExisting -eq "TRUE")
                {
                    $UpdateExisting = $TRUE
                }
            Else
                {
                    $UpdateExisting = $FALSE
                }

            # Get AU scope Id

                $AUs = Get-MgDirectoryAdministrativeUnit

                $AUId = ($AUs | Where-Object { $_.DisplayName -eq $AUName }).id

            # Get Role definition Id - BUG FIX: use Role_AU_Definitions_ID (not Role_Group_Definitions_ID) for AU-scoped roles
                $roleDefinition = $Global:Role_AU_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
                $roleDefinitionId = $roleDefinition.Id

            # Get Group Principal Id (PERF: cached lookup; v2.4.0)
                $Group = Resolve-PimGroupCached -DisplayName $PAG_Groupname
                $principalId = $Group.Id

            If ( ($AUId) -and ($RoleDefinitionId) -and ($PrincipalId) )
                {
                    # BUG FIX: Graph SDK exports "Assigned" (not "Active") and "Eligibility" (not "Eligible")
                    $AssignmentTypeLookup = $AssignmentType
                    If ($AssignmentType -eq 'Active')   { $AssignmentTypeLookup = 'Assigned'    }
                    
                    $CheckExistingAssignment = $CurrentAssignments_EntraIDRoles | where-object { ($_.AssignmentType -eq $AssignmentTypeLookup) -and ($_.PrincipalId -eq $Group.Id) -and ($_.RoleId -eq $roleDefinitionId) -and ($_.DirectoryScopeId -eq "/administrativeUnits/$($AUId)") }

                    If ($CheckExistingAssignment)
                        {
                            $CheckExistingAssignment = $CheckExistingAssignment[0]

                            # Check if assignment is Permanent/noExpiration
                            If ($CheckExistingAssignment.ScheduleExpirationType -ieq "noExpiration")
                                {
                                    If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                        {
                                            write-host ""
                                            Write-host "Existing Assignment will be updated with assignment details"
                                            Write-host "Mode: AdminUpdate"
                                            write-host ""
                                            $PIMAction = "AdminUpdate"
                                        }
                                    Else
                                        {
                                            # BUG FIX 3: Permanent assignment exists, no update requested - explicitly NoAction
                                            write-host ""
                                            Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)"
                                            Write-host "Mode: NoAction"
                                            write-host ""
                                            $PIMAction = "NoAction"
                                        }
                                }
                            Else
                                {
                                    # not permanent - check expiry
                                    $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                    If ([string]::IsNullOrWhiteSpace($ValueChk))
                                        {
                                            # Empty EndDateTime despite not being noExpiration -> treat as permanent
                                            write-host ""
                                            Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Green
                                            Write-host "Mode: NoAction"
                                            write-host ""
                                            $PIMAction = "NoAction"
                                        }
                                    Else
                                        {
                                            $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                            If (-not $ExpirationDate)
                                                {
                                                    # Unparseable EndDateTime -> safer to skip than to act on bogus math
                                                    write-host ""
                                                    Write-host "OK - Exists (unparseable expiry '$ValueChk'): $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Yellow
                                                    Write-host "Mode: NoAction"
                                                    write-host ""
                                                    $PIMAction = "NoAction"
                                                }
                                            Else
                                                {
                                                    # Calculate and round the number of days
                                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End $ExpirationDate).TotalDays
                                                    $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)

                                                    If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                                        {
                                                            # change action from AdminAssign to AdminExtend
                                                            write-host ""
                                                            Write-host "Existing Assignment will expire in $($NumOfDaysBeforeExpiration) days"
                                                            write-host "Assignment will be extended as AutoExtend=TRUE"
                                                            Write-host "Mode: AdminExtend"
                                                            write-host ""
                                                            $PIMAction = "AdminExtend"
                                                        }
                                                    ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                        {
                                                            write-host ""
                                                            Write-host "Existing Assignment will be updated with assignment details"
                                                            Write-host "Mode: AdminUpdate"
                                                            write-host ""
                                                            $PIMAction = "AdminUpdate"
                                                        }
                                                    Else
                                                        {
                                                            write-host ""
                                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                }
                                        }
                                }
                        }

                    ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                        {
                            write-host ""
                            $PIMAction = "AdminAssign"
                        }
                    
                    If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                        {
                            write-host ""
                            Write-host "Assignment was found .... removing"
                            Write-host "Mode: AdminRemove"
                            write-host ""
                            $PIMAction = "AdminRemove"
                        }

                    ################################################################################################################
                    If ($PIMaction -ne "NoAction")
                        {
                        # Print action summary - only for AdminAssign (not for Extend/Update)
                        If ($PIMAction -eq "AdminAssign")
                            {
                                write-host ""
                                Write-host "Assignment was NOT found .... creating"
                                Write-host "Mode: AdminAssign"
                                write-host ""
                            }
                            $Justification = "IAC: Assigning role $($RoleDefinitionName) to role group $($Group.DisplayName)"

                            If ($roleDefinitionId)
                                {
                                    $params = @{
	                                                action = $PIMAction
	                                                justification = $Justification
                                                    roleDefinitionId = $roleDefinitionId
                                                    principalId = $principalId
	                                                directoryScopeId = "/administrativeUnits/$($AUId)"
                                                }

                                    If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                        {
                                            # BUG FIX 5: Compute start/end using a single UTC base object
                                            $startDateTimeObj = [datetime]::UtcNow
                                            $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")
                                            $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                                $params += @{
	                                                            scheduleInfo = @{
		                                                                            startDateTime = $startDateTime
		                                                                            expiration = @{
			                                                                                        type = "AfterDateTime"
			                                                                                        endDateTime = $endDateTime
		                                                                            }
                                                                                }
                                                            }
                                        }


                                    ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                        {
                                            # BUG FIX 5: Removed dead $endDateTime calculation for permanent assignments
                                            $startDateTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK")

                                                $params += @{
	                                                            scheduleInfo = @{
   	                                                                                startDateTime = $startDateTime
		                                                                            expiration = @{
			                                                                                            type = "noExpiration"
		                                                                                            }
                                                                                }
                                                            }
                                        }
                    
                                    If ($AssignmentType -eq "Eligible")
                                        {
                                            Write-Host ""
                                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as eligible"
                                            Write-host "      for role $($GroupName)"

                                            Try {
                                                New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                            }
                                            Catch {
                                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                            }
                                        }
                                    ElseIf ($AssignmentType -eq "Active")
                                        {
                                            Write-Host ""
                                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as active"
                                            write-host "      for role $($GroupName)"
                                            Try {
                                                New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                            }
                                            Catch {
                                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                            }
                                        }
                                }
                        }
                }
        }
}


Function Assign-Roles-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$GroupRoleAssignmentsFile
         )

######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }

######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $GroupRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            # BUG FIX 1: Reset $PIMAction at the start of every iteration
            $PIMAction = "NoAction"

            $GroupTag            = $Entry.GroupTag
            $RoleDefinitionName  = $Entry.RoleDefinitionName
            $Action              = $Entry.Action
            $AutoExtend          = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting      = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType      = $Entry.AssignmentType
            $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
            $Permanent           = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            If ($AutoExtend -eq "TRUE")
                {
                    $AutoExtend = $TRUE
                }
            Else
                {
                    $AutoExtend = $FALSE
                }

            If ($UpdateExisting -eq "TRUE")
                {
                    $UpdateExisting = $TRUE
                }
            Else
                {
                    $UpdateExisting = $FALSE
                }


            # Workaround due to nesting is NOT supported on Active Role Assignment
            # Nesting is currently not supported for groups that can be assigned to a role.
            # New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest
            # Solution - Assign Role directly to PAG group, if AssignmentType = Active

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            If ($RoleDefinitionName)
                {
                    # Check if group already exist (PERF: cached lookup; v2.4.0)
                    $Group = Resolve-PimGroupCached -DisplayName $Groupname

                If (!($Group))   # create group if it doesn't exist !
                    {
                        If ($GroupName.Length -ge 64)
                            {
                                Write-Host ""
                                Write-Host "Creating group $($GroupName)"

                                New-MgGroup -SecurityEnabled:$true `
                                            -MailEnabled:$false `
                                            -isAssignableToRole:$true `
                                            -groupTypes:@() `
                                            -displayName:$GroupName `
                                            -mailNickname:$GroupName.Substring(0,64)
                            }
                        Else
                            {
                                Write-Host ""
                                Write-Host "Creating group $($GroupName)"

                                New-MgGroup -SecurityEnabled:$true `
                                            -MailEnabled:$false `
                                            -isAssignableToRole:$true `
                                            -groupTypes:@() `
                                            -displayName:$GroupName `
                                            -mailNickname:$GroupName

                            }

                        # Waiting to let it sync
                        Start-Sleep -Seconds 3
                        # PERF: just-created group; force Graph fetch + cache-add (v2.4.0).
                        $Group = Resolve-PimGroupCached -DisplayName $Groupname -NoCache
                    }
                    If ($Group)
                        {

                            # Search for RoleDefinition in array list of Role Definitions
                            $roleDefinition = $Global:Role_Group_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
                            If ($roleDefinition) {
                                $roleDefinitionId = $roleDefinition.Id
                            } else {
                                write-host ""
                                write-host "Cannot find $($RoleDefinitionName) in Entra ID anymore" -ForegroundColor Yellow
                            }

                            # Get Id of new group created
                            $principalId = $Group.Id

                            # Workaround: map AssignmentType for existing-assignment lookup
                            # BUG FIX 4: was "If ($AssignmentType = 'Active')" — assignment operator always evaluates
                            # true and overwrote $AssignmentType even for Eligible entries. Fixed to -eq.
                            # BUG FIX (new): Graph SDK exports "Eligibility" not "Eligible" — map both directions.
                            $AssignmentTypeLookup = $AssignmentType
                            If ($AssignmentType -eq 'Active')   { $AssignmentTypeLookup = 'Assigned'    }
                            
                            $CheckExistingAssignment = $CurrentAssignments_EntraIDRoles | where-object { ($_.AssignmentType -eq $AssignmentTypeLookup) -and ($_.PrincipalId -eq $Group.Id) -and ($_.RoleId -eq $roleDefinitionId)  }

                            # Graph fallback: snapshot may miss Active (Assigned) global-scope role assignments.
                            # Verify directly against Graph before concluding the assignment doesn't exist.
                            If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Active') )
                                {
                                    $GraphCheck = Get-MgBetaRoleManagementDirectoryRoleAssignmentSchedule `
                                                    -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/'" `
                                                    -ErrorAction SilentlyContinue
                                    # Third fallback: direct (non-PIM-scheduled) role assignments
                                    If (!$GraphCheck)
                                        {
                                            $GraphCheckDirect = Get-MgBetaRoleManagementDirectoryRoleAssignment `
                                                            -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/'" `
                                                            -ErrorAction SilentlyContinue
                                            If ($GraphCheckDirect)
                                                {
                                                    $GraphCheck = [PSCustomObject]@{
                                                        ScheduleInfo = [PSCustomObject]@{ Expiration = [PSCustomObject]@{ Type = "noExpiration"; EndDateTime = $null } }
                                                    }
                                                }
                                        }
                                    If ($GraphCheck)
                                        {
                                            write-host ""
                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                            $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                            $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                            $CheckExistingAssignment = [PSCustomObject]@{
                                                AssignmentType            = 'Assigned'
                                                RoleId                    = $roleDefinitionId
                                                PrincipalId               = $Group.Id
                                                DirectoryScopeId          = '/'
                                                ScheduleExpirationType    = $GraphExpirationType
                                                ScheduleExpirationEndDateTime = $GraphEndDateTime
                                            }
                                        }
                                }

                            # Same fallback for Eligible assignments missing from snapshot.
                            If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Eligible') )
                                {
                                    $GraphCheck = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule `
                                                    -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/'" `
                                                    -ErrorAction SilentlyContinue
                                    # Third fallback: direct eligibility assignments
                                    If (!$GraphCheck)
                                        {
                                            $GraphCheckDirect = Get-MgBetaRoleManagementDirectoryRoleAssignment `
                                                            -Filter "principalId eq '$($Group.Id)' and roleDefinitionId eq '$roleDefinitionId' and directoryScopeId eq '/'" `
                                                            -ErrorAction SilentlyContinue
                                            If ($GraphCheckDirect)
                                                {
                                                    $GraphCheck = [PSCustomObject]@{
                                                        ScheduleInfo = [PSCustomObject]@{ Expiration = [PSCustomObject]@{ Type = "noExpiration"; EndDateTime = $null } }
                                                    }
                                                }
                                        }
                                    If ($GraphCheck)
                                        {
                                            write-host ""
                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                            $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                            $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                            $CheckExistingAssignment = [PSCustomObject]@{
                                                AssignmentType            = 'Eligible'
                                                RoleId                    = $roleDefinitionId
                                                PrincipalId               = $Group.Id
                                                DirectoryScopeId          = '/'
                                                ScheduleExpirationType    = $GraphExpirationType
                                                ScheduleExpirationEndDateTime = $GraphEndDateTime
                                            }
                                        }
                                }

                            If ($CheckExistingAssignment)
                                {
                                    $CheckExistingAssignment = $CheckExistingAssignment[0]

                                    # Check if assignment is Permanent/noExpiration
                                    If ($CheckExistingAssignment.ScheduleExpirationType -ieq "noExpiration")
                                        {
                                            If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                {
                                                    Write-host "UPDATE: $RoleDefinitionName -> $($Group.DisplayName) (refreshing assignment details)" -ForegroundColor Yellow
                                                    $PIMAction = "AdminUpdate"
                                                }
                                            Else
                                                {
                                                    # BUG FIX 3: Permanent assignment exists, no update requested - explicitly NoAction
                                                    Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Green
                                                    $PIMAction = "NoAction"
                                                }
                                        }
                                    Else
                                        {
                                            # not permanent - check expiry
                                            $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                            If ([string]::IsNullOrWhiteSpace($ValueChk))
                                                {
                                                    Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Green
                                                    $PIMAction = "NoAction"
                                                }
                                            Else
                                                {
                                                    $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End (Ensure-DateTime $ExpirationDate)).TotalDays
                                                    $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)
                                                    If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                                        {
                                                            write-host ""
                                                            Write-host "EXTEND: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days)" -ForegroundColor Yellow
                                                            write-host "Assignment will be extended as AutoExtend=TRUE"
                                                            write-host ""
                                                            $PIMAction = "AdminExtend"
                                                        }
                                                    ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                        {
                                                            write-host ""
                                                            Write-host "Existing Assignment will be updated with assignment details"
                                                            Write-host "Mode: AdminUpdate"
                                                            write-host ""
                                                            $PIMAction = "AdminUpdate"
                                                        }
                                                    Else
                                                        {
                                                            write-host ""
                                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                }
                                        }
                                }

                            ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                                {
                                    write-host ""
                                    $PIMAction = "AdminAssign"
                                }

                            If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                                {
                                    Write-host "REMOVE: $RoleDefinitionName -> $($Group.DisplayName)" -ForegroundColor Red
                                    $PIMAction = "AdminRemove"
                                }

                            ################################################################################################################
                            If ($PIMaction -ne "NoAction")
                                {
                                # Print action summary - only for AdminAssign (not for Extend/Update)
                                If ($PIMAction -eq "AdminAssign")
                                    {
                                        Write-host "ASSIGN: $RoleDefinitionName -> $($Group.DisplayName) (new assignment)" -ForegroundColor Cyan
                                    }

                                    $Justification = "IAC: Assigning role $($RoleDefinitionName) to role group $($Group.DisplayName)"

                                    If ($roleDefinitionId)
                                        {
                                            $params = @{
	                                                        action = $PIMAction
	                                                        justification = $Justification
	                                                        directoryScopeId = "/"
                                                            roleDefinitionId = $roleDefinitionId
                                                            principalId = $principalId
                                                        }

                                            If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Compute start/end using a single UTC base object
                                                    $startDateTimeObj = [datetime]::UtcNow
                                                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")
                                                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
		                                                                                    startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                type = "AfterDateTime"
			                                                                                                endDateTime = $endDateTime
		                                                                                    }
                                                                                        }
                                                                    }
                                                }


                                            ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Removed dead $endDateTime calculation for permanent assignments
                                                    $startDateTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
   	                                                                                        startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                    type = "noExpiration"
		                                                                                                    }
                                                                                        }
                                                                    }
                                                }
                    
                                            If ($AssignmentType -eq "Eligible")
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($RoleDefinitionName) role as eligible"
                                                    Write-host "      for role $($GroupName)"

                                                    Try {
                                                        New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                                    }
                                                    Catch {
                                                        Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                                    }
                                                }
                                            ElseIf ( ($AssignmentType -eq "Active") -or ($AssignmentType -eq "Assigned") )
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($RoleDefinitionName) role as active"
                                                    write-host "      for role $($GroupName)"
                                                    Try {
                                                        New-MgBetaRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                                                    }
                                                    Catch {
                                                        Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                                    }
                                                }
                                        }
                                }
                        }
                }
        }
}




Function Assign-Roles-Groups-From-SQL
{
    param(

            [Parameter(mandatory)]
                [string]$SQLTable
         )

######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            $GroupTag            = $Entry.GroupTag
            $RoleDefinitionName  = $Entry.RoleDefinitionName
            $AssignmentType      = $Entry.AssignmentType
            $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
            $Permanent           = $Entry.Permanent
            # BUG FIX 8: These fields were missing and left uninitialized/stale
            $Action              = $Entry.Action
            $AutoExtend          = $Entry.AutoExtend
            $UpdateExisting      = $Entry.UpdateExisting

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            If ($AutoExtend -eq "TRUE")
                {
                    $AutoExtend = $TRUE
                }
            Else
                {
                    $AutoExtend = $FALSE
                }

            If ($UpdateExisting -eq "TRUE")
                {
                    $UpdateExisting = $TRUE
                }
            Else
                {
                    $UpdateExisting = $FALSE
                }

            # Workaround due to nesting is NOT supported on Active Role Assignment
            # Nesting is currently not supported for groups that can be assigned to a role.
            # New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest
            # Solution - Assign Role directly to PAG group, if AssignmentType = Active

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            If ($RoleDefinitionName)
                {
                    Create-PIM-Group-Role -GroupName $GroupName `
                                          -RoleDefinitionName $RoleDefinitionName `
                                          -AssignmentType $AssignmentType `
                                          -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                          -Permanent:$Permanent
                }
        }
}


Function Assign-AzResources-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile
         )

######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }

######################################################################################################################
# Assignment of PIM for Azure Resources / Privileged Access Group (PAG)
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            # BUG FIX 1: Reset $PIMAction at the start of every iteration
            $PIMAction = "NoAction"

            $GroupTag              = $Entry.GroupTag
            $AzScope               = $Entry.AzScope
            $AzScopePermission     = $Entry.AzScopePermission
            $Action                = $Entry.Action
            $AutoExtend            = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting        = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            If ($AutoExtend -eq "TRUE")
                {
                    $AutoExtend = $TRUE
                }
            Else
                {
                    $AutoExtend = $FALSE
                }

            If ($UpdateExisting -eq "TRUE")
                {
                    $UpdateExisting = $TRUE
                }
            Else
                {
                    $UpdateExisting = $FALSE
                }

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }
            
            # Check if group already exist (PERF: cached lookup; v2.4.0)
                $Group = Resolve-PimGroupCached -DisplayName $Groupname

                If (!($Group))   # create group if it doesn't exist !
                    {
                        If ($GroupName.Length -ge 64)
                            {
                                Write-Host ""
                                Write-Host "Creating group $($GroupName)"

                                New-MgGroup -SecurityEnabled:$true `
                                            -MailEnabled:$false `
                                            -isAssignableToRole:$false `
                                            -groupTypes:@() `
                                            -displayName:$GroupName `
                                            -mailNickname:$GroupName.Substring(0,64)
                            }
                        Else
                            {
                                Write-Host ""
                                Write-Host "Creating group $($GroupName)"

                                New-MgGroup -SecurityEnabled:$true `
                                            -MailEnabled:$false `
                                            -isAssignableToRole:$false `
                                            -groupTypes:@() `
                                            -displayName:$GroupName `
                                            -mailNickname:$GroupName

                            }

                        # Waiting to let it sync
                        Start-Sleep -Seconds 3
                        # PERF: just-created group; force Graph fetch + cache-add (v2.4.0).
                        $Group = Resolve-PimGroupCached -DisplayName $Groupname -NoCache
                    }
                If ($Group)
                    {
                        # Search for AzScopePermission in array list of Role Definitions
                        $roleDefinition = Get-AzRoleDefinition $AzScopePermission -Erroraction SilentlyContinue -WarningAction SilentlyContinue
                        $roleId = $roleDefinition.Id
                        $roleDefinitionId = $AzScope + "/providers/Microsoft.Authorization/roleDefinitions/" + $roleDefinition.Id

                        # Get Id of new group created
                        $principalId = $Group.Id

                        $CheckExistingAssignment = $CurrentAssignments_AzureRoles | where-object { ($_.AssignmentType -eq $AssignmentType) -and ($_.PrincipalId -eq $principalId) -and ($_.RoleIdShort -eq $RoleId) -and ($_.ResourceScope -eq $AzScope) }

                        # Graph fallback: snapshot may miss Azure Resource assignments.
                        # Query ARM directly before concluding the assignment doesn't exist.
                        If ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                            {
                                $Headers = Get-AzPimTokenCached
                                If ($Headers)
                                    {
                                        If ($AssignmentType -eq "Active")
                                            {
                                                $AzCheckUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01-preview&`$filter=principalId eq '$principalId'"
                                            }
                                        Else
                                            {
                                                $AzCheckUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01-preview&`$filter=principalId eq '$principalId'"
                                            }
                                        Try {
                                            $AzCheckResponse = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzCheckUri -Headers $Headers -ErrorAction SilentlyContinue
                                            $AzCheckData = $AzCheckResponse.Content | ConvertFrom-Json
                                            $AzExisting = $AzCheckData.value | Where-Object { $_.properties.roleDefinitionId -like "*$roleId*" }
                                            If ($AzExisting)
                                                {
                                                    write-host ""
                                                    Write-host "Existing Assignment found via ARM (not in snapshot) ... treating as existing"
                                                    $AzExpiry = $AzExisting[0].properties.endDateTime
                                                    $CheckExistingAssignment = [PSCustomObject]@{
                                                        AssignmentType            = $AssignmentType
                                                        PrincipalId               = $principalId
                                                        RoleIdShort               = $roleId
                                                        ResourceScope             = $AzScope
                                                        SchedulePermanent         = [string]::IsNullOrWhiteSpace($AzExpiry)
                                                        ScheduleExpirationEndDateTime = $AzExpiry
                                                    }
                                                }
                                        }
                                        Catch { } # Silently ignore - will fall through to AdminAssign
                                    }
                            }

                        If ($CheckExistingAssignment)
                            {
                                $CheckExistingAssignment = $CheckExistingAssignment[0]

                                # Check if assignment is Permanent
                                If ( ($CheckExistingAssignment.SchedulePermanent -eq $true) -and ($Permanent -eq $true) )
                                    {
                                        If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                            {
                                                write-host ""
                                                Write-host "Existing Assignment will be updated with assignment details"
                                                Write-host "Mode: AdminUpdate"
                                                write-host ""
                                                $PIMAction = "AdminUpdate"
                                            }
                                        Else
                                            {
                                                # BUG FIX 3: Permanent assignment exists, no update requested - explicitly NoAction
                                                write-host ""
                                                Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)"
                                                Write-host "Mode: NoAction"
                                                write-host ""
                                                $PIMAction = "NoAction"
                                            }
                                    }
                                Else
                                    {
                                        # not permanent
                                        $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                        If (![string]::IsNullOrWhiteSpace($ValueChk))
                                            {
                                                # has an expiry date - calculate days remaining
                                                $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                                If (-not $ExpirationDate)
                                                    {
                                                        # Unparseable expiry -> assume full window to avoid bogus 99-year math
                                                        $NumOfDaysBeforeExpiration = $NumOfDaysWhenExpire
                                                    }
                                                Else
                                                    {
                                                        $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End $ExpirationDate).TotalDays
                                                        $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)
                                                    }
                                            }
                                        Else
                                            {
                                                # no expiry date - treat as full remaining days for AutoExtend comparison
                                                $NumOfDaysBeforeExpiration = $NumOfDaysWhenExpire
                                            }
                                        If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                            {
                                                # change action from AdminAssign to AdminExtend
                                                write-host ""
                                                Write-host "Existing Assignment will expire in $($NumOfDaysBeforeExpiration) days"
                                                write-host "Assignment will be extended as AutoExtend=TRUE"
                                                Write-host "Mode: AdminExtend"
                                                write-host ""
                                                $PIMAction = "AdminExtend"
                                            }
                                        ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                            {
                                                write-host ""
                                                Write-host "Existing Assignment will be updated with assignment details"
                                                Write-host "Mode: AdminUpdate"
                                                write-host ""
                                                $PIMAction = "AdminUpdate"
                                            }
                                        Else
                                            {
                                                # BUG FIX 2: Simplified - assignment exists, not expiring soon -> skip
                                                write-host ""
                                                Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                Write-host "Mode: NoAction"
                                                write-host ""
                                                $PIMAction = "NoAction"
                                            }
                                    }
                            }

                        ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                            {
                                write-host ""
                                $PIMAction = "AdminAssign"
                            }

                        If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                            {
                                write-host ""
                                Write-host "Assignment was found .... removing"
                                Write-host "Mode: AdminRemove"
                                write-host ""
                                $PIMAction = "AdminRemove"
                            }

                        ################################################################################################################
                        If ($PIMaction -ne "NoAction")
                            {
                            # Print action summary - only for AdminAssign (not for Extend/Update)
                            If ($PIMAction -eq "AdminAssign")
                                {
                                    write-host ""
                                    Write-host "Assignment was NOT found .... creating"
                                    Write-host "Mode: AdminAssign"
                                    write-host ""
                                }

                                $Justification = "IAC: Assigning role $($AzScopePermission) to group $($Group.DisplayName)"

                                If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                    {
                                        # BUG FIX 5: Compute start/end using a single UTC base object
                                        $startDateTimeObj = [datetime]::UtcNow
                                        $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")
                                        $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                        $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                                    properties = @{
                                                                                        principalId = $principalId
                                                                                        roleDefinitionId = $roleDefinitionId
	                                                                                    requestType = $PIMAction
                                                                                        justification = $Justification
                                                                                        scheduleInfo = @{
                                                                                                        startDateTime = $startDateTime
                                                                                                        expiration = @{
			                                                                                                                type = "AfterDateTime"
			                                                                                                                endDateTime = $endDateTime
                                                                                                                        }
                                                                                                    }
                                                                                    }
                                                                }
                                    }
                                ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                    {
                                        # BUG FIX 5: Removed dead $endDateTime calculation for permanent assignments
                                        $startDateTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK")

                                        $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                                    properties = @{
                                                                                        principalId = $principalId
                                                                                        roleDefinitionId = $roleDefinitionId
                                                                                        justification = $Justification
	                                                                                    requestType = $PIMAction
                                                                                        scheduleInfo = @{
                                                                                                            startDateTime = $startDateTime
                                                                                                            expiration = @{
			                                                                                                                    type = "noExpiration"
                                                                                                                          }
                                                                                                        }
                                                                                  }
                                                                }
                                    }

                                $Headers = Get-AzPimTokenCached

                                $Guid = (new-guid).Guid

                                $AzRoleAssignmentBodyJson = $AzRoleAssignmentBody | ConvertTo-Json -Depth 20

                                $AzDisplayName = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName
                                If ($AssignmentType -eq "Eligible")
                                    {
                                        Write-Host ""
                                        Write-Host "PIM - Assigning $($AzScopePermission) role as eligible"
                                        Write-host "      for group $($GroupName)"
                                        Write-Host "      on scope [ $($AzDisplayName) ]"
                                        Write-host "      $($AzScope) "

                                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                                        Try {
                                            invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson -ErrorAction Stop | Out-Null
                                        }
                                        Catch {
                                            # ARM can return plain-text errors (e.g. rate limit) instead of JSON - guard parse
                                            $ErrBody = $null
                                            Try { $ErrBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop } Catch {}
                                            $ErrCode = If ($ErrBody) { $ErrBody.error.code } Else { $_.Exception.Message }
                                            If ($ErrCode -eq "RoleAssignmentExists" -or $ErrCode -like "*RoleAssignmentExists*")
                                                { Write-host "Existing Assignment found via ARM (API confirmed) ... skipping" -ForegroundColor Green }
                                            ElseIf ($ErrCode -eq "RoleAssignmentDoesNotExist" -or $ErrCode -like "*RoleAssignmentDoesNotExist*")
                                                { Write-host "Assignment already removed (not found in ARM) ... skipping" -ForegroundColor Green }
                                            Else
                                                { Write-host "ERROR: $ErrCode" -ForegroundColor Red }
                                        }
                                    }
                                ElseIf ($AssignmentType -eq "Active")
                                    {
                                        Write-Host ""
                                        Write-Host "PIM - Assigning $($AzScopePermission) role as active"
                                        Write-host "      for group $($GroupName)"
                                        Write-Host "      on scope [ $($AzDisplayName) ]"
                                        Write-host "      $($AzScope) "

                                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                                        Try {
                                            invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson -ErrorAction Stop | Out-Null
                                        }
                                        Catch {
                                            # ARM can return plain-text errors (e.g. rate limit) instead of JSON - guard parse
                                            $ErrBody = $null
                                            Try { $ErrBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop } Catch {}
                                            $ErrCode = If ($ErrBody) { $ErrBody.error.code } Else { $_.Exception.Message }
                                            If ($ErrCode -eq "RoleAssignmentExists" -or $ErrCode -like "*RoleAssignmentExists*")
                                                { Write-host "Existing Assignment found via ARM (API confirmed) ... skipping" -ForegroundColor Green }
                                            ElseIf ($ErrCode -eq "RoleAssignmentDoesNotExist" -or $ErrCode -like "*RoleAssignmentDoesNotExist*")
                                                { Write-host "Assignment already removed (not found in ARM) ... skipping" -ForegroundColor Green }
                                            Else
                                                { Write-host "ERROR: $ErrCode" -ForegroundColor Red }
                                        }
                                    }
                            }
                    }
        }
}


Function Assign-AzResources-Groups-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$SQLTable
         )

######################################################################################################################
# Assignment of PIM for Azure Resources / Privileged Access Group (PAG)
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            $GroupTag              = $Entry.GroupTag
            $AzScope               = $Entry.AzScope
            $AzScopePermission     = $Entry.AzScopePermission
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }
            
            Assign-PIM-Group-Resource -GroupName $GroupName `
                                      -AzScope $AzScope `
                                      -AzScopePermission $AzScopePermission `
                                      -AssignmentType $AssignmentType `
                                      -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                      -Permanent:$Permanent `
                                      -ResourceInfoArray $Global:AzureResources_Definitions_ID
        }
}

Function Assign-PIMForGroups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$PIMForGroupsAssignmentsFile
         )


######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }

######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $PIMForGroupsAssignmentsFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            # BUG FIX 1: Reset $PIMAction at the start of every iteration
            $PIMAction = "NoAction"

            <# Types of Actions
                Assign: For administrators to assign roles to users or groups.
                adminRemove: For administrators to remove users or groups from roles.
                adminUpdate: For administrators to change existing role assignments.
                adminExtend: For administrators to extend expiring assignments.
                adminRenew: For administrators to renew expired assignments.
            #>

            $GroupTagTarget      = $Entry.TargetGroupTag
            $GroupTagSource      = $Entry.SourceGroupTag
            $Action              = $Entry.Action
            $AutoExtend          = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting      = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType      = $Entry.AssignmentType
            $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
            $Permanent           = $Entry.Permanent

            If ( ($GroupTagTarget -like  "$Global:PIM_GroupTag_Scoped_StartsWith*") -or ($Global:PIM_GroupTag_Scoped_StartsWith -eq $null) )
                {

                    If ($Permanent -eq "TRUE")
                        {
                            $Permanent = $TRUE
                        }
                    Else
                        {
                            $Permanent = $FALSE
                        }

                    If ($AutoExtend -eq "TRUE")
                        {
                            $AutoExtend = $TRUE
                        }
                    Else
                        {
                            $AutoExtend = $FALSE
                        }

                    If ($UpdateExisting -eq "TRUE")
                        {
                            $UpdateExisting = $TRUE
                        }
                    Else
                        {
                            $UpdateExisting = $FALSE
                        }

                    If ($GroupTagSource)
                        {
                            # Get actual group, based on tags
                            $GroupSource = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTagSource }

                            If ($GroupSource)
                                {
                                    $GroupNameSource = $GroupSource.GroupName
                                }
                            Else
                                {
                                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTagSource) in the definitions" -ForegroundColor Red
                                }
                        }

                    If ($GroupTagTarget)
                        {
                            # Get actual group, based on tags
                            $GroupTarget = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTagTarget }

                            If ($GroupTarget)
                                {
                                    $GroupNameTarget = $GroupTarget.GroupName
                                }
                            Else
                                {
                                    Write-host "ERROR: Could NOT find any groups with GroupTag $($GroupTagTarget) in the definitions" -ForegroundColor Red
                                }

                            $GroupName = $GroupNameSource
                            $PAG_GroupName = $GroupNameTarget

                            # Check if group already exist (PERF: cached lookups; v2.4.0)
                            $Group = Resolve-PimGroupCached -DisplayName $Groupname

                            # Check if group already exist
                            $PAGGroup = Resolve-PimGroupCached -DisplayName $PAG_GroupName


                            If ( ($Group) -and ($PAGGroup) )
                                {
                                    # BUG FIX: Graph SDK exports "Assigned"/"Eligibility" not "Active"/"Eligible"
                                    $AssignmentTypeLookup = $AssignmentType
                                    If ($AssignmentType -eq 'Active')   { $AssignmentTypeLookup = 'Assigned'    }
                                    
                                    $CheckExistingAssignment = $CurrentAssignments_PIM4Groups | where-object { ($_.AssignmentType -eq $AssignmentTypeLookup) -and ($_.GroupId -eq $Group.Id) -and ($_.PrincipalId -eq $PAGGroup.Id) }

                                    # Graph fallback: snapshot may miss Active/Eligible PIM group membership assignments.
                                    If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Active') )
                                        {
                                            $GraphCheck = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule `
                                                            -Filter "groupId eq '$($Group.Id)' and principalId eq '$($PAGGroup.Id)' and accessId eq 'member'" `
                                                            -ErrorAction SilentlyContinue
                                            If (!$GraphCheck)
                                                {
                                                    # Third fallback: direct group membership (non-PIM-scheduled)
                                                    $GraphCheckDirect = Get-MgGroupMember -GroupId $Group.Id -ErrorAction SilentlyContinue |
                                                                        Where-Object { $_.Id -eq $PAGGroup.Id }
                                                    If ($GraphCheckDirect)
                                                        {
                                                            $GraphCheck = [PSCustomObject]@{
                                                                ScheduleInfo = [PSCustomObject]@{ Expiration = [PSCustomObject]@{ Type = "noExpiration"; EndDateTime = $null } }
                                                            }
                                                        }
                                                }
                                            If ($GraphCheck)
                                                {
                                                    write-host ""
                                                    Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                                    $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                                    $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                                    $CheckExistingAssignment = [PSCustomObject]@{
                                                        AssignmentType            = 'Assigned'
                                                        GroupId                   = $Group.Id
                                                        PrincipalId               = $PAGGroup.Id
                                                        ScheduleExpirationType    = $GraphExpirationType
                                                        ScheduleExpirationEndDateTime = $GraphEndDateTime
                                                    }
                                                }
                                        }

                                    If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Eligible') )
                                        {
                                            # v2.4.1: consume tenant-wide preload from Get-PimGroupSchedulesPreloaded
                                            # (auto-triggered on first call). Replaces the per-row Graph filter that
                                            # cost ~600ms x ~1000 rows = ~6 min on a stale-snapshot Baseline run.
                                            # The helper handles failures internally and returns $null on miss.
                                            $GraphCheck = Get-PimGroupSchedule -GroupId $Group.Id -PrincipalId $PAGGroup.Id -AssignmentType Eligible -AccessId member
                                            If ($GraphCheck)
                                                {
                                                    write-host ""
                                                    Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                                    $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                                    $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                                    $CheckExistingAssignment = [PSCustomObject]@{
                                                        AssignmentType            = 'Eligible'
                                                        GroupId                   = $Group.Id
                                                        PrincipalId               = $PAGGroup.Id
                                                        ScheduleExpirationType    = $GraphExpirationType
                                                        ScheduleExpirationEndDateTime = $GraphEndDateTime
                                                    }
                                                }
                                        }

                                    If ($CheckExistingAssignment)
                                        {
                                            $CheckExistingAssignment = $CheckExistingAssignment[0]

                                            # Check if assignment is Permanent/noExpiration
                                            If ($CheckExistingAssignment.ScheduleExpirationType -ieq "noExpiration")
                                                {
                                                    If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                        {
                                                            write-host ""
                                                            Write-host "Existing Assignment will be updated with assignment details"
                                                            Write-host "Mode: AdminUpdate"
                                                            write-host ""
                                                            $PIMAction = "AdminUpdate"
                                                        }
                                                    Else
                                                        {
                                                            # BUG FIX 3: Permanent assignment exists, no update requested - explicitly NoAction
                                                            write-host ""
                                                            Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)"
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                }
                                            Else
                                                {
                                                    # not permanent - check expiry
                                                    $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                                    If ([string]::IsNullOrWhiteSpace($ValueChk))
                                                        {
                                                            write-host ""
                                                            Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)"
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                    Else
                                                        {
                                                            $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                                            If (-not $ExpirationDate)
                                                                {
                                                                    write-host ""
                                                                    Write-host "OK - Exists (unparseable expiry '$ValueChk'): $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Yellow
                                                                    Write-host "Mode: NoAction"
                                                                    write-host ""
                                                                    $PIMAction = "NoAction"
                                                                }
                                                            Else
                                                                {
                                                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End $ExpirationDate).TotalDays
                                                                    $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)
                                                                    If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                                                        {
                                                                            write-host ""
                                                                            Write-host "EXTEND: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days)" -ForegroundColor Yellow
                                                                            write-host "Assignment will be extended as AutoExtend=TRUE"
                                                                                    write-host ""
                                                                            $PIMAction = "AdminExtend"
                                                                        }
                                                                    ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                                        {
                                                                            write-host ""
                                                                            Write-host "Existing Assignment will be updated with assignment details"
                                                                            Write-host "Mode: AdminUpdate"
                                                                            write-host ""
                                                                            $PIMAction = "AdminUpdate"
                                                                        }
                                                                    Else
                                                                        {
                                                                            write-host ""
                                                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                                            Write-host "Mode: NoAction"
                                                                            write-host ""
                                                                            $PIMAction = "NoAction"
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                    
                                    ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                                        {
                                            write-host ""
                                            $PIMAction = "AdminAssign"
                                        }

                                    If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                                        {
                                            write-host ""
                                            Write-host "Assignment was found .... removing"
                                            Write-host "Mode: AdminRemove"
                                            write-host ""
                                            $PIMAction = "AdminRemove"
                                        }

                                    ################################################################################################################
                                    # BUG FIX - REMEMBER TO UNHIDE WORKAROUND in PIM-Function.psm1 - search for PIM4Groups - +1 year old assignments wasn't found when using Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest
                                    
                                    #    $PIMAction = "AdminUpdate"
                                    
                                    ################################################################################################################
                                    
                                    If ($PIMaction -ne "NoAction")
                                        {
                                        # Print action summary - only for AdminAssign (not for Extend/Update)
                                        If ($PIMAction -eq "AdminAssign")
                                            {
                                                write-host ""
                                                Write-host "Assignment was NOT found .... creating"
                                                Write-host "Mode: AdminAssign"
                                                write-host ""
                                            }
                                            $Justification = "IAC: Assigning access to group $($GroupName) for PIM group $($PAG_GroupName)"

                                            $params = @{
	                                            accessId = "member"
	                                            groupId = $Group.Id
	                                            action = $PIMAction
	                                            justification = $Justification
	                                            directoryScopeId = "/"
                                                principalId = $PAGGroup.Id
                                            }

                                            If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Compute start/end using a single UTC base object
                                                    $startDateTimeObj = [datetime]::UtcNow
                                                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")
                                                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
		                                                                                    startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                type = "AfterDateTime"
			                                                                                                endDateTime = $endDateTime
		                                                                                    }
                                                                                        }
                                                                    }
                                                }


                                            ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                                {
                                                    # BUG FIX 5: Removed dead $endDateTime calculation for permanent assignments
                                                    $startDateTime = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK")

                                                        $params += @{
	                                                                    scheduleInfo = @{
   	                                                                                        startDateTime = $startDateTime
		                                                                                    expiration = @{
			                                                                                                    type = "noExpiration"
		                                                                                                    }
                                                                                        }
                                                                    }
                                                }

                                            If ($AssignmentType -eq "Eligible")
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($PAG_GroupName) as Eligible "
                                                    Write-host "      to group $($Groupname)"
                                                    Write-host ""

                                                    Try {
                                                        New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop
                                                    }
                                                    Catch {
                                                        $ErrCode = $_.FullyQualifiedErrorId
                                                        If ($ErrCode -like "*RoleAssignmentExists*")
                                                            {
                                                                Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green
                                                            }
                                                        ElseIf ($ErrCode -like "*RoleAssignmentDoesNotExist*")
                                                            {
                                                                Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green
                                                            }
                                                        ElseIf ($ErrCode -like "*NestingNotSupportedForRoleAssignableGroup*")
                                                            {
                                                                Write-host "SKIP: Nesting not supported - target group is role-assignable. Use Assign-Roles-Groups-From-file-CSV for this assignment." -ForegroundColor Yellow
                                                            }
                                                        Else
                                                            {
                                                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                                            }
                                                    }
                                                }
                                            ElseIf ($AssignmentType -eq "Active")
                                                {
                                                    Write-Host ""
                                                    Write-Host "PIM - Assigning $($PAG_GroupName) as Active to group $($Groupname)"

                                                    Try {
                                                        New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                                                    }
                                                    Catch {
                                                        $ErrCode = $_.FullyQualifiedErrorId
                                                        If ($ErrCode -like "*RoleAssignmentExists*")
                                                            {
                                                                Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green
                                                            }
                                                        ElseIf ($ErrCode -like "*RoleAssignmentDoesNotExist*")
                                                            {
                                                                Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green
                                                            }
                                                        ElseIf ($ErrCode -like "*NestingNotSupportedForRoleAssignableGroup*")
                                                            {
                                                                Write-host "SKIP: Nesting not supported - target group is role-assignable. Use Assign-Roles-Groups-From-file-CSV for this assignment." -ForegroundColor Yellow
                                                            }
                                                        Else
                                                            {
                                                                Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                                                            }
                                                    }
                                                }
                                        }
                                }
                        }
                }
        }
}



Function CreateUpdate-Accounts-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AccountsDefinitionFile,
            [Parameter()]
                [string]$PathAdmins,
            [Parameter()]
                [string]$PathAdminsL0T0,
            [Parameter()]
                [Object]$Credentials,
            [Parameter()]
                [switch]$OnlyAD = $false,
            [Parameter()]
                [switch]$OnlyID = $false
         )


######################################################################################################################
# Admin Accounts | Create/Update
######################################################################################################################

    # Exchange Online
    # v2 AutomateIT contract: once a solution is on the AutomateIT platform,
    # ALL auth goes through the HighPriv (Modern) SPN -- the operational
    # identity. Bootstrap SPN stays min-privilege (KV-read-only). EXO is the
    # only path here that requires cert (no client_secret support for
    # app-only), so the Modern SPN gets its OWN cert (distinct from
    # Bootstrap) -- provision once per tenant via New-PlatformModernCert.ps1,
    # which generates + installs the cert locally, registers it on the SPN,
    # and writes the thumbprint to KV. Connect-PlatformModern then exposes
    # the thumbprint via the global on every engine run.
    Manage-Powershell-Module -ModuleName 'ExchangeOnlineManagement' -Scope AllUsers
    $exoAppId = $global:HighPriv_Modern_ApplicationID_Azure
    $exoThumb = $global:HighPriv_Modern_CertificateThumbprint_Azure
    if (-not $exoAppId -or -not $exoThumb) {
        throw @"
Connect-ExchangeOnline: Modern SPN cert not usable for EXO app-only auth.
  AppId      : $exoAppId
  Thumbprint : $exoThumb

Fix (one-time per tenant):
  1. Confirm Initialize-PlatformAutomationFramework ran successfully
     (`$global:HighPriv_Modern_ApplicationID_Azure` populated above).
  2. From an ELEVATED PowerShell on this host, provision the Modern SPN cert:
       . `$global:PathScripts\SOLUTIONS\PlatformConfiguration\INTERNAL\Provision\New-PlatformModernCert.ps1
     The script creates a self-signed cert, installs it in Cert:\LocalMachine\My,
     registers it on the Modern SPN in Entra, and writes the thumbprint to
     KV as 'Modern-Thumbprint'. Idempotent -- safe to re-run.
  3. In Entra, grant the Modern SPN (one-time, manual):
       - API permission: Office 365 Exchange Online -> Exchange.ManageAsApp
         (V1, Application, admin-consented).  NOTE: this is the V1 variant.
         Despite "V2" (Exchange.ManageAsAppV2) sounding newer, cmdlet-set
         authorization for the EXO V3 module is governed by the V1 permission;
         granting only V2 results in an empty cmdlet set at connect time,
         which surfaces as the misleading 'Module could not be correctly
         formed. Please run Connect-ExchangeOnline again.' error.
       - Directory role : Exchange Recipient Administrator
  4. Re-run the launcher.
"@
    }
    # -Organization is REQUIRED for cert-based Connect-ExchangeOnline (unlike
    # the interactive path, where it's optional). The customer's repository
    # .custom.ps1 SHOULD set $TenantNameOrganization to the tenant's primary
    # .onmicrosoft.com domain, but on cold installs that variable is often
    # empty -- and the old interactive auth path silently masked the gap by
    # not requiring it. Auto-resolve from MgGraph (we're already connected
    # via Initialize-PlatformAutomationFramework) so the cert path doesn't
    # block on a missing customer-config setting.
    $exoOrg = $TenantNameOrganization
    if ([string]::IsNullOrWhiteSpace($exoOrg)) {
        try {
            $org = Get-MgOrganization -ErrorAction Stop -WarningAction SilentlyContinue
            if ($org) {
                $initial = $org.VerifiedDomains | Where-Object IsInitial -eq $true | Select-Object -First 1
                if ($initial) { $exoOrg = $initial.Name }
            }
        } catch {}
        if ([string]::IsNullOrWhiteSpace($exoOrg)) {
            throw "Connect-ExchangeOnline: `$TenantNameOrganization` is empty and Get-MgOrganization couldn't auto-resolve the initial .onmicrosoft.com domain. Set `$TenantNameOrganization = 'yourtenant.onmicrosoft.com'` in config\repository.custom.ps1."
        }
        Write-Output "  [info] `$TenantNameOrganization` not set in repository.custom.ps1; auto-resolved to '$exoOrg' from Get-MgOrganization."
    }
    # ExchangeOnlineManagement V3 has a documented runspace-state bug where
    # Connect-ExchangeOnline errors with "Module could not be correctly formed.
    # Please run Connect-ExchangeOnline again." -- and the naive retry alone
    # does NOT fix it on PS 7.5+. The full Microsoft Q&A reset chain is:
    #   1. Disconnect any prior session
    #   2. Remove EXO module AND the dynamic CreateExoPSSession* modules
    #      (these are generated proxies that retain bad state across reloads)
    #   3. Import EXO fresh with -DisableNameChecking (skips Get-Verb noise
    #      that triggers a different module-loading path in PS 7.5)
    #   4. Connect; on the V3 quirk error, repeat the whole reset chain
    function Reset-ExoModuleState {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null } catch {}
        Get-Module -Name 'CreateExoPSSession*' -ErrorAction SilentlyContinue | Remove-Module -Force -ErrorAction SilentlyContinue
        Get-Module -Name 'tmp_*' -ErrorAction SilentlyContinue | Remove-Module -Force -ErrorAction SilentlyContinue
        Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
        Import-Module ExchangeOnlineManagement -Force -DisableNameChecking -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    Reset-ExoModuleState

    Write-Output "Connecting to Exchange Online using HighPriv Modern SPN (AppId $exoAppId, cert $exoThumb, organization $exoOrg) ..."
    $exoConnected = $false
    for ($_exoAttempt = 1; $_exoAttempt -le 2; $_exoAttempt++) {
        try {
            Connect-ExchangeOnline -CertificateThumbprint $exoThumb -AppId $exoAppId -ShowProgress $false -Organization $exoOrg -ShowBanner -ErrorAction Stop
            $exoConnected = $true
            break
        } catch {
            $_exoErr = $_
            if ($_exoAttempt -eq 1 -and $_exoErr.Exception.Message -match 'Module could not be correctly formed|InternalUrgent|forming the session') {
                Write-Warning "Connect-ExchangeOnline: attempt 1 hit the EXO V3 runspace-state bug ('$($_exoErr.Exception.Message.Trim())'). Performing full module reset + retry..."
                Reset-ExoModuleState
                Start-Sleep -Seconds 3
                continue
            }
            throw $_exoErr
        }
    }
    if (-not $exoConnected) {
        throw "Connect-ExchangeOnline: both attempts failed after the EXO V3 module-reset workaround. Inspect the last error above for the real cause (not the 'Module could not be correctly formed' symptom)."
    }

    $AdminAccounts_Data = Import-csv -Path $AccountsDefinitionFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }


    ForEach ($Entry in $AdminAccounts_Data)
        {
            $FirstName              = $Entry.FirstName
            $LastName               = $Entry.LastName
            $Initials               = $Entry.Initials
            $TierLevel              = $Entry.TierLevel
            $TargetUsage            = $Entry.TargetUsage
            $TargetPlatform         = $Entry.TargetPlatform
            $UserType               = $Entry.UserType
            $UserName               = $Entry.UserName
            $UsageLocation          = $Entry.UsageLocation

            If ($global:DefaultDomainUPN) {
                write-verbose "Default Domain defined ( $($global:DefaultDomainUPN) )"
                $UserPrincipalName = $Entry.UserName + "@" + $global:DefaultDomainUPN 
            } Else {
                $UserPrincipalName = $Entry.UserPrincipalName
            }

            $DisplayName            = $Entry.DisplayName
            $ForwardMails           = $Entry.ForwardMails
            $MailForwardToAddress   = $Entry.MailForwardToAddress
            $CreateTAP              = $Entry.CreateTAP
            $TAPStartDate           = $Entry.TAPStartDate
            $AccountStatus          = if ($Entry.PSObject.Properties.Name -contains 'AccountStatus') { $Entry.AccountStatus } else { 'Enabled' }
            $StatusChangeCode       = if ($Entry.PSObject.Properties.Name -contains 'StatusChangeCode') { $Entry.StatusChangeCode } else { '' }

            # v2.2.0 (roadmap #1) -- optional admin metadata columns. All four are
            # additive + defensive: if the CSV pre-dates v2.2.0 the column won't
            # exist on the imported row, so we default to empty string. None of
            # these are required by the engine; ID create branch consumes them
            # opportunistically (Company -> -CompanyName on New-MgBetaUser,
            # ManagerEmail -> follow-up manager@odata.bind, Notes -> password log
            # comment, StartDate -> informational Write-Host).
            $Company                = if ($Entry.PSObject.Properties.Name -contains 'Company')      { $Entry.Company }      else { '' }
            $Notes                  = if ($Entry.PSObject.Properties.Name -contains 'Notes')        { $Entry.Notes }        else { '' }
            $ManagerEmail           = if ($Entry.PSObject.Properties.Name -contains 'ManagerEmail') { $Entry.ManagerEmail } else { '' }
            $StartDate              = if ($Entry.PSObject.Properties.Name -contains 'StartDate')    { $Entry.StartDate }    else { '' }

            # Notes are written to the password log; the Graph user object has no
            # native long-text field that fits (extensionAttributes are 256-char
            # capped per attribute and not exposed via Update-MgBetaUser cleanly).
            # Truncate defensively to 1024 chars so the log file stays parseable.
            if ($Notes -and $Notes.Length -gt 1024) {
                $Notes = $Notes.Substring(0, 1024)
            }

            # MSP kill-switch / customer-driven Disable / Revoke: branch out BEFORE
            # the normal create/update path. Invoke-PimAccountStatusChange:
            #   - is a no-op when AccountStatus is empty / 'Enabled'
            #   - in MSP variant, requires the StatusChangeCode column to match a
            #     per-admin secret in the customer's KV (Test-PimAccountStatusChangeAuthorized)
            #     before disabling/revoking -- defense in depth against an MSP-side compromise
            #   - skips the rest of this iteration (no create / update) so a
            #     Disabled or Revoked admin stays in the state we just put them in
            If ($AccountStatus -and $AccountStatus -ne 'Enabled') {
                Invoke-PimAccountStatusChange -UserPrincipalName $UserPrincipalName -AccountStatus $AccountStatus -StatusChangeCode $StatusChangeCode
                continue
            }

            If ($ForwardMails -eq "TRUE")
                {
                    $ForwardMails = $TRUE
                }
            Else
                {
                    $ForwardMails = $FALSE
                }

            # Per-account random password. Each newly-created account gets its own;
            # captured to output/admin-passwords-<yyyyMMdd>.txt by Write-PimAdminPassword
            # after a successful New-MgBetaUser / New-ADUser.
            $generatedPassword  = New-PimRandomPassword
            $PasswordProfile    = @{ Password = $generatedPassword }
            $AD_PasswordProfile = ConvertTo-SecureString $generatedPassword -AsPlainText -Force

            $Description = $DisplayName

            If ( ($TargetPlatform -eq "ID") -and ($OnlyID -eq $true) -and ($OnlyAD -eq $false) )
                {
                    $User = Get-MgUser -Userid $UserPrincipalName -ErrorAction SilentlyContinue
                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $Result = Update-MgBetaUser -UserId $UserPrincipalName `
                                                    -GivenName $FirstName `
                                                    -Surname $LastName `
                                                    -DisplayName $DisplayName `
                                                    -MailNickName $UserName `
                                                    -UserPrincipalName $UserPrincipalName `
                                                    -JobTitle $Description `
                                                    -UsageLocation $UsageLocation `
                                                    -PasswordPolicies DisablePasswordExpiration

                            If ($ForwardMails) {
                                Try {
                                    Set-Mailbox -Identity $UserPrincipalName -ForwardingSmtpAddress $MailForwardToAddress -DeliverToMailboxAndForward:$false -ErrorAction Stop
                                }
                                Catch {
                                    write-host ""
                                    Write-host "Failure: Cannot set mail-forwarding. Check available Exchange licenses or wait 20 min to let Entra sync up !" -ForegroundColor Yellow
                                }
                            }
                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"

                            # v2.2.0 (roadmap #1) -- splat-build so optional metadata
                            # only shows up on the New-MgBetaUser call when the CSV row
                            # actually has a value. Avoids pushing empty strings into
                            # Graph + keeps the call backwards compatible with
                            # pre-v2.2.0 CSVs that lack these columns entirely.
                            $newUserSplat = @{
                                GivenName         = $FirstName
                                Surname           = $LastName
                                DisplayName       = $DisplayName
                                PasswordProfile   = $PasswordProfile
                                AccountEnabled    = $true
                                MailNickName      = $UserName
                                UserPrincipalName = $UserPrincipalName
                                JobTitle          = $Description
                                UsageLocation     = $UsageLocation
                            }
                            if ($Company) {
                                $newUserSplat['CompanyName'] = $Company
                            }
                            $Result = New-MgBetaUser @newUserSplat

                            $Result = Update-MgBetaUser -UserId $UserPrincipalName -PasswordPolicies DisablePasswordExpiration

                            # v2.2.0 (roadmap #1) -- Notes go to the password log as a
                            # comment; Entra has no first-class long-text field for
                            # ad-hoc admin notes (extensionAttributes are 256-char
                            # capped + don't round-trip cleanly via Update-MgBetaUser).
                            # StartDate is informational only (Entra has no native
                            # "account starts on" field; CreateTAP + TAPStartDate handle
                            # the actual scheduled-credential case via roadmap #12).
                            if ($Notes) {
                                Write-Host "Note: $Notes" -ForegroundColor Cyan
                            }
                            if ($StartDate) {
                                Write-Host "StartDate (informational, not pushed to Entra): $StartDate" -ForegroundColor Cyan
                            }

                            # v2.2.0 (roadmap #1) -- ManagerEmail is resolved to the
                            # tenant user object id, then linked via the standard
                            # manager@odata.bind reference. Try/catch because the
                            # manager may not exist in this tenant yet (cross-tenant
                            # guest, or manager onboarded after the admin row). The
                            # engine intentionally does NOT fail the admin-create on
                            # a missing manager -- the assignment is informational.
                            if ($ManagerEmail) {
                                Try {
                                    $managerObj = Get-MgUser -UserId $ManagerEmail -ErrorAction Stop
                                    if ($managerObj -and $managerObj.Id) {
                                        $managerRef = @{
                                            '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($managerObj.Id)"
                                        }
                                        Set-MgUserManagerByRef -UserId $UserPrincipalName -BodyParameter $managerRef -ErrorAction Stop
                                        Write-Host "Linked manager $ManagerEmail to $UserPrincipalName" -ForegroundColor Green
                                    }
                                }
                                Catch {
                                    Write-Host "Skipping manager link for $UserPrincipalName -> $ManagerEmail (not resolvable in this tenant): $($_.Exception.Message)" -ForegroundColor Yellow
                                }
                            }

                            Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'ID'

                            # TAP (Temporary Access Pass) -- created when the CSV row sets CreateTAP=TRUE.
                            # Customer-facing recommended path: deliver the TAP code out-of-band, the
                            # admin uses it to register their own credentials, and the random password
                            # above never has to leave the password log file.
                            If ($CreateTAP -eq 'TRUE' -or $CreateTAP -eq $true) {
                                $tap = New-PimTemporaryAccessPass -UserId $UserPrincipalName -StartDateTime $TAPStartDate
                                if ($tap) {
                                    Write-PimAdminTap -UserPrincipalName $UserPrincipalName -Code $tap.Code -StartDateTime $tap.StartDateTime -LifetimeInMinutes $tap.LifetimeInMinutes

                                    # v2.2.0 (roadmap #11): out-of-band TAP delivery.
                                    # Only attempts a send when the customer has actually
                                    # configured notification channels (.custom.ps1 -- the
                                    # .locked.ps1 defaults to an empty hashtable). A failed
                                    # send must NOT block account creation, so the whole
                                    # call is wrapped in try/catch + best-effort logging.
                                    if ($global:PIM_NotificationChannels -and $global:PIM_NotificationChannels.Count -gt 0) {
                                        Try {
                                            $sendArgs = @{
                                                UserPrincipalName = $UserPrincipalName
                                                Code              = $tap.Code
                                                LifetimeMinutes   = [int]$tap.LifetimeInMinutes
                                            }
                                            # StartDateTime from Graph is typically string; normalize for the helper
                                            $sendArgs['StartDateTime'] = if ($tap.StartDateTime -is [datetime]) {
                                                $tap.StartDateTime
                                            } else {
                                                try { [datetime]$tap.StartDateTime } catch { [datetime]::UtcNow }
                                            }
                                            if ($ManagerEmail) { $sendArgs['Recipient'] = $ManagerEmail }
                                            $sendResult = Send-PimAdminTap @sendArgs
                                            if ($sendResult.Sent.Count -gt 0) {
                                                Write-Host "  -> TAP delivered via: $($sendResult.Sent -join ', ')" -ForegroundColor Green
                                            }
                                            if ($sendResult.Failed.Count -gt 0) {
                                                Write-Host "  -> TAP delivery FAILED for: $($sendResult.Failed -join ', ') (account creation NOT blocked)" -ForegroundColor Yellow
                                            }
                                        }
                                        Catch {
                                            Write-Host "  -> TAP delivery threw (account creation NOT blocked): $($_.Exception.Message)" -ForegroundColor Yellow
                                        }
                                    }
                                }
                            }

                            If ($ForwardMails) {
                                Try {
                                    Set-Mailbox -Identity $UserPrincipalName -ForwardingSmtpAddress $MailForwardToAddress -DeliverToMailboxAndForward:$false -ErrorAction SilentlyContinue
                                }
                                Catch {
                                }
                            }

                        }
                }

            ElseIf ( ($TargetPlatform -eq "AD") -and ($OnlyID -eq $false) -and ($OnlyAD -eq $true) )
                {
                    # v2.4.118: revert the gMSA -Credential omission added in
                    # v2.4.117. The v1 contract was: always pass -Credential
                    # using a real service-account credential held in KV
                    # (Legacy-UserName-Internal-Prod + Legacy-Password-Internal-Prod).
                    # Real gMSA hosting -- where the process runs AS the gMSA
                    # under a Scheduled Task -- doesn't go through this code
                    # path with a placeholder password; it's expected to use
                    # a regular AD service account that DOES have a real
                    # password. Matching the v1 behavior unconditionally.
                    $adCommonParams = @{}
                    if ($Credentials) {
                        $adCommonParams['Credential'] = $Credentials
                    }

                    # Hard-fail Get-ADUser so an auth/DC issue can't silently
                    # cascade into the Create branch (which used to generate
                    # + persist a password before New-ADUser even ran -- and
                    # since New-ADUser would also fail the AD account never
                    # existed; the password file just filled up with phantom
                    # entries).
                    $User = $null
                    $getAdUserErr = $null
                    try {
                        $User = Get-ADUser -Filter 'UserPrincipalName -eq $UserPrincipalName' @adCommonParams -ErrorAction Stop
                    } catch {
                        $getAdUserErr = $_
                    }

                    if ($getAdUserErr) {
                        $authMsg = $getAdUserErr.Exception.Message
                        $credName = if ($Credentials -and $Credentials.UserName) { $Credentials.UserName } else { '<no credential>' }
                        Write-Host ("ERROR: Get-ADUser failed for {0} with credential '{1}': {2}. Skipping this AD row -- NOT writing password file." -f $UserPrincipalName, $credName, $authMsg) -ForegroundColor Red
                        continue
                    }

                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $User | Set-ADUser -GivenName $FirstName `
                                               -Surname $LastName `
                                               -DisplayName $DisplayName `
                                               -Description $Description `
                                               -EmailAddress $UserPrincipalName `
                                               -UserPrincipalName $UserPrincipalName `
                                               @adCommonParams

                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"

                            # v2.4.121: CSV TierLevel column carries the TIER
                            # (T0/T1/T2/T3) -- NOT the Level. Level is a
                            # separate dimension encoded elsewhere (typically
                            # in the UPN body, e.g. 'Admin-SKR-L0-T0-ID' carries
                            # both L0 Level and T0 Tier). The old engine matched
                            # CSV TierLevel against literal "L0" / "L1" -- so
                            # any CSV using "T0" / "T1" silently dropped every
                            # Create row. Fixed by matching against the actual
                            # Tier convention. The legacy "L0" / "L1" literals
                            # are accepted as back-compat so historical CSVs
                            # that mis-labelled the column don't break.
                            #
                            # Tier 0 (T0) -> high-priv OU ($PathAdminsL0T0).
                            # Tier 1/2/3 (T1/T2/T3) and blank -> general OU
                            # ($PathAdmins).
                            $tierUpper = if ($null -ne $TierLevel) { ([string]$TierLevel).ToUpperInvariant().Trim() } else { '' }
                            $isTier0 = ($tierUpper -eq 'T0') -or ($tierUpper -eq 'L0')  # 'L0' kept ONLY for back-compat with the pre-v2.4.121 misnamed CSVs
                            $targetOu = if ($isTier0) { $PathAdminsL0T0 } else { $PathAdmins }
                            $tierForLog = if ([string]::IsNullOrWhiteSpace($tierUpper)) { '<blank>' } else { $tierUpper }

                            $createOk = $false
                            if ([string]::IsNullOrWhiteSpace($targetOu)) {
                                Write-Host ("ERROR: New-ADUser SKIPPED for {0} -- target OU is empty (TierLevel='{1}' resolved to {2}, but the corresponding -Path parameter wasn't supplied by the launcher). Fix the launcher's PathAdmins / PathAdminsL0T0 wiring. NOT persisting password." -f $UserPrincipalName, $tierForLog, $(if ($isHighPriv) { '$PathAdminsL0T0' } else { '$PathAdmins' })) -ForegroundColor Red
                            } else {
                                try {
                                    $Result = New-ADUser -Name $UserName `
                                                         -GivenName $FirstName `
                                                         -Surname $LastName `
                                                         -DisplayName $DisplayName `
                                                         -Description $Description `
                                                         -AccountPassword $AD_PasswordProfile `
                                                         -EmailAddress $UserPrincipalName `
                                                         -UserPrincipalName $UserPrincipalName `
                                                         -Path $targetOu `
                                                         -Enabled:$true `
                                                         @adCommonParams `
                                                         -ErrorAction Stop
                                    $createOk = $true
                                    Write-Host ("  -> OU: {0}" -f $targetOu) -ForegroundColor DarkGray
                                } catch {
                                    Write-Host ("ERROR: New-ADUser failed for {0} (TierLevel='{1}', OU='{2}'): {3}. NOT persisting password." -f $UserPrincipalName, $tierForLog, $targetOu, $_.Exception.Message) -ForegroundColor Red
                                }
                            }

                            # Only persist the generated password when the
                            # AD account was actually created. Previously the
                            # password file got an entry even when create
                            # failed -- phantom credentials accumulating
                            # every run.
                            if ($createOk) {
                                Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'AD'
                            }
                        }
                }
        }
}


Function CreateUpdate-Accounts-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$SQLTable,
            [Parameter()]
                [string]$Path,
            [Parameter()]
                [Object]$Credentials,
            [Parameter()]
                [switch]$OnlyAD = $false,
            [Parameter()]
                [switch]$OnlyID = $false
         )


######################################################################################################################
# Admin Accounts | Create/Update
######################################################################################################################

    $AdminAccounts_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

    ForEach ($Entry in $AdminAccounts_Data)
        {
            $FirstName              = $Entry.FirstName
            $LastName               = $Entry.LastName
            $Initials               = $Entry.Initials
            $TierLevel              = $Entry.TierLevel
            $TargetUsage            = $Entry.TargetUsage
            $TargetPlatform         = $Entry.TargetPlatform
            $UserType               = $Entry.UserType
            $UserName               = $Entry.UserName
            $UsageLocation          = $Entry.UsageLocation
            $UserPrincipalName      = $Entry.UserPrincipalName
            $DisplayName            = $Entry.DisplayName
            $ForwardMailsToContact  = $Entry.ForwardMailsToContact
            $MailForwardAddress     = $Entry.MailForwardAddress

            If ($ForwardMailsToContact -eq "TRUE")
                {
                    $ForwardMailsToContact = $TRUE
                }
            Else
                {
                    $ForwardMailsToContact = $FALSE
                }

            # Per-account random password. Each newly-created account gets its own;
            # captured to output/admin-passwords-<yyyyMMdd>.txt by Write-PimAdminPassword
            # after a successful New-MgBetaUser / New-ADUser.
            $generatedPassword  = New-PimRandomPassword
            $PasswordProfile    = @{ Password = $generatedPassword }
            $AD_PasswordProfile = ConvertTo-SecureString $generatedPassword -AsPlainText -Force

            $Description = $TargetUsage + ", " + `
                           $TargetPlatform + ", " + `
                           $TierLevel + ", " + `
                           $UserType

            If ( ($TargetPlatform -eq "ID") -and ($OnlyID -eq $true) -and ($OnlyAD -eq $false) )
                {
                    $User = Get-MgUser -Userid $UserPrincipalName -ErrorAction SilentlyContinue
                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $Result = Update-MgUser -UserId $UserPrincipalName `
                                                    -GivenName $FirstName `
                                                    -Surname $LastName `
                                                    -DisplayName $DisplayName `
                                                    -AccountEnabled `
                                                    -MailNickName $UserName `
                                                    -UserPrincipalName $UserPrincipalName `
                                                    -JobTitle $Description `
                                                    -UsageLocation $UsageLocation

                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"
                            $Result = New-MgUser -GivenName $FirstName `
                                                 -Surname $LastName `
                                                 -DisplayName $DisplayName `
                                                 -PasswordProfile $PasswordProfile `
                                                 -AccountEnabled `
                                                 -MailNickName $UserName `
                                                 -UserPrincipalName $UserPrincipalName `
                                                 -JobTitle $Description `
                                                 -UsageLocation $UsageLocation

                            Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'ID'
                        }
                }

            ElseIf ( ($TargetPlatform -eq "AD") -and ($OnlyID -eq $false) -and ($OnlyAD -eq $true) )
                {
                    $User = Get-ADUser -Filter 'UserPrincipalName -eq $UserPrincipalName' `
                                       -Credential $Credentials `
                                       -ErrorAction SilentlyContinue
                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $User | Set-ADUser -GivenName $FirstName `
                                               -Surname $LastName `
                                               -DisplayName $DisplayName `
                                               -Description $Description `
                                               -EmailAddress $UserPrincipalName `
                                               -UserPrincipalName $UserPrincipalName `
                                               -Credential $Credentials

                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"
                            $Result = New-ADUser -Name $UserName `
                                                 -GivenName $FirstName `
                                                 -Surname $LastName `
                                                 -DisplayName $DisplayName `
                                                 -Description $Description `
                                                 -AccountPassword $AD_PasswordProfile `
                                                 -EmailAddress $UserPrincipalName `
                                                 -UserPrincipalName $UserPrincipalName `
                                                 -Path $Path `
                                                 -Enabled:$true `
                                                 -Credential $Credentials

                            Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'AD'
                        }
                }
        }
}


Function Assign-Groups-Accounts-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AccountsAssignmentFile
         )

######################################################################################################################
# Get current Assignments
######################################################################################################################

    $FileOutputPath = Get-PimOutputDir

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    # Missing files = first run on this VM (the exporter hasn't populated them yet); treat as empty.
    $CurrentAssignments_PIM4Groups   = if (Test-Path -LiteralPath $FileOutputPIM4Groups)   { Import-csv -Path $FileOutputPIM4Groups   -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_EntraIDRoles = if (Test-Path -LiteralPath $FileOutputEntraIDRoles) { Import-csv -Path $FileOutputEntraIDRoles -Delimiter ";" -Encoding UTF8 } else { @() }
    $CurrentAssignments_AzureRoles   = if (Test-Path -LiteralPath $FileOutputAzureRoles)   { Import-csv -Path $FileOutputAzureRoles   -Delimiter ";" -Encoding UTF8 } else { @() }

######################################################################################################################
# Admin Accounts | Delegations of PAGs
######################################################################################################################

    $EntraID_Users = $Global:Users_All_ID
    $EntraID_Groups = $Global:Groups_All_ID

    $AdminAccounts_Data = Import-csv -Path $AccountsAssignmentFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

    ForEach ($Entry in $AdminAccounts_Data)
        {
            # Reset per-iteration state so stale values from a prior row never leak
            # into the next account when a GroupTag lookup misses.
            $GroupName = $null
            $Group     = $null
            $UserInfo  = $null
            $GroupInfo = $null

            $UserName                  = $Entry.UserName
            $GroupTag                  = $Entry.GroupTag
            $GroupAssignment           = $Entry.GroupAssignment
            $Action                    = $Entry.Action
            $AutoExtend                = $Entry.AutoExtend # true or false (string) - extend expiring assignments
            $UpdateExisting            = $Entry.UpdateExisting # true or false (string) - change existing role assignments.
            $AssignmentType            = $Entry.AssignmentType
            $NumOfDaysWhenExpire       = $Entry.NumOfDaysWhenExpire
            $Permanent                 = $Entry.Permanent

            Write-host ""
            Write-host "Processing account $($UserName)"

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            If ($AutoExtend -eq "TRUE")
                {
                    $AutoExtend = $TRUE
                }
            Else
                {
                    $AutoExtend = $FALSE
                }

            If ($UpdateExisting -eq "TRUE")
                {
                    $UpdateExisting = $TRUE
                }
            Else
                {
                    $UpdateExisting = $FALSE
                }

            $UserInfo = $EntraID_Users | where-object { $_.UserPrincipalName -like "*$($UserName)*" }

            # Get actual group & au, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions -- skipping row" -ForegroundColor Red
                    continue
                }

            $UserId = $UserInfo.UserPrincipalName

            $GroupInfo = $EntraID_Groups | Where-Object { $_.DisplayName -eq $GroupName }

            If ($GroupInfo)
                {
                    # BUG FIX: Graph SDK exports "Assigned"/"Eligibility" not "Active"/"Eligible"
                    $AssignmentTypeLookup = $AssignmentType
                    If ($AssignmentType -eq 'Active')   { $AssignmentTypeLookup = 'Assigned'    }
                    
                    $CheckExistingAssignment = $CurrentAssignments_PIM4Groups | where-object { ($_.AssignmentType -eq $AssignmentTypeLookup) -and ($_.GroupId -eq $GroupInfo.Id) -and ($_.PrincipalId -eq $UserInfo.Id) }

                    # Graph fallback: snapshot may miss Active/Eligible PIM group membership assignments.
                    If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Active') )
                        {
                            $GraphCheck = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule `
                                            -Filter "groupId eq '$($GroupInfo.Id)' and principalId eq '$($UserInfo.Id)' and accessId eq 'member'" `
                                            -ErrorAction SilentlyContinue
                            If (!$GraphCheck)
                                {
                                    # Third fallback: direct group membership (non-PIM-scheduled)
                                    $GraphCheckDirect = Get-MgGroupMember -GroupId $GroupInfo.Id -ErrorAction SilentlyContinue |
                                                        Where-Object { $_.Id -eq $UserInfo.Id }
                                    If ($GraphCheckDirect)
                                        {
                                            $GraphCheck = [PSCustomObject]@{
                                                ScheduleInfo = [PSCustomObject]@{ Expiration = [PSCustomObject]@{ Type = "noExpiration"; EndDateTime = $null } }
                                            }
                                        }
                                }
                            If ($GraphCheck)
                                {
                                    write-host ""
                                    Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                    $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                    $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                    $CheckExistingAssignment = [PSCustomObject]@{
                                        AssignmentType            = 'Assigned'
                                        GroupId                   = $GroupInfo.Id
                                        PrincipalId               = $UserInfo.Id
                                        ScheduleExpirationType    = $GraphExpirationType
                                        ScheduleExpirationEndDateTime = $GraphEndDateTime
                                    }
                                }
                        }

                    If ( (!($CheckExistingAssignment)) -and ($AssignmentType -eq 'Eligible') )
                        {
                            # v2.4.1: consume tenant-wide preload from Get-PimGroupSchedulesPreloaded
                            # (auto-triggered on first call). Replaces the per-row Graph filter that
                            # cost ~600ms x ~1000 rows = ~6 min on a stale-snapshot Baseline run.
                            # The helper handles failures internally and returns $null on miss.
                            $GraphCheck = Get-PimGroupSchedule -GroupId $GroupInfo.Id -PrincipalId $UserInfo.Id -AssignmentType Eligible -AccessId member
                            If ($GraphCheck)
                                {
                                    write-host ""
                                    Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName)"
                                    $GraphExpirationType = $GraphCheck[0].ScheduleInfo.Expiration.Type
                                    $GraphEndDateTime = If ($GraphExpirationType -ieq "noExpiration") { $null } Else { $GraphCheck[0].ScheduleInfo.Expiration.EndDateTime }
                                    $CheckExistingAssignment = [PSCustomObject]@{
                                        AssignmentType            = 'Eligible'
                                        GroupId                   = $GroupInfo.Id
                                        PrincipalId               = $UserInfo.Id
                                        ScheduleExpirationType    = $GraphExpirationType
                                        ScheduleExpirationEndDateTime = $GraphEndDateTime
                                    }
                                }
                        }

                    If ($CheckExistingAssignment)
                        {
                            $CheckExistingAssignment = $CheckExistingAssignment[0]

                            # Check if assignment if Permanent/noExpiration
                            If ($CheckExistingAssignment.ScheduleExpirationType -ieq "noExpiration")
                                {
                                    If ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                        {
                                            write-host ""
                                            Write-host "Existing Assignment will be updated with assignment details"
                                            Write-host "Mode: AdminUpdate"
                                            write-host ""
                                            $PIMAction = "AdminUpdate"
                                        }
                                }
                            Else
                                {
                                    # not permanent
                                    $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                    If ([string]::IsNullOrWhiteSpace($ValueChk))
                                        {
                                            write-host ""
                                            Write-host "OK - Permanent exists: $RoleDefinitionName -> $($Group.DisplayName) (skipping)"
                                            Write-host "Mode: NoAction"
                                            write-host ""
                                            $PIMAction = "NoAction"
                                        }
                                    Else
                                        {
                                            $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk
                                            If (-not $ExpirationDate)
                                                {
                                                    write-host ""
                                                    Write-host "OK - Exists (unparseable expiry '$ValueChk'): $RoleDefinitionName -> $($Group.DisplayName) (skipping)" -ForegroundColor Yellow
                                                    Write-host "Mode: NoAction"
                                                    write-host ""
                                                    $PIMAction = "NoAction"
                                                }
                                            Else
                                                {
                                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End $ExpirationDate).TotalDays
                                                    $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)
                                                    If ( ($NumOfDaysBeforeExpiration -le 30) -and ($AutoExtend) )
                                                        {
                                                            write-host ""
                                                            Write-host "Existing Assignment will expire in $($NumOfDaysBeforeExpiration) days"
                                                            write-host "Assignment will be extended as AutoExtend=TRUE"
                                                            Write-host "Mode: AdminExtend"
                                                            write-host ""
                                                            $PIMAction = "AdminExtend"
                                                        }
                                                    ElseIf ( ( ($Action -eq "Assign") -and ($UpdateExisting) ) -or ($Action -eq "Update") )
                                                        {
                                                            Write-host "UPDATE: $RoleDefinitionName -> $($Group.DisplayName) (refreshing assignment details)" -ForegroundColor Yellow
                                                            $PIMAction = "AdminUpdate"
                                                        }
                                                    Else
                                                        {
                                                            write-host ""
                                                            Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (expires in $($NumOfDaysBeforeExpiration) days, skipping)" -ForegroundColor Green
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
                                                            $PIMAction = "NoAction"
                                                        }
                                                }
                                        }
                                }
                        }

                    ElseIf ( (!($CheckExistingAssignment)) -and ($Action -eq "Assign") )
                        {
                            write-host ""
                            $PIMAction = "AdminAssign"
                        }
                    
                    If ( ($CheckExistingAssignment) -and ($Action -eq "Remove") )
                        {
                            write-host ""
                            Write-host "Assignment was found .... removing"
                            Write-host "Mode: AdminRemove"
                            write-host ""
                            $PIMAction = "AdminRemove"
                        }

                    ################################################################################################################
                    # BUG FIX - REMEMBER TO UNHIDE WORKAROUND in PIM-Function.psm1 - search for PIM4Groups - +1 year old assignments wasn't found when using Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest
                                    
                      # $PIMAction = "AdminUpdate"
                    
                    ################################################################################################################
                    If ($PIMaction -ne "NoAction")
                        {
                        # Print action summary - only for AdminAssign (not for Extend/Update)
                        If ($PIMAction -eq "AdminAssign")
                            {
                                write-host ""
                                Write-host "Assignment was NOT found .... creating"
                                Write-host "Mode: AdminAssign"
                                write-host ""
                            }

                            $Justification = "IAC: Assigning access to group $($GroupName) for user $($UserId)"

                            $params = @{
	                            accessId = "member"
	                            groupId = $GroupInfo.Id
	                            action = $PIMAction
	                            justification = $Justification
	                            directoryScopeId = "/"
                                principalId = $UserInfo.Id
                            }

                            If ( (!($Permanent)) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                {
                                    $startDateTimeObj = [datetime]::UtcNow

                                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                        $params += @{
	                                                    scheduleInfo = @{
		                                                                    startDateTime = $startDateTime
		                                                                    expiration = @{
			                                                                                type = "AfterDateTime"
			                                                                                endDateTime = $endDateTime
		                                                                    }
                                                                        }
                                                    }
                                }
                            ElseIf ( ($Permanent) -and ( ($Action -eq "Assign") -or ($Action -eq "Extend") -or ($Action -eq "Update") ) )
                                {
                                    $startDateTimeObj = [datetime]::UtcNow

                                    $startDateTime = $startDateTimeObj.ToString("yyyy-MM-ddTHH:mm:ssK")

                                    $endDateTime   = $startDateTimeObj.AddDays($NumOfDaysWhenExpire).ToString("yyyy-MM-ddTHH:mm:ssK")

                                        $params += @{
	                                                    scheduleInfo = @{
   	                                                                        startDateTime = $startDateTime
		                                                                    expiration = @{
			                                                                                    type = "noExpiration"
		                                                                                    }
                                                                        }
                                                    }
                                }


                            If ($AssignmentType -eq "Eligible")
                                {
                                    Write-Host ""
                                    Write-Host "PIM - Assigning Admin $($Userid) as Eligible"
                                    Write-host "      to group $($GroupInfo.DisplayName)"

                                    Try {
                                        New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop
                                    }
                                    Catch {
                                        $ErrCode = $_.FullyQualifiedErrorId
                                        If ($ErrCode -like "*RoleAssignmentExists*")
                                            { Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (Graph confirmed, skipping)" -ForegroundColor Green }
                                        ElseIf ($ErrCode -like "*RoleAssignmentDoesNotExist*")
                                            { Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green }
                                        ElseIf ($ErrCode -like "*NestingNotSupportedForRoleAssignableGroup*")
                                            { Write-host "SKIP: Nesting not supported - target group is role-assignable." -ForegroundColor Yellow }
                                        Else
                                            { Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
                                    }
                                }
                            ElseIf ($AssignmentType -eq "Active")
                                {
                                    Write-Host ""
                                    Write-Host "PIM - Assigning Admin $($Userid) as Active "
                                    Write-host "      to group $($GroupInfo.DisplayName)"

                                    Try {
                                        New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                                    }
                                    Catch {
                                        $ErrCode = $_.FullyQualifiedErrorId
                                        If ($ErrCode -like "*RoleAssignmentExists*")
                                            { Write-host "OK - Exists: $RoleDefinitionName -> $($Group.DisplayName) (Graph confirmed, skipping)" -ForegroundColor Green }
                                        ElseIf ($ErrCode -like "*RoleAssignmentDoesNotExist*")
                                            { Write-host "Assignment already removed (not found in Graph) ... skipping" -ForegroundColor Green }
                                        ElseIf ($ErrCode -like "*NestingNotSupportedForRoleAssignableGroup*")
                                            { Write-host "SKIP: Nesting not supported - target group is role-assignable." -ForegroundColor Yellow }
                                        Else
                                            { Write-host "ERROR: $($_.Exception.Message)" -ForegroundColor Red }
                                    }
                                }
                        }
                }
        }
}


Function Assign-Groups-Accounts-From-SQL
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$SQLTable
         )

######################################################################################################################
# Admin Accounts | Delegations of PAGs
######################################################################################################################

    $EntraID_Users = $Global:Users_All_ID
    $EntraID_Groups = $Global:Groups_All_ID

    $AdminAccounts_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

    ForEach ($Entry in $AdminAccounts_Data)
        {
            # Reset per-iteration state so stale values from a prior row never leak
            # into the next account when a GroupTag lookup misses.
            $GroupName = $null
            $Group     = $null
            $UserInfo  = $null

            $UserName                  = $Entry.UserName
            $GroupTag                  = $Entry.GroupTag
            $GroupAssignment           = $Entry.GroupAssignment
            $AssignmentType            = $Entry.AssignmentType
            $NumOfDaysWhenExpire       = $Entry.NumOfDaysWhenExpire
            $Permanent                 = $Entry.Permanent

            Write-host ""
            Write-host "Processing account $($UserName)"

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            $UserInfo = $EntraID_Users | where-object { $_.UserPrincipalName -like "*$($UserName)*" }

            # Get actual group & au, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PIM groups with GroupTag $($GroupTag) in the definitions -- skipping row" -ForegroundColor Red
                    continue
                }

            Assign-User-PIM-PAG-Group -UserInfo $UserInfo `
                                      -GroupName $GroupName `
                                      -GroupAllArray $EntraID_Groups `
                                      -AssignmentType $AssignmentType `
                                      -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                      -Permanent $Permanent
        }
}


Function CreateUpdate-Policies-PIM-Roles
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


######################################################################################################
# Policies for PIM for Azure AD roles (Microsoft Graph)
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PIM Policies for Roles
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # List all PIM for Azure AD Roles policies

        $Uri          = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
        $PIM_Policies_Roles = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

        # counter
        $PIM_Policies_Roles_Counter = ($PIM_Policies_Roles | Measure-Object).count
        $Pos = 0

        # Process policy rules for all PIM policies for roles
        ForEach ($Policy in $PIM_Policies_Roles)
            {
                $Pos = 1 + $Pos
                $PolicyId = $Policy.id 
                write-host ""
                Write-host "[ $($Pos) / $($PIM_Policies_Roles_Counter) ] - Updating rules in PIM for Azure AD Policy [$($PolicyId)]"
                       
                # Create Role Policies
                # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview

                # Expiration
                    <#
                        # Activation maximum duration (hours)
                        Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                 -PolicyId $PolicyId `
                                                 -AssignmentType Assignment `
                                                 -RuleType RoleManagementPolicyExpirationRule `
                                                 -Caller EndUser

                    #>

                        # Allow permanent eligible assignment
                        # Expire eligible assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Allow permanent active assignment
                        # Expire active assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled

                # Enablement
                        # On activation, require: None, Azure AD Multi-Factor Authentication
                        # Require ticket information on activation
                        # Require justification on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Require Azure Multi-Factor Authentication on active assignment
                        # Require justification on active assignment
                        # Require ticket information on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled

                    <#
                        # On activation, require: Azure AD Conditional Access authentication context
                            Update-PIM-Policy-Role -RuleId "AuthenticationContext_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyAuthenticationContextRule

                        # Require approval to activate
                            Update-PIM-Policy-Role -RuleId "Approval_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyApprovalRule
                    #>


                # Notification
                        # 	Send notifications when eligible members activate this role: Role activation alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when eligible members activate this role: Notification to activated user (requestor)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when members are assigned as eligible to this role: Role assignment alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
            }
}


Function CreateUpdate-Policies-PIM-AzResources-File-CSV
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile
         )


######################################################################################################
# Policies for PIM for Azure Resources (Azure Resource Manager)
######################################################################################################

    $Azure_Resources_Data = Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

    $ScopeGrouped = $Azure_Resources_Data | Group-Object -Property AzScope, AzScopePermission

    ForEach ($Group in $ScopeGrouped)
        {
            $Entry = $Group.Group[0]

            $AzScope             = $Entry.AzScope
            $AzDisplayName       = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName
            $AzScopePermission   = $Entry.AzScopePermission
            $AssignmentType      = $Entry.AssignmentType
            $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
            $Permanent           = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }


            Write-host ""
            Write-host "Processing Az Resource Scope [ $($AzDisplayName) ]"
            Write-host "$($AzScope) "

            # List all PIM for Azure resources policies
                $Headers = Get-AzPimTokenCached

            # Role Policies
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AzResourcesRaw = $Response.Content
                $PIM_Policies_AzResources = $PIM_Policies_AzResourcesRaw | ConvertFrom-Json
                $PIM_Policies_AzResources = $PIM_Policies_AzResources.value

            # Role Assignments
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AssignmentRaw = $Response.Content
                $PIM_Policies_Assignments = $PIM_Policies_AssignmentRaw | ConvertFrom-Json
                $PIM_Policies_Assignments = $PIM_Policies_Assignments.value

            # Role Definitions at scope
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_DefinitionsRaw = $Response.Content
                $PIM_Policies_Definitions = $PIM_Policies_DefinitionsRaw | ConvertFrom-Json
                $PIM_Policies_Definitions = $PIM_Policies_Definitions.value

            $DefinitionInScope =  $PIM_Policies_Definitions | Where-Object { $_.properties.rolename -eq $AzScopePermission }
            $PolicyAssignmentInScope = $PIM_Policies_Assignments | Where-Object { $_.properties.roleDefinitionId -eq $DefinitionInScope.id }
            $PolicyInScope = $PolicyAssignmentInScope.properties.policyId.Split("/")[-1]

            # Loop all possible role permissions on Azure resources in PIM - adjust policy settings
            ForEach ($Policy in $PolicyInScope)
                {
                    $Pos = 1 + $Pos

                    # Get all rules for a policy
                    $policyId = $Policy

                    Write-host ""
                    Write-host "Updating policy rules for role $($AzScopePermission) (policy $($PolicyId))"

                    $Headers = Get-AzPimTokenCached

                    ############################################################################################
                    # Update policy rule -> Expiration_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_EndUser_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                            caller = "Admin"
                                                                                                            operations = @(
			                                                                                                                    "All"
                                                                                                                            )
                                                                                                  }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Eligibility_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Eligibility_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

            
                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Eligibility_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

 
                    ############################################################################################
                    # Update policy rule -> Enablement_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_EndUser_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Headers = Get-AzPimTokenCached

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

    
                    ############################################################################################
                    # Update policy rule -> Notification_Admin_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Admin_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Admin_EndUser_recipientType
                                                                                        notificationLevel = $Notification_Admin_EndUser_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_EndUser_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Requestor_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Requestor_EndUser_Assignment_recipientType
                                                                                        notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Admin_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Admin_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Admin_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Requestor_Admin_Eligibility"
                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Requestor_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                }
        }
}


Function CreateUpdate-Policies-PIM-AzResources-SQL
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]          
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()] 
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()] 
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$SQLTable
         )


######################################################################################################
# Policies for PIM for Azure Resources (Azure Resource Manager)
######################################################################################################

    $Azure_Resources_Data = Invoke-Sqlcmd -ServerInstance $global:SQLServerName -Database $global:SQLDatabaseName  -AccessToken $global:SQLToken -Query "Select * from $($SQLTable)"

    $ScopeGrouped = $Azure_Resources_Data | Group-Object -Property AzScope, AzScopePermission

    ForEach ($Group in $ScopeGrouped)
        {
            $Entry = $Group.Group[0]

            $AzScope             = $Entry.AzScope
            $AzDisplayName       = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName
            $AzScopePermission   = $Entry.AzScopePermission
            $AssignmentType      = $Entry.AssignmentType
            $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
            $Permanent           = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }


            Write-host ""
            Write-host "Processing Az Resource Scope [ $($AzDisplayName) ]"
            Write-host "$($AzScope) "

            # List all PIM for Azure resources policies
                $Headers = Get-AzPimTokenCached

            # Role Policies
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AzResourcesRaw = $Response.Content
                $PIM_Policies_AzResources = $PIM_Policies_AzResourcesRaw | ConvertFrom-Json
                $PIM_Policies_AzResources = $PIM_Policies_AzResources.value

            # Role Assignments
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AssignmentRaw = $Response.Content
                $PIM_Policies_Assignments = $PIM_Policies_AssignmentRaw | ConvertFrom-Json
                $PIM_Policies_Assignments = $PIM_Policies_Assignments.value

            # Role Definitions at scope
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_DefinitionsRaw = $Response.Content
                $PIM_Policies_Definitions = $PIM_Policies_DefinitionsRaw | ConvertFrom-Json
                $PIM_Policies_Definitions = $PIM_Policies_Definitions.value

            $DefinitionInScope =  $PIM_Policies_Definitions | Where-Object { $_.properties.rolename -eq $AzScopePermission }
            $PolicyAssignmentInScope = $PIM_Policies_Assignments | Where-Object { $_.properties.roleDefinitionId -eq $DefinitionInScope.id }
            $PolicyInScope = $PolicyAssignmentInScope.properties.policyId.Split("/")[-1]

            # Loop all possible role permissions on Azure resources in PIM - adjust policy settings
            ForEach ($Policy in $PolicyInScope)
                {
                    $Pos = 1 + $Pos

                    # Get all rules for a policy
                    $policyId = $Policy

                    Write-host ""
                    Write-host "Updating policy rules for role $($AzScopePermission) (policy $($PolicyId))"

                    $Headers = Get-AzPimTokenCached

                    ############################################################################################
                    # Update policy rule -> Expiration_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_EndUser_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                            caller = "Admin"
                                                                                                            level = "Assignment"
                                                                                                            operations = @(
			                                                                                                                    "All"
                                                                                                                            )
                                                                                                  }
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Eligibility_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Eligibility_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

            
                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Eligibility_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

 
                    ############################################################################################
                    # Update policy rule -> Enablement_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_EndUser_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Headers = Get-AzPimTokenCached

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

    
                    ############################################################################################
                    # Update policy rule -> Notification_Admin_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Admin_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Admin_EndUser_recipientType
                                                                                        notificationLevel = $Notification_Admin_EndUser_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_EndUser_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Requestor_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Requestor_EndUser_Assignment_recipientType
                                                                                        notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Admin_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Admin_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Admin_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Requestor_Admin_Eligibility"
                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Requestor_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                }
        }
}


Function CreateUpdate-Policies-PIM-Groups
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Owner_Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Owner_Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Owner_Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Owner_Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Owner_Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Owner_Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Owner_Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Owner_Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Owner_Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Owner_Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Owner_Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [bool]$Member_Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Member_Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Member_Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Member_Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Member_Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Member_Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Member_Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Member_Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [AllowNull()]
                [AllowEmptyCollection()]
                [array]$Member_Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Member_Notification_Admin_EndUser_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Member_Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Member_Notification_Requestor_EndUser_Assignment_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Member_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Member_Notification_Admin_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Member_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Member_Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [AllowEmptyCollection()]
                [array]$Member_Notification_Requestor_Admin_Eligibility_notificationRecipients = @(),
            [Parameter(mandatory)]
                [bool]$Member_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
          )

######################################################################################################
# Policies for PIM for Groups (Microsoft Graph)
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PIM Policies for Groups
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        Write-host "Getting group-info from Entra ID ... Please Wait !"
        If ($Global:PIM_Groups_Scoped -eq "")
            {
                # v2.3.2: server-side-filtered (startswith on the customer's
                # PimGroupPattern prefix); skips the 30k-group dump on large
                # tenants. The DisplayName -like 'PIM-*' filter is now implicit
                # in Get-PimGroupsFiltered.
                $Groups_All = Get-PimGroupsFiltered
                $Groups_All_Scope = $Groups_All | where-Object { ($_.SecurityEnabled -eq $true) -and ($_.GroupTypes -notin "DynamicMembership") -and ($_.OnPremisesSyncEnabled -ne $true) }
            }
        Else
            {
                $Groups_All_Scope = $Global:PIM_Groups_Scoped
            }

        # List all PIM for Groups policies
        $PIM_Policies_Groups = @()

        Write-host "Getting PIM-policies for all groups ... Please Wait !"
        ForEach ($Group in $Groups_All_Scope)
            {
                Write-host "Getting PIM-policies from $($Group.DisplayName)"
                $FilterString = "scopeId eq '$($Group.Id)' and scopeType eq 'Group'"
              #  $PIM_Policies_Groups += Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '$($Group.Id)' and scopeType eq 'Group'" -ExpandProperty "rules(`$select=id)" -ErrorAction SilentlyContinue
                $PIM_Policies_Groups += Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '$($Group.Id)' and scopeType eq 'Group'" -ExpandProperty "rules(`$select=id)"
            }

        # counter
        $PIM_Policies_Groups_Counter = ($PIM_Policies_Groups | Measure-Object).count
        $Pos = 0

        # loop through all policies
        ForEach ($Policy in $PIM_Policies_Groups)
            {
                $Pos = 1 + $Pos
                $PolicyId = $Policy.id 
                write-host ""
                Write-host "[ $($Pos) / $($PIM_Policies_Groups_Counter) ] - Updating rules in PIM for Groups Policy [$($PolicyId)]"
                       
                # Create Role Policies
                # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview

                # Expiration
                        Update-PIM-Policy-Role -RuleId "Expiration_Admin_Eligibility" `
                                                    -PolicyId $PolicyId `
                                                    -RuleType PolicyExpirationRule `
                                                    -Owner_Expiration_EndUser_Assignment_isExpirationRequired $Owner_Expiration_EndUser_Assignment_isExpirationRequired `
                                                    -Owner_Expiration_EndUser_Assignment_maximumDuration $Owner_Expiration_EndUser_Assignment_maximumDuration `
                                                    -Owner_Expiration_Admin_Assignment_isExpirationRequired $Owner_Expiration_Admin_Assignment_isExpirationRequired `
                                                    -Owner_Expiration_Admin_Assignment_maximumDuration $Owner_Expiration_Admin_Assignment_maximumDuration `
                                                    -Owner_Expiration_Admin_Eligibility_isExpirationRequired $Owner_Expiration_Admin_Eligibility_isExpirationRequired `
                                                    -Owner_Expiration_Admin_Eligibility_maximumDuration $Owner_Expiration_Admin_Eligibility_maximumDuration `
                                                    -Owner_Enablement_Admin_Assignment_enabledRules $Owner_Enablement_Admin_Assignment_enabledRules `
                                                    -Owner_Enablement_Admin_Eligibility_enabledRules $Owner_Enablement_Admin_Eligibility_enabledRules `
                                                    -Owner_Enablement_EndUser_Assignment_enabledRules $Owner_Enablement_EndUser_Assignment_enabledRules `
                                                    -Owner_Notification_Admin_EndUser_Assignment_notificationType $Owner_Notification_Admin_EndUser_Assignment_notificationType `
                                                    -Owner_Notification_Admin_EndUser_recipientType $Owner_Notification_Admin_EndUser_recipientType `
                                                    -Owner_Notification_Admin_EndUser_notificationLevel $Owner_Notification_Admin_EndUser_notificationLevel `
                                                    -Owner_Notification_Admin_EndUser_notificationRecipients $Owner_Notification_Admin_EndUser_notificationRecipients `
                                                    -Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled $Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationType $Owner_Notification_Requestor_EndUser_Assignment_notificationType `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_recipientType $Owner_Notification_Requestor_EndUser_Assignment_recipientType `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationLevel $Owner_Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients $Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationType $Owner_Notification_Admin_Admin_Eligibility_notificationType `
                                                    -Owner_Notification_Admin_Admin_Eligibility_recipientType $Owner_Notification_Admin_Admin_Eligibility_recipientType `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationLevel $Owner_Notification_Admin_Admin_Eligibility_notificationLevel `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationRecipients $Owner_Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                    -Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationType $Owner_Notification_Requestor_Admin_Eligibility_notificationType `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_recipientType $Owner_Notification_Requestor_Admin_Eligibility_recipientType `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationLevel $Owner_Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients $Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Member_Expiration_EndUser_Assignment_isExpirationRequired $Member_Expiration_EndUser_Assignment_isExpirationRequired `
                                                    -Member_Expiration_EndUser_Assignment_maximumDuration $Member_Expiration_EndUser_Assignment_maximumDuration `
                                                    -Member_Expiration_Admin_Assignment_isExpirationRequired $Member_Expiration_Admin_Assignment_isExpirationRequired `
                                                    -Member_Expiration_Admin_Assignment_maximumDuration $Member_Expiration_Admin_Assignment_maximumDuration `
                                                    -Member_Expiration_Admin_Eligibility_isExpirationRequired $Member_Expiration_Admin_Eligibility_isExpirationRequired `
                                                    -Member_Expiration_Admin_Eligibility_maximumDuration $Member_Expiration_Admin_Eligibility_maximumDuration `
                                                    -Member_Enablement_Admin_Assignment_enabledRules $Member_Enablement_Admin_Assignment_enabledRules `
                                                    -Member_Enablement_Admin_Eligibility_enabledRules $Member_Enablement_Admin_Eligibility_enabledRules `
                                                    -Member_Enablement_EndUser_Assignment_enabledRules $Member_Enablement_EndUser_Assignment_enabledRules `
                                                    -Member_Notification_Admin_EndUser_Assignment_notificationType $Member_Notification_Admin_EndUser_Assignment_notificationType `
                                                    -Member_Notification_Admin_EndUser_recipientType $Member_Notification_Admin_EndUser_recipientType `
                                                    -Member_Notification_Admin_EndUser_notificationLevel $Member_Notification_Admin_EndUser_notificationLevel `
                                                    -Member_Notification_Admin_EndUser_notificationRecipients $Member_Notification_Admin_EndUser_notificationRecipients `
                                                    -Member_Notification_Admin_EndUser_isDefaultRecipientsEnabled $Member_Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationType $Member_Notification_Requestor_EndUser_Assignment_notificationType `
                                                    -Member_Notification_Requestor_EndUser_Assignment_recipientType $Member_Notification_Requestor_EndUser_Assignment_recipientType `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationLevel $Member_Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationRecipients $Member_Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                    -Member_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Member_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationType $Member_Notification_Admin_Admin_Eligibility_notificationType `
                                                    -Member_Notification_Admin_Admin_Eligibility_recipientType $Member_Notification_Admin_Admin_Eligibility_recipientType `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationLevel $Member_Notification_Admin_Admin_Eligibility_notificationLevel `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationRecipients $Member_Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                    -Member_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Member_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationType $Member_Notification_Requestor_Admin_Eligibility_notificationType `
                                                    -Member_Notification_Requestor_Admin_Eligibility_recipientType $Member_Notification_Requestor_Admin_Eligibility_recipientType `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationLevel $Member_Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationRecipients $Member_Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                    -Member_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Member_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled

                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
                                                    -Owner_Expiration_EndUser_Assignment_isExpirationRequired $Owner_Expiration_EndUser_Assignment_isExpirationRequired `
                                                    -Owner_Expiration_EndUser_Assignment_maximumDuration $Owner_Expiration_EndUser_Assignment_maximumDuration `
                                                    -Owner_Expiration_Admin_Assignment_isExpirationRequired $Owner_Expiration_Admin_Assignment_isExpirationRequired `
                                                    -Owner_Expiration_Admin_Assignment_maximumDuration $Owner_Expiration_Admin_Assignment_maximumDuration `
                                                    -Owner_Expiration_Admin_Eligibility_isExpirationRequired $Owner_Expiration_Admin_Eligibility_isExpirationRequired `
                                                    -Owner_Expiration_Admin_Eligibility_maximumDuration $Owner_Expiration_Admin_Eligibility_maximumDuration `
                                                    -Owner_Enablement_Admin_Assignment_enabledRules $Owner_Enablement_Admin_Assignment_enabledRules `
                                                    -Owner_Enablement_Admin_Eligibility_enabledRules $Owner_Enablement_Admin_Eligibility_enabledRules `
                                                    -Owner_Enablement_EndUser_Assignment_enabledRules $Owner_Enablement_EndUser_Assignment_enabledRules `
                                                    -Owner_Notification_Admin_EndUser_Assignment_notificationType $Owner_Notification_Admin_EndUser_Assignment_notificationType `
                                                    -Owner_Notification_Admin_EndUser_recipientType $Owner_Notification_Admin_EndUser_recipientType `
                                                    -Owner_Notification_Admin_EndUser_notificationLevel $Owner_Notification_Admin_EndUser_notificationLevel `
                                                    -Owner_Notification_Admin_EndUser_notificationRecipients $Owner_Notification_Admin_EndUser_notificationRecipients `
                                                    -Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled $Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationType $Owner_Notification_Requestor_EndUser_Assignment_notificationType `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_recipientType $Owner_Notification_Requestor_EndUser_Assignment_recipientType `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationLevel $Owner_Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients $Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                    -Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationType $Owner_Notification_Admin_Admin_Eligibility_notificationType `
                                                    -Owner_Notification_Admin_Admin_Eligibility_recipientType $Owner_Notification_Admin_Admin_Eligibility_recipientType `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationLevel $Owner_Notification_Admin_Admin_Eligibility_notificationLevel `
                                                    -Owner_Notification_Admin_Admin_Eligibility_notificationRecipients $Owner_Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                    -Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationType $Owner_Notification_Requestor_Admin_Eligibility_notificationType `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_recipientType $Owner_Notification_Requestor_Admin_Eligibility_recipientType `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationLevel $Owner_Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients $Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                    -Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Member_Expiration_EndUser_Assignment_isExpirationRequired $Member_Expiration_EndUser_Assignment_isExpirationRequired `
                                                    -Member_Expiration_EndUser_Assignment_maximumDuration $Member_Expiration_EndUser_Assignment_maximumDuration `
                                                    -Member_Expiration_Admin_Assignment_isExpirationRequired $Member_Expiration_Admin_Assignment_isExpirationRequired `
                                                    -Member_Expiration_Admin_Assignment_maximumDuration $Member_Expiration_Admin_Assignment_maximumDuration `
                                                    -Member_Expiration_Admin_Eligibility_isExpirationRequired $Member_Expiration_Admin_Eligibility_isExpirationRequired `
                                                    -Member_Expiration_Admin_Eligibility_maximumDuration $Member_Expiration_Admin_Eligibility_maximumDuration `
                                                    -Member_Enablement_Admin_Assignment_enabledRules $Member_Enablement_Admin_Assignment_enabledRules `
                                                    -Member_Enablement_Admin_Eligibility_enabledRules $Member_Enablement_Admin_Eligibility_enabledRules `
                                                    -Member_Enablement_EndUser_Assignment_enabledRules $Member_Enablement_EndUser_Assignment_enabledRules `
                                                    -Member_Notification_Admin_EndUser_Assignment_notificationType $Member_Notification_Admin_EndUser_Assignment_notificationType `
                                                    -Member_Notification_Admin_EndUser_recipientType $Member_Notification_Admin_EndUser_recipientType `
                                                    -Member_Notification_Admin_EndUser_notificationLevel $Member_Notification_Admin_EndUser_notificationLevel `
                                                    -Member_Notification_Admin_EndUser_notificationRecipients $Member_Notification_Admin_EndUser_notificationRecipients `
                                                    -Member_Notification_Admin_EndUser_isDefaultRecipientsEnabled $Member_Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationType $Member_Notification_Requestor_EndUser_Assignment_notificationType `
                                                    -Member_Notification_Requestor_EndUser_Assignment_recipientType $Member_Notification_Requestor_EndUser_Assignment_recipientType `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationLevel $Member_Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                    -Member_Notification_Requestor_EndUser_Assignment_notificationRecipients $Member_Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                    -Member_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Member_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationType $Member_Notification_Admin_Admin_Eligibility_notificationType `
                                                    -Member_Notification_Admin_Admin_Eligibility_recipientType $Member_Notification_Admin_Admin_Eligibility_recipientType `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationLevel $Member_Notification_Admin_Admin_Eligibility_notificationLevel `
                                                    -Member_Notification_Admin_Admin_Eligibility_notificationRecipients $Member_Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                    -Member_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Member_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationType $Member_Notification_Requestor_Admin_Eligibility_notificationType `
                                                    -Member_Notification_Requestor_Admin_Eligibility_recipientType $Member_Notification_Requestor_Admin_Eligibility_recipientType `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationLevel $Member_Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                    -Member_Notification_Requestor_Admin_Eligibility_notificationRecipients $Member_Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                    -Member_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Member_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled

                # Enablement
                            Update-PIM-Policy-Role -RuleId "Enablement_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                            Update-PIM-Policy-Role -RuleId "Enablement_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled

                    <#
                        # On activation, require: Azure AD Conditional Access authentication context
                            Update-PIM-Policy-Role -RuleId "AuthenticationContext_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyAuthenticationContextRule

                        # Require approval to activate
                            Update-PIM-Policy-Role -RuleId "Approval_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyApprovalRule
                    #>


                # Notification
                        # 	Send notifications when eligible members activate this role: Role activation alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when eligible members activate this role: Notification to activated user (requestor)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when members are assigned as eligible to this role: Role assignment alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


                        # Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
                                                     -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
            }
}


Function CreateUpdate-AD-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$GroupDescription,
            [Parameter(mandatory)]
                [string]$GroupDisplayName,
            [Parameter(mandatory)]
                [string]$GroupCategory = "Security",
            [Parameter(mandatory)]
                [string]$GroupScope = "Global",
            [Parameter(mandatory)]
                [string]$Path,
            [Parameter(mandatory)]
                [Object]$Credentials
         )

<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = $Role_GroupName
    $GroupDescription    = $Role_GroupDescription
#>

    # Check if group already exist
    Try
        {
            $Group = Get-AdGroup -Identity $GroupName -Credential $Credentials -Properties Description, DisplayName
        }
    Catch
        {
            Write-Host ""
            Write-Host "Creating AD group $($GroupName)"
            $Group = New-ADGroup  -SamAccountName $GroupName `
                                  -Credential $Credentials `
                                  -Description $GroupDescription `
                                  -DisplayName $GroupDisplayName `
                                  -GroupCategory $GroupCategory `
                                  -GroupScope $GroupScope `
                                  -Name $GroupName `
                                  -Path $Path
        }

        If ( ($Group.DisplayName -ne $GroupDisplayName) -or ($Group.Description -ne $GroupDescription ) )
            {
                Write-Host ""
                Write-Host "Updating AD group $($GroupName)"
                $Group | Set-ADGroup -SamAccountName $GroupName `
                                        -Credential $Credentials `
                                        -Description $GroupDescription `
                                        -DisplayName $GroupDisplayName `
                                        -GroupCategory $GroupCategory `
                                        -GroupScope $GroupScope
            }
        Else
            {
                Write-Host ""
                Write-Host "OK - AD group $($GroupName) metadata is updated"
            }
}


Function Sync_Members_PIM-Group-AD-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [object]$IDSyncGroupsArray,
            [Parameter(mandatory)]
                [object]$IDUsersArrayAll,
            [Parameter(mandatory)]
                [Object]$IDGroupsArrayAll,
            [Parameter(mandatory)]
                [Object]$Credentials,
            [Parameter()]
                [string]$AccountSearchFor,
            [Parameter()]
                [string]$AccountReplaceWith
         )

<#
    TROUBLESHOOTING ONLY !!

    $IDUsersArrayAll = $EntraID_Users_All

    $IDGroupsArrayAll = $EntraID_Groups_All
    $IDSyncGroupsArray = $AD_Sync_Groups_Scoped

    $Credentials = $AD_Credentials 

    $AccountSearchFor = "-ID"
    $AccountReplaceWith = "-AD"

#>

    import-module Microsoft.Graph.Groups
    ForEach ($Group in $IDSyncGroupsArray)
        {
            $AD_GroupName = $Group.DisplayName
            $ID_GroupName = $Group.DisplayName

            Write-host ""
            Write-host "Validating PIM members for group $($ID_GroupName)"

            # get group members for AD group
            $AD_Group_Members = Get-AdGroupMember -Identity $AD_GroupName -Credential $Credentials
            $AD_Group_Members_TTL = Get-AdGroup $AD_GroupName -Property member –ShowMemberTimeToLive -Credential $Credentials

            $ID_Group = $IDGroupsArrayAll | Where-Object { $_.DisplayName -eq $ID_GroupName }

            $ID_Group_Members = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter "groupId eq '$($ID_Group.id)'"

            # Use Members Only - ignore Owners
            $ID_Group_Members = $ID_Group_Members | where-object { $_.AccessId -ne 'owner' }

            $ID_Members_Array = @()
            If ($ID_Group_Members)
                {
                    ForEach ($Entry in $ID_Group_Members)
                        {
                            $UserInfo = $IDUsersArrayAll | Where-Object { $_.Id -eq $Entry.PrincipalId }
                            If ($UserInfo)
                                {
                                    $ID_Members_Array += $UserInfo
                                }
                        }
                }

            # Step 1 - Add active PIM members from ID group
                ForEach ($Entry in $ID_Group_Members)
                    {
                        
                        $UserInfo = $IDUsersArrayAll | Where-Object { $_.Id -eq $Entry.PrincipalId }

                        If ($UserInfo)
                            {
                                $ID_UserName = $UserInfo.MailNickName
                                $AD_UserName = $ID_UserName.Replace($AccountSearchFor,$AccountReplaceWith)

                                # Calculate PIM session time
                                $PIM_Activation_End   = $Entry.EndDateTime

                                # Workaround if PIM activation happens at the same time as the sync-membership loop checks the PIM schedule
                                # Solution will auto-correct assignment
                                If ([string]::IsNullOrEmpty($PIM_Activation_End))
                                    {
                                        $PIM_Activation_End = (Get-date)
                                        $PIM_Activation_End = $PIM_Activation_End.AddHours(1)
                                    }
                                $AD_TimeSpanTotalTTL = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalSeconds
                                $AD_TimeSpanTotalTTL = [Math]::Round($AD_TimeSpanTotalTTL, 0)

                                $AD_TimeSpanTotalMinutes = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalMinutes
                                $AD_TimeSpanTotalMinutes = [Math]::Round($AD_TimeSpanTotalMinutes, 0)
                                $AD_TimeSpanTotalMinutesGroupMemberShip = New-TimeSpan -Minutes $AD_TimeSpanTotalMinutes

                                # Get user Distingushed name to compare TTL in AD with expected TTL from PIM session
                                $User = Get-ADUser $AD_UserName -Credential $Credentials

                                # Get TTL in AD for specific user as member of the group
                                $Actual_User_TTL_info = $AD_Group_Members_TTL.member | Where-Object { $_ -like "*$($User.DistinguishedName)*" }
                                If ($Actual_User_TTL_info)
                                    {
                                        $PosChar1 = $Actual_User_TTL_info.IndexOf("=")
                                        $PosChar2 = $Actual_User_TTL_info.IndexOf(">")
                                        $Actual_User_TTL = ($Actual_User_TTL_info.SubString(($PosChar1+1),($PosChar2-1-$PosChar1)))
                                        $Actual_User_TTL = [int]$Actual_User_TTL

                                        $Compare_Actual_TTL_Expected = $Actual_User_TTL - $AD_TimeSpanTotalTTL
                                        Write-host ""
                                        Write-host "  Current TTL in AD is $($Actual_User_TTL) for user $($AD_UserName)"
                                        Write-host "  Expected TTL from ID PIM-session is $($AD_TimeSpanTotalTTL)"
                                        Write-host "  Deviation of seconds is $($Compare_Actual_TTL_Expected)"
                                        If ($Compare_Actual_TTL_Expected -in -120..120)
                                            {
                                                Write-host "  Deviation of seconds is acceptable" -ForegroundColor Green
                                                $TTLWindowAccepted = $true
                                            }
                                        Else
                                            {
                                                Write-host "  Deviation of seconds is NOT acceptable (+/-2 min)" -ForegroundColor Red
                                                $TTLWindowAccepted = $false
                                            }
                                    }
                                Else
                                    {
                                            $TTLWindowAccepted = $false
                                    }
                            

                                If ( ($AD_UserName -notin $AD_Group_Members.name) -or ($TTLWindowAccepted -eq $false) )
                                    {
                                        $PIM_Activation_End   = $Entry.EndDateTime

                                        # Workaround if PIM activation happens at the same time as the sync-membership loop checks the PIM schedule
                                        # Solution will auto-correct assignment
                                        If ([string]::IsNullOrEmpty($PIM_Activation_End))
                                            {
                                                $PIM_Activation_End = (Get-date)
                                                $PIM_Activation_End = $PIM_Activation_End.AddHours(1)
                                            }

                                        $AD_TimeSpanTotalMinutes = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalMinutes
                                        $AD_TimeSpanTotalMinutes = [Math]::Round($AD_TimeSpanTotalMinutes, 0)
                                        $AD_TimeSpanTotalMinutesGroupMemberShip = New-TimeSpan -Minutes $AD_TimeSpanTotalMinutes
                       
                                        Write-host ""
                                        Write-host "  PIM for AD: Adding user $($AD_UserName) with group membership for $($AD_TimeSpanTotalMinutes) min (PIM for AD)" -ForegroundColor Yellow
                                        Write-host ""

                                        Try
                                            {
                                                Add-ADGroupMember -Identity $AD_GroupName `
                                                                  -Members $AD_UserName `
                                                                  -MemberTimeToLive $AD_TimeSpanTotalMinutesGroupMemberShip `
                                                                  -Credential $AD_Credentials
                                            }
                                        Catch
                                            {
                                                Add-ADGroupMember -Identity $AD_GroupName `
                                                                  -Members $AD_UserName `
                                                                  -Credential $AD_Credentials
                                            }
                                    }
                                Else
                                    {
                                        Write-host ""
                                        Write-host "  PIM for AD: User $($AD_UserName) is already member of $($AD_GroupName)" -ForegroundColor Green
                                        Write-host ""
                                    }
                            }
                    }

            # Step 2 - remove members in AD group, which are not member of Entra ID group
            ForEach ($Entry in $AD_Group_Members)
                {
                        $AD_UserName = $Entry.name
                        If ($AD_UserName -like "*-AD")
                            {
                                $ID_UserName = $AD_UserName.Replace("-AD","-ID")
                                If ($ID_UserName -notin $ID_Members_Array.MailNickName)
                                    {
                                        Write-host ""
                                        Write-host "  PIM for AD: Removing User $($AD_UserName) from group $($AD_GroupName)" -ForegroundColor Yellow
                                        Write-host ""
                                        Remove-ADGroupMember -Identity $AD_GroupName `
                                                             -Members $AD_UserName `
                                                             -Credential $AD_Credentials `
                                                             -Confirm:$false
                                    }
                            }
                        Else
                            {
                                # Change to use SAMAccountName
                                $AD_UserName = $Entry.SamAccountName
                                $ID_UserName = $AD_UserName
                                If ($ID_UserName -notin $ID_Members_Array.MailNickName)
                                    {
                                        Write-host ""
                                        Write-host "  PIM for AD: Removing User $($AD_UserName) from group $($AD_GroupName)" -ForegroundColor Yellow
                                        Write-host ""
                                        Remove-ADGroupMember -Identity $AD_GroupName `
                                                             -Members $AD_UserName `
                                                             -Credential $AD_Credentials `
                                                             -Confirm:$false
                                    }
                            }
                }
        }
}


Function PIM_Policy_Check_Update
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
            [array]$Policy,

            [Parameter(mandatory)]
            [ValidateSet("MicrosoftGraph","AzureARM")]
            [string]$PIM_API,


            [Parameter(mandatory)]
            [ValidateSet("EnablementRule","ExpirationRule","NotificationRule","AuthenticationContextRule","ApprovalRule")]
            [string]$RuleType,

            [Parameter(mandatory)]
            [ValidateSet("Expiration_Admin_Eligibility","Enablement_Admin_Eligibility","Expiration_EndUser_Assignment","Notification_Admin_Admin_Eligibility","Notification_Requestor_Admin_Eligibility","Notification_Approver_Admin_Eligibility","Expiration_Admin_Assignment","Enablement_Admin_Assignment","Notification_Admin_Admin_Assignment","Notification_Requestor_Admin_Assignment","Notification_Approver_Admin_Assignment","Enablement_EndUser_Assignment","Approval_EndUser_Assignment","AuthenticationContext_EndUser_Assignment","Notification_Admin_EndUser_Assignment","Notification_Requestor_EndUser_Assignment","Notification_Approver_EndUser_Assignment")]
            [string]$RuleId,

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [Parameter(ParameterSetName = 'Expiration')]
            [Parameter(ParameterSetName = 'Notification')]
            [Parameter(ParameterSetName = 'Enablement')]
            [Parameter(ParameterSetName = 'Approval')]
            [ValidateSet("None","Admin","EndUser")]
            [string]$caller,

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [Parameter(ParameterSetName = 'Expiration')]
            [Parameter(ParameterSetName = 'Notification')]
            [Parameter(ParameterSetName = 'Enablement')]
            [Parameter(ParameterSetName = 'Approval')]
            [ValidateSet("all","activate", "deactivate", "assign", "update", "remove", "extend", "renew")]
            [String[]]$Operations,

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [Parameter(ParameterSetName = 'Expiration')]
            [Parameter(ParameterSetName = 'Notification')]
            [Parameter(ParameterSetName = 'Enablement')]
            [Parameter(ParameterSetName = 'Approval')]
            [ValidateSet("Assignment","Eligibility")]
            [string]$Level,

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [Parameter(ParameterSetName = 'Expiration')]
            [Parameter(ParameterSetName = 'Notification')]
            [Parameter(ParameterSetName = 'Enablement')]
            [Parameter(ParameterSetName = 'Approval')]
            [AllowEmptyCollection()]
            [array]$inheritableSettings = @(),

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [Parameter(ParameterSetName = 'Expiration')]
            [Parameter(ParameterSetName = 'Notification')]
            [Parameter(ParameterSetName = 'Enablement')]
            [Parameter(ParameterSetName = 'Approval')]
            [AllowEmptyCollection()]
            [array]$enforcedSettings = @(),

           # Expiration
            [Parameter(ParameterSetName = 'Expiration')]
            [bool]$isExpirationRequired,

            [Parameter(ParameterSetName = 'Expiration')]
            [string]$maximumDuration,

           # Notification
            [Parameter(ParameterSetName = 'Notification')]
            [ValidateSet("Email")]
            [string]$notificationType,

            [Parameter(ParameterSetName = 'Notification')]
            [ValidateSet("Requestor","Approver","Admin")]
            [string]$recipientType,

            [Parameter(ParameterSetName = 'Notification')]
            [ValidateSet("None","Critical","All")]
            [string]$notificationLevel,

            [Parameter(ParameterSetName = 'Notification')]
            [bool]$isDefaultRecipientsEnabled,

            [Parameter(ParameterSetName = 'Notification')]
            [AllowEmptyCollection()]
            [array]$notificationRecipients = @(),

           # Enablement
            [Parameter(ParameterSetName = 'Enablement')]
            [ValidateSet("MultiFactorAuthentication","Justification","Ticketing")]
            [array]$enabledRules,

           # AuthententicationContext
            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [bool]$AuthContextIsEnabled,

            [Parameter(ParameterSetName = 'AuthenticationContext')]
            [string]$AuthContextClaimValue,

           # Approval
            [Parameter(ParameterSetName = 'Approval')]
            [ValidateSet("SingleStage","Serial","Parallel","NoApproval")]
            [String[]]$approvalMode,

            [Parameter(ParameterSetName = 'Approval')]
            [bool]$isApprovalRequired,

            [Parameter(ParameterSetName = 'Approval')]
            [bool]$isRequestorJustificationRequired,

            [Parameter(ParameterSetName = 'Approval')]
            [bool]$isApprovalRequiredForExtension,

            [Parameter(ParameterSetName = 'Approval')]
            [bool]$isApproverJustificationRequired,

            [Parameter(ParameterSetName = 'Approval')]
            [bool]$isEscalationEnabled,

            [Parameter(ParameterSetName = 'Approval')]
            [int]$escalationTimeInMinutes,

            [Parameter(ParameterSetName = 'Approval')]
            [int]$approvalStageTimeOutInDays,

            [Parameter(ParameterSetName = 'Approval')]
            [array]$primaryApprovers,

            [Parameter(ParameterSetName = 'Approval')]
            [array]$escalationApprovers
         )

#--------------------------------------------------------------------------------------
# Helpers
#--------------------------------------------------------------------------------------

# Test whether a named property exists on a PSObject. Returns $false if the object is $null
# OR if the property is absent. We treat "absent" as a difference (the live policy is using
# defaults that we want to overwrite).
function Test-PropExists {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    return ($Object.PSObject.Properties.Name -contains $Name)
}

# Compare two scalar collections case-insensitively, type-tolerant.
# Handles string vs array, $null vs "" vs @(), case differences.
$Compare_Collection = {
    param($A, $B)
    $aNorm = @($A | ForEach-Object { if ($null -ne $_) { "$_".ToLower() } } | Where-Object { $_ })
    $bNorm = @($B | ForEach-Object { if ($null -ne $_) { "$_".ToLower() } } | Where-Object { $_ })
    if ($aNorm.Count -ne $bNorm.Count) { return $false }
    if ($aNorm.Count -eq 0) { return $true }
    return (@($aNorm | Where-Object { $bNorm -notcontains $_ }).Count -eq 0)
}

# Compare a property from the live rule against a parameter.
# Strict mode: if the property is missing from the live rule, it counts as a difference,
# because PIM is using its default value and we want to assert ours.
function Test-ScalarProp {
    param($LiveObject, [string]$Name, $Desired, [switch]$CaseInsensitive)
    if (-not (Test-PropExists $LiveObject $Name)) {
        return $false   # missing => different
    }
    $current = $LiveObject.$Name
    if ($CaseInsensitive) {
        return ("$current" -ieq "$Desired")
    }
    return ($current -eq $Desired)
}

# NOTE on the "missing" rule:
# For SCALAR properties we want a clear "missing => PATCH" so PIM defaults get overwritten.
# For COLLECTION properties (notificationRecipients, primaryApprovers, etc.) we apply the
# same rule: if the live policy is silent on the property AND we're sending a non-empty
# value, it's a difference. If we're also sending empty, they're equivalent.
# Compare a collection property strictly: if the property is missing from the live
# policy, that is ALWAYS a mismatch (we want to overwrite the API default with our
# explicit value). If present, normalize and compare case-insensitively.
function Test-CollectionPropStrict {
    param($LiveObject, [string]$Name, $Desired)
    if (-not (Test-PropExists $LiveObject $Name)) {
        return $false   # missing => always different => PATCH
    }
    return (& $script:Compare_Collection $LiveObject.$Name $Desired)
}

# Lenient comparison for "plumbing" target fields (inheritableSettings, enforcedSettings,
# targetObjects). The PIM API's canonical empty form for these is null, and ARM is
# inconsistent about whether they survive a PATCH round-trip. Treat any empty form
# (missing / null / "" / @()) as equivalent on BOTH sides; only flag a real mismatch
# when one side is non-empty.
function Test-CollectionPropLenient {
    param($LiveObject, [string]$Name, $Desired)
    $liveVal = $null
    if (Test-PropExists $LiveObject $Name) {
        $liveVal = $LiveObject.$Name
    }
    $liveEmpty = ($null -eq $liveVal) -or
                 ($liveVal -is [string] -and [string]::IsNullOrEmpty($liveVal)) -or
                 (($liveVal -is [System.Collections.IEnumerable]) -and $liveVal -isnot [string] -and @($liveVal).Count -eq 0)

    $desEmpty  = ($null -eq $Desired) -or
                 ($Desired -is [string] -and [string]::IsNullOrEmpty($Desired)) -or
                 (($Desired -is [System.Collections.IEnumerable]) -and $Desired -isnot [string] -and @($Desired).Count -eq 0)

    if ($liveEmpty -and $desEmpty) { return $true }
    if ($liveEmpty -or  $desEmpty) { return $false }
    return (& $script:Compare_Collection $liveVal $Desired)
}

# Stash the script-block on $script: so the helper functions can see it.
$script:Compare_Collection = $Compare_Collection

# Wrap ARM PATCH calls with retry-on-429 logic that respects Retry-After.
# Microsoft documents 429 responses as carrying a Retry-After header in seconds;
# if missing, fall back to exponential backoff. Retries up to MaxRetries times.
#
# Always returns a result object: @{ Success=$true; Response=... } on success,
# @{ Success=$false; Status=<int>; Message=<string> } on failure.
# Never throws — caller must check $result.Success.
function Invoke-AzPimPatch {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string]$Body,
        [int]$MaxRetries = 6
    )

    # Cached-token resilience: if MSAL evicts our token mid-loop the next PATCH
    # comes back 401 Unauthorized. Allow exactly ONE in-flight refresh + retry
    # before giving up so a stale cache entry can't poison a whole batch.
    $tokenRefreshed = $false

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Method PATCH -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json' -ErrorAction Stop
            return @{ Success = $true; Response = $resp }
        }
        catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            $status = $null
            if ($resp) { $status = [int]$resp.StatusCode }
            $msg = $_.Exception.Message

            # 401 Unauthorized: assume cached ARM bearer expired or was evicted.
            # Force a refresh through Get-AzPimTokenCached and retry once (does
            # NOT consume a $MaxRetries slot -- it's an independent recovery path).
            if ($status -eq 401 -and -not $tokenRefreshed) {
                $tokenRefreshed = $true
                try {
                    $Headers = Get-AzPimTokenCached -RefreshOn401
                    Write-Host "    401 Unauthorized -- refreshed ARM token, retrying..." -ForegroundColor DarkYellow
                    continue
                } catch {
                    return @{ Success = $false; Status = 401; Message = "Token refresh failed after 401: $($_.Exception.Message)" }
                }
            }

            # Only retry on 429 (throttling) or 5xx (transient server errors)
            $shouldRetry = ($status -eq 429) -or ($status -ge 500 -and $status -lt 600)
            if (-not $shouldRetry -or $attempt -gt $MaxRetries) {
                return @{ Success = $false; Status = $status; Message = $msg }
            }

            # Determine wait time. Prefer Retry-After (seconds). Fall back to exponential backoff.
            $waitSeconds = 0
            if ($resp -and $resp.Headers) {
                $ra = $resp.Headers['Retry-After']
                if ($ra) {
                    [int]::TryParse($ra, [ref]$waitSeconds) | Out-Null
                }
            }
            if ($waitSeconds -le 0) {
                # Exponential backoff: 5, 10, 20, 40, 80, 160 seconds
                $waitSeconds = [Math]::Min(160, 5 * [Math]::Pow(2, $attempt - 1))
            }

            Write-Host ("    throttled (HTTP {0}), waiting {1}s before retry {2}/{3}..." -f $status, $waitSeconds, $attempt, $MaxRetries) -ForegroundColor DarkYellow
            Start-Sleep -Seconds $waitSeconds
        }
        catch {
            # Any non-WebException (DNS failure, auth refresh, etc.) — don't retry,
            # surface the message but don't throw.
            return @{ Success = $false; Status = $null; Message = $_.Exception.Message }
        }
    }
}

# Adaptive cooldown: PIM caps ARM writes per scope around 5/minute. Sleep 13 seconds
# between PATCH operations to stay under that ceiling. Caller can override via
# $env:PIM_PATCH_COOLDOWN_SECONDS if they have a different scope/quota profile.
function Wait-PimWriteCooldown {
    $cool = 3
    if ($env:PIM_PATCH_COOLDOWN_SECONDS) {
        [int]::TryParse($env:PIM_PATCH_COOLDOWN_SECONDS, [ref]$cool) | Out-Null
    }
    Start-Sleep -Seconds $cool
}

# Convert an empty collection ($null, "", or @()) to $null for the PATCH body.
# Microsoft's PIM API canonical form uses null for empty target fields, not [],
# and Windows PowerShell 5.1's ConvertTo-Json drops empty arrays in some paths
# which causes the API to silently store nothing (and a re-fetch then shows the
# field as missing, which our strict comparison reads as a diff on every run).
function ConvertTo-PimEmptyAsNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ([string]::IsNullOrEmpty($Value)) { return $null }
        return $Value
    }
    # arrays / collections
    $arr = @($Value | Where-Object { $_ -ne $null -and $_ -ne '' })
    if ($arr.Count -eq 0) { return $null }
    return ,$arr   # comma operator preserves array shape for single-element arrays
}

#--------------------------------------------
# Locate the rule we're checking
#--------------------------------------------
IF ($PIM_API -eq "MicrosoftGraph")
    {
        $PolicyRule = $Policy.rules | Where-Object { $_.id -eq $RuleId }
    }
ElseIf ($PIM_API -eq "AzureARM")
    {
        # 'effectiveRules' is what the GET response populates for ARM PIM policies.
        $PolicyRule = $Policy.properties.effectiveRules | Where-Object { $_.id -eq $RuleId }
        $PolicyId   = $Policy.properties.policyId.Split("/")[-1]
    }


If ($PolicyRule)
    {
        # Common target comparisons (all rule types share these)
        $CallerMatch              = (Test-ScalarProp     $PolicyRule.target 'caller'              $caller -CaseInsensitive)
        $LevelMatch               = (Test-ScalarProp     $PolicyRule.target 'level'               $level  -CaseInsensitive)
        $OperationsMatch          = (Test-CollectionPropStrict $PolicyRule.target 'operations'    $operations)
        $InheritableSettingsMatch = (Test-CollectionPropLenient $PolicyRule.target 'inheritableSettings' $inheritableSettings)
        $EnforcedSettingsMatch    = (Test-CollectionPropLenient $PolicyRule.target 'enforcedSettings'    $enforcedSettings)

        # Will be set to a list of mismatched fields for diagnostics
        $MismatchedFields = New-Object System.Collections.Generic.List[string]
        if (-not $CallerMatch)              { [void]$MismatchedFields.Add('target.caller') }
        if (-not $LevelMatch)               { [void]$MismatchedFields.Add('target.level') }
        if (-not $OperationsMatch)          { [void]$MismatchedFields.Add('target.operations') }
        if (-not $InheritableSettingsMatch) { [void]$MismatchedFields.Add('target.inheritableSettings') }
        if (-not $EnforcedSettingsMatch)    { [void]$MismatchedFields.Add('target.enforcedSettings') }

        #------------------------------------------------------------------------------------------------------------------
        If ($RuleType -eq "NotificationRule")
            {
                $NotificationTypeMatch          = (Test-ScalarProp $PolicyRule 'notificationType'          $notificationType         -CaseInsensitive)
                $RecipientTypeMatch             = (Test-ScalarProp $PolicyRule 'recipientType'             $recipientType            -CaseInsensitive)
                $NotificationLevelMatch         = (Test-ScalarProp $PolicyRule 'notificationLevel'         $notificationLevel        -CaseInsensitive)
                $IsDefaultRecipientsEnabledMatch= (Test-ScalarProp $PolicyRule 'isDefaultRecipientsEnabled' $isDefaultRecipientsEnabled)
                $RecipientsMatch                = (Test-CollectionPropStrict $PolicyRule 'notificationRecipients' $notificationRecipients)

                if (-not $NotificationTypeMatch)           { [void]$MismatchedFields.Add('notificationType') }
                if (-not $RecipientTypeMatch)              { [void]$MismatchedFields.Add('recipientType') }
                if (-not $NotificationLevelMatch)          { [void]$MismatchedFields.Add('notificationLevel') }
                if (-not $IsDefaultRecipientsEnabledMatch) { [void]$MismatchedFields.Add('isDefaultRecipientsEnabled') }
                if (-not $RecipientsMatch)                 { [void]$MismatchedFields.Add('notificationRecipients') }

                If ($MismatchedFields.Count -eq 0 -and $PolicyRule.id -eq $RuleId)
                         {
                            Write-Host "OK - Policy Rule $($ruleId)" -ForegroundColor Green
                         }
                Else
                         {
                            Write-Host "Updating $($ruleId) [diff: $($MismatchedFields -join ', ')]" -ForegroundColor Yellow

                            If ($PIM_API -eq "MicrosoftGraph")
                                {
                                    $odataType = "microsoft.graph.unifiedRoleManagementPolicy" + $RuleType
                                    $PolicyId = $Policy.id
                                    $PolicyBody = @{
                                                    '@odata.type' = $odataType
                                                    id = $RuleId
                                                    notificationType = "$notificationType"
                                                    recipientType = "$recipientType"
                                                    notificationLevel = "$notificationLevel"
                                                    isDefaultRecipientsEnabled = $isDefaultRecipientsEnabled
                                                    notificationRecipients = (ConvertTo-PimEmptyAsNull $notificationRecipients)
                                                    target = @{
                                                                '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                                                                caller = "$caller"
                                                                operations = $operations
                                                                level = "$level"
                                                                inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                              }
                                                  }

                                    try {
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id `
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                                                -BodyParameter $PolicyBody -ErrorAction Stop
                                    } catch {
                                        Write-Host ("    FAILED to PATCH {0}: {1}" -f $RuleId, $_.Exception.Message) -ForegroundColor Red
                                    }
                                }
                            ElseIf ($PIM_API -eq "AzureARM")
                                {
                                    $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                            properties = @{
                                                                rules = @(
                                                                    @{
                                                                        id = $RuleId
                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                        notificationType = "$notificationType"
                                                                        recipientType = "$recipientType"
                                                                        notificationLevel = "$notificationLevel"
                                                                        isDefaultRecipientsEnabled = $isDefaultRecipientsEnabled
                                                                        notificationRecipients = (ConvertTo-PimEmptyAsNull $notificationRecipients)
                                                                        target = @{
                                                                            caller = "$caller"
                                                                            operations = $operations
                                                                            level = "$level"
                                                                            inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                            enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                                        }
                                                                    }
                                                                )
                                                            }
                                                        }

                                    $Headers = Get-AzPimTokenCached
                                    $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20
                                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $PolicyId + "?api-version=2020-10-01"
                                    $patchResult = Invoke-AzPimPatch -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                                    if ($patchResult.Success) {
                                        Wait-PimWriteCooldown
                                    } else {
                                        Write-Host ("    FAILED to PATCH {0}: HTTP {1} - {2}" -f $RuleId, $patchResult.Status, $patchResult.Message) -ForegroundColor Red
                                    }
                                }
                        }
            }
        #------------------------------------------------------------------------------------------------------------------
        ElseIf ($RuleType -eq "EnablementRule")
            {
                $EnabledRulesMatch = (Test-CollectionPropStrict $PolicyRule 'enabledRules' $enabledRules)
                if (-not $EnabledRulesMatch) { [void]$MismatchedFields.Add('enabledRules') }

                If ($MismatchedFields.Count -eq 0 -and $PolicyRule.id -eq $RuleId)
                         {
                            Write-Host "OK - Policy Rule $($ruleId)" -ForegroundColor Green
                         }
                Else
                         {
                            Write-Host "Updating $($ruleId) [diff: $($MismatchedFields -join ', ')]" -ForegroundColor Yellow

                            If ($PIM_API -eq "MicrosoftGraph")
                                {
                                    $odataType = "#microsoft.graph.unifiedRoleManagementPolicy" + $RuleType
                                    $PolicyId = $Policy.id
                                    $PolicyBody = @{
                                                    "@odata.type" = "$odataType"
                                                    id = "$RuleId"
                                                    enabledRules = $enabledRules
                                                    target = @{
                                                                caller = "$caller"
                                                                operations = $operations
                                                                level = "$level"
                                                                inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                              }
                                                  }

                                    try {
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id `
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                                                -BodyParameter $PolicyBody -ErrorAction Stop
                                    } catch {
                                        Write-Host ("    FAILED to PATCH {0}: {1}" -f $RuleId, $_.Exception.Message) -ForegroundColor Red
                                    }
                                }
                            ElseIf ($PIM_API -eq "AzureARM")
                                {
                                    $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                            properties = @{
                                                                rules = @(
                                                                    @{
                                                                        id = $ruleId
                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                        enabledRules = $enabledRules
                                                                        target = @{
                                                                            caller = "$caller"
                                                                            operations = $operations
                                                                            level = "$level"
                                                                            inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                            enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                                        }
                                                                    }
                                                                )
                                                            }
                                                        }

                                    $Headers = Get-AzPimTokenCached
                                    $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20
                                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                                    $patchResult = Invoke-AzPimPatch -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                                    if ($patchResult.Success) {
                                        Wait-PimWriteCooldown
                                    } else {
                                        Write-Host ("    FAILED to PATCH {0}: HTTP {1} - {2}" -f $RuleId, $patchResult.Status, $patchResult.Message) -ForegroundColor Red
                                    }
                                }
                        }
            }
        #------------------------------------------------------------------------------------------------------------------
        ElseIf ($RuleType -eq "ExpirationRule")
            {
                $IsExpirationRequiredMatch = (Test-ScalarProp $PolicyRule 'isExpirationRequired' $isExpirationRequired)
                $MaximumDurationMatch      = (Test-ScalarProp $PolicyRule 'maximumDuration'      $maximumDuration -CaseInsensitive)

                if (-not $IsExpirationRequiredMatch) { [void]$MismatchedFields.Add('isExpirationRequired') }
                if (-not $MaximumDurationMatch)      { [void]$MismatchedFields.Add('maximumDuration') }

                If ($MismatchedFields.Count -eq 0 -and $PolicyRule.id -ieq $RuleId)
                         {
                            Write-Host "OK - Policy Rule $($ruleId)" -ForegroundColor Green
                         }
                Else
                         {
                            Write-Host "Updating $($ruleId) [diff: $($MismatchedFields -join ', ')]" -ForegroundColor Yellow

                            If ($PIM_API -eq "MicrosoftGraph")
                                {
                                    $odataType = "microsoft.graph.unifiedRoleManagementPolicy" + $RuleType
                                    $PolicyId = $Policy.id
                                    $PolicyBody = @{
                                                    '@odata.type' = $odataType
                                                    id = $RuleId
                                                    isExpirationRequired = $isExpirationRequired
                                                    maximumDuration = $maximumDuration
                                                    target = @{
                                                                '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                                                                caller = "$caller"
                                                                operations = $operations
                                                                level = "$level"
                                                                inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                              }
                                                  }

                                    try {
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id `
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                                                -BodyParameter $PolicyBody -ErrorAction Stop
                                    } catch {
                                        Write-Host ("    FAILED to PATCH {0}: {1}" -f $RuleId, $_.Exception.Message) -ForegroundColor Red
                                    }
                                }
                            ElseIf ($PIM_API -eq "AzureARM")
                                {
                                    $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                            properties = @{
                                                                rules = @(
                                                                    @{
                                                                        id = $ruleId
                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                        isExpirationRequired = $isExpirationRequired
                                                                        maximumDuration = $maximumDuration
                                                                        target = @{
                                                                            caller = "$caller"
                                                                            operations = $operations
                                                                            level = "$level"
                                                                            inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                            enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                                        }
                                                                    }
                                                                )
                                                            }
                                                        }

                                    $Headers = Get-AzPimTokenCached
                                    $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20
                                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                                    $patchResult = Invoke-AzPimPatch -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                                    if ($patchResult.Success) {
                                        Wait-PimWriteCooldown
                                    } else {
                                        Write-Host ("    FAILED to PATCH {0}: HTTP {1} - {2}" -f $RuleId, $patchResult.Status, $patchResult.Message) -ForegroundColor Red
                                    }
                                }
                        }
            }
        #------------------------------------------------------------------------------------------------------------------
        ElseIf ($RuleType -eq "ApprovalRule")
            {
                # The approval setting may live as $PolicyRule.setting or be missing altogether.
                # approvalStages may be a single object, an array, or "" / missing.
                $setting = $null
                if (Test-PropExists $PolicyRule 'setting') { $setting = $PolicyRule.setting }

                $stage = $null
                if ($null -ne $setting -and (Test-PropExists $setting 'approvalStages')) {
                    $rawStages = $setting.approvalStages
                    if ($rawStages -is [System.Collections.IEnumerable] -and $rawStages -isnot [string]) {
                        $stage = @($rawStages)[0]
                    } elseif ($rawStages -isnot [string]) {
                        $stage = $rawStages
                    }
                }

                $IsApprovalRequiredMatch              = (Test-ScalarProp $setting 'isApprovalRequired'              $isApprovalRequired)
                $IsApprovalRequiredForExtensionMatch  = (Test-ScalarProp $setting 'isApprovalRequiredForExtension'  $isApprovalRequiredForExtension)
                $IsRequestorJustificationRequiredMatch= (Test-ScalarProp $setting 'isRequestorJustificationRequired' $isRequestorJustificationRequired)
                $ApprovalModeMatch                    = (Test-ScalarProp $setting 'approvalMode'                    $approvalMode -CaseInsensitive)
                $ApprovalStageTimeOutInDaysMatch      = (Test-ScalarProp $stage   'approvalStageTimeOutInDays'      $approvalStageTimeOutInDays)
                $IsApproverJustificationRequiredMatch = (Test-ScalarProp $stage   'isApproverJustificationRequired' $isApproverJustificationRequired)
                $EscalationTimeInMinutesMatch         = (Test-ScalarProp $stage   'escalationTimeInMinutes'         $escalationTimeInMinutes)
                $IsEscalationEnabledMatch             = (Test-ScalarProp $stage   'isEscalationEnabled'             $isEscalationEnabled)
                $PrimaryApproversMatch                = (Test-CollectionPropStrict $stage 'primaryApprovers'    $primaryApprovers)
                $EscalationApproversMatch             = (Test-CollectionPropStrict $stage 'escalationApprovers' $escalationApprovers)

                if (-not $IsApprovalRequiredMatch)               { [void]$MismatchedFields.Add('setting.isApprovalRequired') }
                if (-not $IsApprovalRequiredForExtensionMatch)   { [void]$MismatchedFields.Add('setting.isApprovalRequiredForExtension') }
                if (-not $IsRequestorJustificationRequiredMatch) { [void]$MismatchedFields.Add('setting.isRequestorJustificationRequired') }
                if (-not $ApprovalModeMatch)                     { [void]$MismatchedFields.Add('setting.approvalMode') }
                if (-not $ApprovalStageTimeOutInDaysMatch)       { [void]$MismatchedFields.Add('stage.approvalStageTimeOutInDays') }
                if (-not $IsApproverJustificationRequiredMatch)  { [void]$MismatchedFields.Add('stage.isApproverJustificationRequired') }
                if (-not $EscalationTimeInMinutesMatch)          { [void]$MismatchedFields.Add('stage.escalationTimeInMinutes') }
                if (-not $IsEscalationEnabledMatch)              { [void]$MismatchedFields.Add('stage.isEscalationEnabled') }
                if (-not $PrimaryApproversMatch)                 { [void]$MismatchedFields.Add('stage.primaryApprovers') }
                if (-not $EscalationApproversMatch)              { [void]$MismatchedFields.Add('stage.escalationApprovers') }

                If ($MismatchedFields.Count -eq 0 -and $PolicyRule.id -eq $RuleId)
                         {
                            Write-Host "OK - Policy Rule $($ruleId)" -ForegroundColor Green
                         }
                Else
                         {
                            Write-Host "Updating $($ruleId) [diff: $($MismatchedFields -join ', ')]" -ForegroundColor Yellow

                            If ($PIM_API -eq "MicrosoftGraph")
                                {
                                    $odataType = "microsoft.graph.unifiedRoleManagementPolicy" + $RuleType
                                    $PolicyId = $Policy.id
                                    $PolicyBody = @{
                                                    '@odata.type' = $odataType
                                                    id = $RuleId
                                                    setting = @{
                                                        isApprovalRequired = $isApprovalRequired
                                                        isApprovalRequiredForExtension = $isApprovalRequiredForExtension
                                                        isRequestorJustificationRequired = $isRequestorJustificationRequired
                                                        approvalMode = $approvalMode
                                                        approvalStages = @{
                                                            approvalStageTimeOutInDays = $approvalStageTimeOutInDays
                                                            isApproverJustificationRequired = $isApproverJustificationRequired
                                                            escalationTimeInMinutes = $escalationTimeInMinutes
                                                            isEscalationEnabled = $isEscalationEnabled
                                                            primaryApprovers = $primaryApprovers
                                                            escalationApprovers = $escalationApprovers
                                                            }
                                                        }
                                                    target = @{
                                                                '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                                                                caller = "$caller"
                                                                operations = $operations
                                                                level = "$level"
                                                                inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                              }
                                                  }

                                    try {
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id `
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                                                -BodyParameter $PolicyBody -ErrorAction Stop
                                    } catch {
                                        Write-Host ("    FAILED to PATCH {0}: {1}" -f $RuleId, $_.Exception.Message) -ForegroundColor Red
                                    }
                                }
                            ElseIf ($PIM_API -eq "AzureARM")
                                {
                                    $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                            properties = @{
                                                                rules = @(
                                                                    @{
                                                                        id = $ruleId
                                                                        ruleType = "RoleManagementPolicyApprovalRule"
                                                                        setting = @{
                                                                            isApprovalRequired = $isApprovalRequired
                                                                            isApprovalRequiredForExtension = $isApprovalRequiredForExtension
                                                                            isRequestorJustificationRequired = $isRequestorJustificationRequired
                                                                            approvalMode = $approvalMode
                                                                            approvalStages = @{
                                                                                approvalStageTimeOutInDays = $approvalStageTimeOutInDays
                                                                                isApproverJustificationRequired = $isApproverJustificationRequired
                                                                                escalationTimeInMinutes = $escalationTimeInMinutes
                                                                                isEscalationEnabled = $isEscalationEnabled
                                                                                primaryApprovers = $primaryApprovers
                                                                                escalationApprovers = $escalationApprovers
                                                                            }
                                                                        }
                                                                        target = @{
                                                                            caller = "$caller"
                                                                            operations = $operations
                                                                            level = "$level"
                                                                            inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                            enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                                        }
                                                                    }
                                                                )
                                                            }
                                                        }

                                    $Headers = Get-AzPimTokenCached
                                    $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20
                                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                                    $patchResult = Invoke-AzPimPatch -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                                    if ($patchResult.Success) {
                                        Wait-PimWriteCooldown
                                    } else {
                                        Write-Host ("    FAILED to PATCH {0}: HTTP {1} - {2}" -f $RuleId, $patchResult.Status, $patchResult.Message) -ForegroundColor Red
                                    }
                                }
                        }
            }
        #------------------------------------------------------------------------------------------------------------------
        ElseIf ($RuleType -eq "AuthenticationContextRule")
            {
                $IsEnabledMatch  = (Test-ScalarProp $PolicyRule 'isEnabled'  $AuthContextIsEnabled)
                $ClaimValueMatch = (Test-ScalarProp $PolicyRule 'claimValue' $AuthContextclaimValue -CaseInsensitive)

                if (-not $IsEnabledMatch)  { [void]$MismatchedFields.Add('isEnabled') }
                if (-not $ClaimValueMatch) { [void]$MismatchedFields.Add('claimValue') }

                If ($MismatchedFields.Count -eq 0 -and $PolicyRule.id -eq $RuleId)
                         {
                            Write-Host "OK - Policy Rule $($ruleId)" -ForegroundColor Green
                         }
                Else
                         {
                            Write-Host "Updating $($ruleId) [diff: $($MismatchedFields -join ', ')]" -ForegroundColor Yellow

                            If ($PIM_API -eq "MicrosoftGraph")
                                {
                                    $odataType = "microsoft.graph.unifiedRoleManagementPolicy" + $RuleType
                                    $PolicyId = $Policy.id
                                    $PolicyBody = @{
                                                    '@odata.type' = $odataType
                                                    id = $RuleId
                                                    isEnabled = $AuthContextIsEnabled
                                                    claimValue = $AuthContextclaimValue
                                                    target = @{
                                                                '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                                                                caller = "$caller"
                                                                operations = $operations
                                                                level = "$level"
                                                                inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                              }
                                                  }

                                    try {
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id `
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                                                -BodyParameter $PolicyBody -ErrorAction Stop
                                    } catch {
                                        Write-Host ("    FAILED to PATCH {0}: {1}" -f $RuleId, $_.Exception.Message) -ForegroundColor Red
                                    }
                                }
                            ElseIf ($PIM_API -eq "AzureARM")
                                {
                                    $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                            properties = @{
                                                                rules = @(
                                                                    @{
                                                                        id = $ruleId
                                                                        ruleType = "RoleManagementPolicyAuthenticationContextRule"
                                                                        isEnabled = $AuthContextIsEnabled
                                                                        claimValue = $AuthContextclaimValue
                                                                        target = @{
                                                                            caller = "$caller"
                                                                            operations = $operations
                                                                            level = "$level"
                                                                            inheritableSettings = (ConvertTo-PimEmptyAsNull $inheritableSettings)
                                                                            enforcedSettings    = (ConvertTo-PimEmptyAsNull $enforcedSettings)
                                                                        }
                                                                    }
                                                                )
                                                            }
                                                        }

                                    $Headers = Get-AzPimTokenCached
                                    $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20
                                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                                    $patchResult = Invoke-AzPimPatch -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                                    if ($patchResult.Success) {
                                        Wait-PimWriteCooldown
                                    } else {
                                        Write-Host ("    FAILED to PATCH {0}: HTTP {1} - {2}" -f $RuleId, $patchResult.Status, $patchResult.Message) -ForegroundColor Red
                                    }
                                }
                        }
            }
    }
Else
    {
        # Many built-in roles only define a subset of the 17 standard PIM rules.
        # This is normal, not an error — print quietly so it's visible but not alarming.
        Write-Host "  (skipped - rule '$RuleId' not defined on this policy)" -ForegroundColor DarkGray
    }
}

######################################################################################################################
# Helpers ported from the retired 2LINKIT-Functions.psm1
######################################################################################################################

function Manage-Powershell-Module {
    <#
    .SYNOPSIS
        Ensure a PSGallery module is installed + imported.

    .PARAMETER ModuleName
        PSGallery module to install/import (e.g. AzResourceGraphPS, AzLogDcrIngestPS).

    .PARAMETER Scope
        Install scope. Defaults to AllUsers (matches the legacy behaviour).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [ValidateSet('AllUsers','CurrentUser')]
        [string]$Scope = 'AllUsers'
    )

    $installed = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed) {
        Write-Host "  [Manage-Powershell-Module] $ModuleName not found -- installing from PSGallery (Scope=$Scope)..." -ForegroundColor Gray
        try {
            Install-Module -Name $ModuleName -Scope $Scope -Force -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
        } catch {
            Write-Warning "  [Manage-Powershell-Module] failed to install $ModuleName ($($_.Exception.Message)). Continuing -- engine may fail if it needs this module."
            return
        }
        $installed = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    }

    if ($installed -and -not (Get-Module -Name $ModuleName)) {
        try {
            Import-Module -Name $ModuleName -Global -Force -WarningAction SilentlyContinue -ErrorAction Stop
            Write-Host "  [Manage-Powershell-Module] $ModuleName v$($installed.Version) imported." -ForegroundColor DarkGray
        } catch {
            Write-Warning "  [Manage-Powershell-Module] $ModuleName found but Import-Module failed: $($_.Exception.Message)"
        }
    }
}

function Get-PimSolutionRoot {
    # Two levels up from engine\_shared\ = SOLUTIONS\PIM4EntraPS\.
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

# Module-init: stamp the running PIM4EntraPS solution version on every engine
# load. Same one-line format as SI emits at engine startup
# ("SecurityInsight RiskAnalysis engine v2.2.387 (<path>)").
$_pimVerFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'
if (Test-Path -LiteralPath $_pimVerFile) {
    try {
        $_pimVer = (Get-Content -LiteralPath $_pimVerFile -Raw).Trim()
        if ($_pimVer) {
            $_pimEngineName = $null
            $_pimEngineFile = $null
            try {
                $_pimCaller = Get-PSCallStack | Where-Object { $_.ScriptName -and ($_.ScriptName -ne $PSCommandPath) -and ($_.ScriptName -notmatch '_shared') } | Select-Object -First 1
                if ($_pimCaller -and $_pimCaller.ScriptName) {
                    $_pimEngineFile = $_pimCaller.ScriptName
                    $_pimEngineName = [System.IO.Path]::GetFileNameWithoutExtension($_pimEngineFile)
                }
            } catch {}
            if ($_pimEngineName) {
                Write-Host ("  [INFO] PIM4EntraPS {0} engine v{1} ({2})" -f $_pimEngineName, $_pimVer, $_pimEngineFile)
            } else {
                Write-Host ("  [INFO] PIM4EntraPS solution v{0}" -f $_pimVer)
            }
        }
    } catch { Write-Warning "PIM-Functions: failed reading VERSION at $_pimVerFile -- $($_.Exception.Message)" }
}

# Module-init: load naming-convention files into $global:PIM_NamingConventions
# so the engine helpers (Get-PimAdminsFiltered / Get-PimGroupsFiltered) work
# regardless of which launcher invoked us. Loads .locked.ps1 first, then
# .custom.ps1 if present (customer's override wins on every key).
$_pimNcRoot   = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config'
$_pimNcLocked = Join-Path $_pimNcRoot 'PIM4EntraPS.NamingConventions.locked.ps1'
$_pimNcCustom = Join-Path $_pimNcRoot 'PIM4EntraPS.NamingConventions.custom.ps1'
if (Test-Path -LiteralPath $_pimNcLocked) {
    try { . $_pimNcLocked; Write-Host "  [INFO] PIM-Functions: loaded $_pimNcLocked" -ForegroundColor DarkGray } catch { Write-Warning "PIM-Functions: failed loading $_pimNcLocked -- $($_.Exception.Message)" }
}
if (Test-Path -LiteralPath $_pimNcCustom) {
    try { . $_pimNcCustom; Write-Host "  [INFO] PIM-Functions: loaded $_pimNcCustom (custom overrides applied)" -ForegroundColor DarkGray } catch { Write-Warning "PIM-Functions: failed loading $_pimNcCustom -- $($_.Exception.Message)" }
}

# v2.2.0 (roadmap #11): load notification-channel config into
# $global:PIM_NotificationChannels so Send-PimAdminTap (+ future
# Send-PimAuditNotification etc.) work without per-launcher wiring.
$_pimNcLocked2 = Join-Path $_pimNcRoot 'PIM4EntraPS.NotificationChannels.locked.ps1'
$_pimNcCustom2 = Join-Path $_pimNcRoot 'PIM4EntraPS.NotificationChannels.custom.ps1'
if (Test-Path -LiteralPath $_pimNcLocked2) {
    try { . $_pimNcLocked2; Write-Host "  [INFO] PIM-Functions: loaded $_pimNcLocked2" -ForegroundColor DarkGray } catch { Write-Warning "PIM-Functions: failed loading $_pimNcLocked2 -- $($_.Exception.Message)" }
}
if (Test-Path -LiteralPath $_pimNcCustom2) {
    try { . $_pimNcCustom2; Write-Host "  [INFO] PIM-Functions: loaded $_pimNcCustom2 (custom overrides applied)" -ForegroundColor DarkGray } catch { Write-Warning "PIM-Functions: failed loading $_pimNcCustom2 -- $($_.Exception.Message)" }
}
Remove-Variable -Name _pimNcRoot, _pimNcLocked, _pimNcCustom, _pimNcLocked2, _pimNcCustom2 -ErrorAction SilentlyContinue

function Get-PimConfigDir {
    <#
    .SYNOPSIS
        Resolve the active config folder under SOLUTIONS/PIM4EntraPS/.

    .DESCRIPTION
        Routes to config-<variant>/ when $global:PIM_ConfigVariant is set
        (e.g. 'local' or 'msp'), otherwise to plain config/ for backward
        compatibility with single-tenancy installs. Creates the folder if
        missing.
    #>
    [CmdletBinding()]
    param()

    $solutionRoot = Get-PimSolutionRoot
    $variant = $global:PIM_ConfigVariant
    $folderName = if ($variant) { "config-$variant" } else { 'config' }
    $cfgDir = Join-Path $solutionRoot $folderName
    if (-not (Test-Path -LiteralPath $cfgDir)) {
        New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
    }
    return $cfgDir
}

function Get-PimCustomScript {
    <#
    .SYNOPSIS
        Resolve a config-folder customer-owned PS file (`<Name>.custom.ps1`).

    .DESCRIPTION
        Used by engines to source customer-owned config helpers (repository,
        policies, etc.) that live under the active config folder. Routes
        through Get-PimConfigDir so MSP / local variants land in the right
        place. The .custom.ps1 file is gitignored; a tracked .custom.sample.ps1
        sibling acts as the bootstrap template.

        Throws with a copy-from-sample hint if the customer file is missing.

    .PARAMETER Name
        Base name without suffix, e.g. 'repository' -> 'repository.custom.ps1'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    $cfgRoot = Get-PimConfigDir
    $custom  = Join-Path $cfgRoot ("{0}.custom.ps1" -f $Name)
    $legacy  = Join-Path $cfgRoot ("{0}.ps1" -f $Name)        # pre-v2.0 unsuffixed customer file
    $sample  = Join-Path $cfgRoot ("{0}.custom.sample.ps1" -f $Name)

    if (Test-Path -LiteralPath $custom) { return $custom }

    # v1 upgrade path: a customer migrating from pre-v2.0 PIM4EntraPS may have
    # copied their old `<name>.ps1` (unsuffixed) into the new config/ folder.
    # Treat the unsuffixed file as real customer data and RENAME it into the
    # v2 .custom.ps1 slot in place -- preserves edits, makes the next run
    # invisible, and short-circuits the sample auto-bootstrap below so we
    # don't trample the customer's actual data with a template.
    if (Test-Path -LiteralPath $legacy) {
        Move-Item -LiteralPath $legacy -Destination $custom -Force
        Write-Warning "Get-PimCustomScript: migrated pre-v2.0 '$legacy' -> '$custom' (renamed in place). Your file content is preserved; only the filename suffix changed."
        return $custom
    }

    # First-run bootstrap: if the customer file is missing but a sample exists,
    # auto-copy the sample to the customer slot and continue. The sample is the
    # documented bootstrap template; copying it lets a fresh install run end-
    # to-end without the operator hand-copying 20+ files. WARNING emitted so
    # the operator knows to review/replace placeholder values before the next
    # production run.
    if (Test-Path -LiteralPath $sample) {
        Copy-Item -LiteralPath $sample -Destination $custom -Force
        Write-Warning "Get-PimCustomScript: auto-bootstrapped '$custom' from sample. REVIEW + customize before relying on this run -- the sample is a template, not production config."
        return $custom
    }

    throw "Get-PimCustomScript: '$custom' not found, and no sample to bootstrap from."
}

function Get-PimConfigCsv {
    <#
    .SYNOPSIS
        Resolve a customer-owned <name>.custom.csv config file.

    .DESCRIPTION
        v2.3.0: PIM4EntraPS no longer ships `<name>.locked.csv` baseline files
        for the per-tenant config CSVs. Every customer's PIM topology is
        unique (admins, role groups, assignments, AU scopes), so a "shipped
        baseline that every customer extends" is the wrong mental model --
        customers always start from `<name>.custom.sample.csv` (which IS
        shipped, documents the schema, and includes worked example rows) and
        write to `<name>.custom.csv` (gitignored, customer-owned).

        Variant-aware: routes through Get-PimConfigDir, so MSP runs read
        config-msp/<name>.custom.csv while local runs read from config-local/
        (or plain config/ in single-tenancy mode).

        Pre-v2.3.0 legacy fallback: if a customer is upgrading and still has
        a `<name>.locked.csv` lying around (left over from v2.2.x or earlier),
        the engine will read it but emit a one-time WARNING per file pointing
        the operator at the migration step: rename or copy the file to
        `<name>.custom.csv` to silence the warning.

    .PARAMETER Name
        Base name without extension/suffix, e.g. 'PIM-Definitions-AU'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    $cfgRoot = Get-PimConfigDir
    $custom  = Join-Path $cfgRoot ("{0}.custom.csv" -f $Name)
    $legacy  = Join-Path $cfgRoot ("{0}.csv" -f $Name)        # pre-v2.0 unsuffixed customer file
    $locked  = Join-Path $cfgRoot ("{0}.locked.csv" -f $Name)
    $sample  = Join-Path $cfgRoot ("{0}.custom.sample.csv" -f $Name)

    if (Test-Path -LiteralPath $custom) { return $custom }

    # v1 upgrade path: a customer migrating from pre-v2.0 PIM4EntraPS may have
    # copied their old `<name>.csv` (unsuffixed) into the new config/ folder.
    # Treat the unsuffixed file as real customer data and RENAME it into the
    # v2 .custom.csv slot in place -- preserves rows, makes the next run
    # invisible, and short-circuits the sample auto-bootstrap below so we
    # don't trample the customer's actual data with a template.
    if (Test-Path -LiteralPath $legacy) {
        Move-Item -LiteralPath $legacy -Destination $custom -Force
        Write-Warning "Get-PimConfigCsv: migrated pre-v2.0 '$legacy' -> '$custom' (renamed in place). Your rows are preserved; only the filename suffix changed."
        return $custom
    }

    if (Test-Path -LiteralPath $locked) {
        Write-Warning ("Get-PimConfigCsv: '{0}.locked.csv' is a legacy pre-v2.3.0 file. " +
                       "Rename/copy it to '{0}.custom.csv' to silence this warning. " +
                       "(.locked.csv shipped baselines were removed in v2.3.0 -- every " +
                       "customer now owns their config as .custom.csv from day one.)" -f $Name)
        return $locked
    }

    # First-run bootstrap: if the customer CSV is missing but a sample exists,
    # auto-copy the sample to the customer slot and continue. Sample CSVs ship
    # with worked example rows -- letting them flow through unmodified would
    # apply EXAMPLE definitions to a live tenant, so the warning is explicit.
    if (Test-Path -LiteralPath $sample) {
        Copy-Item -LiteralPath $sample -Destination $custom -Force
        Write-Warning "Get-PimConfigCsv: auto-bootstrapped '$custom' from sample. REVIEW + replace example rows before relying on this run -- the sample contains placeholder data, not production rows."
        return $custom
    }

    throw "Get-PimConfigCsv: '$custom' not found (variant '$($global:PIM_ConfigVariant)') and no sample to bootstrap from."
}

function Get-PimOutputDir {
    <#
    .SYNOPSIS
        Return the SOLUTIONS/PIM4EntraPS/output[/<variant>]/ folder.

    .DESCRIPTION
        Variant-aware. When $global:PIM_ConfigVariant is set, state files
        land under output/<variant>/ so LastApplied snapshots from local
        and MSP runs never collide. Otherwise stays at output/ for
        back-compat.
    #>
    [CmdletBinding()]
    param()

    $outDir = Join-Path (Get-PimSolutionRoot) 'output'
    if ($global:PIM_ConfigVariant) {
        $outDir = Join-Path $outDir $global:PIM_ConfigVariant
    }
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }
    return $outDir
}

function Get-PimOutputPath {
    <#
    .SYNOPSIS
        Resolve a path under SOLUTIONS/PIM4EntraPS/output/ for engine state files.

    .DESCRIPTION
        Engines write per-run state CSVs here (e.g. *_LastApplied.csv used for
        delta detection between runs). The output/ folder is gitignored, so it
        never leaves the customer VM. Folder is created on demand.

    .PARAMETER Name
        Filename WITH extension, e.g. 'PIM-Definitions-AU_LastApplied.csv'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    return (Join-Path (Get-PimOutputDir) $Name)
}

function Resolve-PimTapStartDateTime {
    <#
    .SYNOPSIS
        Parse a TAP StartDateTime input into a [datetime] (UTC).

    .DESCRIPTION
        v2.2.0 (roadmap #12). Lets the admin CSV's TAPStartDate column carry
        relative natural-ish expressions ("in 2 days at 8am", "tomorrow 9am",
        "next monday 10:00", "+2d 8:00") in addition to the regular ISO 8601
        / culture-specific date strings v2.1.x already supported.

        Strategy (first match wins):
          1. Pass-through if already [datetime] / [datetimeoffset].
          2. Pass-through for ISO 8601 (`yyyy-MM-ddTHH:mm:ssZ` shaped).
          3. CorrelateDateTimeLanguage (handles en-US + da-DK + ISO formats).
          4. Three relative regexes:
               '+2d 8:00'  / 'in 2 days at 8am'  / '2 hours'
               'tomorrow'  / 'today 9am'
               'next monday 10:00'
          5. Last-resort [datetime]::Parse.
          6. $null if everything fails (caller MUST handle null).

        Defaults for relative expressions: hour=09, minute=00 (typical "next
        business day morning" handover). Caller should always check for $null
        and fall back to "TAP starts immediately" semantics.

    .PARAMETER InputValue
        String OR [datetime]. Anything else is coerced to its .ToString().

    .OUTPUTS
        [datetime] (UTC kind) or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][object]$InputValue
    )

    if ($null -eq $InputValue) { return $null }

    # Pass-through native datetime types
    if ($InputValue -is [datetime]) {
        return ([datetime]$InputValue).ToUniversalTime()
    }
    if ($InputValue -is [datetimeoffset]) {
        return ([datetimeoffset]$InputValue).UtcDateTime
    }

    $s = ([string]$InputValue).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    # --- 1. ISO 8601 fast-path -------------------------------------------------
    # Detect Z / offset / T-separator and prefer DateTimeOffset (more forgiving)
    if ($s -match 'Z$|[+-]\d{2}:\d{2}$|T\d') {
        try {
            $dto = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
                return $dto.UtcDateTime
            }
        } catch {}
    }

    # --- 2. CorrelateDateTimeLanguage (en-US + da-DK + ISO formats) ------------
    try {
        $parsed = CorrelateDateTimeLanguage -DateInput $s -WarningAction SilentlyContinue
        if ($parsed -is [datetime]) {
            # Assume local kind when culture-parsed (typical CSV input). Convert to UTC.
            if ($parsed.Kind -eq [System.DateTimeKind]::Unspecified) {
                $parsed = [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Local)
            }
            return $parsed.ToUniversalTime()
        }
    } catch {}

    # --- 3. Relative expressions -----------------------------------------------
    # Normalize whitespace; collapse 'in 2 days at 8am' style noise words.
    $sNorm = ($s.ToLowerInvariant() -replace '\s+', ' ').Trim()

    # 3a. '+2d 8:00' / 'in 2 days at 8am' / '2 hours' / '+3 days at 8 am'
    if ($sNorm -match '^(?:\+|in )?(\d+)\s*(d|day|days|h|hour|hours)\s*(?:at\s+)?(\d+)?(?::(\d+))?\s*(am|pm)?$') {
        $n     = [int]$Matches[1]
        $unit  = $Matches[2]
        $hour  = if ($Matches[3]) { [int]$Matches[3] } else { 9 }
        $min   = if ($Matches[4]) { [int]$Matches[4] } else { 0 }
        $ampm  = $Matches[5]
        if ($ampm -eq 'pm' -and $hour -lt 12) { $hour += 12 }
        if ($ampm -eq 'am' -and $hour -eq 12) { $hour = 0 }
        $base = (Get-Date).Date
        if ($unit -like 'h*') {
            # 'h' / 'hours' -- N hours from NOW; hour/min default 9:00 is ignored
            if (-not $Matches[3]) {
                return ([datetime]::Now).AddHours($n).ToUniversalTime()
            }
            # Explicit hour with 'h' is odd ('2h at 8am') -- treat as days fallback
        }
        $candidate = $base.AddDays($n).AddHours($hour).AddMinutes($min)
        return ([datetime]::SpecifyKind($candidate, [System.DateTimeKind]::Local)).ToUniversalTime()
    }

    # 3b. 'tomorrow [at] 8am' / 'today 14:30'
    if ($sNorm -match '^(tomorrow|today)\s*(?:at\s+)?(\d+)?(?::(\d+))?\s*(am|pm)?$') {
        $dayWord = $Matches[1]
        $hour    = if ($Matches[2]) { [int]$Matches[2] } else { 9 }
        $min     = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
        $ampm    = $Matches[4]
        if ($ampm -eq 'pm' -and $hour -lt 12) { $hour += 12 }
        if ($ampm -eq 'am' -and $hour -eq 12) { $hour = 0 }
        $offsetDays = if ($dayWord -eq 'tomorrow') { 1 } else { 0 }
        $candidate = (Get-Date).Date.AddDays($offsetDays).AddHours($hour).AddMinutes($min)
        return ([datetime]::SpecifyKind($candidate, [System.DateTimeKind]::Local)).ToUniversalTime()
    }

    # 3c. 'next monday [at] 10:00'
    if ($sNorm -match '^next\s+(mon|tue|wed|thu|fri|sat|sun)\w*\s*(?:at\s+)?(\d+)?(?::(\d+))?\s*(am|pm)?$') {
        $dayShort = $Matches[1]
        $hour     = if ($Matches[2]) { [int]$Matches[2] } else { 9 }
        $min      = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
        $ampm     = $Matches[4]
        if ($ampm -eq 'pm' -and $hour -lt 12) { $hour += 12 }
        if ($ampm -eq 'am' -and $hour -eq 12) { $hour = 0 }
        $map = @{ mon=1; tue=2; wed=3; thu=4; fri=5; sat=6; sun=0 }
        $targetDow = [int]$map[$dayShort]
        $today = (Get-Date).Date
        $todayDow = [int]$today.DayOfWeek
        $delta = ($targetDow - $todayDow + 7) % 7
        if ($delta -eq 0) { $delta = 7 }   # 'next monday' on a Monday = +7, not 0
        $candidate = $today.AddDays($delta).AddHours($hour).AddMinutes($min)
        return ([datetime]::SpecifyKind($candidate, [System.DateTimeKind]::Local)).ToUniversalTime()
    }

    # --- 4. Last resort: [datetime]::Parse -------------------------------------
    try {
        $fallback = [datetime]::Parse($s, [System.Globalization.CultureInfo]::CurrentCulture)
        if ($fallback.Kind -eq [System.DateTimeKind]::Unspecified) {
            $fallback = [datetime]::SpecifyKind($fallback, [System.DateTimeKind]::Local)
        }
        return $fallback.ToUniversalTime()
    } catch {
        return $null
    }
}

function New-PimTemporaryAccessPass {
    <#
    .SYNOPSIS
        Create a Temporary Access Pass (TAP) for a freshly-provisioned Entra ID user.

    .DESCRIPTION
        TAP gives the user a one-time code (default 60-minute lifetime) so they
        can register their own credentials without ever needing the initial
        random password. Use this when the account-definitions CSV row sets
        CreateTAP = TRUE.

        Requires:
          - Graph permission: UserAuthenticationMethod.ReadWrite.All (application).
          - The tenant's Authentication methods policy must enable TAP.

    .PARAMETER UserId
        Account UPN (the user the TAP is for).

    .PARAMETER LifetimeInMinutes
        TAP validity window after StartDateTime. Default 60. Tenant policy
        sets the allowed min/max; values outside the policy will be rejected.

    .PARAMETER IsUsableOnce
        $true = single-use (recommended for admin bootstrap).
        $false = multi-use within the lifetime window.

    .PARAMETER StartDateTime
        Optional. Either an ISO-8601 string, a culture-specific date string,
        or a v2.2.0 (roadmap #12) relative expression like "in 2 days at 8am" /
        "tomorrow 9am" / "next monday 10:00" / "+2d 8:00". Resolution goes
        through Resolve-PimTapStartDateTime first; if that returns $null we
        fall back to the legacy [datetime]::Parse. Unparseable values are
        omitted (TAP starts immediately) with a Write-Warning.

    .OUTPUTS
        [pscustomobject] @{ Code; StartDateTime; LifetimeInMinutes } -- caller
        is responsible for delivering the code to the user (out-of-band).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserId,
        [int]$LifetimeInMinutes = 60,
        [bool]$IsUsableOnce = $true,
        [string]$StartDateTime
    )

    $body = @{
        lifetimeInMinutes = $LifetimeInMinutes
        isUsableOnce      = $IsUsableOnce
    }
    if ($StartDateTime) {
        # v2.2.0 (roadmap #12): try the new relative-aware resolver first
        # (handles 'in 2 days at 8am' etc.). Fall back to the legacy direct
        # cast for max backward compat with any pre-existing CSV cell that
        # happens to be a hard [datetime]::Parse-able shape the new helper
        # didn't recognize.
        $resolved = $null
        try {
            $resolved = Resolve-PimTapStartDateTime -InputValue $StartDateTime
        } catch {
            $resolved = $null
        }
        if (-not $resolved) {
            try {
                $resolved = ([datetime]$StartDateTime).ToUniversalTime()
            } catch {
                Write-Warning "  [TAP] could not parse StartDateTime '$StartDateTime' -- omitting (TAP will start immediately)."
            }
        }
        if ($resolved) {
            $body.startDateTime = $resolved.ToString('o')
        }
    }

    try {
        $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -BodyParameter $body -ErrorAction Stop
    } catch {
        Write-Warning "  [TAP] failed for $($UserId): $($_.Exception.Message)"
        return $null
    }

    [pscustomobject]@{
        Code              = $tap.TemporaryAccessPass
        StartDateTime     = $tap.StartDateTime
        LifetimeInMinutes = $tap.LifetimeInMinutes
        IsUsableOnce      = $tap.IsUsableOnce
    }
}

function Write-PimAdminTap {
    <#
    .SYNOPSIS
        Persist + display a TAP code issued for a newly-created admin account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$Code,
        [Parameter()][string]$StartDateTime,
        [Parameter()][int]$LifetimeInMinutes
    )

    $file = Get-PimOutputPath -Name ("admin-passwords-{0:yyyyMMdd}.txt" -f [DateTime]::UtcNow)
    $line = "{0:yyyy-MM-ddTHH:mm:ssZ}`tID`t{1}`tTAP={2}`tstart={3}`tlifetime={4}min" -f `
            [DateTime]::UtcNow, $UserPrincipalName, $Code, $StartDateTime, $LifetimeInMinutes
    Add-Content -Path $file -Value $line -Encoding UTF8
    Write-Host "  -> TAP for $UserPrincipalName : $Code  (start=$StartDateTime, lifetime=${LifetimeInMinutes}min)" -ForegroundColor Yellow
    Write-Host "     appended to: $file" -ForegroundColor DarkCyan
}

function Send-PimAdminTap {
    <#
    .SYNOPSIS
        v2.2.0 (roadmap #11) -- deliver an admin's initial Temporary Access
        Pass (TAP) via configured notification channels (Email / Teams / Slack).

    .DESCRIPTION
        Reads `$global:PIM_NotificationChannels` for per-channel config
        (typically populated by `config/PIM4EntraPS.NotificationChannels.locked.ps1`
        + the customer's `.custom.ps1` override). When -Channel is omitted,
        sends to EVERY configured channel best-effort (one failure does not
        block the others). When -Channel is set, only that channel fires.

        Channel matrix:
          * Smtp  -> Send-MailMessage (PS 5.1 native; -WarningAction
                     SilentlyContinue suppresses the MS deprecation warning).
                     Recipient defaults to the parameter; admins' ManagerEmail
                     is the typical caller-supplied value.
          * Teams -> Invoke-RestMethod POST of an Adaptive-Card JSON payload
                     to the channel's incoming webhook URL.
          * Slack -> Invoke-RestMethod POST of `{ text: '...' }` to the
                     channel's incoming webhook URL.

        WhatIf semantics: when `$global:WhatIfMode -eq $true`, NO network
        traffic is generated; the function logs `[WHATIF] would send TAP to
        <recipient> via <channel>` and returns Sent=@().

        Idempotent / side-effect-free against PIM state: sending a TAP code
        does not change the user object or any Graph state (the TAP was
        already minted by New-PimTemporaryAccessPass).

    .PARAMETER UserPrincipalName
        The admin the TAP belongs to.

    .PARAMETER Code
        The TAP code string (already minted by New-PimTemporaryAccessPass).

    .PARAMETER StartDateTime
        TAP start moment (UTC or local; helper formats both for the body).

    .PARAMETER LifetimeMinutes
        TAP validity window after StartDateTime.

    .PARAMETER Channel
        Optional explicit channel ('Smtp' | 'Teams' | 'Slack'). When omitted,
        all configured channels fire.

    .PARAMETER Recipient
        Optional override. SMTP: an email address (defaults to the admin's
        ManagerEmail when the caller provides it via this parameter).
        Teams/Slack: ignored (the webhook URL itself targets the channel).

    .OUTPUTS
        Hashtable: @{ Sent = @('Smtp', 'Teams'); Failed = @(); Errors = @{} }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][datetime]$StartDateTime,
        [Parameter(Mandatory)][int]$LifetimeMinutes,
        [Parameter()][ValidateSet('Smtp','Teams','Slack')][string]$Channel,
        [Parameter()][string]$Recipient
    )

    $result = @{
        Sent   = @()
        Failed = @()
        Errors = @{}
    }

    $channels = $global:PIM_NotificationChannels
    if ($null -eq $channels -or $channels.Count -eq 0) {
        Write-Warning "  [TAP-Send] `$global:PIM_NotificationChannels not configured -- nothing to send to. See config/PIM4EntraPS.NotificationChannels.custom.sample.ps1."
        return $result
    }

    # Normalize StartDateTime: prefer UTC for the wire, keep local for human eyes
    if ($StartDateTime.Kind -eq [System.DateTimeKind]::Unspecified) {
        $startUtc = [datetime]::SpecifyKind($StartDateTime, [System.DateTimeKind]::Local).ToUniversalTime()
    } elseif ($StartDateTime.Kind -eq [System.DateTimeKind]::Local) {
        $startUtc = $StartDateTime.ToUniversalTime()
    } else {
        $startUtc = $StartDateTime
    }
    $startLocal = $startUtc.ToLocalTime()
    $expiryUtc  = $startUtc.AddMinutes($LifetimeMinutes)

    $startLocalStr = $startLocal.ToString('yyyy-MM-dd HH:mm zzz')
    $startUtcStr   = $startUtc.ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $expiryUtcStr  = $expiryUtc.ToString('yyyy-MM-dd HH:mm') + ' UTC'

    $subject = "Your initial PIM admin TAP for $UserPrincipalName"
    $bodyLines = @(
        "Hello,"
        ""
        "A Temporary Access Pass (TAP) has been issued for the privileged admin account:"
        "  $UserPrincipalName"
        ""
        "TAP code:        $Code"
        "Valid from:      $startLocalStr  ($startUtcStr)"
        "Lifetime:        $LifetimeMinutes minute(s)"
        "Expires at:      $expiryUtcStr"
        ""
        "How to use it:"
        "  1. Open https://mysignins.microsoft.com/security-info from a browser"
        "     where you are NOT already signed in to this account."
        "  2. Sign in with the admin UPN above; when prompted, enter the TAP"
        "     code as the password."
        "  3. Register your strong credentials (Passkey / Authenticator / FIDO2)"
        "     immediately. Once registered, the TAP is single-use and burned."
        ""
        "If you did not request this account, contact your security operations"
        "team immediately."
    )
    $body = $bodyLines -join "`r`n"

    # Decide which channels to fire
    $toFire = @()
    if ($Channel) {
        if ($channels.ContainsKey($Channel)) {
            $toFire = @($Channel)
        } else {
            Write-Warning "  [TAP-Send] requested channel '$Channel' is not configured in `$global:PIM_NotificationChannels."
            return $result
        }
    } else {
        $toFire = @($channels.Keys)
    }

    foreach ($ch in $toFire) {
        $cfg = $channels[$ch]
        if ($null -eq $cfg) { continue }

        # --- SMTP -----------------------------------------------------------
        if ($ch -eq 'Smtp') {
            $smtpRecipient = $Recipient
            if (-not $smtpRecipient) {
                Write-Warning "  [TAP-Send/Smtp] no recipient supplied (-Recipient empty, no ManagerEmail upstream) -- skip."
                $result.Failed += $ch
                $result.Errors[$ch] = 'no recipient'
                continue
            }
            $server = $cfg.Server
            $from   = $cfg.From
            $port   = if ($cfg.Port) { [int]$cfg.Port } else { 25 }
            $useSsl = [bool]$cfg.UseSsl
            $cred   = $cfg.Credential
            if (-not $server -or -not $from) {
                Write-Warning "  [TAP-Send/Smtp] config missing Server or From -- skip."
                $result.Failed += $ch
                $result.Errors[$ch] = 'config Server/From missing'
                continue
            }
            if ($global:WhatIfMode) {
                Write-Host "  [WHATIF] would send TAP to $smtpRecipient via Smtp (server=$server, port=$port)" -ForegroundColor Yellow
                continue
            }
            try {
                $mailParams = @{
                    SmtpServer = $server
                    Port       = $port
                    From       = $from
                    To         = $smtpRecipient
                    Subject    = $subject
                    Body       = $body
                    BodyAsHtml = $false
                    Encoding   = [System.Text.Encoding]::UTF8
                    ErrorAction = 'Stop'
                }
                if ($useSsl) { $mailParams['UseSsl'] = $true }
                if ($cred)   { $mailParams['Credential'] = $cred }
                Send-MailMessage @mailParams -WarningAction SilentlyContinue
                Write-Host "  [TAP-Send/Smtp] -> $smtpRecipient OK" -ForegroundColor Green
                $result.Sent += $ch
            } catch {
                Write-Warning "  [TAP-Send/Smtp] -> $smtpRecipient failed: $($_.Exception.Message)"
                $result.Failed += $ch
                $result.Errors[$ch] = $_.Exception.Message
            }
            continue
        }

        # --- Teams ----------------------------------------------------------
        if ($ch -eq 'Teams') {
            $url = $cfg.WebhookUrl
            if (-not $url) {
                Write-Warning "  [TAP-Send/Teams] no WebhookUrl configured -- skip."
                $result.Failed += $ch
                $result.Errors[$ch] = 'WebhookUrl missing'
                continue
            }
            if ($global:WhatIfMode) {
                Write-Host "  [WHATIF] would send TAP to Teams webhook" -ForegroundColor Yellow
                continue
            }
            # Adaptive Card (1.4) wrapped in a Teams 'message' envelope. Plain
            # text only; no avatars, no buttons. Keep payload minimal so it
            # works in both classic Teams connectors and Workflows-based
            # webhooks. Body is broken into TextBlocks to render readably.
            $factSet = @(
                @{ title = 'Admin UPN';   value = $UserPrincipalName }
                @{ title = 'TAP code';    value = $Code }
                @{ title = 'Valid from';  value = "$startLocalStr ($startUtcStr)" }
                @{ title = 'Lifetime';    value = "$LifetimeMinutes minute(s)" }
                @{ title = 'Expires at';  value = $expiryUtcStr }
            )
            $card = @{
                type    = 'AdaptiveCard'
                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                version = '1.4'
                body    = @(
                    @{
                        type    = 'TextBlock'
                        size    = 'Medium'
                        weight  = 'Bolder'
                        text    = $subject
                        wrap    = $true
                    },
                    @{
                        type  = 'FactSet'
                        facts = $factSet
                    },
                    @{
                        type = 'TextBlock'
                        text = 'Use the TAP at https://mysignins.microsoft.com/security-info to register strong credentials (Passkey / Authenticator). The TAP is single-use and burns on first successful sign-in.'
                        wrap = $true
                    }
                )
            }
            $payload = @{
                type        = 'message'
                attachments = @(
                    @{
                        contentType = 'application/vnd.microsoft.card.adaptive'
                        contentUrl  = $null
                        content     = $card
                    }
                )
            }
            try {
                $json = $payload | ConvertTo-Json -Depth 12 -Compress
                Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $json -ErrorAction Stop | Out-Null
                Write-Host "  [TAP-Send/Teams] webhook POST OK" -ForegroundColor Green
                $result.Sent += $ch
            } catch {
                Write-Warning "  [TAP-Send/Teams] webhook POST failed: $($_.Exception.Message)"
                $result.Failed += $ch
                $result.Errors[$ch] = $_.Exception.Message
            }
            continue
        }

        # --- Slack ----------------------------------------------------------
        if ($ch -eq 'Slack') {
            $url = $cfg.WebhookUrl
            if (-not $url) {
                Write-Warning "  [TAP-Send/Slack] no WebhookUrl configured -- skip."
                $result.Failed += $ch
                $result.Errors[$ch] = 'WebhookUrl missing'
                continue
            }
            if ($global:WhatIfMode) {
                Write-Host "  [WHATIF] would send TAP to Slack webhook" -ForegroundColor Yellow
                continue
            }
            $text = @(
                "*$subject*"
                "Admin UPN: ``$UserPrincipalName``"
                "TAP code: ``$Code``"
                "Valid from: $startLocalStr ($startUtcStr)"
                "Lifetime: $LifetimeMinutes minute(s); expires $expiryUtcStr"
                "Register strong credentials at https://mysignins.microsoft.com/security-info -- single-use, burns on first sign-in."
            ) -join "`n"
            $payload = @{ text = $text }
            try {
                $json = $payload | ConvertTo-Json -Depth 4 -Compress
                Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $json -ErrorAction Stop | Out-Null
                Write-Host "  [TAP-Send/Slack] webhook POST OK" -ForegroundColor Green
                $result.Sent += $ch
            } catch {
                Write-Warning "  [TAP-Send/Slack] webhook POST failed: $($_.Exception.Message)"
                $result.Failed += $ch
                $result.Errors[$ch] = $_.Exception.Message
            }
            continue
        }
    }

    return $result
}

function Write-PimAdminPassword {
    <#
    .SYNOPSIS
        Persist + display the random initial password assigned to a newly-created admin account.

    .DESCRIPTION
        Appends one line per account to output/admin-passwords-<yyyyMMdd>.txt and
        echoes the same line to the console so the operator can capture it. The
        per-day file is gitignored (lives under output/). Customers who use TAP
        can ignore the file; for non-TAP flows it's the only place to retrieve
        the initial password.

    .PARAMETER UserPrincipalName
        Account UPN (key the password belongs to).

    .PARAMETER Password
        The plain-text password just used to create the account.

    .PARAMETER Platform
        'ID' (Entra) or 'AD' (on-prem AD).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][ValidateSet('ID','AD')][string]$Platform
    )

    $file = Get-PimOutputPath -Name ("admin-passwords-{0:yyyyMMdd}.txt" -f [DateTime]::UtcNow)
    $line = "{0:yyyy-MM-ddTHH:mm:ssZ}`t{1}`t{2}`t{3}" -f [DateTime]::UtcNow, $Platform, $UserPrincipalName, $Password
    Add-Content -Path $file -Value $line -Encoding UTF8
    Write-Host "  -> initial password for $UserPrincipalName ($Platform): $Password" -ForegroundColor Cyan
    Write-Host "     appended to: $file" -ForegroundColor DarkCyan
}

function Sync-PimMspConfig {
    <#
    .SYNOPSIS
        Pull MSP-central config files into config-msp/ before the engine reads them.

    .DESCRIPTION
        Reads config-msp/msp.source.json to learn where to fetch from, then
        materializes the per-tenant config snapshot under config-msp/. Always
        atomic per file (write .tmp, Move-Item -Force). Logs to
        output/msp/msp-sync-<utcStamp>.log.

        v2.1.0 supports `sourceType = "git"` only. blob + https sources are
        roadmap (v2.2.x).

    .NOTES
        msp.source.json schema (v2.1.0):
          {
            "sourceType":      "git",
            "url":             "https://github.com/<msp>/pim-msp-central.git",
            "branch":          "main",                              // optional, default main
            "subPath":         "tenants/<tenant-id-or-name>",       // optional, default repo root
            "auth":            { "method": "PAT|None",
                                 "patEnvVar": "PIM_MSP_GIT_PAT" }   // env var holds the PAT
          }

        The fetched files MUST match the standard PIM4EntraPS config layout
        (the 14 CSVs + helper .ps1 files). Files not in the standard layout
        are ignored (won't be staged into config-msp/).
    #>
    [CmdletBinding()]
    param()

    if ($global:PIM_ConfigVariant -ne 'msp') {
        Write-Verbose "Sync-PimMspConfig: skipped (variant '$($global:PIM_ConfigVariant)' is not 'msp')."
        return
    }

    $cfgDir   = Get-PimConfigDir
    $manifest = Join-Path $cfgDir 'msp.source.json'
    if (-not (Test-Path -LiteralPath $manifest)) {
        throw "Sync-PimMspConfig: $manifest not found. Copy msp.source.sample.json to msp.source.json and fill in your MSP central source."
    }

    $src = Get-Content -Path $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $src.sourceType) { throw "Sync-PimMspConfig: msp.source.json missing 'sourceType'." }

    $logDir = Get-PimOutputDir
    $stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $logPath = Join-Path $logDir "msp-sync-$stamp.log"

    Write-Host ""
    Write-Host "Sync-PimMspConfig: pulling MSP central config (sourceType=$($src.sourceType))..." -ForegroundColor Cyan
    "[$stamp] Sync-PimMspConfig starting (sourceType=$($src.sourceType), url=$($src.url))" | Add-Content -Path $logPath

    switch ($src.sourceType) {
        'git' { Sync-PimMspConfig_Git -Source $src -DestDir $cfgDir -LogPath $logPath }
        default { throw "Sync-PimMspConfig: sourceType '$($src.sourceType)' not supported in v2.1.0. Use 'git'." }
    }

    # Update lastSyncUtc in-place (preserves the rest of the manifest).
    $src | Add-Member -NotePropertyName 'lastSyncUtc' -NotePropertyValue $stamp -Force
    $src | ConvertTo-Json -Depth 5 | Set-Content -Path $manifest -Encoding UTF8

    Write-Host "Sync-PimMspConfig: complete. Log: $logPath" -ForegroundColor Green
}

function Sync-PimMspConfig_Git {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Source,
        [Parameter(Mandatory)][string]$DestDir,
        [Parameter(Mandatory)][string]$LogPath
    )

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Sync-PimMspConfig_Git: 'git' not found on PATH. Install Git for Windows or use sourceType='https'."
    }

    $branch = if ($Source.branch) { $Source.branch } else { 'main' }
    $subPath = if ($Source.subPath) { $Source.subPath.Trim('/') } else { '' }

    # Shallow clone into a fresh temp dir, copy out, delete temp. Keeps the
    # working tree clean and avoids merging into any prior state.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-msp-sync-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0,8)))
    New-Item -Path $tmp -ItemType Directory -Force | Out-Null
    try {
        # Surface PAT via temporary env var if requested. Don't write to disk.
        $url = $Source.url
        if ($Source.auth -and $Source.auth.method -eq 'PAT' -and $Source.auth.patEnvVar) {
            $pat = [System.Environment]::GetEnvironmentVariable($Source.auth.patEnvVar)
            if (-not $pat) {
                throw "Sync-PimMspConfig_Git: env var '$($Source.auth.patEnvVar)' is empty -- set it before launching the engine."
            }
            # Inject as x-access-token (works for github + most git hosts).
            $url = $url -replace '^https://', "https://x-access-token:$pat@"
        }

        "[git] clone --depth=1 --branch=$branch <url-redacted>" | Add-Content -Path $LogPath
        & git clone --depth 1 --branch $branch --quiet $url $tmp 2>&1 | Add-Content -Path $LogPath
        if ($LASTEXITCODE -ne 0) { throw "git clone failed -- see $LogPath" }

        $copyRoot = if ($subPath) { Join-Path $tmp $subPath } else { $tmp }
        if (-not (Test-Path -LiteralPath $copyRoot)) { throw "Sync-PimMspConfig_Git: subPath '$subPath' not present in cloned repo." }

        # Whitelist: only the standard CSV + helper PS file patterns. No .git,
        # no README, no surprise files into config-msp/.
        $patterns = @('*.locked.csv', '*.custom.sample.csv', '*.locked.ps1', '*.custom.sample.ps1')
        $copied = 0
        foreach ($pat in $patterns) {
            foreach ($f in Get-ChildItem -LiteralPath $copyRoot -File -Filter $pat -ErrorAction SilentlyContinue) {
                $dst = Join-Path $DestDir $f.Name
                Copy-Item -LiteralPath $f.FullName -Destination ("$dst.tmp") -Force
                Move-Item -LiteralPath ("$dst.tmp") -Destination $dst -Force
                "[copy] $($f.Name)" | Add-Content -Path $LogPath
                $copied++
            }
        }
        "[done] $copied file(s) staged into $DestDir" | Add-Content -Path $LogPath
        Write-Host "  -> $copied file(s) staged into $DestDir" -ForegroundColor DarkGray
    }
    finally {
        # Best-effort cleanup; shallow git on Windows keeps locked handles
        # occasionally, swallow.
        try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop } catch {}
    }
}

function Test-PimAccountStatusChangeAuthorized {
    <#
    .SYNOPSIS
        Verify that a centrally-defined AccountStatus change (Disabled / Revoked)
        is authorized by the customer's CISO via a per-admin Key Vault secret.

    .DESCRIPTION
        Defense in depth for the MSP variant. When a row in config-msp/
        Account-Definitions-Admins.csv sets AccountStatus to Disabled or
        Revoked, this function fetches a per-admin secret from the
        CUSTOMER'S Key Vault (NOT the MSP's) and compares it to the
        StatusChangeCode column in the same CSV row. The engine only
        proceeds when they match exactly.

        This means: if an attacker pushes a malicious AccountStatus=Revoked
        through the MSP central repo, they ALSO need to know the CISO-set
        code in every tenant's KV -- which they don't have, so the engine
        refuses to act and logs a security event.

        Default-deny: if the customer's KV has no secret for this admin,
        the function returns $false. The CISO opts in per admin by writing
        the secret + telling the MSP the agreed-upon code.

        Naming convention for the KV secret:
            "pim-status-{slug}"
        where {slug} is the UPN with '@' and '.' replaced by '-' and
        lower-cased. Example:
            Admin-MSP-MOK-T0-ID@contoso.onmicrosoft.com
            -> pim-status-admin-msp-mok-t0-id-contoso-onmicrosoft-com

        Required globals (set in repository.custom.ps1):
            $global:PIM_StatusChange_KeyVaultName  -- the customer's KV name

    .PARAMETER UserPrincipalName
        The admin UPN whose status is being changed.

    .PARAMETER ProvidedCode
        The StatusChangeCode column value from the MSP CSV row.

    .OUTPUTS
        [bool] $true if the change is authorized, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [string]$ProvidedCode
    )

    if (-not $global:PIM_StatusChange_KeyVaultName) {
        Write-Warning "  [SECURITY] No `$global:PIM_StatusChange_KeyVaultName configured. Refusing central status change for $UserPrincipalName."
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($ProvidedCode)) {
        Write-Warning "  [SECURITY] MSP CSV row for $UserPrincipalName sets a non-Enabled AccountStatus but no StatusChangeCode. Refusing."
        return $false
    }

    $slug = ($UserPrincipalName.ToLowerInvariant() -replace '[@.]', '-')
    $secretName = "pim-status-$slug"

    try {
        $expected = Get-AzKeyVaultSecret -VaultName $global:PIM_StatusChange_KeyVaultName -Name $secretName -AsPlainText -ErrorAction Stop
    } catch {
        Write-Warning "  [SECURITY] KV secret '$secretName' not found in vault '$($global:PIM_StatusChange_KeyVaultName)'. CISO has not opted-in central status change for $UserPrincipalName. Refusing."
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($expected)) {
        Write-Warning "  [SECURITY] KV secret '$secretName' is empty. Refusing."
        return $false
    }

    # Constant-time-ish comparison (length first, then byte-by-byte). Avoid
    # short-circuit on character mismatch so timing leak is negligible.
    if ($expected.Length -ne $ProvidedCode.Length) {
        Write-Warning "  [SECURITY] StatusChangeCode mismatch for $UserPrincipalName (length differs from CISO-set secret). Refusing + alerting."
        return $false
    }
    $mismatch = 0
    for ($i = 0; $i -lt $expected.Length; $i++) {
        $mismatch = $mismatch -bor ([int][char]$expected[$i] -bxor [int][char]$ProvidedCode[$i])
    }
    if ($mismatch -ne 0) {
        Write-Warning "  [SECURITY] StatusChangeCode mismatch for $UserPrincipalName. Refusing + alerting."
        # Write to audit log explicitly -- this is a security event.
        try {
            $alertCsv = Join-Path (Get-PimOutputDir) ("status-change-DENIED-{0:yyyyMMdd}.csv" -f [DateTime]::UtcNow)
            [pscustomobject]@{
                Timestamp         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                UserPrincipalName = $UserPrincipalName
                Variant           = $global:PIM_ConfigVariant
                Reason            = 'StatusChangeCode mismatch'
                CodeProvidedSha   = (Get-FileHash -Algorithm SHA256 -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($ProvidedCode)))).Hash.Substring(0,16)
            } | Export-Csv -Path $alertCsv -Delimiter ';' -Encoding UTF8 -Append -NoTypeInformation
        } catch {}
        return $false
    }

    Write-Host "  [SECURITY] StatusChangeCode verified against KV for $UserPrincipalName -- proceeding." -ForegroundColor DarkGreen
    return $true
}

function Invoke-PimAccountStatusChange {
    <#
    .SYNOPSIS
        Apply a non-Enabled AccountStatus (Disabled / Revoked) to an admin.

    .DESCRIPTION
        Centralized branch + guard for MSP-driven kill-switch flips. Called
        by CreateUpdate-Accounts-From-file-CSV when the row's AccountStatus
        is not Enabled (or missing -> default Enabled).

        Guard rules:
          - When variant = 'msp' AND status in (Disabled, Revoked):
            Test-PimAccountStatusChangeAuthorized must return $true,
            else the change is refused and logged.
          - When variant != 'msp': no KV check (local CSV = customer
            directly in control).
          - When status = Enabled: no-op (status change to Enabled is
            handled by the normal create/update path).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$AccountStatus,
        [string]$StatusChangeCode
    )

    if ([string]::IsNullOrWhiteSpace($AccountStatus) -or $AccountStatus -eq 'Enabled') { return }

    if ($AccountStatus -notin @('Disabled','Revoked')) {
        Write-Warning "  Unknown AccountStatus '$AccountStatus' for $UserPrincipalName -- expected Enabled / Disabled / Revoked. Skipping."
        return
    }

    if ($global:PIM_ConfigVariant -eq 'msp') {
        if (-not (Test-PimAccountStatusChangeAuthorized -UserPrincipalName $UserPrincipalName -ProvidedCode $StatusChangeCode)) {
            return
        }
    }

    switch ($AccountStatus) {
        'Disabled' { Invoke-PimAccountDisable -UserPrincipalName $UserPrincipalName }
        'Revoked'  { Invoke-PimAccountRevoke  -UserPrincipalName $UserPrincipalName }
    }
}

function Invoke-PimAccountDisable {
    <#
    .SYNOPSIS
        Soft-kill an admin: set AccountEnabled=$false. Leaves PIM assignments in place.

    .DESCRIPTION
        Used when AccountStatus=Disabled in the admin CSV. Reversible:
        flipping back to AccountStatus=Enabled re-enables the user on the
        next engine run with no PIM rebuild required (much faster than
        Revoked -> Enabled, which requires full re-creation).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "  [Disable] $UserPrincipalName not found in tenant -- nothing to do." -ForegroundColor DarkGray
        return
    }
    if ($user.AccountEnabled -eq $false) {
        Write-Host "  [Disable] $UserPrincipalName already disabled -- skip." -ForegroundColor DarkGray
        return
    }
    if ($global:WhatIfMode) {
        Write-Host "  [WHATIF] would set AccountEnabled=`$false on $UserPrincipalName" -ForegroundColor Yellow
        return
    }
    try {
        Update-MgUser -UserId $user.Id -AccountEnabled:$false -ErrorAction Stop
        Write-Host "  [Disable] $UserPrincipalName -- AccountEnabled=`$false (PIM assignments left intact)" -ForegroundColor Yellow
    } catch {
        Write-Warning "  [Disable] $UserPrincipalName failed: $($_.Exception.Message)"
    }
}

function Invoke-PimAccountRevoke {
    <#
    .SYNOPSIS
        Hard-kill an admin: remove from every PIM group + cancel every active /
        eligible PIM activation + set AccountEnabled=$false.

    .DESCRIPTION
        Used when AccountStatus=Revoked in the admin CSV. NOT a delete --
        the user object stays so the audit trail survives. Reversibility:
        flipping back to AccountStatus=Enabled triggers a full re-creation
        on the next engine run (every role-group membership + PIM assignment
        the CSV declares is re-applied; anything else is gone for good).

        Best for: MSP central kill-switch, offboarding, compromise response.

        Action sequence (each step idempotent + WhatIfMode-aware):
          1. Cancel every eligible PIM-for-Groups schedule for this principal.
          2. Cancel every active   PIM-for-Groups assignment for this principal.
          3. Cancel every eligible PIM Entra ID role for this principal.
          4. Cancel every active   PIM Entra ID role for this principal.
          5. Remove from every Entra group they're a direct member of.
          6. Set AccountEnabled=$false.

        Writes a row per revocation event to output/<variant>/revoke-events-<utc>.csv
        with UPN, prior memberships, prior eligibilities, timestamp for audit.

    .NOTES
        v2.1.0: steps 1+2+5+6 are implemented. Steps 3+4 (PIM Entra ID role
        cancellation) need the directoryRoleAssignmentScheduleRequest +
        directoryRoleEligibilityScheduleRequest endpoints and will land in
        v2.1.1 -- for now we WARN if the user has any active Entra role PIM
        schedules so the operator knows to handle them manually.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName
    )

    $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "  [Revoke] $UserPrincipalName not found in tenant -- nothing to do." -ForegroundColor DarkGray
        return
    }

    $auditDir = Get-PimOutputDir
    $auditRow = [ordered]@{
        Timestamp           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        UserPrincipalName   = $UserPrincipalName
        UserId              = $user.Id
        WhatIfMode          = [bool]$global:WhatIfMode
        Variant             = $global:PIM_ConfigVariant
        GroupsRemovedFrom   = @()
        EligibleSchedules   = 0
        ActiveSchedules     = 0
        EntraRoleWarnings   = @()
        Errors              = @()
    }

    # --- Step 1+2: PIM-for-Groups schedules
    try {
        $eligibles = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "principalId eq '$($user.Id)'" -All -ErrorAction Stop
    } catch { $eligibles = @() }
    foreach ($e in $eligibles) {
        $auditRow.EligibleSchedules++
        if ($global:WhatIfMode) {
            Write-Host "  [WHATIF] would adminRemove eligible PIM-Group memberOf groupId=$($e.GroupId)" -ForegroundColor Yellow
            continue
        }
        $body = @{
            accessId      = $e.AccessId
            principalId   = $e.PrincipalId
            groupId       = $e.GroupId
            action        = 'adminRemove'
            justification = "AccountStatus=Revoked via PIM4EntraPS engine ($($global:PIM_ConfigVariant) variant)"
        }
        try {
            New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $body -ErrorAction Stop | Out-Null
            Write-Host "  [Revoke] eligible PIM-Group memberOf groupId=$($e.GroupId) -- cancelled" -ForegroundColor Yellow
        } catch {
            $auditRow.Errors += "elig $($e.GroupId): $($_.Exception.Message)"
            Write-Warning "  [Revoke] eligible cancel for $($e.GroupId) failed: $($_.Exception.Message)"
        }
    }

    try {
        $actives = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter "principalId eq '$($user.Id)'" -All -ErrorAction Stop
    } catch { $actives = @() }
    foreach ($a in $actives) {
        $auditRow.ActiveSchedules++
        if ($global:WhatIfMode) {
            Write-Host "  [WHATIF] would adminRemove active PIM-Group memberOf groupId=$($a.GroupId)" -ForegroundColor Yellow
            continue
        }
        $body = @{
            accessId      = $a.AccessId
            principalId   = $a.PrincipalId
            groupId       = $a.GroupId
            action        = 'adminRemove'
            justification = "AccountStatus=Revoked via PIM4EntraPS engine ($($global:PIM_ConfigVariant) variant)"
        }
        try {
            New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $body -ErrorAction Stop | Out-Null
            Write-Host "  [Revoke] active PIM-Group memberOf groupId=$($a.GroupId) -- cancelled" -ForegroundColor Yellow
        } catch {
            $auditRow.Errors += "active $($a.GroupId): $($_.Exception.Message)"
            Write-Warning "  [Revoke] active cancel for $($a.GroupId) failed: $($_.Exception.Message)"
        }
    }

    # --- Step 3+4: PIM Entra ID role schedules (v2.1.0: detect + warn only)
    try {
        $roleSchedules = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "principalId eq '$($user.Id)'" -All -ErrorAction Stop
        if ($roleSchedules) {
            $auditRow.EntraRoleWarnings += "$($roleSchedules.Count) eligible Entra ID role schedule(s) NOT auto-cancelled (v2.1.0 limitation -- cancel manually in PIM blade)"
            Write-Warning "  [Revoke] $UserPrincipalName has $($roleSchedules.Count) eligible Entra ID role PIM schedule(s). Cancel manually in the Entra portal (auto-cancel in v2.1.1)."
        }
    } catch {}

    # --- Step 5: remove from direct group memberships
    try {
        $memberships = Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction Stop
    } catch { $memberships = @() }
    foreach ($m in $memberships) {
        if ($m.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.group') { continue }
        $gid = $m.Id
        if ($global:WhatIfMode) {
            Write-Host "  [WHATIF] would remove $UserPrincipalName from group $gid" -ForegroundColor Yellow
            continue
        }
        try {
            Remove-MgGroupMemberByRef -GroupId $gid -DirectoryObjectId $user.Id -ErrorAction Stop
            $auditRow.GroupsRemovedFrom += $gid
            Write-Host "  [Revoke] removed from group $gid" -ForegroundColor Yellow
        } catch {
            $auditRow.Errors += "removeMember ${gid}: $($_.Exception.Message)"
        }
    }

    # --- Step 6: disable account
    if (-not $global:WhatIfMode) {
        try {
            Update-MgUser -UserId $user.Id -AccountEnabled:$false -ErrorAction Stop
            Write-Host "  [Revoke] $UserPrincipalName -- AccountEnabled=`$false" -ForegroundColor Red
        } catch {
            $auditRow.Errors += "disable: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  [WHATIF] would set AccountEnabled=`$false on $UserPrincipalName" -ForegroundColor Yellow
    }

    # --- Audit row
    $auditCsv = Join-Path $auditDir ("revoke-events-{0:yyyyMMdd}.csv" -f [DateTime]::UtcNow)
    $auditRowFlat = [pscustomobject]@{
        Timestamp         = $auditRow.Timestamp
        UserPrincipalName = $auditRow.UserPrincipalName
        UserId            = $auditRow.UserId
        WhatIfMode        = $auditRow.WhatIfMode
        Variant           = $auditRow.Variant
        GroupsRemoved     = ($auditRow.GroupsRemovedFrom -join '|')
        EligibleCancelled = $auditRow.EligibleSchedules
        ActiveCancelled   = $auditRow.ActiveSchedules
        EntraRoleWarnings = ($auditRow.EntraRoleWarnings -join '|')
        Errors            = ($auditRow.Errors -join '|')
    }
    if (Test-Path -LiteralPath $auditCsv) {
        $auditRowFlat | Export-Csv -Path $auditCsv -Delimiter ';' -Encoding UTF8 -Append -NoTypeInformation
    } else {
        $auditRowFlat | Export-Csv -Path $auditCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
    }
    Write-Host "  [Revoke] audit row appended -> $auditCsv" -ForegroundColor DarkCyan
}

function Get-PimNamePrefix {
    <#
    .SYNOPSIS
        Extract the literal prefix (everything before the first {Token})
        from a naming-convention pattern.

    .EXAMPLE
        Get-PimNamePrefix 'PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}'
        # -> 'PIM-'

        Get-PimNamePrefix 'Admin-{Initials}-L{Level}-T{Tier}-{Platform}'
        # -> 'Admin-'
    #>
    [CmdletBinding()]
    param([string]$Pattern)
    if (-not $Pattern) { return '' }
    $idx = $Pattern.IndexOf('{')
    if ($idx -lt 0) { return $Pattern }
    return $Pattern.Substring(0, $idx)
}

function Get-PimGroupsFiltered {
    <#
    .SYNOPSIS
        Server-side-filtered Get-MgGroup. Loads only groups whose displayName
        starts with the naming-convention prefix derived from
        $global:PIM_NamingConventions.PimGroupPattern.

    .DESCRIPTION
        Replacement for `Get-MgGroup -All` in engine hot paths. Saves the
        full-tenant fetch (e.g. a 514 000-user tenant returns ~hundreds of
        PIM-* groups instead of all 30 000 groups).

        Fallback rules:
          - No prefix found / prefix shorter than 3 chars => warn + fall
            back to unfiltered Get-MgGroup -All (loud Write-Warning so the
            operator notices the perf regression and fixes their config).
          - Optional $Extra parameter appends extra filter clauses (OR'd
            with the prefix clause). Used when role / dept / etc. groups
            have their own prefix in addition to PIM- groups.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Extra
    )

    $prefixes = New-Object System.Collections.ArrayList
    $nc = $global:PIM_NamingConventions
    if ($nc) {
        $p = Get-PimNamePrefix -Pattern $nc.PimGroupPattern
        if ($p -and $p.Length -ge 3) { [void]$prefixes.Add($p) }
        # AU pattern too, in case it differs (rare but seen).
        $pa = Get-PimNamePrefix -Pattern $nc.PimGroupAuPattern
        if ($pa -and $pa.Length -ge 3 -and $pa -ne $p) { [void]$prefixes.Add($pa) }
    }
    if ($Extra) {
        foreach ($e in $Extra) { if ($e -and -not ($prefixes -contains $e)) { [void]$prefixes.Add($e) } }
    }

    if ($prefixes.Count -eq 0) {
        Write-Warning "Get-PimGroupsFiltered: no PimGroupPattern prefix configured (NamingConventions). Loading ALL groups (this is slow on large tenants -- set PimGroupPattern to override)."
        return @(Get-MgGroup -All)
    }

    $clauses = $prefixes | ForEach-Object { "startswith(displayName,'$_')" }
    $filter = $clauses -join ' or '
    Write-Host "  [perf] Get-PimGroupsFiltered: `$filter=$filter" -ForegroundColor DarkGray
    # ConsistencyLevel=eventual + $count required for advanced $filter shapes.
    return @(Get-MgGroup -All -Filter $filter -ConsistencyLevel eventual -CountVariable __ -ErrorAction Stop)
}

function Resolve-PimGroupCached {
    <#
    .SYNOPSIS
        Look up a group by display name from the in-memory $Global:Groups_All_ID
        cache; fall back to a single Graph call if not found.

    .DESCRIPTION
        Drop-in replacement for `Get-MgGroup -Filter "DisplayName eq '<name>'"`
        used in per-row CSV loops. Eliminates ~700 Graph round-trips per
        Baseline run on customer-scale tenants by serving the lookup from the
        cache that Get-PimGroupsFiltered already populated at engine startup.

        On a cache miss (group exists in tenant but didn't match the
        PIM-prefix filter), falls back to a single `Get-MgGroup -Filter`
        call wrapped in Try/Catch with a Write-Warning that names the
        group. Result is added to the cache so a second lookup is free.

        On total failure (Graph throws AND group not in cache), returns
        $null + writes a warning. Callers handle $null the same way they
        would if `Get-MgGroup -Filter` returned no rows.

    .PARAMETER DisplayName
        The group display name to resolve.

    .PARAMETER NoCache
        Skip the cache lookup; force a Graph fetch. Use sparingly (only
        when you suspect the cache is stale, e.g. immediately after a
        Create operation in the same run).

    .OUTPUTS
        Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup (or $null on miss).

    .NOTES
        Cache is $Global:Groups_All_ID (a hashtable keyed by DisplayName)
        lazily initialised on first call. If the calling engine populated
        a different cache shape (e.g. an array from Get-PimGroupsFiltered),
        the helper handles both: array -> hashtable conversion on first
        call, then keyed lookup thereafter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName,

        [switch]$NoCache
    )

    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $null }

    # Lazily initialise the script-scoped canonical cache from $Global:Groups_All_ID.
    # The engine populates $Global:Groups_All_ID via Get-PimGroupsFiltered at startup;
    # shape is typically an array, but tolerate hashtable too.
    if (-not $script:PimGroupCache -or $script:PimGroupCache -isnot [hashtable]) {
        $script:PimGroupCache = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
        $source = $Global:Groups_All_ID
        if ($source) {
            if ($source -is [hashtable]) {
                foreach ($k in $source.Keys) {
                    $v = $source[$k]
                    if ($v -and $v.DisplayName) {
                        $script:PimGroupCache[$v.DisplayName] = $v
                    } elseif ($v) {
                        $script:PimGroupCache[$k] = $v
                    }
                }
            } else {
                foreach ($g in @($source)) {
                    if ($g -and $g.DisplayName -and -not $script:PimGroupCache.ContainsKey($g.DisplayName)) {
                        $script:PimGroupCache[$g.DisplayName] = $g
                    }
                }
            }
        }
    }

    # Cache lookup (case-insensitive keyed by DisplayName).
    if (-not $NoCache) {
        if ($script:PimGroupCache.ContainsKey($DisplayName)) {
            return $script:PimGroupCache[$DisplayName]
        }
    }

    # Cache miss (or -NoCache): Graph fetch with eventual-consistency retry.
    # When -NoCache is used, the caller is signaling "I just created this
    # group, expect Entra propagation lag" -- a single Graph call returns 0
    # results because the new object isn't replicated to the search index
    # yet (typical lag: 3-30s, occasionally longer). Without retry, the
    # function returns $null + the caller passes an empty string to the
    # next Add-Member / Add-AU call, which fails with "Cannot bind argument
    # to parameter 'ObjectId' because it is an empty string."
    $escaped = $DisplayName.Replace("'", "''")
    $found = $null
    $maxAttempts = if ($NoCache) { 6 } else { 1 }
    $backoff     = 5
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $found = Get-MgGroup -Filter "DisplayName eq '$escaped'" -ErrorAction Stop
            if ($found) { break }
        } catch {
            if ($attempt -eq $maxAttempts) {
                Write-Warning "  [Resolve-PimGroupCached] Graph lookup for group '$DisplayName' failed after $attempt attempt(s): $($_.Exception.Message)"
                return $null
            }
        }
        if ($attempt -lt $maxAttempts) {
            Write-Host ("  [Resolve-PimGroupCached] '{0}' not visible yet (attempt {1}/{2}); waiting {3}s for Entra propagation..." -f $DisplayName, $attempt, $maxAttempts, $backoff) -ForegroundColor DarkGray
            Start-Sleep -Seconds $backoff
        }
    }

    if ($found) {
        # Graph -Filter can return 0/1/many; normalise to single object (DisplayName is non-unique in theory).
        $first = @($found)[0]
        if ($first -and $first.DisplayName) {
            $script:PimGroupCache[$first.DisplayName] = $first
        } else {
            $script:PimGroupCache[$DisplayName] = $first
        }
        return $first
    }

    Write-Warning ("  [Resolve-PimGroupCached] '{0}' not found in Graph after {1} attempts (~{2}s of Entra propagation wait). Returning `$null; caller will likely fail with an empty-string error." -f $DisplayName, $maxAttempts, ($maxAttempts * $backoff))
    return $null
}

function Get-PimAdminsFiltered {
    <#
    .SYNOPSIS
        Server-side-filtered Get-MgUser. Loads only users whose
        userPrincipalName starts with one of the admin-account prefixes
        derived from $global:PIM_NamingConventions.AdminAccountPatterns
        (or AdminAccountPattern legacy single string).

    .DESCRIPTION
        Replacement for `Get-MgUser -All` in engine hot paths. On a tenant
        with 500 000 users + 30 admin accounts, this returns 30 users
        instead of all 500 000.

        Fallback: if no naming convention prefix is configured, warns and
        falls back to unfiltered Get-MgUser -All.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Extra
    )

    $prefixes = New-Object System.Collections.ArrayList
    $nc = $global:PIM_NamingConventions
    if ($nc) {
        # AdminAccountPatterns accepts THREE shapes -- pick whichever fits the
        # tenant's mental model:
        #   1. [hashtable]  @{ Internal = 'adm_{Owner}'; External = 'ext_{Owner}' }
        #      (UserType -> template; values can be templates OR plain prefixes)
        #   2. [string[]]   @('adm_', 'Admin-', 'X-Admin')
        #      (plain prefix list -- simplest when you just need to widen the filter)
        #   3. [string]     'adm_'
        #      (single prefix as a bare string)
        if ($nc.AdminAccountPatterns -is [hashtable]) {
            foreach ($v in $nc.AdminAccountPatterns.Values) {
                $p = Get-PimNamePrefix -Pattern $v
                if ($p -and $p.Length -ge 3 -and -not ($prefixes -contains $p)) { [void]$prefixes.Add($p) }
            }
        }
        elseif ($nc.AdminAccountPatterns -is [System.Collections.IEnumerable] -and $nc.AdminAccountPatterns -isnot [string]) {
            foreach ($v in $nc.AdminAccountPatterns) {
                $p = Get-PimNamePrefix -Pattern $v
                if ($p -and $p.Length -ge 3 -and -not ($prefixes -contains $p)) { [void]$prefixes.Add($p) }
            }
        }
        elseif ($nc.AdminAccountPatterns -is [string] -and $nc.AdminAccountPatterns) {
            $p = Get-PimNamePrefix -Pattern $nc.AdminAccountPatterns
            if ($p -and $p.Length -ge 3 -and -not ($prefixes -contains $p)) { [void]$prefixes.Add($p) }
        }
        if ($nc.AdminAccountPattern) {
            $p = Get-PimNamePrefix -Pattern $nc.AdminAccountPattern
            if ($p -and $p.Length -ge 3 -and -not ($prefixes -contains $p)) { [void]$prefixes.Add($p) }
        }
    }
    if ($Extra) {
        foreach ($e in $Extra) { if ($e -and -not ($prefixes -contains $e)) { [void]$prefixes.Add($e) } }
    }

    if ($prefixes.Count -eq 0) {
        Write-Warning "Get-PimAdminsFiltered: no admin-name prefix in NamingConventions. Loading ALL users (this is slow on large tenants -- set AdminAccountPatterns to override)."
        return @(Get-MgUser -All)
    }

    $clauses = $prefixes | ForEach-Object { "startswith(userPrincipalName,'$_')" }
    $filter = $clauses -join ' or '
    Write-Host "  [perf] Get-PimAdminsFiltered: `$filter=$filter" -ForegroundColor DarkGray
    return @(Get-MgUser -All -Filter $filter -ConsistencyLevel eventual -CountVariable __ -ErrorAction Stop)
}

# ---------------------------------------------------------------------------
# v2.4.0 perf helpers -- tenant-wide preload pattern.
#
# Why these exist:
#   Pre-v2.4 the Baseline / Exporter / Revoker engines fanned out one Graph
#   call per CSV row (`Get-MgIdentityGovernance...Schedule -Filter "groupId
#   eq '...'"`) and one ARM REST call per Azure scope. At customer scale
#   (~1000 PIM-for-Groups rows + ~60 Azure scopes) that is ~10 min + ~70 s
#   of pure HTTP wait. Microsoft Graph and Azure Resource Graph both
#   support a single tenant-wide query that returns the same data in 1-3 s.
#   These helpers do that preload ONCE per session and stage the results
#   in $script: hashtables for O(1) lookup by the lookup helpers below.
#
#   Eligibility schedules are NOT in Azure Resource Graph (Microsoft Learn
#   2026-06: AuthorizationResources table covers only roleassignments /
#   roledefinitions / classicadministrators), so the per-scope ARM walk is
#   still required for Azure RBAC PIM eligibility. This file only covers
#   the parts that CAN be preloaded.
# ---------------------------------------------------------------------------

function Get-PimGroupSchedulesPreloaded {
    <#
    .SYNOPSIS
        Single tenant-wide preload of ALL PIM-for-Groups eligibility +
        assignment schedules. Replaces per-row `-Filter "groupId eq..."`
        round-trips with a hashtable keyed by GroupId.

    .DESCRIPTION
        Calls both:
          Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -All
          Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -All
        Each typically returns 500-2000 rows tenant-wide in 1-3s (one paged
        Graph call) -- vs the current per-CSV-row 600ms x 1000 = ~10 min
        fallback path. Result is staged in two $script: hashtables that the
        engine helpers consult via Get-PimGroupSchedule.

        Idempotent + cache-aware: if the preload has already run this session
        (within MaxAgeMinutes, default 5), reuses the cached set. Call again
        with -Force to refresh.

    .PARAMETER MaxAgeMinutes
        Reuse cached preload if it's younger than this. Default 5.

    .PARAMETER Force
        Refresh the cache regardless of age.

    .OUTPUTS
        PSCustomObject { Eligibility = <count>; Assignment = <count>;
                         LoadedUtc = <datetime>; ElapsedSec = <double> }
    #>
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 5,
        [switch]$Force
    )

    # Cache hit?
    if (-not $Force -and $script:PimGroupSchedulesPreloadLoadedUtc) {
        $ageMin = ([DateTime]::UtcNow - $script:PimGroupSchedulesPreloadLoadedUtc).TotalMinutes
        if ($ageMin -lt $MaxAgeMinutes) {
            $eCount = 0
            if ($script:PimGroupEligibilityByGroupId) {
                foreach ($v in $script:PimGroupEligibilityByGroupId.Values) { if ($v) { $eCount += $v.Count } }
            }
            $aCount = 0
            if ($script:PimGroupAssignmentByGroupId) {
                foreach ($v in $script:PimGroupAssignmentByGroupId.Values) { if ($v) { $aCount += $v.Count } }
            }
            Write-Host ("  [perf] Get-PimGroupSchedulesPreloaded: cache hit (age={0:N1}m, {1} eligible + {2} active rows)" -f $ageMin, $eCount, $aCount) -ForegroundColor DarkGray
            return [PSCustomObject]@{
                Eligibility = $eCount
                Assignment  = $aCount
                LoadedUtc   = $script:PimGroupSchedulesPreloadLoadedUtc
                ElapsedSec  = 0.0
                CacheHit    = $true
            }
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Microsoft.Graph SDK regression (~v2.30+): the cmdlets
    # Get-MgIdentityGovernancePrivilegedAccessGroup{Eligibility,Assignment}Schedule
    # added client-side validation that REQUIRES -GroupId, -PrincipalId, or
    # -Filter -- '-All' alone now throws MissingParameters even though the
    # underlying REST endpoint still supports an unfiltered tenant-wide list.
    # Bypass via Invoke-MgGraphRequest against the raw v1.0 endpoint, hand-
    # rolling the @odata.nextLink pagination.
    function _Get-PimSchedulePaged {
        param([Parameter(Mandatory)][string]$RelativeUri)
        $rows = @()
        $uri  = "https://graph.microsoft.com/v1.0/$RelativeUri`?`$top=999"
        while ($uri) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $rows += $resp.value }
            $uri = $resp.'@odata.nextLink'
        }
        return $rows
    }

    # Eligibility preload
    $eligRows = @()
    Try {
        $eligRows = @(_Get-PimSchedulePaged -RelativeUri 'identityGovernance/privilegedAccess/group/eligibilitySchedules')
    } Catch {
        Write-Warning "Get-PimGroupSchedulesPreloaded: eligibilitySchedules list failed: $($_.Exception.Message) -- eligibility cache will be empty; engine will fall back to per-row lookups."
        $eligRows = @()
    }

    # Assignment (active) preload
    $assignRows = @()
    Try {
        $assignRows = @(_Get-PimSchedulePaged -RelativeUri 'identityGovernance/privilegedAccess/group/assignmentSchedules')
    } Catch {
        Write-Warning "Get-PimGroupSchedulesPreloaded: assignmentSchedules list failed: $($_.Exception.Message) -- assignment cache will be empty; engine will fall back to per-row lookups."
        $assignRows = @()
    }

    # Index by GroupId. A group may have many principals, so each value is an array.
    $eligIdx = @{}
    foreach ($r in $eligRows) {
        if (-not $r) { continue }
        $gid = [string]$r.GroupId
        if (-not $gid) { continue }
        if (-not $eligIdx.ContainsKey($gid)) { $eligIdx[$gid] = New-Object System.Collections.ArrayList }
        [void]$eligIdx[$gid].Add($r)
    }

    $assignIdx = @{}
    foreach ($r in $assignRows) {
        if (-not $r) { continue }
        $gid = [string]$r.GroupId
        if (-not $gid) { continue }
        if (-not $assignIdx.ContainsKey($gid)) { $assignIdx[$gid] = New-Object System.Collections.ArrayList }
        [void]$assignIdx[$gid].Add($r)
    }

    $script:PimGroupEligibilityByGroupId      = $eligIdx
    $script:PimGroupAssignmentByGroupId       = $assignIdx
    $script:PimGroupSchedulesPreloadLoadedUtc = [DateTime]::UtcNow

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    Write-Host ("  [perf] Get-PimGroupSchedulesPreloaded: loaded {0} eligible + {1} active in {2}s" -f $eligRows.Count, $assignRows.Count, $elapsed) -ForegroundColor DarkGray

    return [PSCustomObject]@{
        Eligibility = $eligRows.Count
        Assignment  = $assignRows.Count
        LoadedUtc   = $script:PimGroupSchedulesPreloadLoadedUtc
        ElapsedSec  = $elapsed
        CacheHit    = $false
    }
}

function Get-PimGroupSchedule {
    <#
    .SYNOPSIS
        Look up PIM-for-Groups schedules for a specific (GroupId, PrincipalId,
        AssignmentType) tuple from the preload cache populated by
        Get-PimGroupSchedulesPreloaded. Returns $null on miss.

    .DESCRIPTION
        Drop-in replacement for per-row `Get-MgIdentityGovernance...Schedule
        -Filter "groupId eq '...' and principalId eq '...' and accessId eq
        'member'"` calls in Assign-PIMForGroups-From-file-CSV (lines 4118 +
        4972 in current PSM1).

        Auto-triggers Get-PimGroupSchedulesPreloaded on first call if the
        cache isn't populated yet.

    .PARAMETER GroupId
        The PIM-for-Groups target group.

    .PARAMETER PrincipalId
        The principal (user or group) whose schedule we want.

    .PARAMETER AssignmentType
        'Eligible' or 'Active'. Selects which preload bucket to consult.

    .PARAMETER AccessId
        'member' (default) or 'owner'. Filters within the cache result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][ValidateSet('Eligible', 'Active')][string]$AssignmentType,
        [ValidateSet('member', 'owner')][string]$AccessId = 'member'
    )

    # Lazy preload on first call.
    if (-not $script:PimGroupSchedulesPreloadLoadedUtc) {
        [void](Get-PimGroupSchedulesPreloaded)
    }

    $bucket = $null
    if ($AssignmentType -eq 'Eligible') {
        $bucket = $script:PimGroupEligibilityByGroupId
    } else {
        $bucket = $script:PimGroupAssignmentByGroupId
    }

    if (-not $bucket) { return $null }
    if (-not $bucket.ContainsKey($GroupId)) { return $null }

    $rows = $bucket[$GroupId]
    if (-not $rows -or $rows.Count -eq 0) { return $null }

    # Filter to the matching principal + accessId.
    $hits = New-Object System.Collections.ArrayList
    foreach ($r in $rows) {
        if (-not $r) { continue }
        if ([string]$r.PrincipalId -ne $PrincipalId) { continue }
        # AccessId on group schedules is typically 'member' or 'owner'.
        $rowAccess = 'member'
        if ($r.PSObject.Properties['AccessId'] -and $r.AccessId) { $rowAccess = [string]$r.AccessId }
        if ($rowAccess -ne $AccessId) { continue }
        [void]$hits.Add($r)
    }

    if ($hits.Count -eq 0) { return $null }
    return ,$hits.ToArray()
}

function Get-AzActiveRoleAssignmentsViaArg {
    <#
    .SYNOPSIS
        Single Azure Resource Graph query (Search-AzGraph -UseTenantScope)
        returning EVERY active Azure RBAC role assignment visible to the
        calling SPN. Replaces per-scope `Get-AzRoleAssignment -Scope` loops.

    .DESCRIPTION
        Uses the AuthorizationResources ARG table (confirmed in MS Learn
        2026-06: contains microsoft.authorization/roleassignments tenant-
        wide; does NOT contain roleEligibilitySchedules, so PIM eligibility
        STILL needs the per-scope ARM walk -- this helper covers active
        assignments only).

        Auto-paginates with -SkipToken for tenants over 1000 rows.

        Output shape mirrors what the existing per-scope code produces so
        downstream code can swap in without restructuring: an array of
        PSCustomObject with Id, Name, Scope, PrincipalId, PrincipalType,
        RoleDefinitionId, RoleDefinitionName (resolved client-side from
        roleDefinitionId by looking up the trailing GUID, since ARG returns
        the full /providers/.../roleDefinitions/<guid> string).

    .PARAMETER MaxAgeMinutes
        Reuse cached preload if it's younger than this. Default 5.

    .PARAMETER Force
        Refresh the cache regardless of age.

    .OUTPUTS
        Array of role-assignment objects. Cached in $script:AzActiveRoleAssignmentsCache.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 5,
        [switch]$Force
    )

    # Cache hit?
    if (-not $Force -and $script:AzActiveRoleAssignmentsCacheLoadedUtc) {
        $ageMin = ([DateTime]::UtcNow - $script:AzActiveRoleAssignmentsCacheLoadedUtc).TotalMinutes
        if ($ageMin -lt $MaxAgeMinutes) {
            $count = 0
            if ($script:AzActiveRoleAssignmentsCache) { $count = @($script:AzActiveRoleAssignmentsCache).Count }
            Write-Host ("  [perf] Get-AzActiveRoleAssignmentsViaArg: cache hit (age={0:N1}m, {1} assignments)" -f $ageMin, $count) -ForegroundColor DarkGray
            return $script:AzActiveRoleAssignmentsCache
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $q = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| project id, name, scope=tostring(properties.scope),
          principalId=tostring(properties.principalId),
          principalType=tostring(properties.principalType),
          roleDefinitionId=tostring(properties.roleDefinitionId)
"@

    $all = New-Object System.Collections.ArrayList
    $skipToken = $null
    $pages = 0

    Try {
        do {
            $pages++
            if ($skipToken) {
                $page = Search-AzGraph -Query $q -UseTenantScope -First 1000 -SkipToken $skipToken -ErrorAction Stop
            } else {
                $page = Search-AzGraph -Query $q -UseTenantScope -First 1000 -ErrorAction Stop
            }

            if ($page) {
                foreach ($row in $page) { [void]$all.Add($row) }
            }

            # Search-AzGraph result objects expose SkipToken on the returned PSObject.
            $skipToken = $null
            if ($page -and $page.PSObject.Properties['SkipToken']) { $skipToken = $page.SkipToken }
        } while ($skipToken)
    } Catch {
        Write-Warning "Get-AzActiveRoleAssignmentsViaArg: Search-AzGraph (authorizationresources) failed on page $($pages): $($_.Exception.Message) -- returning partial set of $($all.Count) row(s). Caller may need to fall back to per-scope Get-AzRoleAssignment."
    }

    # Resolve RoleDefinitionName from the trailing GUID of roleDefinitionId.
    # We cache the lookup per definition GUID so we only call Get-AzRoleDefinition once per role.
    $roleNameCache = @{}
    $result = New-Object System.Collections.ArrayList
    foreach ($row in $all) {
        if (-not $row) { continue }
        $rdId = [string]$row.roleDefinitionId
        $rdGuid = $null
        if ($rdId) {
            # roleDefinitionId looks like /subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions/<guid>
            # or /providers/Microsoft.Authorization/roleDefinitions/<guid> for tenant-scoped builtin.
            $idx = $rdId.LastIndexOf('/')
            if ($idx -ge 0 -and $idx -lt ($rdId.Length - 1)) {
                $rdGuid = $rdId.Substring($idx + 1)
            }
        }

        $rdName = $null
        if ($rdGuid) {
            if ($roleNameCache.ContainsKey($rdGuid)) {
                $rdName = $roleNameCache[$rdGuid]
            } else {
                Try {
                    $def = Get-AzRoleDefinition -Id $rdGuid -ErrorAction Stop
                    if ($def) { $rdName = $def.Name }
                } Catch {
                    Write-Warning "Get-AzActiveRoleAssignmentsViaArg: Get-AzRoleDefinition -Id $rdGuid failed: $($_.Exception.Message) -- RoleDefinitionName will be blank for this row."
                }
                $roleNameCache[$rdGuid] = $rdName
            }
        }

        [void]$result.Add([PSCustomObject]@{
            Id                 = $row.id
            Name               = $row.name
            Scope              = $row.scope
            PrincipalId        = $row.principalId
            PrincipalType      = $row.principalType
            RoleDefinitionId   = $rdGuid
            RoleDefinitionName = $rdName
        })
    }

    $script:AzActiveRoleAssignmentsCache          = $result
    $script:AzActiveRoleAssignmentsCacheLoadedUtc = [DateTime]::UtcNow

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    Write-Host ("  [perf] Get-AzActiveRoleAssignmentsViaArg: loaded {0} assignment(s) across {1} ARG page(s) in {2}s" -f $result.Count, $pages, $elapsed) -ForegroundColor DarkGray

    # TODO v2.4.x: Search-AzGraph 429 throttling is not yet handled with
    # explicit backoff/retry -- relies on Az.ResourceGraph internal retry.
    # If a customer trips it, add a Polly-style retry-after loop here.

    return $result
}

function New-PimRandomPassword {
    <#
    .SYNOPSIS
        Generate a strong random password for newly-created admin accounts.

    .DESCRIPTION
        Replacement for the legacy "fetch one shared password from Key Vault"
        pattern. Each call returns a fresh password, so every admin account
        provisioned via CreateUpdate-Accounts-From-file-CSV gets its own.
        Customers using TAP (Temporary Access Pass) never need to know this
        password; for non-TAP flows it is written to a per-run timestamped
        file under output/admin-passwords-<utc>.txt for one-time pickup.

    .PARAMETER Length
        Password length. Default 24, minimum 16.

    .OUTPUTS
        [string] plain-text password (caller must keep secure).
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(16, 128)]
        [int]$Length = 24
    )

    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'      # no I, O
    $lower   = [char[]]'abcdefghijkmnpqrstuvwxyz'      # no l, o
    $digits  = [char[]]'23456789'                       # no 0, 1
    $symbols = [char[]]'!@#$%^&*-_=+?'

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $pickOne = {
            param($set)
            $buf = New-Object byte[] 4
            $rng.GetBytes($buf)
            $idx = [BitConverter]::ToUInt32($buf, 0) % $set.Length
            $set[$idx]
        }

        # Guarantee at least one of each class.
        $chars = New-Object System.Collections.ArrayList
        [void]$chars.Add((& $pickOne $upper))
        [void]$chars.Add((& $pickOne $lower))
        [void]$chars.Add((& $pickOne $digits))
        [void]$chars.Add((& $pickOne $symbols))

        $allClasses = $upper + $lower + $digits + $symbols
        for ($i = $chars.Count; $i -lt $Length; $i++) {
            [void]$chars.Add((& $pickOne $allClasses))
        }

        # Shuffle with cryptographic randomness so the guaranteed chars don't sit at the front.
        $arr = $chars.ToArray()
        for ($i = $arr.Length - 1; $i -gt 0; $i--) {
            $buf = New-Object byte[] 4
            $rng.GetBytes($buf)
            $j = [BitConverter]::ToUInt32($buf, 0) % ($i + 1)
            $tmp = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $tmp
        }

        return (-join $arr)
    }
    finally {
        $rng.Dispose()
    }
}
