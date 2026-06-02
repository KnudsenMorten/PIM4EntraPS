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

    $formats = @(
        "M/d/yyyy h:mm:ss tt", 
        "dd-MM-yyyy HH:mm:ss", 
        "yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-ddTHH:mm:ss.fffffffZ",
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        "yyyy-MM-ddTHH:mm:ssK",
        "yyyy-MM-ddTHH:mm:ss", 
        "yyyy-MM-dd", 
        "MM/dd/yyyy"
    )

    $cultures = @(
        [CultureInfo]::GetCultureInfo("en-US"),
        [CultureInfo]::GetCultureInfo("da-DK"),
        [CultureInfo]::InvariantCulture
    )

    foreach ($culture in $cultures) {
        foreach ($fmt in $formats) {
            try {
                $parsedDate = [DateTime]::ParseExact($DateInput, $fmt, $culture)
                Write-Debug "Parsed using format '$fmt' and culture '$($culture.Name)'"
                return $parsedDate
            } catch {
                Write-Debug "Failed format '$fmt' with culture '$($culture.Name)'"
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


    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
 
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
            $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
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

    $AzScope             = "/providers/Microsoft.Management/managementGroups/00000000-0000-0000-0000-000000000000"
    $AzScopePermission   = "Owner"
#>

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue
    
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
            $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
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

            $Headers = Get-AzAccessTokenManagement

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


Function CreateUpdate-PIM-PAG-Group
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


    # Check if group already exist
    # OLD METHOD - SLOW - $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue
    $Group = $Global:Groups_All_ID | where-object { $_.DisplayName -eq $GroupName }

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
            $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
        }
    Else
        {
            Write-host "Checking Group Owners"
            If ($Owners)
                {
                    # $Owners = "ADMIN-ABC-L0-T0-ID@example.invalid,x-Admin-ABC-L0-T0-ID@example.invalid,admin@example.invalid"

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

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue

    # Check if group already exist
    $PAGGroup = Get-MgGroup -Filter "DisplayName eq '$($PAG_GroupName)'" -Erroraction SilentlyContinue


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


    $Headers = Get-AzAccessTokenManagement

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
                CreateUpdate-PIM-PAG-Group -GroupName $GroupName `
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
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
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
                CreateUpdate-PIM-PAG-Group -GroupName $GroupName `
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
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
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

                    # Get Group Principal Id
                        $Group = Get-MgGroup -Filter "DisplayName eq '$($PAG_Groupname)'"
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
                                            Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                            Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                                    write-host ""
                                                    Write-host "Existing Assignment will be updated with assignment details"
                                                    Write-host "Mode: AdminUpdate"
                                                    write-host ""
                                                    $PIMAction = "AdminUpdate"
                                                }
                                            Else
                                                {
                                                    # BUG FIX 3: Permanent assignment exists and no update requested - explicitly NoAction
                                                    write-host ""
                                                    Write-host "Existing permanent Assignment found ... skipping"
                                                    Write-host "Mode: NoAction"
                                                    write-host ""
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
                                                    write-host ""
                                                    Write-host "Existing permanent Assignment found ... skipping"
                                                    Write-host "Mode: NoAction"
                                                    write-host ""
                                                    $PIMAction = "NoAction"
                                                }
                                            Else
                                                {
                                                    $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk

                                                    # Calculate and round the number of days
                                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End (Ensure-DateTime $ExpirationDate)).TotalDays
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
                                                            Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
                                                            $PIMAction = "NoAction"
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
                                                            { Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green }
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
                                                            { Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green }
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

            # Get Group Principal Id
                $Group = Get-MgGroup -Filter "DisplayName eq '$($PAG_Groupname)'"
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
                                            Write-host "Existing permanent Assignment found ... skipping"
                                            Write-host "Mode: NoAction"
                                            write-host ""
                                            $PIMAction = "NoAction"
                                        }
                                }
                            Else
                                {
                                    # not permanent - check expiry
                                    $ValueChk = [string]$CheckExistingAssignment.ScheduleExpirationEndDateTime
                                    $ExpirationDate = CorrelateDateTimeLanguage -DateInput $ValueChk

                                    # Calculate and round the number of days
                                    $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End (Ensure-DateTime $ExpirationDate)).TotalDays
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
                                            # BUG FIX 2: Simplified - assignment exists, not expiring soon, no update requested -> skip
                                            write-host ""
                                            Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
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
                    # Check if group already exist
                    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
    
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
                        $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
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
                                            Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                            Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                                    Write-host "Existing permanent Assignment found ... skipping"
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
                                                    Write-host "Existing permanent Assignment found ... skipping"
                                                    Write-host "Mode: NoAction"
                                                    write-host ""
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
                                                            Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
                                                            Write-host "Mode: NoAction"
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
            
            # Check if group already exist
                $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue
    
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
                        $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
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
                                $Headers = Get-AzAccessTokenManagement
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
                                                Write-host "Existing permanent Assignment found ... skipping"
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
                                                $NumOfDaysBeforeExpiration = (New-TimeSpan -Start (Get-Date) -End (Ensure-DateTime $ExpirationDate)).TotalDays
                                                $NumOfDaysBeforeExpiration = [math]::Round($NumOfDaysBeforeExpiration, 0)
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
                                                Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
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

                                $Headers = Get-AzAccessTokenManagement

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

                            # Check if group already exist
                            $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue

                            # Check if group already exist
                            $PAGGroup = Get-MgGroup -Filter "DisplayName eq '$($PAG_GroupName)'" -Erroraction SilentlyContinue


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
                                                    Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                            $GraphCheck = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                                                            -Filter "groupId eq '$($Group.Id)' and principalId eq '$($PAGGroup.Id)' and accessId eq 'member'" `
                                                            -ErrorAction SilentlyContinue
                                            If ($GraphCheck)
                                                {
                                                    write-host ""
                                                    Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                                            Write-host "Existing permanent Assignment found ... skipping"
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
                                                            Write-host "Existing permanent Assignment found ... skipping"
                                                            Write-host "Mode: NoAction"
                                                            write-host ""
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
                                                                    Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
                                                                    Write-host "Mode: NoAction"
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
    Manage-Powershell-Module -ModuleName 'ExchangeOnlineManagement' -Scope AllUsers
    Write-Output "Connecting to Exchange Online using High Privilege Account using Modern method (certificate)"
    Connect-ExchangeOnline -CertificateThumbprint $HighPriv_Modern_CertificateThumbprint_O365 -AppId $HighPriv_Modern_ApplicationID_O365 -ShowProgress $false -Organization $TenantNameOrganization -ShowBanner

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
                            $Result = New-MgBetaUser -GivenName $FirstName `
                                                 -Surname $LastName `
                                                 -DisplayName $DisplayName `
                                                 -PasswordProfile $PasswordProfile `
                                                 -AccountEnabled `
                                                 -MailNickName $UserName `
                                                 -UserPrincipalName $UserPrincipalName `
                                                 -JobTitle $Description `
                                                 -UsageLocation $UsageLocation

                            $Result = Update-MgBetaUser -UserId $UserPrincipalName -PasswordPolicies DisablePasswordExpiration

                            Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'ID'

                            # TAP (Temporary Access Pass) -- created when the CSV row sets CreateTAP=TRUE.
                            # Customer-facing recommended path: deliver the TAP code out-of-band, the
                            # admin uses it to register their own credentials, and the random password
                            # above never has to leave the password log file.
                            If ($CreateTAP -eq 'TRUE' -or $CreateTAP -eq $true) {
                                $tap = New-PimTemporaryAccessPass -UserId $UserPrincipalName -StartDateTime $TAPStartDate
                                if ($tap) {
                                    Write-PimAdminTap -UserPrincipalName $UserPrincipalName -Code $tap.Code -StartDateTime $tap.StartDateTime -LifetimeInMinutes $tap.LifetimeInMinutes
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
                            
                            If ($TierLevel -eq "L0")
                                {
                            
                                    $Result = New-ADUser -Name $UserName `
                                                         -GivenName $FirstName `
                                                         -Surname $LastName `
                                                         -DisplayName $DisplayName `
                                                         -Description $Description `
                                                         -AccountPassword $AD_PasswordProfile `
                                                         -EmailAddress $UserPrincipalName `
                                                         -UserPrincipalName $UserPrincipalName `
                                                         -Path $PathAdminsL0T0 `
                                                         -Enabled:$true `
                                                         -Credential $Credentials
                                }
                            ElseIf ($TierLevel -eq "L1")
                                {

                                    $Result = New-ADUser -Name $UserName `
                                                         -GivenName $FirstName `
                                                         -Surname $LastName `
                                                         -DisplayName $DisplayName `
                                                         -Description $Description `
                                                         -AccountPassword $AD_PasswordProfile `
                                                         -EmailAddress $UserPrincipalName `
                                                         -UserPrincipalName $UserPrincipalName `
                                                         -Path $PathAdmins `
                                                         -Enabled:$true `
                                                         -Credential $Credentials
                                }

                            Write-PimAdminPassword -UserPrincipalName $UserPrincipalName -Password $generatedPassword -Platform 'AD'
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
                                    Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                            $GraphCheck = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                                            -Filter "groupId eq '$($GroupInfo.Id)' and principalId eq '$($UserInfo.Id)' and accessId eq 'member'" `
                                            -ErrorAction SilentlyContinue
                            If ($GraphCheck)
                                {
                                    write-host ""
                                    Write-host "Existing Assignment found via Graph (not in snapshot) ... treating as existing"
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
                                            Write-host "Existing permanent Assignment found ... skipping"
                                            Write-host "Mode: NoAction"
                                            write-host ""
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
                                                    Write-host "Existing Assignment found ... skipping (expires in $($NumOfDaysBeforeExpiration) days)"
                                                    Write-host "Mode: NoAction"
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
                                            { Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green }
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
                                            { Write-host "Existing Assignment found via Graph (API confirmed) ... skipping" -ForegroundColor Green }
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
                $Headers = Get-AzAccessTokenManagement

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

                    $Headers = Get-AzAccessTokenManagement

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

                        $Headers = Get-AzAccessTokenManagement

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
                $Headers = Get-AzAccessTokenManagement

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

                    $Headers = Get-AzAccessTokenManagement

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

                        $Headers = Get-AzAccessTokenManagement

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
                $Groups_All = Get-MgGroup -all:$true
                $Groups_All_Scope = $Groups_All | where-Object { ($_.SecurityEnabled -eq $true) }
                $Groups_All_Scope = $Groups_All_Scope | where-Object { ($_.GroupTypes -notin "DynamicMembership") }
                $Groups_All_Scope = $Groups_All_Scope | where-Object { ($_.OnPremisesSyncEnabled -ne $true) }
                $Groups_All_Scope = $Groups_All_Scope | where-Object { ($_.DisplayName -like "PIM-*") }
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
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id ``
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId ``
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

                                    $Headers = Get-AzAccessTokenManagement
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
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id ``
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId ``
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

                                    $Headers = Get-AzAccessTokenManagement
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
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id ``
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId ``
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

                                    $Headers = Get-AzAccessTokenManagement
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
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id ``
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId ``
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

                                    $Headers = Get-AzAccessTokenManagement
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
                                        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $Policy.id ``
                                                                                -UnifiedRoleManagementPolicyRuleId $RuleId ``
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

                                    $Headers = Get-AzAccessTokenManagement
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

# Module-init: load naming-convention files into $global:PIM_NamingConventions
# so the engine helpers (Get-PimAdminsFiltered / Get-PimGroupsFiltered) work
# regardless of which launcher invoked us. Loads .locked.ps1 first, then
# .custom.ps1 if present (customer's override wins on every key).
$_pimNcRoot   = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config'
$_pimNcLocked = Join-Path $_pimNcRoot 'PIM4EntraPS.NamingConventions.locked.ps1'
$_pimNcCustom = Join-Path $_pimNcRoot 'PIM4EntraPS.NamingConventions.custom.ps1'
if (Test-Path -LiteralPath $_pimNcLocked) {
    try { . $_pimNcLocked } catch { Write-Warning "PIM-Functions: failed loading $_pimNcLocked -- $($_.Exception.Message)" }
}
if (Test-Path -LiteralPath $_pimNcCustom) {
    try { . $_pimNcCustom } catch { Write-Warning "PIM-Functions: failed loading $_pimNcCustom -- $($_.Exception.Message)" }
}
Remove-Variable -Name _pimNcRoot, _pimNcLocked, _pimNcCustom -ErrorAction SilentlyContinue

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
    $sample  = Join-Path $cfgRoot ("{0}.custom.sample.ps1" -f $Name)

    if (Test-Path -LiteralPath $custom) { return $custom }

    $hint = if (Test-Path -LiteralPath $sample) { " Copy '$sample' to '$custom' and edit it." } else { "" }
    throw "Get-PimCustomScript: '$custom' not found.$hint"
}

function Get-PimConfigCsv {
    <#
    .SYNOPSIS
        Resolve a config-folder CSV file with .custom -> .locked fallback.

    .DESCRIPTION
        Variant-aware: routes through Get-PimConfigDir, so MSP runs read
        config-msp/<name>.custom.csv (fallback config-msp/<name>.locked.csv)
        while local runs read from config-local/ (or plain config/ in
        single-tenancy mode).

    .PARAMETER Name
        Base name without extension/suffix, e.g. 'PIM-Definitions-AU'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    $cfgRoot = Get-PimConfigDir
    $custom  = Join-Path $cfgRoot ("{0}.custom.csv" -f $Name)
    $locked  = Join-Path $cfgRoot ("{0}.locked.csv" -f $Name)

    if (Test-Path -LiteralPath $custom) { return $custom }
    if (Test-Path -LiteralPath $locked) { return $locked }

    throw "Get-PimConfigCsv: neither '$custom' nor '$locked' exists (variant '$($global:PIM_ConfigVariant)')."
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
        Optional ISO-8601 / parseable string. If omitted, TAP starts immediately.

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
        try {
            $body.startDateTime = ([datetime]$StartDateTime).ToUniversalTime().ToString('o')
        } catch {
            Write-Warning "  [TAP] could not parse StartDateTime '$StartDateTime' -- omitting (TAP will start immediately)."
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
        if ($nc.AdminAccountPatterns -is [hashtable]) {
            foreach ($v in $nc.AdminAccountPatterns.Values) {
                $p = Get-PimNamePrefix -Pattern $v
                if ($p -and $p.Length -ge 3 -and -not ($prefixes -contains $p)) { [void]$prefixes.Add($p) }
            }
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
