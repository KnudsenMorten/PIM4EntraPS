######################################################################################################
# Management & Deployment of Privileged Identity Managemement (PIM)
# Created by Morten Knudsen, Microsoft MVP
######################################################################################################

# Variables
    $PIM_Function_Path                                                    = "C:\SCRIPTS\PIM\PIM-Functions.psm1"
    $DeptGroupsDefinitionFile                                             = "C:\SCRIPTS\PIM\PAG-Definitions-Departments.csv"
    $RoleGroupsDefinitionFile                                             = "C:\SCRIPTS\PIM\PAG-Definitions-Roles.csv"
    $TaskGroupsDefinitionFile                                             = "C:\SCRIPTS\PIM\PAG-Definitions-Tasks.csv"
    $ServiceGroupsDefinitionFile                                          = "C:\SCRIPTS\PIM\PAG-Definitions-Services.csv"
    $ProcessGroupsDefinitionFile                                          = "C:\SCRIPTS\PIM\PAG-Definitions-Processes.csv"
    $ResourceGroupsDefinitionFile                                         = "C:\SCRIPTS\PIM\PAG-Definitions-Resources.csv"
    $AdministrativeUnitDefinitionFile                                     = "C:\SCRIPTS\PIM\AU-Definitions.csv"

    $AdministrativeUnitRoleAssignmentsFile                                = "C:\SCRIPTS\PIM\PAG-Assignments-Roles-AUs.csv"
    $GroupRoleAssignmentsFile                                             = "C:\SCRIPTS\PIM\PAG-Assignments-Roles-Groups.csv"
    $GroupAzResourcesAssignmentsFile                                      = "C:\SCRIPTS\PIM\PAG-Assignments-Azure-Resources.csv"
    $AccountsAssignmentFile                                               = "C:\SCRIPTS\PIM\PAG-Assignments-Admins.csv"

    $AccountsDefinitionFile                                               = "C:\SCRIPTS\PIM\Account-Definitions-Admins.csv"

    $Expiration_EndUser_Assignment_isExpirationRequired                   = $true
    $Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

    $Expiration_Admin_Assignment_isExpirationRequired                     = $true
    $Expiration_Admin_Assignment_maximumDuration                          = "P365D"

    $Expiration_Admin_Eligibility_isExpirationRequired                    = $true
    $Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

    $Enablement_Admin_Assignment_enabledRules                             = @("MultiFactorAuthentication", "Justification")

    $Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

    $Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

    $Notification_Admin_EndUser_Assignment_notificationType               = "Email"
    $Notification_Admin_EndUser_recipientType                             = "Admin"
    $Notification_Admin_EndUser_notificationLevel                         = "All"
    $Notification_Admin_EndUser_notificationRecipients                    = @("mok@linkit.net")
    $Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

    $Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
    $Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
    $Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
    $Notification_Requestor_EndUser_Assignment_notificationRecipients     = @("mok@linkit.net")
    $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

    $Notification_Admin_Admin_Eligibility_notificationType                = "Email"
    $Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
    $Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
    $Notification_Admin_Admin_Eligibility_notificationRecipients          = @("mok@linkit.net")
    $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

    $Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
    $Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
    $Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
    $Notification_Requestor_Admin_Eligibility_notificationRecipients      = @("mok@linkit.net")
    $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true

    $PathAccounts                                                         = "OU=Admin, OU=SPECIAL ACCOUNTS, DC=2LINKIT, DC=LOCAL"
    $PathADDelegationGroups                                               = "OU=Delegation Groups, OU=2LINKIT Groups, OU=2LINKIT, DC=2LINKIT, DC=LOCAL"

    $AD_UserName                                                          = "2LINKIT\MOK"
    $AD_Password                                                          = "DonsLandevej177!"

    $AD_Password_Secure                                                   = ConvertTo-SecureString $AD_Password -AsPlainText -Force
    $AD_Credentials                                                       = New-Object System.Management.Automation.PSCredential ($AD_UserName, $AD_Password_Secure)
    $AD_DCServer                                                          = "DC1.2linkit.local"

    $AzAppId                                                              = "7602a1ec-6234-4275-ac96-ce5fa4589d1a"
    $AzAppSecret                                                          = "ZrG8Q~nfLRVVMdR34ws4jUV3nYkOwrgkf7iClbUO"
    $AzAppSecretSecure                                                    = ConvertTo-SecureString $AzAppSecret -AsPlainText -Force
    $TenantId                                                             = "00000000-0000-0000-0000-000000000000"


######################################################################################################
# PIM Function library
######################################################################################################

    # Loading PIM functions
    Import-Module $PIM_Function_Path -Global -force -WarningAction SilentlyContinue


######################################################################################################
# Connect to MgGraph & Azure
######################################################################################################

    # Azure Connect with AzApp & AzSecret
  #  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AzAppId, $AzAppSecretSecure
  #  Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential -WarningAction SilentlyContinue

    Disconnect-AzAccount
    Connect-AzAccount -TenantId $TenantId -WarningAction SilentlyContinue

    # Microsoft Graph connect with AzApp & AzSecret
        <#
            Connect-MicrosoftGraphPS -AppId $AzAppId `
                                     -AppSecret $AzAppSecret `
                                     -TenantId $TenantId
        #>
<#
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    $ConnectHeaders = Connect-MicrosoftGraphPS -AppId $AzAppId -AppSecret $AzAppSecret -TenantId $TenantId
#>


    # Microsoft Graph connect with interactive login with the permission defined in the scopes
    Disconnect-MgGraph -ErrorAction SilentlyContinue

    $Scopes = @("RoleManagement.Read.Directory",`
                "Directory.Read.All",`
                "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup"
                "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"
                "PrivilegedAccess.ReadWrite.AzureADGroup"
                "RoleManagementPolicy.Read.AzureADGroup"
                "RoleManagementPolicy.ReadWrite.AzureADGroup"
                )
    Connect-MicrosoftGraphPS -Scopes $Scopes
    Connect-ExchangeOnline

######################################################################################################
# Load definitions
######################################################################################################
    Build-List-of-Definitions -DeptGroupsDefinitionFile $DeptGroupsDefinitionFile `
                              -RoleGroupsDefinitionFile $RoleGroupsDefinitionFile `
                              -TaskGroupsDefinitionFile $TaskGroupsDefinitionFile `
                              -ServiceGroupsDefinitionFile $ServiceGroupsDefinitionFile `
                              -ProcessGroupsDefinitionFile $ProcessGroupsDefinitionFile `
                              -ResourceGroupsDefinitionFile $ResourceGroupsDefinitionFile `
                              -AdministrativeUnitDefinitionFile $AdministrativeUnitDefinitionFile `
                              -AccountsDefinitionFile $AccountsDefinitionFile


# Create Group Managed Service Account
New-ADServiceAccount -Name "xxx" `
                     -DNSHostName "xxx" `
                     -KerberosEncryptionType AES256 `
                     -ManagedPasswordIntervalInDays 30 `
                     -PrincipalsAllowedToRetrieveManagedPassword "xx" `
                     -SamAccountName "xx" `
                     -ServicePrincipalNames "xx"

$AccountName            = "GMSA-PIM-AD"
$DNSHostName            = "GMSA-PIM-AD@2linkit.local"
$GroupPrincipalsAllowed = "GMSA-Group-PrincipalsAllowed-SVC-PIM-AD"
New-ADServiceAccount -Name $AccountName `
                     -DNSHostName $DNSHostName `
                     -KerberosEncryptionType AES256 `
                     -ManagedPasswordIntervalInDays 30 `
                     -PrincipalsAllowedToRetrieveManagedPassword $GroupPrincipalsAllowed `
                     -SamAccountName $AccountName


# Install-Module GMSACredential
$Cred = Get-GMSACredential -GMSAName "GMSA-PIM-AD" -Domain '2linkit.local'
$Cred

$Results = Invoke-GMSACommand -Credential $Cred -ScriptBlock {
    # Code to query remote SQL server
}

# Exchange Roles
    $RoleName = "Recipient Management"
    $GroupTag = "PAG-SERV-50"
    Add-Exchange-Role-to-PAG-Group -RoleName $RoleName -GroupTag $GroupTag

    $RoleName = "Communication Compliance"
    $GroupTag = "PAG-SERV-54"
    Add-Exchange-Role-to-PAG-Group -RoleName $RoleName -GroupTag $GroupTag



# Intune Roles

# Defender Unified Roles

