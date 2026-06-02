# PIM for Groups - Owner

$global:Owner_Expiration_EndUser_Assignment_isExpirationRequired                   = $true
$global:Owner_Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

$global:Owner_Expiration_Admin_Assignment_isExpirationRequired                     = $true
$global:Owner_Expiration_Admin_Assignment_maximumDuration                          = "P365D"

$global:Owner_Expiration_Admin_Eligibility_isExpirationRequired                    = $true
$global:Owner_Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

$global:Owner_Enablement_Admin_Assignment_enabledRules                             = @()

$global:Owner_Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

$global:Owner_Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

$global:Owner_Notification_Admin_EndUser_Assignment_notificationType               = "Email"
$global:Owner_Notification_Admin_EndUser_recipientType                             = "Admin"
$global:Owner_Notification_Admin_EndUser_notificationLevel                         = "All"
$global:Owner_Notification_Admin_EndUser_notificationRecipients                    = @()
$global:Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

$global:Owner_Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
$global:Owner_Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
$global:Owner_Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
$global:Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients     = @()
$global:Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

$global:Owner_Notification_Admin_Admin_Eligibility_notificationType                = "Email"
$global:Owner_Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
$global:Owner_Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
$global:Owner_Notification_Admin_Admin_Eligibility_notificationRecipients          = @()
$global:Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

$global:Owner_Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
$global:Owner_Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
$global:Owner_Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
$global:Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients      = @()
$global:Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true

#----------------------------------
# PIM for Groups - Member

$global:Owner_Expiration_EndUser_Assignment_isExpirationRequired                   = $true
$global:Owner_Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

$global:Owner_Expiration_Admin_Assignment_isExpirationRequired                     = $true
$global:Owner_Expiration_Admin_Assignment_maximumDuration                          = "P365D"

$global:Owner_Expiration_Admin_Eligibility_isExpirationRequired                    = $true
$global:Owner_Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

$global:Owner_Enablement_Admin_Assignment_enabledRules                             = @()

$global:Owner_Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

$global:Owner_Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

$global:Owner_Notification_Admin_EndUser_Assignment_notificationType               = "Email"
$global:Owner_Notification_Admin_EndUser_recipientType                             = "Admin"
$global:Owner_Notification_Admin_EndUser_notificationLevel                         = "All"
$global:Owner_Notification_Admin_EndUser_notificationRecipients                    = @()
$global:Owner_Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

$global:Owner_Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
$global:Owner_Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
$global:Owner_Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
$global:Owner_Notification_Requestor_EndUser_Assignment_notificationRecipients     = @()
$global:Owner_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

$global:Owner_Notification_Admin_Admin_Eligibility_notificationType                = "Email"
$global:Owner_Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
$global:Owner_Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
$global:Owner_Notification_Admin_Admin_Eligibility_notificationRecipients          = @()
$global:Owner_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

$global:Owner_Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
$global:Owner_Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
$global:Owner_Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
$global:Owner_Notification_Requestor_Admin_Eligibility_notificationRecipients      = @()
$global:Owner_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true

#----------------------------------
# Azure Resources

$global:Azres_Expiration_EndUser_Assignment_isExpirationRequired                   = $true
$global:Azres_Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

$global:Azres_Expiration_Admin_Assignment_isExpirationRequired                     = $true
$global:Azres_Expiration_Admin_Assignment_maximumDuration                          = "P365D"

$global:Azres_Expiration_Admin_Eligibility_isExpirationRequired                    = $true
$global:Azres_Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

$global:Azres_Enablement_Admin_Assignment_enabledRules                             = @()

$global:Azres_Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

$global:Azres_Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

$global:Azres_Notification_Admin_EndUser_Assignment_notificationType               = "Email"
$global:Azres_Notification_Admin_EndUser_recipientType                             = "Admin"
$global:Azres_Notification_Admin_EndUser_notificationLevel                         = "All"
$global:Azres_Notification_Admin_EndUser_notificationRecipients                    = @()
$global:Azres_Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

$global:Azres_Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
$global:Azres_Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
$global:Azres_Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
$global:Azres_Notification_Requestor_EndUser_Assignment_notificationRecipients     = @()
$global:Azres_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

$global:Azres_Notification_Admin_Admin_Eligibility_notificationType                = "Email"
$global:Azres_Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
$global:Azres_Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
$global:Azres_Notification_Admin_Admin_Eligibility_notificationRecipients          = @()
$global:Azres_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

$global:Azres_Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
$global:Azres_Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
$global:Azres_Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
$global:Azres_Notification_Requestor_Admin_Eligibility_notificationRecipients      = @()
$global:Azres_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true

#----------------------------------
# Roles

$global:EntraRoles_Expiration_EndUser_Assignment_isExpirationRequired                   = $true
$global:EntraRoles_Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

$global:EntraRoles_Expiration_Admin_Assignment_isExpirationRequired                     = $true
$global:EntraRoles_Expiration_Admin_Assignment_maximumDuration                          = "P365D"

$global:EntraRoles_Expiration_Admin_Eligibility_isExpirationRequired                    = $true
$global:EntraRoles_Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

$global:EntraRoles_Enablement_Admin_Assignment_enabledRules                             = @()

$global:EntraRoles_Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

$global:EntraRoles_Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

$global:EntraRoles_Notification_Admin_EndUser_Assignment_notificationType               = "Email"
$global:EntraRoles_Notification_Admin_EndUser_recipientType                             = "Admin"
$global:EntraRoles_Notification_Admin_EndUser_notificationLevel                         = "All"
$global:EntraRoles_Notification_Admin_EndUser_notificationRecipients                    = @()
$global:EntraRoles_Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

$global:EntraRoles_Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
$global:EntraRoles_Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
$global:EntraRoles_Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
$global:EntraRoles_Notification_Requestor_EndUser_Assignment_notificationRecipients     = @()
$global:EntraRoles_Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

$global:EntraRoles_Notification_Admin_Admin_Eligibility_notificationType                = "Email"
$global:EntraRoles_Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
$global:EntraRoles_Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
$global:EntraRoles_Notification_Admin_Admin_Eligibility_notificationRecipients          = @()
$global:EntraRoles_Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

$global:EntraRoles_Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
$global:EntraRoles_Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
$global:EntraRoles_Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
$global:EntraRoles_Notification_Requestor_Admin_Eligibility_notificationRecipients      = @()
$global:EntraRoles_Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true
