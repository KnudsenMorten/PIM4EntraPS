# PIM4EntraPS -- onboarding modes (guest invite, cloud-only) + self-service
# consultant enable/disable. Dot-sourced by PIM-Functions.psm1 (uses
# PIM-ChangeQueue.ps1 + PIM-PortalAccess.ps1) and the pim-manager.
#
# Guest invite: externals can be invited as B2B GUESTS instead of created as
# regular users -- CLOUD ONLY (you cannot invite a guest into on-prem AD). The
# AD/on-prem path is unchanged.
# Self-service: a business dept/service owner can enable/disable THEIR OWN
# consultants (gated by the portal-access capability + managedAdmins), reusing
# this portal. Both are pure decision functions (testable); the live Graph calls
# are thin wrappers.

Set-StrictMode -Off

function Resolve-PimOnboardingMode {
    # Decide how to onboard an account:
    #   external + cloud           -> guest-invite (B2B)
    #   external + NOT cloud       -> unsupported (guest invite is cloud-only)
    #   member   + cloud           -> cloud-user
    #   member   + NOT cloud       -> ad-user (on-prem)
    # RequestedType 'guest' forces the external path.
    param([bool]$Cloud, [bool]$External, [string]$RequestedType)
    $wantGuest = $External -or ("$RequestedType".ToLowerInvariant() -eq 'guest')
    if ($wantGuest) {
        if (-not $Cloud) { return [pscustomobject]@{ mode = 'unsupported'; userType = $null; reason = 'guest invite is cloud-only; cannot invite an external into on-prem AD' } }
        return [pscustomobject]@{ mode = 'guest-invite'; userType = 'Guest'; reason = 'external + cloud -> B2B guest invitation' }
    }
    if ($Cloud) { return [pscustomobject]@{ mode = 'cloud-user'; userType = 'Member'; reason = 'internal cloud user' } }
    return [pscustomobject]@{ mode = 'ad-user'; userType = 'Member'; reason = 'on-prem AD user' }
}

# UserType taxonomy (a COLUMN on the admin/resource row; each customer sets it,
# never inferred from the name): Internal | Consultant | OperationPartner (= MSP).
# Consultant + OperationPartner/MSP are EXTERNAL (guest-eligible); Internal (or
# blank) is internal. (External/Guest/B2B also accepted as synonyms of external.)
function Get-PimRowUserType {
    param([Parameter(Mandatory)][object]$Row)
    $get = {
        param($n)
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } ; return '' }
        $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } else { return '' }
    }
    $ut = "$(& $get 'UserType')".Trim()
    if ($ut) { return $ut }
    # legacy fallback: a truthy IsExternal column -> Consultant
    $ie = "$(& $get 'IsExternal')".Trim().ToLowerInvariant()
    if ($ie -in @('true','1','yes','y')) { return 'Consultant' }
    return 'Internal'
}

function Get-PimRowIsExternal {
    # External = Consultant / OperationPartner (or External/Guest/B2B synonyms).
    param([Parameter(Mandatory)][object]$Row)
    $ut = (Get-PimRowUserType -Row $Row).ToLowerInvariant()
    return ($ut -in @('consultant','operationpartner','operation-partner','msp','partner','external','guest','b2b'))
}

function Resolve-PimOnboardingModeForRow {
    # Row-driven onboarding decision: external-ness comes from the row's column,
    # cloud-ness from the platform. The customer's own naming convention is never
    # consulted here.
    param([Parameter(Mandatory)][object]$Row, [bool]$Cloud)
    return Resolve-PimOnboardingMode -Cloud $Cloud -External (Get-PimRowIsExternal -Row $Row)
}

function New-PimGuestInvitationBody {
    # Build the Graph /invitations request body (pure). The live POST is a thin
    # wrapper (Send-PimGuestInvitation) so this stays testable.
    param(
        [Parameter(Mandatory)][string]$Email,
        [string]$DisplayName,
        [string]$RedirectUrl = 'https://myapplications.microsoft.com',
        [bool]$SendInvitationMessage = $true,
        [string]$CustomMessage
    )
    if (-not "$Email".Trim()) { throw "New-PimGuestInvitationBody: Email is required." }
    $body = [ordered]@{
        invitedUserEmailAddress = "$Email".Trim()
        inviteRedirectUrl       = "$RedirectUrl"
        sendInvitationMessage   = [bool]$SendInvitationMessage
    }
    if ("$DisplayName".Trim()) { $body['invitedUserDisplayName'] = "$DisplayName".Trim() }
    if ("$CustomMessage".Trim()) { $body['invitedUserMessageInfo'] = [ordered]@{ customizedMessageBody = "$CustomMessage" } }
    $body['invitedUserType'] = 'Guest'
    return $body
}

function Send-PimGuestInvitation {
    # Live B2B invitation (cloud only). Thin wrapper over Invoke-MgGraphRequest.
    param([Parameter(Mandatory)][string]$Email, [string]$DisplayName, [string]$RedirectUrl = 'https://myapplications.microsoft.com', [string]$CustomMessage)
    $body = New-PimGuestInvitationBody -Email $Email -DisplayName $DisplayName -RedirectUrl $RedirectUrl -CustomMessage $CustomMessage
    return Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/invitations' -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
}

function New-PimAccountToggleChange {
    # Self-service enable/disable of a MANAGED account (consultant / operation
    # partner / any) -> a change-queue Update on Account-Definitions-Admins
    # (Enabled bit). GATE at the caller; this only builds the change record.
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][ValidateSet('enable','disable')][string]$Action,
        [string]$By = "$env:USERNAME"
    )
    $enabled = ($Action -eq 'enable')
    return New-PimChange -Entity 'Account-Definitions-Admins' -Key "$AccountName" -Op Update -By $By -Payload ([pscustomobject]@{ UserName = "$AccountName"; Enabled = $enabled })
}

function Resolve-PimSelfServiceToggle {
    # Generic end-to-end decision for the self-service endpoint: may this portal-
    # admin enable/disable this managed account? Returns { allowed; change?; reason }.
    param(
        [AllowNull()][object]$Profile,
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][ValidateSet('enable','disable')][string]$Action,
        [switch]$IsSuperAdmin,
        [string]$By = "$env:USERNAME"
    )
    if (-not (Test-PimPortalCanEnableConsultant -Profile $Profile -AdminName $AccountName -IsSuperAdmin:$IsSuperAdmin)) {
        return [pscustomobject]@{ allowed = $false; change = $null; reason = "not permitted: '$AccountName' is not one of your managed accounts (needs the enable-consultants capability)" }
    }
    return [pscustomobject]@{ allowed = $true; change = (New-PimAccountToggleChange -AccountName $AccountName -Action $Action -By $By); reason = 'ok' }
}
