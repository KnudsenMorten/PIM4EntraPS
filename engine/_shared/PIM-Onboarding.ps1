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
    # partner / any) -> a change-queue Update on Account-Definitions-Admins. The
    # canonical column is AccountStatus (Enabled | Disabled) -- the engine flips the
    # Entra accountEnabled bit + audits it. GATE at the caller; this only builds the
    # change record (the engine stays the only writer to Entra).
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][ValidateSet('enable','disable')][string]$Action,
        [string]$By = "$env:USERNAME"
    )
    $status = if ($Action -eq 'enable') { 'Enabled' } else { 'Disabled' }
    return New-PimChange -Entity 'Account-Definitions-Admins' -Key "$AccountName" -Op Update -By $By -Payload ([pscustomobject]@{ UserName = "$AccountName"; AccountStatus = $status })
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

# --- GUEST INVITE INTO THE DELEGATION MODEL -------------------------------------
# Inviting an external consultant is not just a B2B invitation -- the consultant
# must land IN the group-centric delegation model: an Account-Definitions-Admins
# row (UserType = Consultant, cloud guest) plus, optionally, a delegation into one
# direct group (PIM-Assignments-Admins membership). The pure planner below builds
# all three artefacts (invitation body + the two change-queue records) so they go
# through the normal Review & Save flow; the engine remains the only writer to
# Entra/Azure and the live invitation send (Send-PimGuestInvitation) is a separate
# explicit step the operator confirms.

function Test-PimPortalCanInviteGuest {
    # May this portal-admin invite a guest? Requires the invite-guest capability;
    # super-admins bypass. (managedAdmins is NOT checked here -- a guest is new, so
    # there is nothing to match yet; the delegation target group is gated separately
    # via Test-PimPortalCanManageGroup at the caller when a GroupTag is supplied.)
    param([AllowNull()][object]$Profile, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    return ($caps -contains 'invite-guest')
}

function New-PimGuestAdminRow {
    # Build the Account-Definitions-Admins Create change for an invited guest. A
    # guest is ALWAYS a cloud (Consultant) external account -- never on-prem AD.
    # Initials/DisplayName are derived when not supplied (mirrors the admin-import
    # path). UserName/UserPrincipalName default to the invited email.
    param(
        [Parameter(Mandatory)][string]$Email,
        [string]$DisplayName,
        [string]$FirstName,
        [string]$LastName,
        [string]$Company,
        [string]$Department,
        [string]$Notes,
        [string]$By = "$env:USERNAME"
    )
    $email = "$Email".Trim()
    if (-not $email) { throw "New-PimGuestAdminRow: Email is required." }
    $disp = "$DisplayName".Trim()
    if (-not $disp) {
        $fn = "$FirstName".Trim(); $ln = "$LastName".Trim()
        $disp = (@($fn, $ln) | Where-Object { $_ }) -join ' '
        if (-not $disp) { $disp = ($email -split '@')[0] }
    }
    # Initials: from first+last, else first two alpha chars of the local part.
    $ini = ''
    if ("$FirstName".Trim() -and "$LastName".Trim()) {
        $ini = ("$FirstName".Trim().Substring(0,1) + "$LastName".Trim().Substring(0,1)).ToUpperInvariant()
    } else {
        $lp = ($email -split '@')[0] -replace '[^A-Za-z]', ''
        if ($lp.Length -ge 2) { $ini = $lp.Substring(0,2).ToUpperInvariant() } elseif ($lp) { $ini = $lp.ToUpperInvariant() }
    }
    $row = [ordered]@{
        FirstName     = "$FirstName".Trim()
        LastName      = "$LastName".Trim()
        Initials      = $ini
        TargetUsage   = 'Cloud'
        TargetPlatform = 'ID'
        UserType      = 'Consultant'           # external -> guest-eligible
        AdminType     = 'external-guest'        # guest -> g- name prefix (§17)
        Environment   = 'entra'                 # guest is always cloud/Entra -> -ID suffix
        UserName      = $email
        DisplayName   = $disp
        UserPrincipalName = $email
        ForwardMailsToContact = 'FALSE'
        Company       = "$Company".Trim()
        Notes         = "$Notes".Trim()
        AccountStatus = 'Enabled'
        Purpose       = 'Day2Day'
    }
    if ("$Department".Trim()) { $row['Department'] = "$Department".Trim() }
    return New-PimChange -Entity 'Account-Definitions-Admins' -Key $email -Op Create -By $By -Payload ([pscustomobject]$row)
}

function New-PimGuestDelegationChange {
    # Build the PIM-Assignments-Admins Create change that places the invited guest
    # INTO a direct delegation group (membership = delegation). Eligible by default
    # (PIM activation, least-privilege). The engine applies it like any membership.
    param(
        [Parameter(Mandatory)][string]$Email,
        [Parameter(Mandatory)][string]$GroupTag,
        [ValidateSet('Eligible','Active')][string]$AssignmentType = 'Eligible',
        [int]$NumOfDaysWhenExpire = 0,
        [string]$By = "$env:USERNAME"
    )
    $email = "$Email".Trim()
    if (-not $email) { throw "New-PimGuestDelegationChange: Email is required." }
    if (-not "$GroupTag".Trim()) { throw "New-PimGuestDelegationChange: GroupTag is required." }
    $key = "$email|$($GroupTag.Trim())"
    $payload = [ordered]@{
        Username       = $email
        GroupTag       = "$GroupTag".Trim()
        AssignmentType = $AssignmentType
        Action         = 'Add'
        Permanent      = ($NumOfDaysWhenExpire -le 0)
    }
    if ($NumOfDaysWhenExpire -gt 0) { $payload['NumOfDaysWhenExpire'] = $NumOfDaysWhenExpire }
    return New-PimChange -Entity 'PIM-Assignments-Admins' -Key $key -Op Create -By $By -Payload ([pscustomobject]$payload)
}

function New-PimGuestOnboardingPlan {
    # End-to-end PLAN for inviting an external consultant as a guest INTO the
    # delegation model (cloud only). Returns:
    #   { ok; mode; invitation; changes[]; reason }
    # changes[] = the Account-Definitions-Admins Create + (when a GroupTag is given)
    # the PIM-Assignments-Admins Create -- both for Review & Save. The invitation is
    # the body for Send-PimGuestInvitation; nothing is written here.
    param(
        [Parameter(Mandatory)][string]$Email,
        [string]$DisplayName,
        [string]$FirstName,
        [string]$LastName,
        [string]$Company,
        [string]$Department,
        [string]$Notes,
        [string]$GroupTag,
        [ValidateSet('Eligible','Active')][string]$AssignmentType = 'Eligible',
        [int]$NumOfDaysWhenExpire = 0,
        [bool]$Cloud = $true,
        [string]$CustomMessage,
        [string]$RedirectUrl = 'https://myapplications.microsoft.com',
        [string]$By = "$env:USERNAME"
    )
    $email = "$Email".Trim()
    if (-not $email) { throw "New-PimGuestOnboardingPlan: Email is required." }
    $decision = Resolve-PimOnboardingMode -Cloud $Cloud -External $true -RequestedType 'guest'
    if ($decision.mode -ne 'guest-invite') {
        return [pscustomobject]@{ ok = $false; mode = $decision.mode; invitation = $null; changes = @(); reason = $decision.reason }
    }
    $disp = "$DisplayName".Trim()
    if (-not $disp) { $disp = (@("$FirstName".Trim(), "$LastName".Trim()) | Where-Object { $_ }) -join ' ' }
    $invitation = New-PimGuestInvitationBody -Email $email -DisplayName $disp -RedirectUrl $RedirectUrl -CustomMessage $CustomMessage
    $changes = New-Object System.Collections.Generic.List[object]
    $changes.Add((New-PimGuestAdminRow -Email $email -DisplayName $DisplayName -FirstName $FirstName -LastName $LastName -Company $Company -Department $Department -Notes $Notes -By $By))
    if ("$GroupTag".Trim()) {
        $changes.Add((New-PimGuestDelegationChange -Email $email -GroupTag "$GroupTag" -AssignmentType $AssignmentType -NumOfDaysWhenExpire $NumOfDaysWhenExpire -By $By))
    }
    return [pscustomobject]@{
        ok = $true; mode = 'guest-invite'; invitation = $invitation
        changes = $changes.ToArray(); reason = 'ok'
    }
}
