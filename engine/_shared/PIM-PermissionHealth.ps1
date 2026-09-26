<#
  🔴 PERMISSION HEALTH -- THE PORTAL MUST SAY WHEN CORE FUNCTIONALITY CANNOT WORK.

  Operator, 2026-09-12: *"i need to be informed immediately in the portal of this critical issue.
  this is a disater that core functionality is not working due to lack of permissions"* / *"it is
  ALL missing roles"*.

  🪤 WHY THIS EXISTS. A missing Graph app-role does not announce itself. Graph answers with a 403,
  the provider catches it, and the failure reaches the operator as a DOMAIN sentence -- the live
  example being `GroupsPolicies: no member policy for '<group>'`, which reads like a tenant data
  problem and sent this session to check the wrong principal twice. Meanwhile:
    * the deploy reported success,
    * every tick reported success,
    * and the delegation/policy work simply did not happen.
  The evidence existed the whole time; nothing ever COMPARED what the runtime identity holds
  against what the code needs. That comparison is cheap, it is pure data, and it is exactly the
  kind of thing a portal should put in front of a human the moment it is false.

  🔑 IT CHECKS THE RUNTIME IDENTITY, NOT THE ONE IN THE CONFIG. The hosted engine calls Graph as
  the container's MANAGED IDENTITY; the engine SPN named in Key Vault is a different principal that
  may be fully permissioned while the thing that actually executes is not. Measured on internal:
  the SPN held all 10 required roles; the MI held 9 of 17 and could not write a group policy.
  So the caller passes the identity it is RUNNING as, and this compares that.

  PURE: no Graph, no SQL, no clock. Verdict only -- the caller gathers the facts.
#>

Set-StrictMode -Off

# The Graph application permissions the engine's own code paths require, each mapped to the
# capability it unlocks so the portal can say WHAT BREAKS, not just which GUID is absent.
# Derived by enumerating every `Invoke-PimGraph -Path` in engine/ + tools/ (2026-09-12).
function Get-PimRequiredGraphCapabilities {
    # 🔑 MANDATORY vs OPTIONAL (operator, 2026-09-12: *"some permissions are optional (connector)
    # and rest are mandatory"*). The distinction decides SEVERITY, and getting it wrong in either
    # direction ruins the banner: grade a connector permission as fatal and every tenant that does
    # not use Intune shows a permanent red that people learn to ignore; grade a core one as
    # optional and the outage this whole check exists to catch reads as a shrug.
    #   mandatory -> core PIM cannot work without it            => ERROR
    #   optional  -> ONE workload connector is unavailable      => WARNING, and name the connector
    @(
        @{ role='Group.ReadWrite.All';                                  capability='Create and manage PIM groups';                    tier='mandatory'; connector='' }
        # §70.16 (2026-09-13): a ROLE-ASSIGNABLE group (isAssignableToRole=true -- every ROLE-* delegation group) can only
        # be created, and its members/owners changed, with this role in addition to Group.ReadWrite.All. Missing it was a
        # silent 403 on the operator's new delegation, and this banner stayed green because the table did not ask for it.
        @{ role='RoleManagement.ReadWrite.Directory';                   capability='Create role-assignable PIM groups and manage their members/owners'; tier='mandatory'; connector='' }
        @{ role='User.ReadWrite.All';                                   capability='Create and manage admin accounts';                tier='mandatory'; connector='' }
        @{ role='UserAuthenticationMethod.ReadWrite.All';               capability='Issue and reset Temporary Access Passes';         tier='mandatory'; connector='' }
        @{ role='Directory.Read.All';                                   capability='Read the directory';                              tier='mandatory'; connector='' }
        @{ role='AdministrativeUnit.ReadWrite.All';                     capability='Administrative Units';                            tier='mandatory'; connector='' }
        # 🔴 BUG-151 -- THIS DEMANDED THE BROAD ROLE, SO A LEAST-PRIVILEGE ENVIRONMENT REPORTED
        # "core functionality is BLOCKED". `RoleManagement.ReadWrite.Directory` is the documented
        # HIGHER-PRIVILEGED ALTERNATIVE to the RoleEligibilitySchedule/RoleAssignmentSchedule pair
        # (MS Learn) -- either grant works, and v1 used the narrow pair. §64.2 deliberately switched
        # internal to the pair and REMOVED the broad role; this table did not follow, so the §63.6
        # banner went red on a correctly configured environment. Measured 2026-09-12 against the
        # roles ca-pim-tick actually holds: ok=False, "1 REQUIRED Graph permission(s) missing".
        # 🪤 A BANNER THAT IS RED WHEN NOTHING IS WRONG IS HOW THE NEXT REAL OUTAGE GETS IGNORED --
        # the same reasoning this file already applies to connector permissions. Crying wolf and
        # staying silent are the SAME defect measured from opposite ends.
        # 🔑 Graded as a PAIR, not two independent rows: eligible and active assignment are one
        # capability to an operator, and reporting "half of Entra role assignment works" helps nobody.
        @{ role='RoleEligibilitySchedule.ReadWrite.Directory';          capability='Assign Entra directory roles (eligible)';         tier='mandatory'; connector='entra-roles'; altRole='RoleManagement.ReadWrite.Directory' }
        @{ role='RoleAssignmentSchedule.ReadWrite.Directory';           capability='Assign Entra directory roles (active)';           tier='mandatory'; connector='entra-roles'; altRole='RoleManagement.ReadWrite.Directory' }
        @{ role='RoleManagementPolicy.ReadWrite.Directory';             capability='Entra role PIM policies';                         tier='mandatory'; connector='' }
        @{ role='RoleManagementPolicy.ReadWrite.AzureADGroup';          capability='PIM-for-Groups policies (approval, MFA, duration)'; tier='mandatory'; connector='' }
        @{ role='PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup'; capability='Eligible group assignments';                      tier='mandatory'; connector='' }
        @{ role='PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup';  capability='Active group assignments';                        tier='mandatory'; connector='' }
        @{ role='Domain.Read.All';                                      capability='Resolve the tenant default domain';               tier='mandatory'; connector='' }
        @{ role='Policy.Read.All';                                      capability='Read the tenant TAP policy (one-time use, lifetime)'; tier='mandatory'; connector='' }
        # 🔑 THESE FIVE ARE MANDATORY TOO (operator, 2026-09-12: *"the last 5 are mandatory"*).
        # An earlier draft graded them optional because each maps to one connector -- that was the
        # wrong cut. Access reviews, enterprise-app roles, Defender and Intune are IN-THE-BOX
        # product surfaces delivered over Graph: the engine ships providers for them, the scheduler
        # runs those providers, and the GUI offers them. If the permission is absent the provider
        # 403s silently -- which is precisely the failure mode this file exists to end.
        # 🪤 WHAT IS ACTUALLY OPTIONAL is the set of EXTERNAL workload connectors (Power Platform,
        # Business Central, Dataverse, Azure DevOps, Power BI). Those are not Graph app-roles at
        # all -- they are authorised inside each workload's own system -- so they never belonged in
        # this list. They live in Get-PimWorkloadConnectorRequirements, graded optional there.
        @{ role='AccessReview.Read.All';                                capability='Access reviews';                                  tier='mandatory'; connector='access-reviews' }
        @{ role='AccessReview.ReadWrite.All';                           capability='Access reviews (create the group reviews, BUG-256)'; tier='mandatory'; connector='access-reviews' }
        @{ role='AppRoleAssignment.ReadWrite.All';                      capability='Enterprise-application roles';                    tier='mandatory'; connector='entra-approle' }
        @{ role='Application.Read.All';                                 capability='Enterprise-application roles (read target app)';  tier='mandatory'; connector='entra-approle' }
        @{ role='RoleManagement.ReadWrite.Defender';                    capability='Defender XDR roles';                              tier='mandatory'; connector='defender-xdr' }
        @{ role='DeviceManagementRBAC.ReadWrite.All';                   capability='Intune roles and scope tags';                     tier='mandatory'; connector='intune' }
    )
}

function Get-PimWorkloadConnectorRequirements {
    <#
      The workload connectors and how each is AUTHORISED. All optional -- a tenant grants only the
      workloads it actually delegates (operator, 2026-09-12: *"some permissions are optional
      (connector) and rest are mandatory ... like power platform, business central"*).

      🔑 THE POINT OF THIS TABLE: only four of the ten are Graph app-roles. The rest are authorised
      in the WORKLOAD'S OWN system, and four of those expose **zero** application app-roles, so they
      cannot be granted from Entra by anyone -- verified against the live directory 2026-09-12
      (Dataverse, Azure DevOps, PowerApps/BAP and Azure Service Management all returned 0).
      Showing them in one table with their real grant path stops the recurring question "why did
      granting a Graph permission not enable Power Platform" -- it never could.
    #>
    @(
        @{ connector='entra-roles';     surface='Entra directory roles';      model='graph';    grant='Graph app-role RoleManagement.ReadWrite.Directory' }
        @{ connector='entra-approle';   surface='Enterprise-application roles'; model='graph';  grant='Graph app-roles AppRoleAssignment.ReadWrite.All + Application.Read.All' }
        @{ connector='defender-xdr';    surface='Defender XDR roles';         model='graph';    grant='Graph app-role RoleManagement.ReadWrite.Defender' }
        @{ connector='intune';          surface='Intune roles + scope tags';  model='graph';    grant='Graph app-role DeviceManagementRBAC.ReadWrite.All' }
        @{ connector='azure-rbac';      surface='Azure resource roles';       model='azure-rbac'; grant='User Access Administrator at the tenant root management group (NOT a Graph permission)' }
        @{ connector='powerbi';         surface='Power BI workspaces';        model='service-approle'; grant='Power BI Service app-role Tenant.ReadWrite.All + enable "service principals can use Power BI APIs" in the Power BI admin portal' }
        @{ connector='business-central';surface='Business Central permission sets'; model='service-approle'; grant='Dynamics 365 BC app-role Automation.ReadWrite.All, plus registering the app as a BC app user with SUPER' }
        @{ connector='power-platform';  surface='Power Platform environment roles'; model='service-registration'; grant='Register as a Power Platform management app (BAP) -- the service exposes NO application app-roles' }
        @{ connector='dataverse';       surface='Dataverse security roles';   model='service-registration'; grant='Create an application user with a security role IN EACH environment -- no application app-roles exist' }
        @{ connector='azure-devops';    surface='Azure DevOps security groups'; model='service-registration'; grant='Project Collection Administrators in the DevOps organisation -- no application app-roles exist' }
    ) | ForEach-Object {
        # tier: MANDATORY = shipped in the box over Graph/ARM and driven by a scheduled provider
        #       (Entra roles, enterprise-app roles, Defender, Intune, Azure resource roles).
        #       OPTIONAL  = an external workload authorised in its own system; a tenant enables it
        #       only if it actually delegates that workload.
        $_ + @{ tier = $(if ($_.model -in @('graph','azure-rbac')) { 'mandatory' } else { 'optional' }) }
    }
}

function New-PimIdentityRecord {
    <#
      One row of the portal's identity inventory.

      🔑 WHY THE PORTAL MUST SHOW THIS (operator, 2026-09-12: *"i also need to have all involved
      creds in the portal, so everyones knows object id + displayname + app id (if used) and the
      requried permissions"*). This session lost a long stretch to exactly the confusion this table
      removes: the engine SPN named in Key Vault held every required role, while the principal that
      actually executes -- a container MANAGED IDENTITY with a different object id -- held 9 of 17.
      Nothing in the product showed which was which, so "the SPN has the permission" and "the engine
      can do the work" looked like the same statement. They are not.

      🪤 An MI has an objectId and NO usable appId for granting; an app registration has BOTH, and
      the two ids are routinely confused when someone pastes one into a grant. So the record carries
      them separately and says which one a grant must target.

      PURE: shapes a record; the caller supplies the facts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('ManagedIdentity','Application')][string]$Kind,
        [string]$ObjectId = '',
        [string]$AppId    = '',
        [Parameter(Mandatory)][string]$Purpose,
        [bool]$IsRuntime  = $false,
        [object]$Health   = $null
    )
    [pscustomobject]@{
        name      = $Name
        kind      = $Kind
        objectId  = "$ObjectId"
        # A managed identity has no app registration to grant against -- showing an appId column
        # for one invites pasting the wrong value into a role assignment.
        appId     = $(if ($Kind -eq 'Application') { "$AppId" } else { '' })
        grantTarget = $(if ($Kind -eq 'ManagedIdentity') { 'objectId (managed identity -- has no app registration)' } else { 'appId / objectId (app registration)' })
        purpose   = $Purpose
        isRuntime = $IsRuntime
        health    = $Health
    }
}

function Get-PimPermissionHealth {
    <#
      Compare what the RUNTIME identity holds against what the code needs.

      -GrantedGraphRoles : role VALUES currently assigned to the running identity.
      -AzureRoleScopes   : scopes where it can manage Azure role assignments (empty = none).
      -IdentityName      : what to show the operator (e.g. 'ca-pim-tick').
      -GraphReadable     : $false when the granted set could NOT be read. 🪤 That is "unknown",
                           never "all present" -- reporting an unreadable state as healthy is the
                           same swallow this whole check exists to end.

      Returns @{ ok; severity; identity; missingGraph[]; brokenCapabilities[]; azureOk;
                 headline; detail; indeterminate }.
    #>
    [CmdletBinding()]
    param(
        [string[]]$GrantedGraphRoles = @(),
        [string[]]$AzureRoleScopes   = @(),
        [string]$IdentityName        = 'the engine identity',
        [bool]$GraphReadable         = $true,
        # 🔑 MAIL IS A THIRD GRANT MODEL, and it is deliberately NOT a Graph app-role.
        # `Mail.Send` is withheld on purpose (DESIGN §1359): sending is authorised by a SCOPED
        # Exchange RBAC assignment pinned to one shared mailbox, and a tenant-wide Mail.Send sitting
        # beside it would REMOVE that restriction rather than add capability -- measured against a
        # decoy mailbox. So this dimension asks two different questions: is a sender configured, and
        # does a send actually succeed. $null = not probed (unknown), which is never reported as OK.
        [string]$MailSender          = '',
        [object]$MailSendOk          = $null
    )

    $required = @(Get-PimRequiredGraphCapabilities)
    if (-not $GraphReadable) {
        return [pscustomobject]@{
            ok = $false; severity = 'warning'; indeterminate = $true
            identity = $IdentityName; missingGraph = @(); brokenCapabilities = @(); azureOk = $null
            headline = 'Permissions could not be checked'
            detail   = "The portal could not read the app-role assignments of $IdentityName, so it cannot confirm the engine has what it needs. This is NOT a clean bill of health -- it means the check itself failed."
        }
    }

    $have = @{}
    foreach ($g in @($GrantedGraphRoles)) { if ("$g".Trim()) { $have["$g".Trim()] = $true } }
    # 🔑 BUG-151 -- `altRole` is a SATISFIED-BY, not a second requirement. Microsoft documents
    # RoleManagement.ReadWrite.Directory as the higher-privileged alternative to the narrow
    # schedule pair, so an environment holding EITHER can do the work. Without this, switching a
    # tenant to least privilege (or leaving it broad) makes one of the two configurations report a
    # missing mandatory permission while working perfectly.
    $isHeld = {
        param($req)
        if ($have.ContainsKey($req.role)) { return $true }
        $alt = "$($req.altRole)".Trim()
        return ([bool]$alt -and $have.ContainsKey($alt))
    }
    $missing    = @($required | Where-Object { -not (& $isHeld $_) })
    $missingReq = @($missing | Where-Object { "$($_.tier)" -ne 'optional' })
    $missingOpt = @($missing | Where-Object { "$($_.tier)" -eq 'optional' })
    # Connectors switched off purely because a permission is absent -- named, so the reader can
    # decide whether they wanted that workload at all.
    $offConnectors = @($missingOpt | ForEach-Object { "$($_.connector)" } | Where-Object { $_ } | Sort-Object -Unique)
    $azureOk = (@($AzureRoleScopes) | Where-Object { "$_".Trim() }).Count -gt 0

    # Mail: configured AND proven. A configured sender that cannot send is not "ok" -- the whole
    # point is that TAP delivery and every notification silently stop.
    $mailConfigured = [bool]("$MailSender".Trim())
    $mailOk      = $false
    $mailUnknown = $false
    if (-not $mailConfigured) { $mailOk = $false }
    elseif ($null -eq $MailSendOk) { $mailUnknown = $true }
    else { $mailOk = [bool]$MailSendOk }

    # 🪤 OPTIONAL MUST NOT DRAG THE VERDICT RED. `ok` means "core PIM works" -- a tenant that never
    # bought Intune or Defender is HEALTHY, and saying otherwise trains people to ignore the banner.
    # The optional set is reported separately as "these workloads are off".
    $ok = ($missingReq.Count -eq 0 -and $azureOk -and $mailOk)
    # A missing Graph role stops a whole capability dead, so it is an ERROR. Azure RBAC absent is
    # equally fatal to the Azure half. Mail that is merely UNPROVEN is a warning, not an error --
    # over-stating it would train the reader to ignore this banner, which is how the next real
    # outage gets missed.
    # 🪤 UNPROVEN and PROVEN-BROKEN are different states and must not share a severity. A send that
    # was never tested is a warning (the reader is asked to press Verify); a send that was tested
    # and FAILED is an error, because TAP delivery is then known-dead. Collapsing the two would
    # either cry wolf on every fresh deploy or hide a real outage -- the first draft did the latter.
    $mailBroken = ((-not $mailConfigured) -or ($mailConfigured -and -not $mailUnknown -and -not $mailOk))
    $severity =
        if ($ok -and -not $missingOpt.Count) { 'ok' }
        elseif ($missingReq.Count -or -not $azureOk -or $mailBroken) { 'error' }
        else { 'warning' }   # core fine; an optional connector is off, or mail is unproven

    $caps = @($missingReq | ForEach-Object { $_.capability } | Sort-Object -Unique)
    $parts = @()
    if ($missingReq.Count)  { $parts += ("{0} REQUIRED Graph permission(s) missing" -f $missingReq.Count) }
    if (-not $azureOk)      { $parts += 'no Azure role-management scope' }
    if (-not $mailConfigured) { $parts += 'no mail sender configured' }
    elseif ($mailUnknown)   { $parts += 'mail not verified' }
    elseif (-not $mailOk)   { $parts += 'mail send FAILS' }

    $headline =
        if ($ok -and -not $missingOpt.Count) { 'Permissions OK' }
        elseif ($ok) { ("Core PIM OK -- {0} optional workload(s) unavailable" -f $offConnectors.Count) }
        else { ("Core functionality is BLOCKED -- " + ($parts -join ', ')) }

    $detail = if ($ok) {
        $d = "$IdentityName holds every REQUIRED permission; core PIM works."
        if ($offConnectors.Count) { $d += "  These optional workloads are unavailable until their permission is granted: " + ($offConnectors -join ', ') + "." }
        $d
    } else {
        # Say "missing permissions" only when a permission IS missing -- a mail-only problem is not a permission gap.
        $d = if ($missingReq.Count -or -not $azureOk) { "$IdentityName is missing REQUIRED permissions, so the engine CANNOT complete work it reports as scheduled." }
             else { "$IdentityName holds every required Graph and Azure permission." }
        if ($caps.Count)   { $d += "  Blocked: " + ($caps -join '; ') + "." }
        if (-not $azureOk) { $d += "  Azure resource roles cannot be assigned at any scope (needs User Access Administrator, typically at the tenant root management group)." }
        if (-not $mailConfigured) { $d += "  No sender mailbox is configured, so TAP delivery and every notification are dead." }
        elseif ($mailUnknown)     { $d += "  Mail sending has not been verified -- press Verify to test it." }
        elseif (-not $mailOk)     { $d += "  Mail sending FAILS: the scoped Exchange RBAC assignment for '$MailSender' is missing or wrong (Mail.Send is deliberately NOT granted as a Graph role)." }
        if ($offConnectors.Count) { $d += "  Separately, these optional workloads are off: " + ($offConnectors -join ', ') + "." }
        $d
    }

    $shape = { param($x) [pscustomobject]@{ role = $x.role; capability = $x.capability; tier = "$($x.tier)"; connector = "$($x.connector)" } }
    [pscustomobject]@{
        ok = $ok; severity = $severity; indeterminate = $false
        identity = $IdentityName
        missingRequired = @($missingReq | ForEach-Object { & $shape $_ })
        missingOptional = @($missingOpt | ForEach-Object { & $shape $_ })
        # kept for callers that just want "everything absent"
        missingGraph = @($missing | ForEach-Object { & $shape $_ })
        unavailableConnectors = $offConnectors
        brokenCapabilities = $caps
        azureOk = $azureOk
        mail = [pscustomobject]@{ sender = "$MailSender"; configured = $mailConfigured; ok = $mailOk; verified = (-not $mailUnknown) }
        headline = $headline
        detail = $detail
    }
}
