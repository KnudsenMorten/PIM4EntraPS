# PIM Manager -- Security review pack

**Product:** PIM Manager &nbsp;|&nbsp; **Version:** 2.4.538 &nbsp;|&nbsp; **Date:** 2026-10-09

This pack is for the CISO and the security team who must approve PIM Manager before it is installed. It describes the product and this version, not one customer's environment. Every statement was checked against the product's code for this version, not only against its design documents. Where the product does NOT yet control a risk, the pack says so and names the open item (SP-GAP-n) on the product's backlog.

## Contents

1. [Architecture](#architecture)
2. [Identities](#identities)
3. [Permissions with justification](#permissions)
4. [Data](#data)
5. [Access by the vendor](#vendor-access)
6. [Supply chain](#supply-chain)
7. [Change control and audit](#change-control)
8. [Threat model and hardening](#threat-model)
9. [Compliance mapping](#compliance)
10. [Uninstall and exit](#uninstall)
11. [Scripts](#scripts)

<a id="architecture"></a>
## 1. Architecture

PIM Manager keeps privileged access in Microsoft Entra ID and Azure in line with a desired state that your administrators manage. It runs entirely in **your own Azure subscription**, in a resource group you choose (default name `rg-pim`). Invardia does not host the product, your data or its runtime.

### Components (all in your subscription)
- **Engine job** `ca-pim-tick` -- an Azure Container Apps job on a schedule. It reads the desired state from SQL and applies it to Entra ID, PIM for Groups, Azure RBAC, Intune and Defender XDR role management through REST calls with its managed identity.
- **Manager** `ca-pim-manager` -- the web GUI (Container App). Administrators sign in with Entra ID (App Service Authentication, "Easy Auth"). Its Microsoft Graph rights are read-only; changes are queued in SQL and applied by the engine.
- **Updater job** `ca-pim-update` -- builds the new version from source inside your own container registry and rolls the Manager and jobs (chapter 6).
- **Azure SQL Database** -- the desired state, settings, audit log and commit journal. Entra-only authentication.
- **Azure Container Registry** -- holds the images built in your subscription (Premium for private network setups, Basic otherwise).
- **Log Analytics workspace** -- receives the Container Apps logs.
- **Key Vault** -- only when a feature needs a secret (SMTP relay password, emergency passphrase, MSP signing key). A plain install creates none.
- Optional: **PIM Activator** browser extension with its own app registration (chapter 2), the **access-request (RFA) broker** `ca-pim-rfa`, an **MCP endpoint** on the Manager, and a **hybrid worker** VM for on-premises Active Directory.
- MSP installs add a managing-tenant side (a signed baseline bundle published to storage, pulled by each managed tenant).

### What Invardia hosts
- invardia.com: the download of standalone setup scripts, licences, the optional update channel for Pro, and the receiver for the telemetry uplink (chapter 4). None of these is needed for the product to keep running; the engine runs without any call to Invardia.
- Invardia never hosts your directory data, your SQL database or your runtime.

### Network exposure options
- **Default:** the Container Apps environment is external. A new Manager is created closed (a deny-all ingress rule) and is opened only after Entra sign-in is configured and verified. Worker jobs have no ingress at all.
- **IP-restricted:** ingress IP allow-rules can be added; the update path keeps them.
- **Private:** an internal-only Container Apps environment and a SQL private endpoint with public network access disabled are supported install options (opt-in).
- SQL: Entra-only authentication. The default deploy creates the Azure rule "Allow Azure services"; a VNet rule or private endpoint replaces it when chosen (see SP-GAP-12).

### Data flow summary
- Engine and Manager -> Microsoft Graph / Azure Resource Manager / Defender / Power BI / Exchange Online REST: HTTPS, managed identity tokens.
- Engine and Manager -> Azure SQL: TLS (Encrypt=True, certificate validated), managed identity.
- Administrators' browsers -> Manager: HTTPS, Entra sign-in.
- Product -> invardia.com: HTTPS, outbound only (telemetry, licence, optional updates). Nothing from Invardia connects in to your environment.

<a id="identities"></a>
## 2. Identities

Every identity the product creates or uses, with its purpose and lifetime. Runtime identities are **managed identities** -- no secret or certificate to steal or rotate. The default resource names are shown; an installation may prefix them.

**Identities created or used**

| Identity | Kind | Purpose | Credential | Lifetime |
|---|---|---|---|---|
| ca-pim-tick (engine) | System-assigned managed identity of the engine job | Reads the tenant and applies the desired state | None (managed identity) | Lives as long as the job |
| ca-pim-manager (Manager) | System-assigned managed identity of the Manager app | Reads the tenant for the GUI, writes SQL, starts the engine on Run now | None (managed identity) | Lives as long as the app |
| ca-pim-update (updater) | System-assigned managed identity of the update job | Builds the new version in your registry and rolls the apps; applies schema | None (managed identity) | Lives as long as the job |
| id-pim-<token> | User-assigned managed identity | Pulls images from your registry; attached to the Manager and jobs | None (managed identity) | Kept until the resource group is removed |
| id-pim-sql-<token> | User-assigned managed identity (private SQL only) | SQL administrator for the in-cloud schema bootstrap job | None (managed identity) | Kept until removed |
| Downlink / baseline-publish / RFA broker jobs | System-assigned managed identities (MSP and access-request options only) | Pull or publish the MSP bundle; serve access requests | None (managed identity) | Lives as long as the job/app |
| Manager sign-in app registration | App registration (Easy Auth) | Entra sign-in to the Manager; app assignment required | Client secret, 2 years, stored as a Container Apps secret | Until the Manager is removed |
| Manager users group (members, no guests) | Dynamic security group (optional) | Lets all member accounts sign in, never guests | n/a | Until removed |
| Access-request API app registration | App registration (RFA option) | Token audience for the access-request broker; no API permissions | None | Until removed |
| Engine app registration (certificate) | App registration + service principal (classic deploy path only) | Engine identity for installs that do not run on managed identity | Self-signed certificate, 2 years, on the deploy host | Until removed; see SP-GAP-13 |
| Deploy app registration | App registration (optional, unattended deploys) | Runs deploys without a person signed in | Certificate on the deploy host | Until removed |
| grp-pim-sql-admins | Role-assignable security group | The SQL server's Entra administrator; members are the product's deploy/update identities | n/a | Until removed |
| PIM Activator app registration | App registration (optional) | The browser extension's sign-in; users activate their own eligible roles and groups | None (public client, PKCE) | Until removed |
| Mail sender | Shared mailbox + Exchange RBAC for Applications scope (optional) | Sends TAP codes, approvals and alerts from one mailbox | None (send right on that one mailbox) | Until removed |
| Invardia Support app | Multi-purpose vendor app registration created in YOUR tenant by Invardia's setup script | Setup and support by Invardia, with your consent (chapter 5) | Client secret (90 days for customers), held in Invardia's support Key Vault | Until you remove it |
| Hybrid worker gMSAs (optional) | Group managed service accounts in on-premises AD | Create/maintain admin accounts and groups in AD | Managed by AD | Until removed |
| Break-glass accounts | Your own emergency accounts (not created by the product) | Listed in Settings; the engine never removes, disables or revokes them | Yours | Yours |

<a id="permissions"></a>
## 3. Permissions with justification

Every permission the product grants or requires, per identity, read from the install and grant code of this version. **Optional** means the grant is made only when you choose that feature or switch. The engine needs broad write rights because managing privileged access is its job; chapter 8 explains the controls around that.

> The engine identity's Graph permissions are tier-0 equivalent: RoleManagement.ReadWrite.Directory can assign any directory role and AppRoleAssignment.ReadWrite.All can grant any application permission. Treat the engine identity as a tier-0 asset (SP-GAP-1).

### Least-privilege choices made in code
- The Manager's Graph rights are **read-only**; writes are queued and applied by the engine.
- **Mail.Send is never granted tenant-wide** to the engine or Manager; mail uses Exchange RBAC for Applications scoped to ONE mailbox, and the mail setup removes a tenant-wide Mail.Send if it finds one.
- Exchange Administrator for mail setup is **activated time-bound through PIM** (default 4 hours), not assigned permanently.
- User Access Administrator at the tenant root is **opt-in**; the default is Reader.
- Workload identities may only be given Reader, User Access Administrator or Role Based Access Control Administrator by the reachability planner; Owner and Contributor are refused there.
- The baseline-publish job has no fixed SQL role: SELECT on named objects only, and db_owner / db_datawriter / db_ddladmin / db_datareader are revoked.
- Storage keys are disabled where the product creates storage; access is Azure RBAC.

### Least-privilege gaps (honest)
- AccessReview.ReadWrite.All is broader than the access-review provider needs; no narrower Graph permission exists.
- The Manager has db_datawriter and db_ddladmin in SQL like the engine (SP-GAP-7).
- The registry pull identity is also a member of the SQL admin group, and the updater holds Contributor on the resource group (SP-GAP-7).
- The deploy app registration is subscription Owner by default and, with -GrantGraph, holds RoleManagement.ReadWrite.Directory (SP-GAP-13).
- The standalone Grant-PimEnginePermissions script grants whatever role and scope it is given; it has no allow-list (SP-GAP-13).

**Permission table (per identity)**

| Identity | Type | Permission | Scope | Why it is needed | What breaks without it | Optional |
|---|---|---|---|---|---|---|
| Engine (ca-pim-tick) | Graph application | Directory.Read.All | Tenant | Read users, groups, roles and directory objects to compare with the desired state | Everything -- the engine cannot read the tenant | No |
| Engine (ca-pim-tick) | Graph application | User.ReadWrite.All | Tenant | Create and maintain the dedicated admin accounts | Admin account lifecycle (create, update, disable) | No |
| Engine (ca-pim-tick) | Graph application | Group.ReadWrite.All | Tenant | Create and maintain PIM groups and their membership | Group-based delegation | No |
| Engine (ca-pim-tick) | Graph application | RoleManagement.ReadWrite.Directory | Tenant | Create role-assignable groups and assign directory roles to them | Role-assignable groups and Entra role delegation | No |
| Engine (ca-pim-tick) | Graph application | RoleManagement.Read.All | Tenant | Read role definitions and assignments | Role reporting and drift detection | No |
| Engine (ca-pim-tick) | Graph application | RoleEligibilitySchedule.ReadWrite.Directory | Tenant | Create eligible Entra role assignments | Eligible Entra role delegation | No |
| Engine (ca-pim-tick) | Graph application | RoleEligibilitySchedule.Remove.Directory | Tenant | Remove eligible Entra role assignments on revoke | Revoke of Entra role eligibility | No |
| Engine (ca-pim-tick) | Graph application | RoleAssignmentSchedule.ReadWrite.Directory | Tenant | Create active (time-bound) Entra role assignments | Active role assignments | No |
| Engine (ca-pim-tick) | Graph application | RoleAssignmentSchedule.Remove.Directory | Tenant | Remove active Entra role assignments on revoke | Revoke of active roles | No |
| Engine (ca-pim-tick) | Graph application | RoleManagementPolicy.Read.Directory | Tenant | Read Entra role PIM policies | Policy drift reporting | No |
| Engine (ca-pim-tick) | Graph application | RoleManagementPolicy.ReadWrite.Directory | Tenant | Apply Entra role PIM policies (approval, MFA, duration) | PIM policy management for Entra roles | No |
| Engine (ca-pim-tick) | Graph application | RoleManagementPolicy.Read.AzureADGroup | Tenant | Read PIM-for-Groups policies | Group policy reporting | No |
| Engine (ca-pim-tick) | Graph application | RoleManagementPolicy.ReadWrite.AzureADGroup | Tenant | Apply PIM-for-Groups policies | PIM policy management for groups | No |
| Engine (ca-pim-tick) | Graph application | PrivilegedAccess.ReadWrite.AzureADGroup | Tenant | Manage PIM for Groups | PIM-for-Groups delegation | No |
| Engine (ca-pim-tick) | Graph application | PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup | Tenant | Create eligible group memberships | Eligible group membership | No |
| Engine (ca-pim-tick) | Graph application | PrivilegedEligibilitySchedule.Remove.AzureADGroup | Tenant | Remove eligible group memberships on revoke | Revoke of group eligibility | No |
| Engine (ca-pim-tick) | Graph application | PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup | Tenant | Create active group memberships | Active group membership | No |
| Engine (ca-pim-tick) | Graph application | PrivilegedAssignmentSchedule.Remove.AzureADGroup | Tenant | Remove active group memberships on revoke | Revoke of group membership | No |
| Engine (ca-pim-tick) | Graph application | AdministrativeUnit.ReadWrite.All | Tenant | Create and use administrative units as delegation scopes | AU-scoped delegation | No |
| Engine (ca-pim-tick) | Graph application | AppRoleAssignment.ReadWrite.All | Tenant | Manage application role assignments (Entra app-role provider) | App-role delegation | No |
| Engine (ca-pim-tick) | Graph application | Application.Read.All | Tenant | Resolve applications and service principals | App-role provider, reporting | No |
| Engine (ca-pim-tick) | Graph application | UserAuthenticationMethod.ReadWrite.All | Tenant | Issue a Temporary Access Pass to a new admin account | Onboarding of new admin accounts (TAP) | No |
| Engine (ca-pim-tick) | Graph application | AccessReview.Read.All | Tenant | Read access reviews | Access review reporting | No |
| Engine (ca-pim-tick) | Graph application | AccessReview.ReadWrite.All | Tenant | Create and run access reviews (broader than needed; no narrower permission exists) | Access reviews | No |
| Engine (ca-pim-tick) | Graph application | RoleManagement.ReadWrite.Defender | Tenant (Defender XDR) | Manage Defender XDR (unified RBAC) roles | Defender XDR provider | No (used only when Defender is managed) |
| Engine (ca-pim-tick) | Graph application | DeviceManagementRBAC.ReadWrite.All | Tenant (Intune) | Manage Intune RBAC roles | Intune provider | No (used only when Intune is managed) |
| Engine (ca-pim-tick) | Graph application | Domain.Read.All | Tenant | Read verified domains for admin account naming | Admin naming | No |
| Engine (ca-pim-tick) | Graph application | Policy.Read.All | Tenant | Read authentication and authorization policies used in checks | Policy checks | No |
| Engine (ca-pim-tick) | Azure RBAC | Reader | Tenant root management group | Discovery of management groups and subscriptions; Azure RBAC reporting | Azure discovery and reporting | Default on; can be skipped |
| Engine (ca-pim-tick) | Azure RBAC | Reader | The hosting subscription (and optionally a management group) | Read Azure resources and role assignments | Azure reporting | Default on; can be skipped |
| Engine (ca-pim-tick) | Azure RBAC | User Access Administrator | Tenant root management group, or the delegated scopes | Write Azure role assignments and PIM for Azure resources | Azure RBAC delegation (read-only without it) | Yes (opt-in switch) |
| Engine (ca-pim-tick) | Azure RBAC | Reader | The ca-pim-tick job resource | Read its own execution status | Run status in the GUI | No |
| Engine (ca-pim-tick) | Azure RBAC | Storage Table Data Contributor | The access-request storage account | Store access-request state | Access requests (RFA) | Yes (RFA option) |
| Engine (ca-pim-tick) | Azure RBAC (custom role) | Microsoft.Storage/storageAccounts/read + write | The one MSP bundle storage account | Maintain the bundle store's network rules (MSP managing tenant, public-signed mode) | MSP bundle publication | Yes (MSP only) |
| Engine (ca-pim-tick) | SQL | db_datareader, db_datawriter, db_ddladmin | The PIM database | Read and write the desired state, audit and journal; apply schema changes | Everything | No |
| Engine (ca-pim-tick) | Exchange RBAC for Applications | Application Mail.Send | A management scope containing ONE sender mailbox | Send TAP codes, approvals and alerts | Mail (the GUI shows codes instead) | Yes (mail option) |
| Engine (ca-pim-tick) | Key Vault RBAC | Key Vault Secrets User | The one SMTP relay secret | Read the SMTP relay password | Mail through an SMTP relay | Yes (SMTP option) |
| Engine (ca-pim-tick) | Other | Member of a Power BI security group + the Fabric tenant setting for read-only admin APIs | Power BI / Fabric | Read Power BI workspaces for discovery | Power BI provider | Yes (Power BI workload) |
| Manager (ca-pim-manager) | Graph application (read-only) | Directory.Read.All, Domain.Read.All, User.Read.All, Group.Read.All, AdministrativeUnit.Read.All, Application.Read.All, AccessReview.Read.All, RoleManagement.Read.All, RoleManagementPolicy.Read.Directory, RoleManagementPolicy.Read.AzureADGroup, RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory, PrivilegedAccess.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup | Tenant | Show the tenant in the GUI (pickers, reports, live state) | GUI views and pickers | No |
| Manager (ca-pim-manager) | Azure RBAC | Reader | The hosting subscription | Show Azure scopes and roles | Azure views | No |
| Manager (ca-pim-manager) | Azure RBAC | Container Apps Jobs Operator | The ca-pim-tick job only | Start the engine on Run now / commit | Run now (the engine still runs on its schedule) | Default on; can be skipped |
| Manager (ca-pim-manager) | Azure RBAC | AcrPull | Your container registry (legacy path; normally the pull identity) | Pull its image | Start-up | No |
| Manager (ca-pim-manager) | SQL | db_datareader, db_datawriter, db_ddladmin | The PIM database | Read and stage changes, settings and audit | GUI | No |
| Manager (ca-pim-manager) | Key Vault RBAC | Key Vault Secrets User | The one emergency-passphrase secret | Emergency sign-in check | Emergency access | Yes |
| Manager (ca-pim-manager) | Exchange RBAC for Applications | Application Mail.Send | The one sender mailbox scope | Send mail from the GUI (test mail, approvals) | GUI mail | Yes (mail option) |
| Updater (ca-pim-update) | Azure RBAC | Contributor | The environment's resource group (and the registry when it is in another group) | Update container apps and jobs; schedule image builds | Updates | Can be skipped (then updates are manual) |
| Updater (ca-pim-update) | Azure RBAC | AcrPull | Your container registry | Pull built images | Updates | No |
| Updater (ca-pim-update) | SQL | Member of grp-pim-sql-admins (fallback: db_datareader, db_datawriter, db_ddladmin) | The SQL server | Apply schema changes during an update | Schema updates | No |
| Pull identity (id-pim-<token>) | Azure RBAC | AcrPull | Your container registry | Pull images for the Manager and jobs | Start-up | No |
| Pull identity (id-pim-<token>) | SQL | Member of grp-pim-sql-admins | The SQL server | Schema bootstrap (see SP-GAP-7) | Bootstrap | No |
| SQL bootstrap identity (id-pim-sql-<token>) | SQL | SQL Entra administrator (or group member) | The SQL server (private SQL only) | Create the database users from inside the private network | Private SQL installs | Yes (private SQL) |
| grp-pim-sql-admins | SQL | SQL server Entra administrator | The SQL server | One managed group instead of a person as SQL admin | Schema changes, recovery | No |
| Downlink job (MSP managed tenant) | Graph application | The engine permission set above | The managed tenant | Apply the bundle pulled from the managing tenant | MSP managed tenant | Yes (MSP only) |
| Downlink job (MSP managed tenant) | Azure RBAC + SQL | AcrPull; member of grp-pim-sql-admins (fallback: the three db roles) | Registry; SQL server | Pull image; write the store | MSP managed tenant | Yes (MSP only) |
| Baseline-publish job (MSP managing tenant) | Azure RBAC | Storage Blob Data Contributor | The bundle container only | Publish the signed bundle | MSP publication | Yes (MSP only) |
| Baseline-publish job (MSP managing tenant) | Key Vault RBAC | Key Vault Crypto User | The signing key only (sign/verify) | Sign the bundle with a non-exportable key | MSP publication | Yes (MSP only) |
| Baseline-publish job (MSP managing tenant) | SQL | SELECT on named objects; INSERT/UPDATE on its own last-run view; all fixed db roles revoked | The PIM database | Read the central admin set | MSP publication | Yes (MSP only) |
| RFA broker (ca-pim-rfa) | Azure RBAC | Storage Table Data Contributor | The access-request storage account (shared keys disabled) | Store access requests | Access requests | Yes (RFA option) |
| RFA broker (ca-pim-rfa) | Exchange RBAC for Applications | Application Mail.Send | The one sender mailbox scope | Mail access-request decisions | RFA mail | Yes |
| Manager sign-in app registration | Graph delegated | openid, profile, email, offline_access, User.Read (admin-consented) | Signed-in user only | Sign the administrator in | Sign-in | No |
| Manager sign-in app registration | Delegated scope (MCP option) | mcp.access (Azure CLI pre-authorised) | Signed-in user, bounded by the Manager role | MCP clients call the Manager as the user | MCP endpoint | Yes (MCP, Pro) |
| PIM Activator app registration | Graph delegated | PrivilegedAccess.ReadWrite.AzureADGroup, Group.Read.All, User.Read, RoleManagement.Read.Directory, RoleManagement.ReadWrite.Directory, AdministrativeUnit.Read.All, Application.Read.All; Azure Service Management user_impersonation | Signed-in user only -- bounded by that user's own eligibility | Users activate and deactivate their OWN eligible groups and roles | Activation from the extension | Yes (Activator option); tenant-wide admin consent by default |
| Deploy app registration (optional) | Azure RBAC | Owner (optional: Network Contributor on a hub VNet) | The hosting subscription | Unattended deploys (resources and role assignments) | Unattended deploys | Yes |
| Deploy app registration (optional) | Graph application | Directory.Read.All, AppRoleAssignment.ReadWrite.All, Application.Read.All, Group.Create, GroupMember.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, RoleManagement.ReadWrite.Directory | Tenant | Grant the runtime identities and create the product's groups without a person | Unattended deploys | Yes (-GrantGraph) |
| Deploy app registration (optional) | Key Vault RBAC | Key Vault Reader on the MSP signing key (not granted when it already holds Key Vault Crypto User, Key Vault Crypto Officer or Key Vault Administrator there); may self-grant Key Vault Secrets Officer on the vault it writes | One key / one vault | Read the signing key's public part; write the SMTP secret | MSP build, SMTP setup | Yes |
| Engine app registration (classic path) | Graph application | The engine permission set above | Tenant | Engine identity where managed identity is not used | That install type | Yes (see SP-GAP-13) |
| Engine app registration (classic path) | Exchange | Exchange.ManageAsApp (standing) + Exchange Administrator activated time-bound through PIM | Tenant | Mail sender setup by the engine identity | That mail setup path | Yes (-IncludeExchange) |
| Engine app registration (classic path) | SQL | db_datareader, db_datawriter, db_ddladmin (db_owner and dbmanager revoked) | The PIM database | Engine store access | That install type | Yes |
| Engine app registration (classic path) | Azure RBAC | User Access Administrator (optional); Storage Blob Data Contributor (legacy MSP host publisher) | Tenant root; bundle storage account | Azure delegation; legacy bundle publish | Those options | Yes |
| Setup admin app (mail setup, optional) | Exchange + Entra role | Exchange.ManageAsApp (standing), RoleManagement.ReadWrite.Directory, Exchange Administrator activated time-bound through PIM (default 4 h) | Tenant | Create the shared mailbox and its scoped send right without a person | Unattended mail setup | Yes (browser sign-in needs none of these) |
| Person running the setup scripts | Graph delegated + Azure | AppRoleAssignment.ReadWrite.All, Application.Read.All (Grant-PimEnginePermissions); Azure user_impersonation | Signed-in person only | Grant the engine its missing rights | That script | n/a (chapter 11 lists rights per script) |
| Hybrid worker VM identity | Graph application | Group.Read.All, User.Read.All, PrivilegedAssignmentSchedule.Read.AzureADGroup (optional: Mail.Send tenant-wide, see SP-GAP-13) | Tenant | Read which admins need AD accounts | Hybrid AD | Yes (hybrid worker) |
| Hybrid worker VM identity | Azure RBAC + SQL | Storage Blob Data Reader on the source container; db_datareader, db_datawriter (never db_ddladmin) | One container; the PIM database | Fetch the worker code; record results | Hybrid AD | Yes |
| Hybrid worker gMSA (AD) | AD delegation | Create/modify groups in the groups OU; create users + full control on users in the admin-accounts OU; optional: AdminSDHolder member write (tier 0) | The OUs you name | Create and maintain admin accounts and groups on-premises | Hybrid AD | Yes |
| Hybrid worker server gMSA (AD) | AD / GPO | Local Administrators on servers in the server OU (Restricted Groups GPO) | The server OU you name | Just-in-time server admin access | Server JIT | Yes |
| Invardia Support app (troubleshoot level) | SQL | db_datareader + VIEW DEFINITION (db_datawriter, db_ddladmin, db_owner revoked) | The PIM database | Read the store when you ask for support | Remote troubleshooting | Yes (your choice) |
| Invardia Support app (setup level) | SQL + Entra | Member of grp-pim-sql-admins; owner of the SQL admin group, the Manager sign-in app, the access-request app and the Manager users group | SQL server; those objects | Install and repair on your behalf | Assisted setup | Yes (your choice) |
| Invardia Support app (tenant rights) | Graph + Azure RBAC | Granted by Invardia's own setup script, not by PIM Manager -- see chapter 5 | As listed there | Vendor setup and support | Assisted setup / support | Yes (your choice) |

<a id="data"></a>
## 4. Data

### Data read from your tenant
- Users (names, UPN, mail, enabled state, last sign-in time), groups, owners and members, Entra roles and PIM schedules and policies, administrative units, domains, subscribed SKUs, applications and service principals, access reviews.
- Azure management groups, subscriptions, role definitions, role assignments and PIM-for-Azure schedules (Azure Resource Graph).
- Intune and Defender XDR role definitions and assignments; Power BI workspaces (when those workloads are managed).
- Authentication methods of the admin accounts it manages (to issue a Temporary Access Pass).
- On-premises AD users and groups (hybrid worker only).
- **Not read:** sign-in logs, audit logs, risky users, Conditional Access policies, mailbox content, files.

### Data stored (your Azure SQL database, in your subscription)
- Desired state and definitions (admins, groups, roles, departments, workloads) -- includes admin names, UPNs and manager e-mail addresses.
- Settings, a tenant cache of what was read, the managed-object ledger (what the engine owns).
- The change queue and approvals.
- **Audit log** (`pim.AuditEvents`: who, what, before, after) and **commit journal** (`pim.CommitJournal`: before/after of every commit, initiator, approver) -- both append-only by trigger.
- Configuration backups and pre-commit snapshots.
- MSP managing tenants: a registry of managed tenants (app ids and certificate thumbprints only, secrets as Key Vault pointers).
- **Not stored:** TAP codes and generated passwords (shown once, never written). API keys are stored as SHA-256 hashes only. The SMTP password and emergency passphrase are in Key Vault, not SQL.

### Retention
- `AuditRetentionMonths` -- default 0 = keep forever; when set, 13 to 1200 months (1-12 refused); a daily job purges and the purge itself is audited.
- Configuration backups -- `ConfigBackupRetentionDays` default 90 (1-3650); pinned and newest kept.
- Pre-commit snapshots -- 10 per entity. Job run history -- 10 per job.
- The commit journal, applied-commit log and change queue are never purged today (SP-GAP-10).
- Log Analytics keeps the workspace default retention (30 days) unless you change it.

### Data sent to Invardia
All outbound, HTTPS, to invardia.com. Nothing is sent about users, groups or roles by design; the exact fields are below.
- **Telemetry uplink** (hourly; feature gate `telemetry.uplink`, **on by default**, switch off in Settings > Features; switching off sends one final opt-out record and then nothing). Two modes: **anonymous** (no licence install key: a random install id, bucketed counts, no tenant, host or text) and **identified** (with an install key: adds tenant id, host name and redacted error text). The redaction removes tokens, keys, SAS signatures and PEM blocks; it does **not** remove e-mail addresses, UPNs or object names that can appear in an error message (SP-GAP-9).
- **Licence request** (every 30 minutes until a licence is installed; gate `licence.autoRequest`, on by default): product, version, tenant id, install id, current licence id and expiry. No contact details.
- **Install-key claim and update manifest** (Pro, gate `updates.invardia`): product, tenant id, licence, ring.
- **Install tracking** (only when an install is started from an Invardia install token): the step names and outcomes.
- Licence validation itself is offline: a signature check with no network call.

### Encryption and residency
- **At rest:** Azure SQL Transparent Data Encryption with service-managed keys (Azure default; the product does not configure customer-managed keys). Key Vault for secrets.
- **In transit:** HTTPS to every API; SQL connections with Encrypt=True and certificate validation. The SQL server's minimum TLS version is the Azure default; the product does not set it explicitly (SP-GAP-12).
- **Residency:** every resource is created in your subscription in the region you choose. The installer's region list is West Europe, Sweden Central and Denmark East. Invardia receives only the uplink fields above.

### Deletion on uninstall
See chapter 10. Your SQL database (and so all stored data) remains until you delete the resource group or the database.

**Telemetry uplink -- exact fields**

| Record | Fields | Mode |
|---|---|---|
| Every record | Schema, Kind, Product (pim-manager), Version, Ring, LastSeenUtc | Both |
| Heartbeat (daily) | Edition (community / pro / trial), Hosting (container), RuntimeIdentity (managed identity / certificate), LicenceState | Both |
| Run report (per job, per cycle) | Job name, Outcome, DurationMs, ErrorClass, run count | Both |
| Guard record | GuardId, GuardOutcome, Severity, Area, Job, measured and threshold numbers, HeldCount, TripCount, FirstSeenUtc | Both |
| Anonymous mode adds | InstallId (random, stored in settings); counts bucketed | Anonymous |
| Identified mode adds | ClaimedTenantId, Host, ErrorText (redacted, up to 8000 characters), raw counts; guard ActionText (500 characters) and Link | Identified |
| Opt-out | One final optout record, then nothing | Both |

<a id="vendor-access"></a>
## 5. Access by the vendor

Invardia has **no standing access** to a PIM Manager environment unless you create the **Invardia Support app** in your tenant. You decide whether it exists, at which level, and for how long.

### What the Support app can do
The app's tenant rights are created by Invardia's own setup script (published at invardia.com/support), not by PIM Manager. In that script today:
- **Troubleshoot level:** read-only Graph (directory, applications, users, groups, roles, PIM policies and schedules, PIM for Groups read) plus Application.ReadWrite.OwnedBy (to renew its own secret); Azure Reader and Log Analytics Reader on the resource groups you name; Key Vault Reader.
- **Setup level:** adds Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, Group.Create and RoleManagement.ReadWrite.Directory in Graph, and Contributor + User Access Administrator on the subscriptions you name (optionally at the tenant root), Key Vault Secrets Officer, Network Contributor on a hub VNet. **Setup level is tier-0 equivalent** -- grant it for an install or repair, then lower it.
- PIM Manager's own grant script (`Grant-PimSupportAccess.ps1`) adds, at troubleshoot level, a read-only SQL user (db_datareader + VIEW DEFINITION); at setup level, membership of the SQL admin group and ownership of the product's sign-in app, access-request app, SQL admin group and users group.

### Credential and conditions
- The Support app uses a **client secret** (this is the only identity in the product allowed one, and only for setup and support, never for the runtime). For customers it expires after 90 days; old secrets are removed when a new one is made. Invardia keeps it in its support Key Vault.
- Invardia's sign-in tool checks that the token's tenant and app match the environment, refuses a production environment without an explicit production switch, and stops when you have disabled the environment.
- An optional Conditional Access policy can restrict the app to Invardia's support IP address; it is created **disabled** and needs Workload Identities Premium (SP-GAP-11).

### How you remove it
1. `Grant-PimSupportAccess.ps1 -Remove` -- takes back the SQL user, the SQL admin group membership and the ownerships.
2. Invardia's `New-InvardiaSupportApp.ps1 -Action Disable` (sign-in blocked, grants kept) or `-Action Remove` (deletes the app, its Azure roles and the Conditional Access policy).
3. Or simply delete the app registration / service principal in Entra ID.

### Audit trail
- What the Support app does is visible in **your** Entra sign-in and audit logs and the Azure Activity Log.
- PIM Manager's own audit log does **not** record actions the Support app makes directly against Graph, Azure or SQL, and the Review active assignments page hides the Support app's own assignments by default (a tick box shows them) (SP-GAP-11).

<a id="supply-chain"></a>
## 6. Supply chain

### How code reaches your environment
- The updater job `ca-pim-update` **builds the product from source inside your own container registry** and rolls the Manager and jobs. No pre-built vendor image is pulled.
- **Invardia update channel (Pro):** the update manifest is signed (RS256, RSA 4096) and verified against a public key embedded in the product -- never fetched at run time. The manifest must name your ring, a version, a SHA-256, a size and a sequence number (replays are refused); the download must be HTTPS; the archive's SHA-256 and size are checked before unpacking, and the version inside must match the manifest.
- **Source-archive channel (default for self-hosted updates):** the archive is fetched from a storage container the update job is configured with. Today this path checks only the archive's format, **not a signature or hash**, and its ring file is unsigned (SP-GAP-2).
- **Community edition:** updated from the public source repository; no signature check of the release tag (SP-GAP-2).
- **Licences:** signed (RSA-SHA256) and verified offline against embedded public certificates, both before storing and after reading back.

### Rings, who releases, and your control
- Rings 0-3. Customers are on ring 2 by default. Ring 2 is never advanced automatically.
- A release is built only from a tagged source version and published by a dedicated publisher identity; ring 2 releases require the release owner's written approval in the publish step (a recorded text, not a cryptographic second signature).
- **Invardia holds the update-signing key.** Your controls: `PIM_UPDATE_HOLD=1` freezes the environment at its version; downgrades are refused unless you allow them; a minimum-from version prevents skipping a required step; updates run on a schedule you can change (default 03:00 UTC daily); the update job can be removed for fully manual updates.

### Source availability
- The source is published in a public GitHub repository (linked from invardia.com), so the code you run can be read and compared with what is built. The licence is open core (Community free; Pro under a commercial licence).

### Dependency policy
- **No PowerShell modules** at runtime: the engine, Manager, updater and the published setup scripts use REST and .NET only, with browser sign-in.
- The container base images are pinned by digest; the container runs as a non-root user.
- One NuGet package (Microsoft.Data.SqlClient) is pinned by version but not by hash (SP-GAP-2).
- Exceptions, outside the runtime: the on-premises hybrid worker uses the Windows ActiveDirectory and GroupPolicy modules (RSAT) on your domain host; some local-only operator modes of the Manager can use Microsoft Graph / Az modules when already installed.

<a id="change-control"></a>
## 7. Change control and audit

### Every change is staged, then committed
- Changes made in the Manager are **staged** and only reach the tenant when **committed**. The engine applies only what is defined in the database: an object the product does not own is reported, never removed (the managed-object ledger). An unreadable ledger prunes nothing.
- **Commit journal:** every commit records before and after, who initiated it and who approved it, in the same transaction as the change -- if the journal row fails, the change fails. Append-only by trigger.
- **Undo:** a commit can be undone by planning its inverse and committing it through the same gates (SuperAdmin: any commit; Admin: their own).
- **Backup and restore:** a snapshot before every apply; configuration backups on a schedule; an environment backup can be imported with a plan first and the engine paused, never overwriting what exists.

### Approvals
- **Maker/checker (Pro, off by default):** changes classified as sensitive (privileged roles, Tier 0/1, guests, offboarding) need a second approver; self-approval is refused unless the setting that allows it is switched on (SP-GAP-5).
- **Always on:** changing the break-glass list needs a second SuperAdmin, with no self-approve switch.

### Guards (always on)
- Never disable accounts when the desired admin set is empty or could not be read; account disable is opt-in.
- **Mass-disable breaker:** default 5 accounts or 10 %, hard ceilings 50 and 25 %.
- **Removal budget per scope:** default 5, hard ceiling 5; a trip drops the whole removal set for that run.
- A guard can be released only by a SuperAdmin, bound to the exact plan, for one run or at most 24 hours, and the release is audited. The break-glass exclusion, account deletion and objects the product does not own can never be released. The product never deletes a user account.
- Every guard trip is mailed, audited and reported.
- **Break-glass accounts** in Settings are never removed, disabled or revoked; if the list cannot be read, every account is treated as protected.
- The engine has a dry-run (-WhatIf) mode; scheduled jobs can be paused one by one or all at once.

### Manager roles
- None, Reader, Delegated, Admin, SuperAdmin. Hosted with no authenticated principal = no access (401). The access model refuses to be left without a SuperAdmin.

### Audit
- `pim.AuditEvents` records actor, source, action, target, before, after and dry-run flag; append-only by trigger; purged only by the retention job (minimum 13 months; default keep forever).
- Logs of the Container Apps go to the Log Analytics workspace in your subscription.
- Limits: SQL principals with db_ddladmin (the runtime identities) or SQL admin can drop the append-only triggers, and a direct SQL write bypasses the journal (SP-GAP-6). Azure SQL auditing and diagnostic settings are not configured by the installer (SP-GAP-12).

<a id="threat-model"></a>
## 8. Threat model and hardening

The top risks for a privileged-access product, the control that exists in this version, and what is not yet controlled. Each gap is an open item on the product backlog.

**Threats and controls**

| Threat | Control in this version | Not controlled today (backlog id) |
|---|---|---|
| Privilege escalation through the engine identity (it can assign any directory role and grant any app permission) | Managed identity (no credential to steal); Manager is read-only in Graph; engine applies only DB-defined objects; guards; break-glass protection; every change audited and journaled | No hard refusal to assign the most privileged roles (e.g. Global Administrator) -- they are only classified sensitive (SP-GAP-1) |
| Compromised Manager administrator | Entra sign-in with app assignment required, no guests by default; roles Reader/Admin/SuperAdmin; staged commits; guards; audit and journal; undo | MFA is not enforced by the product (it relies on your Conditional Access); signed-token verification is opt-in; maker/checker is Pro and off by default (SP-GAP-5) |
| Update tampering | Invardia channel: signed manifest, embedded key, hash + size + version + ring + replay checks; builds in your registry; HOLD; no automatic ring-2 advance | Source-archive channel, its ring file and the Community git update are not signature-checked; the hybrid worker's source download is not hash-checked (SP-GAP-2) |
| Script tampering (a privileged person runs a modified setup script) | Scripts are single self-contained files with a published SHA256SUMS.txt; no pipe-to-execute in the product; no second-stage code download | Scripts are not Authenticode-signed; the GUI commands show no verify step; one command downloads and runs on one line (SP-GAP-3) |
| Vendor (Invardia) access misuse or compromise | No standing access; the Support app is yours to create, lower and remove; secret expiry; tenant/app/production checks in Invardia's sign-in tool | Setup level is tier-0 equivalent; Conditional Access lock off by default; actions not in PIM's audit (SP-GAP-11) |
| Tampering with the audit trail | Append-only triggers on the audit log and journal; retention minimum 13 months | Runtime identities hold db_ddladmin and can drop the triggers (SP-GAP-6) |
| Lateral movement between product identities | Separate identities per component; Manager read-only in Graph; publish job without fixed SQL roles | Pull identity is SQL admin; updater is resource-group Contributor; Manager holds db_ddladmin; an engine secret, if used, also reaches the Manager (SP-GAP-7) |
| Data leaving the tenant | No directory data in telemetry by design; anonymous mode without an install key; opt-out | Identified-mode error text is not stripped of names/UPNs; the licence request sends the tenant id on by default (SP-GAP-9) |
| Network exposure | Manager created closed until Entra sign-in is verified; workers have no ingress; Entra-only SQL; private options | Default is public ingress and the SQL 'Allow Azure services' rule; no explicit SQL minimum TLS (SP-GAP-12) |
| Secrets at rest | Managed identities everywhere at runtime; Key Vault for secrets; API keys hashed | Install key and licence pull token stored in settings in plain text (TDE only); emergency passphrase stored as unsalted SHA-256; vaults without purge protection (SP-GAP-8) |

**Hardening checklist you can apply**

| # | Action | Why |
|---|---|---|
| 1 | List your break-glass accounts in Settings (Get Started step) -- the list is empty until you do | The engine then never touches them |
| 2 | Require MFA and compliant devices for the Manager sign-in app with Conditional Access | The product does not enforce MFA itself |
| 3 | Turn on signed-token verification for the hosted Manager (PIM_HOSTED_REQUIRE_SIGNED_TOKEN) | Defence in depth on the sign-in headers |
| 4 | Enable maker/checker (Pro) and keep self-approval off | A second person for sensitive changes |
| 5 | Use the private network options: internal Container Apps environment and SQL private endpoint; or add IP allow-rules | Removes public exposure and the 'Allow Azure services' SQL rule |
| 6 | Set the SQL server's minimum TLS to 1.2 and enable Azure SQL auditing to your workspace | Not configured by the installer |
| 7 | Keep User Access Administrator at the tenant root off unless you manage Azure RBAC with the product | Least privilege |
| 8 | Grant the Invardia Support app only when needed, at troubleshoot level, and remove it afterwards; enable its Conditional Access lock | Vendor access only on demand |
| 9 | Monitor the engine and Manager managed identities with Entra workload identity alerts; treat them as tier 0 | They hold tier-0-equivalent rights |
| 10 | Set AuditRetentionMonths to your policy and Log Analytics retention to match | Defaults keep the audit forever and logs 30 days |
| 11 | Decide on telemetry: keep anonymous, use identified for Pro support, or switch telemetry.uplink off | Data leaving the tenant |
| 12 | Before running any setup script: save it, compare Get-FileHash with SHA256SUMS.txt, read it, then run it | Scripts are not yet signed |
| 13 | Use PIM_UPDATE_HOLD for change windows; review release notes before lifting it | You control when code changes |

<a id="compliance"></a>
## 9. Compliance mapping

How PIM Manager's controls can **support** your own controls. This is not a certification and does not make your organisation compliant; you remain responsible for your controls and their evidence.

**Mapping (supports the customer's control)**

| Framework | Control | How PIM Manager supports it |
|---|---|---|
| ISO/IEC 27001:2022 Annex A | 5.15 Access control / 5.18 Access rights | Desired-state delegation through groups and PIM, reviewed and applied consistently; drift reported |
| ISO/IEC 27001:2022 Annex A | 8.2 Privileged access rights | Dedicated admin accounts, eligible (just-in-time) roles, PIM policies with approval and duration |
| ISO/IEC 27001:2022 Annex A | 5.16 Identity management / 5.11 Return of assets (access) | Admin account lifecycle, auto-disable date, offboarding removes memberships and eligibilities |
| ISO/IEC 27001:2022 Annex A | 5.17 Authentication information | Temporary Access Pass onboarding; no passwords stored |
| ISO/IEC 27001:2022 Annex A | 8.15 Logging / 8.16 Monitoring | Append-only audit log and commit journal in your SQL; container logs in your workspace; guard alerts |
| ISO/IEC 27001:2022 Annex A | 8.32 Change management | Staged commits, maker/checker (Pro), undo, snapshots, release rings and update hold |
| ISO/IEC 27001:2022 Annex A | 5.19-5.22 Supplier relationships | No standing vendor access; Support app under your control; this pack |
| NIS2 (Article 21) | 21(2)(i) Access control policies and asset management | Least-privilege, just-in-time delegation managed as desired state |
| NIS2 (Article 21) | 21(2)(j) Multi-factor authentication | PIM policies can require MFA on activation; the Manager relies on your Conditional Access |
| NIS2 (Article 21) | 21(2)(d) Supply chain security | Builds from source in your registry; signed Pro updates; ring control; this pack |
| NIS2 (Article 21) | 21(2)(f) Effectiveness assessment | Access reviews, drift and coverage reports, audit export |
| CIS Critical Security Controls v8 | 5.4 Restrict administrator privileges to dedicated admin accounts | Dedicated admin accounts per person |
| CIS Critical Security Controls v8 | 6.1-6.2 Establish access granting and revoking processes | Commit-based grant and revoke with audit |
| CIS Critical Security Controls v8 | 6.8 Define and maintain role-based access control | Role and department definitions applied by the engine |
| CIS Critical Security Controls v8 | 5.3 Disable dormant accounts | Inactivity sweep (guarded, opt-in disable) |
| CIS Critical Security Controls v8 | 8.2 Collect audit logs | Audit log and journal |

<a id="uninstall"></a>
## 10. Uninstall and exit

### Removing the product
- **Fastest complete removal of the Azure side:** delete the resource group the product was installed in. That removes the Container Apps, jobs, SQL server and database (all stored data), registry, Log Analytics workspace, Key Vault (soft-deleted for 90 days, then purged) and user-assigned identities.
- `Remove-PimContainerStack.ps1` removes only the container apps, jobs and Container Apps environment and their role assignments at subscription scope, and deliberately keeps SQL, registry, Key Vault, storage, network and identities -- use it to rebuild, not to exit.

### What remains after deleting the resource group (remove by hand)
- Role assignments made at the tenant root management group or on other subscriptions (Reader, optional User Access Administrator).
- App registrations: the Manager sign-in app, the access-request app, the engine and deploy app registrations (when created), the PIM Activator app.
- Groups: `grp-pim-sql-admins`, the Manager users group, the Power BI admin-API group.
- The mail sender's shared mailbox and its Exchange management scope and role assignment.
- The Invardia Support app (chapter 5).
- **Everything the engine created in your tenant on purpose:** admin accounts, PIM groups, administrative units, role eligibilities and assignments, PIM policies. These are your access model -- they keep working without the product. Remove or keep them as part of your exit plan; the Manager's reports and the managed-object ledger list them before you uninstall.
- On-premises: hybrid worker gMSAs, AD delegations and the server GPO.

### Exit
- Export your configuration (Settings > backups) before removal; it is JSON you keep.
- There is no single uninstall script today (SP-GAP-10).

<a id="scripts"></a>
## 11. Scripts

Scripts are run by highly privileged people, so they are listed here one by one with the rights needed, the changes made and their state **today**. The target state for every product's scripts (framework requirements 12.7 and 12.10) is: Authenticode-signed and listed in SHA256SUMS.txt; documented save, verify, read, run (never pipe-to-execute); no second-stage downloads; -WhatIf preview; a transcript; browser sign-in, no secrets in or out. **That target is not reached in this version** -- the table states what is true now (SP-GAP-3, SP-GAP-4).

### How to run a script today (recommended)
1. Download it: `Invoke-WebRequest https://invardia.com/support/pim/<Script>.ps1 -OutFile <Script>.ps1`
2. Verify it: compare `Get-FileHash .\<Script>.ps1 -Algorithm SHA256` with the line in `SHA256SUMS.txt` published next to it.
3. Read it -- each script is one self-contained file; the source is also in the public repository.
4. Run it, with `-WhatIf` (or `-PlanOnly` where the table says so) first.

### Facts that hold for every published script
- **Not Authenticode-signed today.** A SHA256SUMS.txt is published with the scripts.
- **No PowerShell modules**; REST and .NET only; browser sign-in (no device code).
- **No pipe-to-execute** anywhere in the product; scripts do not download and run further code.
- **No transcript** is written by the published scripts today; some write a result file with -OutFile.
- No per-script documentation manifest yet (framework 12.7).

**Published support scripts (invardia.com/support/pim/)**

| Script | Purpose | Rights needed to run it | Changes it makes | Preview today | Signed today |
|---|---|---|---|---|---|
| Grant-PimEnginePermissions.ps1 | Give the engine identity its missing Graph permissions and Azure roles (the command the Manager shows) | Global Administrator or Privileged Role Administrator (app permissions); Owner or User Access Administrator at the scope (Azure roles) | Graph app-role assignments and Azure role assignments for the engine, exactly as listed in the command; no allow-list (SP-GAP-13) | -PlanOnly (no -WhatIf) | No (SHA256SUMS) |
| Initialize-PimSqlAdminGroup.ps1 | Make grp-pim-sql-admins the SQL server's Entra admin with the product's identities as members | Privileged Role Administrator (role-assignable group) + Owner/Contributor on the SQL server | Creates the group; sets the SQL Entra admin; adds the product identities, the Invardia Support app (if present) and you | -PlanOnly (no -WhatIf) | No (SHA256SUMS) |
| Initialize-PimWorkloadPrereqs.ps1 | Fix a workload prerequisite the product cannot fix itself (Power BI group, Fabric setting, Sentinel, Azure rights) | AppRoleAssignment.ReadWrite.All + Group.ReadWrite.All (delegated); Fabric administrator; User Access Administrator at the scope | Power BI security group + engine membership; Fabric tenant setting; engine Graph roles; optional Sentinel workspace (billed) and User Access Administrator; product settings | -WhatIf (honoured) | No (SHA256SUMS) |
| Initialize-PimMailSender.ps1 | Create the sender mailbox and its send right scoped to that one mailbox | Exchange Administrator or Global Administrator (browser); or the Support app (activates Exchange Administrator time-bound) | Shared mailbox; management scope; Application Mail.Send role assignment for the product identities; removes tenant-wide Graph Mail.Send; product settings | -WhatIf (honoured; stops before any Exchange call) | No (SHA256SUMS) |
| Set-PimSmtpRelayPassword.ps1 | Store the SMTP relay password in the environment's Key Vault | Key Vault secret write (it can grant itself Key Vault Secrets Officer on that vault if you may) | Optional vault; the secret; Key Vault Secrets User on that one secret for the product identities | -WhatIf (honoured) | No (SHA256SUMS) |
| Deploy-PimActivatorBackend.ps1 | Create or update the PIM Activator app registration | Application Administrator or Cloud Application Administrator (active); Privileged Role Administrator or Global Administrator for consent | App registration, service principal, redirect URIs, delegated permissions (chapter 3), tenant-wide admin consent (default on), group assignment | None (SP-GAP-4) | No (SHA256SUMS) |
| Publish-PimActivatorRemediation.ps1 | Build the Intune Remediation (detect + remediate) for the Activator and upload it | Intune Administrator (DeviceManagementScripts.ReadWrite.All, delegated) | Writes the two scripts locally; creates/updates an Intune remediation that runs as SYSTEM with signature check off; assigns only to the group you name | None (SP-GAP-4) | No (SHA256SUMS) |
| Deploy-PimActivatorClient.ps1 | Install the Activator extension and settings on a machine without Intune | Local administrator (machine scope); none (user scope) | Browser policy registry keys (force-install list, allowed sources, extension settings); the browser then fetches the extension from its update URL | None (SP-GAP-4) | No (SHA256SUMS) |

**Installer and repository scripts a person runs**

| Script | Purpose | Rights needed to run it | Changes it makes | Preview today | Signed today |
|---|---|---|---|---|---|
| Install-PimManager.ps1 | The guided install (called by Invardia's bootstrap or run directly) | Azure Owner, or Contributor + User Access Administrator, on the subscription; Entra Privileged Role Administrator or Global Administrator (active) for the directory steps | Everything in chapters 1-3 for the chosen options; licence; optional Support app access | -PreflightOnly (rights + plan check) | No |
| Invoke-PimDeployAll.ps1 | Full deploy: identities, infrastructure, schema, image, verify, rollback | As Install-PimManager | As above | Plan by default; -Apply to run | No |
| Confirm-PimInstall.ps1 | End-of-install check; also repairs some lines (access model, update job, root Reader, firewall rule) | Reader for the check; the repair's own rights | Repairs run without a preview (SP-GAP-4) | None for repairs | No |
| Grant-PimSupportAccess.ps1 | Give or take back the Invardia Support app's access (troubleshoot / setup / -Remove) | Privileged Role Administrator (role-assignable group); SQL admin | Chapter 5 | -WhatIf (honoured) | No |
| Invoke-PimMspBuild.ps1 | MSP managing / managed tenant build | As Install-PimManager, per tenant | MSP components (chapter 3) | Plan by default; -Apply | No |
| Set-PimManagerAccess.ps1, Set-PimBreakGlassAccounts.ps1, Set-PimEmergencyPassphrase.ps1, Set-PimLicense.ps1, Copy-PimSettings.ps1, Import-PimPermissionTemplate.ps1, Register-PimManagedTenant.ps1, Deploy-PimUpdateJob.ps1 | Settings and component scripts the GUI names | SQL admin / Owner on the resource as each states | Product settings; the named component | -WhatIf (honoured) | No |
| Set-PimManagerMcpAuth.ps1, Set-PimRfaBrokerApiAuth.ps1, Upgrade-PimToPro.ps1 | MCP sign-in, access-request API sign-in, edition upgrade | Application Administrator; Owner on the app | App registration settings; edition | -Apply switch (plan otherwise) | No |
| Import-PimEnvironmentBackup.ps1, Update-PimCommunity.ps1, Initialize-PimTenantStore.ps1 | Restore a backup; Community update; store init | SQL admin; repository write | As named | Import plans first (-Apply); others none (SP-GAP-4) | No |
| Hybrid worker scripts (Initialize-PimHybridWorkerAd, Install-PimHybridWorker, New-PimHybridWorkerInfra, Grant-PimHybridWorkerAccess, Set-PimHybridWorkerEgress) | On-premises AD worker | Domain Admin (AD delegation, GPO); Owner on the worker resources | gMSAs, AD delegations, server GPO, VM, identity grants (chapter 3) | -WhatIf in all except Install-PimHybridWorker | No; Install-PimHybridWorker writes a transcript and verifies the PowerShell installer's signature |

---

PIM Manager is sold and supported by Invardia, a brand of 2LINKIT. Questions about this pack: info@invardia.com. Support for licensed customers: portal.invardia.com. This pack describes how the product supports your own controls; it is not a certification, and PIM Manager does not hold ISO 27001, SOC 2 or similar certification.
