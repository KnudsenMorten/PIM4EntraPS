# Security design

This page summarises the security design. The complete review pack for security teams (every identity and permission,
data, the vendor's access, supply chain, the threat model with its controls, the compliance mapping and the exit) is
published at https://invardia.com/products/pim-manager/security/.

## Sign-in

- Every page needs a signed-in person. Sign-in and token checks are done by Microsoft: administrators sign in with
  Microsoft Entra ID through Microsoft's built-in sign-in for Azure Container Apps, with **no client secret** (the
  portal's managed identity is a federated credential on the app registration).
- On every request the portal checks the Entra access token itself with Microsoft's token library
  (Microsoft.IdentityModel): signature, your tenant, the portal as audience, expiry. PIM Manager then decides what the
  person may do. No API keys and no shared secrets exist. Details for the browser, scripts, AI assistants (MCP) and
  applications: [How to authenticate](authenticate.md).
- Sessions last **8 hours, fixed**. Your Conditional Access policies (MFA, compliant device, locations) apply to the
  sign-in as to any Entra application.
- App assignment is required: only the people or groups you assign can sign in. An optional users group admits all
  member accounts and never guests.
- Portal roles: Reader, Delegated, Admin and SuperAdmin. The access model refuses to be left without a SuperAdmin.

## The portal's protections

Every response carries security headers:

| Header | Value |
|---|---|
| Content-Security-Policy | Only the portal's own origin; no framing (`frame-ancestors 'none'`), no plug-ins |
| Strict-Transport-Security | One year |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | same-origin |

## Data and encryption

- **Stored in your Azure SQL database:** the desired state and definitions, settings, the change queue and approvals,
  the audit log, the commit journal, configuration backups. Not stored: Temporary Access Pass codes and generated
  passwords (shown once). The access request API takes Microsoft Entra application tokens with an app role; no API key
  or shared secret is issued or stored.
- **At rest:** Transparent Data Encryption. **In transit:** HTTPS to every API; SQL connections encrypted with
  certificate validation.
- **Residency:** every resource is in your subscription, in the region you chose.
- **Sent to Invardia:** run reports and a heartbeat (no users, groups or roles), the licence request, and the update
  manifest request. Telemetry can be switched off in Settings.

## Network

| Mode | What it means |
|---|---|
| Public | The portal has a public HTTPS address with Entra sign-in in front; worker jobs have no ingress at all |
| IP-restricted | Ingress allow-rules on the portal; updates keep them |
| Private | An internal-only Container Apps environment and private endpoints for the database and registry; the portal is reached through your VPN, ExpressRoute, Private Access or a jump host |

Outbound: Microsoft Graph, Azure Resource Manager, Defender, Exchange Online, Power BI (when managed) and invardia.com
(licence, optional updates, telemetry). Nothing from Invardia connects in.

## Logging and audit

- **The audit log** records actor, source, action, target, before and after for every change. **The commit journal**
  records before and after of every committed row, who initiated it and who approved it, in the same transaction as
  the change. Both are append-only, enforced by triggers in the database.
- **SQL auditing** sends every security-relevant statement by any identity, including the Invardia Support app, to your
  Log Analytics workspace, kept 90 days.
- Container logs go to the same workspace. From there they can be exported to your SIEM with Azure's standard data
  export or diagnostic settings.
- Audit retention is yours to set: by default the audit log is kept forever; a shorter retention is at least 13 months,
  and every purge is itself audited.

## Database access

See [Database access (least privilege)](sql-access).

## Changes the product makes in your tenant

See [Guards and Strict mode](guards) for the limits, approvals and the one delete path.
