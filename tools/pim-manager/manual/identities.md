# Identities and permissions

Every runtime identity is a **managed identity**: there is no secret or certificate to steal, store or rotate. Each
component has its own identity, and each identity has only the rights its job needs.

## The identities

| Identity | Kind | What it does | What it can never do |
|---|---|---|---|
| Portal | Managed identity of the portal app | Reads the tenant for the screens (Graph read-only), stages changes in the database, starts the engine job | Write to the tenant, change the database schema, change the engine, push images, administer SQL |
| Engine | Managed identity of the engine job | Applies the desired state to Entra ID, PIM for Groups, Azure RBAC, Intune and Defender XDR | Change objects that are not defined in the database; delete an account by itself |
| Updater | Managed identity of the update job | Builds the new version in your registry, applies the schema, rolls the apps | Change database security outside the signed grant procedure |
| Image pull | User-assigned managed identity | Pulls images from your registry | Reach the database (it has no database user at all) |
| Sign-in front | App registration, with the portal's managed identity as a federated credential | Signs administrators in (OpenID Connect code flow with PKCE, 8-hour fixed session) | Hold a secret: there is none |
| PIM Activator (optional) | App registration, public client with PKCE | Lets each user activate their **own** eligible groups and roles | Act beyond the signed-in user's own eligibility |
| Invardia Support app (optional) | App registration in your tenant, only if you create it | Troubleshooting on request (see [Support access](support-access)) | Anything after you switch it off |

## The engine's rights, and why they are broad

The engine manages privileged access, so it needs write rights in Microsoft Graph: users, groups, role management,
PIM schedules and policies, administrative units, app-role assignments, Temporary Access Pass, access reviews, Intune
RBAC and Defender XDR roles. Its Graph rights are tier-0 equivalent, so **treat the engine identity as a tier-0 asset**.

What keeps those rights in check:

- The engine only touches objects that are defined in the database; anything else is reported, never removed.
- Every write passes the guards first (see [Guards and Strict mode](guards)); a large or weakening change waits for a
  person.
- The engine never deletes an account by itself. The only delete is an operator's **Delete account** on an account
  PIM Manager manages.
- Break-glass accounts are never removed, disabled or revoked.
- Azure: Reader by default; User Access Administrator only when you switch it on.

## The portal's rights

- Microsoft Graph: **read-only** permissions only. Every change is queued in the database and applied by the engine.
- Azure: Reader on the hosting subscription and on the PIM resource group; **Container Apps Jobs Operator on the engine
  job only**, so it can start that job and nothing else.
- Database: its own role (pim_web), with no right to change the schema.

## Mail

Mail is never sent with a tenant-wide Mail.Send right. It goes through Exchange RBAC for Applications, scoped to one
shared mailbox. The engine and the portal each have their own scoped send right.

The full permission table, per identity and per permission with the reason and what breaks without it, is in the
security review pack (see [Security design](security)).
