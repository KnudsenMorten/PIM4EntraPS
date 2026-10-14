# PIM Manager: how it works

PIM Manager keeps privileged access in Microsoft Entra ID, Azure, Intune and Defender XDR in line with one desired state
that your administrators manage. People get admin rights through groups, just in time, with the policies you define,
and every change is staged, checked, approved where needed and recorded.

Everything runs in **your own Azure subscription**. Invardia does not host the product, your data or its runtime, and
the product keeps working without any connection to Invardia.

## The parts in your subscription

| Part | What it is | What it does |
|---|---|---|
| Portal (PIM Manager) | A Container App behind a sign-in front | Where administrators look, stage changes, approve and commit. It reads your tenant; it never writes to it. |
| Engine | A Container Apps job on a schedule | Reads the desired state from the database and applies it to Entra ID, PIM for Groups, Azure RBAC, Intune and Defender XDR. |
| Updater | A Container Apps job, daily by default | Builds the new version from source inside your own registry, applies the database schema and rolls the portal and jobs. |
| Database | Azure SQL, Entra sign-in only | The desired state, settings, the audit log and the commit journal. |
| Container registry | Azure Container Registry | Holds the images built in your subscription. |
| Log Analytics workspace | Azure Monitor | Container logs and the SQL security audit (90 days). |
| Optional parts | | The PIM Activator browser extension, the access-request broker, the hybrid worker for on-premises Active Directory, and the managing / managed tenant jobs for service providers. |

## How a change reaches your tenant

1. An administrator signs in to the portal and stages a change, for example a new eligible role for a group.
2. When the change is sensitive, a second person approves it.
3. The administrator commits. The commit is written to the database together with its journal row (who, what, before
   and after) in one transaction.
4. The portal starts the engine job. It has the right to start that one job and nothing else.
5. The engine signs in with its own managed identity, checks every guard (see [Guards and Strict mode](guards)) and
   applies the change through the Microsoft APIs.
6. The outcome is written back: the applied state per row, the audit event, and a mail when something needs attention.

The portal can never change the tenant itself and can never change the engine. The engine changes only objects that
are defined in the database: anything it does not own is reported, never removed.

## Where to read next

- [Install](install) and [Identities and permissions](identities)
- [Database access](sql-access) and [Security design](security)
- [Guards and Strict mode](guards) and [Releases, rings and updates](release-and-updates)
