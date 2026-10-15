# Support access

Invardia has **no access** to your installation unless you create the **Invardia Support app** in your tenant. Most
installations never do. PIM Manager runs, updates and protects itself without it.

## The support team

Every request -- a portal ticket, a mail to support@invardia.com, the in-product assistant, or an automatic event
(a failed run, a guard trip, an install failure) -- becomes a numbered ticket (SUP-yyyy-nnnnn) and is handled at three
levels:

| Level | Who | What it does |
|---|---|---|
| 1 | Support agent (24x7) | Reads every event within minutes and **qualifies it before routing**: is it valid; a feature, a defect, a question or a customer-side setting; its priority (P1-P4); a bigger design; a hotfix; does it need the owner's yes. Answers how-to and customer-side questions from the published documentation. |
| 2 | Product engineering (PIM Manager) | Reproduces and fixes a defect, tests it, releases it to ring 0 and ring 1, monitors it and reports back. |
| 3 | Support manager / development owner | Bigger design changes, security defects, every reply on a P1, and the approval of rings 2 and 3. |

- **Release rule:** the product fixes and releases to rings 0 and 1; the support agent proposes the version as a
  candidate; the owner approves rings 2 and 3. An agent never approves a customer ring.
- **Every message is checked** by a supervisor and a built-in gatekeeper before it reaches you, and every message shows
  the level and role that wrote it.
- You follow the ticket in the portal and by mail: Received, Acknowledged, Escalated, Fix in progress, Fix ready,
  Resolved.

## When you want help

1. Run Invardia's setup script for the Support app (published at https://invardia.com/support/) and choose a level.
2. For database work, a Global Administrator or Privileged Role Administrator adds the Support app to the SQL admin
   group. That is an Entra change; nobody needs to be inside the database first.
3. Invardia works on your case. When it is done, switch the app off or remove it.

## Levels

| Level | What it allows |
|---|---|
| As-built | Start the one as-built job and read the PDF it writes (the installation's configuration, without people, user names or secrets). The PDF is deleted after 24 hours. |
| Troubleshoot | Read-only Graph and Azure on the scopes you name; read the PIM database |
| Setup | Install and repair on your behalf. Tier-0 equivalent: grant it for an install or repair, then lower it |

## How Invardia works through it

- Every action uses Invardia's support tool, which checks that the token's tenant and app match your environment and
  refuses a production environment without an explicit production switch.
- Every SQL statement goes through Invardia's support SQL route, which records the statement and its reason **before**
  it runs.
- Security changes to a running installation are made with a scripted cut-over: a plan first, every change read back,
  a rollback record. Customers are told beforehand.
- Everything the Support app does is in **your** Entra sign-in and audit logs, the Azure Activity Log and the SQL audit
  in your Log Analytics workspace.

## The credential

The Support app is the only identity in the product allowed a client secret, and only for setup and support, never
for the runtime. For customers it expires after 90 days. Invardia keeps it in its support Key Vault. An optional
Conditional Access policy can restrict the app to Invardia's support address.

## How you end it

- Switch the Support app off or delete it in Entra ID. The access ends at once.
- Or run `Grant-PimSupportAccess.ps1 -Remove` to take back the database user, the group membership and the ownerships.
