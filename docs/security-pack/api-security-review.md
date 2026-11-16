# PIM Manager API for applications -- what is refused (version 3.1.31)

Scripts and services can use the PIM Manager API with their own Entra application (a Pro feature). Before a version
reaches any installation, an automated security review checks that each of the following is refused. A failed check
stops the release.

**Sign-in**
- A sign-in that is not a genuine Microsoft Entra application token for this PIM Manager, from your own tenant, that is
  still valid and carries the PIM Manager API role.
- A person's (delegated) sign-in on the application API, and a token that does not say it is an application token.
- An application your SuperAdmins have not listed, even with a valid token.
- An application token on the AI assistant (MCP) endpoint, which is for people only.

**What an application may do**
- Security settings stay with people: who signs in and approves, break-glass accounts, licence and edition, which
  applications may use the API, the second-person rules, and the audit, backup and alert settings.
- An application never approves or carries out a request, including its own.
- A large or weakening change by an application waits for a SuperAdmin.
- An action that has not been classified is treated as the strictest kind and is refused to applications.

**Invardia support (only when you switch it on)**
- Only fixes from the published fix catalog, only on a support ticket, at most 25 access rows per hour; every change is
  mailed to your administrators and recorded in the audit trail with the ticket number.

**Requests**
- Requests from a web page in another site (no cross-origin access), bodies larger than 1 MB, bodies that are not JSON,
  and fields the API does not know.
- Plain HTTP: the Manager is reached over HTTPS only.

**Records**
- Sign-in tokens and secrets are never written to a log or the audit trail, and error answers never describe the reason
  for a refusal.
