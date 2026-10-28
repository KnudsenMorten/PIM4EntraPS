# Connectors for the PIM access request API (Pro)

One REST API on the public access request broker serves every system that wants to ask PIM for access:
ServiceNow, a ticketing or HR system that can send JSON, Power Automate, Logic Apps, or a script. The connectors in this
folder are **recipes and samples over that one API** -- there is no second API and nothing extra to host.

| Folder | For | What is in it |
|---|---|---|
| [`json/`](json/README.md) | any system that can call a REST endpoint | `openapi.json` (the contract, generated from the broker), `Invoke-PimAccessRequest.ps1` (reference client), Power Automate / Logic Apps steps |
| [`servicenow/`](servicenow/README.md) | ServiceNow | OAuth profile against Microsoft Entra ID, a Flow Designer action (request + wait), the catalog item variables, the status mapping |

## What a caller can ask for

| `type` | Effect | Ends |
|---|---|---|
| `enable` | the admin account is enabled for `hours` (1 to 744) | the account is disabled again when the window ends (its roles are kept) |
| `group` | **ad-hoc** membership of the permission group `groupName` for `hours` | the membership is **removed automatically** when the window ends |
| `proposal` | a **standing** change (`requestType`: `group-add`, `delegation-request`, `group-membership`, `admin-group-assignment`; the PIM group in `groupTag`; who asked in `requestor`; no `hours`) | never applied by the machine: it becomes a **pending change** an administrator reviews and commits in PIM. State `forwarded` once handed over. Activation requests, requests where the requester is the target, and anything while the intake is switched off are rejected; Tier 0/1 always waits for a person |

Ad-hoc access is never confused with delegated (standing) access: it is marked *ad-hoc* in the PIM Manager, and a group
the account already holds through delegation is refused.

## The contract every connector follows

1. **Sign in** -- one of:
   * **Microsoft Entra application token (recommended).** Client credentials with a **certificate**; the application's
     client id is allow-listed in the PIM Manager under **Settings > Access requests > API applications**. The broker's
     sign-in layer validates the token; PIM checks the allow-list again when it takes the request in.
   * **PIM API key** (`X-Api-Key` header) for a system that cannot use Entra tokens. Created under **Settings > Access
     requests > API keys** with the scopes `requests.write` / `requests.read` and an expiry; shown once; only its hash is
     stored; revocable at any time.
2. **`POST /api/v1/requests`** with **your own ticket number** in `ticket`. The call is idempotent on the ticket: the
   same ticket again returns that request's status, so a retry after a timeout never creates a second request.
3. **`GET /api/v1/requests/{id}`** until the state is final: `active` (it is in effect), `ended`, `denied`, `rejected`
   (the reason is in `status`), `expired`, `cancelled`, `forwarded` (a proposal handed to PIM's review queue).
4. **`POST /api/v1/requests/{id}/cancel`** ends a window early.

The caller's own workflow **is** the approval: a request made through the API is approved on arrival and applied within
a few minutes. The API only ever returns requests the same caller made.

## Before the first call (PIM Manager, SuperAdmin)

1. The **Access request API** feature is enabled and licensed (Pro).
2. The broker is deployed and its URL is set under **Settings > Access requests**.
3. The calling application is allow-listed, or an API key is created for it.
4. For `type: group`: the target account and group exist in PIM; the group is not one the account already holds.
