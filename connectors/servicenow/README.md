# ServiceNow connector

ServiceNow is a public SaaS service, so it calls the **public access request broker** -- never the PIM Manager, which can
stay internal. Nothing on the public side can reach PIM: the broker only stores the request, and PIM pulls it in.

## 1. The Entra application ServiceNow signs in as

1. In Microsoft Entra ID, register an application, e.g. *ServiceNow - PIM access requests*.
2. Upload a **certificate** (no client secret). Keep the private key in ServiceNow's key store (step 2).
3. In the PIM Manager, **Settings > Access requests > API applications**: add the application's **client id**.

(No ServiceNow certificate support in your instance? Create a PIM **API key** under **Settings > Access requests > API
keys** with `requests.write` + `requests.read`, store it as a password2 field / credential, and send it as `X-Api-Key`.)

## 2. OAuth profile (System OAuth > Application Registry)

* *Connect to a third party OAuth Provider*; **Default Grant type:** `Client Credentials`.
* **Token URL:** `https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token`
* **Client ID:** the application's client id; client authentication with the **JWT bearer / certificate** profile
  (JWT Keys + JWT Provider over the uploaded certificate).
* **OAuth Entity Scope:** `api://<broker application id>/.default`
* Test with *Get OAuth Token* before building the flow.

## 3. Flow Designer action: *PIM - request access*

Inputs:

| Input | Type | Example |
|---|---|---|
| `upn` | String | `adm-jane@contoso.com` (the ADMIN account) |
| `type` | Choice `enable` / `group` | `group` |
| `group_name` | String (only for `group`) | `ERP-Admins` |
| `hours` | Integer 1-744 | `24` |
| `ticket` | String | the RITM number |
| `reason` | String | the request's short description |

Steps:

1. **REST step** -- *Connection*: the OAuth profile above (or *No authentication* + header `X-Api-Key` from a credential);
   *Base URL*: `https://<broker-host>`; *Resource path* `/api/v1/requests`; *Method* `POST`; *Headers*
   `Content-Type: application/json`; *Request body*:
   `{"userPrincipalName":"${upn}","type":"${type}","groupName":"${group_name}","hours":${hours},"ticket":"${ticket}","reason":"${reason}"}`
2. **JSON parser step** -- `id`, `state`, `status`.
3. **Outputs:** `request_id`, `state`, `status`.

A second action, *PIM - request status* (`GET /api/v1/requests/${request_id}`), and a third, *PIM - end early*
(`POST /api/v1/requests/${request_id}/cancel`), use the same connection.

## 4. Catalog item *Temporary admin access*

Variables: `admin_account` (reference to the person's admin account, or a string), `access_type` (enable my admin
account / join a permission group), `permission_group` (visible when `access_type` = group), `duration_hours` (default
24, 1-744), `business_reason`.

Flow: catalog item approved (your approval) -> *PIM - request access* with `ticket` = the RITM number -> **Do the
following until** `state` is final: wait 1 minute, *PIM - request status* -> write `status` to the RITM work notes ->
close the RITM as *Closed Complete* on `active`, *Closed Incomplete* on `denied` / `rejected` / `expired`.

The call is idempotent on the RITM number: a flow that is restarted and calls again gets the same request back.

## 5. Status mapping

| PIM `state` | Meaning | RITM |
|---|---|---|
| `submitted`, `approved` | accepted, PIM is applying it | Work in Progress |
| `active` | in effect until `windowEndUtc` | Closed Complete (note the end time) |
| `ended` / `cancelled` | the window is over / was ended early | -- |
| `rejected` | PIM refused it -- the reason is in `status` | Closed Incomplete |
| `denied` / `expired` | (portal requests only) | -- |
