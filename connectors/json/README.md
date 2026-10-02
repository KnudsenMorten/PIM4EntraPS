# JSON connector -- any system that can call a REST endpoint

* **Contract:** [`openapi.json`](openapi.json) -- generated from the broker itself (`GET /api/v1/openapi.json` returns the
  same document), so the file and the running API cannot drift apart.
* **Reference client:** [`Invoke-PimAccessRequest.ps1`](Invoke-PimAccessRequest.ps1) -- request, wait, status, cancel; an
  Entra application token with a certificate or an API key.

## The request

```http
POST https://<broker-host>/api/v1/requests
Authorization: Bearer <Entra token>          (or)   X-Api-Key: <PIM API key>
Content-Type: application/json

{
  "userPrincipalName": "adm-jane@contoso.com",
  "type": "group",                 // "enable" (default) or "group"
  "groupName": "ERP-Admins",       // only for "group"
  "hours": 24,                     // 1 .. 744
  "ticket": "RITM0012345",         // YOUR ticket number -- makes a retry safe
  "reason": "ERP consultant cannot help -- second consultant steps in"
}
```

Answers: `202 { id, state: "submitted", status }` for a new request; `200 { ...status }` when the same ticket was already
sent; `400` (invalid, with the reason), `401` (no / bad sign-in), `403` (application not allowed / key without the scope),
`429` (too many calls -- honour `Retry-After`).

## Status and cancel

```http
GET  https://<broker-host>/api/v1/requests/<id>          -> { id, state, status, userPrincipalName, type, groupName, hours, ticket, windowEndUtc, submittedUtc }
POST https://<broker-host>/api/v1/requests/<id>/cancel   -> 202 { id, state: "cancel-requested" }
```

Final states: `active`, `ended`, `denied`, `rejected`, `expired`, `cancelled`. Poll every 20-60 seconds.

## Power Automate / Logic Apps

1. **Trigger:** your own (an approved form, a ticket that reached *Approved*, a Teams approval ...).
2. **HTTP** action -- *Method* `POST`, *URI* `https://<broker-host>/api/v1/requests`, *Headers* `Content-Type:
   application/json`, *Body* as above with your ticket id. *Authentication*: **Active Directory OAuth** with a
   **certificate** (Tenant, Audience = the broker application's id URI, Client ID, Pfx + password from Key Vault) -- or a
   header `X-Api-Key` read from Key Vault.
3. **Parse JSON** with the `id` / `state` / `status` schema.
4. **Do until** `state` is one of the final states: **Delay** 30 s, then **HTTP** `GET .../api/v1/requests/@{body('Parse_JSON')?['id']}`.
5. Write `status` back to the ticket.

Keep the certificate or the key in Key Vault; never paste either into the flow.
