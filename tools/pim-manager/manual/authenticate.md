# How to authenticate

PIM Manager has one way in: a Microsoft Entra ID sign-in. Microsoft's platform signs you in. Microsoft's own token
library checks every token. PIM Manager then decides what you may do. There are no API keys, no shared secrets and no
passwords to manage.

## Who checks what

| Step | Done by |
|---|---|
| Sign-in (account, MFA, your Conditional Access policies) | Microsoft Entra ID, through Microsoft's built-in sign-in for Azure Container Apps |
| The token on every request: signature, issuer (your tenant), audience (your PIM Manager), expiry | Microsoft.IdentityModel, Microsoft's token library, inside PIM Manager |
| What you may do: your PIM Manager role (Reader, Delegated, Admin, SuperAdmin), the delegated scope, the tenant | PIM Manager |

Every token must be an Entra **access token** for your PIM Manager (`api://<app id>`, scope `user_impersonation`) from
your own tenant, signed by Microsoft, and not expired. Anything else is refused.

## In the browser

1. Open the address of your PIM Manager. You are sent to the Microsoft sign-in page and pick your account.
2. The session lasts 8 hours. The access token behind it lasts about one hour. The page renews it on its own a few
   minutes before it ends, so you keep working without a new sign-in.
3. When the session ends, or a renewal is not possible, the page shows **Sign in again** and **Sign in with another
   account**. Staged changes stay in the browser and come back after the sign-in.

## From a script

A script uses a person's own Entra access token for the PIM Manager. The Azure CLI is pre-authorised for that scope,
so no consent prompt appears:

```powershell
az login
$token = az account get-access-token --resource api://<app id> --query accessToken -o tsv
Invoke-RestMethod -Uri 'https://<your manager address>/api/config' -Headers @{ Authorization = "Bearer $token" }
```

Any MSAL-based client works the same way: request the scope `api://<app id>/user_impersonation` for the signed-in
person and send the token as `Authorization: Bearer <token>`. What the script may do is the person's PIM Manager role.

## From an AI assistant (MCP)

The MCP endpoint is `https://<your manager address>/mcp`. MCP clients sign in with OAuth against Microsoft Entra ID:

- A call without a valid token is answered `401` with a `WWW-Authenticate` header that points to the discovery
  document `https://<your manager address>/.well-known/oauth-protected-resource/mcp`.
- That document names your tenant's Entra authorization server and the scope `api://<app id>/user_impersonation`.
- The person signs in once in the client. The tools they see and may call follow their PIM Manager role, and every call
  is in the audit trail.

Only a person's delegated token works here. An application's token is refused on `/mcp`.

## From an application (a service, no person)

Applications use their own Entra application token, from a **managed identity** or a **certificate**, on the
`/api/app/...` routes. Each application must be on the list a SuperAdmin keeps under Settings, with the role Reader or
Admin, and it can only reach the routes allowed for that role. An application that is not on the list is refused.

## What is never accepted

- API keys, shared secrets or passwords of any kind.
- The page's own session value in the `Authorization` header.
- A token for another application, from another tenant, with another scope, without a person, or past its expiry.
