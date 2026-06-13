# PIM Manager — 24/7 hosted (App Service for Containers)

Runs the Manager as an always-on web app so the **business** reaches it by browser
— no per-machine file distribution/updates. Locked down: **private inbound**
(Private Endpoint, public access disabled), **Entra Easy Auth** in front, **Managed
Identity** to Azure SQL over its Private Endpoint (no secret), and the per-session
token still required on `/api`. The **local loopback edition stays the break-glass
path** for when this app plan / Easy Auth / region is down.

## Pieces
- `../../tools/pim-manager/Dockerfile` — the hosted Manager image (PIM_HOSTED=1).
- `main.bicep` — Linux App Service plan (PremiumV3, AlwaysOn) + Web App for
  Containers (system MI, VNet integration outbound, public access disabled),
  Easy Auth (Entra), Private Endpoint inbound + private DNS.
- `main.parameters.sample.json` — copy to `main.parameters.json` (gitignored).

## Deploy (in YOUR subscription)
1. **Azure SQL** first (`../azure-sql/`), and have the VNet + subnets (one delegated
   to `Microsoft.Web/serverFarms` for outbound integration, one for the inbound PE).
2. **Easy Auth app reg**: register an Entra app, expose `api://<clientId>`, add the
   web app's redirect (`https://<appName>.azurewebsites.net/.auth/login/aad/callback`).
   Restrict who can sign in (assignment required) — these become your portal users.
3. **Build + push** the image to ACR (build context = repo root):
   ```
   docker build -f SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile -t <acr>.azurecr.io/pim-manager:1.0.0 .
   az acr login -n <acr>; docker push <acr>.azurecr.io/pim-manager:1.0.0
   ```
4. **Deploy**:
   ```
   az deployment group create -g <rg> -f main.bicep -p @main.parameters.json
   ```
   Grant the app's MI `AcrPull` on the ACR and run `../azure-sql/grant-mi.sql` with
   the app's MI display name so it can reach the DB.
5. **Manager access**: add your business users/roles to `manager-access.custom.json`
   + the portal-admins / approver-matrix config. In hosted mode the implicit
   SuperAdmin default is OFF — unlisted authenticated users fail closed to Reader.

## Break-glass (app plan down)
Run the **local** edition on the mgmt box (no `-Hosted`): loopback, SuperAdmin,
session token. On the VNet it still reaches the same Azure SQL over the PE (so it
sees live data); if SQL is also unreachable it falls back to CSV/local cache.
That's the emergency path — intentionally separate from the hosted business app.

## Notes
- **SQL client on Linux**: `PIM-SqlStore.ps1` uses `System.Data.SqlClient`. If the
  Linux image can't load it, either base the image on a **Windows container**
  (in-box on Windows PowerShell) or port `New-PimSqlConnection` to
  `Microsoft.Data.SqlClient`. Flagged as a deploy-time decision.
- No secret in the image or app settings — MI for SQL/KV; Easy Auth for users.
