# PIM4EntraPS — prod Azure SQL (private endpoint, MI, AAD-only)

The prod data store: an Azure SQL database reachable **only over a Private
Endpoint**, **public network access disabled**, **AAD-only auth** (no SQL logins),
accessed by the Manager/engine via **Managed Identity** (no secret anywhere). The
same `PIM-SqlStore.ps1` code that runs on local SQL Express targets this by
connection string alone.

## Files
- `main.bicep` — the server (AAD-only, public access disabled, TLS 1.2), database,
  Private Endpoint, private DNS zone + VNet link + zone group.
- `main.parameters.sample.json` — copy to `main.parameters.json` (gitignored), fill in.
- `grant-mi.sql` — grant the Manager's Managed Identity a contained DB user.

## Provision (run in YOUR subscription)
1. Pre-reqs: a VNet + subnet for the private endpoint, and an **AAD group** that
   will administer the server (put the operators in it; that's `aadAdminObjectId`).
2. Deploy:
   ```
   az deployment group create -g <rg> -f main.bicep -p @main.parameters.json
   ```
   Outputs `sqlServerFqdn` + a `connectionStringHint`.
3. Grant the Managed Identity (from a host that can reach the PE — VNet box /
   jumphost — signed in as the AAD admin group member):
   ```
   sqlcmd -S <sqlServerFqdn> -d PIM4EntraPS -G -i grant-mi.sql   # -G = AAD auth
   ```
   (Edit `<MI-DISPLAY-NAME>` first — the user-assigned MI name, or the app host's
   system-assigned identity name.)

## Point the Manager at it (passwordless, MI)
The launcher mints an MI token for `https://database.windows.net/` into
`$global:PIM_SqlAccessToken` and sets the passwordless connection string:
```powershell
$global:PIM_SqlAccessToken    = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token   # or from the host MI
$global:PIM_SqlConnectionString = Get-PimAzureSqlConnectionString -Fqdn '<sqlServerFqdn>'
# (or set StorageBackend=sql in config + $global:PIM_SqlServer for the FQDN)
```
`New-PimSqlConnection` puts the token on the connection — no password in any file.

## Migrate the existing config + switch
From a host that can reach the PE:
```powershell
.\setup\Migrate-PimToSql.ps1 -ConfigDir <instance-config> -ConnectionString $global:PIM_SqlConnectionString
```
Non-destructive (CSV files are read, never modified; reversible by flipping
`StorageBackend` back to csv). Then open the Manager — it boots in SQL mode and
loads settings from `pim.Settings` (the file is seed-only thereafter).

## Security notes
- No public endpoint; only the VNet (+ peered/connected networks) can reach the DB.
- No secret at rest: MI/AAD token auth. Settings + naming live in `pim.Settings`,
  not a readable JSON file.
- The AAD admin is a **group** so there is no single break-glass account in the bicep.
