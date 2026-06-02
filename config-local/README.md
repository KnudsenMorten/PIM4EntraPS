# config-local/

Local-tenant admin model when this tenant runs **both** local + MSP variants.

This folder is the equivalent of `../config/` (single-tenancy mode) but
scoped to admins **owned by the local tenant's IT** -- as opposed to
`../config-msp/` which holds admins **owned by the MSP** and pulled from
a central source on each engine run.

## When to use this folder

Only when you run the engine with `-ConfigVariant local`. In single-tenancy
deployments (no MSP), keep using `../config/` and ignore this folder.

## Layout

Same as `../config/`:

```
config-local/
  Account-Definitions-Admins.locked.csv         (shipped baseline; usually empty / customer-managed)
  Account-Definitions-Admins.custom.csv         (gitignored; the customer's actual local admins)
  Account-Definitions-Admins.custom.sample.csv  (tracked header-only template)
  PIM-Definitions-*.{locked,custom,custom.sample}.csv
  PIM-Assignments-*.{locked,custom,custom.sample}.csv
  repository.custom.ps1                         (gitignored)
  repository.custom.sample.ps1                  (tracked template)
  policies.custom.ps1                           (gitignored)
  policies.custom.sample.ps1                    (tracked template)
  PIM4EntraPS.NamingConventions.{locked,custom.sample}.ps1
  PIM4EntraPS.Filters.{locked,custom.sample}.ps1
```

Bootstrap on a fresh install:

```powershell
# Copy every .custom.sample.* to .custom.* and fill in your local admins:
Get-ChildItem .\*.custom.sample.* | ForEach-Object {
    Copy-Item $_.FullName ($_.FullName -replace '\.custom\.sample\.', '.custom.')
}
```

## Foreign-admin isolation

To keep the local engine from accidentally touching MSP-owned admins (and
vice versa), the **filter scriptblock** in
`PIM4EntraPS.Filters.locked.ps1` (or its `.custom.ps1`) should exclude
admins matching the MSP naming convention. Example:

```powershell
$global:PIM_Filters.AdminCandidate = {
    param($User)
    # Local engine: include only admins WITHOUT the MSP infix
    ($User.UserPrincipalName -like 'Admin-*') -and
    ($User.UserPrincipalName -notlike 'Admin-MSP-*')
}
```

The MSP variant's `PIM4EntraPS.Filters.locked.ps1` should be the mirror
image -- include only admins matching `Admin-MSP-*`.
