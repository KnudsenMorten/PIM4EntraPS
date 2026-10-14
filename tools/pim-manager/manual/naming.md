# Naming conventions

Naming is per customer. A fresh installation is seeded with a complete default template, and you change it in
**Settings > Naming** before you build your model. The engine reads the stored template only.

## Accounts and groups

| Object | Default pattern | Example | Configurable |
|---|---|---|---|
| Admin account | `{AdminTypePrefix}{AdminWord}-{Initial}{Platform}` | `Admin-JDOE-ID` | Yes: the word, the prefixes, the pattern |
| Highly privileged admin account | `{AdminWord}-{Initial}-L0-T0{Platform}` | `Admin-JDOE-L0-T0-ID` | Yes |
| Admin type prefix | internal admin: none; external admin: `x-` | `x-Admin-JDOE-ID` | Yes |
| Platform suffix | Entra ID: `-ID`; on-premises AD: `-AD` | `Admin-JDOE-AD` | Yes |
| Admin display name | the person's name + ` (Admin)` | `Jane Doe (Admin)` | Yes |
| Role group | `PIM-{Role}-{Department}` | `PIM-HelpdeskAdmin-Finance` | Yes |
| Role group scoped to an administrative unit | `PIM-{Role}-AU-{AdminUnit}` | `PIM-UserAdmin-AU-Denmark` | Yes |
| Resource permission group | `PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}` | `PIM-Azure-Prod-Reader-L2-T1-MP-ID` | Yes |
| Group type prefixes | `ROLE-`, `ORG-`, `DEPT-`, `PROJ-`, `CORG-` | `DEPT-Finance` | Yes |
| Administrative units for PIM's groups | `PIM-ROLES`, `PIM-DEPARTMENTS`, `PIM-L0`, `PIM-L1`, `PIM-L2` ... | | Yes |
| On-premises AD names (hybrid worker) | entirely yours, set in Settings > Hybrid Active Directory | | Yes, all of them |

## How the groups nest

```text
person
  -> admin account (Admin-JDOE-ID)
       -> member of a department / organisation / project group (DEPT-Finance)
            -> eligible member of a role or permission group (PIM-HelpdeskAdmin-Finance)
                 -> holds the Entra role, Azure role, Intune role or Defender role
```

The principal is always a group: delegation is group membership, and administrative units and Azure scopes are only
scopes. Role-assignable groups accept only **eligible** membership, so access is activated just in time.

## Azure resources an installation creates

| Resource | Default name |
|---|---|
| Resource group | `rg-pim` (or a name you choose) |
| Portal | `ca-pim-manager` |
| Engine job | `ca-pim-tick` |
| Update job | `ca-pim-update` |
| As-built job | `caj-pim-asbuilt` |
| SQL admin group | `grp-pim-sql-admins` |
| SQL server, registry, image-pull identity | a name with the installation's own suffix, for example `sql-pim-` + suffix |

Each installation **records the names it uses**, and every script and job reads them from that record. An
installation with its own names keeps working through every update.

## Environment names

Each installation has a name your administrators give it, for example "Production" or "Test (EU)". It appears in the
portal header and at the start of every mail subject. Invardia identifies an installation by a handle of the form
company + kind, for example `contoso-prod` or `contoso-test`.

## What stays fixed

- Decide the template before you build your model: names are made from it when objects are created, so change it early.
- The database roles (`pim_web`, `pim_engine` ...) and the signed procedure's name are fixed by the product.
