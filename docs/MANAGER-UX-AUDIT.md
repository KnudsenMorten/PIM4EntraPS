# PIM Manager -- field-by-field UX audit (v2.2.0 spec)

The operator opens the Manager every few weeks at most. Each input that
demands they remember the schema (GUIDs, ARM paths, role display names,
naming-convention slugs) is friction. The audit below maps every column
across the 14 CSVs to an input strategy with the goal of zero memorization.

## Conventions used in this audit

- **dropdown** -- a fixed `<select>` with a small enumerated set.
- **autocomplete** -- type-ahead, search across a list. Best for medium
  cardinality (admins, groups). Falls back to "type custom" on miss.
- **tenant cache** -- the list comes from `tools/pim-manager/cache/*.json`,
  refreshed via `Open-PimManager.ps1 -RefreshTenantLists` (auto-runs on
  startup when stale or missing).
- **cross-CSV** -- the list comes from another CSV the operator has
  loaded in this session (e.g. GroupTag autocompletes from
  `PIM-Definitions-Roles` rows).
- **inherited** -- read-only auto-fill derived from another selected
  value. UI shows an "override" toggle that switches the cell back to
  manual edit.
- **auto-derived** -- computed from naming-convention pattern + other
  inputs. Live-preview while the operator types upstream fields.

## Definition CSVs

### Account-Definitions-Admins

| Column | Input | Source / default | Notes |
|---|---|---|---|
| FirstName | text | required | |
| LastName | text | required | |
| Initials | auto-derived | First[0]+Last[0..1] uppercased | editable |
| TierLevel | dropdown T0 / T1 / T2 | T1 | most-common default |
| TargetUsage | dropdown Cloud / Legacy / Both | Cloud | |
| TargetPlatform | dropdown ID / AD / Both | ID | controls whether AD-side rows are generated |
| UserType | dropdown Internal / External / Guest | Internal | |
| UserName | auto-derived | naming pattern `Admin-<Init>-T<Tier>-<Platform>` | editable; live preview |
| DisplayName | auto-derived | `<First> <Last> (Admin, <Usage>, <Platform>, L<Lvl>, T<Tier>)` template | editable |
| UserPrincipalName | auto-derived | `<UserName>@<DefaultDomainUPN>` | dropdown if multiple domains in tenant |
| UsageLocation | dropdown ISO 3166-1 alpha-2 | from tenant default | |
| ForwardMailsToContact | checkbox -> TRUE/FALSE | FALSE | |
| MailForwardAddress | autocomplete tenant users | only shown when Forward=TRUE | |
| CreateTAP | checkbox | TRUE for Cloud/ID admins, FALSE otherwise | |
| TAPStartDate | date picker | empty (= immediate) | |
| AccountStatus | dropdown Enabled / Disabled / Revoked | Enabled | gated by StatusChangeCode in MSP variant |
| StatusChangeCode | text + KV-validation status | only shown when status != Enabled | shows "verified vs KV" / "no KV secret found" inline |

### PIM-Definitions-Roles (role groups)

| Column | Input | Source / default |
|---|---|---|
| GroupName | auto-derived | from naming pattern, editable, live preview |
| GroupDescription | text | required, plain-English |
| GroupTag | auto-derived | naming-pattern suffix; must be unique across all definition CSVs (validated) |
| AdministrativeUnitTag | autocomplete cross-CSV from `PIM-Definitions-AU` | optional |
| CPPlatform | dropdown CP / WDP / MP / APP / USER | CP |
| Plane | dropdown ID / RES / DAT | ID |
| TierLevel | dropdown T0 / T1 / T2 | T0 (role groups are usually T0) |
| PermissionScope | dropdown Global / Scoped | Global |
| SyncPlatform | dropdown AD / none | none |
| IsRoleAssignable | checkbox | TRUE | warning shown if FALSE + a role-assignment row references this tag |

### PIM-Definitions-{Tasks, Services, Processes, Resources, Departments, Organization}

Same shape; permission groups instead of role groups. Wizard B picks
which file the row goes into via a single "What kind of capability?"
dropdown.

| Column | Input | Source / default |
|---|---|---|
| GroupName | auto-derived | from naming pattern |
| GroupDescription | text | required |
| GroupTag | auto-derived | unique-globally validated |
| AdministrativeUnitTag | autocomplete cross-CSV | optional |
| IsRoleAssignable | checkbox | depends on Entra-role assignment intent |
| Workload | dropdown | enum from naming convention |
| Level | dropdown L0..L9 | inherited from Tier per `DESIGN.md` 5.2 |
| TierLevel | dropdown T0/T1/T2 | T1 (permission groups usually T1) |
| Plane | dropdown ID / RES / DAT | ID |
| CPPlatform | dropdown CP / WDP / MP / APP / USER | WDP (permission groups usually workload) |
| Owners | autocomplete tenant users (multi-select) | empty | upn list joined with `\|`; type 3 chars, get displayName + upn |

### PIM-Definitions-AU

| Column | Input | Source / default |
|---|---|---|
| AUDisplayName | text | required |
| AUDescription | text | required |
| AdministrativeUnitTag | auto-derived | from AUDisplayName slug |
| Workload | dropdown | enum |
| Level | dropdown L0..L9 | |
| TierLevel | dropdown T0/T1/T2 | |
| Visibility | dropdown Public / HiddenMembership | Public |

## Assignment CSVs

### PIM-Assignments-Admins (admin -> role-group)

| Column | Input | Source / default |
|---|---|---|
| Username | autocomplete from `Account-Definitions-Admins` UPN | required |
| GroupTag | autocomplete from `PIM-Definitions-Roles` GroupTag | required, FK-validated |
| AssignmentType | dropdown Eligible / Active | Eligible |
| Action | dropdown Assign / Remove | Assign |
| UpdateExisting | dropdown TRUE / FALSE | FALSE |
| AutoExtend | dropdown TRUE / FALSE | TRUE |
| NumOfDaysWhenExpire | dropdown 90 / 180 / 365 / Custom... | 365 |
| Permanent | dropdown TRUE / FALSE | FALSE |
| CPPlatform | inherited from GroupTag | override toggle |
| Plane | inherited from GroupTag | override toggle |
| TierLevel | inherited from GroupTag | override toggle |
| PermissionScope | inherited from GroupTag | override toggle |
| SyncPlatform | inherited from GroupTag | override toggle |

### PIM-Assignments-Groups (role-group nests permission-group)

| Column | Input | Source / default |
|---|---|---|
| TargetGroupTag | autocomplete from `PIM-Definitions-Roles` (the container) | required |
| SourceGroupTag | autocomplete from union of `PIM-Definitions-{Tasks, Services, Processes, Resources, Departments, Organization}` (the member) | required, FK-validated |
| AssignmentType | dropdown Eligible / Active | Active (nested groups are usually permanently nested) |
| Action / UpdateExisting / AutoExtend / Permanent | dropdowns | same defaults as Admins |
| NumOfDaysWhenExpire | dropdown 90 / 180 / 365 / Custom... | 365 |
| CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform | inherited from SourceGroupTag | override toggles |

### PIM-Assignments-Roles-Groups (permission-group -> Entra ID role)

| Column | Input | Source / default |
|---|---|---|
| GroupTag | autocomplete from definition CSVs | required |
| RoleDefinitionName | **dropdown from `cache/entra-roles.json`** | tenant cache, refreshed on startup |
| AssignmentType / Action / UpdateExisting / AutoExtend / Permanent | dropdowns | |
| NumOfDaysWhenExpire | dropdown 90 / 180 / 365 / Custom... | 365 |
| CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform | inherited from GroupTag | |

### PIM-Assignments-Roles-AUs (permission-group -> AU-scoped Entra ID role)

| Column | Input | Source / default |
|---|---|---|
| GroupTag | autocomplete from definition CSVs | required |
| AdministrativeUnitTag | **dropdown from `cache/aus.json`** + cross-CSV from `PIM-Definitions-AU` | required |
| RoleDefinitionName | **dropdown from `cache/entra-roles.json`** | filtered to AU-supported roles |
| AssignmentType / Action / UpdateExisting / AutoExtend / Permanent | dropdowns | |
| NumOfDaysWhenExpire | dropdown 90 / 180 / 365 / Custom... | 365 |
| CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform | inherited | |

### PIM-Assignments-Azure-Resources (permission-group -> Azure RBAC)

| Column | Input | Source / default |
|---|---|---|
| GroupTag | autocomplete from definition CSVs | required |
| AzScope | **tree picker** (MG -> sub -> RG -> resource) backed by `cache/azure-scopes.json` | full ARM path resolved on selection |
| AzScopePermission | dropdown "Common roles" (Owner / Contributor / Reader / User Access Administrator / Storage Blob Data Reader) + "Custom..." -- full Azure RBAC role-name dropdown is v2.3 (needs per-scope role enumeration) | |
| AssignmentType / Action / UpdateExisting / AutoExtend / Permanent | dropdowns | |
| NumOfDaysWhenExpire | dropdown 90 / 180 / 365 / Custom... | 365 |
| CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform | inherited | |

## Cross-cutting UX rules

1. **No typed GUIDs / no typed ARM paths**. Always picker.
2. **No typed role display names**. Always cache-backed dropdown.
3. **Inheritance saves typing**. Selecting a `GroupTag` populates 5
   downstream columns; "override" toggle reveals the underlying cell
   for the rare case where the operator needs to deviate.
4. **Naming convention is auto-applied**. The wizard composes
   `GroupName` and `GroupTag` from semantic inputs (Service, Capability,
   Level, Tier) -- the operator never assembles the slug manually.
5. **Live previews everywhere**. Auto-derived fields show their
   computed value next to the inputs that feed them, before the operator
   commits.
6. **"Custom..." escape hatch on every dropdown**. We never trap the
   operator when the cache is stale or the value is a one-off.
7. **TRUE/FALSE strings are rendered as checkboxes**, but serialized as
   `TRUE` / `FALSE` to keep the CSV diff stable.
8. **Tenant cache auto-refreshes on launch when stale (>24h) or missing**.
   No "click refresh first" cliff for first-time use.
9. **Owners columns are multi-select autocomplete** -- type 3 chars,
   get `displayName <upn>` results from tenant.
10. **Sticky defaults**. Whatever the operator picked last for
    `NumOfDaysWhenExpire`, `AssignmentType`, `AutoExtend` becomes the
    default for the next wizard run in the same session.

## What this spec leaves to v2.3

- Azure RBAC role-name dropdown (per-scope enumeration is N x M).
- Cross-tenant cache (MSP managing many tenants from one Manager
  instance).
- Live-tenant overlay (show CSV vs tenant diff on the graph).
- Approval-flow visualizer (which permission groups require approval +
  who the approvers are).
