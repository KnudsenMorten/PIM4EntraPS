# PIM4EntraPS licensing — Core (free) + Pro (offline license)

## Model

- **Core is free** and fully functional: the single-tenant declarative engine, all configuration CSVs, the PIM Manager (grid, wizards, map, validator, Review & Save), admin lifecycle (create/TAP/offboard), policy templates, owners-as-approvers, audit — **and the SQL data store** (operator decision: SQL is Core, never licensed).
- **Pro features require a license file**: MSP multi-tenant (registry + ring fan-out), workload connectors (Defender XDR Unified RBAC, …), external intake (ServiceNow), access reviews, self-service delegation, contacts/email-flow routing.

Feature catalog (gate names): `MspFanout`, `WorkloadConnectors`, `Intake`, `AccessReviews`, `SelfService`, `ContactsRouting`.

## The license is 100% offline

Customers receive a `.pimlicense` file and drop it into `config\`. Nothing phones home; no public endpoint, no activation server, no internet access needed on the automation server. Verification is an RSA-SHA256 signature check against the **public** certificate embedded in `engine/_shared/PIM-License.ps1` (PS 5.1-safe: raw-bytes `X509Certificate2`, no PEM parsing).

The signing **private key is a non-exportable machine-store certificate on the maintainer's management host** (`CN=PIM4EntraPS-Licensing`) — the same trust model as the PIM Activator extension signing key. Licenses are issued with the internal-only `INTERNAL\pim-licensing\New-PimLicense.ps1`, which never ships.

File format:

```json
{ "product": "PIM4EntraPS", "payloadB64": "<base64 payload JSON>", "signature": "<base64 RSA-SHA256>" }
```

Payload: `licenseId, customer, sku, features[] ('*' = all), tenantIds[], validFrom, validTo, graceDays`. The signature covers the exact payload bytes — any edit (name, dates, features, tenants) invalidates the file.

## Semantics

| Aspect | Behavior |
|---|---|
| Tenant binding | `tenantIds` non-empty → the connected Entra tenant must be listed. The MSP fan-out checks per tenant and **skips** unlicensed tenants (the rest of the fleet still deploys). Empty list = any tenant (evaluations). |
| Expiry | After `validTo`, a grace window (`graceDays`, default 30) keeps Pro working with a renew warning. After grace, Pro features disable. **Core is never affected — an expired license can never break a tenant.** |
| Visibility | Manager Governance tab shows a License panel (status, features, tenants, expiry, grace warning); engine runs print one status line; blocked gates emit one operator-facing message + a `license.blocked` audit event. |
| Enforcement honesty | PowerShell is source-distributed — the in-product gate is a compliance/UX mechanism, not DRM. The real boundary is distribution: Pro feature code should ship from a private channel to licensed customers (Core stays public). The license file makes entitlement provable offline on both sides. |

## Gating a feature (pattern)

```powershell
if (-not (Test-PimProFeature 'MspFanout')) { return }                    # whole feature
if (-not (Test-PimProFeature 'MspFanout' -TenantId $t.TenantId)) { ... } # per tenant
```

`Get-PimLicense` (cached, `-Refresh` to re-read), `Test-PimProFeature`, `Get-PimLicenseStatusText` live in `engine/_shared/PIM-License.ps1`, dot-sourced by the engine module and the Manager.

## Issuing (maintainer host only)

```powershell
.\INTERNAL\pim-licensing\New-PimLicense.ps1 -Customer 'Contoso A/S' `
    -TenantIds '<tenant-guid>','<tenant-guid>' -Years 1 -OutFile C:\TMP\Contoso.pimlicense
```

`*.pimlicense` is gitignored everywhere — customer licenses never enter the repo.
