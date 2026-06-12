# PIM4EntraPS — MSP edition architecture (components, layers, flows)

Status: proof-of-concept built + tested on real cross-tenant infrastructure (2026-06-12).
Companion to LIFECYCLE-GOVERNANCE.md § 19 (design rationale). This file is the
concrete "what runs where, and how data moves" reference.

---

## 1. The two planes

| Plane | Who | Stores | Network posture |
|---|---|---|---|
| **Admin plane (MSP)** | MSP operators | Central registry SQL + signing keys | Private-endpoint only; inbound clamped to jumphost/PAW/SAW IPs |
| **Local plane (per customer)** | the customer's local IT | The customer's own local SQL store | In the customer's own tenant/VNet; reached privately by the local engine |

The two planes are **separate networks that never see each other.** Only **signed
artifacts** cross the boundary (baseline bundle one way, status summary the other).
No SQL-to-SQL link, no MSP standing connection into a customer, no foreign acting
identity in the customer tenant.

---

## 2. Components (every element)

**Admin plane (MSP tenant):**
- `Central registry SQL` — `platform.Tenants`, `platform.TenantApps`, `pim.CentralAdmins` (Owner=MSP baseline), `platform.AuditEvents`, `pim.vw_AdminTenantTargets`. Entra-only auth, public access disabled, private endpoint. *(lab: `sql-pimplatform-we484`, westeurope, PE 10.100.20.5)*
- `Baseline blob storage` — holds the signed baseline bundles. Public access disabled, private endpoint. *(lab: `stpimbaseline78057`, container `baselines`)*
- `Signing keys` (non-exportable, machine cert store, never distributed):
  - `CN=PIM4EntraPS-Licensing` → signs `.pimlicense` (Pro entitlement)
  - `CN=PIM4EntraPS-Baseline` → signs baseline bundles
- `setup/New-PimBaselineBundle.ps1` — **producer**: reads Owner=MSP rows → signs → uploads.
- `setup/Invoke-PimMspFanout.ps1` — registry-driven multi-tenant account fan-out (Pro).
- `Manager (admin)` — App Service, private-endpoint only, inbound = admin IPs. *(lab: `app-pim-manager-2lk4175`)*

**Local plane (each customer tenant):**
- `Local store SQL` (`PimLocal`) — `pim.LocalAdmins` (Owner=Local), `pim.LocalResources`. Entra-only, in the customer's own subscription. *(lab: managedoperation `sql-pimlocal-mgmtop-59449` DK East; Test `sql-pimlocal-testtenant-7330` West Europe — both public + firewall-to-mgmt-IP as the cross-tenant PE exemption)*
- `Per-tenant engine SPN` + **certificate** — the acting identity, registered **in the customer tenant** (Model B). Customer owns its CA, attribution, revocation.
- `setup/Invoke-PimLocalApply.ps1` — **local engine apply**: reads the local store, provisions accounts into the tenant.
- `engine/_shared/PIM-Baseline.ps1` — **consumer**: pulls + verifies the signed bundle (embedded PUBLIC baseline cert).
- `engine/_shared/PIM-License.ps1` — offline Pro gate (embedded PUBLIC licensing cert).
- `engine/_shared/PIM-Functions.psm1` — the declarative engine (`CreateUpdate-Accounts-From-file-CSV`, merge, audit).

**Shared contract (one core, pluggable edges):**
- Auth profile: per-tenant cert (default) | GDAP (CSP niche) | on-prem gMSA.
- Storage profile: CSV | local SQL | central partition.

---

## 3. Layers

```
  L4  Identity / RBAC : per-tenant SPN+cert (local) · signing keys (MSP) · customer CA
  L3  Application     : Manager (admin) · engine apply (local) · producer/consumer (courier)
  L2  Data            : central registry SQL (MSP) | local store SQL (customer)  -- NEVER linked
  L1  Transport       : signed artifacts only (bundle in / summary out) over HTTPS
  L0  Network         : private endpoints; separate VNets; no cross-tenant DB path
```

Ownership tag (`Owner=MSP` | `Owner=Local`) is **provenance**, not a permission gate:
MSP rows are refreshed on each baseline pull (so not hand-edited locally); local rows
are the customer's, fully autonomous (any Purpose incl. privileged, no MSP request).

---

## 4. Architecture diagram

```
        MSP TENANT (admin plane)                       CUSTOMER TENANT (local plane)
   ┌───────────────────────────────────┐         ┌────────────────────────────────────┐
   │  Central registry SQL  (Owner=MSP) │         │  Local store SQL  (Owner=Local)     │
   │   private endpoint, Entra-only     │         │   in customer's own sub, Entra-only │
   │            │                       │         │            ▲                        │
   │            │ read Owner=MSP rows   │         │            │ read local rows        │
   │            ▼                       │         │            │                        │
   │  New-PimBaselineBundle.ps1         │         │  Invoke-PimLocalApply.ps1           │
   │   • build payload (versioned)      │         │   • read local store (child proc)   │
   │   • SIGN  (private baseline key)   │         │   • Connect-MgGraph (per-tenant SPN)│
   │            │                       │         │   • MERGE: baseline + local         │
   │            ▼                       │         │   • create accounts IN THIS TENANT  │
   │  Baseline blob (private endpoint,  │         │            ▲                        │
   │   public disabled) — signed bundle │         │            │ verified rows          │
   │            │                       │         │  PIM-Baseline.ps1 (consumer)        │
   └────────────┼───────────────────────┘         │   • HTTPS GET signed bundle         │
                │                                  │   • VERIFY (embedded PUBLIC key)    │
                │                                  │   • expiry + anti-rollback check    │
                │   LOCAL PULLS the signed bundle  │            │                        │
                ◀──────────── HTTPS GET ───────────┤            ▼                        │
                  (private door, or public+signed) │     Entra ID / Azure RBAC (tenant)  │
                  MSP only hosts+signs; it never    │     ← accounts, groups, scopes      │
                  writes into / connects to cust.   └────────────────────────────────────┘
                                  ▲
                  status summary  │  (signed, counts only — local → MSP fleet view,
                                  │   ideally via the customer's own Log Analytics)
```

---

## 5. Flow A — MSP baseline distribution (build + sign + publish + pull + verify)

1. MSP edits Owner=MSP baseline in the central registry (naming, rings, standard templates).
2. `New-PimBaselineBundle.ps1` reads `pim.CentralAdmins WHERE Owner='MSP'`, builds a versioned payload (`version`, `generatedAtUtc`, `validToUtc`, `rows`).
3. It **signs** the payload bytes RSA-SHA256 with the non-exportable `CN=PIM4EntraPS-Baseline` private key → `{ payloadB64, signature, keyThumbprint }`.
4. It uploads `baseline-v<ts>.json` + `baseline-latest.json` to the baseline blob (private endpoint, public disabled).
5. The bundle reaches the customer's network by one of the transports in § 7.
6. The local engine's `PIM-Baseline.ps1` does an **HTTPS GET** of the bundle (over the customer's private endpoint).
7. It **verifies**: signature against the embedded PUBLIC baseline cert; `product/kind`; not expired; version ≥ last-applied (**anti-rollback**). Any tamper → rejected, nothing applied.
8. On success it returns the Owner=MSP rows for the merge, and records the applied version.

## 6. Flow B — local apply (true env: local store → real accounts)

1. `Invoke-PimLocalApply.ps1` runs for one tenant with that tenant's engine SPN (cert).
2. It reads `pim.LocalAdmins` from the local store **in a child process** (SqlServer's Azure.Core would otherwise break Graph app-only).
3. It `Connect-MgGraph` app-only as the per-tenant SPN and resolves the tenant default domain.
4. It **merges** the pulled-down MSP baseline (Flow A) with the Owner=Local rows.
5. It runs the engine (`CreateUpdate-Accounts-From-file-CSV -OnlyID`) to **create the accounts in this tenant** — both the MSP central admins (from the baseline) and the local admins. Replication-404 on the post-create PATCH is retried.
6. Every change is audited (`local.apply`) in the customer's own tenant.

## 7. Transport — LOCAL PULLS MSP (one direction, always)

**The model is fixed: the local engine PULLS the signed bundle from the MSP. The MSP never writes into, or opens a connection into, the customer tenant.** The MSP only hosts a signed file; the customer reaches out and reads it. (An earlier "MSP writes into the customer's storage" idea is explicitly rejected — it would give the MSP reach into the customer, which we do not want.)

The only choice is the **path the local pull takes** to reach the MSP-hosted file:

1. **Private door (cross-tenant Private Endpoint by approval).** The customer creates a PE in *their* VNet targeting the MSP storage's resource id; the MSP **approves** the pending connection (the approval is the only thing the MSP does, and it grants the MSP nothing in the customer tenant). The pull then rides the Microsoft backbone — no internet. Revoke = customer deletes the PE. *(detail diagram below)*
2. **Public-but-signed + IP allowlist.** The MSP file is reachable over HTTPS, firewalled to the customer's egress IP; the local engine pulls over the internet. Safe because the **signature**, not the network, establishes trust.

Optionally the local engine **caches its own copy** of the pulled bundle in the customer's own storage — still a local-pull, just with a local copy. Either way: customer reads, MSP never writes. The integrity guarantee is always the **signature**; the private endpoint only removes public surface.

### Option 2 detail — cross-tenant Private Endpoint by approval

```
  CUSTOMER TENANT  (local engine)                       MSP TENANT  (owns storage)
  ┌─────────────────────────────────────┐              ┌────────────────────────────────┐
  │  Local engine                        │              │  Baseline blob storage         │
  │    │ resolves <acct>.privatelink     │              │   = Private Link RESOURCE      │
  │    ▼ .blob.core.windows.net          │              │   publicNetworkAccess=Disabled │
  │  Private Endpoint NIC ● 10.<cust>.x  │              │            ▲ (data plane)       │
  │   (targets MSP storage by RESOURCE   │              │            │                   │
  │    ID, subresource = blob)           │              │            │                   │
  └─────────┬────────────────────────────┘              └───────────┼────────────────────┘
            │                                                        │
   (1) customer CREATES the PE ─────────────────────────────────────▶ connection = PENDING
   (2) MSP APPROVES ("by trust") ◀──────────────────────────────────  owner accepts this customer
   (3) PRIVATE path over the Microsoft backbone:
       local engine ─▶ PE NIC (customer VNet) ═══ Azure backbone ═══▶ MSP storage
            (no public internet either side; MSP storage stays public-disabled)
```

Steps: (1) the customer creates the PE in *their* VNet with `PrivateLinkServiceId=<MSP storage resourceId>`, `GroupId=blob` — cross-tenant → status **Pending**; (2) the **MSP approves** the pending connection (`Approve-AzPrivateEndpointConnection`) and grants the customer SPN `Storage Blob Data Reader` — the approval *is* the trust handshake; (3) the customer's `privatelink.blob.core.windows.net` resolves to the PE in their own VNet and traffic rides the backbone. Revoke: customer deletes the PE, or MSP rejects the approval / pulls RBAC. Content is signed regardless.

## 8. Flow C — status rollup (local → MSP)

The local engine emits a **signed summary** (drift/compliance counts, never raw privileged data) — ideally into the customer's **own Log Analytics** (via `AzLogDcrIngestPS`), which the MSP reads. One-directional; MSP never reaches in.

---

## 9. Credential & trust model

- **Acting identity is local.** Each customer tenant has its own engine SPN + non-exportable cert (Model B). The customer owns its Conditional Access, attribution (actions log as a named app in *their* tenant), lifecycle, and instant revocation. No GDAP, no foreign multi-tenant identity (EA/MCA-friendly).
- **Asymmetric signing, no secret at the receiver.** Baseline + license use a private key on the MSP host and a PUBLIC verification cert embedded in the product. Local needs **no secret key** — it only verifies. Bundles are **signed, not encrypted** (transparency: the customer reads exactly what the MSP ships).
- **Two approval types, kept separate:** delegation-time approval is ours (Manager/declarative); **activation approval is native Entra PIM policy** (which the engine *configures*, e.g. `approval-required`, but does not mediate) — the Manager is not in the activation path.

## 10. Security properties (what each control buys)

| Threat | Control |
|---|---|
| Tamper with bundle in transit / at rest / on the distribution point | RSA-SHA256 signature → verify with embedded public key → rejected |
| Forge a bundle | Impossible without the MSP private key (non-exportable, machine store) |
| Roll back to an old baseline | Version-monotonic check (`baseline-state.json`) |
| Replay an expired baseline | `validToUtc` check |
| Hacker reaches the SQL | Private endpoint / public-disabled + Entra-only (no SQL logins) + (cross-tenant) firewall to known IP |
| MSP over-reach into customer data | No standing connection; only signed artifacts cross; acting identity is customer-owned |
| Local self-service abuse | Out of scope by design — activation stays behind native PIM MFA + approval |

## 11a. Engine runtime — cloud-native container (no local VM required)

The local engine does **not** need a VM in the customer's environment. It can run as a **scheduled container** (Azure Container Instances / Container Apps Job) **inside the customer's VNet**:
- The container resolves the MSP storage FQDN via the customer's private DNS → the **cross-tenant private endpoint** → pulls + verifies the signed baseline. *(Proven: a `mcr.microsoft.com/powershell` container in the customer VNet resolved the storage to the PE IP and pulled the signed bundle while MSP storage was public-disabled — `SIGNATURE_VALID=True`, 3 rows.)*
- The same container reads the local store (SQL/CSV), merges, and applies to Entra/Azure with the per-tenant cert / managed identity.
- Scheduling: ACI restart policy / Container Apps Job / Logic App timer. No VM to patch.

On-prem (VMware) customers run the identical engine on a Windows VM instead — same code, different host. Container is the zero-VM cloud-native option; VM is the on-prem option. Both are first-class.

## 11. Built + tested vs designed

**Built + tested (POC, 2026-06-12):** central registry SQL (private endpoint); per-customer local store SQL in each customer's **own** subscription; `Invoke-PimLocalApply` provisioning real accounts in both customer tenants from their local stores; baseline courier (producer sign → private-endpoint blob → consumer pull + verify + **tamper-reject**); offline Pro licensing; per-tenant cert auth incl. app-only activator backend deploy.

**Designed, not yet built:** the repository abstraction so the Manager/engine read SQL directly (today the engine path is via generated CSV); the customer-hosted-storage transport (§ 7 option 1) wiring; the signed status-rollup sink; GDAP and on-prem-gMSA auth profiles; the local self-service portal.
