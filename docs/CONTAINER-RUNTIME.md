# PIM4EntraPS — cloud-native container engine (no local VM)

The local-plane engine can run as a **scheduled container** inside the customer's
own VNet — no VM to build or patch. Proven 2026-06-12: a container in the customer
VNet resolved the MSP storage to the cross-tenant private-endpoint IP, pulled the
**signed** baseline (storage public-disabled, so only the approved PE could carry
it), verified the signature, and **created accounts** in the customer's Entra
(`SIGNATURE_VALID=True`, `CREATED Admin-CONTAINER-ID`).

Files: `engine/container/Dockerfile`, `engine/container/Start-PimEngineContainer.ps1`.

## What the container does (per run)
1. Acquire a Microsoft Graph token for the per-tenant identity.
2. **Pull + verify** the MSP signed baseline over the (cross-tenant) private endpoint — RSA-SHA256 against the embedded public cert, plus expiry + anti-rollback.
3. Read the customer's own local store (`Owner=Local` rows) — optional.
4. **Merge** baseline (`Owner=MSP`) + local and create/maintain the accounts in this tenant.

It is REST-based (no Graph SDK / SqlServer module) to stay small and avoid the Azure.Core assembly conflict.

## Identity (pick one, via `PIM_AUTH_MODE`)
- **ManagedIdentity** (recommended) — ACI/Container Apps system-assigned MI, granted the engine Graph app roles + Storage Blob Data Reader + (if used) SQL `db_datareader`. No secret to manage.
- **Certificate** — `PIM_CERT_PFX_B64` + `PIM_CERT_PFX_PWD`; the entrypoint builds a client-assertion JWT. The per-tenant app trusts the cert.
- **ClientSecret** — `PIM_CLIENT_SECRET` (inject as a secure env / Key Vault reference). Simplest; rotate regularly.

## Environment variables
| Var | Meaning |
|---|---|
| `PIM_TENANT_ID` / `PIM_CLIENT_ID` | customer tenant + per-tenant engine app id |
| `PIM_AUTH_MODE` | `ManagedIdentity` \| `Certificate` \| `ClientSecret` |
| `PIM_BASELINE_URL` | HTTPS URL of `baseline-latest.json` (resolves to the PE in-VNet) |
| `PIM_BASELINE_PUBCERT` | base64 of the MSP baseline public cert (verification) |
| `PIM_DEFAULT_DOMAIN` | tenant default domain for UPNs |
| `PIM_WHATIF` | `true` (default, plan only) \| `false` (create) |
| `PIM_LOCAL_SQL_SERVER` / `PIM_LOCAL_SQL_DB` | optional local store (default DB `PimLocal`) |

## Build + push
```
docker build -t <acr>.azurecr.io/pim-engine:latest -f engine/container/Dockerfile .
docker push <acr>.azurecr.io/pim-engine:latest
```

## Run as ACI in the customer VNet (proven shape)
- Deploy into a subnet delegated to `Microsoft.ContainerInstance/containerGroups`.
- Customer private DNS zone `privatelink.blob.core.windows.net` resolves the baseline storage FQDN to the cross-tenant PE IP, so the pull stays on the Microsoft backbone (no internet).
- `RestartPolicy=Never` for a one-shot job; schedule via a Logic App timer / Container Apps **Job** cron / an ACI start on a schedule.

## Scheduling
- **Container Apps Job** with a cron trigger (cleanest managed scheduler), or
- **ACI** started by a Logic App / Automation timer, or
- An on-prem scheduler invoking `az container start`.

## On-prem (VMware) customers
Same `Start-PimEngineContainer.ps1` logic runs on a Windows VM instead — identical code, different host. Container = zero-VM cloud-native option; VM = on-prem option. Both first-class (see MSP-ARCHITECTURE.md § 11a).

## Security
- Storage stays `publicNetworkAccess=Disabled`; the container reaches it only via the approved cross-tenant private endpoint (or a customer-hosted copy).
- The baseline is **signed, not encrypted** — the container verifies with the **public** cert (no secret at the receiver); tampering is rejected.
- The container's identity lives in the **customer** tenant → customer-owned Conditional Access, attribution, and revocation. The MSP never reaches into the customer.
