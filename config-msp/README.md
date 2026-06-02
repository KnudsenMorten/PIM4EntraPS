# config-msp/

MSP-central admin model, pulled from a central source on every engine run.

This folder holds the data files for admins **owned by the MSP** (or any
central authority -- could be HQ in a multi-subsidiary org). The contents
are not hand-edited on the tenant VM; they're synced from a central
source (git / blob / https) at the start of every `-ConfigVariant msp`
engine run.

## How it works

1. On every `-ConfigVariant msp` launcher call, the engine invokes
   `Sync-PimMspConfig` (function in `engine/_shared/PIM-Functions.psm1`).
2. Sync-PimMspConfig reads `msp.source.json` in this folder.
3. It clones/downloads from the source URL, picks out the standard
   PIM4EntraPS CSV + helper files, atomically stages them here.
4. The engine then runs as normal -- but reads from `config-msp/` instead
   of `config/`, writes state to `output/msp/` instead of `output/`, and
   only touches admins matching the MSP filter (see "Foreign-admin
   isolation" in `../config-local/README.md`).

The result: a single MSP edit + commit propagates to every customer
tenant on its next cron tick. Worst-case propagation = the slowest
tenant's cron interval.

## Setup

```powershell
# 1. Copy the source manifest template + fill it in.
Copy-Item msp.source.sample.json msp.source.json
notepad msp.source.json   # set sourceType, url, branch, subPath, auth

# 2. If using a PAT for git auth, set the env var named in msp.source.json
#    on the tenant VM (e.g. via Set Machine env var, or in the scheduled
#    task's runtime context):
[System.Environment]::SetEnvironmentVariable('PIM_MSP_GIT_PAT', '<your-PAT>', 'Machine')

# 3. Test the sync standalone:
Import-Module .\..\engine\_shared\PIM-Functions.psm1 -Force
$global:PIM_ConfigVariant = 'msp'
Sync-PimMspConfig

# 4. Schedule the engine with -ConfigVariant msp. Recommended: stagger
#    after the local-variant run so they don't compete on Graph throttling.
#       04:00  PIM-Baseline-Management-CSV  -ConfigVariant local
#       04:30  PIM-Baseline-Management-CSV  -ConfigVariant msp
```

## Kill-switch model (CISO opt-in per admin)

For each MSP-managed admin the customer's CISO wants to allow central
disable/revoke for:

1. **CISO** writes a per-admin secret to the customer's Key Vault:
   - Vault: the one named in `$global:PIM_StatusChange_KeyVaultName`
     (set in `repository.custom.ps1`).
   - Secret name: `pim-status-<slug>` where `<slug>` is the admin UPN
     lower-cased with `@` and `.` replaced by `-`. Example:
     `pim-status-admin-msp-mok-t0-id-contoso-onmicrosoft-com`
   - Secret value: any string. Treat as a shared secret with the MSP.

2. CISO tells the MSP the code (out-of-band -- 1Password / encrypted
   mail / phone).

3. MSP, when they want to disable or revoke this admin tenant-wide:
   - Sets `AccountStatus = Disabled` or `Revoked` in their central CSV.
   - Sets `StatusChangeCode = <the agreed code>`.
   - Commits. Every tenant pulls + the engine acts on next run.

If the code doesn't match (or the KV secret doesn't exist), the engine
**refuses** the status change and writes a row to
`output/msp/status-change-DENIED-<yyyyMMdd>.csv` for review.

Default-deny: no KV secret = central kill-switch off for that admin.
CISO must opt in per admin.

## Files in this folder

- `msp.source.json`           -- gitignored: customer's actual source config.
- `msp.source.sample.json`    -- tracked: template to copy.
- `*.locked.csv`              -- synced from central (engine reads these).
- `*.locked.ps1`              -- synced from central (engine reads these).
- `*.custom.csv`              -- gitignored: not used in MSP variant (central
                                 source is authoritative). Don't create.

A `.custom.sample.*` placeholder may sit here for any file customers
might want to override locally on top of the MSP sync, but the default
expectation is "MSP is authoritative -- if you need a local override,
work it back into the central source instead".
