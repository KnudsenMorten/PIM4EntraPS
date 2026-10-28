# config/msp/

Build configs for a **managing tenant** (an MSP's own PIM Manager that publishes a signed baseline) and its
**managed tenants** (each customer's own PIM Manager that pulls that baseline), for the one-command multi-tenant
build `tools/setup/Invoke-PimMspBuild.ps1`.

| File | What it is |
|---|---|
| `managing-tenant.sample.json` | Sample config for the managing tenant (`-Role Master`). |
| `managed-tenant.sample.json` | Sample config for a managed tenant (`-Role Slave`), enrolled with an Invardia enrollment key. |
| `managing-tenant.json`, `managed-tenant.json` | **Your** copies -- git-ignored, never committed. |

A build config holds **ids and names only**. The build refuses a config that carries anything that looks like a
credential (a secret, password, SAS URL, account key, connection string or PEM) and names the key it refused.

## What you need

- **PowerShell 7** on your own machine. **No Azure CLI and no PowerShell modules** -- every Azure, Microsoft Graph and
  SQL call is REST.
- To **sign in in the browser** as an administrator of the tenant you are building (the build opens the sign-in for
  that tenant). Rights: Owner (or Contributor + User Access Administrator) on the subscription; in Entra ID
  Privileged Role Administrator, Application Administrator and Groups Administrator; Exchange Administrator only if
  the build should set up the notification mailbox.
- A PIM Manager **Pro** licence for the managing tenant (bought at invardia.com): add `"licence": { "path":
  "<file>.pimlicense" }` to its config and the build registers it. A managed tenant gets its licence through the
  **enrollment key** its managing company issues.

## 1. Build the managing tenant

```powershell
Copy-Item .\config\msp\managing-tenant.sample.json .\config\msp\managing-tenant.json
# edit: tenant + subscription ids, resource group, region, names, the bundle storage account, superadmins

.\tools\setup\Invoke-PimMspBuild.ps1 -Role Master -ConfigPath .\config\msp\managing-tenant.json           # the plan only
.\tools\setup\Invoke-PimMspBuild.ps1 -Role Master -ConfigPath .\config\msp\managing-tenant.json -Apply    # build
```

The build runs, in order and idempotently: the hosting step (network, registry, identities, database, container
image, Container Apps environment and apps, database schema, notification mailbox, feature settings, Easy Auth
sign-in, the application, the updater), the SQL admin group, the engine and PIM Manager identities' Microsoft Graph
permissions, the scenario, the managed-tenant registry, the signed-baseline storage and its network rules, the
**signing key** (a non-exportable key in the Key Vault named in `keyVaultName`), the daily publish job, the first
publish, and the **enrollment** step that records the bundle's address and signing key id and reports them to
Invardia.

- `slaves[]` lists the managed tenants you register up front (ring and tags). It may be empty: enrolled managed tenants
  are allowed on the bundle store by the managing tenant's daily **enrolled-tenants** job, and you can register a
  tenant later in PIM Manager.
- The **signingkey** step prints the signing key id. Managed tenants built with an enrollment key receive it from
  Invardia; a managed tenant built without one needs it in its `master.signingKeyIds`.

## 2. Issue an enrollment key at Invardia

For each customer, issue a **managed-tenant enrollment key** at invardia.com. Give the key to the customer over a
channel you trust. It is a bearer secret: it is used once, for the claim, and is never written to a config file, a log
or the build's output (it is shown masked).

## 3. Build each managed tenant

**The one command from Invardia (recommended).** The customer runs the installation command Invardia's wizard gives them
(the guided install, with the managed-tenant role and the enrollment key). It runs this same build for them and reports
every step to the tracked install at Invardia.

**Or run the build yourself:**

```powershell
Copy-Item .\config\msp\managed-tenant.sample.json .\config\msp\managed-tenant.json
# edit: tenant + subscription ids, resource group, region, names, superadmins, the address plan

.\tools\setup\Invoke-PimMspBuild.ps1 -Role Slave -ConfigPath .\config\msp\managed-tenant.json -EnrollmentKey <key>          # the plan only
.\tools\setup\Invoke-PimMspBuild.ps1 -Role Slave -ConfigPath .\config\msp\managed-tenant.json -EnrollmentKey <key> -Apply   # build
```

With the enrollment key the build first **claims** the tenant at Invardia (step `enroll`): Invardia creates the
environment under the managing company, signs the licence and returns the managing tenant's bundle address and signing
key ids. Then: hosting, SQL admin group, Graph permissions, scenario, the **licence**, the pull network (its subnet id
is reported to Invardia, and the managing tenant's enrolled-tenants job allows it -- nothing to hand over by hand), the
signed-bundle **pull job**, and the end-of-install check.

- After the first build, the build prints the `master` block it was given. Add it to `managed-tenant.json` to re-run
  the build later **without** the key (every claim issues a new install key, so a re-run never claims again unless you
  pass `-EnrollmentKey` on purpose).
- **Without an enrollment key**, add the `master` block yourself (the managing tenant's `tenantId`, `storageAccount`,
  `container` and `signingKeyIds`), and give the subnet id the `pullnetwork` step prints to the managing company: they
  add it as `slaves[<n>].subnetResourceId` and re-run their build `-From network-<n>`.

## Progress, resume and exit codes

- Every step -- and, inside the long hosting step, every sub-step (`hosting.prereq`, `hosting.image`, `hosting.infra`,
  `hosting.sqlaccess`, `hosting.schema`, `hosting.mailsender`, `hosting.features`, `hosting.easyauth`, `hosting.code`,
  ...) -- is shown on the console and reported to the tracked install at Invardia, so a long step shows progress
  instead of minutes of silence.
- A failed step prints the cause and the resume command: `-From <step>`. Every step checks what exists first, so
  running a step again is safe.
- Exit codes: `0` complete; `1` refused or a step failed; `2` incomplete (every step that could run succeeded, but a
  step is waiting for something, for example a managed tenant's subnet id).
- `-WhatIf` (or leaving out `-Apply`) prints the plan and the steps that need a person; nothing is claimed, signed in,
  created or granted.
