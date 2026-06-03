# PIM Activator (browser extension)

Companion Manifest V3 extension to **PIM4EntraPS** for **Edge and
Chrome**: bulk-activate eligible PIM-for-Groups memberships from the
toolbar instead of clicking through the Entra portal one role at a time.

Hosted on GitHub Pages: `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`.
Deterministic extension id: `hkdglhgahonnjbfindmgplekkcngmcck`.

```
[ extension icon ]  -->  popup
                          - PIM-Helpdesk-L1                 [x]
                          - PIM-Sharepoint-SiteAdmins-L2    [ ]
                          - PIM-AzRes-MP-Platform-L3        [x]
                          Justification: "ticket INC1234"
                          Duration:      1 hour
                          [Activate selected]   -->  3 POSTs to Graph
```

Single Graph round-trip per group (Graph's PIM-for-Groups API requires it),
but the user sees one click instead of N portal navigations.

---

## What's new in v1.1.0

Multi-tenant support. The managed-policy schema now accepts a
`Tenants` array:

```json
{
  "Tenants": [
    { "Name": "ACME Production",  "TenantId": "...", "ClientId": "..." },
    { "Name": "ACME Test",        "TenantId": "...", "ClientId": "..." },
    { "Name": "Customer A",       "TenantId": "...", "ClientId": "..." }
  ]
}
```

Behaviour:

- 0 tenants -- popup says "not configured".
- 1 tenant -- used silently (same as v1.0).
- 2+ tenants -- popup shows a tenant picker on first run per browser
  profile; the choice is cached in `chrome.storage.local`. Footer shows
  the friendly name + a `(switch)` link that clears the cached pick and
  re-renders the picker. Per-profile only -- other Edge / Chrome profiles
  keep their own choice.

Backwards compatible: the v1.0 singleton `tenantId` / `clientId` keys
still work as a fallback when no `Tenants` array is present.

---

## File layout

```
tools/pim-activator/
  manifest.json                              # MV3 manifest (Edge + Chrome)
  popup.html / popup.js                      # the popup UI + tenant picker
  managed_schema.json                        # Tenants array schema + legacy keys
  config.template.js                         # copy -> config.js for dev-mode
  icons/icon-16.png / icon-32.png / icon-128.png
  Deploy-PimActivatorBackend.ps1             # ONE-TIME tenant setup (per Entra tenant)
  Deploy-PimActivatorIntune.ps1              # Intune Remediation + local-installer generator
  Deploy-PimActivatorClient.ps1              # Direct local registry write (dev / single box)
  Deploy-PimActivatorPolicy-Admx.ps1         # ADMX template emitter (AD GPO authoring)
  Setup-PimActivator.ps1                     # End-to-end interactive setup wrapper
  README.md
```

> **Auth stack:** the popup uses `chrome.identity.launchWebAuthFlow` + PKCE
> directly against the Entra v2 endpoints (`/oauth2/v2.0/authorize` +
> `/oauth2/v2.0/token`). No third-party libraries -- vanilla JS + the Web
> Crypto API for the SHA-256 challenge. This is the canonical auth pattern
> for Chromium-family MV3 extensions: it avoids the MSAL.js popup-closes-on-
> blur pitfall and keeps the shipped bundle small. The refresh token is
> cached in `chrome.storage.local` so silent reauth works across popup
> sessions until the user revokes consent or hits the Entra refresh-token
> lifetime cap.

---

## Two-stage rollout

### Stage 1 — one-time tenant setup (run once, in the admin tenant)

Create the app registration the extension authenticates against. Requires
**Application Administrator** (or higher) and these Graph scopes on the
caller: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`,
`DelegatedPermissionGrant.ReadWrite.All`.

```powershell
# 1. Load the extension unpacked once to discover the extension id assigned
#    by Edge (edge://extensions -> Developer Mode -> Load unpacked).
#    The id is a 32-char lowercase string (a-p).
$extId = 'abcdefghijklmnopabcdefghijklmnop'

# 2. Connect to Microsoft Graph against the right tenant.
Connect-MgGraph -TenantId 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' `
                -Scopes  'Application.ReadWrite.All',
                         'AppRoleAssignment.ReadWrite.All',
                         'DelegatedPermissionGrant.ReadWrite.All'

# 3. Create the app, wire SPA redirect URI + delegated perms, grant consent.
.\Deploy-PimActivatorBackend.ps1 -ExtensionId $extId -GrantConsent
```

Output is the `tenantId` + `clientId` you'll feed into Stage 2. Permissions
configured on the app registration:

- `PrivilegedAccess.ReadWrite.AzureADGroup` (delegated)
- `Group.Read.All` (delegated)
- `User.Read` (delegated)

SPA redirect URI: `https://<ExtensionId>.chromiumapp.org/`

Re-running the script with the same `-DisplayName` updates the existing app
in place rather than creating a duplicate.

Repeat Stage 1 once per Entra tenant you want the picker to offer. Capture
each `(Name, TenantId, ClientId)` triple into a CSV (`tenants.csv`):

```
Name,TenantId,ClientId
ACME Production,f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e,11111111-2222-3333-4444-555555555555
ACME Test,11112222-3333-4444-5555-666677778888,99998888-7777-6666-5555-444433332222
Customer A,aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,22221111-3333-4444-5555-666666666666
```

That CSV is the input to every Stage 2 path below.

### Stage 2 -- choose a rollout path

The extension reads its config from Chromium's `chrome.storage.managed`,
which Edge / Chrome populate from the policy registry tree
`HKCU|HKLM\SOFTWARE\Policies\{Microsoft\Edge | Google\Chrome}\3rdparty\extensions\<ExtensionId>\policy`.
**All three rollout paths write the same registry keys** -- only the
delivery mechanism differs. Pick one:

| Path | Best for | Self-heal | Admin tooling |
|---|---|---|---|
| Intune Remediation | Intune-managed estates | Hourly (Intune-scheduled) | Intune Admin Center |
| Local installer (GPO / file share / SCCM) | AD-managed estates, no Intune | Per-logon (GPO) or per-deployment | Group Policy Management |
| Direct local registry write | Dev box, single-machine testing | None (one-shot) | none |
| Server install (PAW / jump box) | Windows Server hosts where admins RDP in | None (one-shot) or per-boot (GPO Startup) | manual / GPO |

#### Path A -- Intune Remediation (recommended for Intune estates)

`Deploy-PimActivatorIntune.ps1` reads `tenants.csv`, generates a
Detection + Remediation script pair, uploads them as an Intune device
health script, and schedules hourly. Detection script compares the
on-disk `Tenants` JSON against the desired JSON; drift -> exit 1 ->
Intune fires the remediation, which rewrites every key from scratch.

```powershell
# Connect once with the right scope.
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All',
                        'Group.Read.All'

# First time -- create + (optionally) auto-assign in one shot.
.\Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation `
    -TenantsCsv .\tenants.csv `
    -GroupId    11111111-2222-3333-4444-555555555555
# -> prints: Remediation id: <guid>   <-- save this for later updates

# -GroupId is OPTIONAL. Omit it to create the remediation unassigned, then
# assign manually via Intune Admin Center -> Devices -> Scripts and
# remediations -> open the new remediation -> Assignments -> Add groups.
```

**Add a tenant later:** edit `tenants.csv`, then push the change:

```powershell
.\Deploy-PimActivatorIntune.ps1 -UpdateIntuneRemediation `
    -TenantsCsv    .\tenants.csv `
    -RemediationId <guid-from-create-run>
```

Clients converge within ~1h (the remediation scheduler runs faster than
the 8-hour MDM sync). No user action required.

Requires `Microsoft.Graph.Beta.DeviceManagement`
(`Install-Module Microsoft.Graph.Beta.DeviceManagement -Scope CurrentUser`).
The signed-in user needs
`DeviceManagementConfiguration.ReadWrite.All` consent.

#### Path B -- AD GPO / file share / SCCM (local installer)

Same script, different mode: `-GenerateLocalInstaller` emits a
self-contained installer set with the tenant JSON **baked in** -- no
parameters, no CSV dependency at deploy time. Drop on a file share, point
your GPO Startup / Logon Script at it, or wrap in an SCCM package.

```powershell
.\Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller `
    -TenantsCsv          .\tenants.csv `
    -LocalInstallerScope User                          # or Machine
# -> writes .\out-localinstaller\:
#      Install-PimActivator.ps1     (no params)
#      Uninstall-PimActivator.ps1   (no params)
#      README.md                    (deploy guidance)
```

Scope choices:

- `User` -- writes HKCU. Deploy via GPO **Logon Script** (User
  Configuration -> Windows Settings -> Scripts -> Logon). No admin rights
  required on the client. Survives Intune coexistence (HKCU does not
  collide with HKLM forcelist policy).
- `Machine` -- writes HKLM. Deploy via GPO **Startup Script** (Computer
  Configuration -> Windows Settings -> Scripts -> Startup) or SCCM.
  Affects every user on the box. **Conflicts** with Intune-managed
  ExtensionInstallForcelist policy -- only use on non-Intune estates.

Re-running the generator overwrites the installer with the latest CSV.
Push it through your normal channel to add / remove tenants.

#### Path C -- Direct local registry write (dev / single box)

`Deploy-PimActivatorClient.ps1` is the lowest-level option. No Intune,
no GPO, just a one-shot registry write. Useful for dev workstations or
proving the flow before wiring up Path A or Path B.

```powershell
.\Deploy-PimActivatorClient.ps1 `
    -Tenants @(
        @{ Name='ACME Production'; TenantId='f0fa27a0-...'; ClientId='11111111-...' },
        @{ Name='ACME Test';       TenantId='11112222-...'; ClientId='99998888-...' }
    ) `
    -Scope User
```

`-Scope User` (HKCU, no admin) or `-Scope Machine` (HKLM, admin
required, conflicts with Intune). `-Browser Edge | Chrome | Both`
(default Both -- writes identical key names under each browser's policy
root).

#### Path D -- Server install (Windows Server / admin jump box / PAW)

The activator runs in Edge / Chrome on Windows Server hosts just as it
does on workstations. Typical targets:

- **Admin jump boxes** -- the box admins RDP into to reach customer /
  prod estates.
- **PAWs** (privileged access workstations) -- locked-down dedicated
  admin devices.
- **Shared admin Windows Servers** -- single host where multiple admins
  RDP in and each needs the extension available in their session.

**Scope choice for servers**

- `-LocalInstallerScope User` (HKCU) -- single-admin server / personal
  PAW. Each admin runs `Install-PimActivator.ps1` once for their own
  profile. No admin rights needed. Best when one person owns the box.
- `-LocalInstallerScope Machine` (HKLM) -- shared admin server where
  multiple admins RDP in. One install (elevated) covers every RDP user.
  Recommended for shared jump boxes.

**Generating the Machine-scope installer**

```powershell
.\Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller `
    -TenantsCsv .\tenants.csv `
    -LocalInstallerOutputDir .\out-server-machine `
    -LocalInstallerScope Machine
```

**Deploying to the server (Machine scope)**

1. Copy the generated folder to the server (RDP file transfer, SMB
   share, or PsExec).
2. Open PowerShell **as Administrator** on the server.
3. Run:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Install\PimActivator-Server\Install-PimActivator.ps1`
4. Restart Edge and Chrome on the server (close all browser windows,
   including any in RDP sessions).
5. Each subsequent RDP session sees the extension auto-installed in
   their browser within ~30s.
6. Each admin signs in to the popup with their own admin account; if
   the `Tenants` array has 2+ entries, each admin picks their own
   tenant per browser profile (cached in `chrome.storage.local` per
   Chromium profile).

**Domain-joined servers via AD GPO Startup Script**

- Generate the Machine-scope installer.
- Push to GPO **Computer Configuration -> Policies -> Windows Settings
  -> Scripts -> Startup**.
- Add `Install-PimActivator.ps1` as a PowerShell startup script.
- Runs as `SYSTEM` at boot, writes the HKLM policy keys, every RDP user
  on the box gets the extension.

**The User-scope alternative (one-admin server)**

- Copy the existing User-scope installer folder.
- Each admin runs it once in a non-elevated PowerShell from their RDP
  session.
- Only that admin's RDP sessions get the extension (their HKCU only).

### Stage 3 -- manual dev-mode install (testing the extension code itself)

```powershell
Copy-Item config.template.js config.js
# Edit config.js, set tenantId + clientId (or a Tenants array).
```

Load unpacked at `edge://extensions` or `chrome://extensions` (Developer
Mode on). Skip Stage 2.

---

## Mental model

The picker UI and the deployment layer are independent:

```
+-----------------------+      +---------------------------+      +-----------------+
| Path A Intune         |      |                           |      |                 |
| Path B local install  | -->  | Chromium policy registry  | -->  | Extension popup |
| Path C direct write   |      | (HKCU/HKLM ...\policy\    |      | (popup.html +   |
|                       |      |  Tenants JSON)            |      |  popup.js)      |
| silent push, no UI    |      | chrome.storage.managed    |      | -> picker if 2+ |
+-----------------------+      +---------------------------+      +-----------------+
```

The deployment layer's only job is to land the `Tenants` JSON in the
right registry path. The picker is plain HTML/JS inside the extension
that reads whatever is in `chrome.storage.managed` at popup-open time.
Add or remove tenants by changing the source CSV; clients re-render the
picker automatically when the cached tenant disappears from the
managed list.

---

## What the user sees

1. Click the extension icon.
2. **First run only** (2+ tenants configured) -- tenant picker lists the
   friendly `Name` of each tenant in the managed `Tenants` array. Pick
   one. Choice is cached per browser profile in `chrome.storage.local`.
3. Silent reauth via cached refresh token (or a one-tab interactive
   sign-in the first time / after consent revocation).
4. Popup lists all PIM groups they're eligible for, filtered by the regex
   in `groupNameFilter` (default `^PIM-`).
5. Tick the groups they need, enter a justification, pick a duration.
6. **Activate selected** -- one POST per group (sequential, gentle on
   throttling). Per-group status updates inline.

Footer shows the selected tenant's friendly name. When 2+ tenants are
configured, a `(switch)` link sits next to the name; clicking it clears
the cached pick and re-renders the picker without affecting other browser
profiles.

State persisted in `chrome.storage.local`:

- `refreshToken` / `accessToken` / `accessTokenExpiry` / `account` -- auth cache
- `selectedTenantId` -- per-profile tenant pick (multi-tenant rollouts)
- `selectedIds` -- pre-tick the user's typical bundle next time
- `lastJustification` / `lastDurationHours`

---

## Permissions reference

| Surface | Perm | Type | Why |
|---|---|---|---|
| App reg (per Stage 1) | `PrivilegedAccess.ReadWrite.AzureADGroup` | Delegated | Read user's eligible groups; create activation requests |
| App reg (per Stage 1) | `Group.Read.All` | Delegated | Resolve groupId → displayName for the picker |
| App reg (per Stage 1) | `User.Read` | Delegated | Sign-in / read principal id |
| Caller of Stage 1 | `Application.ReadWrite.All` | Delegated | Create the app registration |
| Caller of Stage 1 | `AppRoleAssignment.ReadWrite.All` + `DelegatedPermissionGrant.ReadWrite.All` | Delegated | Grant admin consent (only if `-GrantConsent`) |
| Caller of Stage 2 | (local admin) | — | HKLM registry write |

---

## Troubleshooting

- **"Extension not configured" in the popup**: managed policy keys missing
  AND no `config.js`. Confirm the chosen Stage 2 path ran successfully
  (`edge://policy` or `chrome://policy` shows extension policies under
  the extension id; look for a `Tenants` value with valid JSON).
- **Picker keeps appearing every time**: `chrome.storage.local` got
  cleared (incognito, profile reset, "Clear browsing data -> Cookies and
  other site data"). The pick is per browser profile and not synced.
- **Signed into the wrong tenant**: click `(switch)` in the popup footer
  -- this clears `selectedTenantId` for the current profile only and
  re-renders the picker. Other profiles keep their existing pick.
- **Sign-in works, no groups listed**: the user has no eligible PIM
  assignments for groups matching `groupNameFilter`. Try widening the
  filter to `.*` for debugging.
- **HTTP 403 on activate**: tenant requires MFA in-flow for activation.
  Entra returns `interaction_required` / `claims_challenge`; click sign-out
  then sign-in again and complete MFA. Conditional Access policy gating
  PIM is fully honored.
- **HTTP 429**: PIM throttles aggressively. The popup activates groups
  sequentially to stay under the rate limit. If you need >5 activations
  per second, wait between bursts.
