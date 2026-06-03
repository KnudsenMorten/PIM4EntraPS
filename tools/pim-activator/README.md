# PIM Activator (Edge extension)

Companion extension to **PIM4EntraPS**: bulk-activate eligible PIM-for-Groups
memberships from the Edge toolbar instead of clicking through the Entra
portal one role at a time.

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

## File layout

```
tools/pim-activator/
  manifest.json                              # Edge MV3 manifest
  popup.html / popup.js                      # the popup UI
  managed_schema.json                        # what admins can push via Intune
  config.template.js                         # copy -> config.js for dev-mode
  icons/icon-16.png / icon-32.png / icon-128.png
  Deploy-PimActivatorBackend.ps1    # ONE-TIME tenant setup (run by admin)
  Deploy-PimActivatorClient.ps1                   # PER-PAW install (Intune-deployable)
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

### Stage 2 — per-PAW install (Intune-deployable, unattended)

Pushes Edge enterprise policy keys that:

- Force-install the extension from your chosen update URL (Edge Add-ons
  store or a private CRX host)
- Push the per-tenant config (`tenantId`, `clientId`, etc.) into
  `chrome.storage.managed`, which `popup.js` reads in preference to
  `config.js`.

**Direct install on one machine** (as admin):

```powershell
.\Deploy-PimActivatorClient.ps1 `
    -ExtensionId 'abcdefghijklmnopabcdefghijklmnop' `
    -UpdateUrl   'https://edge.microsoft.com/extensionwebstorebase/v1/crx' `
    -TenantId    'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' `
    -ClientId    '11111111-2222-3333-4444-555555555555'
```

**Intune Win32 app deployment:**

1. Wrap `Deploy-PimActivatorClient.ps1` + a `pim-activator.intunewin` with the
   Microsoft Win32 Content Prep Tool (`IntuneWinAppUtil.exe`).
2. Install command:
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 -ExtensionId <id> -UpdateUrl <url> -TenantId <tid> -ClientId <cid>
   ```
3. Uninstall command:
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 -ExtensionId <id> -Uninstall
   ```
4. Detection rule: registry key
   `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<ExtensionId>\policy`
   value `tenantId` exists.
5. Assign to the security group containing your PAW devices.

Policy is picked up by Edge on next launch — no reboot, no user interaction.

**Settings Catalog alternative:** if you'd rather not deploy a Win32 app,
use **Intune → Configuration Profiles → Settings Catalog → Microsoft Edge →
ExtensionInstallForcelist** + **Edge → 3rd party extensions → managed
storage**. Same registry keys, but Intune-native UI.

### Stage 3 — manual dev-mode install (for testing the extension itself)

```powershell
Copy-Item config.template.js config.js
# Edit config.js, set tenantId + clientId.
```

Load unpacked at `edge://extensions` (Developer Mode on). Skip Stage 2.

---

## What the user sees

1. Click the extension icon → silent reauth via cached refresh token (or a
   one-tab interactive sign-in the first time / after consent revocation).
2. Popup lists all PIM groups they're eligible for, filtered by the regex
   in `groupNameFilter` (default `^PIM-`).
3. Tick the groups they need, enter a justification, pick a duration.
4. **Activate selected** → one POST per group (sequential, gentle on
   throttling). Per-group status updates inline.

State persisted in `chrome.storage.local`:

- `refreshToken` / `accessToken` / `accessTokenExpiry` / `account` — auth cache
- `selectedIds` — pre-tick the user's typical bundle next time
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
  AND no `config.js`. Confirm `Deploy-PimActivatorClient.ps1` ran successfully
  (`edge://policy` shows extension policies under the extension id).
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
