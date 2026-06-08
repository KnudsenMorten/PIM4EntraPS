// PIM Activator -- MV3 service worker.
//
// v1.6.4+: minimal SW. All sign-in / discovery logic moved out:
//   - Tenant catalog comes from chrome.storage.managed (Intune-pushed) +
//     chrome.storage.local (manually imported via popup) -- handled in popup.js.
//   - Runtime sign-in uses chrome.identity.launchWebAuthFlow against the
//     active tenant's clientId -- handled in popup.js.
//
// Earlier versions hosted: OAuth2 authorization-code bootstrap (v1.4.x),
// Microsoft Graph CLI bootstrap (v1.5.0), device-code flow (v1.5.10),
// well-known URI fetch on corporate domain (v1.5.11). All retired in v1.6.x
// in favor of the catalog model -- nothing for the SW to do.

// Intentionally empty. Chromium MV3 requires the file to exist (manifest
// references it) but no listeners are needed.
