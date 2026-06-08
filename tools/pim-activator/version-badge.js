// Populate the version badge SYNCHRONOUSLY -- runs before popup.js module loads,
// so the badge is always populated even when popup.js parks in its onboarding
// `await new Promise(() => {})` (first-run / not-yet-onboarded popups).
//
// MV3 CSP forbids inline <script> in extension pages, hence this separate file.
(function () {
  try {
    var m = chrome.runtime.getManifest()
    var v = document.getElementById('version-badge')
    if (v && m) {
      v.textContent = 'v' + m.version
      v.title = 'Extension ID: ' + chrome.runtime.id +
                '\nManifest version: ' + m.manifest_version +
                '\nName: ' + m.name
      document.title = (m.name || 'PIM Activator') + ' v' + m.version
    }
  } catch (e) {
    /* manifest read shouldn't fail in extension context */
  }
})()
