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
      // EDITION BADGE -- ONLY for the non-released channel. The test build's
      // manifest name carries "(TEST)" (released is plain "PIM Activator"), so
      // this badge appears only on test and the released build is never branded.
      var ed = (m.name || '').match(/\((test|dev)\)/i)
      if (ed && !document.getElementById('edition-badge')) {
        var b = document.createElement('span')
        b.id = 'edition-badge'
        b.textContent = 'Test'
        b.title = 'Test channel build (' + m.name + ')'
        b.style.cssText = 'display:inline-block;font-weight:700;font-size:11px;color:#1d3380;' +
          'background:#ffd24a;border:1px solid #e0b400;padding:2px 8px;border-radius:10px;' +
          'margin-left:6px;letter-spacing:0.3px;vertical-align:middle;text-transform:none;'
        v.parentNode.insertBefore(b, v.nextSibling)
      }
    }
  } catch (e) {
    /* manifest read shouldn't fail in extension context */
  }
})()
