// Boot the PIM Manager (loopback, SQL mode, rich scenario seed) before the GUI scenario
// specs run. Delegates to Start-PimScenarioManager.ps1, which writes the .manager.json
// sidecar the specs read. If SQLEXPRESS/seed/Manager are unavailable, the sidecar carries
// skip:true and the specs self-skip (clean, not a failure) -- mirroring the PS Live-test rule.
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

module.exports = async () => {
  const side = path.join(__dirname, '..', '.manager.json');
  // live passthrough: drive an already-running hosted Manager if env vars are set
  if (process.env.PIM_GUI_LIVE_URL && process.env.PIM_GUI_LIVE_TOKEN) {
    fs.writeFileSync(side, JSON.stringify({
      skip: false, live: true,
      baseUrl: process.env.PIM_GUI_LIVE_URL.replace(/\/+$/, ''),
      token: process.env.PIM_GUI_LIVE_TOKEN,
      role: process.env.PIM_GUI_LIVE_ROLE || 'SuperAdmin',
    }, null, 2));
    return;
  }
  const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
  const script = path.join(__dirname, '..', 'Start-PimScenarioManager.ps1');
  console.log('[scenario-gui-setup] booting Manager via Start-PimScenarioManager.ps1 ...');
  const r = spawnSync(ps, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-OutFile', side],
    { stdio: 'inherit', timeout: 240_000 });
  if (r.status !== 0 && !fs.existsSync(side)) {
    fs.writeFileSync(side, JSON.stringify({ skip: true, reason: `boot harness exited ${r.status}` }, null, 2));
  }
  try {
    const info = JSON.parse(fs.readFileSync(side, 'utf8').replace(/^﻿/, ''));
    if (info.skip) console.log(`[scenario-gui-setup] SKIP: ${info.reason}`);
    else console.log(`[scenario-gui-setup] Manager ready at ${info.baseUrl}`);
  } catch (e) {
    fs.writeFileSync(side, JSON.stringify({ skip: true, reason: 'sidecar unreadable' }, null, 2));
  }
};
