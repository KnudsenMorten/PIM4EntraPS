// @ts-check
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SIDE = process.env.PIM_GUI_SIDECAR || path.join(__dirname, '.manager.json');

/**
 * Boots the local Manager (or accepts a live URL/token) and writes the sidecar.
 *
 * LIVE mode: if PIM_GUI_LIVE_URL + PIM_GUI_LIVE_TOKEN are set, skip the local
 * boot entirely and point the suite at the hosted instance.
 *
 * LOCAL mode (default): invoke Start-PimManagerForGui.ps1 which seeds a throwaway
 * SQLEXPRESS DB and boots Open-PimManager.ps1 -Server -NoLaunch in SQL mode.
 * If SQLEXPRESS is missing the PS script writes { skip:true } -> we mark skipped.
 */
module.exports = async () => {
  // Optional live-mode passthrough.
  if (process.env.PIM_GUI_LIVE_URL && process.env.PIM_GUI_LIVE_TOKEN) {
    const info = {
      skip: false,
      live: true,
      baseUrl: process.env.PIM_GUI_LIVE_URL.replace(/\/+$/, ''),
      token: process.env.PIM_GUI_LIVE_TOKEN,
      role: process.env.PIM_GUI_LIVE_ROLE || 'SuperAdmin',
    };
    fs.writeFileSync(SIDE, JSON.stringify(info, null, 2));
    console.log(`[gui-setup] LIVE mode -> ${info.baseUrl}`);
    return;
  }

  const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
  const script = path.join(__dirname, 'Start-PimManagerForGui.ps1');
  const role = process.env.PIM_GUI_ROLE || '';
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-OutFile', SIDE];
  if (role) args.push('-Role', role);

  console.log('[gui-setup] booting local Manager via harness ...');
  const r = spawnSync(ps, args, { stdio: 'inherit', timeout: 180_000 });
  if (r.status !== 0) {
    throw new Error(`Start-PimManagerForGui.ps1 exited ${r.status} (signal ${r.signal})`);
  }

  if (!fs.existsSync(SIDE)) {
    throw new Error(`harness wrote no sidecar at ${SIDE}`);
  }
  const info = JSON.parse(fs.readFileSync(SIDE, 'utf8').replace(/^﻿/, ''));
  if (info.skip) {
    console.log(`[gui-setup] SKIP: ${info.reason || 'prerequisites missing'} -- suite will self-skip.`);
    return; // fixtures.js sees skip:true and skips every test.
  }
  console.log(`[gui-setup] Manager ready at ${info.baseUrl} (role=${info.role}, pid=${info.pid})`);
};
