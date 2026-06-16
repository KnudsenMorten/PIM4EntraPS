// @ts-check
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SIDE = process.env.PIM_GUI_SIDECAR || path.join(__dirname, '.manager.json');

/** Stops the local Manager + drops the throwaway DB (no-op in live/skip mode). */
module.exports = async () => {
  if (!fs.existsSync(SIDE)) return;
  let info = {};
  try { info = JSON.parse(fs.readFileSync(SIDE, 'utf8').replace(/^﻿/, '')); } catch { /* ignore */ }
  if (info.skip || info.live) { fs.rmSync(SIDE, { force: true }); return; }

  const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
  const script = path.join(__dirname, 'Start-PimManagerForGui.ps1');
  console.log('[gui-teardown] stopping local Manager + dropping test DB ...');
  spawnSync(ps, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-Stop', '-OutFile', SIDE],
    { stdio: 'inherit', timeout: 60_000 });
};
