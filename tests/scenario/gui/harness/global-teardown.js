// Stop the scenario Manager + drop the throwaway DB after the GUI scenario specs run.
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

module.exports = async () => {
  const side = path.join(__dirname, '..', '.manager.json');
  if (!fs.existsSync(side)) return;
  let info = {};
  try { info = JSON.parse(fs.readFileSync(side, 'utf8').replace(/^﻿/, '')); } catch { /* */ }
  if (info.skip || info.live) { fs.rmSync(side, { force: true }); return; }
  const ps = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
  const script = path.join(__dirname, '..', 'Start-PimScenarioManager.ps1');
  console.log('[scenario-gui-teardown] stopping Manager + dropping DB ...');
  spawnSync(ps, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-Stop', '-OutFile', side],
    { stdio: 'inherit', timeout: 60_000 });
};
