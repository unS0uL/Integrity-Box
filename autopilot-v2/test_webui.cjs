const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const os = require('node:os');
const cp = require('node:child_process');
const assert = require('node:assert/strict');

(async () => {
  const repo = path.resolve(__dirname, '..');
  const html = fs.readFileSync(path.join(repo, 'webroot/KeyboxLoader/index.html'), 'utf8');
  const begin = html.indexOf('async function loadFile(path)');
  const end = html.indexOf('\ndocument.querySelectorAll', begin);
  assert(begin >= 0 && end > begin);
  let captured, toast;
  const context = vm.createContext({slot: 1, runShell: async command => {
    captured = command;
    return 'IMPORT_EXIT=0';
  }, showToast: (...args) => {toast = args;}});
  vm.runInContext(html.slice(begin, end), context);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'box-webui-'));
  try {
    const marker = path.join(dir, 'must-not-exist');
    const input = "odd'; touch " + marker + "; echo '$(touch " + marker + ')';
    await context.loadFile(input);
    assert.equal(toast[1], 'success');
    const output = path.join(dir, 'argv');
    const stub = path.join(dir, 'sh');
    fs.writeFileSync(stub, '#!/bin/sh\nprintf "%s" "$3" > "$CAPTURE"\nexit 0\n', {mode: 0o700});
    const result = cp.spawnSync('/bin/sh', ['-c', captured], {
      env: {...process.env, PATH: dir + path.delimiter + process.env.PATH, CAPTURE: output},
      encoding: 'utf8'
    });
    assert.equal(result.status, 0);
    assert.equal(fs.readFileSync(output, 'utf8'), input);
    assert.equal(fs.existsSync(marker), false);
    context.runShell = async () => 'misleading IMPORT_EXIT=0\nIMPORT_EXIT=1';
    await context.loadFile(input);
    assert.equal(toast[1], 'error');
  } finally {fs.rmSync(dir, {recursive: true, force: true});}

  const pilot = fs.readFileSync(path.join(repo, 'webroot/Pilot/index.html'), 'utf8');
  const a = pilot.indexOf('function checkAutopilot()');
  const b = pilot.indexOf('\nfunction checkMode()', a);
  const nodes = new Map();
  let response = JSON.stringify({desired_enabled: true, running: false, phase: 'waiting',
    revocation_state: 'unknown', next_due: '0001-01-01', heartbeat: '0001-01-01'});
  const pilotContext = vm.createContext({DAEMON_SCRIPT: '/test/controller',
    runShell: (_command, callback) => callback(response),
    updateHeartbeatUI: () => {},
    document: {getElementById: id => {
      if (!nodes.has(id)) nodes.set(id, {});
      return nodes.get(id);
    }}});
  vm.runInContext(pilot.slice(a, b), pilotContext);
  pilotContext.checkAutopilot();
  assert.equal(nodes.get('autopilotToggle').checked, true);
  assert.equal(nodes.get('statusSubtitle').textContent, 'Waiting for service');
  response = 'invalid JSON';
  pilotContext.checkAutopilot();
  assert.equal(nodes.get('statusSubtitle').textContent, 'Status unavailable');
  const heartbeatStart = pilot.indexOf('function updateHeartbeatUI(');
  const heartbeatEnd = pilot.indexOf('\nfunction updateGithubUI(', heartbeatStart);
  pilotContext.getHeartbeatStatus = () => ({status: 'dead', text: 'Not responding'});
  pilotContext.timeAgo = () => 'old';
  pilotContext.formatExactTime = () => 'timestamp';
  nodes.set('heartbeatIcon', {classList: {add: () => {}}});
  vm.runInContext(pilot.slice(heartbeatStart, heartbeatEnd), pilotContext);
  pilotContext.updateHeartbeatUI(1, true);
  assert.equal(nodes.get('heartbeatSubtitle').textContent, 'Process alive');
  pilotContext.updateHeartbeatUI(1, false);
  assert.equal(nodes.get('heartbeatSubtitle').textContent, 'Not running');
  console.log('WebUI bridge tests PASS: quoting, import failure, truthful status');
})().catch(error => {console.error(error); process.exitCode = 1;});
