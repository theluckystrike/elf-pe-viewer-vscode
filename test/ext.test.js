'use strict';
// The extension host with a stub vscode: activation, opening files, no network, Pro tries, the panel, the CSP.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const B = require('./build');
const { loadExtension, openInViewer } = require('./support/vscode-stub');
const { buildHtml } = require('../src/html');
const { findInFiles } = require('../src/runner');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'elfpe-ext-'));
const file = (name, buf) => { const p = path.join(dir, name); fs.writeFileSync(p, buf); return p; };
const SO = file('libzovo.so', B.elf());
const SO2 = file('libzovo2.so', B.elf({ imports: [['printf', 0], ['free', 0]], exports: ['zovo_add', 'zovo_sub'] }));
const DLL = file('zovo.dll', B.pe());
const TXT = file('notes.txt', Buffer.from('hello, this is text\n'));
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

function trapNetwork() {
  const calls = [];
  const saved = { fetch: global.fetch, hr: http.request, hg: http.get, sr: https.request, sg: https.get, nc: net.connect, ncc: net.createConnection };
  global.fetch = async (u) => { calls.push(String(u)); throw new Error('network blocked in test'); };
  http.request = http.get = https.request = https.get = (...a) => { calls.push(String(a[0] && (a[0].href || a[0].host || a[0]))); throw new Error('network blocked in test'); };
  net.connect = net.createConnection = (...a) => { calls.push('net ' + JSON.stringify(a[0])); throw new Error('network blocked in test'); };
  return { calls, restore: () => { global.fetch = saved.fetch; http.request = saved.hr; http.get = saved.hg; https.request = saved.sr; https.get = saved.sg; net.connect = saved.nc; net.createConnection = saved.ncc; } };
}

test('activation and opening ELF, PE and a text file make no network call and show no message', async () => {
  const nw = trapNetwork();
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    assert.ok(s.providers.has('elfPeViewer.binary') && s.providers.has('elfPeViewer.any'));
    for (const c of ['elfPeViewer.open', 'elfPeViewer.exportJson', 'elfPeViewer.exportC', 'elfPeViewer.compare', 'elfPeViewer.findInFolder', 'elfPeViewer.getPro', 'elfPeViewer.enterLicenseKey']) assert.ok(s.commands.has(c), c);
    const a = await openInViewer(s, SO);
    assert.strictEqual(a.posted[0].type, 'model');
    assert.match(a.posted[0].model.title, /ELF 64-bit LSB shared object/);
    assert.deepStrictEqual(a.posted[0].pro.tries, { export: 3, compare: 3, find: 3 });
    const b = await openInViewer(s, DLL);
    assert.match(b.posted[0].model.title, /PE32\+ DLL/);
    const t = await openInViewer(s, TXT);
    assert.strictEqual(t.posted[0].type, 'error');
    assert.strictEqual(t.posted[0].notBinary, true);
    // hex bytes come from the host
    await a.send({ type: 'hex', offset: 0, length: 16 });
    assert.deepStrictEqual(a.posted.at(-1).bytes.slice(0, 4), [0x7f, 0x45, 0x4c, 0x46]);
    assert.deepStrictEqual(nw.calls, []);
    assert.deepStrictEqual([s.log.info.length, s.log.warn.length, s.log.error.length], [0, 0, 0], 'no message on open');
    assert.deepStrictEqual(s.log.external, []);
  } finally { nw.restore(); s.restore(); }
});

test('export: Escape on the save dialog keeps the try; 3 saves use the 3 tries; the 4th click shows the panel', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const v = await openInViewer(s, SO);
    s.ui.save.push(undefined);
    await v.send({ type: 'tool', tool: 'exportJson' });
    assert.strictEqual((s.state.get('elfPeViewer.proTrial') || {}).export, undefined, 'cancel uses no try');
    for (let i = 1; i <= 3; i++) {
      const out = path.join(dir, `out${i}.${i === 2 ? 'h' : 'json'}`);
      s.ui.save.push(s.vscode.Uri.file(out));
      await v.send({ type: 'tool', tool: i === 2 ? 'exportC' : 'exportJson' });
      assert.ok(fs.existsSync(out), `export ${i} written`);
      assert.strictEqual(s.state.get('elfPeViewer.proTrial').export, i);
    }
    const j = JSON.parse(fs.readFileSync(path.join(dir, 'out1.json'), 'utf8'));
    assert.strictEqual(j.tables.imports.length, 3);
    assert.match(fs.readFileSync(path.join(dir, 'out2.h'), 'utf8'), /typedef struct Elf64_Ehdr|typedef struct/);
    assert.ok(s.log.status.some((t) => /free try 3 of 3/.test(t)));
    assert.strictEqual(s.log.info.length, 0, 'no panel while tries are left');
    s.ui.info.push(undefined); // Cancel
    await v.send({ type: 'tool', tool: 'exportJson' });
    assert.strictEqual(s.log.info.length, 1);
    const panel = s.log.info[0];
    assert.match(panel.text, /Export structure \(JSON or C header\) is part of Zovo Pro/);
    assert.strictEqual(panel.opts.modal, true);
    assert.deepStrictEqual(panel.buttons.slice(0, 3), ['Get Zovo Pro, USD 19', 'Pay with PayPal', 'I already paid']);
    assert.match(panel.opts.detail, /You used the 3 free tries/);
    assert.match(panel.opts.detail, /Compare two binaries/);
    assert.ok(!/refund/i.test(panel.opts.detail), 'refund line hidden while refund_days is empty');
    assert.ok(!panel.buttons.includes('Pay by card'), 'Gumroad button hidden');
    assert.strictEqual(s.log.saved.length, 3, 'nothing written after the tries');
    // the other tools still have their own 3 tries
    assert.deepStrictEqual(v.posted.filter((m) => m.type === 'pro').at(-1).pro.tries, { export: 0, compare: 3, find: 3 });
  } finally { s.restore(); }
});

test('Get Zovo Pro opens the USD 19 tier, never the generic Sponsors page', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    s.state.set('elfPeViewer.proTrial', { compare: 3 });
    const v = await openInViewer(s, SO);
    s.ui.info.push('Get Zovo Pro, USD 19');
    await v.send({ type: 'tool', tool: 'compare' });
    assert.deepStrictEqual(s.log.external.map(String).filter((u) => /github\.com\/sponsors/.test(u)), ['https://github.com/sponsors/theluckystrike/sponsorships?tier_id=679878']);
    assert.ok(!v.posted.some((m) => m.type === 'compare'));
  } finally { s.restore(); }
});

test('compare: cancel keeps the try; a comparison on screen uses one', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const v = await openInViewer(s, SO);
    s.ui.open.push(undefined);
    await v.send({ type: 'tool', tool: 'compare' });
    assert.strictEqual((s.state.get('elfPeViewer.proTrial') || {}).compare, undefined);
    s.ui.open.push([s.vscode.Uri.file(SO2)]);
    await v.send({ type: 'tool', tool: 'compare' });
    const c = v.posted.find((m) => m.type === 'compare');
    assert.ok(c);
    const imp = c.result.tables.find((t) => t.id === 'imports');
    assert.deepStrictEqual(imp.added, ['libc.so.6 → free']);
    assert.strictEqual(s.state.get('elfPeViewer.proTrial').compare, 1);
  } finally { s.restore(); }
});

test('find in folder: no match uses no try; matches are listed and use one', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    s.vscode.workspace.workspaceFolders = [{ name: 'w', uri: s.vscode.Uri.file(dir) }];
    const v = await openInViewer(s, SO);
    s.ui.input.push('NoSuchName_xyz');
    await v.send({ type: 'tool', tool: 'find' });
    assert.strictEqual(v.posted.find((m) => m.type === 'find').results.length, 0);
    assert.strictEqual((s.state.get('elfPeViewer.proTrial') || {}).find, undefined);
    s.ui.input.push('zovo_add');
    await v.send({ type: 'tool', tool: 'find' });
    const r = v.posted.filter((m) => m.type === 'find').at(-1);
    const files = [...new Set(r.results.map((x) => path.basename(x.file)))].sort();
    assert.deepStrictEqual(files, ['libzovo.so', 'libzovo2.so', 'zovo.dll']);
    assert.strictEqual(s.state.get('elfPeViewer.proTrial').find, 1);
  } finally { s.restore(); }
});

test('the watchdog stops a search that hangs on one file and goes on with the next', async () => {
  const slow = file('slow.so', B.elf({ exports: ['a'.repeat(40) + 'c'] }));
  const seen = [];
  const t0 = Date.now();
  await findInFiles([slow, SO], '/^(a|aa)*b$/', { idleMs: 1500, onFile: (p) => seen.push([path.basename(p.file), p.error ? 'stopped' : 'ok']) });
  assert.deepStrictEqual(seen, [['slow.so', 'stopped'], ['libzovo.so', 'ok']]);
  assert.ok(Date.now() - t0 < 10000);
});

test('webview HTML: nonce scripts, no remote origin, no connect-src', () => {
  const html = buildHtml({ cspSource: 'vscode-webview://x', scriptUri: 'vscode-webview://x/main.js', styleUri: 'vscode-webview://x/main.css', title: '<evil>"', nonce: 'abc' });
  const csp = /content="([^"]+)"/.exec(html)[1];
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'nonce-abc'/);
  assert.ok(!/https?:/.test(csp));
  assert.ok(!/connect-src/.test(csp));
  assert.ok(html.includes('&lt;evil&gt;&quot;'));
  assert.ok(!/<script(?![^>]*nonce="abc")/.test(html));
});

test('the webview script sets no innerHTML and loads nothing remote', () => {
  const js = fs.readFileSync(path.join(__dirname, '..', 'media', 'main.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(js));
  assert.ok(!/https?:\/\//.test(js));
  // The CSP has no 'unsafe-inline' for styles: a style attribute would be dropped, so styles go through the CSSOM.
  assert.ok(/e\.style\.setProperty/.test(js));
  assert.ok(!/setAttribute\(\s*['"]style/.test(js));
});

test('showProTools false hides the tools in the webview state', async () => {
  const s = loadExtension();
  try {
    s.config.showProTools = false;
    s.ext.activate(s.context);
    const v = await openInViewer(s, SO);
    assert.strictEqual(v.posted[0].pro.show, false);
  } finally { s.restore(); }
});

test('package.json: phrase-first name, engines ^1.90.0, Pro titles end in (Pro), Zovo Pro palette category', () => {
  const p = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(p.displayName.startsWith('ELF Viewer & PE Viewer'));
  assert.ok(!/DLL Structure Viewer/i.test(p.displayName));
  assert.strictEqual(p.engines.vscode, '^1.90.0');
  assert.strictEqual(p.devDependencies['@types/vscode'], '~1.90.0');
  const pro = p.contributes.commands.filter((c) => /exportJson|exportC|compare|findInFolder/.test(c.command));
  assert.strictEqual(pro.length, 4);
  for (const c of pro) assert.match(c.title, /\(Pro\)$/);
  assert.strictEqual(p.contributes.commands.filter((c) => c.category === 'Zovo Pro').length, 5);
});

test('rating wiring: a rendered binary counts as a good file; a text file is neither a success nor a failure', async () => {
  const s = loadExtension();
  try {
    s.ext.activate(s.context);
    const t = await openInViewer(s, TXT);
    assert.strictEqual(t.posted[0].notBinary, true);
    const st0 = s.state.get('zovo.rating.v2');
    assert.ok(!st0 || !st0.lastError, 'not a failure');
    const v = await openInViewer(s, SO);
    await v.send({ type: 'rendered' });
    await v.send({ type: 'rendered' });
    const st = s.state.get('zovo.rating.v2');
    assert.ok(st && st.count === 1, `one good file counted once: ${JSON.stringify(st)}`);
  } finally { s.restore(); }
});

