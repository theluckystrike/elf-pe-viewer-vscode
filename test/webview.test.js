'use strict';
// Runs media/main.js in jsdom with a parsed model: tabs, the hidden Export menu, table columns (set through the
// CSSOM, since the CSP drops style attributes), filter, hex rows, hostile names as text. jsdom is not a dependency of
// this extension: the test uses JSDOM_PATH or the copy in a sibling product, and is skipped when there is none.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const B = require('./build');
const { parseBuffer } = require('../src/core');

const candidates = [process.env.JSDOM_PATH, path.join(__dirname, '..', 'node_modules', 'jsdom'), path.join(__dirname, '..', '..', 'docx-viewer-vscode', 'node_modules', 'jsdom')].filter(Boolean);
let JSDOM = null;
for (const c of candidates) { try { ({ JSDOM } = require(c)); break; } catch { /* next */ } }
const script = fs.readFileSync(path.join(__dirname, '..', 'media', 'main.js'), 'utf8');

function boot(model, size) {
  const dom = new JSDOM('<!DOCTYPE html><body><div id="app"></div><template id="zovo-footer"><div id="zovo-support">Rate</div></template></body>', { runScripts: 'outside-only', pretendToBeVisual: true });
  const sent = [];
  dom.window.acquireVsCodeApi = () => ({ postMessage: (m) => sent.push(m) });
  dom.window.eval(script);
  const send = (m) => dom.window.dispatchEvent(new dom.window.MessageEvent('message', { data: m }));
  send({ type: 'model', model, name: 'libzovo.so', size, pro: { show: true, licensed: false, tries: { export: 3, compare: 2, find: 3 } } });
  return { dom, doc: dom.window.document, sent, send };
}

test('webview: tabs, hidden Export menu, column grid through the CSSOM, filter, footer', { skip: !JSDOM && 'jsdom not found' }, async () => {
  const buf = B.elf();
  const { doc, sent, dom } = boot(parseBuffer(buf), buf.length);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(sent.map((m) => m.type))), ['ready', 'rendered']);
  const tabs = [...doc.querySelectorAll('.tab')].map((t) => t.dataset.tab);
  assert.deepStrictEqual(tabs, ['overview', 'headers', 'sections', 'segments', 'imports', 'exports', 'libraries', 'symbols', 'dynamic', 'notes', 'hex']);
  assert.strictEqual(doc.querySelector('.menu').hidden, true, 'the Export menu starts closed');
  assert.match(doc.querySelector('[data-tool=compare]').title, /2 free tries left/);
  assert.ok(doc.getElementById('zovo-support'), 'footer');
  doc.querySelector('.tab[data-tab="imports"]').click();
  const head = doc.querySelector('.thead');
  assert.match(head.style.getPropertyValue('grid-template-columns'), /minmax/, 'columns set with style.setProperty');
  assert.strictEqual(head.getAttribute('style') === null || !/unsafe/.test(head.getAttribute('style')), true);
  const f = doc.querySelector('.filter');
  f.value = 'cos';
  f.dispatchEvent(new dom.window.Event('input'));
  await new Promise((r) => setTimeout(r, 250));
  assert.match(doc.querySelector('.tools .muted').textContent, /^1 of 3 rows$/);
  // the Export button opens and closes its menu
  doc.querySelector('[data-tool=export]').click();
  assert.strictEqual(doc.querySelector('.menu').hidden, false);
  doc.querySelector('[data-tool=exportJson]').click();
  assert.deepStrictEqual(JSON.parse(JSON.stringify(sent.at(-1))), { type: 'tool', tool: 'exportJson' });
});

test('webview: hex tab asks for bytes and draws rows; hostile names stay text', { skip: !JSDOM && 'jsdom not found' }, async () => {
  const b = Buffer.from(B.pe());
  const at = b.indexOf(Buffer.from('zovo_add\0'));
  Buffer.from('<img src=x onerror=alert(1)>').copy(b, at);
  const { doc, sent, send } = boot(parseBuffer(b), b.length);
  doc.querySelector('.tab[data-tab="exports"]').click();
  assert.strictEqual(doc.querySelectorAll('#app img').length, 0);
  doc.querySelector('.tab[data-tab="hex"]').click();
  assert.ok(doc.getElementById('hexbox'));
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(sent.some((m) => m.type === 'hex' && m.offset === 0), 'asks for the first 4 KB');
  send({ type: 'hex', offset: 0, bytes: Array.from(b.subarray(0, 4096)) });
  assert.match(doc.querySelector('.hrow').textContent, /^000000004D5A/);
});

test('webview: a file that is not a binary shows the message and the footer', { skip: !JSDOM && 'jsdom not found' }, () => {
  const dom = new JSDOM('<!DOCTYPE html><body><div id="app"></div><template id="zovo-footer"><div id="zovo-support">Rate</div></template></body>', { runScripts: 'outside-only' });
  dom.window.acquireVsCodeApi = () => ({ postMessage() {} });
  dom.window.eval(script);
  dom.window.dispatchEvent(new dom.window.MessageEvent('message', { data: { type: 'error', message: 'This is not an ELF, PE or Mach-O file.', notBinary: true } }));
  assert.match(dom.window.document.querySelector('h2').textContent, /Not an ELF, PE or Mach-O file/);
  assert.ok(dom.window.document.getElementById('zovo-support'));
});
