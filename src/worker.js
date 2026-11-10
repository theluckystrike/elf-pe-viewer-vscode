'use strict';
// Runs the parsers in a worker thread, so a hostile or huge binary can never block or crash the extension host.
// The host (runner.js) kills this worker when it takes too long or uses too much memory.
const { parentPort } = require('worker_threads');
const { Source } = require('./core/source');
const { parse } = require('./core');
const T = require('./core/template');
const tools = require('./core/tools');

const TEMPLATES = { elf: require('../templates/elf.json'), pe: require('../templates/pe.json'), macho: require('../templates/macho.json') };

function sourceOf(job) {
  if (job.buffer) return Source.fromBuffer(new Uint8Array(job.buffer));
  return Source.fromFile(job.file);
}

/** The Hex template engine reads through an async doc; this one reads from the bounded source. */
function docOf(src) {
  return { size: src.size, read: async (off, len) => src.bytesUpTo(off, len) };
}

async function templateNode(job, src) {
  const t = TEMPLATES[job.template];
  if (!t) throw new Error('No field template for this format.');
  const doc = docOf(job.slice ? src.slice(job.slice.offset, job.slice.size) : src);
  return T.parse(t, doc, { limits: { maxMs: 5000, maxNodes: 20000, maxArray: 20000 } });
}

async function run(job, progress) {
  if (job.op === 'parse') {
    const src = sourceOf(job);
    try { const m = parse(src, job.limits); m.size = src.size; return m; } finally { src.close(); }
  }
  if (job.op === 'fields') {
    const src = sourceOf(job);
    try { const r = await templateNode(job, src); return { tree: T.toWire(r.root), error: r.error || '', nodes: r.nodes }; } finally { src.close(); }
  }
  if (job.op === 'headerC') {
    const src = sourceOf(job);
    try { const r = await templateNode(job, src); return T.toC(r.root, job.name); } catch { return ''; } finally { src.close(); }
  }
  if (job.op === 'find') {
    const match = tools.matcher(job.query);
    for (let i = 0; i < job.files.length; i++) {
      const file = job.files[i];
      let hits = [], error = '';
      let src;
      try {
        src = Source.fromFile(file);
        const m = parse(src, { maxMs: 3000, ...(job.limits || {}) });
        hits = tools.findInModel(m, match, 500);
      } catch (e) { error = e.code === 'NOT_BINARY' ? 'skip' : String(e.message || e).slice(0, 200); }
      finally { if (src) src.close(); }
      progress({ index: i, file, hits, error });
    }
    return { done: true };
  }
  throw new Error(`unknown job ${job.op}`);
}

parentPort.on('message', async (msg) => {
  try {
    const result = await run(msg.job, (p) => parentPort.postMessage({ id: msg.id, progress: p }));
    parentPort.postMessage({ id: msg.id, ok: true, result });
  } catch (e) {
    parentPort.postMessage({ id: msg.id, ok: false, error: String((e && e.message) || e), code: e && e.code });
  }
});
