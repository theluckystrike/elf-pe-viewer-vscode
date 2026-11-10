'use strict';
// Starts a worker thread per job, with a memory cap and a watchdog. A job that sends nothing for `idleMs` is killed
// and rejected with code 'TIMEOUT'; a worker that runs out of memory is rejected with code 'MEMORY'. The extension
// host keeps running either way.
const path = require('path');
const { Worker } = require('worker_threads');

const WORKER = path.join(__dirname, 'worker.js');
const MEMORY_MB = 1024;

function runJob(job, { idleMs = 20000, onProgress, transfer } = {}) {
  return new Promise((resolve, reject) => {
    let w;
    try { w = new Worker(WORKER, { resourceLimits: { maxOldGenerationSizeMb: MEMORY_MB, maxYoungGenerationSizeMb: 64 } }); } catch (e) { reject(e); return; }
    let done = false, timer;
    const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); w.terminate().catch(() => {}); fn(v); };
    const arm = () => { clearTimeout(timer); timer = setTimeout(() => { const e = new Error(`Reading took longer than ${Math.round(idleMs / 1000)} seconds and was stopped.`); e.code = 'TIMEOUT'; finish(reject, e); }, idleMs); };
    arm();
    w.on('message', (m) => {
      if (m.progress) {
        arm();
        let r;
        try { r = onProgress && onProgress(m.progress); } catch { r = undefined; }
        if (r === 'stop') finish(resolve, { stopped: true });
        return;
      }
      if (m.ok) finish(resolve, m.result);
      else { const e = new Error(m.error); e.code = m.code; finish(reject, e); }
    });
    w.on('error', (err) => {
      const e = new Error(err && err.code === 'ERR_WORKER_OUT_OF_MEMORY' ? `Reading needed more than ${MEMORY_MB} MB of memory and was stopped.` : String((err && err.message) || err));
      e.code = err && err.code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'MEMORY' : 'WORKER';
      finish(reject, e);
    });
    w.on('exit', (code) => { if (!done) { const e = new Error(`The reader stopped (exit code ${code}).`); e.code = 'WORKER'; finish(reject, e); } });
    w.postMessage({ id: 1, job }, transfer || []);
  });
}

/**
 * Find in many files with one worker; a file that hangs is skipped (watchdog) and the scan goes on in a new worker.
 * onFile({ index, file, hits, error }) is called for each file. cancel() returns true to stop.
 */
async function findInFiles(files, query, { onFile, cancelled = () => false, idleMs = 15000 } = {}) {
  let next = 0;
  while (next < files.length && !cancelled()) {
    const start = next;
    try {
      await runJob({ op: 'find', files: files.slice(start, start + 200), query }, {
        idleMs,
        onProgress: (p) => { next = start + p.index + 1; if (onFile) onFile({ ...p, index: start + p.index }); return cancelled() ? 'stop' : undefined; },
      });
      next = Math.max(next, Math.min(files.length, start + 200));
    } catch (e) {
      if (e.code === 'TIMEOUT' || e.code === 'MEMORY' || e.code === 'WORKER') {
        // the file after the last reported one hung: report it and go on with the rest
        if (next < files.length) { onFile && onFile({ index: next, file: files[next], hits: [], error: e.message }); next++; }
      } else throw e;
    }
  }
}

module.exports = { runJob, findInFiles, WORKER };
