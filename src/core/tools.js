'use strict';
// The Pro tools' pure parts: export a model as JSON or as a C header, compare two models, and match a name in a
// model (find in folder). No vscode, no file system, so they run in tests and in the worker.

const VERSION_NOTE = 'ELF Viewer & PE Viewer by Zovo';

/** Model to a plain JSON-ready object (the slices of a universal binary included). */
function toJsonObject(model, fileName) {
  const one = (m) => ({
    format: m.format,
    title: m.title,
    summary: Object.fromEntries(dedupe(m.summary || [])),
    headers: (m.groups || []).map((g) => ({ title: g.title, fields: g.fields.map(([name, value, offset, size]) => ({ name, value, offset: offset ?? null, size: size ?? null })) })),
    tables: Object.fromEntries((m.tables || []).map((t) => [t.id, t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c.n, r[i]])))])),
    warnings: m.warnings || [],
  });
  const out = { file: fileName || '', exportedBy: VERSION_NOTE, ...one(model) };
  if (model.slices) out.slices = model.slices.map((s) => ({ architecture: s.arch, offset: s.offset, size: s.size, ...one(s.model) }));
  return out;
}

function dedupe(pairs) {
  const seen = new Map();
  for (const [k, v] of pairs) { let key = k, n = 2; while (seen.has(key)) key = `${k} ${n++}`; seen.set(key, v); }
  return [...seen];
}

function toJson(model, fileName) { return JSON.stringify(toJsonObject(model, fileName), null, 2) + '\n'; }

// ---------- C header ----------

const ident = (s, fallback = 'x') => {
  let x = String(s).replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
  if (!x) x = fallback;
  if (/^\d/.test(x)) x = '_' + x;
  return x;
};
const cstr = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\?\?/g, '?\\?').replace(/[\x00-\x1f\x7f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')) + '"';
const cnum = (v, t) => {
  if (t === 'd') return Number.isFinite(v) ? String(v) : '0';
  const s = String(v || '0x0');
  if (!/^-?0x[0-9A-Fa-f]+$/.test(s)) return '0';
  const big = BigInt(s.replace('-', ''));
  return (s.startsWith('-') ? '-' : '') + s.replace('-', '') + (big > 0xffffffffn ? 'ULL' : 'u');
};
const comment = (s) => String(s).replace(/\*\//g, '* /').replace(/[\r\n]+/g, ' ');

/**
 * A C header with the parsed structure: header fields as #define lines with comments, one struct type and one
 * const array per table (sections, segments, imports, exports, symbols, ...), offsets from the start of the file.
 * headerC (optional) is the packed header struct from the Hex template engine (core/template.js toC).
 */
function toCHeader(model, fileName, headerC) {
  const base = ident(String(fileName || 'binary').replace(/\.[^.]*$/, ''), 'binary').toLowerCase();
  const guard = `${base.toUpperCase()}_STRUCTURE_H`;
  const out = [
    `/* Structure of ${comment(fileName || 'the file')}: ${comment(model.title)}.`,
    ` * Exported by ${VERSION_NOTE}. Offsets and sizes are in bytes from the start of the file. */`,
    `#ifndef ${guard}`, `#define ${guard}`, '', '#include <stdint.h>', '',
  ];
  const emit = (m, prefix) => {
    const P = prefix.toUpperCase();
    for (const [k, v] of dedupe(m.summary || [])) out.push(`/* ${comment(k)}: ${comment(v)} */`);
    out.push('');
    for (const g of m.groups || []) {
      out.push(`/* ${comment(g.title)} */`);
      for (const [name, value, offset] of g.fields) {
        const n = `${P}_${ident(g.title).toUpperCase()}_${ident(name.replace(/\(.*?\)/g, '')).toUpperCase()}`;
        const num = /^(-?0x[0-9A-F]+|\d+)\b/i.exec(String(value));
        const at = offset !== undefined && offset !== null ? ` at 0x${offset.toString(16).toUpperCase()}` : '';
        if (num) out.push(`#define ${n} ${num[1].startsWith('0x') || num[1].startsWith('-0x') ? cnum(num[1], 'h') : num[1]} /* ${comment(value)}${at} */`);
        else out.push(`/* ${comment(name)} = ${comment(value)}${at} */`);
      }
      out.push('');
    }
    for (const t of m.tables || []) {
      const tn = `${prefix}_${ident(t.id)}`;
      const cols = t.columns.map((c, i) => ({ ...c, f: ident(c.n === '#' ? 'index' : c.n.replace(/\(.*?\)/g, ''), `c${i}`).toLowerCase(), i }));
      const used = new Set();
      for (const c of cols) { let f = c.f, k = 2; while (used.has(f)) f = `${c.f}_${k++}`; c.f = f; used.add(f); }
      out.push(`/* ${comment(t.title)}: ${t.rows.length} row${t.rows.length === 1 ? '' : 's'} */`);
      out.push(`typedef struct ${tn}_t {`);
      for (const c of cols) out.push(`    ${c.t === 's' ? 'const char *' : c.t === 'd' ? 'int64_t ' : 'uint64_t '}${c.f};`);
      out.push(`} ${tn}_t;`);
      out.push(`#define ${tn.toUpperCase()}_COUNT ${t.rows.length}`);
      out.push(`static const ${tn}_t ${tn}[${Math.max(1, t.rows.length)}] = {`);
      for (const r of t.rows) out.push('    { ' + cols.map((c) => (c.t === 's' ? cstr(r[c.i] ?? '') : cnum(r[c.i], c.t))).join(', ') + ' },');
      if (!t.rows.length) out.push('    { 0 },');
      out.push('};', '');
    }
  };
  if (headerC) {
    out.push('/* The file header as a packed struct, from the binary template. */');
    out.push(headerC.replace(/^#include <stdint.h>\n?/m, '').replace(/, from Hex Viewer Pro\./, ', from the binary template.').trim(), '');
  }
  emit(model, base);
  for (const s of model.slices || []) {
    out.push(`/* ===== Slice ${comment(s.arch)} at 0x${s.offset.toString(16).toUpperCase()} ===== */`, '');
    emit(s.model, `${base}_${ident(s.arch).toLowerCase()}`);
  }
  out.push(`#endif /* ${guard} */`, '');
  return out.join('\n');
}

// ---------- compare ----------

const COMPARE_TABLES = ['sections', 'segments', 'libraries', 'imports', 'exports', 'directories', 'loadcommands', 'symbols'];

/** The model a comparison reads: a universal binary compares its first slice unless arch picks one. */
function pickSlice(model, arch) {
  if (!model.slices || !model.slices.length) return model;
  return (arch && model.slices.find((s) => s.arch === arch) || model.slices[0]).model;
}

/**
 * Compare two models. Returns { header: [{ name, a, b }], tables: [{ id, title, added, removed, changed, same }] }.
 * Rows match by the table's key columns; "changed" lists the columns that differ.
 */
function compareModels(a, b, opts = {}) {
  const A = pickSlice(a, opts.arch), B = pickSlice(b, opts.arch);
  const res = { titleA: A.title, titleB: B.title, header: [], tables: [] };
  const sa = new Map(dedupe(A.summary || [])), sb = new Map(dedupe(B.summary || []));
  for (const k of new Set([...sa.keys(), ...sb.keys()])) if (sa.get(k) !== sb.get(k)) res.header.push({ name: k, a: sa.get(k) ?? '', b: sb.get(k) ?? '' });
  const ga = new Map(), gb = new Map();
  for (const g of A.groups || []) for (const f of g.fields) ga.set(`${g.title} / ${f[0]}`, String(f[1]));
  for (const g of B.groups || []) for (const f of g.fields) gb.set(`${g.title} / ${f[0]}`, String(f[1]));
  for (const k of new Set([...ga.keys(), ...gb.keys()])) {
    if (ga.get(k) !== gb.get(k) && !res.header.some((h) => h.name === k)) res.header.push({ name: k, a: ga.get(k) ?? '', b: gb.get(k) ?? '' });
  }
  const maxList = opts.maxList || 5000;
  for (const id of COMPARE_TABLES) {
    const ta = (A.tables || []).find((t) => t.id === id), tb = (B.tables || []).find((t) => t.id === id);
    if (!ta && !tb) continue;
    const t0 = ta || tb;
    const keyCols = t0.key || [0];
    // Position columns (# and offsets) differ whenever anything moves; leave them out of the "changed" check.
    const skip = new Set(t0.columns.map((c, i) => (c.n === '#' || /offset|IAT entry/i.test(c.n) || (id === 'loadcommands' && c.n === 'Size') ? i : -1)).filter((i) => i >= 0));
    const keyOf = (r) => keyCols.map((i) => String(r[i])).join(' → ');
    const index = (t) => {
      const m = new Map();
      for (const r of t ? t.rows : []) { let k = keyOf(r), n = 2; while (m.has(k)) k = `${keyOf(r)} (${n++})`; m.set(k, r); }
      return m;
    };
    const ma = index(ta), mb = index(tb);
    const out = { id, title: t0.title, columns: t0.columns.map((c) => c.n), added: [], removed: [], changed: [], same: 0, countA: ma.size, countB: mb.size };
    for (const [k, r] of mb) if (!ma.has(k)) { if (out.added.length < maxList) out.added.push(k); }
    for (const [k, r] of ma) {
      const rb = mb.get(k);
      if (!rb) { if (out.removed.length < maxList) out.removed.push(k); continue; }
      const diffs = [];
      r.forEach((v, i) => { if (!skip.has(i) && !keyCols.includes(i) && String(v) !== String(rb[i])) diffs.push({ column: t0.columns[i].n, a: v, b: rb[i] }); });
      if (diffs.length) { if (out.changed.length < maxList) out.changed.push({ key: k, diffs }); } else out.same++;
    }
    out.addedCount = [...mb.keys()].filter((k) => !ma.has(k)).length;
    out.removedCount = [...ma.keys()].filter((k) => !mb.has(k)).length;
    res.tables.push(out);
  }
  return res;
}

/** Compare result to Markdown, for "Save as Markdown". */
function compareMarkdown(res, nameA, nameB) {
  const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const out = [`# ${esc(nameA)} compared with ${esc(nameB)}`, '', `- A: ${esc(nameA)} (${esc(res.titleA)})`, `- B: ${esc(nameB)} (${esc(res.titleB)})`, ''];
  if (res.header.length) {
    out.push('## Header differences', '', '| Field | A | B |', '|---|---|---|');
    for (const h of res.header) out.push(`| ${esc(h.name)} | ${esc(h.a)} | ${esc(h.b)} |`);
    out.push('');
  }
  for (const t of res.tables) {
    out.push(`## ${esc(t.title)}`, '', `A has ${t.countA}, B has ${t.countB}: ${t.addedCount} added, ${t.removedCount} removed, ${t.changed.length} changed, ${t.same} the same.`, '');
    if (t.added.length) out.push('Added in B:', '', ...t.added.map((k) => `- ${esc(k)}`), '');
    if (t.removed.length) out.push('Removed in B:', '', ...t.removed.map((k) => `- ${esc(k)}`), '');
    if (t.changed.length) {
      out.push('Changed:', '', '| Row | Column | A | B |', '|---|---|---|---|');
      for (const c of t.changed) for (const d of c.diffs) out.push(`| ${esc(c.key)} | ${esc(d.column)} | ${esc(d.a)} | ${esc(d.b)} |`);
      out.push('');
    }
  }
  return out.join('\n');
}

// ---------- find in folder ----------

/** Build a matcher from the user's text: plain text (case-insensitive substring) or /regex/flags (length-capped). */
function matcher(query) {
  const q = String(query || '').trim();
  if (!q) return null;
  const re = /^\/(.{1,200})\/([imsu]*)$/.exec(q);
  if (re) {
    // Guard against patterns that can take exponential time on long names: no nested quantifiers.
    if (/\([^)]*[+*}][^)]*\)[+*{]/.test(re[1])) throw new Error('This pattern has a repeated group inside a repeat; please write it without nesting.');
    const rx = new RegExp(re[1], re[2]);
    return { test: (s) => s.length <= 4096 && rx.test(s), label: q };
  }
  const low = q.toLowerCase();
  return { test: (s) => s.toLowerCase().includes(low), label: q };
}

/** Rows of one model that match: [{ kind, name, library, detail, arch }]. */
function findInModel(model, match, max = 1000) {
  const hits = [];
  const scan = (m, arch) => {
    const want = [['imports', 'import'], ['exports', 'export'], ['libraries', 'library'], ['symbols', 'symbol']];
    for (const [id, kind] of want) {
      const t = (m.tables || []).find((x) => x.id === id);
      if (!t) continue;
      const libCol = t.columns.findIndex((c) => c.n === 'Library');
      for (const r of t.rows) {
        if (hits.length >= max) return;
        const name = String(r[0]);
        const lib = libCol >= 0 ? String(r[libCol] || '') : '';
        if (match.test(name)) hits.push({ kind, name, library: kind === 'library' ? '' : lib, arch: arch || '' });
      }
    }
  };
  if (model.slices && model.slices.length) for (const s of model.slices) scan(s.model, s.arch);
  else scan(model, '');
  // A symbol row that repeats an import or export of the same name adds nothing.
  const seen = new Set(hits.filter((h) => h.kind !== 'symbol').map((h) => `${h.arch}|${h.name}`));
  return hits.filter((h) => h.kind !== 'symbol' || !seen.has(`${h.arch}|${h.name}`));
}

module.exports = { toJson, toJsonObject, toCHeader, compareModels, compareMarkdown, matcher, findInModel, pickSlice, COMPARE_TABLES };
