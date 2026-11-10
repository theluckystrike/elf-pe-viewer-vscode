'use strict';
// Binary templates: a JSON file describes the structures of a file format; parse() reads a document with it
// and returns a tree of fields (name, offset, size, value). Templates are data, never code: expressions go
// through core/expr.js. Every parse has limits (fields, depth, array length, time), so a hostile file or a
// hostile template cannot hang or blow up the extension host. Reads go through doc.read(offset, length),
// so unsaved edits show and 4 GB files work (only the bytes a template touches are read).
//
// Template shape (see TEMPLATES.md):
//   { "id", "name", "extensions": [..], "match": [[{ "offset", "hex" } | { "offset", "type", "min", "max" }], ...],
//     "endian": "little" | "big", "root": "StructName", "structs": { "Name": [fields] | { "fields", "endian", "size", "label" } },
//     "enums": { "Name": { "1": "text" } }, "flags": { "Name": { "0x1": "text" } } }
// Field: { "name", "type", "count" | "until" | "while", "length", "size", "at", "peek", "if", "endian", "enum", "flags",
//          "format", "expect", "label", "encoding", "comment", "value" } or a directive { "seek" | "skip" | "align" | "skipWhitespace" }.
const { evaluate, ExprError } = require('./expr');

const PRIM = {
  u8: [1, 'u'], u16: [2, 'u'], u24: [3, 'u'], u32: [4, 'u'], u64: [8, 'u'],
  i8: [1, 'i'], i16: [2, 'i'], i24: [3, 'i'], i32: [4, 'i'], i64: [8, 'i'],
  f32: [4, 'f'], f64: [8, 'f'],
};
const VAR_TYPES = new Set(['bytes', 'char', 'string', 'zstring', 'asciiint', 'line', 'uleb128', 'sleb128']);
const C_TYPES = { u8: 'uint8_t', u16: 'uint16_t', u24: 'uint8_t', u32: 'uint32_t', u64: 'uint64_t', i8: 'int8_t', i16: 'int16_t', i24: 'uint8_t', i32: 'int32_t', i64: 'int64_t', f32: 'float', f64: 'double' };
const DEFAULT_LIMITS = { maxNodes: 50000, maxDepth: 48, maxArray: 100000, maxMs: 15000, maxString: 4096, maxFind: 16 << 20 };
const BLOCK = 1 << 16;
const MAX_BLOCKS = 64;

class Stop extends Error {}
class NeedRead extends Error { constructor(off, n) { super('need read'); this.off = off; this.n = n; } }

// ---------- reading with a small block cache ----------

class Reader {
  constructor(doc) { this.doc = doc; this.size = doc.size; this.blocks = new Map(); }
  async load(k) {
    if (this.blocks.has(k)) { const b = this.blocks.get(k); this.blocks.delete(k); this.blocks.set(k, b); return b; }
    const b = await this.doc.read(k * BLOCK, BLOCK);
    this.blocks.set(k, b);
    if (this.blocks.size > MAX_BLOCKS) this.blocks.delete(this.blocks.keys().next().value);
    return b;
  }
  /** Up to n bytes at off (shorter at the end of the file). */
  async bytes(off, n) {
    n = Math.max(0, Math.min(n, this.size - off));
    if (n <= 0) return new Uint8Array(0);
    const k0 = Math.floor(off / BLOCK), k1 = Math.floor((off + n - 1) / BLOCK);
    if (k0 === k1) { const b = await this.load(k0); const s = off - k0 * BLOCK; return b.subarray(s, Math.min(b.length, s + n)); }
    if (n > 4 * BLOCK) return this.doc.read(off, n);
    const out = new Uint8Array(n);
    let got = 0;
    for (let k = k0; k <= k1; k++) {
      const b = await this.load(k);
      const s = k === k0 ? off - k0 * BLOCK : 0;
      const take = Math.min(b.length - s, n - got);
      if (take <= 0) break;
      out.set(b.subarray(s, s + take), got); got += take;
    }
    return out.subarray(0, got);
  }
  /** Synchronous peek for expressions: throws NeedRead when the block is not loaded yet. */
  peekSync(off, n) {
    if (off + n > this.size) throw new ExprError(`Offset 0x${off.toString(16)} is past the end of the file.`);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      const k = Math.floor((off + i) / BLOCK);
      const b = this.blocks.get(k);
      if (!b) throw new NeedRead(off, n);
      out[i] = b[off + i - k * BLOCK];
    }
    return out;
  }
}

function readNum(b, kind, size, little) {
  const dv = new DataView(b.buffer, b.byteOffset, b.length);
  if (kind === 'f') return size === 4 ? dv.getFloat32(0, little) : dv.getFloat64(0, little);
  if (size === 8) {
    const v = kind === 'u' ? dv.getBigUint64(0, little) : dv.getBigInt64(0, little);
    return v >= -9007199254740991n && v <= 9007199254740991n ? Number(v) : v;
  }
  let v = 0;
  for (let i = 0; i < size; i++) v = v * 256 + b[little ? size - 1 - i : i];
  if (kind === 'i' && v >= 2 ** (size * 8 - 1)) v -= 2 ** (size * 8);
  return v;
}

// ---------- display ----------

const hex2 = b => (b < 16 ? '0' : '') + b.toString(16).toUpperCase();
const hexBytes = (b, max = 16) => Array.from(b.subarray(0, max), hex2).join(' ') + (b.length > max ? ' …' : '');
const hexNum = v => (typeof v === 'bigint' ? (v < 0n ? '-0x' + (-v).toString(16) : '0x' + v.toString(16)) : (v < 0 ? '-0x' + (-v).toString(16) : '0x' + v.toString(16))).toUpperCase().replace('0X', '0x');

function dosDate(v) { const d = v & 31, m = (v >> 5) & 15, y = 1980 + (v >> 9); return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`; }
function dosTime(v) { return `${String(v >> 11).padStart(2, '0')}:${String((v >> 5) & 63).padStart(2, '0')}:${String((v & 31) * 2).padStart(2, '0')}`; }

function quote(s, max = 200) {
  const t = s.length > max ? s.slice(0, max) + '…' : s;
  return '"' + t.replace(/[\x00-\x1f\x7f]/g, c => (c === '\n' ? '\\n' : c === '\r' ? '\\r' : c === '\t' ? '\\t' : c === '\0' ? '\\0' : '\\x' + hex2(c.charCodeAt(0)))) + '"';
}

function displayNum(v, f, tpl) {
  const n = typeof v === 'bigint' ? v : v;
  let base;
  if (f.format === 'hex') base = hexNum(n);
  else if (f.format === 'dec' || typeof n === 'number' && !Number.isInteger(n)) base = String(n);
  else if (f.format === 'unix' && typeof n === 'number') { const d = new Date(n * 1000); base = isNaN(d) ? String(n) : d.toISOString().replace('.000Z', 'Z') + ` (${n})`; }
  else if (f.format === 'dosdate') base = `${dosDate(Number(n))} (${hexNum(n)})`;
  else if (f.format === 'dostime') base = `${dosTime(Number(n))} (${hexNum(n)})`;
  else if (f.format === 'char' && typeof n === 'number') base = `${quote(String.fromCharCode(n))} (${hexNum(n)})`;
  else base = `${n} (${hexNum(n)})`;
  const en = lookupMap(tpl, 'enums', f.enum);
  if (en) {
    const name = en[String(n)] !== undefined ? en[String(n)] : en[hexNum(n)] !== undefined ? en[hexNum(n)] : en[hexNum(n).toLowerCase()];
    return name !== undefined ? `${name} (${f.format === 'hex' || f.format === undefined ? hexNum(n) : n})` : `${base}, unknown value`;
  }
  const fl = lookupMap(tpl, 'flags', f.flags);
  if (fl) {
    const set = [];
    const big = BigInt.asUintN(64, BigInt(typeof n === 'bigint' ? n : Math.trunc(n)));
    let rest = big;
    for (const [k, name] of Object.entries(fl)) {
      let bit; try { bit = BigInt(k); } catch { continue; }
      if (bit && (big & bit) === bit) { set.push(name); rest &= ~bit; }
    }
    if (rest) set.push(hexNum(rest));
    return `${set.length ? set.join(' | ') : 'none'} (${hexNum(n)})`;
  }
  return base;
}

function enumName(v, f, tpl) {
  const en = lookupMap(tpl, 'enums', f.enum);
  if (!en) return undefined;
  const h = hexNum(v);
  return en[String(v)] !== undefined ? en[String(v)] : en[h] !== undefined ? en[h] : en[h.toLowerCase()];
}

function lookupMap(tpl, kind, ref) {
  if (!ref) return null;
  if (typeof ref === 'object') return ref;
  return (tpl[kind] && tpl[kind][ref]) || null;
}

// ---------- template checks ----------

/** Plain-language check of a template object. Returns a list of problems (empty when it is usable). */
function checkTemplate(t) {
  const errs = [];
  if (!t || typeof t !== 'object' || Array.isArray(t)) return ['The template must be a JSON object.'];
  if (typeof t.name !== 'string' || !t.name) errs.push('"name" is missing.');
  if (!t.structs || typeof t.structs !== 'object') errs.push('"structs" is missing.');
  const root = t.root || 'File';
  if (t.structs && !t.structs[root]) errs.push(`The root struct "${root}" is not in "structs".`);
  if (t.endian && !['little', 'big'].includes(t.endian)) errs.push('"endian" must be "little" or "big".');
  if (t.match !== undefined && !Array.isArray(t.match)) errs.push('"match" must be a list.');
  const known = n => PRIM[n] || VAR_TYPES.has(n) || (t.structs && t.structs[n]);
  const visit = (fields, where) => {
    if (!Array.isArray(fields)) { errs.push(`${where}: the fields must be a list.`); return; }
    fields.forEach((f, i) => {
      if (!f || typeof f !== 'object') { errs.push(`${where}, field ${i + 1}: must be an object.`); return; }
      const directive = ['seek', 'skip', 'align', 'skipWhitespace'].some(k => k in f);
      if (directive) return;
      if (typeof f.name !== 'string' || !f.name) errs.push(`${where}, field ${i + 1}: "name" is missing.`);
      if ('value' in f) return;
      const ty = f.type;
      if (typeof ty === 'string') { if (!known(ty)) errs.push(`${where}.${f.name}: unknown type "${ty}".`); }
      else if (ty && typeof ty === 'object' && 'switch' in ty) {
        for (const c of Object.values(ty.cases || {})) if (!known(c)) errs.push(`${where}.${f.name}: unknown type "${c}" in a switch.`);
        if (ty.default && !known(ty.default)) errs.push(`${where}.${f.name}: unknown default type "${ty.default}".`);
      } else if (Array.isArray(ty)) visit(ty, `${where}.${f.name}`);
      else errs.push(`${where}.${f.name || i + 1}: "type" is missing.`);
      if (['bytes', 'char', 'string'].includes(ty) && f.length === undefined) errs.push(`${where}.${f.name}: type ${ty} needs "length".`);
    });
  };
  for (const [name, s] of Object.entries(t.structs || {})) visit(Array.isArray(s) ? s : s && s.fields, name);
  return errs;
}

// ---------- matching ----------

async function matchScore(t, reader, ext) {
  let best = 0;
  for (const alt of t.match || []) {
    let ok = alt.length > 0, score = 0;
    for (const m of alt) {
      try {
        if (m.hex) {
          const want = parseHex(m.hex);
          const off = m.offset < 0 ? reader.size + m.offset : m.offset || 0;
          const got = await reader.bytes(off, want.length);
          if (got.length !== want.length || !got.every((v, i) => v === want[i])) { ok = false; break; }
          score += want.length * 10;
        } else if (m.type && PRIM[m.type]) {
          const [sz, kind] = PRIM[m.type];
          const b = await reader.bytes(m.offset || 0, sz);
          if (b.length < sz) { ok = false; break; }
          const v = Number(readNum(b, kind, sz, m.endian !== 'big'));
          if ((m.min !== undefined && v < m.min) || (m.max !== undefined && v > m.max)) { ok = false; break; }
          score += 5;
        } else if (m.text) {
          const want = new TextEncoder().encode(m.text);
          const got = await reader.bytes(m.offset || 0, want.length);
          if (got.length !== want.length || !got.every((v, i) => v === want[i])) { ok = false; break; }
          score += want.length * 10;
        }
      } catch { ok = false; break; }
    }
    if (ok) best = Math.max(best, score);
  }
  if (!best && ext && (t.extensions || []).includes(ext)) best = 1;
  return best;
}

/** Templates that fit the document, best first: [{ template, score }]. */
async function detect(templates, doc, fileName) {
  const reader = doc instanceof Reader ? doc : new Reader(doc);
  const ext = String(fileName || '').toLowerCase().replace(/^.*\./, '');
  const out = [];
  for (const t of templates) {
    const score = await matchScore(t, reader, ext);
    if (score > 0) out.push({ template: t, score });
  }
  return out.sort((a, b) => b.score - a.score);
}

function parseHex(s) {
  const clean = String(s).replace(/0x/gi, '').replace(/[\s,]/g, '');
  if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new Error(`Bad hex bytes: ${s}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// ---------- parsing ----------

/**
 * Parse `doc` (size + read(offset, length)) with template `t`. opts: { limits, shouldStop }.
 * Returns { root, nodes, error, ms }. Nodes: { __node, kind: 'struct'|'array'|'value', name, type, offset, size,
 * value?, display?, children?, error?, label?, computed? }.
 */
async function parse(t, doc, opts = {}) {
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits || {}) };
  const shouldStop = opts.shouldStop || (() => false);
  const reader = doc instanceof Reader ? doc : new Reader(doc);
  const size = reader.size;
  const t0 = Date.now();
  let nodes = 0, lastYield = Date.now();
  const structs = t.structs || {};
  const def = name => { const s = structs[name]; return Array.isArray(s) ? { fields: s } : s; };

  const count = async () => {
    if (++nodes > limits.maxNodes) throw new Stop(`The template made more than ${limits.maxNodes.toLocaleString('en-US')} fields; the tree stops here.`);
    if (Date.now() - lastYield > 8) {
      await new Promise(r => setImmediate(r)); lastYield = Date.now();
      if (shouldStop()) throw new Stop('Stopped.');
      if (Date.now() - t0 > limits.maxMs) throw new Stop(`The template ran longer than ${limits.maxMs / 1000} seconds; the tree stops here.`);
    }
  };

  // Scope for expressions: the current struct node, then its parents.
  const scopeOf = (node, cur, extra) => ({
    lookup(name) {
      if (extra && name in extra) return extra[name];
      if (name === 'this') return node;
      if (name === 'parent') return node.parentNode || null;
      if (name === 'root') return rootNode;
      if (name === 'i') { for (let n = node; n; n = n.parentNode) if (n.loopIndex !== undefined) return n.loopIndex; }
      for (let n = node; n; n = n.parentNode) if (n.vars && n.vars.has(name)) return n.vars.get(name);
      throw new ExprError(`"${name}" is not defined yet.`);
    },
    member(o, key) {
      if (o == null) throw new ExprError(`Cannot read "${key}" of nothing.`);
      if (typeof o === 'string') { if (key === 'length') return o.length; if (Number.isInteger(key)) return o.charCodeAt(key); throw new ExprError(`Text has no "${key}".`); }
      if (o.__node && o.kind === 'array') {
        if (key === 'length') return o.children.length;
        const i = Number(key);
        if (Number.isInteger(i) && i >= 0 && i < o.children.length) return o.children[i];
        if (Number.isInteger(i) && i < 0 && -i <= o.children.length) return o.children[o.children.length + i];
        throw new ExprError(`${o.name} has no element ${key}.`);
      }
      if (o.__node && o.kind === 'struct') {
        if (key === 'offset' && !o.vars.has('offset')) return o.offset;
        if (key === 'size' && !o.vars.has('size')) return o.size;
        if (o.vars.has(key)) return o.vars.get(key);
        throw new ExprError(`${o.name} has no field "${key}".`);
      }
      if (o.__node && o.kind === 'value') { if (key === 'offset') return o.offset; if (key === 'size') return o.size; }
      throw new ExprError(`Cannot read "${key}".`);
    },
    pos: () => cur.pos,
    size: () => size,
    start: () => node.offset,
    end: () => cur.end,
    peek(fn, off) {
      const n = fn === 'u8' ? 1 : /16/.test(fn) ? 2 : 4;
      const little = /le$/.test(fn) ? true : /be$/.test(fn) ? false : cur.little;
      return readNum(reader.peekSync(off, n), 'u', n, little);
    },
  });

  // Evaluate with automatic loading of bytes that u8()/u16()/u32() need.
  const ev = async (src, node, cur, extra) => {
    for (let tries = 0; ; tries++) {
      try { return evaluate(src, scopeOf(node, cur, extra)); }
      catch (e) {
        if (e instanceof NeedRead && tries < 64) { await reader.bytes(e.off, e.n); continue; }
        if (e instanceof ExprError || e instanceof NeedRead) throw new Stop(`${e.message || 'Bad expression'} (in ${typeof src === 'string' ? src : JSON.stringify(src)})`);
        throw e;
      }
    }
  };
  const evNum = async (src, node, cur, what) => {
    const v = typeof src === 'number' ? src : await ev(src, node, cur);
    const n = typeof v === 'bigint' ? Number(v) : typeof v === 'boolean' ? Number(v) : v;
    if (typeof n !== 'number' || !Number.isFinite(n)) throw new Stop(`${what} is not a number (${src}).`);
    return Math.trunc(n);
  };
  const endianOf = async (spec, node, cur, fallback) => {
    if (!spec) return fallback;
    if (spec === 'little' || spec === 'big') return spec === 'little';
    const v = await ev(spec, node, cur);
    if (v !== 'little' && v !== 'big') throw new Stop(`The byte order must be "little" or "big", not ${v}.`);
    return v === 'little';
  };

  const mk = (kind, name, type, offset, parentNode) => ({ __node: true, kind, name, type, offset, size: 0, parentNode, children: kind === 'value' ? undefined : [], vars: kind === 'struct' ? new Map() : undefined });

  async function resolveType(f, node, cur) {
    const ty = f.type;
    if (typeof ty === 'string' || Array.isArray(ty)) return ty;
    if (ty && typeof ty === 'object' && 'switch' in ty) {
      const v = await ev(ty.switch, node, cur);
      const key = typeof v === 'bigint' ? v.toString() : String(v);
      const cases = ty.cases || {};
      let hit = cases[key];
      if (hit === undefined && typeof v === 'number') hit = cases[hexNum(v)] !== undefined ? cases[hexNum(v)] : cases[hexNum(v).toLowerCase()];
      return hit !== undefined ? hit : (ty.default || null);
    }
    throw new Stop(`Field ${f.name} has no type.`);
  }

  /** Parse one item of type `ty` at cur.pos into a node; advances cur.pos. */
  async function one(f, ty, name, node, cur, depth) {
    await count();
    const offset = cur.pos;
    if (ty === null) {
      // switch without a match: show the bytes the size covers, if any
      const v = mk('value', name, 'bytes', offset, node);
      v.size = 0; v.display = '(no case for this value)';
      return v;
    }
    if (Array.isArray(ty) || structs[ty]) {
      if (depth > limits.maxDepth) throw new Stop(`Structs are nested more than ${limits.maxDepth} deep.`);
      const d = Array.isArray(ty) ? { fields: ty } : def(ty);
      const s = mk('struct', name, Array.isArray(ty) ? 'struct' : ty, offset, node);
      // size and byte order are evaluated in the new struct's scope: its parent is the struct that holds the field
      const little = await endianOf(d.endian, s, cur, cur.little);
      const fixed = f.size !== undefined ? await evNum(f.size, s, cur, `The size of ${name}`) : d.size !== undefined ? await evNum(d.size, s, cur, `The size of ${name}`) : null;
      if (fixed !== null && fixed < 0) throw new Stop(`${name} has a negative size (${fixed}).`);
      const inner = { pos: offset, little, end: fixed !== null ? Math.min(cur.end, offset + fixed) : cur.end };
      try {
        for (const g of d.fields || []) await field(g, s, inner, depth + 1);
      } catch (e) {
        s.size = Math.max(0, inner.pos - offset);
        if (e instanceof Stop && !s.error) s.error = e.message;
        throw Object.assign(e, { partial: s });
      }
      s.size = fixed !== null ? fixed : inner.pos - offset;
      const lab = d.label || f.label;
      if (lab) {
        // a label that names an enum field shows the enum name (LC_SEGMENT_64, not 25)
        const direct = typeof lab === 'string' && /^[A-Za-z_]\w*$/.test(lab) ? s.vars.get(lab) : null;
        if (direct && direct.enumName !== undefined) s.label = direct.enumName;
        else { try { const l = await ev(lab, s, inner); s.label = l && typeof l === 'object' ? '' : String(l); } catch { /* a label is optional */ } }
      }
      cur.pos = offset + s.size;
      return s;
    }
    if (PRIM[ty]) {
      const [sz, kind] = PRIM[ty];
      const little = await endianOf(f.endian, node, cur, cur.little);
      const v = mk('value', name, ty, offset, node);
      v.size = sz;
      if (offset + sz > size) { v.error = `Needs ${sz} bytes at 0x${offset.toString(16).toUpperCase()}, past the end of the file.`; throw Object.assign(new Stop(v.error), { partial: v }); }
      const b = await reader.bytes(offset, sz);
      v.value = readNum(b, kind, sz, little);
      v.display = displayNum(v.value, f, t);
      const en = enumName(v.value, f, t);
      if (en !== undefined) v.enumName = String(en);
      cur.pos = offset + sz;
      return v;
    }
    if (VAR_TYPES.has(ty)) {
      const v = mk('value', name, ty, offset, node);
      if (ty === 'bytes' || ty === 'char' || ty === 'string') {
        const len = await evNum(f.length, node, cur, `The length of ${name}`);
        if (len < 0) { v.error = `${name} has a negative length (${len}).`; throw Object.assign(new Stop(v.error), { partial: v }); }
        v.size = len; v.type = `${ty}[${len}]`;
        if (offset + len > size) { v.error = `${name} needs ${len.toLocaleString('en-US')} bytes, past the end of the file.`; v.size = Math.max(0, size - offset); throw Object.assign(new Stop(v.error), { partial: v }); }
        const b = await reader.bytes(offset, Math.min(len, ty === 'bytes' ? 32 : limits.maxString));
        if (ty === 'bytes') { v.display = len ? hexBytes(b) : '(empty)'; v.value = len <= 8 ? hexBytes(b, 8) : undefined; }
        else {
          // char[n] is a C text field: it ends at the first zero byte
          const z = ty === 'char' ? b.indexOf(0) : -1;
          v.value = decode(z >= 0 ? b.subarray(0, z) : b, f.encoding || (ty === 'char' ? 'latin1' : 'utf8'));
          if (len > limits.maxString && z < 0) v.value += '…';
          v.display = quote(v.value);
        }
        cur.pos = offset + len;
      } else if (ty === 'zstring' || ty === 'line') {
        const max = f.length !== undefined ? await evNum(f.length, node, cur, `The length of ${name}`) : limits.maxString;
        const b = await reader.bytes(offset, Math.min(max, limits.maxString) + 1);
        const stopAt = ty === 'zstring' ? b.indexOf(0) : b.indexOf(10);
        const n = stopAt >= 0 ? stopAt : Math.min(b.length, max);
        let text = b.subarray(0, n);
        if (ty === 'line' && text.length && text[text.length - 1] === 13) text = text.subarray(0, text.length - 1);
        v.value = decode(text, f.encoding || 'utf8'); v.display = quote(v.value);
        v.size = n + (stopAt >= 0 ? 1 : 0);
        cur.pos = offset + v.size;
      } else if (ty === 'asciiint') {
        const b = await reader.bytes(offset, 40);
        let i = 0;
        while (i < b.length && (b[i] === 32 || b[i] === 9 || b[i] === 10 || b[i] === 13 || b[i] === 12 || b[i] === 0)) i++;
        let j = i;
        if (j < b.length && (b[j] === 45 || b[j] === 43)) j++;
        while (j < b.length && b[j] >= 48 && b[j] <= 57) j++;
        const s = decode(b.subarray(i, j), 'latin1');
        if (!/\d/.test(s)) { v.size = j; v.error = 'No digits here.'; throw Object.assign(new Stop(`${name}: no number at 0x${offset.toString(16).toUpperCase()}.`), { partial: v }); }
        v.value = Number(s); v.display = displayNum(v.value, f, t); v.size = j;
        cur.pos = offset + j;
      } else {
        const b = await reader.bytes(offset, 10);
        let r = 0n, shift = 0n, i = 0, byte = 0x80;
        while (i < b.length && (byte & 0x80)) { byte = b[i++]; r |= BigInt(byte & 0x7f) << shift; shift += 7n; }
        if (byte & 0x80) { v.error = 'The LEB128 number does not end.'; throw Object.assign(new Stop(v.error), { partial: v }); }
        if (ty === 'sleb128' && (byte & 0x40)) r -= 1n << shift;
        v.value = r >= -9007199254740991n && r <= 9007199254740991n ? Number(r) : r;
        v.display = displayNum(v.value, f, t); v.size = i;
        cur.pos = offset + i;
      }
      return v;
    }
    throw new Stop(`Unknown type "${ty}" for ${name}.`);
  }

  async function field(f, node, cur, depth) {
    if (f.if !== undefined && !(await ev(f.if, node, cur))) return;
    if ('seek' in f) { cur.pos = await evNum(f.seek, node, cur, 'seek'); return; }
    if ('skip' in f) { cur.pos += await evNum(f.skip, node, cur, 'skip'); return; }
    if ('align' in f) { const a = await evNum(f.align, node, cur, 'align'); if (a > 0) cur.pos = Math.ceil(cur.pos / a) * a; return; }
    if ('skipWhitespace' in f) {
      for (let n = 0; n < 4096; n++) { const b = await reader.bytes(cur.pos, 1); if (!b.length || ![9, 10, 12, 13, 32, 0].includes(b[0])) break; cur.pos++; }
      return;
    }
    const name = f.name;
    if ('value' in f) {
      await count();
      const v = mk('value', name, 'value', cur.pos, node);
      v.computed = true;
      v.value = await ev(f.value, node, cur);
      if (v.value && typeof v.value === 'object') v.value = v.value.__node ? (v.value.kind === 'value' ? v.value.value : v.value.name) : String(v.value);
      v.display = typeof v.value === 'number' || typeof v.value === 'bigint' ? displayNum(v.value, f, t) : typeof v.value === 'string' ? quote(v.value) : String(v.value);
      if (f.hidden) { node.vars.set(name, v); return; }
      addChild(node, v);
      return;
    }
    const saved = cur.pos;
    if (f.at !== undefined) {
      cur.pos = await locate(f.at, node, cur);
    }
    if (cur.pos < 0 || cur.pos > size) throw new Stop(`${name} would start at 0x${cur.pos.toString(16).toUpperCase()}, outside the file (${size.toLocaleString('en-US')} bytes).`);
    const isArray = f.count !== undefined || f.until !== undefined || f.while !== undefined;
    let made;
    try {
      if (!isArray) {
        const ty = await resolveType(f, node, cur);
        made = await one(f, ty, name, node, cur, depth);
      } else {
        made = mk('array', name, '', cur.pos, node);
        addChild(node, made);
        node.vars.set(name, made); // elements can read earlier elements: name[i - 1]
        const n = f.count !== undefined ? await evNum(f.count, node, cur, `The count of ${name}`) : null;
        if (n !== null && n < 0) throw new Stop(`${name} has a negative count (${n}).`);
        const cap = Math.min(n === null ? Infinity : n, limits.maxArray);
        const arrEnd = f.arraySize !== undefined ? cur.pos + await evNum(f.arraySize, node, cur, `The size of ${name}`) : null;
        let i = 0, tyName = '';
        const outerIndex = node.loopIndex;
        try {
        for (; i < cap; i++) {
          node.loopIndex = i;
          if (arrEnd !== null && cur.pos >= arrEnd) break;
          if (f.while !== undefined && !(await ev(f.while, node, cur, { _: made.children[made.children.length - 1], i }))) break;
          if (f.while === undefined && n === null && f.until === 'eof' && cur.pos >= Math.min(cur.end, size)) break;
          if (f.elementAt !== undefined) {
            const at = await ev(f.elementAt, node, cur, { _: made.children[made.children.length - 1], i });
            cur.pos = typeof at === 'bigint' ? Number(at) : Math.trunc(Number(at));
            if (!Number.isFinite(cur.pos)) throw new Stop(`The offset of ${name}[${i}] is not a number.`);
            if (cur.pos < 0 || cur.pos > size) throw new Stop(`${name}[${i}] would start at 0x${cur.pos.toString(16).toUpperCase()}, outside the file.`);
          }
          const before = cur.pos;
          const ty = await resolveType(f, node, cur);
          let el;
          try { el = await one(f, ty, `${name}[${i}]`, node, cur, depth); }
          catch (e) { if (e.partial) { e.partial.name = `${name}[${i}]`; addChild(made, e.partial); e.partial = made; } throw e; }
          el.index = i;
          addChild(made, el);
          tyName = tyName === '' ? el.type : tyName === el.type ? tyName : 'mixed';
          if (f.until !== undefined && f.until !== 'eof' && (await ev(f.until, node, cur, { _: el, i }))) { i++; break; }
          if (cur.pos === before && n === null) { made.error = `${name}[${i}] is empty (0 bytes), so the list stops here.`; i++; break; }
        }
        } finally { node.loopIndex = outerIndex; }
        if (n !== null && n > limits.maxArray && i >= limits.maxArray) made.error = `${n.toLocaleString('en-US')} items; the first ${limits.maxArray.toLocaleString('en-US')} are shown.`;
        else if (n === null && i >= limits.maxArray) made.error = `More than ${limits.maxArray.toLocaleString('en-US')} items; the list stops here.`;
        made.type = `${tyName && tyName !== 'mixed' ? tyName : 'item'}[${made.children.length}]`;
        made.size = f.elementAt !== undefined ? made.children.reduce((m, c) => Math.max(m, c.offset + c.size), made.offset) - made.offset : cur.pos - made.offset;
        if (f.elementAt !== undefined && made.children.length) made.offset = Math.min(...made.children.map(c => c.offset));
        if (arrEnd !== null) { made.size = arrEnd - made.offset; cur.pos = arrEnd; }
        node.vars.set(name, made);
        if (f.peek) cur.pos = saved;
        return;
      }
    } catch (e) {
      if (e.partial && e.partial !== node) {
        if (e.partial.kind !== 'array' || !node.children.includes(e.partial)) addChild(node, e.partial);
        node.vars.set(name, e.partial);
        e.partial = null;
      }
      throw e;
    }
    if (f.expect !== undefined && made.kind === 'value') {
      const exp = f.expect;
      const ok = typeof exp === 'number' ? Number(made.value) === exp : typeof exp === 'string' && /^\s*([0-9a-f]{2}\s*)+$/i.test(exp) && made.type.startsWith('bytes')
        ? (await reader.bytes(made.offset, made.size)).every((v, k) => v === parseHex(exp)[k])
        : String(made.value) === String(exp);
      if (!ok) made.error = `Expected ${typeof exp === 'number' ? exp + ' (' + hexNum(exp) + ')' : quote(String(exp))}.`;
    }
    if (f.comment) made.comment = String(f.comment).slice(0, 300);
    if (!f.hidden) addChild(node, made);
    node.vars.set(name, made);
    if (f.peek || (f.at !== undefined && f.restore)) cur.pos = saved;
  }

  async function locate(at, node, cur) {
    if (typeof at === 'number' || typeof at === 'string') return evNum(at, node, cur, 'at');
    if (at && typeof at === 'object' && (at.find || at.findText)) {
      const needle = at.find ? parseHex(at.find) : new TextEncoder().encode(at.findText);
      const within = Math.min(at.within !== undefined ? await evNum(at.within, node, cur, 'within') : size, limits.maxFind);
      const fromEnd = at.from === 'end';
      const lo = fromEnd ? Math.max(0, size - within) : cur.pos;
      const hi = fromEnd ? size : Math.min(size, cur.pos + within);
      const CH = 1 << 20;
      if (fromEnd) {
        for (let top = hi; top > lo; top -= CH) {
          const s = Math.max(lo, top - CH);
          const b = await reader.bytes(s, Math.min(hi, top + needle.length - 1) - s);
          const i = Buffer.from(b.buffer, b.byteOffset, b.length).lastIndexOf(Buffer.from(needle));
          if (i >= 0) return s + i;
        }
      } else {
        for (let s = lo; s < hi; s += CH) {
          const b = await reader.bytes(s, Math.min(hi, s + CH + needle.length - 1) - s);
          const i = Buffer.from(b.buffer, b.byteOffset, b.length).indexOf(Buffer.from(needle));
          if (i >= 0) return s + i;
        }
      }
      throw new Stop(`${at.find ? at.find : JSON.stringify(at.findText)} was not found ${fromEnd ? `in the last ${within.toLocaleString('en-US')} bytes` : 'after 0x' + cur.pos.toString(16).toUpperCase()}.`);
    }
    throw new Stop('"at" must be an offset or { "find": ... }.');
  }

  function addChild(parent, child) { if (!parent.children.includes(child)) parent.children.push(child); }

  const rootName = t.root || 'File';
  const rootNode = mk('struct', t.name || 'File', rootName, 0, null);
  const cur = { pos: 0, little: t.endian !== 'big', end: size };
  let error = null;
  try {
    const d = def(rootName);
    if (!d) throw new Stop(`The root struct "${rootName}" is missing.`);
    cur.little = await endianOf(d.endian, rootNode, cur, cur.little);
    for (const f of d.fields || []) await field(f, rootNode, cur, 1);
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    error = e.message;
  }
  rootNode.size = Math.max(...[cur.pos, ...rootNode.children.map(c => c.offset + c.size)].filter(Number.isFinite), 0) - 0;
  rootNode.size = Math.min(rootNode.size, size);
  // A field or struct that claims bytes past the end of the file is cut at the end and marked.
  const stack = [rootNode];
  while (stack.length) {
    const n = stack.pop();
    if (n.offset + n.size > size) {
      n.size = Math.max(0, size - n.offset);
      if (!n.error) n.error = 'This runs past the end of the file.';
    }
    if (n.children) for (const c of n.children) stack.push(c);
  }
  return { root: rootNode, nodes, error, ms: Date.now() - t0 };
}

function decode(b, enc) {
  try {
    if (enc === 'latin1' || enc === 'ascii') { let s = ''; for (const x of b) s += String.fromCharCode(x); return s; }
    if (enc === 'utf16le' || enc === 'utf16be') return new TextDecoder(enc === 'utf16le' ? 'utf-16le' : 'utf-16be').decode(b);
    return new TextDecoder('utf-8').decode(b);
  } catch { return ''; }
}

// ---------- output for the webview and for export ----------

/** Plain tree for postMessage: { n, t, o, s, v, e, l, c, k, x }. */
function toWire(node, budget = { left: 50000 }) {
  if (budget.left-- <= 0) return null;
  const w = { n: node.name, t: node.type, o: node.offset, s: node.size, k: node.kind[0] };
  if (node.display !== undefined) w.v = node.display;
  if (node.error) w.e = node.error;
  if (node.label) w.l = node.label;
  if (node.comment) w.m = node.comment;
  if (node.computed) w.x = 1;
  if (node.children) { w.c = []; for (const c of node.children) { const cw = toWire(c, budget); if (!cw) break; w.c.push(cw); } }
  return w;
}

/** Values as JSON: structs become objects, arrays lists, numbers numbers (u64 above 2^53 as text). */
function toJson(node, depth = 0) {
  if (depth > 200) return null;
  if (node.kind === 'value') {
    if (typeof node.value === 'bigint') return node.value.toString();
    if (node.value === undefined) return { offset: node.offset, size: node.size, bytes: node.display };
    return node.value;
  }
  if (node.kind === 'array') return node.children.map(c => toJson(c, depth + 1));
  const o = {};
  for (const c of node.children) {
    let key = c.name, k = 2;
    while (key in o) key = `${c.name}_${k++}`;
    o[key] = toJson(c, depth + 1);
  }
  return o;
}

/**
 * C declarations for the parsed layout of `node`: one packed struct per shape, arrays with the parsed count,
 * and an initializer with the parsed values. Shapes that differ per element become byte arrays.
 */
function toC(node, fileName) {
  const types = new Map(); // signature -> name
  const decls = [];
  const ident = s => { let x = String(s).replace(/\[\d+\]$/, '').replace(/[^A-Za-z0-9_]/g, '_'); if (/^\d/.test(x)) x = '_' + x; return x || 'field'; };
  const sig = n => n.kind === 'value' ? `${n.type}` : n.kind === 'array' ? `[${n.children.length}:${n.children.length ? sig(n.children[0]) : ''}]` : `{${n.children.filter(c => !c.computed).map(c => ident(c.name) + ':' + sig(c)).join(',')}}`;
  const sameShape = arr => arr.children.length && arr.children.every(c => sig(c) === sig(arr.children[0]));
  const cType = n => {
    if (n.kind === 'value') {
      if (C_TYPES[n.type]) return { t: C_TYPES[n.type], dim: n.type === 'u24' || n.type === 'i24' ? '[3]' : '' };
      return { t: /^char|^string/.test(n.type) ? 'char' : 'uint8_t', dim: `[${n.size}]` };
    }
    if (n.kind === 'array') {
      if (!sameShape(n)) return { t: 'uint8_t', dim: `[${n.size}]`, note: 'elements differ in layout' };
      const inner = cType(n.children[0]);
      return { t: inner.t, dim: `[${n.children.length}]${inner.dim}`, note: inner.note };
    }
    const s = sig(n);
    if (types.has(s)) return { t: types.get(s), dim: '' };
    let base = ident(n.type === 'struct' ? n.name : n.type), name = base, k = 2;
    while ([...types.values()].includes(name)) name = `${base}_${k++}`;
    types.set(s, name);
    const lines = n.children.filter(c => !c.computed).map(c => {
      const ct = cType(c);
      return `    ${ct.t} ${ident(c.name)}${ct.dim};${ct.note ? ' /* ' + ct.note + ' */' : ''} /* 0x${c.offset.toString(16).toUpperCase()} */`;
    });
    decls.push(`typedef struct ${name} {\n${lines.join('\n') || '    uint8_t _empty[1];'}\n} ${name};`);
    return { t: name, dim: '' };
  };
  const init = (n, ind) => {
    const pad = '    '.repeat(ind);
    if (n.kind === 'value') {
      if (typeof n.value === 'number') return Number.isInteger(n.value) ? (n.value < 0 ? String(n.value) : '0x' + n.value.toString(16).toUpperCase()) : String(n.value);
      if (typeof n.value === 'bigint') return (n.value < 0n ? n.value.toString() : '0x' + n.value.toString(16).toUpperCase()) + 'ULL';
      if (typeof n.value === 'string' && /^char|^string/.test(n.type)) return JSON.stringify(n.value.slice(0, n.size));
      return '{ 0 } /* ' + n.size + ' bytes at 0x' + n.offset.toString(16).toUpperCase() + ' */';
    }
    if (n.kind === 'array' && !sameShape(n)) return '{ 0 } /* ' + n.size + ' bytes */';
    const kids = n.children.filter(c => !c.computed);
    if (!kids.length) return '{ 0 }';
    return '{\n' + kids.map(c => pad + '    ' + init(c, ind + 1)).join(',\n') + '\n' + pad + '}';
  };
  const top = cType(node);
  const varName = ident(String(fileName || 'data').replace(/\.[^.]*$/, '')).toLowerCase() || 'data';
  return [
    `/* ${node.name} of ${fileName || 'the file'}, from Hex Viewer Pro. Offsets are from the start of the file. */`,
    '#include <stdint.h>',
    '',
    '#pragma pack(push, 1)',
    decls.join('\n\n'),
    '#pragma pack(pop)',
    '',
    `static const ${top.t} ${varName}${top.dim} = ${init(node, 0)};`,
    '',
  ].join('\n');
}

/** Lenient JSON for template files: // and /* *\/ comments and trailing commas are allowed. */
function parseJsonc(text) {
  let out = '', i = 0, inStr = false;
  while (i < text.length) {
    const c = text[i];
    if (inStr) { out += c; if (c === '\\') { out += text[i + 1] || ''; i += 2; continue; } if (c === '"') inStr = false; i++; continue; }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === ',') { let j = i + 1; while (j < text.length && /\s/.test(text[j])) j++; if (text[j] === '}' || text[j] === ']') { i++; continue; } }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { const j = text.indexOf('*/', i + 2); i = j < 0 ? text.length : j + 2; continue; }
    out += c; i++;
  }
  return JSON.parse(out);
}

module.exports = { parse, detect, checkTemplate, toWire, toJson, toC, parseJsonc, parseHex, Reader, PRIM, DEFAULT_LIMITS };
