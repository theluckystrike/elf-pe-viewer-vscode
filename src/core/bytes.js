'use strict';
// Pure byte helpers shared by the extension host and the webview: offsets, search patterns, copy formats,
// the data inspector, text-column encodings and file-type detection. No vscode, no fs, no DOM.

const HEX = '0123456789abcdef';
const HEXU = '0123456789ABCDEF';

function hex2(b) { return HEXU[b >> 4] + HEXU[b & 15]; }

/** Offset as upper-case hex with at least `width` digits (no prefix). */
function hexOffset(n, width = 8) {
  const s = Math.floor(n).toString(16).toUpperCase();
  return s.length >= width ? s : '0'.repeat(width - s.length) + s;
}

function fmtSize(n) {
  if (!Number.isFinite(n) || n < 0) return '?';
  if (n < 1024) return `${n} byte${n === 1 ? '' : 's'}`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
}

function fmtInt(n) { return Math.floor(n).toLocaleString('en-US'); }

/**
 * Parse a "Go to offset" entry. Accepts 0x1F, 1Fh, $1F, #1F (hex), 1234 (decimal), a leading + or - for a
 * jump relative to `current`, and "end" or "end-16". Spaces and underscores are ignored.
 * Returns { ok: true, offset } clamped to [0, size - 1] (0 for an empty file), or { ok: false, error }.
 */
function parseOffset(input, current, size) {
  let s = String(input == null ? '' : input).trim().toLowerCase().replace(/[\s_]/g, '');
  if (!s) return { ok: false, error: 'Type an offset, for example 0x1F40, 8000 or +0x100.' };
  let base = 0, sign = 0;
  const end = /^end(?:([+-])(.+))?$/.exec(s);
  if (end) {
    base = Math.max(0, size - 1);
    if (!end[1]) return { ok: true, offset: base };
    sign = end[1] === '+' ? 1 : -1; s = end[2];
  } else if (s[0] === '+' || s[0] === '-') {
    sign = s[0] === '+' ? 1 : -1; base = current || 0; s = s.slice(1);
  }
  let v;
  if (/^0x[0-9a-f]+$/.test(s)) v = parseInt(s.slice(2), 16);
  else if (/^[$#][0-9a-f]+$/.test(s)) v = parseInt(s.slice(1), 16);
  else if (/^[0-9a-f]+h$/.test(s)) v = parseInt(s.slice(0, -1), 16);
  else if (/^\d+$/.test(s)) v = parseInt(s, 10);
  else if (/^[0-9a-f]*[a-f][0-9a-f]*$/.test(s)) v = parseInt(s, 16); // plain hex digits with a letter: 1f40
  else return { ok: false, error: `"${input}" is not an offset. Use hex (0x1F40) or decimal (8000).` };
  if (!Number.isSafeInteger(v)) return { ok: false, error: 'That offset is too large.' };
  let off = sign ? base + sign * v : v;
  if (size <= 0) return { ok: true, offset: 0 };
  if (off < 0) off = 0;
  if (off > size - 1) return { ok: false, error: `Offset ${hexOffset(off, 1)}h is past the end of the file (last byte at ${hexOffset(size - 1, 1)}h).`, offset: size - 1 };
  return { ok: true, offset: off };
}

/** UTF-8 bytes of a JS string (works where TextEncoder exists and in Node). */
function utf8(s) { return new TextEncoder().encode(s); }

function utf16le(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); out[2 * i] = c & 255; out[2 * i + 1] = c >> 8; }
  return out;
}

/**
 * Turn a search entry into bytes. mode: 'hex' | 'text' | 'utf16'.
 * Hex accepts "4A 5B", "4a5b", "0x4A,0x5B" and ?? (or ?) as a one-byte wildcard.
 * Text is UTF-8 (plain ASCII matches ASCII and Latin-1 files too). ignoreCase applies to A-Z only.
 * Returns { ok, bytes, mask } where mask[i] = 0 marks a wildcard byte, or { ok: false, error }.
 */
function parsePattern(query, mode, ignoreCase) {
  const q = String(query == null ? '' : query);
  if (!q) return { ok: false, error: 'Type something to search for.' };
  if (mode === 'hex') {
    const t = q.replace(/0x/gi, ' ').replace(/[,;:\-\s]+/g, ' ').trim();
    const toks = [];
    for (const part of t.split(' ')) {
      if (!part) continue;
      if (/^\?{1,2}$/.test(part)) { toks.push(null); continue; }
      if (!/^[0-9a-fA-F?]+$/.test(part)) return { ok: false, error: `"${part}" is not hex. Use pairs like 4A 5B, and ?? for any byte.` };
      if (/^\?+$/.test(part)) { for (let i = 0; i < part.length; i += 2) toks.push(null); continue; }
      if (part.length % 2) return { ok: false, error: `"${part}" has an odd number of hex digits.` };
      for (let i = 0; i < part.length; i += 2) {
        const pr = part.slice(i, i + 2);
        if (pr === '??') toks.push(null);
        else if (/\?/.test(pr)) return { ok: false, error: 'A wildcard covers a whole byte: use ??.' };
        else toks.push(parseInt(pr, 16));
      }
    }
    if (!toks.length) return { ok: false, error: 'Type hex bytes, for example 50 4B 03 04.' };
    if (toks.every(x => x === null)) return { ok: false, error: 'The pattern needs at least one byte that is not ??.' };
    if (toks.length > 4096) return { ok: false, error: 'The pattern is longer than 4,096 bytes.' };
    const bytes = new Uint8Array(toks.map(x => (x === null ? 0 : x)));
    const mask = toks.some(x => x === null) ? new Uint8Array(toks.map(x => (x === null ? 0 : 1))) : null;
    return { ok: true, bytes, mask, ignoreCase: false };
  }
  const bytes = mode === 'utf16' ? utf16le(q) : utf8(q);
  if (bytes.length > 4096) return { ok: false, error: 'The text is longer than 4,096 bytes.' };
  return { ok: true, bytes, mask: null, ignoreCase: !!ignoreCase };
}

function lowerAscii(b) { return b >= 65 && b <= 90 ? b + 32 : b; }

function matchesAt(buf, i, pat, mask, ic) {
  for (let k = 0; k < pat.length; k++) {
    if (mask && !mask[k]) continue;
    const b = ic ? lowerAscii(buf[i + k]) : buf[i + k];
    if (b !== pat[k]) return false;
  }
  return true;
}

/** Prepared pattern: lower-cased when ignoreCase, with the anchor (longest fixed run) for fast scans. */
function preparePattern(p) {
  const pat = p.ignoreCase ? Uint8Array.from(p.bytes, lowerAscii) : p.bytes;
  return { pat, mask: p.mask, ic: !!p.ignoreCase, len: pat.length };
}

/**
 * First match at index >= from in buf[0 .. limit) whose full pattern fits in buf. Returns -1 when none.
 * A plain scan; fine for 1 MB chunks (the host uses Buffer.indexOf when it can).
 */
function findForward(buf, pp, from, limit = buf.length) {
  const { pat, mask, ic, len } = pp;
  const last = Math.min(limit, buf.length) - len;
  const first = mask ? mask.indexOf(1) : 0;
  const fb = pat[first];
  for (let i = Math.max(0, from); i <= last; i++) {
    const b = ic ? lowerAscii(buf[i + first]) : buf[i + first];
    if (b === fb && matchesAt(buf, i, pat, mask, ic)) return i;
  }
  return -1;
}

/** Last match starting at index <= from (and >= lowest). Returns -1 when none. */
function findBackward(buf, pp, from, lowest = 0) {
  const { pat, mask, ic, len } = pp;
  for (let i = Math.min(from, buf.length - len); i >= Math.max(0, lowest); i--) if (matchesAt(buf, i, pat, mask, ic)) return i;
  return -1;
}

const COPY_FORMATS = [
  ['hex', 'Hex (4A5B)'],
  ['hexSpaced', 'Hex with spaces (4A 5B)'],
  ['c', 'C array'],
  ['python', 'Python bytes'],
  ['base64', 'Base64'],
  ['text', 'Text (UTF-8)'],
  ['latin1', 'Text (Latin-1)'],
];

function base64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('base64');
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Text for the clipboard. format is one of COPY_FORMATS. name is used for the C array name. */
function formatCopy(bytes, format, name) {
  const n = bytes.length;
  switch (format) {
    case 'hex': { let s = ''; for (let i = 0; i < n; i++) s += hex2(bytes[i]); return s; }
    case 'hexSpaced': {
      const rows = [];
      for (let i = 0; i < n; i += 16) { const r = []; for (let k = i; k < Math.min(n, i + 16); k++) r.push(hex2(bytes[k])); rows.push(r.join(' ')); }
      return rows.join('\n');
    }
    case 'c': {
      const id = String(name || 'data').replace(/[^A-Za-z0-9_]/g, '_').replace(/^(\d)/, '_$1') || 'data';
      const rows = [];
      for (let i = 0; i < n; i += 12) { const r = []; for (let k = i; k < Math.min(n, i + 12); k++) r.push('0x' + hex2(bytes[k])); rows.push('  ' + r.join(', ')); }
      return `unsigned char ${id}[${n}] = {\n${rows.join(',\n')}\n};`;
    }
    case 'python': {
      let s = "b'";
      for (let i = 0; i < n; i++) s += '\\x' + HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
      return s + "'";
    }
    case 'base64': return base64(bytes);
    case 'text': return new TextDecoder('utf-8').decode(bytes).replace(/\0/g, '');
    case 'latin1': { let s = ''; for (let i = 0; i < n; i++) s += bytes[i] ? String.fromCharCode(bytes[i]) : ''; return s; }
    default: throw new Error('unknown copy format ' + format);
  }
}

/** Parse pasted text as hex bytes (spaces, commas, 0x and \x prefixes allowed). Returns Uint8Array or null. */
function parseHexPaste(text) {
  const t = String(text || '').replace(/0x|\\x/gi, ' ').replace(/[,;\s{}\[\]]+/g, '');
  if (!t || t.length % 2 || !/^[0-9a-fA-F]+$/.test(t)) return null;
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(2 * i, 2), 16);
  return out;
}

// ---- data inspector ----

function guid(b) {
  const h = i => hex2(b[i]);
  return `{${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}}`;
}

function leb128(b, signed) {
  let result = 0n, shift = 0n, i = 0, byte = 0;
  do {
    if (i >= b.length || i >= 10) return null;
    byte = b[i++];
    result |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
  } while (byte & 0x80);
  if (signed && (byte & 0x40)) result -= 1n << shift;
  return { value: result, length: i };
}

function isoTime(ms) {
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return 'out of range';
  return new Date(ms).toISOString().replace('.000Z', 'Z');
}

function float16(v) {
  const s = v >> 15 ? -1 : 1, e = (v >> 10) & 31, f = v & 1023;
  if (e === 0) return s * 2 ** -14 * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * 2 ** (e - 15) * (1 + f / 1024);
}

function num(x) {
  if (typeof x === 'bigint') return x.toString();
  if (Number.isNaN(x)) return 'NaN';
  if (!Number.isFinite(x)) return x > 0 ? 'Infinity' : '-Infinity';
  if (x !== 0 && (Math.abs(x) < 1e-6 || Math.abs(x) >= 1e15)) return x.toExponential(7);
  return String(+x.toPrecision(9));
}

/**
 * Data inspector rows for the bytes at `offset`. b holds up to 16 bytes from the offset (fewer at the end of
 * the file). Each row: [label, value]. A value is '' when there are not enough bytes.
 */
function inspect(b, offset, littleEndian) {
  const le = !!littleEndian;
  const n = b.length;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const has = k => n >= k;
  const rows = [];
  rows.push(['Offset', `0x${hexOffset(offset, 1)} (${fmtInt(offset)})`]);
  if (!n) return rows;
  rows.push(['Binary', b[0].toString(2).padStart(8, '0')]);
  rows.push(['Octal', '0o' + b[0].toString(8)]);
  rows.push(['uint8', String(dv.getUint8(0))]);
  rows.push(['int8', String(dv.getInt8(0))]);
  rows.push(['uint16', has(2) ? String(dv.getUint16(0, le)) : '']);
  rows.push(['int16', has(2) ? String(dv.getInt16(0, le)) : '']);
  rows.push(['uint24', has(3) ? String(le ? b[0] | (b[1] << 8) | (b[2] << 16) : (b[0] << 16) | (b[1] << 8) | b[2]) : '']);
  rows.push(['uint32', has(4) ? String(dv.getUint32(0, le)) : '']);
  rows.push(['int32', has(4) ? String(dv.getInt32(0, le)) : '']);
  rows.push(['uint64', has(8) ? dv.getBigUint64(0, le).toString() : '']);
  rows.push(['int64', has(8) ? dv.getBigInt64(0, le).toString() : '']);
  rows.push(['float16', has(2) ? num(float16(dv.getUint16(0, le))) : '']);
  rows.push(['float32', has(4) ? num(dv.getFloat32(0, le)) : '']);
  rows.push(['float64', has(8) ? num(dv.getFloat64(0, le)) : '']);
  const u = leb128(b, false), s = leb128(b, true);
  rows.push(['ULEB128', u ? `${u.value} (${u.length} byte${u.length > 1 ? 's' : ''})` : '']);
  rows.push(['SLEB128', s ? `${s.value} (${s.length} byte${s.length > 1 ? 's' : ''})` : '']);
  rows.push(['Unix time 32', has(4) ? isoTime(dv.getUint32(0, le) * 1000) : '']);
  rows.push(['Unix time 64', has(8) ? (() => { const v = dv.getBigInt64(0, le); return v > 253402300799n || v < -62135596800n ? 'out of range' : isoTime(Number(v) * 1000); })() : '']);
  rows.push(['Windows FILETIME', has(8) ? (() => { const v = dv.getBigUint64(0, le); if (v === 0n || v > 2650467743999999999n) return 'out of range'; return isoTime(Number(v / 10000n) - 11644473600000); })() : '']);
  rows.push(['GUID', has(16) ? guid(b) : '']);
  let ch = '';
  try {
    const len = b[0] < 0x80 ? 1 : b[0] >= 0xf0 ? 4 : b[0] >= 0xe0 ? 3 : b[0] >= 0xc0 ? 2 : 0;
    if (len && has(len)) {
      const t = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, len));
      const cp = t.codePointAt(0);
      ch = `${cp < 32 || cp === 127 ? '(control)' : t} U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
    } else ch = 'not a UTF-8 start byte';
  } catch { ch = 'not valid UTF-8'; }
  rows.push(['UTF-8 char', ch]);
  if (has(2)) {
    const cu = dv.getUint16(0, le);
    rows.push(['UTF-16 char', cu >= 0xd800 && cu <= 0xdfff ? `surrogate U+${cu.toString(16).toUpperCase()}` : `${cu < 32 ? '(control)' : String.fromCharCode(cu)} U+${cu.toString(16).toUpperCase().padStart(4, '0')}`]);
  } else rows.push(['UTF-16 char', '']);
  return rows;
}

// ---- text column ----

const EBCDIC = "\u0000\u0001\u0002\u0003\u009c\t\u0086\u007f\u0097\u008d\u008e\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u009d\u0085\b\u0087\u0018\u0019\u0092\u008f\u001c\u001d\u001e\u001f\u0080\u0081\u0082\u0083\u0084\n\u0017\u001b\u0088\u0089\u008a\u008b\u008c\u0005\u0006\u0007\u0090\u0091\u0016\u0093\u0094\u0095\u0096\u0004\u0098\u0099\u009a\u009b\u0014\u0015\u009e\u001a  âäàáãåçñ¢.<(+|&éêëèíîïìß!$*);¬-/ÂÄÀÁÃÅÇÑ¦,%_>?øÉÊËÈÍÎÏÌ`:#@'=\"Øabcdefghi«»ðýþ±°jklmnopqrªºæ¸Æ¤µ~stuvwxyz¡¿ÐÝÞ®^£¥·©§¶¼½¾[]¯¨´×{ABCDEFGHI­ôöòóõ}JKLMNOPQR¹ûüùúÿ\\÷STUVWXYZ²ÔÖÒÓÕ0123456789³ÛÜÙÚ\u009f";

const ENCODINGS = [['ascii', 'ASCII'], ['latin1', 'Latin-1'], ['utf8', 'UTF-8'], ['utf16le', 'UTF-16 LE'], ['utf16be', 'UTF-16 BE'], ['ebcdic', 'EBCDIC (CP037)']];

function isControl(cp) { return cp < 0x20 || (cp >= 0x7f && cp < 0xa0); }

function controlGlyph(cp) {
  if (cp < 0x20) return String.fromCharCode(0x2400 + cp); // ␀ .. ␟
  if (cp === 0x7f) return '␡'; // ␡
  return '·';
}

/**
 * The text-column characters for one row. bytes: the row (plus up to 3 bytes after it, for UTF-8 and UTF-16
 * characters that run past the row end). rowStart: file offset of bytes[0], used to align UTF-16 pairs.
 * count: bytes in the row. Returns an array of `count` entries: { ch, kind } where kind is
 * 'p' printable, 'c' control or non-printable, 'x' continuation byte of a multi-byte character, 'z' zero byte.
 */
function textCells(bytes, count, encoding, rowStart, glyphs) {
  const out = new Array(count);
  const ctl = cp => ({ ch: glyphs ? controlGlyph(cp) : '.', kind: cp === 0 ? 'z' : 'c' });
  if (encoding === 'utf16le' || encoding === 'utf16be') {
    const odd = rowStart % 2;
    for (let i = 0; i < count; i++) {
      if ((i + odd) % 2 === 1) { out[i] = { ch: ' ', kind: 'x' }; continue; }
      if (i + 1 >= bytes.length) { out[i] = { ch: '.', kind: 'c' }; continue; }
      const cu = encoding === 'utf16le' ? bytes[i] | (bytes[i + 1] << 8) : (bytes[i] << 8) | bytes[i + 1];
      if (cu >= 0xd800 && cu <= 0xdfff) out[i] = { ch: '�', kind: 'c' };
      else if (isControl(cu)) out[i] = ctl(cu);
      else out[i] = { ch: String.fromCharCode(cu), kind: 'p' };
    }
    return out;
  }
  if (encoding === 'utf8') {
    let i = 0;
    // continuation bytes at the row start belong to a character in the row before
    while (i < count && (bytes[i] & 0xc0) === 0x80) out[i++] = { ch: ' ', kind: 'x' };
    for (; i < count; i++) {
      const b = bytes[i];
      if (b < 0x80) { out[i] = isControl(b) ? ctl(b) : { ch: String.fromCharCode(b), kind: 'p' }; continue; }
      const len = b >= 0xf0 && b < 0xf8 ? 4 : b >= 0xe0 ? 3 : b >= 0xc2 ? 2 : 0;
      let ok = len > 0 && i + len <= bytes.length;
      for (let k = 1; ok && k < len; k++) if ((bytes[i + k] & 0xc0) !== 0x80) ok = false;
      if (!ok) { out[i] = { ch: '.', kind: 'c' }; continue; }
      let cp;
      if (len === 2) cp = ((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f);
      else if (len === 3) cp = ((b & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f);
      else cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
      out[i] = isControl(cp) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? ctl(cp) : { ch: String.fromCodePoint(cp), kind: 'p' };
      for (let k = 1; k < len && i + k < count; k++) out[i + k] = { ch: ' ', kind: 'x' };
      i += len - 1;
    }
    return out;
  }
  for (let i = 0; i < count; i++) {
    const b = bytes[i];
    let cp;
    if (encoding === 'ebcdic') cp = EBCDIC.charCodeAt(b);
    else if (encoding === 'latin1') cp = b;
    else cp = b < 0x80 ? b : -1;
    if (cp < 0) out[i] = { ch: '.', kind: 'c' };
    else if (isControl(cp)) out[i] = ctl(cp);
    else out[i] = { ch: String.fromCharCode(cp), kind: 'p' };
  }
  return out;
}

/** The byte to write when a character is typed in the text column, or -1 when it has no one-byte form. */
function byteForChar(ch, encoding) {
  if (!ch || ch.length !== 1) return -1;
  const c = ch.charCodeAt(0);
  if (encoding === 'ebcdic') { const i = EBCDIC.indexOf(ch); return i >= 0x40 ? i : -1; }
  if (encoding === 'latin1') return c >= 0x20 && c <= 0xff && !(c >= 0x7f && c < 0xa0) ? c : -1;
  return c >= 0x20 && c < 0x7f ? c : -1;
}

// ---- file type ----

function startsWith(b, sig, at = 0) {
  if (b.length < at + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
  return true;
}

/** A short name for the file type from its first bytes, or '' when unknown. */
function detectType(b) {
  const a = s => Array.from(s, c => c.charCodeAt(0));
  if (!b || !b.length) return '';
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'PNG image';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'JPEG image';
  if (startsWith(b, a('GIF8'))) return 'GIF image';
  if (startsWith(b, a('RIFF')) && startsWith(b, a('WAVE'), 8)) return 'WAV audio';
  if (startsWith(b, a('RIFF')) && startsWith(b, a('WEBP'), 8)) return 'WebP image';
  if (startsWith(b, a('RIFF')) && startsWith(b, a('AVI '), 8)) return 'AVI video';
  if (startsWith(b, a('%PDF-'))) return 'PDF document';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return 'ZIP archive';
  if (startsWith(b, [0x1f, 0x8b])) return 'gzip data';
  if (startsWith(b, a('7z'), 0) && startsWith(b, [0xbc, 0xaf, 0x27, 0x1c], 2)) return '7-Zip archive';
  if (startsWith(b, [0x28, 0xb5, 0x2f, 0xfd])) return 'Zstandard data';
  if (startsWith(b, a('SQLite format 3\0'))) return 'SQLite database';
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) {
    const cls = b[4] === 2 ? '64-bit' : b[4] === 1 ? '32-bit' : '';
    const end = b[5] === 1 ? 'little-endian' : b[5] === 2 ? 'big-endian' : '';
    return ['ELF', cls, end].filter(Boolean).join(' ') + ' executable';
  }
  if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe])) return 'Mach-O 64-bit executable';
  if (startsWith(b, [0xce, 0xfa, 0xed, 0xfe])) return 'Mach-O 32-bit executable';
  if (startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) {
    // Java class files and Mach-O universal binaries share this magic; the class major version is >= 45.
    const v = b.length >= 8 ? (b[6] << 8) | b[7] : 0;
    return v >= 45 ? `Java class file (version ${v})` : 'Mach-O universal binary';
  }
  if (startsWith(b, a('MZ'))) return 'Windows executable (MZ/PE)';
  if (startsWith(b, [0x00, 0x61, 0x73, 0x6d])) return 'WebAssembly module';
  if (startsWith(b, a('OggS'))) return 'Ogg media';
  if (startsWith(b, a('fLaC'))) return 'FLAC audio';
  if (startsWith(b, a('ID3'))) return 'MP3 audio';
  if (b.length >= 12 && startsWith(b, a('ftyp'), 4)) return 'MP4 / QuickTime media';
  if (startsWith(b, [0xff, 0xfe])) return 'UTF-16 LE text (BOM)';
  if (startsWith(b, [0xfe, 0xff])) return 'UTF-16 BE text (BOM)';
  if (startsWith(b, [0xef, 0xbb, 0xbf])) return 'UTF-8 text (BOM)';
  if (startsWith(b, a('glTF'))) return 'GLB 3D model';
  if (startsWith(b, a('GGUF'))) return 'GGUF model';
  if (startsWith(b, [0x93, 0x4e, 0x55, 0x4d, 0x50, 0x59])) return 'NumPy array';
  if (startsWith(b, [0x89, 0x48, 0x44, 0x46])) return 'HDF5 data';
  if (startsWith(b, a('BM'))) return 'BMP image';
  if (startsWith(b, a('II*\0')) || startsWith(b, a('MM\0*'))) return 'TIFF image';
  return '';
}

module.exports = {
  hex2, hexOffset, fmtSize, fmtInt, parseOffset, parsePattern, preparePattern, findForward, findBackward, matchesAt, lowerAscii,
  COPY_FORMATS, formatCopy, parseHexPaste, inspect, guid, leb128, float16, ENCODINGS, EBCDIC, textCells, byteForChar, detectType, utf16le,
};
