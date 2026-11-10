'use strict';
// One entry point: detect the format from the first bytes and run its reader. No vscode, no network.
const { Source } = require('./source');
const { Budget } = require('./model');
const { parseElf, isElf } = require('./elf');
const { parsePe, isPe } = require('./pe');
const { machoKind, parseFat, parseThin } = require('./macho');
const { detectType } = require('./bytes');

/** 'ELF' | 'PE' | 'Mach-O' | 'Mach-O universal' | '' */
function detect(src) {
  try {
    if (isElf(src)) return 'ELF';
    if (isPe(src)) return 'PE';
    const k = machoKind(src);
    if (k === 'thin') return 'Mach-O';
    if (k === 'fat') return 'Mach-O universal';
  } catch { /* too short */ }
  return '';
}

/** Short guess for files that are none of the three, for the "not a binary we read" message. */
function guess(src) {
  const b = src.bytesUpTo(0, 16);
  const s = String.fromCharCode(...b);
  if (b.length === 0) return 'an empty file';
  if (s.startsWith('!<arch>')) return 'a static library archive (ar); open the object files inside it';
  if (s.startsWith('dex\n')) return 'an Android DEX file';
  // The Hex engine's file type names (core/bytes.js): PNG, ZIP, PDF, Java class, WebAssembly and more.
  const t = detectType(b);
  if (t && !/executable|universal binary/.test(t)) return `${/^[AEIOU]/.test(t) ? 'an' : 'a'} ${t}`;
  return '';
}

function parse(src, limits) {
  const budget = new Budget(limits);
  const kind = detect(src);
  if (kind === 'ELF') return parseElf(src, budget);
  if (kind === 'PE') return parsePe(src, budget);
  if (kind === 'Mach-O') return parseThin(src, budget);
  if (kind === 'Mach-O universal') return parseFat(src, budget, parseThin);
  const g = guess(src);
  const e = new Error(`This is not an ELF, PE or Mach-O file${g ? `: it looks like ${g}` : ''}.`);
  e.code = 'NOT_BINARY';
  throw e;
}

function parseBuffer(buf, limits) { return parse(Source.fromBuffer(buf), limits); }

function parseFile(file, limits) {
  const src = Source.fromFile(file);
  try { const m = parse(src, limits); m.size = src.size; return m; } finally { src.close(); }
}

module.exports = { detect, parse, parseBuffer, parseFile };
