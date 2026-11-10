'use strict';
// ELF reader: ELF32 and ELF64, little and big endian. Header, program headers (segments), section headers,
// symbols (.symtab, .dynsym), dynamic section (needed libraries, SONAME, RPATH), imports with the library from the
// GNU version tables, exports, notes (build id). Every count is checked against the file size and LIMITS.
const { Trunc, hex, safe } = require('./source');
const { Model } = require('./model');

const MACHINES = {
  0: 'None', 2: 'SPARC', 3: 'x86 (i386)', 4: 'Motorola 68000', 7: 'Intel 80860', 8: 'MIPS', 10: 'MIPS RS3000 LE', 15: 'PA-RISC', 18: 'SPARC32+', 20: 'PowerPC', 21: 'PowerPC 64',
  22: 'IBM S/390', 40: 'ARM', 42: 'SuperH', 43: 'SPARC V9', 50: 'IA-64', 62: 'x86-64', 83: 'AVR', 92: 'OpenRISC', 94: 'Xtensa', 105: 'TI MSP430', 106: 'Blackfin',
  113: 'Altera Nios II', 164: 'Qualcomm Hexagon', 183: 'AArch64', 185: 'Atmel AVR32', 188: 'Tilera TILEPro', 189: 'MicroBlaze', 190: 'NVIDIA CUDA', 220: 'Z80', 224: 'AMD GPU',
  243: 'RISC-V', 247: 'Linux BPF', 252: 'C-SKY', 258: 'LoongArch',
};
const TYPES = { 0: 'NONE', 1: 'REL (relocatable object)', 2: 'EXEC (executable)', 3: 'DYN (shared object or PIE)', 4: 'CORE (core dump)' };
const OSABI = { 0: 'System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux (GNU)', 6: 'Solaris', 7: 'AIX', 8: 'IRIX', 9: 'FreeBSD', 10: 'Tru64', 11: 'Novell Modesto', 12: 'OpenBSD', 64: 'ARM EABI', 97: 'ARM', 255: 'Standalone' };
const PT = { 0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY', 0x70000001: 'ARM_EXIDX', 0x70000003: 'RISCV_ATTRIBUTES', 0x65041580: 'PAX_FLAGS' };
const SHT = { 0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 10: 'SHLIB', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY', 16: 'PREINIT_ARRAY', 17: 'GROUP', 18: 'SYMTAB_SHNDX', 19: 'RELR',
  0x6ffffff5: 'GNU_ATTRIBUTES', 0x6ffffff6: 'GNU_HASH', 0x6ffffffd: 'GNU_verdef', 0x6ffffffe: 'GNU_verneed', 0x6fffffff: 'GNU_versym', 0x70000001: 'ARM_EXIDX', 0x70000003: 'ARM_ATTRIBUTES', 0x6fff4c03: 'LLVM_ADDRSIG' };
const STT = { 0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE', 5: 'COMMON', 6: 'TLS', 10: 'IFUNC' };
const STB = { 0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'UNIQUE' };
const DT = { 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 12: 'INIT', 13: 'FINI', 14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT', 20: 'PLTREL', 21: 'DEBUG', 22: 'TEXTREL', 23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY', 26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ', 29: 'RUNPATH', 30: 'FLAGS', 32: 'PREINIT_ARRAY', 33: 'PREINIT_ARRAYSZ', 35: 'RELRSZ', 36: 'RELR', 37: 'RELRENT',
  0x6ffffef5: 'GNU_HASH', 0x6ffffff0: 'VERSYM', 0x6ffffff9: 'RELACOUNT', 0x6ffffffa: 'RELCOUNT', 0x6ffffffb: 'FLAGS_1', 0x6ffffffc: 'VERDEF', 0x6ffffffd: 'VERDEFNUM', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM' };
const DT_STR = new Set([1, 14, 15, 29]);

function shFlags(v) {
  const f = Number(v & 0xffffffffn), out = [];
  if (f & 1) out.push('W'); if (f & 2) out.push('A'); if (f & 4) out.push('X'); if (f & 0x10) out.push('M'); if (f & 0x20) out.push('S');
  if (f & 0x40) out.push('I'); if (f & 0x80) out.push('L'); if (f & 0x200) out.push('G'); if (f & 0x400) out.push('T'); if (f & 0x800) out.push('C');
  return out.join('');
}
function phFlags(f) { return (f & 4 ? 'R' : '-') + (f & 2 ? 'W' : '-') + (f & 1 ? 'X' : '-'); }
const name = (map, v) => (map[v] !== undefined ? map[v] : hex(v));

function isElf(src) {
  if (src.size < 16) return false;
  const b = src.bytes(0, 4);
  return b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
}

function parseElf(src, budget) {
  const m = new Model('ELF', budget);
  m.template = 'elf';
  const L = m.budget.limits;
  if (src.size < 16) throw new Trunc(0, 16, src.size);
  const id = src.bytes(0, 16);
  const cls = id[4], data = id[5];
  if (cls !== 1 && cls !== 2) throw new Error(`EI_CLASS is ${id[4]}; an ELF file says 1 (32-bit) or 2 (64-bit).`);
  if (data !== 1 && data !== 2) throw new Error(`EI_DATA is ${id[5]}; an ELF file says 1 (little endian) or 2 (big endian).`);
  const is64 = cls === 2, le = data === 1;
  const W = is64 ? 8 : 4;
  const ehsize = is64 ? 64 : 52;
  const u16 = (o) => src.u16(o, le), u32 = (o) => src.u32(o, le), word = (o) => src.word(o, le, is64);

  const ident = m.group('ELF identification (e_ident)');
  ident.fields.push(['Magic', '7F 45 4C 46 ("\\x7fELF")', 0, 4], ['Class', is64 ? 'ELF64' : 'ELF32', 4, 1], ['Data', le ? 'little endian (LSB)' : 'big endian (MSB)', 5, 1],
    ['Version', String(id[6]), 6, 1], ['OS/ABI', name(OSABI, id[7]), 7, 1], ['ABI version', String(id[8]), 8, 1]);

  if (src.size < ehsize) { m.warn(`The ELF header needs ${ehsize} bytes; the file has ${src.size}.`); m.title = `ELF ${is64 ? 64 : 32}-bit, header cut short`; return m.finish(); }
  const h = {
    type: u16(16), machine: u16(18), version: u32(20), entry: word(24),
    phoff: word(is64 ? 32 : 28), shoff: word(is64 ? 40 : 32), flags: u32(is64 ? 48 : 36),
    ehsize: u16(is64 ? 52 : 40), phentsize: u16(is64 ? 54 : 42), phnum: u16(is64 ? 56 : 44),
    shentsize: u16(is64 ? 58 : 46), shnum: u16(is64 ? 60 : 48), shstrndx: u16(is64 ? 62 : 50),
  };
  const o = (a, b) => (is64 ? b : a);
  const hdr = m.group('ELF header');
  hdr.fields.push(
    ['Type (e_type)', name(TYPES, h.type), 16, 2], ['Machine (e_machine)', `${name(MACHINES, h.machine)} (${h.machine})`, 18, 2], ['Version (e_version)', String(h.version), 20, 4],
    ['Entry point (e_entry)', hex(h.entry), 24, W], ['Program headers at (e_phoff)', hex(h.phoff), o(28, 32), W], ['Section headers at (e_shoff)', hex(h.shoff), o(32, 40), W],
    ['Flags (e_flags)', hex(h.flags), o(36, 48), 4], ['Header size (e_ehsize)', String(h.ehsize), o(40, 52), 2],
    ['Program header size (e_phentsize)', String(h.phentsize), o(42, 54), 2], ['Program headers (e_phnum)', String(h.phnum), o(44, 56), 2],
    ['Section header size (e_shentsize)', String(h.shentsize), o(46, 58), 2], ['Section headers (e_shnum)', String(h.shnum), o(48, 60), 2],
    ['Section name table index (e_shstrndx)', String(h.shstrndx), o(50, 62), 2]);

  const typeShort = { 1: 'relocatable', 2: 'executable', 3: 'shared object', 4: 'core dump' }[h.type] || `type ${h.type}`;
  m.title = `ELF ${is64 ? 64 : 32}-bit ${le ? 'LSB' : 'MSB'} ${typeShort}, ${name(MACHINES, h.machine)}`;
  m.summary.push(['Format', `ELF${is64 ? 64 : 32}, ${le ? 'little' : 'big'} endian`], ['Type', name(TYPES, h.type)], ['Machine', name(MACHINES, h.machine)], ['OS/ABI', name(OSABI, id[7])], ['Entry point', hex(h.entry)]);

  // ---- section headers (read first: the program headers may need the extended counts in section 0) ----
  const sections = [];
  const shoff = safe(h.shoff);
  const SHSZ = is64 ? 64 : 40;
  let shnum = h.shnum, shstrndx = h.shstrndx, phnum = h.phnum;
  m.part('Section headers', () => {
    if (!h.shoff) return;
    if (shoff === null || shoff >= src.size) { m.warn(`Section headers: e_shoff ${hex(h.shoff)} is past the end of the file.`); return; }
    if (h.shentsize < SHSZ) { m.warn(`Section headers: e_shentsize is ${h.shentsize}; ELF${is64 ? 64 : 32} needs at least ${SHSZ}. The section table is not read.`); return; }
    const readSh = (i) => {
      const b = shoff + i * h.shentsize;
      return {
        index: i, nameOff: u32(b), type: u32(b + 4), flags: word(b + 8), addr: word(b + o(12, 16)), offset: word(b + o(16, 24)), size: word(b + o(20, 32)),
        link: u32(b + o(24, 40)), info: u32(b + o(28, 44)), align: word(b + o(32, 48)), entsize: word(b + o(36, 56)), at: b,
      };
    };
    if (shnum === 0 || shstrndx === 0xffff || phnum === 0xffff) {
      const s0 = readSh(0);
      if (shnum === 0 && s0.size > 0n) shnum = safe(s0.size) || 0;
      if (shstrndx === 0xffff) shstrndx = s0.link;
      if (phnum === 0xffff) phnum = s0.info;
    }
    const fit = Math.floor((src.size - shoff) / h.shentsize);
    let n = shnum;
    if (n > fit) { m.warn(`Section headers: e_shnum says ${n}, but only ${fit} fit before the end of the file.`); n = fit; }
    if (n > L.maxSections) { m.warn(`Section headers: ${n} sections; reading the first ${L.maxSections}.`); n = L.maxSections; }
    for (let i = 0; i < n && m.budget.ok(); i++) sections.push(readSh(i));
  });

  const strAt = (secIndex, off) => {
    const s = sections[secIndex];
    if (!s || s.type === 8) throw new Error(`string table section ${secIndex} is missing`);
    const base = safe(s.offset), size = safe(s.size);
    if (base === null || size === null || off >= size) throw new Error(`name offset ${hex(off)} is outside the string table`);
    return src.cstr(base + off, Math.min(L.maxString, size - off));
  };
  for (const s of sections) {
    s.name = '';
    if (shstrndx && shstrndx < sections.length) { try { s.name = strAt(shstrndx, s.nameOff); } catch { s.name = `(name at ${hex(s.nameOff)})`; } }
  }
  const secName = (i) => (i === 0 ? 'UNDEF' : i === 0xfff1 ? 'ABS' : i === 0xfff2 ? 'COMMON' : i >= 0xff00 ? hex(i) : (sections[i] && sections[i].name) || String(i));

  // ---- program headers ----
  const segments = [];
  m.part('Program headers', () => {
    if (!h.phoff || !phnum) return;
    const phoff = safe(h.phoff);
    const PHSZ = is64 ? 56 : 32;
    if (phoff === null || phoff >= src.size) { m.warn(`Program headers: e_phoff ${hex(h.phoff)} is past the end of the file.`); return; }
    if (h.phentsize < PHSZ) { m.warn(`Program headers: e_phentsize is ${h.phentsize}; ELF${is64 ? 64 : 32} needs at least ${PHSZ}.`); return; }
    let n = phnum;
    const fit = Math.floor((src.size - phoff) / h.phentsize);
    if (n > fit) { m.warn(`Program headers: e_phnum says ${n}, but only ${fit} fit before the end of the file.`); n = fit; }
    n = Math.min(n, L.maxSegments);
    for (let i = 0; i < n; i++) {
      const b = phoff + i * h.phentsize;
      segments.push(is64
        ? { type: u32(b), flags: u32(b + 4), offset: word(b + 8), vaddr: word(b + 16), paddr: word(b + 24), filesz: word(b + 32), memsz: word(b + 40), align: word(b + 48), at: b }
        : { type: u32(b), offset: word(b + 4), vaddr: word(b + 8), paddr: word(b + 12), filesz: word(b + 16), memsz: word(b + 20), flags: u32(b + 24), align: word(b + 28), at: b });
    }
  });
  const segT = m.table('segments', 'Segments (program headers)', [['#', 'd'], ['Type', 's'], ['Offset', 'h'], ['Virtual address', 'h'], ['Physical address', 'h'], ['File size', 'h'], ['Memory size', 'h'], ['Flags', 's'], ['Align', 'h']], [1, 3]);
  segments.forEach((p, i) => {
    const off = safe(p.offset), len = safe(p.filesz);
    m.row(segT, [i, name(PT, p.type), hex(p.offset), hex(p.vaddr), hex(p.paddr), hex(p.filesz), hex(p.memsz), phFlags(p.flags), hex(p.align)],
      off !== null && len !== null && off < src.size ? [off, Math.min(len, src.size - off)] : null);
  });
  const vaddrToOff = (va) => {
    for (const p of segments) {
      if (p.type !== 1) continue;
      if (va >= p.vaddr && va < p.vaddr + p.filesz) return safe(p.offset + (va - p.vaddr));
    }
    return null;
  };

  const secT = m.table('sections', 'Sections', [['#', 'd'], ['Name', 's'], ['Type', 's'], ['Address', 'h'], ['Offset', 'h'], ['Size', 'h'], ['Entry size', 'h'], ['Flags', 's'], ['Link', 'd'], ['Info', 'd'], ['Align', 'h']], [1]);
  for (const s of sections) {
    const off = safe(s.offset), len = safe(s.size);
    m.row(secT, [s.index, s.name, name(SHT, s.type), hex(s.addr), hex(s.offset), hex(s.size), hex(s.entsize), shFlags(s.flags), s.link, s.info, hex(s.align)],
      s.type !== 8 && off !== null && len !== null && off < src.size ? [off, Math.min(len, src.size - off)] : null);
  }
  m.summary.push(['Sections', String(sections.length)], ['Segments', String(segments.length)]);

  // ---- interpreter ----
  m.part('Interpreter', () => {
    const p = segments.find((s) => s.type === 3);
    if (!p) return;
    const off = safe(p.offset);
    if (off === null) return;
    const interp = src.cstr(off, Math.min(L.maxString, safe(p.filesz) || 256));
    m.summary.push(['Interpreter', interp]);
    hdr.fields.push(['Interpreter (PT_INTERP)', interp, off, interp.length]);
  });

  // ---- version tables (for import libraries) ----
  const verNeed = new Map(); // version index -> { file, version }
  m.part('Version needs (.gnu.version_r)', () => {
    const vs = sections.find((s) => s.type === 0x6ffffffe);
    if (!vs) return;
    const base = safe(vs.offset), size = safe(vs.size);
    if (base === null || size === null) return;
    const end = Math.min(src.size, base + size);
    let off = base, guard = 0;
    const seen = new Set();
    while (off + 16 <= end && guard++ < 4096 && m.budget.ok()) {
      if (seen.has(off)) { m.warn('Version needs: the entries point back to an earlier entry (a loop); reading stopped there.'); break; }
      seen.add(off);
      const cnt = u16(off + 2), file = u32(off + 4), aux = u32(off + 8), next = u32(off + 12);
      let fname = '';
      try { fname = strAt(vs.link, file); } catch { fname = ''; }
      let a = off + aux, k = 0;
      const seenA = new Set();
      while (k < cnt && k < 4096 && a + 16 <= end) {
        if (seenA.has(a)) { m.warn('Version needs: an aux entry points back to an earlier one (a loop); reading stopped there.'); break; }
        seenA.add(a);
        const other = u16(a + 6), vname = u32(a + 8), anext = u32(a + 12);
        let v = '';
        try { v = strAt(vs.link, vname); } catch { v = ''; }
        verNeed.set(other & 0x7fff, { file: fname, version: v });
        k++;
        if (!anext) break;
        a += anext;
      }
      if (!next) break;
      off += next;
    }
  });

  // ---- symbols ----
  const symT = m.table('symbols', 'Symbols', [['Name', 's'], ['Value', 'h'], ['Size', 'd'], ['Type', 's'], ['Bind', 's'], ['Visibility', 's'], ['Section', 's'], ['Table', 's']], [0, 7]);
  const impT = m.table('imports', 'Imports', [['Name', 's'], ['Library', 's'], ['Version', 's'], ['Type', 's'], ['Bind', 's']], [1, 0]);
  const expT = m.table('exports', 'Exports', [['Name', 's'], ['Address', 'h'], ['Size', 'd'], ['Type', 's'], ['Bind', 's'], ['Section', 's']], [0]);
  const needed = [];
  const SYMSZ = is64 ? 24 : 16;
  const readSyms = (s) => {
    const base = safe(s.offset), size = safe(s.size);
    if (base === null || size === null) return [];
    if (base >= src.size) { m.warn(`${s.name || 'symbol table'}: offset ${hex(s.offset)} is past the end of the file.`); return []; }
    const ent = safe(s.entsize) || SYMSZ;
    if (ent < SYMSZ) { m.warn(`${s.name}: entry size ${ent} is too small for an ELF${is64 ? 64 : 32} symbol.`); return []; }
    let n = Math.floor(size / ent);
    const fit = Math.floor((src.size - base) / ent);
    if (n > fit) { m.warn(`${s.name}: ${n} symbols do not fit in the file; reading ${fit}.`); n = fit; }
    let versym = null;
    if (s.type === 11) {
      const vs = sections.find((x) => x.type === 0x6fffffff);
      if (vs) versym = safe(vs.offset);
    }
    const out = [];
    for (let i = 1; i < n && m.budget.ok(); i++) {
      if (out.length >= L.maxRows) { m.warn(`${s.name}: showing the first ${L.maxRows.toLocaleString('en-US')} symbols of ${n.toLocaleString('en-US')}.`); break; }
      const b = base + i * ent;
      const sym = is64
        ? { nameOff: u32(b), info: src.u8(b + 4), other: src.u8(b + 5), shndx: u16(b + 6), value: src.u64(b + 8, le), size: src.u64(b + 16, le) }
        : { nameOff: u32(b), value: BigInt(u32(b + 4)), size: BigInt(u32(b + 8)), info: src.u8(b + 12), other: src.u8(b + 13), shndx: u16(b + 14) };
      try { sym.name = sym.nameOff ? strAt(s.link, sym.nameOff) : ''; } catch { sym.name = `(name at ${hex(sym.nameOff)})`; }
      sym.type = sym.info & 15; sym.bind = sym.info >> 4; sym.vis = ['DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED'][sym.other & 3];
      if (versym !== null) {
        try { const v = u16(versym + i * 2) & 0x7fff; sym.ver = verNeed.get(v); } catch { /* no version for this one */ }
      }
      out.push(sym);
    }
    return out;
  };
  let dynsyms = [];
  m.part('Symbols', () => {
    for (const s of sections) {
      if (s.type !== 2 && s.type !== 11) continue;
      const tableName = s.type === 2 ? '.symtab' : '.dynsym';
      const syms = readSyms(s);
      if (s.type === 11) dynsyms = syms;
      for (const y of syms) {
        if (!y.name && y.type === 3) continue; // section symbols carry no name
        if (!m.row(symT, [y.name, hex(y.value), safe(y.size) ?? Number.MAX_SAFE_INTEGER, name(STT, y.type), name(STB, y.bind), y.vis, secName(y.shndx), tableName])) break;
      }
    }
  });

  // ---- dynamic section ----
  const dynT = m.table('dynamic', 'Dynamic section', [['Tag', 's'], ['Value', 'h'], ['Meaning', 's']], [0, 2]);
  m.part('Dynamic section', () => {
    let base = null, size = null, strIdx = -1;
    const ds = sections.find((s) => s.type === 6);
    if (ds) { base = safe(ds.offset); size = safe(ds.size); strIdx = ds.link; }
    else { const p = segments.find((s) => s.type === 2); if (p) { base = safe(p.offset); size = safe(p.filesz); } }
    if (base === null || size === null) return;
    const ent = is64 ? 16 : 8;
    const n = Math.min(Math.floor(size / ent), Math.floor(Math.max(0, src.size - base) / ent), 8192);
    const entries = [];
    for (let i = 0; i < n; i++) {
      const b = base + i * ent;
      const tag = safe(src.word(b, le, is64)) ?? -1, val = src.word(b + W, le, is64);
      if (tag === 0) break;
      entries.push({ tag, val, at: b });
    }
    // Without section headers, DT_STRTAB (an address) gives the string table.
    let strBase = null, strSize = null;
    if (strIdx >= 0 && sections[strIdx]) { strBase = safe(sections[strIdx].offset); strSize = safe(sections[strIdx].size); }
    else {
      const st = entries.find((e) => e.tag === 5), sz = entries.find((e) => e.tag === 10);
      if (st) { strBase = vaddrToOff(st.val); strSize = sz ? safe(sz.val) : 65536; }
    }
    const dstr = (v) => {
      const off = safe(v);
      if (strBase === null || off === null || off >= (strSize ?? 0)) return '';
      return src.cstr(strBase + off, Math.min(L.maxString, strSize - off));
    };
    for (const e of entries) {
      let meaning = '';
      if (DT_STR.has(e.tag)) { try { meaning = dstr(e.val); } catch { meaning = ''; } }
      if (e.tag === 1 && meaning && needed.length < L.maxLibraries) needed.push(meaning);
      if (e.tag === 14 && meaning) m.summary.push(['SONAME', meaning]);
      if ((e.tag === 15 || e.tag === 29) && meaning) m.summary.push([e.tag === 15 ? 'RPATH' : 'RUNPATH', meaning]);
      if (e.tag === 0x6ffffffb) meaning = [[1, 'NOW'], [8, 'NODELETE'], [0x8000000, 'PIE']].filter(([b]) => Number(e.val & 0xffffffffn) & b).map((x) => x[1]).join(' ');
      m.row(dynT, [name(DT, e.tag), hex(e.val), meaning], [e.at, ent]);
    }
  });
  const libT = m.table('libraries', 'Libraries', [['Library', 's'], ['How', 's']], [0]);
  for (const n of needed) m.row(libT, [n, 'DT_NEEDED']);
  if (needed.length) m.summary.push(['Needed libraries', needed.length > 6 ? `${needed.slice(0, 6).join(', ')} and ${needed.length - 6} more` : needed.join(', ')]);

  // ---- imports and exports ----
  m.part('Imports and exports', () => {
    const useDyn = dynsyms.length > 0;
    const list = useDyn ? dynsyms : [];
    if (!useDyn) {
      // Objects and static executables: the .symtab globals.
      const st = sections.find((s) => s.type === 2);
      if (st) list.push(...readSyms(st));
    }
    // Without a version entry the dynamic linker takes the symbol from the first loaded object that has it.
    const anyLib = needed.length ? '(resolved at load time)' : '';
    for (const y of list) {
      if (!y.name || y.type === 3 || y.type === 4) continue;
      const global = y.bind === 1 || y.bind === 2 || y.bind === 10;
      if (!global) continue;
      if (y.shndx === 0) {
        if (!m.row(impT, [y.name, y.ver ? y.ver.file : anyLib, y.ver ? y.ver.version : '', name(STT, y.type), name(STB, y.bind)])) break;
      } else if (y.vis === 'DEFAULT' || y.vis === 'PROTECTED') {
        if (!m.row(expT, [y.name, hex(y.value), safe(y.size) ?? 0, name(STT, y.type), name(STB, y.bind), secName(y.shndx)])) break;
      }
    }
  });
  m.summary.push(['Imports', String(impT.rows.length)], ['Exports', String(expT.rows.length)]);

  // ---- notes ----
  const noteT = m.table('notes', 'Notes', [['Owner', 's'], ['Type', 's'], ['Description', 's']], [0, 1]);
  m.part('Notes', () => {
    const areas = sections.filter((s) => s.type === 7).map((s) => [safe(s.offset), safe(s.size)]);
    if (!areas.length) for (const p of segments) if (p.type === 4) areas.push([safe(p.offset), safe(p.filesz)]);
    let count = 0;
    for (const [base, size] of areas) {
      if (base === null || size === null) continue;
      const end = Math.min(src.size, base + size);
      let off = base;
      while (off + 12 <= end && count++ < 512) {
        const nsz = u32(off), dsz = u32(off + 4), type = u32(off + 8);
        const nameOff = off + 12, descOff = nameOff + ((nsz + 3) & ~3);
        const next = descOff + ((dsz + 3) & ~3);
        if (nsz > 4096 || dsz > 1 << 20 || next > end || next <= off) break;
        const owner = nsz ? src.fixed(nameOff, nsz) : '';
        let t = String(type), desc = `${dsz} bytes`;
        if (owner === 'GNU' && type === 3) { t = 'GNU_BUILD_ID'; desc = Array.from(src.bytes(descOff, Math.min(dsz, 64)), (x) => x.toString(16).padStart(2, '0')).join(''); m.summary.push(['Build ID', desc]); }
        else if (owner === 'GNU' && type === 1 && dsz >= 16) { t = 'GNU_ABI_TAG'; desc = `${['Linux', 'Hurd', 'Solaris', 'FreeBSD'][u32(descOff)] || u32(descOff)} ${u32(descOff + 4)}.${u32(descOff + 8)}.${u32(descOff + 12)}`; }
        else if (owner === 'GNU' && type === 5) t = 'GNU_PROPERTY_TYPE_0';
        else if (owner === 'Go' && type === 4) { t = 'Go build ID'; desc = src.fixed(descOff, Math.min(dsz, 256)); }
        else if (owner === 'CORE') t = { 1: 'PRSTATUS', 2: 'FPREGSET', 3: 'PRPSINFO', 6: 'AUXV', 0x46494c45: 'FILE' }[type] || t;
        m.row(noteT, [owner, t, desc], [off, next - off]);
        off = next;
      }
    }
  });

  if (shoff !== null && h.shoff && h.shnum && sections.length === 0) m.warn('No section could be read.');
  if (!h.shoff) m.warn('This file has no section headers (stripped or packed): sections, symbols and names come from the program headers only.');
  return m.finish();
}

module.exports = { parseElf, isElf, MACHINES };
