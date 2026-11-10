'use strict';
// PE reader: EXE, DLL, SYS, EFI and COFF images, PE32 and PE32+. DOS header, COFF header, optional header, data
// directories, sections, imports (by name and ordinal), delay-load imports, exports (with forwarders), debug info
// (PDB path), .NET runtime header, resources (types and sizes), Authenticode size, overlay. Every RVA is mapped
// through the section table and checked against the file; every list has a cap.
const { hex, safe } = require('./source');
const { Model } = require('./model');

const MACHINES = { 0x0: 'Unknown', 0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM', 0x1c4: 'ARMv7 Thumb-2', 0xaa64: 'ARM64', 0xa641: 'ARM64EC', 0xa64e: 'ARM64X', 0x200: 'Itanium (IA-64)', 0x5032: 'RISC-V 32', 0x5064: 'RISC-V 64', 0xebc: 'EFI byte code', 0x1f0: 'PowerPC', 0x166: 'MIPS R4000', 0x6232: 'LoongArch 32', 0x6264: 'LoongArch 64' };
const SUBSYSTEMS = { 0: 'Unknown', 1: 'Native (driver)', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console', 9: 'Windows CE GUI', 10: 'EFI application', 11: 'EFI boot service driver', 12: 'EFI runtime driver', 13: 'EFI ROM', 14: 'Xbox', 16: 'Windows boot application' };
const CHARACTERISTICS = { 0x1: 'RELOCS_STRIPPED', 0x2: 'EXECUTABLE_IMAGE', 0x4: 'LINE_NUMS_STRIPPED', 0x8: 'LOCAL_SYMS_STRIPPED', 0x20: 'LARGE_ADDRESS_AWARE', 0x100: '32BIT_MACHINE', 0x200: 'DEBUG_STRIPPED', 0x400: 'REMOVABLE_RUN_FROM_SWAP', 0x800: 'NET_RUN_FROM_SWAP', 0x1000: 'SYSTEM', 0x2000: 'DLL', 0x4000: 'UP_SYSTEM_ONLY' };
const DLL_CHARACTERISTICS = { 0x20: 'HIGH_ENTROPY_VA', 0x40: 'DYNAMIC_BASE (ASLR)', 0x80: 'FORCE_INTEGRITY', 0x100: 'NX_COMPAT (DEP)', 0x200: 'NO_ISOLATION', 0x400: 'NO_SEH', 0x800: 'NO_BIND', 0x1000: 'APPCONTAINER', 0x2000: 'WDM_DRIVER', 0x4000: 'GUARD_CF', 0x8000: 'TERMINAL_SERVER_AWARE' };
const SECTION_FLAGS = { 0x20: 'CODE', 0x40: 'INITIALIZED_DATA', 0x80: 'UNINITIALIZED_DATA', 0x200: 'INFO', 0x800: 'REMOVE', 0x1000: 'COMDAT', 0x2000000: 'DISCARDABLE', 0x4000000: 'NOT_CACHED', 0x8000000: 'NOT_PAGED', 0x10000000: 'SHARED', 0x20000000: 'EXECUTE', 0x40000000: 'READ', 0x80000000: 'WRITE' };
const DIRS = ['Export', 'Import', 'Resource', 'Exception', 'Certificate (security)', 'Base relocation', 'Debug', 'Architecture', 'Global pointer', 'TLS', 'Load config', 'Bound import', 'Import address table (IAT)', 'Delay import', '.NET (CLR) header', 'Reserved'];
const RES_TYPES = { 1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE', 19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST' };
const DEBUG_TYPES = { 1: 'COFF', 2: 'CodeView', 3: 'FPO', 4: 'MISC', 5: 'Exception', 6: 'Fixup', 9: 'Borland', 12: 'VC_FEATURE', 13: 'POGO', 14: 'ILTCG', 16: 'Repro', 20: 'Extended DLL characteristics' };

function flagList(v, map) {
  const out = [];
  let rest = v >>> 0;
  for (const [k, n] of Object.entries(map)) { const b = Number(k); if ((v & b) === b && b) { out.push(n); rest &= ~b; } }
  if (rest) out.push(hex(rest >>> 0));
  return out.join(' | ') || 'none';
}
const name = (map, v) => (map[v] !== undefined ? map[v] : hex(v));
const unixTime = (t) => (t ? `${new Date(t * 1000).toISOString().replace('.000Z', 'Z')} (${hex(t)})` : '0');

function isPe(src) {
  if (src.size < 2) return false;
  const b = src.bytes(0, 2);
  return b[0] === 0x4d && b[1] === 0x5a; // "MZ"
}

function parsePe(src, budget) {
  const m = new Model('PE', budget);
  m.template = 'pe';
  const L = m.budget.limits;
  const u16 = (o) => src.u16(o, true), u32 = (o) => src.u32(o, true);
  const dos = m.group('MS-DOS header');
  dos.fields.push(['Magic (e_magic)', '"MZ"', 0, 2]);
  if (src.size < 0x40) { m.title = 'MS-DOS executable, header cut short'; m.warn(`The MS-DOS header needs 64 bytes; the file has ${src.size}.`); return m.finish(); }
  const lfanew = u32(0x3c);
  dos.fields.push(['Bytes on last page (e_cblp)', String(u16(2)), 2, 2], ['Pages (e_cp)', String(u16(4)), 4, 2], ['Initial IP (e_ip)', hex(u16(0x14)), 0x14, 2], ['PE header at (e_lfanew)', hex(lfanew), 0x3c, 4]);
  if (lfanew + 24 > src.size || lfanew < 4 || u32(lfanew) !== 0x4550) {
    m.title = 'MS-DOS executable (no PE header)';
    m.summary.push(['Format', 'MS-DOS MZ executable'], ['PE header', `none at ${hex(lfanew)}`]);
    m.warn(`No "PE\\0\\0" signature at e_lfanew ${hex(lfanew)}: this is a plain MS-DOS program, or the header is damaged.`);
    return m.finish();
  }
  const c = lfanew + 4;
  const coff = { machine: u16(c), nsec: u16(c + 2), time: u32(c + 4), symptr: u32(c + 8), nsym: u32(c + 12), optsize: u16(c + 16), chars: u16(c + 18) };
  const ch = m.group('COFF file header');
  ch.fields.push(['Signature', '"PE\\0\\0"', lfanew, 4], ['Machine', `${name(MACHINES, coff.machine)} (${hex(coff.machine)})`, c, 2], ['Number of sections', String(coff.nsec), c + 2, 2],
    ['Time date stamp', unixTime(coff.time), c + 4, 4], ['Pointer to symbol table', hex(coff.symptr), c + 8, 4], ['Number of symbols', String(coff.nsym), c + 12, 4],
    ['Size of optional header', String(coff.optsize), c + 16, 2], ['Characteristics', flagList(coff.chars, CHARACTERISTICS), c + 18, 2]);

  const o = c + 20;
  let magic = 0, is64 = false, opt = {};
  const dirs = [];
  const og = m.group('Optional header');
  m.part('Optional header', () => {
    if (coff.optsize < 2) return;
    magic = u16(o);
    is64 = magic === 0x20b;
    if (magic !== 0x10b && magic !== 0x20b) { m.warn(`Optional header magic is ${hex(magic)} (PE32 is 0x10B, PE32+ is 0x20B).`); return; }
    const end = o + coff.optsize;
    const need = is64 ? 112 : 96;
    if (end > src.size) m.warn('Optional header: it runs past the end of the file.');
    opt = {
      entry: u32(o + 16), baseOfCode: u32(o + 20), imageBase: is64 ? src.u64(o + 24, true) : BigInt(u32(o + 28)),
      sectionAlign: u32(o + 32), fileAlign: u32(o + 36), osMajor: u16(o + 40), osMinor: u16(o + 42), subMajor: u16(o + 48), subMinor: u16(o + 50),
      sizeOfImage: u32(o + 56), sizeOfHeaders: u32(o + 60), checksum: u32(o + 64), subsystem: u16(o + 68), dllChars: u16(o + 70),
      linker: `${src.u8(o + 2)}.${src.u8(o + 3)}`,
    };
    og.fields.push(['Magic', `${is64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)'} (${hex(magic)})`, o, 2], ['Linker version', opt.linker, o + 2, 2],
      ['Size of code', hex(u32(o + 4)), o + 4, 4], ['Entry point (RVA)', hex(opt.entry), o + 16, 4], ['Base of code', hex(opt.baseOfCode), o + 20, 4],
      ['Image base', hex(opt.imageBase), is64 ? o + 24 : o + 28, is64 ? 8 : 4], ['Section alignment', hex(opt.sectionAlign), o + 32, 4], ['File alignment', hex(opt.fileAlign), o + 36, 4],
      ['OS version', `${opt.osMajor}.${opt.osMinor}`, o + 40, 4], ['Subsystem version', `${opt.subMajor}.${opt.subMinor}`, o + 48, 4], ['Size of image', hex(opt.sizeOfImage), o + 56, 4],
      ['Size of headers', hex(opt.sizeOfHeaders), o + 60, 4], ['Checksum', hex(opt.checksum), o + 64, 4], ['Subsystem', `${name(SUBSYSTEMS, opt.subsystem)} (${opt.subsystem})`, o + 68, 2],
      ['DLL characteristics', flagList(opt.dllChars, DLL_CHARACTERISTICS), o + 70, 2]);
    if (coff.optsize < need) { m.warn(`Optional header: ${coff.optsize} bytes is too short for the data directories.`); return; }
    const ndOff = o + (is64 ? 108 : 92);
    let nd = u32(ndOff);
    og.fields.push(['Number of data directories', String(nd), ndOff, 4]);
    const room = Math.floor((end - (ndOff + 4)) / 8);
    if (nd > 16) { m.warn(`Optional header: NumberOfRvaAndSizes is ${nd}; the format has 16. Reading 16.`); nd = 16; }
    if (nd > room) { m.warn(`Optional header: ${nd} data directories do not fit in the optional header; reading ${Math.max(0, room)}.`); nd = Math.max(0, room); }
    for (let i = 0; i < nd; i++) dirs.push({ i, rva: u32(ndOff + 4 + i * 8), size: u32(ndOff + 8 + i * 8), at: ndOff + 4 + i * 8 });
  });

  // ---- sections ----
  const secs = [];
  const secT = m.table('sections', 'Sections', [['#', 'd'], ['Name', 's'], ['Virtual address', 'h'], ['Virtual size', 'h'], ['Raw offset', 'h'], ['Raw size', 'h'], ['Characteristics', 's'], ['Flags', 'h']], [1]);
  m.part('Section table', () => {
    const base = o + coff.optsize;
    let n = coff.nsec;
    const fit = Math.max(0, Math.floor((src.size - base) / 40));
    if (n > fit) { m.warn(`Section table: ${n} sections do not fit in the file; reading ${fit}.`); n = fit; }
    n = Math.min(n, L.maxSections);
    const strtab = coff.symptr && coff.symptr + coff.nsym * 18 < src.size ? coff.symptr + coff.nsym * 18 : 0;
    for (let i = 0; i < n; i++) {
      const b = base + i * 40;
      let nm = src.fixed(b, 8);
      if (/^\/\d+$/.test(nm) && strtab) { try { nm = src.cstr(strtab + Number(nm.slice(1)), 256); } catch { /* keep "/123" */ } }
      const s = { name: nm, vsize: u32(b + 8), va: u32(b + 12), rawSize: u32(b + 16), rawPtr: u32(b + 20), chars: u32(b + 36), at: b };
      secs.push(s);
      const span = s.rawPtr < src.size && s.rawSize ? [s.rawPtr, Math.min(s.rawSize, src.size - s.rawPtr)] : null;
      m.row(secT, [i + 1, s.name, hex(s.va), hex(s.vsize), hex(s.rawPtr), hex(s.rawSize), flagList(s.chars & 0xfe0fffff, SECTION_FLAGS), hex(s.chars)], span);
      if (s.rawSize && s.rawPtr + s.rawSize > src.size) m.warn(`Section ${s.name}: raw data runs past the end of the file.`);
    }
  });

  /** RVA to file offset, or null. */
  const rvaToOff = (rva) => {
    if (opt.sizeOfHeaders && rva < opt.sizeOfHeaders) return rva < src.size ? rva : null;
    for (const s of secs) {
      const span = Math.max(s.vsize, s.rawSize);
      if (rva >= s.va && rva < s.va + span) {
        const d = rva - s.va;
        if (d >= s.rawSize) return null; // in memory only (zero-filled)
        const off = s.rawPtr + d;
        return off < src.size ? off : null;
      }
    }
    return secs.length === 0 && rva < src.size ? rva : null;
  };
  const strRva = (rva, max = L.maxString) => { const off = rvaToOff(rva); if (off === null) throw new Error(`RVA ${hex(rva)} is not in the file`); return src.cstr(off, max); };

  // ---- data directories ----
  const dirT = m.table('directories', 'Data directories', [['#', 'd'], ['Directory', 's'], ['RVA', 'h'], ['Size', 'h'], ['File offset', 'h'], ['Section', 's']], [1]);
  for (const d of dirs) {
    const off = d.i === 4 ? (d.rva < src.size ? d.rva : null) : (d.rva ? rvaToOff(d.rva) : null);
    const sec = d.i === 4 ? '(file offset)' : (secs.find((s) => d.rva >= s.va && d.rva < s.va + Math.max(s.vsize, s.rawSize)) || {}).name || '';
    if (d.rva || d.size) m.row(dirT, [d.i, DIRS[d.i], hex(d.rva), hex(d.size), off === null ? '' : hex(off), sec], off !== null ? [off, Math.min(d.size, src.size - off)] : [d.at, 8]);
  }
  const dir = (i) => dirs.find((d) => d.i === i && d.rva) || null;

  const fmt = is64 ? 'PE32+' : 'PE32';
  const isDll = !!(coff.chars & 0x2000);
  const kind = opt.subsystem === 1 ? 'driver' : isDll ? 'DLL' : (coff.chars & 2) ? 'executable' : 'object';
  m.title = `${magic ? fmt : 'COFF'} ${kind}, ${name(MACHINES, coff.machine)}${opt.subsystem !== undefined ? `, ${name(SUBSYSTEMS, opt.subsystem)}` : ''}`;
  m.summary.push(['Format', magic ? `${fmt} (${is64 ? '64' : '32'}-bit)` : 'COFF'], ['Kind', kind], ['Machine', name(MACHINES, coff.machine)], ['Built', unixTime(coff.time)]);
  if (magic) {
    m.summary.push(['Subsystem', name(SUBSYSTEMS, opt.subsystem)], ['Entry point', `${hex(opt.entry)} (RVA)`], ['Image base', hex(opt.imageBase)]);
    const sec = [];
    sec.push(opt.dllChars & 0x40 ? 'ASLR on' : 'ASLR off', opt.dllChars & 0x100 ? 'DEP on' : 'DEP off');
    if (opt.dllChars & 0x4000) sec.push('Control Flow Guard');
    if (opt.dllChars & 0x20) sec.push('high-entropy ASLR');
    m.summary.push(['Security flags', sec.join(', ')]);
  }
  m.summary.push(['Sections', String(secs.length)]);

  // ---- imports ----
  const impT = m.table('imports', 'Imports', [['Name', 's'], ['Library', 's'], ['Ordinal', 's'], ['Hint', 'd'], ['Kind', 's'], ['IAT entry (RVA)', 'h']], [1, 0, 2]);
  const libT = m.table('libraries', 'Libraries', [['Library', 's'], ['Functions', 'd'], ['How', 's']], [0]);
  const libs = new Map();
  const thunkList = (rva, dll, kindName, iatRva) => {
    const tsz = is64 ? 8 : 4;
    let off = rvaToOff(rva);
    if (off === null) { m.warn(`${dll}: the import name table at RVA ${hex(rva)} is not in the file.`); return 0; }
    let n = 0;
    for (; n < L.maxThunks && m.budget.ok(); n++) {
      if (off + tsz > src.size) { m.warn(`${dll}: the import list runs past the end of the file.`); break; }
      const v = is64 ? src.u64(off, true) : BigInt(u32(off));
      if (v === 0n) break;
      const byOrd = is64 ? (v >> 63n) === 1n : (v >> 31n) === 1n;
      let fn = '', ord = '', hint = 0;
      if (byOrd) { ord = String(Number(v & 0xffffn)); fn = `#${ord}`; }
      else {
        const hr = Number(v & 0x7fffffffn);
        const ho = rvaToOff(hr);
        if (ho === null || ho + 2 > src.size) fn = `(name at RVA ${hex(hr)})`;
        else { hint = u16(ho); try { fn = src.cstr(ho + 2, 1024); } catch { fn = `(name at RVA ${hex(hr)})`; } }
      }
      if (!m.row(impT, [fn, dll, ord, hint, kindName, hex(iatRva + n * tsz)])) break;
      off += tsz;
    }
    if (n >= L.maxThunks) m.warn(`${dll}: more than ${L.maxThunks} imported names; the rest is not listed.`);
    return n;
  };
  m.part('Import directory', () => {
    const d = dir(1);
    if (!d) return;
    let off = rvaToOff(d.rva);
    if (off === null) { m.warn(`Import directory: RVA ${hex(d.rva)} is not in the file.`); return; }
    const seen = new Set();
    for (let i = 0; i < L.maxLibraries && m.budget.ok(); i++, off += 20) {
      if (off + 20 > src.size) { m.warn('Import directory: it runs past the end of the file.'); break; }
      const oft = u32(off), nameRva = u32(off + 12), ft = u32(off + 16);
      if (!oft && !nameRva && !ft) break;
      let dll;
      try { dll = strRva(nameRva, 512); } catch { dll = `(name at RVA ${hex(nameRva)})`; }
      const key = `${oft}:${ft}:${nameRva}`;
      if (seen.has(key)) { m.warn(`Import directory: ${dll} is listed twice with the same tables; the copy is skipped.`); continue; }
      seen.add(key);
      const n = thunkList(oft || ft, dll, 'import', ft);
      libs.set(dll, { n: (libs.get(dll) || { n: 0 }).n + n, how: 'import' });
    }
  });
  m.part('Delay-load imports', () => {
    const d = dir(13);
    if (!d) return;
    let off = rvaToOff(d.rva);
    if (off === null) return;
    for (let i = 0; i < L.maxLibraries && m.budget.ok(); i++, off += 32) {
      if (off + 32 > src.size) break;
      const attrs = u32(off), nameRva = u32(off + 4), iat = u32(off + 12), intRva = u32(off + 16);
      if (!nameRva && !iat && !intRva) break;
      // Old (VC6) descriptors hold virtual addresses, not RVAs.
      const fix = (v) => (attrs & 1 || !v ? v : Number((BigInt(v) - (opt.imageBase || 0n)) & 0xffffffffn));
      let dll;
      try { dll = strRva(fix(nameRva), 512); } catch { dll = `(name at ${hex(nameRva)})`; }
      const n = thunkList(fix(intRva), dll, 'delay-load', fix(iat));
      if (!libs.has(dll)) libs.set(dll, { n, how: 'delay-load' }); else libs.get(dll).n += n;
    }
  });
  for (const [dll, v] of libs) m.row(libT, [dll, v.n, v.how]);
  if (libs.size) { const names = [...libs.keys()]; m.summary.push(['Libraries', names.length > 6 ? `${names.slice(0, 6).join(', ')} and ${names.length - 6} more` : names.join(', ')]); }

  // ---- exports ----
  const expT = m.table('exports', 'Exports', [['Name', 's'], ['Ordinal', 'd'], ['Address (RVA)', 'h'], ['Forwarded to', 's']], [0, 1]);
  m.part('Export directory', () => {
    const d = dir(0);
    if (!d) return;
    const off = rvaToOff(d.rva);
    if (off === null || off + 40 > src.size) { m.warn(`Export directory: RVA ${hex(d.rva)} is not in the file.`); return; }
    const nameRva = u32(off + 12), base = u32(off + 16);
    let nfun = u32(off + 20), nnames = u32(off + 24);
    const afun = u32(off + 28), anames = u32(off + 32), aords = u32(off + 36);
    let dllName = '';
    try { dllName = strRva(nameRva, 512); } catch { /* unnamed */ }
    if (dllName) m.summary.push(['Export name', dllName]);
    const cap = L.maxRows;
    if (nfun > cap) { m.warn(`Export directory: NumberOfFunctions is ${nfun}; reading ${cap}.`); nfun = cap; }
    if (nnames > cap) { m.warn(`Export directory: NumberOfNames is ${nnames}; reading ${cap}.`); nnames = cap; }
    const fo = rvaToOff(afun), no = rvaToOff(anames), oo = rvaToOff(aords);
    const names = new Map();
    if (no !== null && oo !== null) {
      const fitN = Math.min(Math.floor((src.size - no) / 4), Math.floor((src.size - oo) / 2));
      if (nnames > fitN) { m.warn('Export directory: the name list runs past the end of the file.'); nnames = Math.max(0, fitN); }
      for (let i = 0; i < nnames && m.budget.ok(); i++) {
        const idx = src.u16(oo + i * 2, true);
        let nm;
        try { nm = strRva(u32(no + i * 4), 1024); } catch { nm = `(name ${i})`; }
        if (!names.has(idx)) names.set(idx, nm);
      }
    }
    if (fo === null) { if (nfun) m.warn('Export directory: the address table is not in the file.'); return; }
    const fitF = Math.floor((src.size - fo) / 4);
    if (nfun > fitF) { m.warn('Export directory: the address table runs past the end of the file.'); nfun = Math.max(0, fitF); }
    for (let i = 0; i < nfun && m.budget.ok(); i++) {
      const rva = u32(fo + i * 4);
      if (!rva && !names.has(i)) continue;
      let fwd = '';
      if (rva >= d.rva && rva < d.rva + d.size) { try { fwd = strRva(rva, 512); } catch { fwd = '(forwarder)'; } }
      if (!m.row(expT, [names.get(i) || `#${base + i}`, base + i, hex(rva), fwd])) break;
    }
  });
  m.summary.push(['Imports', String(impT.rows.length)], ['Exports', String(expT.rows.length)]);

  // ---- debug directory (PDB path) ----
  const dbgT = m.table('debug', 'Debug directory', [['Type', 's'], ['Size', 'd'], ['RVA', 'h'], ['File offset', 'h'], ['Details', 's']], [0]);
  m.part('Debug directory', () => {
    const d = dir(6);
    if (!d) return;
    const off = rvaToOff(d.rva);
    if (off === null) return;
    const n = Math.min(Math.floor(d.size / 28), 64);
    for (let i = 0; i < n; i++) {
      const b = off + i * 28;
      if (b + 28 > src.size) break;
      const type = u32(b + 12), size = u32(b + 16), rva = u32(b + 20), ptr = u32(b + 24);
      let details = '';
      if (type === 2 && ptr + 24 <= src.size && u32(ptr) === 0x53445352) { // "RSDS"
        const g = src.bytes(ptr + 4, 16);
        const h2 = (a, bb) => Array.from(g.subarray(a, bb), (x) => x.toString(16).padStart(2, '0')).join('');
        const guid = [h2(0, 4).match(/../g).reverse().join(''), h2(4, 6).match(/../g).reverse().join(''), h2(6, 8).match(/../g).reverse().join(''), h2(8, 10), h2(10, 16)].join('-').toUpperCase();
        const age = u32(ptr + 20);
        let pdb = '';
        try { pdb = src.cstr(ptr + 24, 1024); } catch { /* none */ }
        details = `PDB ${pdb}, GUID {${guid}}, age ${age}`;
        if (pdb) m.summary.push(['PDB', pdb]);
      }
      m.row(dbgT, [name(DEBUG_TYPES, type), size, hex(rva), hex(ptr), details], ptr < src.size && size ? [ptr, Math.min(size, src.size - ptr)] : [b, 28]);
    }
  });

  // ---- .NET ----
  m.part('.NET header', () => {
    const d = dir(14);
    if (!d) return;
    const off = rvaToOff(d.rva);
    if (off === null || off + 24 > src.size) return;
    const g = m.group('.NET (CLR) header');
    const rt = `${u16(off + 4)}.${u16(off + 6)}`, mdRva = u32(off + 8), flags = u32(off + 16);
    g.fields.push(['Runtime header version', rt, off + 4, 4], ['Metadata RVA', hex(mdRva), off + 8, 4], ['Flags', flagList(flags, { 1: 'IL_ONLY', 2: '32BIT_REQUIRED', 8: 'STRONG_NAME_SIGNED', 0x10: 'NATIVE_ENTRYPOINT', 0x20000: '32BIT_PREFERRED' }), off + 16, 4]);
    let ver = '';
    const mo = rvaToOff(mdRva);
    if (mo !== null && mo + 16 <= src.size && u32(mo) === 0x424a5342) { // "BSJB"
      const len = Math.min(u32(mo + 12), 255);
      ver = src.fixed(mo + 16, Math.min(len, src.size - mo - 16));
      g.fields.push(['Metadata version', ver, mo + 16, len]);
    }
    m.summary.push(['.NET', ver ? `managed assembly, runtime ${ver}` : 'managed assembly']);
    m.title += ', .NET';
  });

  // ---- resources ----
  const resT = m.table('resources', 'Resources', [['Type', 's'], ['Name', 's'], ['Language', 'd'], ['Size', 'd'], ['RVA', 'h']], [0, 1, 2]);
  m.part('Resources', () => {
    const d = dir(2);
    if (!d) return;
    const root = rvaToOff(d.rva);
    if (root === null) return;
    const seen = new Set();
    let count = 0;
    const label = (entryName, isType) => {
      if (entryName & 0x80000000) {
        const so = root + (entryName & 0x7fffffff);
        if (so + 2 > src.size) return '?';
        const len = Math.min(u16(so), 256);
        const b = src.bytesUpTo(so + 2, len * 2);
        return new TextDecoder('utf-16le').decode(b);
      }
      return isType ? name(RES_TYPES, entryName) : String(entryName);
    };
    const walk = (dirOff, depth, path) => {
      if (depth > 3 || seen.has(dirOff) || dirOff + 16 > src.size) { if (seen.has(dirOff)) m.warn('Resources: a directory points back to an earlier one (a loop); that branch is skipped.'); return; }
      seen.add(dirOff);
      const n = Math.min(u16(dirOff + 12) + u16(dirOff + 14), 4096);
      for (let i = 0; i < n && count < 10000 && m.budget.ok(); i++) {
        const e = dirOff + 16 + i * 8;
        if (e + 8 > src.size) return;
        const nm = u32(e), target = u32(e + 4);
        const here = [...path, depth === 0 ? label(nm, true) : depth === 1 ? label(nm, false) : nm];
        if (target & 0x80000000) walk(root + (target & 0x7fffffff), depth + 1, here);
        else {
          const de = root + target;
          if (de + 16 > src.size) continue;
          const rva = u32(de), size = u32(de + 4);
          const fo = rvaToOff(rva);
          count++;
          m.row(resT, [here[0] || '', here[1] || '', typeof here[2] === 'number' ? here[2] : 0, size, hex(rva)], fo !== null ? [fo, Math.min(size, src.size - fo)] : null);
        }
      }
    };
    walk(root, 0, []);
  });

  // ---- certificate and overlay ----
  m.part('Certificate', () => {
    const d = dir(4);
    if (d && d.size) m.summary.push(['Signature', d.rva + d.size <= src.size ? `Authenticode data, ${d.size.toLocaleString('en-US')} bytes at ${hex(d.rva)}` : 'Authenticode entry points past the end of the file']);
    else if (magic) m.summary.push(['Signature', 'not signed']);
  });
  m.part('Overlay', () => {
    let end = opt.sizeOfHeaders || 0;
    for (const s of secs) if (s.rawSize && s.rawPtr + s.rawSize > end) end = s.rawPtr + s.rawSize;
    const cert = dir(4);
    const certEnd = cert ? cert.rva + cert.size : 0;
    const over = src.size - Math.max(end, cert && cert.rva >= end ? certEnd : 0);
    if (end && over > 0 && end < src.size) m.summary.push(['Overlay', `${over.toLocaleString('en-US')} bytes after the last section${cert && cert.rva >= end ? ' and the signature' : ''}`]);
  });

  return m.finish();
}

module.exports = { parsePe, isPe, MACHINES };
