'use strict';
// Mach-O reader: 32 and 64-bit, either byte order, and universal (fat) files with each slice read on its own.
// Header, load commands, segments and sections, linked libraries, imports with their library (two-level namespace),
// exports (the export trie, with loop and depth guards, or the symbol table), symbols, UUID, platform and versions,
// code signature and encryption info.
const { hex, safe, uleb } = require('./source');
const { Model } = require('./model');

const CPU = { 7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'ARM64', 0x0200000c: 'ARM64_32', 18: 'PowerPC', 0x01000012: 'PowerPC 64', 14: 'SPARC', 1: 'VAX', 6: 'MC680x0', 13: 'MC88000' };
const FILETYPES = { 1: 'OBJECT (object file)', 2: 'EXECUTE (executable)', 3: 'FVMLIB', 4: 'CORE (core dump)', 5: 'PRELOAD', 6: 'DYLIB (dynamic library)', 7: 'DYLINKER', 8: 'BUNDLE', 9: 'DYLIB_STUB', 10: 'DSYM (debug symbols)', 11: 'KEXT_BUNDLE (kernel extension)', 12: 'FILESET' };
const HFLAGS = { 0x1: 'NOUNDEFS', 0x4: 'DYLDLINK', 0x8: 'BINDATLOAD', 0x80: 'TWOLEVEL', 0x200: 'NOMULTIDEFS', 0x2000: 'SUBSECTIONS_VIA_SYMBOLS', 0x8000: 'WEAK_DEFINES', 0x10000: 'BINDS_TO_WEAK', 0x20000: 'ALLOW_STACK_EXECUTION', 0x200000: 'PIE', 0x800000: 'HAS_TLV_DESCRIPTORS', 0x1000000: 'NO_HEAP_EXECUTION', 0x2000000: 'APP_EXTENSION_SAFE', 0x80000000: 'DYLIB_IN_CACHE' };
const LC = {
  0x1: 'SEGMENT', 0x2: 'SYMTAB', 0x3: 'SYMSEG', 0x4: 'THREAD', 0x5: 'UNIXTHREAD', 0xb: 'DYSYMTAB', 0xc: 'LOAD_DYLIB', 0xd: 'ID_DYLIB', 0xe: 'LOAD_DYLINKER', 0xf: 'ID_DYLINKER',
  0x10: 'PREBOUND_DYLIB', 0x11: 'ROUTINES', 0x12: 'SUB_FRAMEWORK', 0x13: 'SUB_UMBRELLA', 0x14: 'SUB_CLIENT', 0x15: 'SUB_LIBRARY', 0x16: 'TWOLEVEL_HINTS', 0x17: 'PREBIND_CKSUM',
  0x80000018: 'LOAD_WEAK_DYLIB', 0x19: 'SEGMENT_64', 0x1a: 'ROUTINES_64', 0x1b: 'UUID', 0x8000001c: 'RPATH', 0x1d: 'CODE_SIGNATURE', 0x1e: 'SEGMENT_SPLIT_INFO', 0x8000001f: 'REEXPORT_DYLIB',
  0x20: 'LAZY_LOAD_DYLIB', 0x21: 'ENCRYPTION_INFO', 0x22: 'DYLD_INFO', 0x80000022: 'DYLD_INFO_ONLY', 0x80000023: 'LOAD_UPWARD_DYLIB', 0x24: 'VERSION_MIN_MACOSX', 0x25: 'VERSION_MIN_IPHONEOS',
  0x26: 'FUNCTION_STARTS', 0x27: 'DYLD_ENVIRONMENT', 0x80000028: 'MAIN', 0x29: 'DATA_IN_CODE', 0x2a: 'SOURCE_VERSION', 0x2b: 'DYLIB_CODE_SIGN_DRS', 0x2c: 'ENCRYPTION_INFO_64',
  0x2d: 'LINKER_OPTION', 0x2e: 'LINKER_OPTIMIZATION_HINT', 0x2f: 'VERSION_MIN_TVOS', 0x30: 'VERSION_MIN_WATCHOS', 0x31: 'NOTE', 0x32: 'BUILD_VERSION', 0x80000033: 'DYLD_EXPORTS_TRIE',
  0x80000034: 'DYLD_CHAINED_FIXUPS', 0x80000035: 'FILESET_ENTRY', 0x36: 'ATOM_INFO',
};
const PLATFORMS = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit', 11: 'visionOS', 12: 'visionOS Simulator' };
const SECT_TYPES = { 0: 'REGULAR', 1: 'ZEROFILL', 2: 'CSTRING_LITERALS', 3: '4BYTE_LITERALS', 4: '8BYTE_LITERALS', 5: 'LITERAL_POINTERS', 6: 'NON_LAZY_SYMBOL_POINTERS', 7: 'LAZY_SYMBOL_POINTERS', 8: 'SYMBOL_STUBS', 9: 'MOD_INIT_FUNC_POINTERS', 10: 'MOD_TERM_FUNC_POINTERS', 11: 'COALESCED', 12: 'GB_ZEROFILL', 13: 'INTERPOSING', 14: '16BYTE_LITERALS', 15: 'DTRACE_DOF', 17: 'THREAD_LOCAL_REGULAR', 18: 'THREAD_LOCAL_ZEROFILL', 19: 'THREAD_LOCAL_VARIABLES', 20: 'THREAD_LOCAL_VARIABLE_POINTERS', 21: 'THREAD_LOCAL_INIT_FUNCTION_POINTERS', 22: 'INIT_FUNC_OFFSETS' };
const DYLIB_CMDS = { 0xc: 'load', 0x80000018: 'weak', 0x8000001f: 'reexport', 0x20: 'lazy', 0x80000023: 'upward' };

const name = (map, v) => (map[v] !== undefined ? map[v] : hex(v));
const ver = (v) => `${v >>> 16}.${(v >> 8) & 0xff}.${v & 0xff}`;
const prot = (p) => (p & 1 ? 'r' : '-') + (p & 2 ? 'w' : '-') + (p & 4 ? 'x' : '-');
function cpuName(type, sub) {
  const base = name(CPU, type >>> 0);
  const s = sub & 0xffffff;
  if ((type >>> 0) === 0x0100000c && s === 2) return 'ARM64e';
  if ((type >>> 0) === 0x01000007 && s === 8) return 'x86-64h';
  if (type === 12 && s === 9) return 'ARMv7';
  if (type === 12 && s === 11) return 'ARMv7s';
  return base;
}

const MAGICS = { 0xfeedface: [false, true], 0xfeedfacf: [true, true], 0xcefaedfe: [false, false], 0xcffaedfe: [true, false] };

/** 'thin', 'fat', or '' for the first bytes of a file. */
function machoKind(src) {
  if (src.size < 8) return '';
  const be = src.u32(0, false);
  if (MAGICS[be]) return 'thin';
  if (be === 0xcafebabe || be === 0xcafebabf) {
    const n = src.u32(4, false);
    // Java class files start with CAFEBABE too; their next word is the class version (45 or more).
    if (n > 0 && n < 40) return 'fat';
  }
  return '';
}

function parseFat(src, budget, parseThin) {
  const m = new Model('Mach-O universal', budget);
  m.template = 'macho';
  const L = m.budget.limits;
  const is64 = src.u32(0, false) === 0xcafebabf;
  let n = src.u32(4, false);
  const g = m.group('Universal (fat) header');
  g.fields.push(['Magic', is64 ? 'FAT_MAGIC_64 (0xCAFEBABF)' : 'FAT_MAGIC (0xCAFEBABE)', 0, 4], ['Architectures', String(n), 4, 4]);
  const ent = is64 ? 32 : 20;
  const fit = Math.floor((src.size - 8) / ent);
  if (n > fit) { m.warn(`Universal header: ${n} architectures do not fit in the file; reading ${fit}.`); n = fit; }
  if (n > L.maxSlices) { m.warn(`Universal header: ${n} architectures; reading the first ${L.maxSlices}.`); n = L.maxSlices; }
  const t = m.table('slices', 'Architectures', [['#', 'd'], ['Architecture', 's'], ['CPU type', 'h'], ['CPU subtype', 'h'], ['Offset', 'h'], ['Size', 'h'], ['Align', 's']], [1]);
  m.slices = [];
  const archs = [];
  for (let i = 0; i < n; i++) {
    const b = 8 + i * ent;
    const cpu = src.u32(b, false), sub = src.u32(b + 4, false);
    const off = is64 ? safe(src.u64(b + 8, false)) : src.u32(b + 8, false);
    const size = is64 ? safe(src.u64(b + 16, false)) : src.u32(b + 12, false);
    const align = src.u32(b + (is64 ? 24 : 16), false);
    const arch = cpuName(cpu, sub);
    archs.push(arch);
    const okRange = off !== null && size !== null && off > 0 && off < src.size;
    m.row(t, [i, arch, hex(cpu), hex(sub), hex(off ?? 0), hex(size ?? 0), align < 32 ? `2^${align}` : String(align)], okRange ? [off, Math.min(size, src.size - off)] : [b, ent]);
    if (!okRange) { m.warn(`${arch}: the slice at ${hex(off ?? 0)} is outside the file.`); continue; }
    if (off + size > src.size) m.warn(`${arch}: the slice runs past the end of the file; it is read up to the end.`);
    if (archs.length > 1 && m.slices.some((s) => s.offset === off)) { m.warn(`${arch}: the slice starts where another one does; it is read once.`); continue; }
    let model;
    try { model = parseThin(src.slice(off, size), m.budget); }
    catch (e) { model = { format: 'Mach-O', title: `${arch} slice that could not be read`, summary: [], groups: [], tables: [], warnings: [String(e && e.message || e)] }; }
    m.slices.push({ arch, offset: off, size, model });
  }
  m.title = `Mach-O universal binary, ${archs.length} architecture${archs.length === 1 ? '' : 's'}: ${archs.join(', ')}`;
  m.summary.push(['Format', 'Mach-O universal (fat)'], ['Architectures', archs.join(', ') || 'none']);
  return m.finish();
}

function parseThin(src, budget) {
  const m = new Model('Mach-O', budget);
  m.template = 'macho';
  const L = m.budget.limits;
  const magic = src.u32(0, false);
  const [is64, be] = MAGICS[magic] || [];
  if (is64 === undefined) throw new Error(`magic ${hex(magic)} is not a Mach-O magic`);
  const le = !be;
  const u32 = (o) => src.u32(o, le), u16 = (o) => src.u16(o, le);
  const hsize = is64 ? 32 : 28;
  if (src.size < hsize) { m.title = 'Mach-O, header cut short'; m.warn(`The Mach-O header needs ${hsize} bytes; the data has ${src.size}.`); return m.finish(); }
  const hd = { cpu: u32(4), sub: u32(8), filetype: u32(12), ncmds: u32(16), sizeofcmds: u32(20), flags: u32(24) };
  const arch = cpuName(hd.cpu, hd.sub);
  const g = m.group('Mach-O header');
  g.fields.push(['Magic', `${hex(magic)} (${is64 ? '64' : '32'}-bit, ${le ? 'little' : 'big'} endian)`, 0, 4], ['CPU type', `${arch} (${hex(hd.cpu)})`, 4, 4], ['CPU subtype', hex(hd.sub), 8, 4],
    ['File type', name(FILETYPES, hd.filetype), 12, 4], ['Load commands', String(hd.ncmds), 16, 4], ['Size of load commands', String(hd.sizeofcmds), 20, 4],
    ['Flags', Object.entries(HFLAGS).filter(([b]) => (hd.flags & Number(b)) >>> 0 === Number(b)).map((x) => x[1]).join(' | ') || 'none', 24, 4]);
  const ftShort = { 1: 'object file', 2: 'executable', 6: 'dynamic library', 8: 'bundle', 7: 'dynamic linker', 10: 'dSYM companion', 11: 'kernel extension', 4: 'core dump' }[hd.filetype] || `file type ${hd.filetype}`;
  m.title = `Mach-O ${is64 ? '64' : '32'}-bit ${ftShort}, ${arch}`;
  m.summary.push(['Format', `Mach-O ${is64 ? '64' : '32'}-bit, ${le ? 'little' : 'big'} endian`], ['Kind', name(FILETYPES, hd.filetype)], ['Architecture', arch]);

  const cmdT = m.table('loadcommands', 'Load commands', [['#', 'd'], ['Command', 's'], ['Size', 'd'], ['Offset', 'h'], ['Details', 's']], [1, 4]);
  const segT = m.table('segments', 'Segments', [['Name', 's'], ['VM address', 'h'], ['VM size', 'h'], ['File offset', 'h'], ['File size', 'h'], ['Max prot', 's'], ['Init prot', 's'], ['Sections', 'd']], [0]);
  const secT = m.table('sections', 'Sections', [['Segment', 's'], ['Section', 's'], ['Address', 'h'], ['Size', 'h'], ['Offset', 'h'], ['Align', 's'], ['Type', 's'], ['Flags', 'h']], [0, 1]);
  const libT = m.table('libraries', 'Libraries', [['Library', 's'], ['How', 's'], ['Current version', 's'], ['Compatibility version', 's']], [0]);
  const dylibs = [];
  const linkedit = {};
  let symtab = null, entry = null;
  const lcStr = (cmdOff, cmdSize, strOff) => (strOff >= 8 && strOff < cmdSize ? src.cstr(cmdOff + strOff, Math.min(L.maxString, cmdSize - strOff)) : '');

  m.part('Load commands', () => {
    let off = hsize;
    const end = Math.min(src.size, hsize + hd.sizeofcmds);
    if (hsize + hd.sizeofcmds > src.size) m.warn(`Load commands: sizeofcmds (${hd.sizeofcmds}) runs past the end of the data.`);
    let n = Math.min(hd.ncmds, L.maxCommands);
    if (hd.ncmds > L.maxCommands) m.warn(`Load commands: ${hd.ncmds} commands; reading ${L.maxCommands}.`);
    for (let i = 0; i < n && m.budget.ok(); i++) {
      if (off + 8 > end) { m.warn(`Load commands: command ${i} of ${hd.ncmds} starts past the end of the command area.`); break; }
      const cmd = u32(off), size = u32(off + 4);
      if (size < 8 || off + size > end) { m.warn(`Load commands: command ${i} (${name(LC, cmd)}) has size ${size}, which ${size < 8 ? 'is too small' : 'runs past the command area'}; reading stopped there.`); break; }
      let details = '';
      try {
        if (cmd === 0x1 || cmd === 0x19) {
          const s64 = cmd === 0x19;
          const seg = src.fixed(off + 8, 16);
          const vmaddr = s64 ? src.u64(off + 24, le) : BigInt(u32(off + 24));
          const vmsize = s64 ? src.u64(off + 32, le) : BigInt(u32(off + 28));
          const fileoff = s64 ? src.u64(off + 40, le) : BigInt(u32(off + 32));
          const filesize = s64 ? src.u64(off + 48, le) : BigInt(u32(off + 36));
          const maxp = u32(off + (s64 ? 56 : 40)), initp = u32(off + (s64 ? 60 : 44)), nsects = u32(off + (s64 ? 64 : 48));
          const fo = safe(fileoff), fs = safe(filesize);
          m.row(segT, [seg, hex(vmaddr), hex(vmsize), hex(fileoff), hex(filesize), prot(maxp), prot(initp), nsects], fo !== null && fs !== null && fo < src.size && fs ? [fo, Math.min(fs, src.size - fo)] : [off, size]);
          details = `${seg} ${hex(vmaddr)} ${prot(initp)}, ${nsects} section${nsects === 1 ? '' : 's'}`;
          const ss = s64 ? 80 : 68, first = off + (s64 ? 72 : 56);
          const room = Math.floor((off + size - first) / ss);
          if (nsects > room) m.warn(`Segment ${seg}: ${nsects} sections do not fit in its load command; reading ${Math.max(0, room)}.`);
          for (let k = 0; k < Math.min(nsects, Math.max(0, room)); k++) {
            const b = first + k * ss;
            const sect = src.fixed(b, 16), sg = src.fixed(b + 16, 16);
            const addr = s64 ? src.u64(b + 32, le) : BigInt(u32(b + 32));
            const ssize = s64 ? src.u64(b + 40, le) : BigInt(u32(b + 36));
            const soff = u32(b + (s64 ? 48 : 40)), align = u32(b + (s64 ? 52 : 44)), flags = u32(b + (s64 ? 64 : 56));
            const type = flags & 0xff;
            const zero = type === 1 || type === 12 || type === 18;
            const sz = safe(ssize);
            m.row(secT, [sg, sect, hex(addr), hex(ssize), hex(soff), align < 32 ? `2^${align}` : String(align), name(SECT_TYPES, type), hex(flags >>> 0)], !zero && soff && soff < src.size && sz ? [soff, Math.min(sz, src.size - soff)] : null);
          }
        } else if (DYLIB_CMDS[cmd] || cmd === 0xd) {
          const nm = lcStr(off, size, u32(off + 8));
          const cur = ver(u32(off + 16)), compat = ver(u32(off + 20));
          if (cmd === 0xd) { m.summary.push(['Install name', nm]); g.fields.push(['Install name (LC_ID_DYLIB)', nm, off, size]); }
          else { dylibs.push(nm); if (dylibs.length <= L.maxLibraries) m.row(libT, [nm, DYLIB_CMDS[cmd], cur, compat], [off, size]); }
          details = `${nm} (${cur})`;
        } else if (cmd === 0x2) {
          symtab = { symoff: u32(off + 8), nsyms: u32(off + 12), stroff: u32(off + 16), strsize: u32(off + 20) };
          details = `${symtab.nsyms} symbols at ${hex(symtab.symoff)}, strings at ${hex(symtab.stroff)} (${symtab.strsize} bytes)`;
        } else if (cmd === 0xe || cmd === 0xf) {
          details = lcStr(off, size, u32(off + 8));
          if (cmd === 0xe) m.summary.push(['Dynamic linker', details]);
        } else if (cmd === 0x8000001c) {
          details = lcStr(off, size, u32(off + 8));
          m.summary.push(['RPATH', details]);
        } else if (cmd === 0x1b && size >= 24) {
          const b = src.bytes(off + 8, 16);
          const h = Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join('');
          details = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
          m.summary.push(['UUID', details]);
        } else if (cmd === 0x80000028 && size >= 24) {
          entry = src.u64(off + 8, le);
          details = `entry offset ${hex(entry)}, stack ${hex(src.u64(off + 16, le))}`;
          m.summary.push(['Entry point', `${hex(entry)} (file offset of main)`]);
        } else if (cmd === 0x32 && size >= 24) {
          const plat = u32(off + 8), minos = u32(off + 12), sdk = u32(off + 16);
          details = `${name(PLATFORMS, plat)} ${ver(minos)}, SDK ${ver(sdk)}`;
          m.summary.push(['Platform', `${name(PLATFORMS, plat)}, minimum ${ver(minos)}, SDK ${ver(sdk)}`]);
        } else if ([0x24, 0x25, 0x2f, 0x30].includes(cmd) && size >= 16) {
          const plat = { 0x24: 'macOS', 0x25: 'iOS', 0x2f: 'tvOS', 0x30: 'watchOS' }[cmd];
          details = `${plat} ${ver(u32(off + 8))}, SDK ${ver(u32(off + 12))}`;
          m.summary.push(['Platform', `${plat}, minimum ${ver(u32(off + 8))}`]);
        } else if (cmd === 0x2a && size >= 16) {
          const v = src.u64(off + 8, le);
          details = [Number(v >> 40n), Number((v >> 30n) & 0x3ffn), Number((v >> 20n) & 0x3ffn), Number((v >> 10n) & 0x3ffn), Number(v & 0x3ffn)].join('.');
        } else if ([0x1d, 0x26, 0x29, 0x80000033, 0x80000034, 0x1e, 0x2b, 0x2e].includes(cmd) && size >= 16) {
          const dataoff = u32(off + 8), datasize = u32(off + 12);
          linkedit[cmd] = { dataoff, datasize };
          details = `${datasize.toLocaleString('en-US')} bytes at ${hex(dataoff)}`;
          if (cmd === 0x1d) m.summary.push(['Code signature', `${datasize.toLocaleString('en-US')} bytes at ${hex(dataoff)}`]);
        } else if ((cmd === 0x22 || cmd === 0x80000022) && size >= 48) {
          linkedit.dyld = { exportOff: u32(off + 40), exportSize: u32(off + 44) };
          details = `export trie ${u32(off + 44)} bytes at ${hex(u32(off + 40))}`;
        } else if ((cmd === 0x21 || cmd === 0x2c) && size >= 20) {
          const cryptid = u32(off + 16);
          details = `${u32(off + 12)} bytes at ${hex(u32(off + 8))}, ${cryptid ? 'encrypted' : 'not encrypted'}`;
          if (cryptid) m.summary.push(['Encryption', `encrypted (cryptid ${cryptid})`]);
        } else if (cmd === 0x2d && size >= 12) {
          details = `${u32(off + 8)} option string(s)`;
        }
      } catch (e) { details = `could not be read: ${e.message}`; }
      m.row(cmdT, [i, `LC_${name(LC, cmd)}`, size, hex(off), details], [off, size]);
      off += size;
    }
  });
  if (dylibs.length) m.summary.push(['Libraries', dylibs.length > 6 ? `${dylibs.slice(0, 6).join(', ')} and ${dylibs.length - 6} more` : dylibs.join(', ')]);

  // ---- symbols, imports ----
  const symT = m.table('symbols', 'Symbols', [['Name', 's'], ['Value', 'h'], ['Type', 's'], ['Section', 'd'], ['External', 's'], ['Library', 's']], [0]);
  const impT = m.table('imports', 'Imports', [['Name', 's'], ['Library', 's'], ['Weak', 's']], [1, 0]);
  const expT = m.table('exports', 'Exports', [['Name', 's'], ['Address', 'h'], ['Kind', 's']], [0]);
  const libOf = (desc) => {
    const ord = (desc >> 8) & 0xff;
    if (ord === 0) return 'self';
    if (ord === 0xfe) return 'main executable';
    if (ord === 0xff) return 'flat lookup';
    return dylibs[ord - 1] || `library #${ord}`;
  };
  const defined = [];
  m.part('Symbol table', () => {
    if (!symtab) return;
    const NSZ = is64 ? 16 : 12;
    if (symtab.symoff >= src.size && symtab.nsyms) { m.warn(`Symbol table: offset ${hex(symtab.symoff)} is past the end of the data.`); return; }
    let n = symtab.nsyms;
    const fit = Math.floor((src.size - symtab.symoff) / NSZ);
    if (n > fit) { m.warn(`Symbol table: ${n} symbols do not fit in the data; reading ${fit}.`); n = fit; }
    const strEnd = Math.min(src.size, symtab.stroff + symtab.strsize);
    for (let i = 0; i < n && m.budget.ok(); i++) {
      const b = symtab.symoff + i * NSZ;
      const strx = u32(b), type = src.u8(b + 4), sect = src.u8(b + 5), desc = u16(b + 6);
      const value = is64 ? src.u64(b + 8, le) : BigInt(u32(b + 8));
      if (type & 0xe0) continue; // debugger (stab) entries
      let nm = '';
      if (strx && symtab.stroff + strx < strEnd) nm = src.cstr(symtab.stroff + strx, Math.min(L.maxString, strEnd - symtab.stroff - strx));
      if (!nm) continue;
      const ext = !!(type & 1);
      const t = type & 0x0e;
      const tName = { 0: 'undefined', 2: 'absolute', 0xe: 'section', 0xc: 'prebound', 0xa: 'indirect' }[t] || hex(t);
      const lib = t === 0 && ext ? libOf(desc) : '';
      if (!m.row(symT, [nm, hex(value), tName, sect, ext ? (type & 0x10 ? 'private extern' : 'yes') : 'no', lib])) break;
      if (t === 0 && ext) m.row(impT, [nm, lib, desc & 0x80 ? 'weak' : '']);
      else if (t === 0xe && ext && !(type & 0x10)) defined.push([nm, value]);
    }
  });

  // ---- exports: the trie when there is one, else the defined external symbols ----
  m.part('Exports', () => {
    const trie = linkedit[0x80000033] ? { off: linkedit[0x80000033].dataoff, size: linkedit[0x80000033].datasize } : linkedit.dyld && linkedit.dyld.exportSize ? { off: linkedit.dyld.exportOff, size: linkedit.dyld.exportSize } : null;
    if (trie && trie.size) {
      const start = trie.off, end = Math.min(src.size, trie.off + trie.size);
      if (start >= src.size) { m.warn(`Export trie: offset ${hex(start)} is past the end of the data.`); return; }
      const seen = new Set();
      const stack = [[0, '']];
      let loops = 0;
      while (stack.length && m.budget.ok()) {
        const [node, prefix] = stack.pop();
        const at = start + node;
        if (seen.has(at)) { loops++; continue; }
        seen.add(at);
        if (at >= end) { m.warn('Export trie: a node offset points past the trie.'); continue; }
        const t = uleb(src, at, end);
        let p = at + t.len;
        const termSize = safe(t.value) ?? 0;
        if (termSize) {
          const q = p;
          const fl = uleb(src, q, end);
          const flags = safe(fl.value) ?? 0;
          let r = q + fl.len;
          if (flags & 0x8) {
            const ord = uleb(src, r, end); r += ord.len;
            const imp = src.cstr(r, Math.min(L.maxString, Math.max(1, end - r)));
            if (!m.row(expT, [prefix, '', `re-export from ${dylibs[(safe(ord.value) || 1) - 1] || 'library'}${imp ? ` (${imp})` : ''}`])) break;
          } else {
            const addr = uleb(src, r, end);
            const kinds = [flags & 0x3 ? (flags & 0x3) === 1 ? 'thread local' : 'absolute' : 'regular'];
            if (flags & 0x4) kinds.push('weak');
            if (flags & 0x10) kinds.push('stub and resolver');
            if (!m.row(expT, [prefix, hex(addr.value), kinds.join(', ')])) break;
          }
          p = q + termSize;
        }
        if (p >= end) continue;
        const kids = src.u8(p); p++;
        const children = [];
        for (let k = 0; k < kids && p < end; k++) {
          const label = src.cstr(p, Math.min(L.maxString, end - p));
          p += Buffer.byteLength(label) + 1;
          const child = uleb(src, p, end); p += child.len;
          if (prefix.length + label.length > L.maxString) { m.warn('Export trie: a name is longer than 4096 characters; that branch is skipped.'); continue; }
          children.push([safe(child.value) ?? -1, prefix + label]);
        }
        for (let k = children.length - 1; k >= 0; k--) if (children[k][0] >= 0) stack.push(children[k]);
        if (seen.size > 2 * L.maxRows) { m.warn('Export trie: too many nodes; reading stopped.'); break; }
      }
      if (loops) m.warn(`Export trie: ${loops} node link${loops === 1 ? '' : 's'} point back to a node already read (a loop); each node was read once.`);
    } else {
      for (const [nm, v] of defined) if (!m.row(expT, [nm, hex(v), 'symbol table'])) break;
    }
  });
  m.summary.push(['Segments', String(segT.rows.length)], ['Sections', String(secT.rows.length)], ['Imports', String(impT.rows.length)], ['Exports', String(expT.rows.length)]);
  return m.finish();
}

module.exports = { machoKind, parseFat, parseThin, cpuName, MAGICS };
