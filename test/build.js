'use strict';
// Builds small, valid ELF, PE and Mach-O files byte by byte for the tests (no fixture files). Each builder returns
// a Buffer and takes options to make the hostile variants (cut files, huge counts, loops).

class W {
  constructor(le = true) { this.le = le; this.b = Buffer.alloc(0); }
  get pos() { return this.b.length; }
  grow(n) { this.b = Buffer.concat([this.b, Buffer.alloc(n)]); }
  at(off, n) { if (off + n > this.b.length) this.grow(off + n - this.b.length); }
  u8(off, v) { this.at(off, 1); this.b[off] = v & 0xff; }
  u16(off, v) { this.at(off, 2); this.le ? this.b.writeUInt16LE(v & 0xffff, off) : this.b.writeUInt16BE(v & 0xffff, off); }
  u32(off, v) { this.at(off, 4); this.le ? this.b.writeUInt32LE(v >>> 0, off) : this.b.writeUInt32BE(v >>> 0, off); }
  u64(off, v) { this.at(off, 8); this.le ? this.b.writeBigUInt64LE(BigInt(v), off) : this.b.writeBigUInt64BE(BigInt(v), off); }
  word(off, v, is64) { is64 ? this.u64(off, v) : this.u32(off, Number(v)); }
  bytes(off, buf) { this.at(off, buf.length); Buffer.from(buf).copy(this.b, off); }
  str(off, s) { this.bytes(off, Buffer.from(s + '\0', 'utf8')); }
  align(n) { const p = Math.ceil(this.pos / n) * n; if (p > this.pos) this.grow(p - this.pos); return p; }
}

class StrTab {
  constructor() { this.buf = [0]; this.map = new Map([['', 0]]); }
  add(s) { if (this.map.has(s)) return this.map.get(s); const o = this.buf.length; this.buf.push(...Buffer.from(s, 'utf8'), 0); this.map.set(s, o); return o; }
  get bytes() { return Buffer.from(this.buf); }
}

/**
 * ELF shared object: .text, .dynsym/.dynstr, .gnu.version(_r), .dynamic, .symtab/.strtab, .note.gnu.build-id, .shstrtab.
 * opts: { is64, le, machine, imports: [[name, libIndex]], exports: [name], needed: [lib], loopVerneed, shnum (override), cut }
 */
function elf(opts = {}) {
  const is64 = opts.is64 !== false, le = opts.le !== false;
  const w = new W(le);
  const W8 = is64 ? 8 : 4;
  const needed = opts.needed || ['libc.so.6', 'libm.so.6'];
  const imports = opts.imports || [['printf', 0], ['malloc', 0], ['cos', 1]];
  const exports = opts.exports || ['zovo_add', 'zovo_version'];
  const ehsize = is64 ? 64 : 52, phsz = is64 ? 56 : 32, shsz = is64 ? 64 : 40, symsz = is64 ? 24 : 16;
  // layout
  const phoff = ehsize, phnum = 4;
  let off = phoff + phnum * phsz;
  const interp = '/lib64/ld-linux-x86-64.so.2';
  const interpOff = off; w.str(off, interp); off = w.align(8);
  const noteOff = off; // GNU build id
  w.u32(off, 4); w.u32(off + 4, 20); w.u32(off + 8, 3); w.str(off + 12, 'GNU'); w.bytes(off + 16, Buffer.from('00112233445566778899aabbccddeeff01234567', 'hex'));
  const noteSize = 36; off = w.align(8);
  const textOff = off; w.bytes(off, Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3, 0x90, 0x90, 0x90])); off = w.align(8);
  const dynstr = new StrTab();
  const libOffs = needed.map((l) => dynstr.add(l));
  const soname = dynstr.add('libzovo.so.1');
  const verNames = needed.map((l, i) => dynstr.add(i === 0 ? 'GLIBC_2.2.5' : 'GLIBC_2.29'));
  const dsyms = [{ name: 0, info: 0, shndx: 0, value: 0 }];
  for (const [n] of imports) dsyms.push({ name: dynstr.add(n), info: (1 << 4) | 2, shndx: 0, value: 0 });
  exports.forEach((n, i) => dsyms.push({ name: dynstr.add(n), info: (1 << 4) | 2, shndx: 4, value: 0x1000 + i * 16, size: 16 }));
  const dynstrOff = off; w.bytes(off, dynstr.bytes); off = w.align(8);
  const dynsymOff = off;
  dsyms.forEach((s, i) => {
    const b = dynsymOff + i * symsz;
    if (is64) { w.u32(b, s.name); w.u8(b + 4, s.info); w.u8(b + 5, 0); w.u16(b + 6, s.shndx); w.u64(b + 8, s.value); w.u64(b + 16, s.size || 0); }
    else { w.u32(b, s.name); w.u32(b + 4, s.value); w.u32(b + 8, s.size || 0); w.u8(b + 12, s.info); w.u8(b + 13, 0); w.u16(b + 14, s.shndx); }
  });
  off = w.align(8);
  const versymOff = off;
  dsyms.forEach((s, i) => { const imp = i >= 1 && i <= imports.length ? imports[i - 1] : null; w.u16(versymOff + i * 2, imp ? 2 + imp[1] : i === 0 ? 0 : 1); });
  off = w.align(8);
  // verneed: one entry per needed library, one aux each (version index 2 + i)
  const verneedOff = off;
  needed.forEach((l, i) => {
    const b = verneedOff + i * 32;
    w.u16(b, 1); w.u16(b + 2, 1); w.u32(b + 4, libOffs[i]); w.u32(b + 8, 16);
    // vn_next is unsigned: a hostile value can only jump far ahead (0xFFFFFFE0), never back.
    w.u32(b + 12, i < needed.length - 1 ? 32 : opts.loopVerneed ? 0xffffffe0 : 0);
    const a = b + 16;
    w.u32(a, 0x0d696914); w.u16(a + 4, 0); w.u16(a + 6, 2 + i); w.u32(a + 8, verNames[i]); w.u32(a + 12, 0);
  });
  off = verneedOff + needed.length * 32; off = w.align(8);
  const dynOff = off;
  const dyn = [...libOffs.map((o) => [1, o]), [14, soname], [5, 0x2000], [10, dynstr.bytes.length], [0x6ffffffb, 0x8000001], [0, 0]];
  dyn.forEach(([t, v], i) => { w.word(dynOff + i * 2 * W8, t, is64); w.word(dynOff + i * 2 * W8 + W8, v, is64); });
  const dynSize = dyn.length * 2 * W8; off = dynOff + dynSize; off = w.align(8);
  // .symtab with a local and the exports
  const strtab = new StrTab();
  const syms = [{ name: 0, info: 0, shndx: 0, value: 0 }, { name: strtab.add('local_helper'), info: 2, shndx: 4, value: 0x1040 }, { name: strtab.add('zovo.c'), info: 4, shndx: 0xfff1, value: 0 }];
  exports.forEach((n, i) => syms.push({ name: strtab.add(n), info: (1 << 4) | 2, shndx: 4, value: 0x1000 + i * 16, size: 16 }));
  const symtabOff = off;
  syms.forEach((s, i) => {
    const b = symtabOff + i * symsz;
    if (is64) { w.u32(b, s.name); w.u8(b + 4, s.info); w.u16(b + 6, s.shndx); w.u64(b + 8, s.value); w.u64(b + 16, s.size || 0); }
    else { w.u32(b, s.name); w.u32(b + 4, s.value); w.u32(b + 8, s.size || 0); w.u8(b + 12, s.info); w.u16(b + 14, s.shndx); }
  });
  off = symtabOff + syms.length * symsz;
  const strtabOff = off; w.bytes(off, strtab.bytes); off += strtab.bytes.length;
  const shstr = new StrTab();
  const secs = [
    ['', 0, 0, 0, 0, 0, 0, 0, 0],
    ['.interp', 1, 2, interpOff, interp.length + 1, 0, 0, 1, 0],
    ['.note.gnu.build-id', 7, 2, noteOff, noteSize, 0, 0, 4, 0],
    ['.dynsym', 11, 2, dynsymOff, dsyms.length * symsz, 5, 1, 8, symsz],
    ['.text', 1, 6, textOff, 8, 0, 0, 16, 0],
    ['.dynstr', 3, 2, dynstrOff, dynstr.bytes.length, 0, 0, 1, 0],
    ['.gnu.version', 0x6fffffff, 2, versymOff, dsyms.length * 2, 3, 0, 2, 2],
    ['.gnu.version_r', 0x6ffffffe, 2, verneedOff, needed.length * 32, 5, needed.length, 8, 0],
    ['.dynamic', 6, 3, dynOff, dynSize, 5, 0, 8, 2 * W8],
    ['.symtab', 2, 0, symtabOff, syms.length * symsz, 10, 3, 8, symsz],
    ['.strtab', 3, 0, strtabOff, strtab.bytes.length, 0, 0, 1, 0],
    ['.shstrtab', 3, 0, 0, 0, 0, 0, 1, 0],
  ];
  const nameOffs = secs.map((s) => shstr.add(s[0]));
  const shstrOff = off; w.bytes(off, shstr.bytes); off += shstr.bytes.length;
  secs[11][3] = shstrOff; secs[11][4] = shstr.bytes.length;
  off = w.align(8);
  const shoff = off;
  secs.forEach((s, i) => {
    const b = shoff + i * shsz;
    const [, type, flags, o, size, link, info, align, entsize] = s;
    w.u32(b, nameOffs[i]); w.u32(b + 4, type);
    if (is64) { w.u64(b + 8, flags); w.u64(b + 16, o ? 0x1000 + o : 0); w.u64(b + 24, o); w.u64(b + 32, size); w.u32(b + 40, link); w.u32(b + 44, info); w.u64(b + 48, align); w.u64(b + 56, entsize); }
    else { w.u32(b + 8, flags); w.u32(b + 12, o ? 0x1000 + o : 0); w.u32(b + 16, o); w.u32(b + 20, size); w.u32(b + 24, link); w.u32(b + 28, info); w.u32(b + 32, align); w.u32(b + 36, entsize); }
  });
  const end = shoff + secs.length * shsz;
  w.at(end, 0);
  // program headers: PHDR? LOAD, DYNAMIC, INTERP, NOTE
  const phs = [[1, 5, 0, 0, end], [2, 6, dynOff, 0x1000 + dynOff, dynSize], [3, 4, interpOff, 0x1000 + interpOff, interp.length + 1], [4, 4, noteOff, 0x1000 + noteOff, noteSize]];
  phs.forEach(([type, flags, o, va, sz], i) => {
    const b = phoff + i * phsz;
    if (is64) { w.u32(b, type); w.u32(b + 4, flags); w.u64(b + 8, o); w.u64(b + 16, va); w.u64(b + 24, va); w.u64(b + 32, sz); w.u64(b + 40, sz); w.u64(b + 48, 8); }
    else { w.u32(b, type); w.u32(b + 4, o); w.u32(b + 8, va); w.u32(b + 12, va); w.u32(b + 16, sz); w.u32(b + 20, sz); w.u32(b + 24, flags); w.u32(b + 28, 8); }
  });
  // header
  w.bytes(0, [0x7f, 0x45, 0x4c, 0x46, is64 ? 2 : 1, le ? 1 : 2, 1, 3]);
  w.u16(16, opts.type || 3); w.u16(18, opts.machine ?? (is64 ? 62 : 3)); w.u32(20, 1);
  w.word(24, 0x1000, is64); w.word(is64 ? 32 : 28, phoff, is64); w.word(is64 ? 40 : 32, opts.shoff ?? shoff, is64); w.u32(is64 ? 48 : 36, 0);
  w.u16(is64 ? 52 : 40, ehsize); w.u16(is64 ? 54 : 42, phsz); w.u16(is64 ? 56 : 44, opts.phnum ?? phnum);
  w.u16(is64 ? 58 : 46, shsz); w.u16(is64 ? 60 : 48, opts.shnum ?? secs.length); w.u16(is64 ? 62 : 50, 11);
  return opts.cut ? w.b.subarray(0, opts.cut) : w.b;
}

/**
 * PE DLL: .text, .rdata with an import directory (KERNEL32.dll by name, WS2_32.dll by ordinal) and an export directory
 * (2 named functions, one forwarder). opts: { is64, cut, nsec, importLoop, numberOfFunctions }
 */
function pe(opts = {}) {
  const is64 = opts.is64 !== false;
  const w = new W(true);
  const lfanew = 0x80;
  w.bytes(0, [0x4d, 0x5a]); w.u32(0x3c, lfanew);
  w.bytes(lfanew, [0x50, 0x45, 0, 0]);
  const c = lfanew + 4;
  const optSize = is64 ? 240 : 224;
  w.u16(c, is64 ? 0x8664 : 0x14c); w.u16(c + 2, opts.nsec ?? 2); w.u32(c + 4, 1700000000); w.u16(c + 16, optSize); w.u16(c + 18, 0x2022);
  const o = c + 20;
  w.u16(o, is64 ? 0x20b : 0x10b); w.u8(o + 2, 14); w.u8(o + 3, 38);
  w.u32(o + 16, 0x1000); w.u32(o + 20, 0x1000);
  if (is64) w.u64(o + 24, 0x180000000n); else w.u32(o + 28, 0x10000000);
  w.u32(o + 32, 0x1000); w.u32(o + 36, 0x200); w.u16(o + 40, 6); w.u16(o + 48, 6); w.u32(o + 56, 0x3000); w.u32(o + 60, 0x400);
  w.u16(o + 68, 2); w.u16(o + 70, 0x4160);
  const nd = o + (is64 ? 108 : 92);
  w.u32(nd, 16);
  const dirAt = (i) => nd + 4 + i * 8;
  const sec = o + optSize;
  const sections = [['.text', 0x1000, 0x200, 0x400, 0x200, 0x60000020], ['.rdata', 0x2000, 0x1000, 0x600, 0x1000, 0x40000040]];
  sections.forEach(([n, va, vs, raw, rs, ch], i) => { const b = sec + i * 40; w.bytes(b, Buffer.from(n)); w.u32(b + 8, vs); w.u32(b + 12, va); w.u32(b + 16, rs); w.u32(b + 20, raw); w.u32(b + 36, ch); });
  w.at(0x1600, 0);
  w.bytes(0x400, [0xc3]);
  // .rdata at RVA 0x2000, file 0x600
  const R = (rva) => 0x600 + (rva - 0x2000);
  const T = is64 ? 8 : 4;
  // import descriptors at 0x2000: KERNEL32 (by name), WS2_32 (ordinal 23), terminator
  const idt = 0x2000;
  const int1 = 0x2100, int2 = 0x2140, iat1 = 0x2180, iat2 = 0x21c0;
  const names = { k32: 0x2200, ws2: 0x2210, f1: 0x2220, f2: 0x2240 };
  w.u32(R(idt), int1); w.u32(R(idt) + 12, names.k32); w.u32(R(idt) + 16, iat1);
  w.u32(R(idt) + 20, opts.importLoop ? int1 : int2); w.u32(R(idt) + 32, opts.importLoop ? names.k32 : names.ws2); w.u32(R(idt) + 36, opts.importLoop ? iat1 : iat2);
  if (opts.importLoop) {
    // The second descriptor repeats the first, and the name table never ends inside the section (no zero thunk).
    for (let i = 0; i < 0x1000 / T; i++) is64 ? w.u64(R(int1) + i * T, BigInt(names.f1)) : w.u32(R(int1) + i * T, names.f1);
  } else {
    is64 ? (w.u64(R(int1), BigInt(names.f1)), w.u64(R(int1) + 8, BigInt(names.f2))) : (w.u32(R(int1), names.f1), w.u32(R(int1) + 4, names.f2));
    is64 ? w.u64(R(int2), (1n << 63n) | 23n) : w.u32(R(int2), 0x80000017);
  }
  w.str(R(names.k32), 'KERNEL32.dll'); w.str(R(names.ws2), 'WS2_32.dll');
  w.u16(R(names.f1), 0x2a); w.str(R(names.f1) + 2, 'GetProcAddress'); w.u16(R(names.f2), 0x1b); w.str(R(names.f2) + 2, 'LoadLibraryW');
  w.u32(dirAt(1), idt); w.u32(dirAt(1) + 4, 60);
  // export directory at 0x2400
  const ed = 0x2400, eat = 0x2440, enpt = 0x2460, eot = 0x2480, en = 0x24a0;
  const nfun = opts.numberOfFunctions ?? 3;
  w.u32(R(ed) + 12, en); w.u32(R(ed) + 16, 1); w.u32(R(ed) + 20, nfun); w.u32(R(ed) + 24, 3); w.u32(R(ed) + 28, eat); w.u32(R(ed) + 32, enpt); w.u32(R(ed) + 36, eot);
  w.u32(R(eat), 0x1000); w.u32(R(eat) + 4, 0x1010); w.u32(R(eat) + 8, 0x24c0);
  w.u32(R(enpt), 0x2500); w.u32(R(enpt) + 4, 0x2510); w.u32(R(enpt) + 8, 0x2520);
  w.u16(R(eot), 0); w.u16(R(eot) + 2, 1); w.u16(R(eot) + 4, 2);
  w.str(R(en), 'zovo.dll'); w.str(R(0x24c0), 'NTDLL.RtlZeroMemory');
  w.str(R(0x2500), 'zovo_add'); w.str(R(0x2510), 'zovo_version'); w.str(R(0x2520), 'ZeroMemory');
  w.u32(dirAt(0), ed); w.u32(dirAt(0) + 4, 0x100);
  return opts.cut ? w.b.subarray(0, opts.cut) : w.b;
}

function uleb(v) { const out = []; do { let b = v & 0x7f; v = Math.floor(v / 128); if (v) b |= 0x80; out.push(b); } while (v); return out; }

/**
 * Mach-O 64-bit dylib: __TEXT (__text), __LINKEDIT, LC_ID_DYLIB, two LC_LOAD_DYLIB, LC_UUID, LC_BUILD_VERSION,
 * LC_SYMTAB (2 imports, 1 export), LC_DYLD_EXPORTS_TRIE. opts: { be, trieLoop, ncmds, cmdsize0, cut }
 */
function macho(opts = {}) {
  const le = !opts.be;
  const w = new W(le);
  const cmds = [];
  const cmdArea = 32;
  let off = cmdArea;
  const add = (fn, size) => { cmds.push([off, size]); fn(off); off += size; };
  // LC_SEGMENT_64 __TEXT with one section
  add((b) => { w.u32(b, 0x19); w.u32(b + 4, 72 + 80); w.bytes(b + 8, Buffer.from('__TEXT')); w.u64(b + 24, 0); w.u64(b + 32, 0x4000); w.u64(b + 40, 0); w.u64(b + 48, 0x4000); w.u32(b + 56, 5); w.u32(b + 60, 5); w.u32(b + 64, 1);
    const s = b + 72; w.bytes(s, Buffer.from('__text')); w.bytes(s + 16, Buffer.from('__TEXT')); w.u64(s + 32, 0x3f00); w.u64(s + 40, 0x10); w.u32(s + 48, 0x3f00); w.u32(s + 52, 4); w.u32(s + 64, 0x80000400); }, 152);
  add((b) => { w.u32(b, 0x19); w.u32(b + 4, 72); w.bytes(b + 8, Buffer.from('__LINKEDIT')); w.u64(b + 24, 0x4000); w.u64(b + 32, 0x1000); w.u64(b + 40, 0x4000); w.u64(b + 48, 0x200); w.u32(b + 56, 1); w.u32(b + 60, 1); }, 72);
  const dylib = (cmd, name) => (b) => { w.u32(b, cmd); w.u32(b + 4, 24 + Math.ceil((name.length + 1) / 8) * 8); w.u32(b + 8, 24); w.u32(b + 12, 2); w.u32(b + 16, 0x10000); w.u32(b + 20, 0x10000); w.str(b + 24, name); };
  const dsz = (name) => 24 + Math.ceil((name.length + 1) / 8) * 8;
  add(dylib(0xd, '@rpath/libzovo.dylib'), dsz('@rpath/libzovo.dylib'));
  add(dylib(0xc, '/usr/lib/libSystem.B.dylib'), dsz('/usr/lib/libSystem.B.dylib'));
  add(dylib(0x80000018, '/usr/lib/libz.1.dylib'), dsz('/usr/lib/libz.1.dylib'));
  add((b) => { w.u32(b, 0x1b); w.u32(b + 4, 24); w.bytes(b + 8, Buffer.from('0123456789abcdef0123456789abcdef', 'hex')); }, 24);
  add((b) => { w.u32(b, 0x32); w.u32(b + 4, 24); w.u32(b + 8, 1); w.u32(b + 12, 0x0e0000); w.u32(b + 16, 0x0f0000); }, 24);
  let symtabCmd, trieCmd;
  add((b) => { symtabCmd = b; w.u32(b, 0x2); w.u32(b + 4, 24); }, 24);
  add((b) => { trieCmd = b; w.u32(b, 0x80000033); w.u32(b + 4, 16); }, 16);
  const sizeofcmds = off - cmdArea;
  // linkedit at 0x4000: symbols, strings, trie
  const L = 0x4000;
  const str = new StrTab();
  const syms = [[str.add('_malloc'), 0x01, 0, 1 << 8, 0], [str.add('_inflate'), 0x01, 0, 2 << 8, 0], [str.add('_zovo_add'), 0x0f, 1, 0, 0x3f00], [str.add('_local'), 0x0e, 1, 0, 0x3f08]];
  syms.forEach(([strx, type, sect, desc, value], i) => { const b = L + i * 16; w.u32(b, strx); w.u8(b + 4, type); w.u8(b + 5, sect); w.u16(b + 6, desc); w.u64(b + 8, value); });
  const strOff = L + syms.length * 16; w.bytes(strOff, str.bytes);
  const trieOff = Math.ceil((strOff + str.bytes.length) / 8) * 8;
  // trie: root -> "_zovo_" -> node A (terminal? no) -> "add" -> leaf ; and "_zovo_" -> "ver" leaf
  // node layout: [terminalSize][...][childCount][label\0][childOffset]...
  const root = [0, 1, ...Buffer.from('_zovo_'), 0];
  const nodeA = [0, 2, ...Buffer.from('add'), 0];
  const nodeAPos = root.length + 1;
  const nodeAFull = (leaf1, leaf2) => [...nodeA, leaf1, ...Buffer.from('version'), 0, leaf2];
  const leaf = (addr) => { const info = [0, ...uleb(addr)]; return [info.length, ...info, 0]; };
  const tmpA = nodeAFull(0, 0);
  const leaf1Pos = nodeAPos + tmpA.length, l1 = leaf(0x3f00), leaf2Pos = leaf1Pos + l1.length, l2 = leaf(0x3f10);
  let trie = [...root, nodeAPos, ...nodeAFull(leaf1Pos, leaf2Pos), ...l1, ...l2];
  if (opts.trieLoop) {
    // the "version" child points back to the root, which points to node A again: a loop
    trie = [...root, nodeAPos, ...nodeAFull(leaf1Pos, 0), ...l1, ...l2];
  }
  w.bytes(trieOff, Buffer.from(trie));
  w.u32(symtabCmd + 8, L); w.u32(symtabCmd + 12, syms.length); w.u32(symtabCmd + 16, strOff); w.u32(symtabCmd + 20, str.bytes.length);
  w.u32(trieCmd + 8, trieOff); w.u32(trieCmd + 12, trie.length);
  w.at(L + 0x200, 0);
  // header
  w.u32(0, 0xfeedfacf); w.u32(4, 0x0100000c); w.u32(8, 0); w.u32(12, 6); w.u32(16, opts.ncmds ?? cmds.length); w.u32(20, sizeofcmds); w.u32(24, 0x00100085);
  if (opts.cmdsize0) w.u32(cmds[1][0] + 4, 0);
  return opts.cut ? w.b.subarray(0, opts.cut) : w.b;
}

/** Universal binary of the given slices: [[cputype, cpusubtype, buffer]]. */
function fat(slices, opts = {}) {
  const w = new W(false);
  w.u32(0, 0xcafebabe); w.u32(4, opts.nfat ?? slices.length);
  let off = 0x1000;
  slices.forEach(([cpu, sub, buf], i) => {
    const b = 8 + i * 20;
    w.u32(b, cpu); w.u32(b + 4, sub); w.u32(b + 8, opts.badOffset && i === 1 ? 0x7fffffff : off); w.u32(b + 12, buf.length); w.u32(b + 16, 12);
    w.bytes(off, buf);
    off = Math.ceil((off + buf.length) / 0x1000) * 0x1000;
  });
  return w.b;
}

module.exports = { elf, pe, macho, fat, W };
