'use strict';
// Parser tests with bytes built in the test (test/build.js). No fixture files, no network.
const test = require('node:test');
const assert = require('node:assert');
const B = require('./build');
const { parseBuffer, detect } = require('../src/core');
const { Source } = require('../src/core/source');

const tbl = (m, id) => (m.tables.find((t) => t.id === id) || { rows: [] });
const col = (m, id, name) => { const t = tbl(m, id); const i = t.columns ? t.columns.findIndex((c) => c.n === name) : -1; return t.rows.map((r) => r[i]); };
const sum = (m, k) => (m.summary.find((s) => s[0] === k) || [])[1];

for (const [is64, le] of [[true, true], [false, true], [true, false], [false, false]]) {
  test(`ELF${is64 ? 64 : 32} ${le ? 'LE' : 'BE'}: header, sections, segments, imports with library and version, exports, build id`, () => {
    const m = parseBuffer(B.elf({ is64, le }));
    assert.strictEqual(m.format, 'ELF');
    assert.match(m.title, new RegExp(`ELF ${is64 ? 64 : 32}-bit ${le ? 'LSB' : 'MSB'} shared object`));
    assert.deepStrictEqual(m.warnings, []);
    assert.deepStrictEqual(col(m, 'sections', 'Name'), ['', '.interp', '.note.gnu.build-id', '.dynsym', '.text', '.dynstr', '.gnu.version', '.gnu.version_r', '.dynamic', '.symtab', '.strtab', '.shstrtab']);
    assert.deepStrictEqual(col(m, 'segments', 'Type'), ['LOAD', 'DYNAMIC', 'INTERP', 'NOTE']);
    assert.deepStrictEqual(tbl(m, 'imports').rows.map((r) => [r[0], r[1], r[2]]), [['printf', 'libc.so.6', 'GLIBC_2.2.5'], ['malloc', 'libc.so.6', 'GLIBC_2.2.5'], ['cos', 'libm.so.6', 'GLIBC_2.29']]);
    assert.deepStrictEqual(col(m, 'exports', 'Name'), ['zovo_add', 'zovo_version']);
    assert.deepStrictEqual(col(m, 'libraries', 'Library'), ['libc.so.6', 'libm.so.6']);
    assert.strictEqual(sum(m, 'SONAME'), 'libzovo.so.1');
    assert.strictEqual(sum(m, 'Interpreter'), '/lib64/ld-linux-x86-64.so.2');
    assert.strictEqual(sum(m, 'Build ID'), '00112233445566778899aabbccddeeff01234567');
    assert.ok(col(m, 'symbols', 'Name').includes('local_helper'));
    // every span is inside the file
    for (const t of m.tables) for (const s of t.spans) if (s) assert.ok(s[0] >= 0 && s[0] + s[1] <= B.elf({ is64, le }).length, `${t.id} span`);
  });
}

test('PE32+ and PE32 DLL: sections, imports by name and ordinal, exports with a forwarder', () => {
  for (const is64 of [true, false]) {
    const m = parseBuffer(B.pe({ is64 }));
    assert.strictEqual(m.format, 'PE');
    assert.match(m.title, is64 ? /^PE32\+ DLL, x64/ : /^PE32 DLL, x86/);
    assert.deepStrictEqual(m.warnings, []);
    assert.deepStrictEqual(col(m, 'sections', 'Name'), ['.text', '.rdata']);
    assert.deepStrictEqual(tbl(m, 'imports').rows.map((r) => [r[0], r[1], r[2]]), [['GetProcAddress', 'KERNEL32.dll', ''], ['LoadLibraryW', 'KERNEL32.dll', ''], ['#23', 'WS2_32.dll', '23']]);
    assert.deepStrictEqual(tbl(m, 'exports').rows, [['zovo_add', 1, '0x1000', ''], ['zovo_version', 2, '0x1010', ''], ['ZeroMemory', 3, '0x24C0', 'NTDLL.RtlZeroMemory']]);
    assert.strictEqual(sum(m, 'Export name'), 'zovo.dll');
    assert.match(sum(m, 'Security flags'), /ASLR on, DEP on, Control Flow Guard, high-entropy ASLR/);
  }
});

test('Mach-O 64 dylib: load commands, libraries, imports with their library, exports from the trie', () => {
  const m = parseBuffer(B.macho());
  assert.strictEqual(m.format, 'Mach-O');
  assert.match(m.title, /^Mach-O 64-bit dynamic library, ARM64/);
  assert.deepStrictEqual(m.warnings, []);
  assert.deepStrictEqual(tbl(m, 'libraries').rows.map((r) => [r[0], r[1]]), [['/usr/lib/libSystem.B.dylib', 'load'], ['/usr/lib/libz.1.dylib', 'weak']]);
  assert.deepStrictEqual(tbl(m, 'imports').rows.map((r) => [r[0], r[1]]), [['_malloc', '/usr/lib/libSystem.B.dylib'], ['_inflate', '/usr/lib/libz.1.dylib']]);
  assert.deepStrictEqual(tbl(m, 'exports').rows.map((r) => [r[0], r[1]]), [['_zovo_add', '0x3F00'], ['_zovo_version', '0x3F10']]);
  assert.deepStrictEqual(col(m, 'sections', 'Section'), ['__text']);
  assert.strictEqual(sum(m, 'UUID'), '01234567-89AB-CDEF-0123-456789ABCDEF');
  assert.strictEqual(sum(m, 'Install name'), '@rpath/libzovo.dylib');
  assert.match(sum(m, 'Platform'), /^macOS, minimum 14\.0\.0, SDK 15\.0\.0$/);
});

test('Mach-O universal (fat): both slices read on their own', () => {
  const m = parseBuffer(B.fat([[0x0100000c, 2, B.macho()], [0x01000007, 3, B.macho()]]));
  assert.strictEqual(m.format, 'Mach-O universal');
  assert.deepStrictEqual(m.slices.map((s) => s.arch), ['ARM64e', 'x86-64']);
  for (const s of m.slices) assert.deepStrictEqual(col(s.model, 'exports', 'Name'), ['_zovo_add', '_zovo_version']);
  assert.deepStrictEqual(m.warnings, []);
});

test('detect: the three formats, and Java class files are not taken for universal binaries', () => {
  assert.strictEqual(detect(Source.fromBuffer(B.elf())), 'ELF');
  assert.strictEqual(detect(Source.fromBuffer(B.pe())), 'PE');
  assert.strictEqual(detect(Source.fromBuffer(B.macho())), 'Mach-O');
  assert.strictEqual(detect(Source.fromBuffer(Buffer.from('cafebabe00000034', 'hex'))), '');
  assert.throws(() => parseBuffer(Buffer.from('cafebabe00000034000000', 'hex')), /not an ELF, PE or Mach-O file: it looks like a Java class file/);
  assert.throws(() => parseBuffer(Buffer.alloc(0)), /it looks like an empty file/);
  assert.throws(() => parseBuffer(Buffer.from('!<arch>\n')), /static library archive/);
  assert.throws(() => parseBuffer(Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex')), /it looks like a PNG image/);
  assert.throws(() => parseBuffer(Buffer.from('0061736d01000000', 'hex')), /it looks like a WebAssembly module/);
});

// ---------- hostile files ----------

test('truncated headers: every prefix of each sample parses or fails with a message, never a crash', () => {
  const samples = { elf64: B.elf(), elf32be: B.elf({ is64: false, le: false }), pe64: B.pe(), pe32: B.pe({ is64: false }), macho: B.macho(), fat: B.fat([[0x0100000c, 0, B.macho()]]) };
  for (const [name, full] of Object.entries(samples)) {
    const step = Math.max(1, Math.floor(full.length / 400));
    for (let n = 0; n <= full.length; n += n < 128 ? 1 : step) {
      let m;
      try { m = parseBuffer(full.subarray(0, n)); } catch (e) { assert.ok(e.code === 'NOT_BINARY', `${name} cut at ${n}: ${e.stack}`); continue; }
      assert.ok(typeof m.title === 'string' && m.title.length, `${name} cut at ${n}: title`);
      for (const t of m.tables) for (const s of t.spans) if (s) assert.ok(s[0] >= 0 && s[0] + s[1] <= n, `${name} cut at ${n}: ${t.id} span ${s} past ${n}`);
    }
  }
});

test('truncated ELF header says how many bytes it needs', () => {
  const m = parseBuffer(B.elf().subarray(0, 40));
  assert.match(m.warnings.join(' '), /The ELF header needs 64 bytes; the file has 40/);
});

test('section and segment counts larger than the file are cut to what fits, with a warning', () => {
  const m = parseBuffer(B.elf({ shnum: 60000, phnum: 50000 }));
  assert.match(m.warnings.join(' '), /e_shnum says 60000, but only \d+ fit/);
  assert.match(m.warnings.join(' '), /e_phnum says 50000, but only \d+ fit/);
  const p = parseBuffer(B.pe({ nsec: 65535 }));
  assert.match(p.warnings.join(' '), /Section table: 65535 sections do not fit in the file/);
  const x = parseBuffer(B.macho({ ncmds: 0xffffffff }));
  assert.match(x.warnings.join(' '), /Load commands: 4294967295 commands; reading 8192/);
  const f = parseBuffer(B.fat([[0x0100000c, 0, B.macho()]], { nfat: 39 }));
  assert.ok(f.warnings.length > 0);
});

test('e_shoff past the end of the file', () => {
  const m = parseBuffer(B.elf({ shoff: 0x7fffffff }));
  assert.match(m.warnings.join(' '), /e_shoff 0x7FFFFFFF is past the end of the file/);
  assert.ok(tbl(m, 'segments').rows.length === 4, 'segments still read');
});

test('import loops: PE repeated descriptor and endless thunk list, Mach-O trie cycle, ELF verneed jump', () => {
  const t0 = Date.now();
  const p = parseBuffer(B.pe({ importLoop: true }));
  assert.match(p.warnings.join(' '), /listed twice with the same tables/);
  assert.ok(tbl(p, 'imports').rows.length <= 65536);
  const x = parseBuffer(B.macho({ trieLoop: true }));
  assert.match(x.warnings.join(' '), /a loop/);
  assert.deepStrictEqual(col(x, 'exports', 'Name'), ['_zovo_add']);
  const e = parseBuffer(B.elf({ loopVerneed: true }));
  assert.strictEqual(tbl(e, 'imports').rows.length, 3);
  assert.ok(Date.now() - t0 < 5000);
});

test('a load command with size 0 stops the command loop with a warning', () => {
  const m = parseBuffer(B.macho({ cmdsize0: true }));
  assert.match(m.warnings.join(' '), /has size 0, which is too small/);
});

test('export count of 4 billion is capped and the parse ends quickly', () => {
  const t0 = Date.now();
  const m = parseBuffer(B.pe({ numberOfFunctions: 0xffffffff }));
  assert.ok(Date.now() - t0 < 5000);
  assert.match(m.warnings.join(' '), /NumberOfFunctions is 4294967295/);
});

test('fuzz: 3,000 mutated files of each format never throw an unexpected error or hang', () => {
  let seed = 12345;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const bases = [B.elf(), B.elf({ is64: false, le: false }), B.pe(), B.pe({ is64: false }), B.macho(), B.fat([[0x0100000c, 0, B.macho()]])];
  const t0 = Date.now();
  for (const base of bases) {
    for (let k = 0; k < 500; k++) {
      const b = Buffer.from(base);
      const flips = 1 + rnd(16);
      for (let j = 0; j < flips; j++) {
        const at = rnd(Math.min(b.length, j % 2 ? b.length : 512));
        b[at] = rnd(4) === 0 ? 0xff : rnd(256);
      }
      const t1 = Date.now();
      try { parseBuffer(b, { maxMs: 2000 }); } catch (e) { assert.strictEqual(e.code, 'NOT_BINARY', e.stack); }
      assert.ok(Date.now() - t1 < 3000, 'one file took more than 3 s');
    }
  }
  assert.ok(Date.now() - t0 < 60000);
});

test('names with control characters are shown escaped', () => {
  const b = Buffer.from(B.pe());
  const at = b.indexOf(Buffer.from('zovo_add\0'));
  b[at + 4] = 0x1b;
  const m = parseBuffer(b);
  assert.ok(col(m, 'exports', 'Name').includes('zovo\\x1badd'));
});
