'use strict';
// Pro tool cores: JSON and C header export (the header is compiled with the system C compiler when there is one),
// compare, find.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const B = require('./build');
const { parseBuffer } = require('../src/core');
const T = require('../src/core/tools');

test('JSON export: tables as objects, slices of a universal binary, valid JSON', () => {
  const j = JSON.parse(T.toJson(parseBuffer(B.elf()), 'libzovo.so'));
  assert.strictEqual(j.file, 'libzovo.so');
  assert.strictEqual(j.format, 'ELF');
  assert.deepStrictEqual(j.tables.imports[2], { Name: 'cos', Library: 'libm.so.6', Version: 'GLIBC_2.29', Type: 'FUNC', Bind: 'GLOBAL' });
  assert.strictEqual(j.summary.SONAME, 'libzovo.so.1');
  const f = JSON.parse(T.toJson(parseBuffer(B.fat([[0x0100000c, 0, B.macho()], [0x01000007, 3, B.macho()]])), 'u'));
  assert.deepStrictEqual(f.slices.map((s) => s.architecture), ['ARM64', 'x86-64']);
  assert.strictEqual(f.slices[1].tables.exports[0].Name, '_zovo_add');
});

test('C header export compiles (cc -fsyntax-only) for ELF, PE, Mach-O and universal files', (t) => {
  const cc = spawnSync('cc', ['--version']);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'elfpe-ch-'));
  try {
    const samples = { 'lib zovo.so.1': B.elf(), 'zovo.dll': B.pe({ is64: false }), 'libzovo.dylib': B.macho(), 'tool': B.fat([[0x0100000c, 2, B.macho()], [0x01000007, 3, B.macho()]]) };
    for (const [name, buf] of Object.entries(samples)) {
      const h = T.toCHeader(parseBuffer(buf), name);
      assert.match(h, /#ifndef [A-Z0-9_]+_STRUCTURE_H/);
      assert.match(h, /static const [a-z0-9_]+_imports_t [a-z0-9_]+_imports\[\d+\] = \{/);
      if (cc.status !== 0) continue;
      const file = path.join(dir, name.replace(/\W+/g, '_') + '.h');
      fs.writeFileSync(file, h);
      const r = spawnSync('cc', ['-fsyntax-only', '-Wall', '-Wno-unused-const-variable', '-x', 'c', file], { encoding: 'utf8' });
      assert.strictEqual(r.status, 0, `${name}: ${r.stderr}`);
    }
    if (cc.status !== 0) t.diagnostic('no C compiler: syntax check skipped');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('C header escapes quotes, backslashes, trigraphs and comment ends in names', () => {
  const m = parseBuffer(B.elf({ exports: ['a"b\\c??=d', 'x*/y'] }));
  const h = T.toCHeader(m, 'evil.so');
  assert.ok(h.includes('"a\\"b\\\\c?\\?=d"'));
  assert.ok(!/x\*\/y/.test(h.replace(/"x\*\/y"/g, '')), 'a */ outside a string would end a comment');
});

test('compare: added and removed imports, exports and libraries; header differences', () => {
  const a = parseBuffer(B.elf());
  const b = parseBuffer(B.elf({ imports: [['printf', 0], ['free', 0]], exports: ['zovo_add', 'zovo_sub'], needed: ['libc.so.6'] }));
  const r = T.compareModels(a, b);
  const t = (id) => r.tables.find((x) => x.id === id);
  assert.deepStrictEqual(t('imports').added, ['libc.so.6 \u2192 free']);
  assert.deepStrictEqual(t('imports').removed.sort(), ['libc.so.6 \u2192 malloc', 'libm.so.6 \u2192 cos']);
  assert.deepStrictEqual(t('exports').added, ['zovo_sub']);
  assert.deepStrictEqual(t('exports').removed, ['zovo_version']);
  assert.deepStrictEqual(t('libraries').removed, ['libm.so.6']);
  assert.ok(r.header.some((h) => h.name === 'Imports'));
  const md = T.compareMarkdown(r, 'a.so', 'b.so');
  assert.match(md, /^# a\.so compared with b\.so/);
  assert.match(md, /Added in B:\n\n- libc\.so\.6 → free/);
});

test('compare: PE32 against PE32+ shows the machine and format change, the same imports', () => {
  const r = T.compareModels(parseBuffer(B.pe({ is64: false })), parseBuffer(B.pe()));
  assert.ok(r.header.some((h) => h.name === 'Machine' && /x86/.test(h.a) && /x64/.test(h.b)));
  const imp = r.tables.find((x) => x.id === 'imports');
  assert.deepStrictEqual([imp.added.length, imp.removed.length, imp.same], [0, 0, 3]);
});

test('find: plain text is a case-insensitive substring, /regex/ works, nested repeats are refused', () => {
  const m = parseBuffer(B.pe());
  assert.deepStrictEqual(T.findInModel(m, T.matcher('getproc')).map((h) => [h.kind, h.name, h.library]), [['import', 'GetProcAddress', 'KERNEL32.dll']]);
  assert.deepStrictEqual(T.findInModel(m, T.matcher('/^zovo_/')).map((h) => h.name), ['zovo_add', 'zovo_version']);
  assert.deepStrictEqual(T.findInModel(m, T.matcher('ws2_32')).map((h) => [h.kind, h.name]), [['library', 'WS2_32.dll']]);
  assert.throws(() => T.matcher('/(a+)+$/'), /repeated group inside a repeat/);
  assert.strictEqual(T.matcher('   '), null);
  const x = parseBuffer(B.fat([[0x0100000c, 0, B.macho()], [0x01000007, 3, B.macho()]]));
  assert.deepStrictEqual(T.findInModel(x, T.matcher('inflate')).map((h) => [h.arch, h.kind, h.library]), [['ARM64', 'import', '/usr/lib/libz.1.dylib'], ['x86-64', 'import', '/usr/lib/libz.1.dylib']]);
});
