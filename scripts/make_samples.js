'use strict';
// Writes the 3 small walkthrough samples (an ELF shared object, a PE DLL, a Mach-O universal dylib) from the test
// builders. Run: node scripts/make_samples.js
const fs = require('fs');
const path = require('path');
const B = require('../test/build');
const out = path.join(__dirname, '..', 'samples');
fs.mkdirSync(out, { recursive: true });
const files = {
  'sample-libzovo.so': B.elf({ imports: [['printf', 0], ['malloc', 0], ['free', 0], ['strlen', 0], ['cos', 1], ['sqrt', 1]], exports: ['zovo_add', 'zovo_version', 'zovo_parse', 'zovo_free'] }),
  'sample-zovo.dll': B.pe(),
  'sample-zovo.dylib': B.fat([[0x0100000c, 0, B.macho()], [0x01000007, 3, B.macho()]]),
};
for (const [n, b] of Object.entries(files)) { fs.writeFileSync(path.join(out, n), b); console.log(n, b.length); }
