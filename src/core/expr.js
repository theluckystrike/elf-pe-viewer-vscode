'use strict';
// A small, safe expression language for binary templates. No eval, no Function, no property access
// outside the template's own values. Numbers are JS numbers (u64 values above 2^53 lose precision in
// expressions; they still show exactly in the tree). Supported:
//   literals 12, 0x1F, 0b101, 'text', "text", true, false
//   names a, a.b, a[2], a.length, parent.x, root.x, _ (the current element of an array loop)
//   + - * / % (integer division with //), << >> >>> & | ^ ~, == != < <= > >=, && || !, ?: and (...)
//   functions: min max abs align(x, n) pos() size() start() end() str(x) hex(x) len(x) defined(x)
//              u8(off) u16(off) u32(off) (current byte order), u16le u16be u32le u32be: peek at file bytes
// Every evaluation has a step budget, so a hostile template cannot hang the extension host.

const FUNCS = new Set(['min', 'max', 'abs', 'align', 'pos', 'size', 'start', 'end', 'str', 'hex', 'len', 'defined', 'oct',
  'u8', 'u16', 'u32', 'u16le', 'u16be', 'u32le', 'u32be']);
const PEEKS = new Set(['u8', 'u16', 'u32', 'u16le', 'u16be', 'u32le', 'u32be']);
const MAX_LEN = 2000;
const MAX_STEPS = 20000;

class ExprError extends Error {}

function tokenize(src) {
  if (typeof src !== 'string') throw new ExprError('An expression must be text.');
  if (src.length > MAX_LEN) throw new ExprError(`An expression is longer than ${MAX_LEN} characters.`);
  const out = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    let m;
    const rest = src.slice(i);
    if ((m = /^0x[0-9a-f_]+|^0b[01_]+|^\d[\d_]*(\.\d+)?(e[+-]?\d+)?/i.exec(rest))) {
      const t = m[0].replace(/_/g, '');
      const v = /^0b/i.test(t) ? parseInt(t.slice(2), 2) : Number(t);
      if (!Number.isFinite(v)) throw new ExprError(`Bad number ${m[0]}.`);
      out.push({ t: 'num', v }); i += m[0].length; continue;
    }
    if ((m = /^[A-Za-z_$][\w$]*/.exec(rest))) { out.push({ t: 'id', v: m[0] }); i += m[0].length; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1, s = '';
      while (j < src.length && src[j] !== c) { if (src[j] === '\\' && j + 1 < src.length) { j++; s += src[j] === 'n' ? '\n' : src[j]; } else s += src[j]; j++; }
      if (j >= src.length) throw new ExprError('A text in quotes has no closing quote.');
      out.push({ t: 'str', v: s }); i = j + 1; continue;
    }
    if ((m = /^(>>>|<<|>>|<=|>=|==|!=|&&|\|\||\/\/|[-+*/%<>&|^~!?:().,[\]])/.exec(rest))) { out.push({ t: 'op', v: m[0] }); i += m[0].length; continue; }
    throw new ExprError(`Unexpected character "${c}" in ${src}`);
  }
  out.push({ t: 'end' });
  return out;
}

// Precedence climbing parser to a small AST.
const BIN = [
  ['||'], ['&&'], ['|'], ['^'], ['&'], ['==', '!='], ['<', '<=', '>', '>='], ['<<', '>>', '>>>'], ['+', '-'], ['*', '/', '//', '%'],
];

function parse(src) {
  const toks = tokenize(src);
  let p = 0;
  const peek = () => toks[p];
  const isOp = v => toks[p].t === 'op' && toks[p].v === v;
  const expect = v => { if (!isOp(v)) throw new ExprError(`Expected "${v}" in ${src}`); p++; };
  let depth = 0;
  const ternary = () => {
    if (++depth > 64) throw new ExprError('The expression is nested too deep.');
    const c = binary(0);
    if (isOp('?')) { p++; const a = ternary(); expect(':'); const b = ternary(); depth--; return { k: '?', c, a, b }; }
    depth--;
    return c;
  };
  const binary = lvl => {
    if (lvl >= BIN.length) return unary();
    let l = binary(lvl + 1);
    while (toks[p].t === 'op' && BIN[lvl].includes(toks[p].v)) { const op = toks[p++].v; const r = binary(lvl + 1); l = { k: 'bin', op, l, r }; }
    return l;
  };
  const unary = () => {
    if (isOp('-') || isOp('!') || isOp('~') || isOp('+')) { const op = toks[p++].v; return { k: 'un', op, x: unary() }; }
    return postfix(primary());
  };
  const primary = () => {
    const t = peek();
    if (t.t === 'num' || t.t === 'str') { p++; return { k: 'lit', v: t.v }; }
    if (t.t === 'id') {
      p++;
      if (t.v === 'true') return { k: 'lit', v: true };
      if (t.v === 'false') return { k: 'lit', v: false };
      if (isOp('(')) {
        if (!FUNCS.has(t.v)) throw new ExprError(`Unknown function ${t.v}().`);
        p++;
        const args = [];
        if (!isOp(')')) { args.push(ternary()); while (isOp(',')) { p++; args.push(ternary()); } }
        expect(')');
        return { k: 'call', f: t.v, args };
      }
      return { k: 'name', v: t.v };
    }
    if (isOp('(')) { p++; const e = ternary(); expect(')'); return e; }
    throw new ExprError(`Unexpected ${t.t === 'end' ? 'end' : '"' + t.v + '"'} in ${src}`);
  };
  const postfix = e => {
    for (;;) {
      if (isOp('.')) { p++; const t = peek(); if (t.t !== 'id') throw new ExprError(`Expected a name after "." in ${src}`); p++; e = { k: 'get', o: e, key: { k: 'lit', v: t.v } }; }
      else if (isOp('[')) { p++; const key = ternary(); expect(']'); e = { k: 'get', o: e, key }; }
      else return e;
    }
  };
  const ast = ternary();
  if (peek().t !== 'end') throw new ExprError(`Unexpected "${peek().v}" in ${src}`);
  return ast;
}

const cache = new Map();
function compile(src) {
  if (typeof src === 'number') return { k: 'lit', v: src };
  let a = cache.get(src);
  if (!a) { a = parse(src); if (cache.size > 5000) cache.clear(); cache.set(src, a); }
  return a;
}

const num = v => (typeof v === 'bigint' ? Number(v) : typeof v === 'boolean' ? (v ? 1 : 0) : v);
// A field value as stored in the tree: { value } for numbers and text, arrays and structs as nodes.
function unwrap(v) {
  if (v && typeof v === 'object' && v.__node) return v.kind === 'value' ? v.value : v;
  return v;
}

/**
 * Evaluate `src` in `scope`: { lookup(name), member(obj, key), pos(), size() }.
 * Returns a number, string, boolean or a node (struct/array) for member access.
 */
function evaluate(src, scope) {
  const ast = compile(src);
  let steps = 0;
  // raw(): a name or member access without unwrapping, so value fields keep .offset and .size
  const raw = n => {
    if (n.k === 'name') return scope.lookup(n.v);
    if (n.k === 'get') { const o = raw(n.o); const key = ev(n.key); return scope.member(o, key); }
    return ev(n);
  };
  const ev = n => {
    if (++steps > MAX_STEPS) throw new ExprError('The expression took too many steps.');
    switch (n.k) {
      case 'lit': return n.v;
      case 'name': return unwrap(scope.lookup(n.v));
      case 'get': return unwrap(raw(n));
      case 'un': {
        const x = num(ev(n.x));
        if (n.op === '-') return -x; if (n.op === '+') return +x; if (n.op === '!') return !x;
        return Number(~BigInt.asIntN(64, BigInt(Math.trunc(x))));
      }
      case '?': return ev(n.c) ? ev(n.a) : ev(n.b);
      case 'bin': {
        if (n.op === '&&') { const l = ev(n.l); return l ? ev(n.r) : l; }
        if (n.op === '||') { const l = ev(n.l); return l ? l : ev(n.r); }
        let l = ev(n.l), r = ev(n.r);
        if (n.op === '==' || n.op === '!=') {
          const eq = (typeof l === 'string' || typeof r === 'string') ? String(num(l)) === String(num(r)) : num(l) === num(r);
          return n.op === '==' ? eq : !eq;
        }
        if (n.op === '+' && (typeof l === 'string' || typeof r === 'string')) return String(l) + String(r);
        if (BITS.has(n.op)) return bitop(n.op, l, r);
        l = num(l); r = num(r);
        if (typeof l !== 'number' || typeof r !== 'number') throw new ExprError(`"${n.op}" needs numbers.`);
        switch (n.op) {
          case '+': return l + r; case '-': return l - r; case '*': return l * r;
          case '/': if (r === 0) throw new ExprError('Division by zero.'); return l / r;
          case '//': if (r === 0) throw new ExprError('Division by zero.'); return Math.floor(l / r);
          case '%': if (r === 0) throw new ExprError('Division by zero.'); return l % r;
          case '<': return l < r; case '<=': return l <= r; case '>': return l > r; case '>=': return l >= r;
        }
        throw new ExprError(`Unknown operator ${n.op}.`);
      }
      case 'call': {
        const a = n.args.map(ev);
        if (PEEKS.has(n.f)) {
          const off = num(a[0]);
          if (!Number.isSafeInteger(off) || off < 0) throw new ExprError(`${n.f}() needs an offset of 0 or more.`);
          return scope.peek(n.f, off);
        }
        switch (n.f) {
          case 'min': return Math.min(...a.map(num));
          case 'max': return Math.max(...a.map(num));
          case 'abs': return Math.abs(num(a[0]));
          case 'align': { const x = num(a[0]), m = num(a[1]) || 1; return Math.ceil(x / m) * m; }
          case 'pos': return scope.pos();
          case 'size': return scope.size();
          case 'start': return scope.start ? scope.start() : 0;
          case 'end': return scope.end ? scope.end() : scope.size();
          case 'str': return String(a[0]);
          case 'hex': return '0x' + Math.trunc(num(a[0])).toString(16).toUpperCase();
          case 'len': return a[0] && typeof a[0] === 'object' && Array.isArray(a[0].children) ? a[0].children.length : String(a[0] == null ? '' : a[0]).length;
          case 'defined': return a[0] !== undefined && a[0] !== null;
          case 'oct': { const t = String(a[0] == null ? '' : a[0]).replace(/[\0\s]+/g, ''); return /^[0-7]+$/.test(t) ? parseInt(t, 8) : 0; }
        }
      }
    }
    throw new ExprError('Bad expression.');
  };
  return ev(ast);
}

// Bit operations on up to 64-bit unsigned values (JS bit operators are 32-bit). u64 fields come in as BigInt
// and stay exact; the result is a Number when it fits in 2^53, else a BigInt.
const BITS = new Set(['&', '|', '^', '<<', '>>', '>>>']);
const big = v => (typeof v === 'bigint' ? v : BigInt(Math.trunc(num(v)) || 0));
function bitop(op, l, r) {
  if ((typeof l !== 'number' && typeof l !== 'bigint' && typeof l !== 'boolean') || (typeof r !== 'number' && typeof r !== 'bigint' && typeof r !== 'boolean')) throw new ExprError(`"${op}" needs numbers.`);
  const L = BigInt.asUintN(64, big(l)), R = big(r);
  let v;
  switch (op) {
    case '&': v = L & BigInt.asUintN(64, R); break;
    case '|': v = L | BigInt.asUintN(64, R); break;
    case '^': v = L ^ BigInt.asUintN(64, R); break;
    case '<<': v = BigInt.asUintN(64, L << (R & 63n)); break;
    case '>>': case '>>>': v = L >> (R & 63n); break;
  }
  return v <= 9007199254740991n ? Number(v) : v;
}

module.exports = { evaluate, compile, tokenize, ExprError, MAX_STEPS };
