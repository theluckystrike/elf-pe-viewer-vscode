// ELF Viewer & PE Viewer webview. Every value is put on the page with textContent (never as HTML), so names from a
// hostile file stay text. Bytes come from the extension host on request; nothing here talks to the network.
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');
  const ROW_H = 22, HEX_ROW_H = 20, HEX_CHUNK = 4096, MAX_SPACER = 1000000;
  const S = { model: null, name: '', size: 0, tab: 'overview', slice: 0, filters: {}, sorts: {}, scroll: {}, hex: { top: 0, chunks: new Map(), pending: new Set(), mark: null }, compare: null, find: null, fields: null, pro: { show: true, tries: {} } };

  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    // Styles go through the CSSOM (style.setProperty): the CSP has no 'unsafe-inline', so a style attribute would be dropped.
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
      else if (k === 'style') { for (const decl of String(v).split(';')) { const i = decl.indexOf(':'); if (i > 0) e.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim()); } }
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  };
  const fmtInt = (n) => Number(n).toLocaleString('en-US');
  const fmtSize = (n) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`);
  const hex8 = (n) => n.toString(16).toUpperCase().padStart(8, '0');
  const cur = () => (S.model && S.model.slices && S.model.slices.length ? S.model.slices[S.slice].model : S.model);
  const post = (m) => vscode.postMessage(m);

  // ---------- frame ----------

  function frame(main) {
    app.textContent = '';
    const m = S.model, c = cur();
    const head = h('header', { class: 'top' },
      h('div', { class: 'title' }, h('span', { class: 'fname', text: S.name }), h('span', { class: 'desc', text: c ? `${c.title} · ${fmtSize(S.size)}` : '' })),
      h('div', { class: 'actions' },
        m && m.slices && m.slices.length ? h('select', { class: 'slice', title: 'Architecture of this universal binary', 'aria-label': 'Architecture', onchange: (e) => { S.slice = Number(e.target.value); post({ type: 'slice', index: S.slice }); S.fields = null; S.scroll = {}; render(); } },
          ...m.slices.map((s, i) => { const o = h('option', { value: String(i), text: s.arch }); if (i === S.slice) o.selected = true; return o; })) : null,
        S.pro.show && m ? proButtons() : null));
    const tabs = h('nav', { class: 'tabs', role: 'tablist' }, ...tabList().map(([id, label, count]) => h('button', {
      class: 'tab' + (S.tab === id ? ' on' : ''), role: 'tab', 'aria-selected': S.tab === id ? 'true' : 'false', 'data-tab': id,
      onclick: () => { S.tab = id; render(); },
    }, label, count !== undefined ? h('span', { class: 'count', text: fmtInt(count) }) : null)));
    const foot = document.getElementById('zovo-footer');
    app.append(head, tabs, h('main', { class: 'view', id: 'view' }, main), foot ? foot.content.cloneNode(true) : '');
  }

  function proButtons() {
    const tries = (f) => (S.pro.licensed ? 'Zovo Pro' : `Zovo Pro tool, ${S.pro.tries[f] ?? 3} free tr${(S.pro.tries[f] ?? 3) === 1 ? 'y' : 'ies'} left`);
    const menu = h('div', { class: 'menu', hidden: true },
      h('button', { text: 'As JSON', 'data-tool': 'exportJson', onclick: () => { menu.hidden = true; post({ type: 'tool', tool: 'exportJson' }); } }),
      h('button', { text: 'As C header', 'data-tool': 'exportC', onclick: () => { menu.hidden = true; post({ type: 'tool', tool: 'exportC' }); } }));
    const wrap = h('span', { class: 'drop' },
      h('button', { class: 'btn', 'data-tool': 'export', title: `Save the structure as JSON or a C header (${tries('export')})`, onclick: (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; } }, 'Export ▾'), menu);
    document.addEventListener('click', () => { menu.hidden = true; }, { once: true });
    return [wrap,
      h('button', { class: 'btn', 'data-tool': 'compare', title: `Compare with another binary (${tries('compare')})`, onclick: () => post({ type: 'tool', tool: 'compare' }) }, 'Compare…'),
      h('button', { class: 'btn', 'data-tool': 'find', title: `Find a symbol or import in a folder (${tries('find')})`, onclick: () => post({ type: 'tool', tool: 'find' }) }, 'Find in folder…')];
  }

  const ORDER = ['sections', 'segments', 'imports', 'exports', 'libraries', 'symbols', 'dynamic', 'directories', 'loadcommands', 'resources', 'debug', 'notes', 'slices'];
  const SHORT = { segments: 'Segments', sections: 'Sections', imports: 'Imports', exports: 'Exports', libraries: 'Libraries', symbols: 'Symbols', dynamic: 'Dynamic', directories: 'Data directories', loadcommands: 'Load commands', resources: 'Resources', debug: 'Debug', notes: 'Notes', slices: 'Architectures' };
  function tabList() {
    const c = cur();
    const out = [['overview', 'Overview'], ['headers', 'Headers']];
    if (!c) return [['overview', 'Overview']];
    const tables = [...(c.tables || [])];
    if (S.model.slices) { const sl = S.model.tables.find((t) => t.id === 'slices'); if (sl) tables.push(sl); }
    tables.sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
    for (const t of tables) out.push([t.id, SHORT[t.id] || t.title, t.rows.length]);
    out.push(['hex', 'Hex']);
    if (S.compare) out.push(['compare', 'Compare']);
    if (S.find) out.push(['find', 'Find']);
    return out;
  }
  function tableById(id) {
    const c = cur();
    return (c.tables || []).find((t) => t.id === id) || (S.model.tables || []).find((t) => t.id === id);
  }

  // ---------- views ----------

  function render() {
    if (!S.model) return;
    const ids = tabList().map((t) => t[0]);
    if (!ids.includes(S.tab)) S.tab = 'overview';
    let main;
    if (S.tab === 'overview') main = overview();
    else if (S.tab === 'headers') main = headers();
    else if (S.tab === 'hex') main = hexView();
    else if (S.tab === 'compare') main = compareView();
    else if (S.tab === 'find') main = findView();
    else main = tableView(tableById(S.tab));
    frame(main);
    // Draw right away (reading clientHeight lays the page out): requestAnimationFrame does not run in a hidden or
    // occluded window, and the rows must be there when it shows again.
    if (S.tab === 'hex') drawHex();
    if (S.afterRender) { const f = S.afterRender; S.afterRender = null; f(); }
  }

  function kv(pairs) {
    return h('table', { class: 'kv' }, h('tbody', {}, ...pairs.map(([k, v, off, len]) => h('tr', {},
      h('th', { text: k }),
      h('td', {}, h('span', { class: 'val', text: v }), off !== undefined && off !== null ? h('a', { class: 'jump', href: '#', title: `Show bytes at 0x${off.toString(16).toUpperCase()}`, onclick: (e) => { e.preventDefault(); showBytes(off + sliceBase(), len || 1); } }, `0x${off.toString(16).toUpperCase()}`) : null)))));
  }
  const sliceBase = () => (S.model.slices && S.model.slices.length ? S.model.slices[S.slice].offset : 0);

  function warnings(list) {
    if (!list || !list.length) return null;
    return h('div', { class: 'notice', role: 'note' }, h('b', { text: `${list.length} note${list.length === 1 ? '' : 's'} about this file` }), h('ul', {}, ...list.slice(0, 50).map((w) => h('li', { text: w }))));
  }

  function overview() {
    const c = cur();
    const tables = (c.tables || []).filter((t) => ['imports', 'exports', 'libraries', 'sections', 'symbols'].includes(t.id));
    return h('div', { class: 'pad' },
      warnings([...(S.model.slices ? S.model.warnings : []), ...(c.warnings || [])]),
      h('h2', { text: c.title }),
      kv((S.model.slices ? S.model.summary : []).concat(c.summary || [])),
      h('div', { class: 'cards' }, ...tables.map((t) => h('button', { class: 'card', onclick: () => { S.tab = t.id; render(); } }, h('b', { text: fmtInt(t.rows.length) }), h('span', { text: SHORT[t.id] || t.title })))));
  }

  function headers() {
    const c = cur();
    const tree = h('div', { class: 'fields' });
    if (S.fields && S.fields.slice === S.slice) tree.append(fieldTree());
    else if (c.template && S.model.size !== undefined) tree.append(h('button', { class: 'btn', onclick: () => { S.fields = { slice: S.slice, loading: true }; post({ type: 'fields' }); render(); } }, 'Show every header field with its offset'));
    return h('div', { class: 'pad' }, ...c.groups.map((g) => h('section', {}, h('h3', { text: g.title }), kv(g.fields))), h('h3', { text: 'Field tree' }), tree);
  }

  function fieldTree() {
    const f = S.fields;
    if (f.loading) return h('p', { class: 'muted', text: 'Reading the fields...' });
    if (f.error && !f.tree) return h('p', { class: 'muted', text: f.error });
    const node = (n, depth) => {
      const label = h('span', {}, h('span', { class: 'fn', text: n.n }), n.v !== undefined ? h('span', { class: 'fv', text: ` = ${n.v}` }) : null, n.l ? h('span', { class: 'muted', text: ` ${n.l}` }) : null, n.e ? h('span', { class: 'err', text: ` ${n.e}` }) : null,
        h('a', { class: 'jump', href: '#', onclick: (e) => { e.preventDefault(); e.stopPropagation(); showBytes(n.o + (f.base || 0), Math.max(1, n.s || 1)); } }, `0x${(n.o + (f.base || 0)).toString(16).toUpperCase()}`));
      if (!n.c || !n.c.length) return h('div', { class: 'leaf' }, label);
      const d = h('details', { open: depth < 2 }, h('summary', {}, label));
      let shown = 0;
      for (const k of n.c) { if (shown++ > 2000) { d.append(h('div', { class: 'muted', text: `${n.c.length - 2000} more fields` })); break; } d.append(node(k, depth + 1)); }
      return d;
    };
    return h('div', {}, f.error ? h('p', { class: 'muted', text: f.error }) : null, node(f.tree, 0));
  }

  function showBytes(off, len) {
    S.hex.mark = [off, Math.max(1, len)];
    S.hex.top = Math.max(0, Math.floor(off / 16) - 4);
    S.tab = 'hex';
    render();
  }

  // ---------- tables (virtual scroll, filter, sort) ----------

  function rowsOf(t) {
    const q = (S.filters[t.id] || '').trim().toLowerCase();
    let idx = t.rows.map((_, i) => i);
    if (q) idx = idx.filter((i) => t.rows[i].some((v) => String(v).toLowerCase().includes(q)));
    const s = S.sorts[t.id];
    if (s) {
      const ty = t.columns[s.col].t;
      const key = (v) => (ty === 'h' ? (/^-?0x[0-9A-F]+$/i.test(String(v)) ? BigInt(String(v).replace('-', '')) * (String(v).startsWith('-') ? -1n : 1n) : -1n) : ty === 'd' ? Number(v) : String(v).toLowerCase());
      idx.sort((a, b) => { const x = key(t.rows[a][s.col]), y = key(t.rows[b][s.col]); return (x < y ? -1 : x > y ? 1 : 0) * s.dir; });
    }
    return idx;
  }

  function tableView(t) {
    if (!t) return h('p', { class: 'pad muted', text: 'Nothing here.' });
    const idx = rowsOf(t);
    const cols = t.columns;
    const hasSpan = t.spans.some(Boolean);
    const grid = `grid-template-columns: ${cols.map((c) => (c.n === '#' ? '56px' : c.t === 's' && cols.length > 2 && (c.n === 'Name' || c.n === 'Details' || c.n === 'Library' || c.n === 'Meaning' || c.n === 'Description' || c.n === 'Characteristics' || c.n === 'Forwarded to') ? 'minmax(160px, 3fr)' : 'minmax(80px, 1fr)')).join(' ')}${hasSpan ? ' 64px' : ''}`;
    const filter = h('input', { type: 'search', class: 'filter', placeholder: `Filter ${fmtInt(t.rows.length)} rows`, 'aria-label': 'Filter rows', value: S.filters[t.id] || '' });
    const status = h('span', { class: 'muted', text: idx.length === t.rows.length ? `${fmtInt(t.rows.length)} rows` : `${fmtInt(idx.length)} of ${fmtInt(t.rows.length)} rows` });
    const copy = h('button', { class: 'btn small', title: 'Copy the rows shown, tab separated', onclick: () => post({ type: 'copy', what: `${fmtInt(idx.length)} rows`, text: [cols.map((c) => c.n).join('\t'), ...idx.map((i) => t.rows[i].join('\t'))].join('\n') }) }, 'Copy rows');
    const head = h('div', { class: 'thead', style: grid }, ...cols.map((c, ci) => {
      const s = S.sorts[t.id];
      return h('button', { class: 'th', title: `Sort by ${c.n}`, onclick: () => { S.sorts[t.id] = s && s.col === ci ? { col: ci, dir: -s.dir } : { col: ci, dir: 1 }; S.scroll[t.id] = 0; render(); } }, c.n, s && s.col === ci ? (s.dir > 0 ? ' ▴' : ' ▾') : '');
    }), hasSpan ? h('span', { class: 'th' }) : null);
    const body = h('div', { class: 'tbody', tabindex: '0' });
    const spacer = h('div', { class: 'spacer', style: `height:${idx.length * ROW_H}px` });
    const layer = h('div', { class: 'layer' });
    body.append(spacer, layer);
    let selected = -1;
    const draw = () => {
      const top = body.scrollTop, hgt = body.clientHeight || 600;
      const first = Math.max(0, Math.floor(top / ROW_H) - 5), last = Math.min(idx.length, Math.ceil((top + hgt) / ROW_H) + 5);
      layer.textContent = '';
      layer.style.transform = `translateY(${first * ROW_H}px)`;
      for (let k = first; k < last; k++) {
        const i = idx[k], r = t.rows[i], span = t.spans[i];
        const row = h('div', { class: 'tr' + (k === selected ? ' sel' : ''), style: grid, onclick: () => { selected = k; draw(); } },
          ...r.map((v, ci) => h('span', { class: 'td' + (cols[ci].t !== 's' ? ' num' : ''), title: String(v).length > 30 ? String(v) : null, text: v === '' ? '' : String(v) })),
          hasSpan ? (span ? h('a', { class: 'jump', href: '#', title: `${fmtInt(span[1])} bytes at 0x${(span[0] + sliceBaseFor(t)).toString(16).toUpperCase()}`, onclick: (e) => { e.preventDefault(); e.stopPropagation(); showBytes(span[0] + sliceBaseFor(t), span[1]); } }, 'bytes') : h('span', {})) : null);
        layer.append(row);
      }
    };
    body.addEventListener('scroll', () => { S.scroll[t.id] = body.scrollTop; draw(); });
    body.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'c' && selected >= 0) { post({ type: 'copy', what: 'the row', text: t.rows[idx[selected]].join('\t') }); e.preventDefault(); }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { selected = Math.max(0, Math.min(idx.length - 1, selected + (e.key === 'ArrowDown' ? 1 : -1))); const y = selected * ROW_H; if (y < body.scrollTop) body.scrollTop = y; else if (y + ROW_H > body.scrollTop + body.clientHeight) body.scrollTop = y + ROW_H - body.clientHeight; draw(); e.preventDefault(); }
    });
    let timer;
    filter.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { S.filters[t.id] = filter.value; S.scroll[t.id] = 0; S.afterRender = () => { const f = document.querySelector('.filter'); if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); } }; render(); }, 150); });
    const prev = S.afterRender;
    S.afterRender = () => { if (prev) prev(); body.scrollTop = S.scroll[t.id] || 0; draw(); };
    return h('div', { class: 'tablewrap' }, h('div', { class: 'tools' }, filter, status, copy, t.title !== (SHORT[t.id] || '') ? h('span', { class: 'muted ttl', text: t.title }) : null), head, body);
  }
  const sliceBaseFor = (t) => (S.model.slices && S.model.slices.length && !S.model.tables.includes(t) ? S.model.slices[S.slice].offset : 0);

  // ---------- hex ----------

  function hexView() {
    const rows = Math.max(1, Math.ceil(S.size / 16));
    const goto = h('input', { class: 'goto', placeholder: 'Go to offset (0x1F00 or 7936)', 'aria-label': 'Go to offset' });
    goto.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      const s = goto.value.trim().replace(/_/g, '');
      const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : /^[0-9]+$/.test(s) ? parseInt(s, 10) : /^[0-9a-f]+h$/i.test(s) ? parseInt(s, 16) : NaN;
      if (!Number.isFinite(n) || n < 0 || n >= Math.max(1, S.size)) { goto.classList.add('bad'); return; }
      goto.classList.remove('bad');
      S.hex.mark = [n, 1]; S.hex.top = Math.max(0, Math.floor(n / 16) - 4); drawHex();
    });
    const box = h('div', { class: 'hexbox', id: 'hexbox', tabindex: '0' }, h('div', { class: 'spacer', style: `height:${Math.min(rows * HEX_ROW_H, MAX_SPACER)}px` }), h('div', { class: 'layer hexlayer', id: 'hexlayer' }));
    let syncing = false;
    box.addEventListener('scroll', () => {
      if (syncing) { syncing = false; return; }
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const max = Math.max(0, rows - vis);
      const room = Math.max(1, box.scrollHeight - box.clientHeight);
      S.hex.top = Math.round((box.scrollTop / room) * max);
      drawHex(true);
    });
    box.addEventListener('wheel', (e) => {
      if (rows * HEX_ROW_H <= MAX_SPACER) return; // native scrolling is exact for files up to ~800 KB of rows
      e.preventDefault();
      S.hex.top = Math.max(0, Math.min(rows - 1, S.hex.top + Math.round(e.deltaY / HEX_ROW_H)));
      drawHex();
    }, { passive: false });
    box.addEventListener('keydown', (e) => {
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const step = { PageDown: vis, PageUp: -vis, ArrowDown: 1, ArrowUp: -1 }[e.key];
      if (e.key === 'Home') S.hex.top = 0; else if (e.key === 'End') S.hex.top = Math.max(0, rows - vis); else if (step) S.hex.top = Math.max(0, Math.min(rows - 1, S.hex.top + step)); else return;
      e.preventDefault(); drawHex();
    });
    box._sync = (top) => {
      const vis = Math.floor(box.clientHeight / HEX_ROW_H);
      const max = Math.max(1, rows - vis);
      const room = Math.max(0, box.scrollHeight - box.clientHeight);
      const want = Math.round((top / max) * room);
      if (Math.abs(box.scrollTop - want) > 1) { syncing = true; box.scrollTop = want; }
    };
    const mark = S.hex.mark ? h('span', { class: 'muted', text: `Marked: ${fmtInt(S.hex.mark[1])} byte${S.hex.mark[1] === 1 ? '' : 's'} at 0x${S.hex.mark[0].toString(16).toUpperCase()}` }) : null;
    return h('div', { class: 'tablewrap' }, h('div', { class: 'tools' }, goto, h('span', { class: 'muted', text: `${fmtSize(S.size)}, ${fmtInt(rows)} rows of 16 bytes` }), mark), box);
  }

  function drawHex(fromScroll) {
    const box = document.getElementById('hexbox'), layer = document.getElementById('hexlayer');
    if (!box || !layer) return;
    const vis = Math.ceil(box.clientHeight / HEX_ROW_H) + 1;
    const rows = Math.max(1, Math.ceil(S.size / 16));
    S.hex.top = Math.max(0, Math.min(S.hex.top, Math.max(0, rows - vis + 1)));
    if (!fromScroll) box._sync(S.hex.top);
    layer.style.transform = `translateY(${box.scrollTop}px)`;
    layer.textContent = '';
    const [m0, mlen] = S.hex.mark || [-1, 0];
    for (let r = S.hex.top; r < Math.min(rows, S.hex.top + vis); r++) {
      const off = r * 16;
      const line = h('div', { class: 'hrow' }, h('span', { class: 'hoff', text: hex8(off) }));
      const hexes = h('span', { class: 'hbytes' }), ascii = h('span', { class: 'hascii' });
      let missing = false;
      for (let i = 0; i < 16; i++) {
        const o = off + i;
        if (o >= S.size) { hexes.append(h('span', { class: 'hb', text: '  ' })); continue; }
        const b = byteAt(o);
        if (b === undefined) { missing = true; hexes.append(h('span', { class: 'hb muted', text: '..' })); ascii.append(h('span', { text: ' ' })); continue; }
        const on = o >= m0 && o < m0 + mlen;
        hexes.append(h('span', { class: 'hb' + (on ? ' mark' : '') + (b === 0 ? ' zero' : ''), text: b.toString(16).toUpperCase().padStart(2, '0') }));
        ascii.append(h('span', { class: on ? 'mark' : '', text: b >= 32 && b < 127 ? String.fromCharCode(b) : '.' }));
      }
      line.append(hexes, ascii);
      layer.append(line);
      if (missing) need(off);
    }
  }
  function byteAt(o) { const k = Math.floor(o / HEX_CHUNK); const c = S.hex.chunks.get(k); return c ? c[o - k * HEX_CHUNK] : undefined; }
  function need(off) {
    const k = Math.floor(off / HEX_CHUNK);
    if (S.hex.chunks.has(k) || S.hex.pending.has(k)) return;
    S.hex.pending.add(k);
    post({ type: 'hex', offset: k * HEX_CHUNK, length: HEX_CHUNK });
  }

  // ---------- compare / find ----------

  function compareView() {
    const { result: r, nameA, nameB } = S.compare;
    const sec = (t) => h('section', {}, h('h3', { text: `${t.title}: ${t.addedCount} added, ${t.removedCount} removed, ${t.changed.length} changed, ${fmtInt(t.same)} the same` }),
      t.added.length ? h('details', { open: t.added.length < 200 }, h('summary', { text: `Added in ${nameB} (${t.addedCount})` }), h('ul', { class: 'diff add' }, ...t.added.map((k) => h('li', { text: k })))) : null,
      t.removed.length ? h('details', { open: t.removed.length < 200 }, h('summary', { text: `Removed in ${nameB} (${t.removedCount})` }), h('ul', { class: 'diff del' }, ...t.removed.map((k) => h('li', { text: k })))) : null,
      t.changed.length ? h('details', { open: t.changed.length < 100 }, h('summary', { text: `Changed (${t.changed.length})` }), h('table', { class: 'kv' }, h('tbody', {}, ...t.changed.flatMap((c) => c.diffs.map((d) => h('tr', {}, h('th', { text: `${c.key} · ${d.column}` }), h('td', { text: `${d.a} → ${d.b}` }))))))) : null);
    return h('div', { class: 'pad' },
      h('div', { class: 'tools' }, h('b', { text: `${nameA} compared with ${nameB}` }), h('button', { class: 'btn small', onclick: () => post({ type: 'saveCompare' }) }, 'Open as Markdown')),
      r.header.length ? h('section', {}, h('h3', { text: 'Header differences' }), h('table', { class: 'kv' }, h('tbody', {}, h('tr', {}, h('th', { text: 'Field' }), h('td', {}, h('b', { text: `${nameA} → ${nameB}` }))), ...r.header.map((x) => h('tr', {}, h('th', { text: x.name }), h('td', { text: `${x.a} → ${x.b}` })))))) : h('p', { class: 'muted', text: 'The header fields are the same.' }),
      ...r.tables.map(sec));
  }

  function findView() {
    const { results, summary } = S.find;
    const t = { id: '__find', title: 'Matches', columns: [{ n: 'Name', t: 's' }, { n: 'Kind', t: 's' }, { n: 'Library', t: 's' }, { n: 'Architecture', t: 's' }, { n: 'File', t: 's' }], rows: results.map((r) => [r.name, r.kind, r.library, r.arch, r.rel]), spans: results.map(() => null), key: [0] };
    const list = h('div', { class: 'tbody plain' }, ...results.slice(0, 5000).map((r) => h('div', { class: 'tr link', style: 'grid-template-columns: minmax(160px,2fr) 80px minmax(120px,1fr) 90px minmax(160px,2fr)', title: `Open ${r.file}`, onclick: () => post({ type: 'openFile', path: r.file }) },
      h('span', { class: 'td', text: r.name }), h('span', { class: 'td', text: r.kind }), h('span', { class: 'td', text: r.library }), h('span', { class: 'td', text: r.arch }), h('span', { class: 'td', text: r.rel }))));
    return h('div', { class: 'tablewrap' }, h('div', { class: 'tools' },
      h('b', { text: `${fmtInt(summary.matches)} match${summary.matches === 1 ? '' : 'es'} for "${summary.query}"` }),
      h('span', { class: 'muted', text: `in ${fmtInt(summary.binaries)} binaries of ${fmtInt(summary.files)} files under ${summary.root}${summary.stopped ? ' (stopped)' : ''}` }),
      h('button', { class: 'btn small', onclick: () => post({ type: 'copy', what: 'the matches', text: t.rows.map((r) => r.join('\t')).join('\n') }) }, 'Copy')), list);
  }

  // ---------- messages ----------

  window.addEventListener('message', (e) => {
    const m = e.data || {};
    if (m.pro) S.pro = m.pro;
    if (m.type === 'model') {
      S.model = m.model; S.name = m.name; S.size = m.size || 0; S.slice = 0;
      render();
      post({ type: 'rendered' });
    } else if (m.type === 'error') {
      app.textContent = '';
      app.append(h('div', { class: 'pad' }, h('h2', { text: m.notBinary ? 'Not an ELF, PE or Mach-O file' : 'This file could not be read' }), h('p', { text: m.message }),
        m.notBinary ? h('p', { class: 'muted', text: 'ELF & PE Viewer reads Linux and Unix ELF files (.so, .o, executables), Windows PE files (.exe, .dll, .sys) and Apple Mach-O files (.dylib, executables, universal binaries).' }) : null));
      const foot = document.getElementById('zovo-footer'); if (foot) app.append(foot.content.cloneNode(true));
    } else if (m.type === 'hex') {
      const k = Math.floor(m.offset / HEX_CHUNK);
      S.hex.pending.delete(k);
      S.hex.chunks.set(k, Uint8Array.from(m.bytes || []));
      if (S.hex.chunks.size > 512) S.hex.chunks.delete(S.hex.chunks.keys().next().value);
      if (S.tab === 'hex') drawHex(true);
    } else if (m.type === 'fields') {
      S.fields = { slice: S.slice, tree: m.tree, error: m.error, base: m.base || 0 };
      if (S.tab === 'headers') render();
    } else if (m.type === 'compare') {
      S.compare = m; S.tab = 'compare'; render();
    } else if (m.type === 'find') {
      S.find = m; S.tab = 'find'; render();
    } else if (m.type === 'pro') {
      if (S.model) render();
    } else if (m.type === 'notice') {
      const v = document.getElementById('view');
      if (v) v.prepend(h('div', { class: 'notice', text: m.text }));
    }
  });
  window.addEventListener('resize', () => { if (S.tab === 'hex') drawHex(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.model) render(); });
  post({ type: 'ready' });
}());
