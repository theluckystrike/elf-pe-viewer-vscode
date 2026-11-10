'use strict';
// ELF Viewer & PE Viewer: a read-only custom editor for ELF, PE (EXE, DLL, SYS) and Mach-O files.
// The parsers run in a worker thread (runner.js) with a time and memory cap, so a hostile file cannot hang or crash
// the extension host. No network: the webview gets every byte by postMessage. Pro tools (pro.js) ask only when used.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { runJob, findInFiles } = require('./runner');
const tools = require('./core/tools');
const { buildHtml } = require('./html');
const { createPro } = require('./pro');
const { createRatingPrompt } = require('./rate');
const { registerSupport, commandUris, showLinks } = require('./support');

const EXT_ID = 'zovo.zovo-elf-pe-viewer';
const PREFIX = 'elfPeViewer';
const VIEW_TYPES = ['elfPeViewer.binary', 'elfPeViewer.any'];
const MAX_REMOTE_BYTES = 256 * 1024 * 1024; // non-file URIs are read into memory, up to this size
const MAX_HEX_READ = 1 << 16;
const BINARY_EXT = /\.(exe|dll|sys|efi|ocx|cpl|scr|drv|pyd|mui|so|dylib|bundle|elf|axf|ko|o|obj|out|node|prx|elf32|elf64|macho|kext|a)$|\.so\.[0-9.]+$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', '__pycache__', '.venv', '.tox', '.cache']);

let rating = { success() {}, failure() {} };
let pro;
const viewers = new Set();
let active = null;

function setting(key, dflt) { try { return vscode.workspace.getConfiguration(PREFIX).get(key, dflt); } catch { return dflt; } }
const baseName = (uri) => path.posix.basename(uri.path) || uri.toString();

/** Parse a file (or an in-memory copy for non-file URIs) in the worker. */
async function parseUri(uri, limits) {
  if (uri.scheme === 'file') return runJob({ op: 'parse', file: uri.fsPath, limits });
  const st = await vscode.workspace.fs.stat(uri);
  if (st.size > MAX_REMOTE_BYTES) throw new Error(`This file is ${Math.round(st.size / 1048576)} MB on a remote or virtual file system; files there are read up to 256 MB.`);
  const data = await vscode.workspace.fs.readFile(uri);
  const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  return runJob({ op: 'parse', buffer: buf, limits }, { transfer: [buf] });
}

async function readBytes(uri, offset, length) {
  length = Math.max(0, Math.min(length, MAX_HEX_READ));
  if (uri.scheme === 'file') {
    const fh = await fs.promises.open(uri.fsPath, 'r');
    try {
      const buf = Buffer.alloc(length);
      const { bytesRead } = await fh.read(buf, 0, length, offset);
      return buf.subarray(0, bytesRead);
    } finally { await fh.close(); }
  }
  const data = await vscode.workspace.fs.readFile(uri);
  return Buffer.from(data.subarray(offset, offset + length));
}

class Viewer {
  constructor(uri, panel, context) {
    this.uri = uri; this.panel = panel; this.context = context; this.model = null; this.name = baseName(uri); this.counted = false;
  }
  post(msg) { return this.panel.webview.postMessage(msg).then(undefined, () => false); }
  sliceModel() {
    if (!this.model || !this.model.slices || !this.model.slices.length) return this.model;
    const s = this.model.slices[this.slice || 0] || this.model.slices[0];
    return s.model;
  }
  async load() {
    try {
      this.model = await parseUri(this.uri);
      await this.post({ type: 'model', model: this.model, name: this.name, size: this.model.size, pro: proState() });
    } catch (e) {
      const notBinary = e.code === 'NOT_BINARY';
      if (!notBinary && e.code !== 'ENOENT') rating.failure();
      await this.post({ type: 'error', message: e.message || String(e), notBinary, pro: proState() });
    }
  }
  async onMessage(msg) {
    if (!msg || typeof msg.type !== 'string') return;
    switch (msg.type) {
      case 'ready': return this.load();
      case 'rendered':
        if (!this.counted && this.model) { this.counted = true; rating.success(this.uri); }
        return undefined;
      case 'hex': {
        const off = Number(msg.offset);
        if (!Number.isSafeInteger(off) || off < 0) return undefined;
        try {
          const b = await readBytes(this.uri, off, Number(msg.length) || 4096);
          return this.post({ type: 'hex', offset: off, bytes: Array.from(b) });
        } catch (e) { return this.post({ type: 'hex', offset: off, bytes: [], error: e.message }); }
      }
      case 'slice': this.slice = Math.max(0, Number(msg.index) || 0); return undefined;
      case 'fields': {
        if (this.uri.scheme !== 'file' || !this.model || !this.model.template) return this.post({ type: 'fields', error: 'The field tree needs a local file.' });
        const s = this.model.slices && this.model.slices[this.slice || 0];
        try {
          const r = await runJob({ op: 'fields', file: this.uri.fsPath, template: this.model.template, slice: s ? { offset: s.offset, size: s.size } : null }, { idleMs: 15000 });
          return this.post({ type: 'fields', tree: r.tree, error: r.error, base: s ? s.offset : 0 });
        } catch (e) { return this.post({ type: 'fields', error: e.message }); }
      }
      case 'tool': return runTool(String(msg.tool), this, msg.arg);
      case 'copy': return vscode.env.clipboard.writeText(String(msg.text || '').slice(0, 20 << 20)).then(() => vscode.window.setStatusBarMessage(msg.what ? `Copied ${msg.what}.` : 'Copied.', 3000));
      case 'openFile': {
        const p = String(msg.path || '');
        if (!p || !path.isAbsolute(p)) return undefined;
        return vscode.commands.executeCommand('vscode.openWith', vscode.Uri.file(p), VIEW_TYPES[1]);
      }
      case 'saveCompare': return saveCompare(this);
      case 'settings': return vscode.commands.executeCommand('workbench.action.openSettings', `@ext:${EXT_ID}`);
      default: return undefined;
    }
  }
}

function proState() {
  return { show: setting('showProTools', true) !== false, licensed: !!(pro && pro.licensed), tries: pro ? pro.tries() : {} };
}

class Provider {
  constructor(context) { this.context = context; }
  openCustomDocument(uri) { return { uri, dispose() {} }; }
  resolveCustomEditor(document, panel) {
    const ctx = this.context;
    const media = vscode.Uri.joinPath(ctx.extensionUri, 'media');
    panel.webview.options = { enableScripts: true, enableCommandUris: commandUris(PREFIX), localResourceRoots: [media] };
    panel.webview.html = buildHtml({
      cspSource: panel.webview.cspSource,
      scriptUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'main.js')).toString(),
      styleUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'main.css')).toString(),
      title: baseName(document.uri),
      showSupportLinks: showLinks(vscode, PREFIX),
    });
    const v = new Viewer(document.uri, panel, ctx);
    viewers.add(v);
    if (panel.active) active = v;
    panel.onDidChangeViewState(() => { if (panel.active) active = v; else if (active === v && !panel.visible) active = null; });
    panel.onDidDispose(() => { viewers.delete(v); if (active === v) active = null; });
    panel.webview.onDidReceiveMessage((m) => v.onMessage(m).then(undefined, (e) => v.post({ type: 'notice', text: String(e && e.message || e) })));
  }
}

// ---------------- Pro tools ----------------

async function viewerOrPick(arg, title) {
  if (arg instanceof Viewer) return arg;
  if (arg && arg.fsPath) return { uri: arg, name: baseName(arg), model: await parseUri(arg), detached: true };
  if (active) return active;
  const pick = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: title, title: `${title}: pick an ELF, PE or Mach-O file` });
  if (!pick || !pick[0]) return null;
  return { uri: pick[0], name: baseName(pick[0]), model: await parseUri(pick[0]), detached: true };
}

async function runTool(tool, from, arg) {
  if (tool === 'exportJson' || tool === 'exportC') return exportStructure(from, tool === 'exportC' ? 'c' : 'json');
  if (tool === 'compare') return compare(from);
  if (tool === 'find') return findInFolder(from, arg);
  return undefined;
}

async function exportStructure(from, kind) {
  if (!(await pro.allowed('export'))) return;
  let v;
  try { v = await viewerOrPick(from, 'Export'); } catch (e) { vscode.window.showWarningMessage(`Could not read the file: ${e.message}`); return; }
  if (!v || !v.model) return;
  const ext = kind === 'c' ? 'h' : 'json';
  const base = v.uri.scheme === 'file' ? vscode.Uri.file(`${v.uri.fsPath}.structure.${ext}`) : undefined;
  const target = await vscode.window.showSaveDialog({ defaultUri: base, filters: kind === 'c' ? { 'C header': ['h'] } : { JSON: ['json'] }, title: `Export the structure of ${v.name} as ${kind === 'c' ? 'a C header' : 'JSON'}` });
  if (!target) return; // cancelled: no try used
  let text;
  if (kind === 'c') {
    let headerC = '';
    if (v.uri.scheme === 'file' && v.model.template && !v.model.slices) {
      try { headerC = await runJob({ op: 'headerC', file: v.uri.fsPath, template: v.model.template, name: v.name }, { idleMs: 15000 }); } catch { headerC = ''; }
    }
    text = tools.toCHeader(v.model, v.name, headerC);
  } else text = tools.toJson(v.model, v.name);
  await vscode.workspace.fs.writeFile(target, Buffer.from(text, 'utf8'));
  await pro.produced('export');
  await vscode.window.showTextDocument(target, { preview: false, viewColumn: vscode.ViewColumn.Beside });
  refreshPro();
}

async function compare(from) {
  if (!(await pro.allowed('compare'))) return;
  let a;
  try { a = await viewerOrPick(from, 'Compare'); } catch (e) { vscode.window.showWarningMessage(`Could not read the file: ${e.message}`); return; }
  if (!a || !a.model) return;
  const pick = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Compare', title: `Compare ${a.name} with...`, defaultUri: a.uri.scheme === 'file' ? vscode.Uri.file(path.dirname(a.uri.fsPath)) : undefined });
  if (!pick || !pick[0]) return; // cancelled: no try used
  let b;
  try { b = await parseUri(pick[0]); } catch (e) { vscode.window.showWarningMessage(`${baseName(pick[0])}: ${e.message}`); return; }
  const arch = a.model.slices && a.model.slices[a.slice || 0] ? a.model.slices[a.slice || 0].arch : undefined;
  const result = tools.compareModels(a.model, b, { arch });
  const nameB = baseName(pick[0]);
  if (a instanceof Viewer) {
    a.lastCompare = { result, nameA: a.name, nameB };
    await a.post({ type: 'compare', result, nameA: a.name, nameB });
    a.panel.reveal();
  } else {
    const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: tools.compareMarkdown(result, a.name, nameB) });
    await vscode.window.showTextDocument(doc, { preview: false });
  }
  await pro.produced('compare');
  refreshPro();
}

async function saveCompare(v) {
  if (!v.lastCompare) return;
  const { result, nameA, nameB } = v.lastCompare;
  const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: tools.compareMarkdown(result, nameA, nameB) });
  await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
}

/** Candidate files under a folder: binary extensions, or no extension; at most 20,000 entries looked at. */
async function listCandidates(root, cancelled) {
  const out = [];
  let seen = 0;
  const stack = [[root, 0]];
  while (stack.length && seen < 20000 && out.length < 5000 && !cancelled()) {
    const [dir, depth] = stack.pop();
    let entries;
    try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (++seen > 20000) break;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && depth < 24) stack.push([p, depth + 1]); continue; }
      if (!e.isFile()) continue;
      if (BINARY_EXT.test(e.name) || !/\.[A-Za-z0-9]{1,8}$/.test(e.name)) out.push(p);
    }
  }
  return out;
}

async function findInFolder(from, preset) {
  if (!(await pro.allowed('find'))) return;
  const query = typeof preset === 'string' && preset.trim() ? preset : await vscode.window.showInputBox({
    title: 'Find a symbol or import in a folder',
    prompt: 'A function, symbol or library name. Plain text matches any part of the name; /regex/ works too.',
    placeHolder: 'for example CreateFileW, SSL_read or /^_?pthread_/',
    validateInput: (s) => { try { tools.matcher(s); return null; } catch (e) { return e.message; } },
  });
  if (!query || !query.trim()) return; // cancelled: no try used
  const folders = (vscode.workspace.workspaceFolders || []).filter((f) => f.uri.scheme === 'file');
  let root;
  if (from instanceof Viewer && from.uri.scheme === 'file' && !folders.some((f) => from.uri.fsPath.startsWith(f.uri.fsPath + path.sep))) root = path.dirname(from.uri.fsPath);
  else if (folders.length === 1) root = folders[0].uri.fsPath;
  else if (folders.length > 1) {
    const p = await vscode.window.showQuickPick(folders.map((f) => ({ label: f.name, description: f.uri.fsPath, f })), { title: 'Search which folder?' });
    if (!p) return;
    root = p.f.uri.fsPath;
  }
  if (!root) {
    const p = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, openLabel: 'Search here', title: 'Folder to search' });
    if (!p || !p[0]) return;
    root = p[0].fsPath;
  }
  const results = [];
  let files = 0, skipped = 0, read = 0;
  const stopped = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Finding "${query}"`, cancellable: true }, async (progress, token) => {
    const cancelled = () => token.isCancellationRequested;
    const list = await listCandidates(root, cancelled);
    files = list.length;
    await findInFiles(list, query, {
      cancelled,
      onFile: (p) => {
        if (p.error === 'skip') skipped++; else read++;
        for (const h of p.hits) if (results.length < 5000) results.push({ ...h, file: p.file, rel: path.relative(root, p.file) });
        if (p.index % 20 === 0) progress.report({ message: `${p.index + 1} of ${files} files, ${results.length} match${results.length === 1 ? '' : 'es'}` });
      },
    });
    return cancelled();
  });
  const summary = { query, root, files, binaries: read, matches: results.length, stopped };
  if (from instanceof Viewer) {
    await from.post({ type: 'find', results, summary });
    from.panel.reveal();
  } else if (results.length) {
    const pick = await vscode.window.showQuickPick(results.map((r) => ({ label: r.name, description: `${r.kind}${r.library ? ` from ${r.library}` : ''}${r.arch ? ` (${r.arch})` : ''}`, detail: r.rel, r })), { title: `${results.length} match${results.length === 1 ? '' : 'es'} for "${query}" in ${read} binaries`, matchOnDescription: true, matchOnDetail: true });
    if (pick) await vscode.commands.executeCommand('vscode.openWith', vscode.Uri.file(pick.r.file), VIEW_TYPES[1]);
  } else {
    vscode.window.showInformationMessage(`No match for "${query}" in ${read} binaries under ${root}.`);
  }
  if (results.length) { await pro.produced('find'); refreshPro(); } // a search with no match does not use a try
}

function refreshPro() { for (const v of viewers) v.post({ type: 'pro', pro: proState() }); }

// ---------------- activation ----------------

function activate(context) {
  rating = createRatingPrompt({ vscode, context, extensionId: EXT_ID, section: PREFIX, name: 'ELF & PE Viewer' });
  registerSupport({ vscode, context, prefix: PREFIX, selfId: EXT_ID });
  pro = createPro({ vscode, context });
  context.subscriptions.push(pro.onDidChange(() => refreshPro()));
  const provider = new Provider(context);
  for (const vt of VIEW_TYPES) {
    context.subscriptions.push(vscode.window.registerCustomEditorProvider(vt, provider, { supportsMultipleEditorsPerDocument: true, webviewOptions: { retainContextWhenHidden: true } }));
  }
  const reg = (id, fn) => context.subscriptions.push(vscode.commands.registerCommand(id, fn));
  reg(`${PREFIX}.open`, async (uri) => {
    let target = uri && uri.scheme ? uri : null;
    if (!target) {
      const p = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Open', title: 'Open an ELF, PE (EXE, DLL) or Mach-O file' });
      if (!p || !p[0]) return;
      target = p[0];
    }
    await vscode.commands.executeCommand('vscode.openWith', target, VIEW_TYPES[1]);
  });
  reg(`${PREFIX}.openSample`, async (which) => {
    const name = ['pe', 'macho'].includes(which) ? (which === 'pe' ? 'sample-zovo.dll' : 'sample-zovo.dylib') : 'sample-libzovo.so';
    await vscode.commands.executeCommand('vscode.openWith', vscode.Uri.joinPath(context.extensionUri, 'samples', name), VIEW_TYPES[1]);
  });
  reg(`${PREFIX}.openWalkthrough`, () => vscode.commands.executeCommand('workbench.action.openWalkthrough', `${EXT_ID}#elfPeViewer.start`, false));
  reg(`${PREFIX}.exportJson`, (uri) => exportStructure(uri && uri.fsPath ? uri : active, 'json'));
  reg(`${PREFIX}.exportC`, (uri) => exportStructure(uri && uri.fsPath ? uri : active, 'c'));
  reg(`${PREFIX}.compare`, (uri) => compare(uri && uri.fsPath ? uri : active));
  reg(`${PREFIX}.findInFolder`, () => findInFolder(active));
  context.subscriptions.push(vscode.window.registerUriHandler({ handleUri: (uri) => pro.handleUri(uri) }));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => { if (e.affectsConfiguration(`${PREFIX}.showProTools`)) refreshPro(); }));
}

function deactivate() {}

module.exports = { activate, deactivate, listCandidates, BINARY_EXT };
