// morsec dashboard (L33 dash-actions). Plain script, no framework, nothing fetched but /api/.
// Every string from a file, an agent or a user reaches the page through textContent only
// (design §6.3); links are built from fixed routes and encodeURIComponent. The page never raises
// Touch ID: msd does, for every action that loosens, starts, reads or changes a value. A value
// msd shows is written into one element, never stored, logged or put in the URL, and cleared
// after 15 s, on blur, when the page is hidden, on pagehide and on navigation (SPEC D-12).
'use strict';

(function () {
  const state = { csrf: null, running: null, version: '' };
  const main = document.getElementById('main');
  const stateBox = document.getElementById('state');
  const live = document.querySelector('#live p');
  const ver = document.getElementById('ver');
  // Timers of the current screen (countdowns, scan polling); cleared on every render.
  let timers = [];

  // ---- DOM helpers: text only --------------------------------------------------------------
  function el(tag, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (let i = 2; i < arguments.length; i++) {
      const k = arguments[i];
      if (k === null || k === undefined || k === false) continue;
      if (typeof k === 'string' || typeof k === 'number') {
        const s = document.createElement('span');
        s.textContent = String(k);
        e.appendChild(s);
      } else {
        e.appendChild(k);
      }
    }
    return e;
  }
  function txt(tag, cls, s) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    e.textContent = s === null || s === undefined ? '' : String(s);
    return e;
  }
  function link(route, label, cls) {
    const a = txt('a', cls, label);
    a.setAttribute('href', '#' + route);
    return a;
  }
  function enc(s) { return encodeURIComponent(String(s)); }
  function mono(s) { return txt('span', 'mono', s); }
  // Text that may break only after a "/" (refs, paths): wide tables never split a word.
  function slashed(node, s) {
    const parts = String(s).split('/');
    parts.forEach(function (p, i) {
      node.appendChild(document.createTextNode(p + (i < parts.length - 1 ? '/' : '')));
      if (i < parts.length - 1) node.appendChild(document.createElement('wbr'));
    });
    return node;
  }
  function ref(key) {
    const a = slashed(document.createElement('a'), key);
    a.className = 'ref';
    a.setAttribute('href', '#/secret/' + enc(key));
    return a;
  }
  function pathText(s, cls) { return slashed(txt('span', cls || 'mono', ''), s); }
  function cmd(s) { return txt('code', 'cmd', s); }
  function num(n) { return Number(n || 0).toLocaleString(); }
  function plural(n, one, many) { return num(n) + ' ' + (Number(n) === 1 ? one : many); }
  let liveTimer = null;
  function announce(msg) {
    live.textContent = msg;
    clearTimeout(liveTimer);
    liveTimer = setTimeout(function () { live.textContent = ''; }, 6000);
  }
  function after(ms, f) { const t = setTimeout(f, ms); timers.push(t); return t; }

  // Buttons are type=button and at least 44 px (CSS).
  function btn(label, cls, onClick) {
    const b = txt('button', 'btn' + (cls ? ' ' + cls : ''), label);
    b.setAttribute('type', 'button');
    if (onClick) b.addEventListener('click', onClick);
    return b;
  }

  // Every form control is made here: a <label for> above it and an example in a hint line,
  // never in the field itself (SPEC D-4).
  let fieldSeq = 0;
  function field(label, tag, name, hint) {
    const id = 'f-' + (++fieldSeq);
    const c = document.createElement(tag);
    c.id = id;
    c.setAttribute('name', name);
    const l = txt('label', null, label);
    l.setAttribute('for', id);
    const w = el('div', 'field', l, c);
    if (hint) w.appendChild(txt('p', 'hint', hint));
    return [w, c];
  }
  function select(label, name, options, current) {
    const [w, s] = field(label, 'select', name, null);
    for (const [value, text] of options) {
      const o = txt('option', null, text);
      o.value = value;
      if (current === value) o.selected = true;
      s.appendChild(o);
    }
    return [w, s];
  }
  // A field for a value: hidden, no autocomplete, no spellcheck, never inside a <form>.
  function secretField(label, name, hint) {
    const [w, c] = field(label, 'input', name, hint);
    c.setAttribute('type', 'password');
    c.setAttribute('autocomplete', 'off');
    c.setAttribute('spellcheck', 'false');
    c.setAttribute('autocapitalize', 'off');
    return [w, c];
  }
  function textField(label, name, hint) {
    const [w, c] = field(label, 'input', name, hint);
    c.setAttribute('type', 'text');
    c.setAttribute('autocomplete', 'off');
    c.setAttribute('spellcheck', 'false');
    c.setAttribute('autocapitalize', 'off');
    c.className = 'mono';
    return [w, c];
  }

  // D-8: relative in the cell, the absolute local time (ISO 8601 with offset) in title and datetime.
  function iso(d) {
    const p = function (n) { return String(n).padStart(2, '0'); };
    const off = -d.getTimezoneOffset();
    const sign = off >= 0 ? '+' : '-';
    const a = Math.abs(off);
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' +
      p(d.getMinutes()) + ':' + p(d.getSeconds()) + sign + p(Math.floor(a / 60)) + ':' + p(a % 60);
  }
  function relative(ms) {
    const d = new Date(ms);
    const ago = Date.now() - ms;
    const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (ago < 45000) return 'just now';
    if (ago < 3600000) return Math.max(1, Math.round(ago / 60000)) + ' min ago';
    const today = new Date(); today.setHours(0, 0, 0, 0);
    if (ms >= today.getTime()) return Math.round(ago / 3600000) + ' h ago';
    if (ms >= today.getTime() - 86400000) return 'yesterday ' + hm;
    if (ago < 7 * 86400000) return d.toLocaleDateString([], { weekday: 'short' }) + ' ' + hm;
    return d.toLocaleDateString();
  }
  function when(ms) {
    if (!ms) return txt('span', 'muted', 'never');
    const d = new Date(ms);
    const t = txt('time', null, relative(ms));
    t.setAttribute('datetime', iso(d));
    t.setAttribute('title', iso(d));
    return t;
  }

  // Tables scroll in their own box; `stack` ones become labelled rows under 720 px.
  function table(headers, rows, stack) {
    const t = el('table', stack ? 'stack' : null);
    const thead = el('thead', null);
    const hr = el('tr', null);
    for (const h of headers) hr.appendChild(txt('th', null, h));
    thead.appendChild(hr);
    t.appendChild(thead);
    const tb = el('tbody', null);
    for (const r of rows) {
      const tr = el('tr', null);
      r.forEach(function (c, i) {
        const td = c instanceof Node ? el('td', null, c) : txt('td', null, c);
        td.setAttribute('data-label', headers[i]);
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    }
    t.appendChild(tb);
    return el('div', 'tw', t);
  }
  function badge(s, kind) { return txt('span', 'badge' + (kind ? ' ' + kind : ''), s); }
  // One vocabulary everywhere (SPEC D-7).
  function statusWords(s) {
    if (s === 'protected') return 'protected';
    if (/^needs |^not stored/.test(String(s))) return 'not usable yet: ' + s;
    return String(s);
  }
  function status(s) {
    const cls = s === 'protected' ? 'st-protected' : /^needs |^not stored/.test(String(s)) ? 'st-needs' : '';
    return txt('span', cls, statusWords(s));
  }
  function result(s, reason) { return txt('span', 'st-' + String(s).replace(/[^a-z]/g, ''), s + (reason ? ': ' + reason : '')); }
  function kv(pairs) {
    const d = el('dl', 'kv');
    for (const [k, v] of pairs) {
      d.appendChild(txt('dt', null, k));
      const dd = el('dd', null);
      if (v instanceof Node) dd.appendChild(v); else dd.textContent = v === null || v === undefined ? '' : String(v);
      d.appendChild(dd);
    }
    return d;
  }
  function list(items, empty, cls) {
    if (!items || items.length === 0) return txt('p', 'muted', empty);
    const u = el('ul', 'plain' + (cls ? ' ' + cls : ''));
    for (const i of items) {
      const li = el('li', null);
      if (i instanceof Node) li.appendChild(i); else li.textContent = String(i);
      u.appendChild(li);
    }
    return u;
  }
  // Agent names first, the pid as muted detail (SPEC D-7).
  const AGENTS = { 'claude-code': 'Claude Code', codex: 'Codex', cursor: 'Cursor', 'gemini-cli': 'Gemini CLI', terminal: 'Terminal', dashboard: 'Dashboard', 'ms-dev': 'ms dev' };
  function agentName(label) { return Object.prototype.hasOwnProperty.call(AGENTS, label) ? AGENTS[label] : String(label); }
  function agentCell(label, pid) {
    const s = el('span', null, agentName(label));
    if (pid) s.appendChild(txt('span', 'muted', ' · pid ' + pid));
    return s;
  }
  // A command msd built, with a Copy button: the page's own text, never a value.
  function copyline(command, note) {
    const row = el('div', 'copyline', cmd(command));
    row.appendChild(btn('Copy', 'sm', async function () {
      try {
        await navigator.clipboard.writeText(command);
        announce('Copied the command. Paste it into Terminal.');
      } catch (e) {
        announce('Copy did not work here: select the command and copy it.');
      }
    }));
    if (note) row.appendChild(txt('span', 'muted', note));
    return row;
  }
  function section(title) {
    const s = el('section', 'section');
    s.appendChild(txt('h2', null, title));
    return s;
  }

  // ---- API ----------------------------------------------------------------------------------
  class SignedOut extends Error {}
  async function send(path, init) {
    const opts = init || {};
    try {
      return await fetch(path, {
        method: opts.method || 'GET',
        headers: opts.body === undefined
          ? { 'X-Morsec-CSRF': state.csrf || '' }
          : { 'X-Morsec-CSRF': state.csrf || '', 'Content-Type': 'application/json' },
        body: opts.body,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch (e) {
      throw new SignedOut('closed');
    }
  }
  async function api(path) {
    const r = await send(path);
    if (r.status === 401) throw new SignedOut('signed out');
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    if (r.status === 403 && body && /CSRF/.test(String(body.error))) throw new SignedOut('another tab');
    if (!r.ok) throw new Error((body && body.error) || ('error ' + r.status));
    return body;
  }
  // msd's messages already say what to do next; the page shows them once, capitalised (Q6).
  function sentence(m) {
    const t = String(m || '').replace(/^morsec: /, '').trim();
    return t ? t.charAt(0).toUpperCase() + t.slice(1) : t;
  }
  class ActionFailed extends Error {
    constructor(message, code) { super(message); this.code = code; }
  }
  // POSTs an action. The body is JSON; the answer is {ok, message, …} or {error, code}.
  async function act(path, body) {
    const r = await send(path, { method: 'POST', body: JSON.stringify(body || {}) });
    if (r.status === 401) throw new SignedOut('signed out');
    let out = null;
    try { out = await r.json(); } catch (e) { out = null; }
    if (r.status === 403 && out && /CSRF/.test(String(out.error))) throw new SignedOut('another tab');
    if (!r.ok) {
      const code = out && out.code ? String(out.code) : '';
      throw new ActionFailed(sentence(out && out.error ? out.error : 'Error ' + r.status), code);
    }
    return out;
  }
  async function download(url, fallback) {
    const r = await send(url);
    if (r.status === 401 || r.status === 403) throw new SignedOut('signed out');
    if (!r.ok) throw new Error('export failed: ' + r.status);
    const blob = await r.blob();
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('href', href);
    a.setAttribute('download', fallback);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(href); }, 1000);
  }

  // Runs an action that may raise Touch ID: the screen's buttons are disabled and the page says
  // where to confirm until msd answers (SPEC D-19). `out` shows the result under the control.
  async function run(out, touchId, f) {
    const buttons = Array.from(document.querySelectorAll('main button'));
    for (const b of buttons) b.disabled = true;
    out.className = touchId ? 'waiting' : 'muted';
    out.textContent = touchId ? 'Confirm with Touch ID on this Mac…' : 'Working…';
    if (touchId) announce('Confirm with Touch ID on this Mac.');
    try {
      const r = await f();
      out.className = 'signal result';
      out.textContent = r && r.message ? sentence(r.message) : 'Done.';
      announce(out.textContent);
      return r;
    } catch (e) {
      if (e instanceof SignedOut) { signedOut(e.message); return null; }
      out.className = 'err result';
      out.textContent = e && e.message ? sentence(e.message) : 'Something went wrong.';
      announce(out.textContent);
      out.dataset.code = e && e.code ? e.code : '';
      if (e && e.code === 'gone') after(1500, render);
      return null;
    } finally {
      for (const b of buttons) if (b.isConnected) b.disabled = false;
    }
  }

  // ---- header: the status control (SPEC D-9) -------------------------------------------------
  function renderState() {
    if (state.running === null) { stateBox.replaceChildren(); return; }
    if (state.running) {
      stateBox.replaceChildren(txt('span', 'word on', 'On'), btn('Stop', 'sm danger', confirmStop));
    } else {
      stateBox.replaceChildren(txt('span', 'word off', 'Stopped'), btn('Start', 'sm solid', start));
    }
  }
  function confirmStop() {
    const msg = txt('span', 'ask', 'Stop every agent’s access now?');
    const yes = btn('Stop', 'sm danger', async function () {
      yes.disabled = true;
      try {
        const r = await act('/api/stop');
        state.running = false;
        announce(r.message || 'morsec stopped.');
      } catch (e) {
        if (e instanceof SignedOut) { signedOut(e.message); return; }
        announce(e.message);
      }
      renderState();
      render();
    });
    const no = btn('Cancel', 'sm', renderState);
    stateBox.replaceChildren(msg, yes, no);
    yes.focus();
  }
  async function start() {
    const b = stateBox.querySelector('button');
    if (b) b.disabled = true;
    announce('Confirm with Touch ID on this Mac to start morsec.');
    try {
      const r = await act('/api/start');
      state.running = true;
      announce(r.message || 'morsec is on.');
    } catch (e) {
      if (e instanceof SignedOut) { signedOut(e.message); return; }
      announce(e.message);
    }
    renderState();
    render();
  }
  function setRunning(running, version) {
    state.running = running;
    if (version) { state.version = version; ver.textContent = 'msd ' + version; }
    renderState();
  }

  // ---- warnings and the waiting request (SPEC D-10, D-11) -------------------------------------
  // "Checked just now · 3 checks fine, 1 needs you" after a Re-check (review Q8).
  function recheckMessage(r) {
    const v = r && r.agents ? r.agents : { checks: [], warnings: [] };
    const fine = v.checks.filter(function (c) { return c.ok; }).length;
    const bad = v.checks.length - fine + v.warnings.length;
    return 'Checked just now · ' + plural(fine, 'check', 'checks') + ' fine' + (bad ? ', ' + num(bad) + ' still need' + (bad === 1 ? 's' : '') + ' you' : '');
  }

  // A warning: red only when something is blocked or failing; informational ones are quiet.
  // The fix is the primary button, Dismiss a quiet one after it (review Q12).
  function warningBox(w) {
    const b = el('div', w.dismiss ? 'box' : 'box warn');
    b.appendChild(txt('h3', null, w.title));
    if (w.detail) b.appendChild(txt('p', null, w.detail));
    const out = txt('p', 'muted', '');
    const acts = el('div', 'actions');
    for (const f of w.fix) {
      if (f.action && f.label) {
        const route = f.action;
        acts.appendChild(btn(f.label, 'solid', function () {
          run(out, false, async function () {
            const r = await act(route);
            return { message: route === '/api/agents/recheck' ? recheckMessage(r) : r.message };
          }).then(function (r) { if (r) after(2500, render); });
        }));
      }
    }
    for (const f of w.fix) if (f.command) b.appendChild(copyline(f.command, 'Run it in Terminal.'));
    if (w.dismiss) {
      acts.appendChild(btn('Dismiss', 'quiet', function () {
        run(out, false, function () { return act('/api/warnings/' + enc(w.id) + '/dismiss'); }).then(function (r) { if (r) render(); });
      }));
    }
    if (acts.childNodes.length) b.appendChild(acts);
    b.appendChild(out);
    return b;
  }

  // The request waiting for the person: what it asks in plain words first, the exact command
  // folded away, empty fields left out (review Q1). Who asked is named when it is not an agent
  // session (review S4); morsec's own actions are approved once only (review S2).
  function pendingCard(p) {
    const b = el('div', 'box focus');
    b.appendChild(txt('h3', null, p.from_agent ? p.agent + ' is waiting for you' : 'A request is waiting for you'));
    b.appendChild(txt('p', 'summary', p.summary));
    const facts = [['Key', ref(p.key)], ['Tier', p.tier]];
    if (!p.from_agent && p.requester) facts.push(['Asked by', txt('span', null, p.requester)]);
    if (p.cwd) facts.push(['Folder', pathText(p.cwd)]);
    if (p.effect) facts.push(['What it does', txt('span', null, p.effect)]);
    b.appendChild(kv(facts));
    const d = el('details', null);
    d.appendChild(txt('summary', null, 'The exact request (' + plural(p.command.length, 'part', 'parts') + ')'));
    const ol = el('ol', 'argv');
    p.command.forEach(function (a, i) { ol.appendChild(txt('li', null, '[' + i + '] ' + a)); });
    d.appendChild(ol);
    b.appendChild(d);
    const left = txt('p', 'muted count', '');
    const tick = function () {
      const s = Math.max(0, Math.round((p.expires_unix_ms - Date.now()) / 1000));
      left.textContent = s > 0 ? 'Expires in ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') : 'Expired';
      if (s > 0) after(1000, tick);
    };
    tick();
    const out = txt('p', 'muted', '');
    if (p.deciding) {
      b.appendChild(txt('p', 'waiting', 'Touch ID is up for this request on this Mac.'));
    } else {
      const id = p.id;
      const done = function (r) { if (r) after(800, render); };
      const acts = el('div', 'actions',
        btn('Approve once', 'solid', function () { run(out, true, function () { return act('/api/approvals/' + enc(id) + '/approve', { scope: 'once' }); }).then(done); }));
      if (!p.once_only) {
        acts.appendChild(btn('Approve for this session', null, function () { run(out, true, function () { return act('/api/approvals/' + enc(id) + '/approve', { scope: 'session' }); }).then(done); }));
      }
      acts.appendChild(btn('Deny', 'danger', function () { run(out, false, function () { return act('/api/approvals/' + enc(id) + '/deny'); }).then(done); }));
      b.appendChild(acts);
    }
    b.appendChild(left);
    b.appendChild(out);
    return b;
  }

  // ---- screens ------------------------------------------------------------------------------
  async function home() {
    const h = await api('/api/home');
    setRunning(h.running, h.version);
    const out = el('section', null);
    const hero = el('div', 'hero');
    hero.appendChild(txt('h1', null, h.running ? 'morsec is on.' : 'morsec is stopped.'));
    hero.appendChild(txt('p', 'lead', h.running
      ? 'Agents use your keys without seeing them.'
      : 'Every agent request is refused until you start it again.'));
    out.appendChild(hero);

    const needs = section('Needs you');
    let n = 0;
    if (h.pending) { needs.appendChild(pendingCard(h.pending)); n++; }
    for (const w of h.warnings) { needs.appendChild(warningBox(w)); n++; }
    if (h.projects_unreadable) {
      needs.appendChild(warningBox({ id: '', title: 'Project records failed their check', detail: 'Undo is off until they are fixed. Keys and rules keep working.', fix: [{ command: 'ms doctor' }], dismiss: false }));
      n++;
    }
    if (h.not_usable.length) {
      const b = el('div', 'box');
      b.appendChild(txt('h3', null, 'Keys that are not usable yet'));
      b.appendChild(txt('p', 'muted', 'An agent can’t use these until you give each a website or a command.'));
      b.appendChild(list(h.not_usable.map(function (k) {
        return el('div', 'row', ref(k.key), status(k.status));
      }), ''));
      if (h.needs_website > h.not_usable.length) {
        b.appendChild(link('/projects?show=not-usable', 'and ' + num(h.needs_website - h.not_usable.length) + ' more'));
      }
      needs.appendChild(b);
      n++;
    }
    if (n === 0) needs.appendChild(txt('p', 'muted', 'Nothing needs you right now.'));
    out.appendChild(needs);

    const stats = el('div', 'stats');
    const stat = function (label, value, route, warn) {
      const a = link(route, '', 'stat' + (warn && value > 0 ? ' warn' : ''));
      a.replaceChildren(txt('span', 'lbl', label), txt('span', 'n', num(value)));
      return a;
    };
    stats.appendChild(stat('Projects', h.projects, '/projects'));
    stats.appendChild(stat('Protected', h.protected, '/projects'));
    stats.appendChild(stat('Not usable yet', h.needs_website, '/projects?show=not-usable', true));
    stats.appendChild(stat('Blocked in 24 h', h.blocked_24h, '/activity?result=blocked&since=24h', true));
    out.appendChild(stats);

    const ag = section('Agents');
    ag.appendChild(list(h.agents.map(function (a) {
      return el('div', 'row', txt('strong', null, a.name),
        a.connected ? badge('connected', 'good') : badge(a.installed ? 'not connected' : 'not installed', a.installed ? 'bad' : ''),
        el('span', 'muted', 'last seen ', when(a.last_seen_unix_ms)));
    }), 'No supported agent found.'));
    ag.appendChild(link('/agents', 'Agents and checks'));
    out.appendChild(ag);
    return out;
  }

  function addProject() {
    const s = section('Add a project');
    s.appendChild(txt('p', null, 'Setting up a project reads its files, so it runs in Terminal with your own permissions. morsec checks the folder and gives you the command.'));
    const [w, input] = textField('Project folder', 'folder', 'The full path, for example /Users/you/code/shop');
    const out = el('div', null);
    const go = btn('Check folder', null, async function () {
      const path = input.value.trim();
      if (!path) { out.replaceChildren(txt('p', 'err', 'Type the folder’s full path first.')); return; }
      const msg = txt('p', 'muted', '');
      out.replaceChildren(msg);
      const r = await run(msg, false, function () { return act('/api/projects/check-path', { path: path }); });
      if (!r || !r.check) return;
      const c = r.check;
      if (!c.ok) { out.replaceChildren(txt('p', 'err', c.reason)); return; }
      out.replaceChildren(
        txt('p', null, c.project ? 'This folder is already the project “' + c.project + '”. Running it again re-scans it.' : 'Run this in Terminal to set it up:'),
        copyline(c.command));
    });
    s.appendChild(el('div', 'fields', w, el('div', 'field act', go)));
    s.appendChild(out);
    return s;
  }

  function addKey() {
    const s = section('Add a key');
    s.appendChild(txt('p', 'muted', 'A new key allows nothing until you give it a website or a command on its screen.'));
    const [kw, key] = textField('Key name', 'key', 'For example shop/stripe-secret-key');
    const [vw, value] = secretField('Value (hidden)', 'value', 'Pasted here, sent to morsec, then cleared from this page');
    const [mw, mode] = select('Used as', 'mode', [['swap', 'swap (websites)'], ['run', 'run (commands)']], 'swap');
    const [tw, tier] = select('Tier', 'tier', [['production', 'production (asks each use)'], ['test', 'test (never asks)']], 'production');
    const out = txt('p', 'muted', '');
    const go = btn('Add key', 'solid', function () {
      const body = { key: key.value.trim(), value: value.value, mode: mode.value, tier: tier.value };
      value.value = '';
      run(out, false, function () { return act('/api/keys', body); }).then(function (r) { if (r) after(1200, render); });
      body.value = '';
    });
    s.appendChild(el('div', 'fields', kw, vw, mw, tw, el('div', 'field act', go)));
    s.appendChild(out);
    return s;
  }

  async function projects(arg, q) {
    const v = await api('/api/projects');
    const onlyNeeds = q.get('show') === 'not-usable';
    const out = el('section', null);
    out.appendChild(el('div', 'hero', txt('h1', null, 'Projects'),
      txt('p', 'lead', 'Each project ms init set up, and the keys that live outside one.')));
    if (onlyNeeds) out.appendChild(el('p', 'section', 'Showing what is not usable yet. ', link('/projects', 'Show everything')));
    if (v.unreadable) out.appendChild(txt('p', 'err section', v.unreadable));
    const cards = v.projects.filter(function (p) { return !onlyNeeds || p.needs_website > 0; });
    if (v.projects.length === 0 && !v.unreadable) {
      out.appendChild(txt('p', 'section', 'No projects yet. Add one below: morsec checks the folder and gives you the command to run.'));
    }
    if (cards.length) {
      const g = el('div', 'cards');
      for (const p of cards) {
        const c = el('div', 'card');
        c.appendChild(txt('h3', null, p.display));
        c.appendChild(el('p', null, pathText(p.root, 'root')));
        c.appendChild(txt('p', 'count', num(p.protected) + ' protected · ' + num(p.needs_website) + ' not usable yet'));
        const b = el('div', 'badges');
        if (p.findings) b.appendChild(badge(plural(p.findings, 'key in code', 'keys in code'), 'bad'));
        if (p.committed_files) b.appendChild(badge('committed to git', 'bad'));
        if (p.stopped_early) b.appendChild(badge('scan stopped early', 'bad'));
        if (b.childNodes.length) c.appendChild(b);
        c.appendChild(link('/project/' + enc(p.slug), 'Open ' + p.display, 'btn open'));
        g.appendChild(c);
      }
      out.appendChild(g);
    }
    const loose = section('Keys not in a project');
    const rows = v.loose.filter(function (k) { return !onlyNeeds || !k.ready; });
    if (rows.length === 0) {
      loose.appendChild(txt('p', 'muted', 'None.'));
    } else {
      loose.appendChild(table(['Key', 'Used as', 'Tier', 'Status', 'Websites or folders'], rows.map(function (k) {
        return [ref(k.key), k.mode || '', k.tier || '', status(k.status), mono(k.targets.join(', '))];
      }), true));
    }
    out.appendChild(loose);
    out.appendChild(addKey());
    out.appendChild(addProject());
    return out;
  }

  function undoResult(u) {
    const box = el('div', 'box');
    box.appendChild(txt('h3', null, 'What changed'));
    if (u.restored.length) {
      box.appendChild(txt('p', 'lbl', 'Written back'));
      box.appendChild(list(u.restored.map(function (l) { return el('div', null, mono(l.file + ':' + l.line), ' ', mono(l.var)); }), ''));
    }
    if (u.skipped.length) {
      box.appendChild(txt('p', 'lbl err', 'Left as they are'));
      box.appendChild(list(u.skipped.map(function (l) { return el('div', null, mono(l.file + ':' + l.line), ' ', mono(l.var), txt('span', 'err', ' · ' + l.reason)); }), ''));
    }
    if (u.deleted_keys.length) box.appendChild(el('p', 'muted', 'Deleted from morsec: ', mono(u.deleted_keys.join(', '))));
    return box;
  }

  async function project(slug) {
    const p = await api('/api/projects/' + enc(slug));
    const out = el('section', null);
    out.appendChild(el('p', 'crumbs', link('/projects', 'Projects')));
    const hero = el('div', 'hero');
    hero.appendChild(txt('h1', null, p.display));
    hero.appendChild(txt('p', 'lead', plural(p.rows.length, 'secret', 'secrets') + ', ' + num(p.not_usable) + ' not usable yet'));
    hero.appendChild(pathText(p.root, 'root mono muted'));
    out.appendChild(hero);
    if (p.stopped_early) {
      out.appendChild(txt('p', 'err section', 'The scan stopped after ' + num(p.scan_entries) + ' files, so some secrets may be missing. Set up a subfolder on its own.'));
    }
    const result = el('div', null);
    const sec = section('Secrets');
    if (p.rows.length === 0) {
      sec.appendChild(txt('p', 'muted', 'No secrets were found in this project.'));
    } else {
      sec.appendChild(table(['Variable', 'Key', 'Provider', 'Tier', 'Used as', 'Status', 'Last use', ''], p.rows.map(function (r) {
        const msg = txt('span', 'muted', '');
        const cell = el('div', 'rowacts');
        const doUndo = function () {
          run(msg, true, function () { return act('/api/projects/' + enc(p.slug) + '/undo', { key: r.key }); }).then(function (x) {
            if (x && x.undo) { result.replaceChildren(undoResult(x.undo)); after(2500, render); }
          });
        };
        // Undo is the quiet, second action, and asks first (review Q7).
        const undo = txt('button', 'lnk', 'Undo');
        undo.setAttribute('type', 'button');
        undo.addEventListener('click', function () {
          const yes = txt('button', 'lnk', 'Write the value back');
          yes.setAttribute('type', 'button');
          yes.addEventListener('click', doUndo);
          const no = txt('button', 'lnk', 'Cancel');
          no.setAttribute('type', 'button');
          no.addEventListener('click', function () { cell.replaceChildren(open, undo, msg); });
          cell.replaceChildren(open, yes, no, msg);
        });
        const open = link('/secret/' + enc(r.key), 'Open');
        cell.replaceChildren(open, undo, msg);
        return [el('span', null, mono(r.var), txt('span', 'muted', ' ' + r.file + ':' + r.line)), ref(r.key), r.provider || '', r.tier || '', r.mode || '',
          status(r.status), when(r.last_use_unix_ms), cell];
      }), true));
      const msg = txt('p', 'muted', '');
      const confirmBox = el('div', null);
      sec.appendChild(el('div', 'actions', btn('Undo whole project', 'danger', function () {
        confirmBox.replaceChildren(el('div', 'confirm',
          txt('p', null, 'Write every value back into this project’s files, and delete from morsec the keys no other project uses? You confirm with Touch ID.'),
          el('div', 'actions',
            btn('Undo whole project', 'danger', function () {
              run(msg, true, function () { return act('/api/projects/' + enc(p.slug) + '/undo', {}); }).then(function (x) {
                confirmBox.replaceChildren();
                if (x && x.undo) result.replaceChildren(undoResult(x.undo));
              });
            }),
            btn('Cancel', null, function () { confirmBox.replaceChildren(); }))));
      })));
      sec.appendChild(confirmBox);
      sec.appendChild(msg);
    }
    sec.appendChild(result);
    out.appendChild(sec);

    const code = section('Keys written into code');
    code.appendChild(list(p.findings.map(function (f) {
      return el('div', 'row', mono(f.path + ':' + f.line), txt('span', null, f.provider), mono(f.masked));
    }), 'None found.'));
    if (p.findings.length) code.appendChild(txt('p', 'muted', 'Move each into .env, then set the project up again (below).'));
    out.appendChild(code);

    if (p.committed.length) {
      const g = section('Committed to git');
      g.appendChild(list(p.committed.map(function (c) {
        return el('div', 'err', mono(c.path), ' was committed in ' + plural(c.commits, 'commit', 'commits') + ': the values in git history are not protected; rotate them at each provider.');
      }), ''));
      out.appendChild(g);
    }

    const dev = section('Run your app');
    dev.appendChild(txt('p', null, 'Start your own app through morsec so its requests can use the keys:'));
    if (p.dev_command) dev.appendChild(copyline(p.dev_command, 'Replace npm run dev with your command.'));
    out.appendChild(dev);
    const again = section('Set it up again');
    again.appendChild(txt('p', null, 'Re-scan the project after you add secrets or code. It runs in Terminal, where it reads your files.'));
    if (p.rescan_command) again.appendChild(copyline(p.rescan_command));
    if (p.hints.length) again.appendChild(el('p', 'muted', 'Agent hints in: ', mono(p.hints.join(', '))));
    again.appendChild(kv([['Set up', when(p.created_unix_ms)], ['Last scan', plural(p.scan_entries, 'file and folder', 'files and folders') + ' looked at']]));
    out.appendChild(again);
    return out;
  }

  // ---- a shown value (SPEC D-12) ------------------------------------------------------------
  let shown = null;
  // Control, bidi and invisible characters are shown escaped, so the text can't lie.
  const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]/gu;
  function visible(s) {
    let n = 0;
    const t = s.replace(INVISIBLE, function (c) { n++; return '\\u{' + c.codePointAt(0).toString(16) + '}'; });
    return [t, n];
  }
  function hideValue() {
    if (!shown) return;
    clearTimeout(shown.timer);
    shown.box.textContent = 'Hidden';
    shown.box.className = 'value hidden';
    if (shown.note) shown.note.textContent = '';
    if (shown.hide) shown.hide.hidden = true;
    shown = null;
  }
  window.addEventListener('blur', hideValue);
  window.addEventListener('pagehide', hideValue);
  window.addEventListener('hashchange', hideValue);
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') hideValue(); });

  function rulesSection(s) {
    const box = section('What it may do');
    box.appendChild(txt('p', 'muted', 'Adding a website, a command or a folder, or making it a test key, asks for Touch ID. Taking one away does not.'));
    const out = txt('p', 'muted', '');
    const edit = function (e) { return run(out, true, function () { return act('/api/keys/' + enc(s.key) + '/rules', { edit: e }); }).then(function (r) { if (r) after(900, render); }); };
    // `items` are what is shown; `values` what goes back to msd: for commands, their exact
    // words from the view, never the display string split again (review R1).
    const removable = function (items, kind, label, values) {
      return list(items.map(function (x, i) {
        return el('div', 'row', mono(x), btn('Remove', 'sm', function () {
          const e = {};
          e[kind] = kind === 'remove_command' ? { words: values[i] } : x;
          edit(e);
        }));
      }), 'None yet.' + (label ? ' ' + label : ''));
    };
    if (s.mode === 'run') {
      box.appendChild(txt('h3', null, 'Commands'));
      box.appendChild(removable(s.commands, 'remove_command', 'It is not usable until it has one.', s.command_words));
      const [cw, c] = textField('Add a command', 'command', 'One word per space, for example psql -c * . A word with a space or a quote needs ms rules ' + s.key + ' --add-command \'["…"]\' in Terminal.');
      const chips = el('div', 'chips');
      c.addEventListener('input', function () {
        chips.replaceChildren();
        for (const w of c.value.split(' ').filter(Boolean)) chips.appendChild(txt('span', null, w));
      });
      cw.appendChild(chips);
      box.appendChild(el('div', 'fields', cw, el('div', 'field act', btn('Add command', null, function () {
        const words = c.value.split(' ').filter(Boolean);
        if (words.length) edit({ add_command: { words: words } });
      }))));
      box.appendChild(txt('h3', 'section', 'Folders'));
      box.appendChild(removable(s.roots, 'remove_folder', ''));
      const [fw, f] = textField('Add a folder', 'folder', 'Its commands run only inside it, for example /Users/you/code/shop');
      box.appendChild(el('div', 'fields', fw, el('div', 'field act', btn('Add folder', null, function () {
        if (f.value.trim()) edit({ add_folder: f.value.trim() });
      }))));
    } else {
      box.appendChild(txt('h3', null, 'Websites'));
      box.appendChild(removable(s.hosts, 'remove_host', 'It is not usable until it has one.'));
      const [hw, h] = textField('Add a website', 'host', 'A host name: api.example.com, or *.example.com for every subdomain');
      box.appendChild(el('div', 'fields', hw, el('div', 'field act', btn('Add website', null, function () {
        if (h.value.trim()) edit({ add_host: h.value.trim() });
      }))));
    }
    box.appendChild(txt('h3', 'section', 'Tier'));
    box.appendChild(txt('p', null, s.tier === 'test' ? 'Test: agents use it without asking.' : 'Production: every use asks you first.'));
    box.appendChild(el('div', 'actions', s.tier === 'test'
      ? btn('Make it production (always ask)', null, function () { edit({ set_tier: 'production' }); })
      : btn('Make it test (never ask)', null, function () { edit({ set_tier: 'test' }); })));
    const ro = [];
    if (s.git_hosts.length) ro.push(['Git hosts', mono(s.git_hosts.join(', '))]);
    if (s.env.length) ro.push(['Variables', mono(s.env.join(', '))]);
    if (ro.length) box.appendChild(kv(ro));
    box.appendChild(el('p', 'muted', 'Git hosts, variables, SSH host keys and mint scopes change in Terminal: '));
    box.appendChild(copyline('ms rules ' + s.key));
    box.appendChild(out);
    return box;
  }

  async function secret(key) {
    const s = await api('/api/keys/' + enc(key));
    hideValue();
    const out = el('section', null);
    const crumbs = el('p', 'crumbs', link('/projects', 'Projects'));
    if (s.used_in.length) { crumbs.appendChild(txt('span', 'muted', ' / ')); crumbs.appendChild(link('/project/' + enc(s.used_in[0].project), s.used_in[0].project)); }
    out.appendChild(crumbs);
    const hero = el('div', 'hero');
    const h1 = slashed(txt('h1', 'mono keyname', ''), s.key);
    hero.appendChild(h1);
    hero.appendChild(el('p', 'lead', status(s.status)));
    hero.appendChild(kv([
      ['Provider', s.provider || 'unknown'],
      ['Tier', s.tier || 'no rule'],
      ['Used as', s.mode || 'no rule'],
      ['Added', when(s.created_unix_ms)],
    ]));
    out.appendChild(hero);

    // The value: hidden until Show (Touch ID), cleared after 15 s.
    const vs = section('Value');
    const box = txt('div', 'value hidden', s.stored ? 'Hidden' : 'Not in the vault');
    box.setAttribute('aria-live', 'polite');
    const note = txt('p', 'muted', '');
    const out2 = txt('p', 'muted', '');
    const hide = btn('Hide', null, hideValue);
    hide.hidden = true;
    vs.appendChild(txt('p', 'muted', 'Show and Copy ask for Touch ID on this Mac every time. A shown value hides after 15 seconds; a copied one leaves the clipboard after 30.'));
    vs.appendChild(box);
    vs.appendChild(note);
    if (s.stored) {
      vs.appendChild(el('div', 'actions',
        btn('Show', null, function () {
          run(out2, true, async function () {
            let r = await act('/api/keys/' + enc(s.key) + '/show');
            let [t, n] = visible(String(r.value));
            r.value = null;
            r = null;
            hideValue();
            box.textContent = t;
            t = null;
            box.className = 'value';
            note.textContent = n ? n + ' hidden or control characters are shown as \\u{…}.' : '';
            hide.hidden = false;
            shown = { box: box, note: note, hide: hide, timer: setTimeout(hideValue, 15000) };
            return { message: 'Shown for 15 seconds.' };
          });
        }),
        btn('Copy', null, function () { run(out2, true, function () { return act('/api/keys/' + enc(s.key) + '/copy'); }); }),
        hide));
      vs.appendChild(out2);
      // Replace: a hidden field outside any form, cleared as soon as it is sent.
      const [rw, rv] = secretField('New value (hidden)', 'value', 'Touch ID. The old value stays in use if storing the new one fails');
      const rout = txt('p', 'muted', '');
      vs.appendChild(el('div', 'fields', rw, el('div', 'field act', btn('Replace', null, function () {
        const body = { value: rv.value };
        rv.value = '';
        if (!body.value) { rout.className = 'err'; rout.textContent = 'Type the new value first.'; return; }
        run(rout, true, function () { return act('/api/keys/' + enc(s.key) + '/replace', body); });
        body.value = '';
      }))));
      vs.appendChild(rout);
    }
    out.appendChild(vs);
    if (s.mode) out.appendChild(rulesSection(s));

    const used = section('Where it is used');
    const uout = txt('p', 'muted', '');
    used.appendChild(list(s.used_in.map(function (u) {
      return el('div', 'row', link('/project/' + enc(u.project), u.project), mono(u.file + ':' + u.line), mono(u.var));
    }), 'No project file refers to it.'));
    const uresult = el('div', null);
    if (s.used_in.length) {
      used.appendChild(el('div', 'actions', btn('Undo this one', null, function () {
        run(uout, true, function () { return act('/api/keys/' + enc(s.key) + '/undo'); }).then(function (x) {
          if (x && x.undo) uresult.replaceChildren(undoResult(x.undo));
        });
      })));
      used.appendChild(txt('p', 'muted', 'Undo writes the value back into the files above and deletes the key when nothing else uses it.'));
    }
    used.appendChild(uout);
    used.appendChild(uresult);
    out.appendChild(used);

    if (s.stored || s.mode) {
      const del = section('Delete');
      const last = s.key.split('/').pop();
      const [dw, d] = textField('Type ' + last + ' to confirm', 'confirm', 'Deletes the value and its rule. This can’t be undone.');
      const dout = txt('p', 'muted', '');
      const extra = el('div', null);
      const doDelete = function (force) {
        if (d.value.trim().toLowerCase() !== last.toLowerCase()) { dout.className = 'err'; dout.textContent = 'Type ' + last + ' first.'; return; }
        run(dout, true, function () { return act('/api/keys/' + enc(s.key) + '/delete', { force: force }); }).then(function (r) {
          if (r) { after(1200, function () { location.hash = '#/projects'; }); return; }
          if (!force && dout.dataset.code === 'referenced') extra.replaceChildren(btn('Delete anyway', 'danger', function () { doDelete(true); }));
        });
      };
      del.appendChild(el('div', 'fields', dw, el('div', 'field act', btn('Delete key', 'danger', function () { doDelete(false); }))));
      del.appendChild(extra);
      del.appendChild(dout);
      out.appendChild(del);
    }

    const uses = section('Last 20 uses');
    uses.appendChild(activityTable(s.uses, true));
    out.appendChild(uses);
    return out;
  }

  // `oneKey`: the Secret screen's table, where every row is this key (no Key column: Q11).
  function activityTable(rows, oneKey) {
    if (!rows.length) return txt('p', 'muted', 'Nothing recorded.');
    const what = function (r) { return mono((r.mechanism ? r.mechanism + ' · ' : '') + r.target); };
    if (oneKey) {
      return table(['When', 'Agent', 'What', 'Result'], rows.map(function (r) {
        return [when(r.time_unix_ms), agentCell(r.agent, r.pid), what(r), result(r.result, r.reason)];
      }), true);
    }
    return table(['When', 'Agent', 'Key', 'What', 'Result'], rows.map(function (r) {
      return [when(r.time_unix_ms), agentCell(r.agent, r.pid), r.key ? ref(r.key) : '', what(r), result(r.result, r.reason)];
    }), true);
  }

  const FILTERS = ['since', 'project', 'key', 'agent', 'result'];
  async function activity(arg, q) {
    const f = { since: q.has('since') ? q.get('since') : '24h' };
    for (const k of FILTERS.slice(1)) f[k] = q.get(k) || '';
    const query = FILTERS.filter(function (k) { return f[k]; }).map(function (k) { return k + '=' + enc(f[k]); }).join('&');
    const out = el('section', null);
    out.appendChild(el('div', 'hero', txt('h1', null, 'Activity'), txt('p', 'lead', 'Every use of a key, every refusal, and everything done here, as msd recorded it.')));
    let v = null;
    let error = null;
    try { v = await api('/api/activity?' + query); } catch (e) { if (e instanceof SignedOut) throw e; error = e; }
    const [sw, since] = select('Since', 'since', [['1h', 'the last hour'], ['24h', 'the last 24 hours'], ['7d', 'the last 7 days'], ['30d', 'the last 30 days'], ['', 'everything']], f.since);
    const [pw, proj] = select('Project', 'project', [['', 'any']].concat((v ? v.projects : []).map(function (s) { return [s, s]; })), f.project);
    const [kw, key] = textField('Key', 'key', 'For example shop/stripe-secret-key');
    key.value = f.key;
    const [aw, agent] = select('Agent', 'agent', [['', 'any'], ['claude-code', 'Claude Code'], ['codex', 'Codex'], ['terminal', 'Terminal'], ['dashboard', 'Dashboard'], ['ms-dev', 'ms dev'], ['other', 'other']], f.agent);
    const [rw, res] = select('Result', 'result', [['', 'any'], ['allowed', 'allowed'], ['approved', 'approved'], ['blocked', 'blocked'], ['denied', 'denied'], ['failed', 'failed'], ['alert', 'alert']], f.result);
    const apply = btn('Apply', 'solid', function () {
      const n = { since: since.value, project: proj.value, key: key.value.trim(), agent: agent.value, result: res.value };
      const parts = FILTERS.map(function (k) { return k + '=' + enc(n[k]); });
      location.hash = '#/activity?' + parts.join('&');
    });
    out.appendChild(el('div', 'fields', sw, pw, kw, aw, rw, el('div', 'field act', apply)));
    const verdict = txt('p', 'muted', '');
    out.appendChild(el('div', 'actions',
      btn('Verify the chain', null, async function () {
        verdict.className = 'muted';
        verdict.textContent = 'Checking…';
        try {
          const r = await api('/api/activity/verify');
          verdict.textContent = r.text;
          verdict.className = r.ok ? 'signal' : 'err';
        } catch (e) { fail(e, verdict); }
      }),
      btn('Export JSON', null, async function () { try { await download('/api/activity/export?format=json&' + query, 'morsec-receipts.json'); } catch (e) { fail(e, verdict); } }),
      btn('Export CSV', null, async function () { try { await download('/api/activity/export?format=csv&' + query, 'morsec-receipts.csv'); } catch (e) { fail(e, verdict); } })));
    out.appendChild(verdict);
    if (error) {
      out.appendChild(txt('p', 'err section', (error.message || 'The filter could not be applied.') + ' Change the filters and press Apply.'));
      return out;
    }
    out.appendChild(txt('p', 'muted section count', v.rows.length < v.matched
      ? 'Showing ' + num(v.rows.length) + ' of ' + num(v.matched) + '. Narrow the filters to see older ones.'
      : 'Showing ' + num(v.rows.length) + ' of ' + num(v.matched) + '.'));
    out.appendChild(activityTable(v.rows));
    return out;
  }

  function agentsBody(v) {
    const out = el('div', null);
    const g = el('div', 'cards');
    for (const a of v.agents) {
      const c = el('div', 'card');
      c.appendChild(txt('h3', null, a.name));
      c.appendChild(kv([
        ['Installed', a.installed ? 'yes' : 'no'],
        ['Connected', a.connected ? badge('connected', 'good') : badge('not connected', a.installed ? 'bad' : '')],
        ['Sessions', num(a.sessions)],
        ['Blocked', num(a.blocked)],
        ['Last seen', when(a.last_seen_unix_ms)],
      ]));
      if (a.command) c.appendChild(txt('p', 'muted', a.connected
        ? 'Disconnecting removes its sandbox and proxy settings; you confirm the change in Terminal.'
        : 'Connecting edits its settings; Terminal shows the change and asks first.'));
      if (a.command) c.appendChild(copyline(a.command, 'then press Re-check'));
      else c.appendChild(txt('p', 'muted', 'Install ' + a.name + ' first; then it can be connected here.'));
      g.appendChild(c);
    }
    out.appendChild(g);
    if (v.warnings.length) {
      const w = section('Warnings');
      for (const x of v.warnings) w.appendChild(warningBox(x));
      out.appendChild(w);
    }
    const ch = section('msd’s checks');
    const ul = el('ul', 'plain checks');
    for (const c of v.checks) {
      const li = txt('li', c.ok ? null : 'bad', c.text);
      ul.appendChild(li);
    }
    ch.appendChild(v.checks.length ? ul : txt('p', 'muted', 'No checks.'));
    ch.appendChild(txt('p', 'muted', 'The full check, including each agent’s settings, runs in Terminal:'));
    ch.appendChild(copyline('ms doctor'));
    out.appendChild(ch);
    return out;
  }

  async function agents() {
    const v = await api('/api/agents');
    const out = el('section', null);
    out.appendChild(el('div', 'hero', txt('h1', null, 'Agents'), txt('p', 'lead', 'Which coding agents send their requests through morsec.')));
    const msg = txt('p', 'muted', '');
    const body = el('div', null, agentsBody(v));
    out.appendChild(el('div', 'actions section', btn('Re-check', 'solid', function () {
      run(msg, false, async function () {
        const r = await act('/api/agents/recheck');
        return { message: recheckMessage(r), agents: r.agents };
      }).then(function (r) {
        if (r && r.agents) body.replaceChildren(agentsBody(r.agents));
      });
    })));
    out.appendChild(msg);
    out.appendChild(body);
    return out;
  }

  function scanBody(v) {
    const out = el('div', null);
    if (v.running) out.appendChild(txt('p', 'waiting', 'Scanning…'));
    if (v.error) out.appendChild(txt('p', 'err', v.error.replace(/^morsec: /, '')));
    const s = v.last;
    if (!s) {
      if (!v.running) out.appendChild(txt('p', 'muted', 'No scan since msd started.'));
      return out;
    }
    out.appendChild(kv([
      ['Ran', when(s.at_unix_ms)],
      ['Read', plural(s.files_scanned, 'file', 'files') + ', ' + num(s.bytes_scanned) + ' bytes'],
      ['Keys searched', num(s.keys_checked)],
      ['Complete', s.complete ? 'yes' : 'no: some files were not read'],
    ]));
    out.appendChild(txt('h2', null, s.findings.length ? 'Found' : 'Nothing found'));
    if (s.findings.length) {
      out.appendChild(table(['Transcript', 'Line', 'Key', 'Form'], s.findings.map(function (f) {
        return [mono(f.file), num(f.line), ref(f.key), f.encoding];
      }), true));
      out.appendChild(txt('p', 'err', 'Each key found leaked into a transcript: rotate it at its provider, then replace it here.'));
    }
    if (s.skipped_keys.length) out.appendChild(el('p', 'muted', 'Too short to search: ', mono(s.skipped_keys.join(', '))));
    if (s.notes.length) out.appendChild(list(s.notes, ''));
    return out;
  }

  async function scan() {
    const v = await api('/api/scan');
    const out = el('section', null);
    out.appendChild(el('div', 'hero', txt('h1', null, 'Leak scan'), txt('p', 'lead', 'Searches your agents’ transcripts for your keys’ values. It reads every value, so it asks for Touch ID.')));
    const msg = txt('p', 'muted', '');
    const body = el('div', null, scanBody(v));
    const poll = async function () {
      try {
        const n = await api('/api/scan');
        body.replaceChildren(scanBody(n));
        if (n.running) after(2000, poll);
      } catch (e) { fail(e, msg); }
    };
    if (v.running) after(2000, poll);
    out.appendChild(el('div', 'actions section', btn('Run scan', 'solid', function () {
      run(msg, true, function () { return act('/api/scan/run'); }).then(function (r) { if (r) poll(); });
    })));
    out.appendChild(msg);
    out.appendChild(body);
    return out;
  }

  // ---- router -------------------------------------------------------------------------------
  const routes = {
    '/': home,
    '/projects': projects,
    '/project': project,
    '/secret': secret,
    '/activity': activity,
    '/agents': agents,
    '/scan': scan,
  };

  function parseHash() {
    const h = location.hash.replace(/^#/, '');
    const qi = h.indexOf('?');
    const path = qi >= 0 ? h.slice(0, qi) : h;
    const q = new URLSearchParams(qi >= 0 ? h.slice(qi + 1) : '');
    const parts = path.split('/').filter(Boolean);
    const name = parts.length ? '/' + parts[0] : '/';
    let arg = '';
    try { arg = parts.slice(1).map(decodeURIComponent).join('/'); } catch (e) { arg = ''; }
    return [name, arg, q];
  }

  function fail(e, where) {
    if (e instanceof SignedOut) { signedOut(e.message); return; }
    const m = e && e.message ? e.message.replace(/^morsec: /, '') : 'Something went wrong.';
    if (where) { where.textContent = m; where.className = 'err'; return; }
    main.replaceChildren(el('section', null,
      txt('h1', null, 'This screen could not load.'),
      txt('p', 'lead err', m),
      el('div', 'actions section', btn('Try again', 'solid', render), link('/', 'Home', 'btn'))));
  }

  let seq = 0;
  async function render() {
    hideValue();
    live.textContent = '';
    for (const t of timers) clearTimeout(t);
    timers = [];
    const [name, arg, q] = parseHash();
    const view = Object.prototype.hasOwnProperty.call(routes, name) ? routes[name] : null;
    for (const a of document.querySelectorAll('#nav a')) {
      if (a.getAttribute('data-route') === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    const mine = ++seq;
    if (!view) { main.replaceChildren(el('section', null, txt('h1', null, 'No such screen.'), link('/', 'Go to Home', 'btn'))); return; }
    main.setAttribute('aria-busy', 'true');
    if (!main.firstChild || main.firstChild.nodeName !== 'SECTION') main.replaceChildren(txt('p', 'muted', 'Loading…'));
    try {
      const node = await view(arg, q);
      if (mine === seq) { main.replaceChildren(node); main.focus({ preventScroll: true }); }
      if (name !== '/') {
        try { const h = await api('/api/home'); if (mine === seq) setRunning(h.running, h.version); } catch (e) { /* the screen shows its own state */ }
      }
    } catch (e) {
      if (mine === seq) fail(e);
    } finally {
      main.removeAttribute('aria-busy');
    }
  }

  function signedOut(why) {
    hideValue();
    state.csrf = null;
    state.running = null;
    stateBox.replaceChildren();
    const s = el('section', null);
    s.appendChild(txt('h1', null, 'Open the dashboard from Terminal.'));
    if (why === 'closed') s.appendChild(txt('p', 'lead', 'The dashboard closed: it was idle for 30 minutes, or morsec stopped.'));
    if (why === 'another tab') s.appendChild(txt('p', 'lead', 'It was opened again in another tab, which signed this one out.'));
    s.appendChild(el('p', 'lead', 'This page signs in with a one-time link that works once, for a minute. Run this to get a new one:'));
    s.appendChild(copyline('ms dashboard'));
    main.replaceChildren(s);
  }

  async function boot() {
    const frag = new URLSearchParams(location.hash.replace(/^#/, ''));
    const token = frag.get('t');
    if (token) {
      const v = frag.get('v') || '';
      const target = /^(projects|activity|agents|scan|project\/[A-Za-z0-9%._~-]+)?$/.test(v) ? v : '';
      // The token leaves the address bar and history before it is used.
      history.replaceState(null, '', location.pathname + '#/' + target);
      try {
        const r = await fetch('/api/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token }),
          credentials: 'same-origin',
          cache: 'no-store',
          redirect: 'error',
        });
        if (r.ok) state.csrf = (await r.json()).csrf;
      } catch (e) { state.csrf = null; }
    }
    if (!state.csrf) { signedOut(); return; }
    window.addEventListener('hashchange', render);
    render();
  }

  boot();
})();
