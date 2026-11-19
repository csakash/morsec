// morsec dashboard (L33 dash-actions). Plain script, no framework, nothing fetched but /api/.
// Every string from a file, an agent or a user reaches the page through textContent only
// (design §6.3); links are built from fixed routes and encodeURIComponent. The page never raises
// Touch ID: msd does, for every action that loosens, starts, reads or changes a value. A value
// msd shows is written into one element, never stored, logged or put in the URL, and cleared
// after 15 s, on blur, when the page is hidden, on pagehide and on navigation (SPEC D-12).
// The look is the landing page's (site/src/shared.css): one ruled sheet of cells, a rail of the
// five screens on the left, breadcrumbs on inner screens, whole rows that open what they name.
'use strict';

(function () {
  const state = { csrf: null, running: null, version: '' };
  const main = document.getElementById('main');
  const stateBox = document.getElementById('state');
  const live = document.querySelector('#live p');
  const ver = document.getElementById('ver');
  // Timers of the current screen (countdowns, scan polling); cleared on every render.
  let timers = [];

  // ---- theme: the landing page's toggle. The one thing this page keeps in the browser is the
  // choice itself, 'light' or 'dark' under THEME_KEY: never a value, never anything from msd.
  const THEME_KEY = 'morsec.dashboard.theme';
  function savedTheme() {
    try {
      const t = window.localStorage.getItem(THEME_KEY);
      return t === 'light' || t === 'dark' ? t : null;
    } catch (e) { return null; }
  }
  function saveTheme(t) {
    try { window.localStorage.setItem(THEME_KEY, t === 'dark' ? 'dark' : 'light'); } catch (e) { /* the choice lasts this page */ }
  }
  (function () {
    const root = document.documentElement;
    const t = savedTheme();
    if (t) root.dataset.theme = t;
    const b = document.getElementById('theme');
    if (b) {
      b.addEventListener('click', function () {
        const dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
        root.dataset.theme = dark ? 'light' : 'dark';
        saveTheme(root.dataset.theme);
      });
    }
    const host = document.getElementById('host');
    if (host) host.textContent = location.host;
  })();

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
  // The landing page's corner arrow, cloned from the page's own <template>.
  const arrowTpl = document.getElementById('t-arrow');
  function arrow() { return arrowTpl.content.firstElementChild.cloneNode(true); }
  // A link drawn as a button, with the arrow: it goes somewhere.
  function linkBtn(route, label, cls) {
    const a = link(route, '', 'btn' + (cls ? ' ' + cls : ''));
    a.appendChild(txt('span', null, label));
    a.appendChild(arrow());
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
  function num(n) { return Number(n || 0).toLocaleString(); }
  function pad(n) { return String(n).padStart(2, '0'); }
  function plural(n, one, many) { return num(n) + ' ' + (Number(n) === 1 ? one : many); }
  function lastPart(key) { return String(key).split('/').pop(); }
  let liveTimer = null;
  function announce(msg) {
    live.textContent = msg;
    clearTimeout(liveTimer);
    liveTimer = setTimeout(function () { live.textContent = ''; }, 6000);
  }
  function after(ms, f) { const t = setTimeout(f, ms); timers.push(t); return t; }

  // Buttons are type=button; the landing page's .btn, .btn.solid, .btn.sm, and .btn.deny for
  // what destroys.
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
  function choice(label, name, options, current) {
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

  // ---- the sheet: ruled rows of cells, as on the landing page --------------------------------
  function sheet() { return el('div', 'sheet'); }
  // The label column: an uppercase label on top, the section's number at the bottom.
  function side(label, n, extra) {
    const c = el('div', 'cell side', txt('span', 'lbl', label));
    if (extra) c.appendChild(extra);
    if (n) c.appendChild(txt('span', 'num', n));
    return c;
  }
  // A section head: label | big upright heading and a lede.
  function head(label, title, lede, n, opts) {
    const o = opts || {};
    const right = el('div', 'cell');
    const h = o.heading || txt('h2', null, title);
    right.appendChild(h);
    if (lede) right.appendChild(lede instanceof Node ? lede : txt('p', 'lede', lede));
    if (o.after) right.appendChild(o.after);
    return el('section', 'row head', side(label, n, o.sideExtra), right);
  }
  // A content row: label | body. Returns [row, body]; `id` is the anchor results show under.
  function part(label, id, n) {
    const body = el('div', 'cell body');
    if (id) body.id = id;
    return [el('section', 'row split', side(label, n), body), body];
  }
  // A full-width row for a table.
  function wide(id) {
    const c = el('div', 'cell');
    if (id) c.id = id;
    return [el('section', 'row wide', c), c];
  }
  // Breadcrumbs on inner screens: PROJECTS / SHOP / STRIPE-SECRET-KEY, each a link.
  function crumbs(parts) {
    const c = el('div', 'cell');
    parts.forEach(function (p, i) {
      if (i) c.appendChild(txt('span', 'lbl sep', '/'));
      const a = link(p[0], p[1], 'lbl');
      if (i === parts.length - 1) a.setAttribute('aria-current', 'page');
      c.appendChild(a);
    });
    const n = el('nav', 'row crumbs', c);
    n.setAttribute('aria-label', 'Breadcrumb');
    return n;
  }
  // The small heading of a cell: number, uppercase title, short rule.
  function cap(n, title) { return el('div', 'cap', txt('span', 'num', n), txt('h3', null, title), el('span', 'rule')); }

  // Tables: ticker rows with an index; a row with `href` opens it when clicked anywhere, and its
  // arrow is the link for the keyboard. They stack into labelled rows under 720 px.
  function table(headers, rows, opts) {
    const o = opts || {};
    const t = el('table', 'led stack');
    const thead = el('thead', null);
    const hr = el('tr', null);
    if (o.num) hr.appendChild(txt('th', null, '#'));
    for (const h of headers) hr.appendChild(txt('th', null, h));
    if (o.go) hr.appendChild(el('th', null, txt('span', 'vh', 'Open')));
    thead.appendChild(hr);
    t.appendChild(thead);
    const tb = el('tbody', null);
    rows.forEach(function (r, ri) {
      const cells = Array.isArray(r) ? r : r.cells;
      const href = Array.isArray(r) ? null : r.href;
      const tr = el('tr', href ? 'go' : null);
      if (o.num) {
        const td = txt('td', 'i', pad(ri + 1));
        td.setAttribute('data-label', '#');
        tr.appendChild(td);
      }
      cells.forEach(function (c, i) {
        const td = c instanceof Node ? el('td', null, c) : txt('td', null, c);
        td.setAttribute('data-label', headers[i]);
        tr.appendChild(td);
      });
      if (o.go) {
        const td = el('td', 'go');
        td.setAttribute('data-label', '');
        if (href) {
          const a = link(href.replace(/^#/, ''), '', null);
          a.setAttribute('aria-label', 'Open');
          a.appendChild(arrow());
          td.appendChild(a);
          tr.addEventListener('click', function (e) {
            if (e.target.closest('a, button, summary') || String(window.getSelection())) return;
            location.hash = href;
          });
        }
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    return el('div', 'tw', t);
  }
  function tag(s, kind) { return txt('span', 'tag' + (kind ? ' ' + kind : ''), s); }
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
  function kv(pairs, cls) {
    const d = el('dl', 'kv' + (cls ? ' ' + cls : ''));
    for (const [k, v] of pairs) {
      d.appendChild(txt('dt', null, k));
      const dd = el('dd', null);
      if (v instanceof Node) dd.appendChild(v); else dd.textContent = v === null || v === undefined ? '' : String(v);
      d.appendChild(dd);
    }
    return d;
  }
  // A ruled mono list with a muted index; `empty` when there is nothing.
  function list(items, empty, cls) {
    if (!items || items.length === 0) return txt('p', 'muted', empty);
    const u = el('ol', 'list' + (cls ? ' ' + cls : ''));
    items.forEach(function (i, n) {
      const li = el('li', null);
      if (!cls) li.appendChild(txt('span', 'num', pad(n + 1)));
      if (i instanceof Node) li.appendChild(i); else li.appendChild(txt('span', 'grow', String(i)));
      u.appendChild(li);
    });
    return u;
  }
  // A list whose rows each open something: the whole row is the link, with the arrow.
  function linkList(items, empty) {
    if (!items || items.length === 0) return txt('p', 'muted', empty);
    const u = el('ol', 'list');
    items.forEach(function (it, n) {
      const a = link(it.route, '', 'lrow');
      a.appendChild(txt('span', 'num', pad(n + 1)));
      for (const p of it.parts) a.appendChild(p);
      a.appendChild(arrow());
      u.appendChild(el('li', 'go', a));
    });
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
  // A command msd built, in the landing page's command box: a bar with a label and Copy, then
  // the numbered line. The page's own text, never a value.
  function copyline(command, note, label) {
    const copy = txt('button', 'copy', 'Copy');
    copy.setAttribute('type', 'button');
    copy.addEventListener('click', async function () {
      try {
        await navigator.clipboard.writeText(command);
        announce('Copied the command. Paste it into Terminal.');
        copy.textContent = 'Copied';
        setTimeout(function () { copy.textContent = 'Copy'; }, 1200);
      } catch (e) {
        announce('Copy did not work here: select the command and copy it.');
      }
    });
    const line = el('div', 'l', txt('span', 'ln', '1'), el('code', 'cmd', txt('span', 'p', '$'), document.createTextNode(command)));
    const box = el('div', 'cbox', el('div', 'cb', txt('span', 'lbl', label || 'Terminal'), copy), line);
    if (note) box.appendChild(txt('div', 'cn', note));
    return box;
  }

  // One visible result after an action that redraws the screen (P2): shown at the top of the
  // cell the action belongs to (or in a row of its own at the top of the screen), until the next
  // action or navigation.
  let flash = null;
  function rerender(anchor, r, node, nav) {
    if (r) flash = { anchor: anchor, text: sentence(r.message || 'Done.'), node: node || null, nav: !!nav };
    if (nav) { location.hash = nav; return; }
    render();
  }
  // Only one result line on a screen: a new one clears the others (V1).
  function clearResults(except) {
    for (const r of main.querySelectorAll('p.result, span.result')) {
      if (r !== except) { r.textContent = ''; r.className = r.className.replace(/\b(signal|err) result\b/, '').trim(); }
    }
    for (const n of main.querySelectorAll('.row.note')) if (!except || !n.contains(except)) n.remove();
  }
  function showFlash() {
    if (!flash) return;
    const f = flash;
    flash = null;
    const top = main.querySelector('.sheet');
    if (!top) return;
    clearResults();
    const p = txt('p', (f.err ? 'err' : 'signal') + ' result', f.text);
    const target = f.anchor && document.getElementById(f.anchor);
    if (target) {
      const head = target.querySelector(':scope > .cap, :scope > .bar, :scope > h2, :scope > h3');
      if (head) head.after(p); else target.prepend(p);
    } else {
      // Stop, Start and a whole-project Undo report at the top of the page, below the header,
      // so the sticky header never grows (V2).
      const r = el('div', 'row note', el('div', 'cell', p));
      const c = top.querySelector(':scope > .crumbs');
      if (c) c.after(r); else top.prepend(r);
    }
    if (f.node) p.after(f.node);
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
  // A message as one sentence: capitalised (but "morsec" stays lowercase) and ended with a
  // full stop (P6).
  function sentence(m) {
    let t = String(m || '').replace(/^morsec: /, '').trim();
    if (!t) return t;
    if (!/^morsec\b/.test(t)) t = t.charAt(0).toUpperCase() + t.slice(1);
    return /[.!?…)'"]$/.test(t) ? t : t + '.';
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
      clearResults(out);
      out.className = 'signal result';
      out.textContent = r && r.message ? sentence(r.message) : 'Done.';
      announce(out.textContent);
      return r;
    } catch (e) {
      if (e instanceof SignedOut) { signedOut(e.message); return null; }
      clearResults(out);
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
  // The outcome of Stop or Start shows at the top of the page until the next navigation (F1).
  let stateNote = null;
  function renderState() {
    if (state.running === null) { stateBox.replaceChildren(); return; }
    if (state.running) {
      stateBox.replaceChildren(txt('span', 'lbl st on', 'On'), btn('Stop', 'sm solid', confirmStop));
    } else {
      stateBox.replaceChildren(txt('span', 'lbl st off', 'Stopped'), btn('Start', 'sm solid', start));
    }
    // The outcome of Stop or Start shows at the top of the page, below the header, so the
    // sticky header never grows (V2).
    if (stateNote) { flash = { anchor: null, text: stateNote.text, node: null, nav: false, err: stateNote.err }; stateNote = null; }
  }
  function confirmStop() {
    const msg = txt('span', 'lbl ask', 'Stop every agent’s access?');
    const yes = btn('Stop now', 'sm deny', async function () {
      yes.disabled = true;
      try {
        const r = await act('/api/stop');
        state.running = false;
        stateNote = { text: 'Stopped. Every agent request is refused.', err: false };
        announce(sentence(r.message || 'morsec stopped.'));
      } catch (e) {
        if (e instanceof SignedOut) { signedOut(e.message); return; }
        stateNote = { text: sentence(e.message), err: true };
        announce(stateNote.text);
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
      stateNote = { text: 'Started with Touch ID.', err: false };
      announce(sentence(r.message || 'morsec is on.'));
    } catch (e) {
      if (e instanceof SignedOut) { signedOut(e.message); return; }
      stateNote = { text: sentence(e.message), err: true };
      announce(stateNote.text);
    }
    renderState();
    render();
  }
  function setRunning(running, version) {
    state.running = running;
    if (version) { state.version = version; ver.textContent = 'msd ' + version; }
    renderState();
  }

  // ---- the rail: five numbered screens, their counts, the projects and the open one's keys ----
  let railCtx = {};
  let railSeq = 0;
  function count(id, n, hot) {
    const c = document.getElementById(id);
    if (!c) return;
    c.textContent = n ? num(n) : '';
    c.className = 'c' + (hot && n ? ' hot' : '');
  }
  async function refreshRail() {
    const mine = ++railSeq;
    const ctx = railCtx;
    let h = null;
    let pv = null;
    try {
      [h, pv] = await Promise.all([api('/api/home'), api('/api/projects')]);
    } catch (e) { return; /* the screen shows its own state */ }
    if (mine !== railSeq) return;
    setRunning(h.running, h.version);
    count('c-home', needCount(h), true);
    count('c-projects', h.projects, false);
    count('c-activity', h.blocked_24h, true);
    count('c-agents', h.agents.filter(function (a) { return a.connected; }).length, false);
    let keys = ctx.keys || null;
    if (ctx.project && !keys) {
      try { keys = (await api('/api/projects/' + enc(ctx.project))).rows.map(function (r) { return r.key; }); } catch (e) { keys = []; }
      if (mine !== railSeq) return;
    }
    const sub = document.getElementById('sub-projects');
    sub.replaceChildren();
    for (const p of pv.projects) {
      const li = el('li', null);
      const a = link('/project/' + enc(p.slug), p.display);
      a.setAttribute('title', p.root);
      if (ctx.project === p.slug && !ctx.key) a.setAttribute('aria-current', 'page');
      li.appendChild(a);
      if (ctx.project === p.slug && keys && keys.length) {
        const ks = el('ol', 'sub');
        for (const k of Array.from(new Set(keys))) {
          const ka = link('/secret/' + enc(k), lastPart(k));
          ka.setAttribute('title', k);
          if (ctx.key === k) ka.setAttribute('aria-current', 'page');
          ks.appendChild(el('li', null, ka));
        }
        li.appendChild(ks);
      }
      sub.appendChild(li);
    }
  }
  function needCount(h) {
    return (h.pending ? 1 : 0) + h.warnings.length + (h.projects_unreadable ? 1 : 0) + (h.not_usable.length ? 1 : 0);
  }

  // ---- warnings and the waiting request (SPEC D-10, D-11) -------------------------------------
  // "Checked just now · 3 checks fine, 1 needs you" after a Re-check (review Q8).
  function recheckMessage(r) {
    const v = r && r.agents ? r.agents : { checks: [], warnings: [] };
    const fine = v.checks.filter(function (c) { return c.ok; }).length;
    const bad = v.checks.length - fine + v.warnings.length;
    return 'Checked just now · ' + plural(fine, 'check', 'checks') + ' fine' + (bad ? ', ' + num(bad) + ' still need' + (bad === 1 ? 's' : '') + ' you' : '');
  }

  // One item of Needs you: index, title, then its body; the primary action is a button in it.
  function need(cls, n, title) {
    return el('div', 'need' + (cls ? ' ' + cls : ''), el('div', 'nh', txt('span', 'num', n), txt('h3', null, title)));
  }

  // A warning: red only when something is blocked or failing; informational ones are quiet.
  // The fix is the primary button, Dismiss a quiet one after it (review Q12).
  function warningBox(w, n) {
    const b = need(w.dismiss ? null : 'warn', n, w.title);
    // Paths in the detail break only after "/" (V5).
    if (w.detail) b.appendChild(slashed(txt('p', null, ''), w.detail));
    const out = txt('p', 'muted', '');
    const acts = el('div', 'actions');
    for (const f of w.fix) {
      if (f.action && f.label) {
        const route = f.action;
        acts.appendChild(btn(f.label, 'sm solid', function () {
          run(out, false, async function () {
            const r = await act(route);
            return { message: route === '/api/agents/recheck' ? recheckMessage(r) : r.message };
          }).then(function (r) { if (r) rerender('needs', r); });
        }));
      }
    }
    for (const f of w.fix) if (f.command) b.appendChild(copyline(f.command, 'Run it in Terminal.'));
    if (w.dismiss) {
      acts.appendChild(btn('Dismiss', 'sm ghost', function () {
        run(out, false, function () { return act('/api/warnings/' + enc(w.id) + '/dismiss'); }).then(function (r) { if (r) rerender('needs', r); });
      }));
    }
    if (acts.childNodes.length) b.appendChild(acts);
    b.appendChild(out);
    return b;
  }

  // The request waiting for the person: what it asks in plain words first, the exact command
  // folded away, empty fields left out (review Q1). Who asked is named when it is not an agent
  // session (review S4); morsec's own actions are approved once only (review S2).
  function pendingCard(p, n) {
    const b = need('focus', n, p.from_agent ? p.agent + ' is waiting for you' : 'A request is waiting for you');
    b.appendChild(txt('p', 'summary', p.summary));
    const facts = [['Key', ref(p.key)], ['Tier', p.tier]];
    if (!p.from_agent && p.requester) {
      facts.push(['Asked by', el('span', null, txt('span', null, p.requester),
        txt('span', 'muted', ' The program name is what the process called itself; it does not prove who asked.'))]);
    }
    if (p.cwd) facts.push(['Folder', pathText(p.cwd)]);
    if (p.effect) facts.push(['What it does', txt('span', null, p.effect)]);
    b.appendChild(kv(facts));
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
      const done = function (r) { if (r) rerender('needs', r); };
      const acts = el('div', 'actions',
        btn('Approve once', 'sm solid', function () { run(out, true, function () { return act('/api/approvals/' + enc(id) + '/approve', { scope: 'once' }); }).then(done); }));
      if (!p.once_only) {
        acts.appendChild(btn('Approve for this session', 'sm', function () { run(out, true, function () { return act('/api/approvals/' + enc(id) + '/approve', { scope: 'session' }); }).then(done); }));
      }
      acts.appendChild(btn('Deny', 'sm deny', function () { run(out, false, function () { return act('/api/approvals/' + enc(id) + '/deny'); }).then(done); }));
      b.appendChild(acts);
    }
    b.appendChild(left);
    b.appendChild(out);
    const d = el('details', 'more');
    // Anything that is not morsec's own request is shown exactly, open (SR1).
    if (p.expand) d.open = true;
    d.appendChild(el('summary', null, txt('span', 'num', '+'), txt('span', 't', 'The exact request (' + plural(p.command.length, 'part', 'parts') + ')')));
    const ol = el('ol', 'argv');
    p.command.forEach(function (a, i) { ol.appendChild(txt('li', null, '[' + i + '] ' + a)); });
    d.appendChild(ol);
    b.appendChild(d);
    return b;
  }

  // ---- screens ------------------------------------------------------------------------------
  // A static Morse line under Home's hero, the landing page's band without the motion.
  const MORSE = { a: '.-', b: '-...', c: '-.-.', d: '-..', e: '.', f: '..-.', g: '--.', h: '....', i: '..', k: '-.-', l: '.-..', m: '--', n: '-.', o: '---', p: '.--.', r: '.-.', s: '...', t: '-', u: '..-', v: '...-', w: '.--', y: '-.--' };
  function band(text) {
    const track = el('div', 'track');
    for (const ch of text) {
      if (ch === ' ') { track.appendChild(el('span', 'sp')); continue; }
      const code = MORSE[ch];
      if (!code) continue;
      const m = el('span', 'm');
      for (const s of code) m.appendChild(el('i', s === '-' ? 'l' : 'd'));
      track.appendChild(el('span', 'ch', m, txt('b', null, ch.toUpperCase())));
    }
    const r = el('div', 'row band', el('div', null, track));
    r.setAttribute('aria-hidden', 'true');
    return r;
  }

  function projectTiles(cards) {
    const g = el('div', 'tiles');
    cards.forEach(function (p, i) {
      const t = link('/project/' + enc(p.slug), '', 'tile');
      t.appendChild(el('div', 'tt', txt('span', 'num', pad(i + 1)), arrow()));
      t.appendChild(txt('h3', null, p.display));
      t.appendChild(el('span', 'rule'));
      t.appendChild(pathText(p.root, 'path'));
      const flags = el('div', 'flags');
      if (p.findings) flags.appendChild(txt('span', null, plural(p.findings, 'key in code', 'keys in code')));
      if (p.committed_files) flags.appendChild(txt('span', null, 'committed to git'));
      if (p.stopped_early) flags.appendChild(txt('span', null, 'scan stopped early'));
      if (flags.childNodes.length) t.appendChild(flags);
      t.appendChild(txt('p', 'counts', num(p.protected) + ' protected · ' + num(p.needs_website) + ' not usable yet'));
      g.appendChild(t);
    });
    return el('section', 'row', el('div', 'tilewrap', g));
  }

  async function home() {
    const [h, pv] = await Promise.all([api('/api/home'), api('/api/projects')]);
    setRunning(h.running, h.version);
    const out = sheet();

    const h1 = el('h1', null);
    h1.append('morsec is ', txt('em', 'it', h.running ? 'on' : 'stopped'), '.');
    const left = el('div', 'hero-l',
      el('div', 'top-lbl', txt('span', 'lbl', 'Secret broker · this Mac'), txt('span', 'lbl m', h.version ? 'msd ' + h.version : '')),
      h1,
      txt('p', 'lede', h.running
        ? 'Agents use your keys without seeing them. Production keys still wait for your Touch ID.'
        : 'Every agent request is refused until you start it again.'),
      h.running
        ? el('div', 'ctas', linkBtn('/activity', 'Activity', 'solid'), linkBtn('/projects', 'Projects'))
        : el('div', 'ctas', btn('Start with Touch ID', 'solid', start), linkBtn('/activity', 'Activity')));

    const needs = el('div', 'needs');
    needs.id = 'needs';
    const items = [];
    let n = 0;
    const next = function () { return pad(++n); };
    if (h.pending) items.push(pendingCard(h.pending, next()));
    for (const w of h.warnings) items.push(warningBox(w, next()));
    if (h.projects_unreadable) {
      items.push(warningBox({ id: '', title: 'Project records failed their check', detail: 'Undo is off until they are fixed. Keys and rules keep working.', fix: [{ command: 'ms doctor' }], dismiss: false }, next()));
    }
    if (h.not_usable.length) {
      const b = need(null, next(), 'Keys that are not usable yet');
      b.appendChild(txt('p', 'muted', 'An agent can’t use these until you give each a website or a command.'));
      b.appendChild(linkList(h.not_usable.map(function (k) {
        return { route: '/secret/' + enc(k.key), parts: [el('span', 'grow', slashed(txt('span', 'ref', ''), k.key)), status(k.status)] };
      }), ''));
      if (h.needs_website > h.not_usable.length) {
        b.appendChild(linkBtn('/projects?show=not-usable', 'And ' + num(h.needs_website - h.not_usable.length) + ' more', 'sm'));
      }
      items.push(b);
    }
    needs.appendChild(el('div', 'bar', txt('span', 'lbl', 'Needs you'), txt('span', 'lbl m', items.length ? plural(items.length, 'item', 'items') : 'All clear')));
    for (const it of items) needs.appendChild(it);
    if (items.length === 0) needs.appendChild(el('div', 'need empty', txt('p', 'lede', 'Nothing needs you.')));
    out.appendChild(el('section', 'row hero', left, needs));
    out.appendChild(band(h.running ? 'names travel values arrive only where allowed' : 'stopped every request is refused'));

    const nums = el('section', 'row nums');
    const stat = function (label, value, route, warn) {
      const a = link(route, '', 'ncell' + (warn && value > 0 ? ' hot' : ''));
      a.append(txt('span', 'n', num(value)), el('span', 'u'), txt('span', 'nl', label), arrow());
      return a;
    };
    nums.appendChild(stat('Projects', h.projects, '/projects'));
    nums.appendChild(stat('Protected', h.protected, '/projects'));
    nums.appendChild(stat('Not usable yet', h.needs_website, '/projects?show=not-usable', true));
    nums.appendChild(stat('Blocked in 24 h', h.blocked_24h, '/activity?result=blocked&since=24h', true));
    out.appendChild(nums);

    out.appendChild(el('section', 'row bar', el('div', 'cell', txt('span', 'lbl', 'Projects'), linkBtn('/projects', 'All projects and keys', 'sm'))));
    if (pv.projects.length) out.appendChild(projectTiles(pv.projects));
    else {
      const [r, body] = part('No projects yet', null, null);
      body.appendChild(txt('p', null, 'Set one up from Projects: morsec checks the folder and gives you the command to run.'));
      out.appendChild(r);
    }

    const [ar, ab] = part('Agents', null, null);
    ab.appendChild(linkList(h.agents.map(function (a) {
      return {
        route: '/agents',
        parts: [txt('span', 'grow', a.name),
          a.connected ? tag('connected', 'good') : tag(a.installed ? 'not connected' : 'not installed', a.installed ? 'bad' : ''),
          el('span', 'muted', 'last seen ', when(a.last_seen_unix_ms))],
      };
    }), 'No supported agent found.'));
    out.appendChild(ar);
    return out;
  }

  // What setting a folder up would do, then Set up with Touch ID (L35 SPEC D-11).
  function setupPanel(path, out, anchor) {
    const msg = txt('p', 'muted', '');
    const show = async function () {
      out.replaceChildren(msg);
      const res = await run(msg, false, function () { return act('/api/projects/preview', { path: path }); });
      if (!res || !res.preview) return;
      const p = res.preview;
      msg.textContent = '';
      if (!p.ok) {
        out.replaceChildren(txt('p', 'err', sentence(p.reason || 'That folder can’t be set up.')));
        if (p.command) out.appendChild(copyline(p.command, 'Or set it up in Terminal.'));
        return;
      }
      if (p.nothing_to_do) {
        out.replaceChildren(txt('p', 'muted', 'Nothing new to protect in “' + p.display + '”.'));
        return;
      }
      const box = el('div', 'plan');
      box.appendChild(kv([
        ['Project', el('span', null, txt('span', null, p.display + (p.existing ? ' (set up before: a re-scan)' : '')), ' ', pathText(p.root, 'mono muted'))],
        ['Files', String(p.files.length)],
        ['Keys written into code', p.findings ? num(p.findings) + ' (reported only, never moved)' : 'none'],
      ]));
      box.appendChild(table(['File', 'Secrets', 'New keys', 'Same value'], p.files.map(function (f) {
        return { cells: [f.error ? el('span', null, mono(f.path), txt('span', 'sub err', f.error)) : mono(f.path), num(f.secrets), num(f.new_keys), num(f.reused)] };
      }), { num: true }));
      if (p.keys.length) {
        box.appendChild(txt('p', 'lbl', 'What each new key may do'));
        box.appendChild(list(p.keys.map(function (k) {
          const what = k.reaches.length ? 'may reach ' + k.reaches.join(', ')
            : k.runs_in.length ? 'may run in ' + k.runs_in.join(', ')
            : (k.needs === 'command' ? 'needs a command first' : 'needs a website first');
          return el('span', 'grow', ref(k.key), ' ', txt('span', k.needs ? 'err' : 'muted', what));
        }), ''));
      }
      if (p.stopped_early) box.appendChild(txt('p', 'err', 'The scan stopped early (' + p.stopped_early + '). Set up a subfolder on its own for the rest.'));
      const res2 = txt('p', 'muted', '');
      const go = btn('Set up with Touch ID', 'sm solid', function () {
        run(res2, true, function () { return act('/api/projects/add', { path: path, plan: p.plan }); }).then(function (x) {
          if (x && x.setup) {
            const rows = el('div', 'plan', kv(x.setup.rows.map(function (r) { return [r[0], r[1]]; })));
            if (anchor) rerender(anchor, x, rows); else out.replaceChildren(res2, rows);
          } else if (res2.dataset.code === 'changed') after(1200, show);
        });
      });
      out.replaceChildren(
        txt('p', null, 'morsec moves these secrets into its vault and puts references in the files. Nothing is shown here but names.'),
        box,
        el('div', 'actions', go, btn('Cancel', 'sm ghost', function () { out.replaceChildren(); })),
        res2);
      if (p.command) out.appendChild(copyline(p.command, 'Or set it up in Terminal.'));
    };
    return show;
  }

  function addProject() {
    const [r, s] = part('Add a project', 'addproject', null);
    s.appendChild(txt('p', null, 'morsec reads the folder, shows you what it will protect, and sets it up after you confirm with Touch ID.'));
    const [w, input] = textField('Project folder', 'folder', 'The full path, for example /Users/you/code/shop');
    const out = el('div', 'result');
    const go = btn('Check folder', null, function () {
      const path = input.value.trim();
      if (!path) { out.replaceChildren(txt('p', 'err', 'Type the folder’s full path first.')); return; }
      setupPanel(path, out, null)();
    });
    s.appendChild(el('div', 'fields', w, el('div', 'field act', go)));
    s.appendChild(out);
    return r;
  }

  function addKey() {
    const [row, s] = part('Add a key', 'addkey', null);
    s.appendChild(txt('p', 'muted', 'A new key allows nothing until you give it a website or a command on its screen.'));
    const [kw, key] = textField('Key name', 'key', 'For example shop/stripe-secret-key');
    const [vw, value] = secretField('Value (hidden)', 'value', 'Pasted here, sent to morsec, then cleared from this page');
    const [mw, mode] = choice('Used as', 'mode', [['swap', 'swap (websites)'], ['run', 'run (commands)']], 'swap');
    const [tw, tier] = choice('Tier', 'tier', [['production', 'production (asks each use)'], ['test', 'test (never asks)']], 'production');
    const out = txt('p', 'muted', '');
    const go = btn('Add key', 'solid', function () {
      const body = { key: key.value.trim(), value: value.value, mode: mode.value, tier: tier.value };
      value.value = '';
      run(out, false, function () { return act('/api/keys', body); }).then(function (r) { if (r) rerender('addkey', r); });
      body.value = '';
    });
    s.appendChild(el('div', 'fields', kw, vw, mw, tw, el('div', 'field act', go)));
    s.appendChild(out);
    return row;
  }

  async function projects(arg, q) {
    const v = await api('/api/projects');
    const onlyNeeds = q.get('show') === 'not-usable';
    const out = sheet();
    out.appendChild(head('Projects', 'Projects', 'Each project ms init set up, and the keys that live outside one.', '02'));
    if (onlyNeeds) {
      out.appendChild(el('section', 'row bar', el('div', 'cell', txt('span', 'lbl', 'Showing what is not usable yet'), linkBtn('/projects', 'Show everything', 'sm'))));
    }
    if (v.unreadable) out.appendChild(el('section', 'row note', el('div', 'cell', txt('p', 'err', v.unreadable))));
    const cards = v.projects.filter(function (p) { return !onlyNeeds || p.needs_website > 0; });
    if (v.projects.length === 0 && !v.unreadable) {
      const [r, b] = part('No projects yet', null, null);
      b.appendChild(txt('p', null, 'Add one below: morsec checks the folder and gives you the command to run.'));
      out.appendChild(r);
    }
    if (cards.length) out.appendChild(projectTiles(cards));
    const [lr, loose] = part('Keys not in a project', null, null);
    const rows = v.loose.filter(function (k) { return !onlyNeeds || !k.ready; });
    if (rows.length === 0) {
      loose.appendChild(txt('p', 'muted', 'None.'));
    } else {
      loose.appendChild(table(['Key', 'Used as', 'Tier', 'Status', 'Websites or folders'], rows.map(function (k) {
        return { href: '#/secret/' + enc(k.key), cells: [ref(k.key), k.mode || '', k.tier || '', status(k.status), mono(k.targets.join(', '))] };
      }), { num: true, go: true }));
    }
    out.appendChild(lr);
    out.appendChild(addKey());
    out.appendChild(addProject());
    return out;
  }

  function undoResult(u) {
    const box = el('div', 'confirm');
    box.appendChild(txt('h3', 'h3s', 'What changed'));
    if (u.restored.length) {
      box.appendChild(txt('p', 'lbl', 'Written back'));
      box.appendChild(list(u.restored.map(function (l) { return el('span', 'grow', mono(l.file + ':' + l.line), ' ', mono(l.var)); }), ''));
    }
    if (u.skipped.length) {
      box.appendChild(txt('p', 'lbl err', 'Left as they are'));
      box.appendChild(list(u.skipped.map(function (l) { return el('span', 'grow', mono(l.file + ':' + l.line), ' ', mono(l.var), txt('span', 'err', ' · ' + l.reason)); }), ''));
    }
    if (u.deleted_keys.length) box.appendChild(el('p', 'muted', 'Deleted from morsec: ', mono(u.deleted_keys.join(', '))));
    return box;
  }

  async function project(slug) {
    const p = await api('/api/projects/' + enc(slug));
    railCtx = { project: p.slug, keys: p.rows.map(function (r) { return r.key; }) };
    const out = sheet();
    out.appendChild(crumbs([['/projects', 'Projects'], ['/project/' + enc(p.slug), p.display]]));
    const lede = el('div', null,
      txt('p', 'lede', plural(p.rows.length, 'secret', 'secrets') + ', ' + num(p.not_usable) + ' not usable yet.'),
      pathText(p.root, 'mono muted'));
    out.appendChild(head('Project', p.display, lede, null));
    if (p.stopped_early) {
      out.appendChild(el('section', 'row note', el('div', 'cell', txt('p', 'err', 'The scan stopped after ' + num(p.scan_entries) + ' files, so some secrets may be missing. Set up a subfolder on its own.'))));
    }
    const [sr, sec] = wide('secrets');
    sec.appendChild(el('div', 'count', txt('span', 'lbl', 'Keys'), txt('span', 'lbl m', ' · ' + plural(p.rows.length, 'variable', 'variables'))));
    if (p.rows.length === 0) {
      sec.appendChild(txt('p', 'muted count', 'No secrets were found in this project.'));
    } else {
      sec.appendChild(table(['Key', 'Provider', 'Tier', 'Used as', 'Status', 'Last use', ''], p.rows.map(function (r) {
        const cell = el('div', 'rowacts');
        // Undo is the quiet, second action, and asks first in a row of its own beneath, so
        // the table's columns don't move (review Q7, QA P3).
        const undo = txt('button', 'lnk', 'Undo');
        undo.setAttribute('type', 'button');
        undo.addEventListener('click', function () {
          const tr = cell.closest('tr');
          if (!tr || (tr.nextSibling && tr.nextSibling.className === 'confirmrow')) return;
          const msg = txt('span', 'muted', '');
          const yes = txt('button', 'lnk', 'Write the value back');
          yes.setAttribute('type', 'button');
          const no = txt('button', 'lnk', 'Cancel');
          no.setAttribute('type', 'button');
          const row = el('tr', 'confirmrow');
          const td = el('td', null, el('div', 'rowacts',
            txt('span', null, 'Write ' + r.var + '’s value back into ' + r.file + ' and drop the reference? You confirm with Touch ID.'),
            yes, no, msg));
          td.colSpan = 9;
          row.appendChild(td);
          tr.after(row);
          no.addEventListener('click', function () { row.remove(); });
          yes.addEventListener('click', function () {
            run(msg, true, function () { return act('/api/projects/' + enc(p.slug) + '/undo', { key: r.key }); }).then(function (x) {
              if (x && x.undo) rerender('secrets', x, undoResult(x.undo));
            });
          });
        });
        cell.replaceChildren(undo);
        const k = el('span', null, ref(r.key), txt('span', 'sub', r.var + ' · ' + r.file + ':' + r.line));
        return { href: '#/secret/' + enc(r.key), cells: [k, r.provider || '', r.tier || '', r.mode || '', status(r.status), when(r.last_use_unix_ms), cell] };
      }), { num: true, go: true }));
    }
    out.appendChild(sr);

    const [dr, dev] = part('Run it with your keys', null, null);
    dev.appendChild(txt('p', null, 'Start your own app through morsec so its requests can use the keys:'));
    if (p.dev_command) dev.appendChild(copyline(p.dev_command, 'Replace npm run dev with your command.'));
    out.appendChild(dr);

    const [cr, code] = part('Keys written into code', null, null);
    code.appendChild(list(p.findings.map(function (f) {
      return el('span', 'grow', mono(f.path + ':' + f.line), ' ', txt('span', null, f.provider), ' ', mono(f.masked));
    }), 'None found.'));
    if (p.findings.length) code.appendChild(txt('p', 'muted', 'Move each into .env, then set the project up again (below).'));
    out.appendChild(cr);

    if (p.committed.length) {
      const [gr, g] = part('Committed to git', null, null);
      g.appendChild(list(p.committed.map(function (c) {
        return el('span', 'grow err', mono(c.path), ' was committed in ' + plural(c.commits, 'commit', 'commits') + ': the values in git history are not protected; rotate them at each provider.');
      }), ''));
      out.appendChild(gr);
    }

    const [ar, again] = part('Set it up again', 'again', null);
    again.appendChild(txt('p', null, 'Re-scan the project after you add secrets or code. You see what is new first, then confirm with Touch ID.'));
    const rescanOut = el('div', 'result');
    again.appendChild(el('div', 'actions', btn('Re-scan', 'sm solid', setupPanel(p.root, rescanOut, 'again'))));
    again.appendChild(rescanOut);
    if (p.rescan_command) again.appendChild(copyline(p.rescan_command, 'Or run it in Terminal.'));
    if (p.hints.length) again.appendChild(el('p', 'muted', 'Agent hints in: ', mono(p.hints.join(', '))));
    again.appendChild(kv([['Set up', when(p.created_unix_ms)], ['Last scan', plural(p.scan_entries, 'file and folder', 'files and folders') + ' looked at']]));
    out.appendChild(ar);

    if (p.rows.length) {
      const [ur, ub] = part('Undo', null, null);
      const msg = txt('p', 'muted', '');
      const confirmBox = el('div', null);
      ub.appendChild(txt('p', 'muted', 'Puts the values back into this project’s files, as they were before ms init.'));
      ub.appendChild(el('div', 'actions', btn('Undo whole project', 'sm deny', function () {
        confirmBox.replaceChildren(el('div', 'confirm',
          txt('p', null, 'Write every value back into this project’s files, and delete from morsec the keys no other project uses? You confirm with Touch ID.'),
          el('div', 'actions',
            btn('Undo whole project', 'sm deny', function () {
              run(msg, true, function () { return act('/api/projects/' + enc(p.slug) + '/undo', {}); }).then(function (x) {
                confirmBox.replaceChildren();
                if (!x || !x.undo) return;
                // A fully undone project is gone: go to Projects with the result (F5).
                if (x.undo.skipped.length === 0) rerender(null, x, undoResult(x.undo), '#/projects');
                else rerender('secrets', x, undoResult(x.undo));
              });
            }),
            btn('Cancel', 'sm', function () { confirmBox.replaceChildren(); }))));
      })));
      ub.appendChild(confirmBox);
      ub.appendChild(msg);
      out.appendChild(ur);
    }
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

  // WHERE IT GOES and TIER: the key's rule. Adding asks for Touch ID; taking away does not.
  function ruleCells(s) {
    const where = el('div', 'cell');
    where.id = 'rules';
    where.appendChild(cap('02', 'Where it goes'));
    const tierCell = el('div', 'cell');
    tierCell.id = 'tier';
    tierCell.appendChild(cap('03', 'Tier'));
    if (!s.mode) {
      where.appendChild(txt('p', 'muted', 'No rule yet, so no agent can use it. Give it one in Terminal:'));
      where.appendChild(copyline('ms rules ' + s.key));
      tierCell.appendChild(txt('p', 'muted', 'No rule.'));
      return [where, tierCell];
    }
    where.appendChild(txt('p', 'muted', 'Adding a website, a command or a folder asks for Touch ID. Taking one away does not.'));
    const out = txt('p', 'muted', '');
    const tout = txt('p', 'muted', '');
    const edit = function (e, o) {
      return run(o, true, function () { return act('/api/keys/' + enc(s.key) + '/rules', { edit: e }); }).then(function (r) {
        if (r) { if (e.set_tier) rerender('tier', r); else rerender('rules', r); }
      });
    };
    // `items` are what is shown; `values` what goes back to msd: for commands, their exact
    // words from the view, never the display string split again (review R1).
    const removable = function (items, kind, label, values, what) {
      return list(items.map(function (x, i) {
        const rm = btn('×', 'sm x', function () {
          const e = {};
          e[kind] = kind === 'remove_command' ? { words: values[i] } : x;
          edit(e, out);
        });
        rm.setAttribute('aria-label', 'Remove ' + what + ' ' + x);
        return el('span', 'grow rmrow', mono(x), rm);
      }), 'None yet.' + (label ? ' ' + label : ''));
    };
    if (s.mode === 'run') {
      where.appendChild(txt('p', 'lbl', 'Commands'));
      where.appendChild(removable(s.commands, 'remove_command', 'It is not usable until it has one.', s.command_words, 'command'));
      const [cw, c] = textField('Add a command', 'command', 'One word per space, for example psql -c * . A word with a space or a quote needs ms rules ' + s.key + ' --add-command \'["…"]\' in Terminal.');
      const chips = el('div', 'chips');
      c.addEventListener('input', function () {
        chips.replaceChildren();
        for (const w of c.value.split(' ').filter(Boolean)) chips.appendChild(txt('span', null, w));
      });
      cw.appendChild(chips);
      where.appendChild(el('div', 'fields', cw, el('div', 'field act', btn('Add command', 'sm', function () {
        const words = c.value.split(' ').filter(Boolean);
        if (words.length) edit({ add_command: { words: words } }, out);
      }))));
      where.appendChild(txt('p', 'lbl', 'Folders'));
      where.appendChild(removable(s.roots, 'remove_folder', '', null, 'folder'));
      const [fw, f] = textField('Add a folder', 'folder', 'Its commands run only inside it, for example /Users/you/code/shop');
      where.appendChild(el('div', 'fields', fw, el('div', 'field act', btn('Add folder', 'sm', function () {
        if (f.value.trim()) edit({ add_folder: f.value.trim() }, out);
      }))));
    } else {
      where.appendChild(txt('p', 'lbl', 'Websites'));
      where.appendChild(removable(s.hosts, 'remove_host', 'It is not usable until it has one.', null, 'website'));
      const [hw, h] = textField('Add a website', 'host', 'A host name: api.example.com, or *.example.com for every subdomain');
      where.appendChild(el('div', 'fields', hw, el('div', 'field act', btn('Add website', 'sm', function () {
        if (h.value.trim()) edit({ add_host: h.value.trim() }, out);
      }))));
    }
    // Git hosts (swap), variables and SSH host keys (run): L35 SPEC D-15.
    const addOne = function (label, name, hint, kind, verb) {
      const [w, i] = textField(label, name, hint);
      return el('div', 'fields', w, el('div', 'field act', btn(verb, 'sm', function () {
        const v = i.value.trim();
        if (!v) return;
        const e = {};
        e[kind] = v;
        edit(e, out);
      })));
    };
    if (s.mode === 'swap') {
      where.appendChild(txt('p', 'lbl', 'Git hosts'));
      where.appendChild(removable(s.git_hosts, 'remove_git_host', 'Only needed for git over HTTPS.', null, 'git host'));
      where.appendChild(addOne('Add a git host', 'githost', 'One exact host name git pushes to over HTTPS, for example github.com', 'add_git_host', 'Add git host'));
    } else if (s.mode === 'run') {
      where.appendChild(txt('p', 'lbl', 'Variables'));
      where.appendChild(removable(s.env, 'remove_env', 'Its commands get it the way the tool expects.', null, 'variable'));
      where.appendChild(addOne('Add a variable', 'envvar', 'The variable the tool reads its token from, for example GITHUB_TOKEN', 'add_env', 'Add variable'));
      where.appendChild(txt('p', 'lbl', 'SSH host keys'));
      where.appendChild(removable(s.ssh_host_keys, 'remove_ssh_host_key', 'Only needed for git over SSH.', null, 'host key'));
      where.appendChild(addOne('Add an SSH host key', 'hostkey', 'One known_hosts line: host ssh-ed25519 AAAA…', 'add_ssh_host_key', 'Add host key'));
    }
    if (s.mint_scopes.length) {
      where.appendChild(kv([['Mint scopes', mono(s.mint_scopes.join(', '))]]));
      where.appendChild(txt('p', 'muted', 'Mint scopes are set when the key is added; see them with:'));
      where.appendChild(copyline('ms rules ' + s.key));
    }
    where.appendChild(out);

    tierCell.appendChild(txt('p', 'lede', s.tier === 'test' ? 'Test: agents use it without asking.' : 'Production: every use asks you first.'));
    tierCell.appendChild(el('div', 'actions', s.tier === 'test'
      ? btn('Make it production', 'sm', function () { edit({ set_tier: 'production' }, tout); })
      : btn('Make it test', 'sm', function () { edit({ set_tier: 'test' }, tout); })));
    tierCell.appendChild(txt('p', 'muted', 'Production asks you before every use; test never asks. Making it a test key asks for Touch ID.'));
    tierCell.appendChild(tout);
    return [where, tierCell];
  }

  async function secret(key) {
    const s = await api('/api/keys/' + enc(key));
    hideValue();
    const proj = s.used_in.length ? s.used_in[0].project : null;
    railCtx = { project: proj, key: s.key };
    const out = sheet();
    const trail = [['/projects', 'Projects']];
    if (proj) trail.push(['/project/' + enc(proj), proj]);
    trail.push(['/secret/' + enc(s.key), proj ? lastPart(s.key) : s.key]);
    out.appendChild(crumbs(trail));
    const h2 = slashed(txt('h2', 'keyname', ''), s.key);
    const facts = kv([
      ['Provider', s.provider || 'unknown'],
      ['Tier', s.tier || 'no rule'],
      ['Used as', s.mode || 'no rule'],
      ['Added', when(s.created_unix_ms)],
    ], 'facts');
    const st = status(s.status);
    st.classList.add('lbl');
    out.appendChild(head('Key', null, null, null, { heading: h2, after: facts, sideExtra: st }));

    // VALUE: hidden until Show (Touch ID), cleared after 15 s.
    const vs = el('div', 'cell');
    vs.appendChild(cap('01', 'Value'));
    const box = txt('div', 'value hidden', s.stored ? 'Hidden' : 'Not in the vault');
    box.setAttribute('aria-live', 'polite');
    const note = txt('p', 'muted', '');
    const out2 = txt('p', 'muted', '');
    const hide = btn('Hide', 'sm', hideValue);
    hide.hidden = true;
    vs.appendChild(txt('p', 'muted', 'Show and Copy ask for Touch ID on this Mac every time. A shown value hides after 15 seconds; a copied one leaves the clipboard after 30.'));
    vs.appendChild(box);
    vs.appendChild(note);
    if (s.stored) {
      vs.appendChild(el('div', 'actions',
        btn('Show', 'sm solid', function () {
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
        btn('Copy', 'sm', function () { run(out2, true, function () { return act('/api/keys/' + enc(s.key) + '/copy'); }); }),
        hide));
      vs.appendChild(out2);
    }
    const [where, tierCell] = ruleCells(s);
    out.appendChild(el('section', 'row sec', vs, where, tierCell));

    if (s.stored) {
      // REPLACE: a hidden field outside any form, cleared as soon as it is sent.
      const [rr, rb] = part('Replace', 'replace', null);
      const [rw, rv] = secretField('New value (hidden)', 'value', 'You confirm it with Touch ID. If storing the new value fails, the old one stays in use.');
      const rout = txt('p', 'muted', '');
      rb.appendChild(el('div', 'fields', rw, el('div', 'field act', btn('Replace', null, function () {
        const body = { value: rv.value };
        rv.value = '';
        if (!body.value) { rout.className = 'err'; rout.textContent = 'Type the new value first.'; return; }
        run(rout, true, function () { return act('/api/keys/' + enc(s.key) + '/replace', body); });
        body.value = '';
      }))));
      rb.appendChild(rout);
      out.appendChild(rr);
    }

    const [ur, used] = part('Where it is used', null, null);
    const uout = txt('p', 'muted', '');
    used.appendChild(linkList(s.used_in.map(function (u) {
      return { route: '/project/' + enc(u.project), parts: [txt('span', null, u.project), el('span', 'grow', mono(u.file + ':' + u.line)), mono(u.var)] };
    }), 'No project file refers to it.'));
    const uresult = el('div', null);
    if (s.used_in.length) {
      used.appendChild(el('div', 'actions', btn('Undo this one', 'sm', function () {
        run(uout, true, function () { return act('/api/keys/' + enc(s.key) + '/undo'); }).then(function (x) {
          if (x && x.undo) uresult.replaceChildren(undoResult(x.undo));
        });
      })));
      used.appendChild(txt('p', 'muted', 'Undo writes the value back into the files above and deletes the key when nothing else uses it.'));
    }
    used.appendChild(uout);
    used.appendChild(uresult);
    out.appendChild(ur);

    const [lr, uses] = wide('uses');
    uses.appendChild(el('div', 'count', txt('span', 'lbl', 'Last 20 uses')));
    uses.appendChild(activityTable(s.uses, true));
    out.appendChild(lr);

    if (s.stored || s.mode) {
      const [dr, del] = part('Delete', null, null);
      const last = s.key.split('/').pop();
      const [dw, d] = textField('Type ' + last + ' to confirm', 'confirm', 'Deletes the value and its rule. This can’t be undone.');
      const dout = txt('p', 'muted', '');
      const extra = el('div', null);
      const doDelete = function (force) {
        if (d.value.trim().toLowerCase() !== last.toLowerCase()) { dout.className = 'err'; dout.textContent = 'Type ' + last + ' first.'; return; }
        run(dout, true, function () { return act('/api/keys/' + enc(s.key) + '/delete', { force: force }); }).then(function (r) {
          if (r) { after(1200, function () { location.hash = '#/projects'; }); return; }
          if (!force && dout.dataset.code === 'referenced') extra.replaceChildren(btn('Delete anyway', 'deny', function () { doDelete(true); }));
        });
      };
      del.appendChild(el('div', 'fields', dw, el('div', 'field act', btn('Delete key', 'deny', function () { doDelete(false); }))));
      del.appendChild(dout);
      del.appendChild(extra);
      out.appendChild(dr);
    }
    return out;
  }

  // `oneKey`: the Secret screen's table, where every row is this key (no Key column: Q11).
  function activityTable(rows, oneKey) {
    if (!rows.length) return txt('p', 'muted count', 'Nothing recorded.');
    const what = function (r) { return mono((r.mechanism ? r.mechanism + ' · ' : '') + r.target); };
    if (oneKey) {
      return table(['When', 'Agent', 'What', 'Result'], rows.map(function (r) {
        return [when(r.time_unix_ms), agentCell(r.agent, r.pid), what(r), result(r.result, r.reason)];
      }), { num: true });
    }
    return table(['When', 'Agent', 'Key', 'What', 'Result'], rows.map(function (r) {
      return { href: r.key ? '#/secret/' + enc(r.key) : null, cells: [when(r.time_unix_ms), agentCell(r.agent, r.pid), r.key ? ref(r.key) : '', what(r), result(r.result, r.reason)] };
    }), { num: true, go: true });
  }

  const FILTERS = ['since', 'project', 'key', 'agent', 'result'];
  async function activity(arg, q) {
    const f = { since: q.has('since') ? q.get('since') : '24h' };
    for (const k of FILTERS.slice(1)) f[k] = q.get(k) || '';
    const query = FILTERS.filter(function (k) { return f[k]; }).map(function (k) { return k + '=' + enc(f[k]); }).join('&');
    const out = sheet();
    out.appendChild(head('Activity', 'Activity', 'Every use of a key, every refusal, and everything done here, as msd recorded it.', '03'));
    let v = null;
    let error = null;
    try { v = await api('/api/activity?' + query); } catch (e) { if (e instanceof SignedOut) throw e; error = e; }
    const [sw, since] = choice('Since', 'since', [['1h', '1 hour'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['', 'everything']], f.since);
    const [pw, proj] = choice('Project', 'project', [['', 'any']].concat((v ? v.projects : []).map(function (s) { return [s, s]; })), f.project);
    const [kw, key] = textField('Key', 'key', null);
    key.value = f.key;
    const [aw, agent] = choice('Agent', 'agent', [['', 'any'], ['claude-code', 'Claude Code'], ['codex', 'Codex'], ['terminal', 'Terminal'], ['dashboard', 'Dashboard'], ['ms-dev', 'ms dev'], ['other', 'other']], f.agent);
    const [rw, res] = choice('Result', 'result', [['', 'any'], ['allowed', 'allowed'], ['approved', 'approved'], ['blocked', 'blocked'], ['denied', 'denied'], ['failed', 'failed'], ['alert', 'alert']], f.result);
    const apply = btn('Apply', 'solid', function () {
      const n = { since: since.value, project: proj.value, key: key.value.trim(), agent: agent.value, result: res.value };
      const parts = FILTERS.map(function (k) { return k + '=' + enc(n[k]); });
      location.hash = '#/activity?' + parts.join('&');
    });
    apply.appendChild(arrow());
    out.appendChild(el('section', 'row filters', sw, pw, kw, aw, rw, el('div', 'field act', apply)));
    const verdict = txt('p', 'muted', '');
    const tools = el('div', 'cell',
      el('div', 'actions',
        btn('Verify the chain', 'sm', async function () {
          verdict.className = 'muted';
          verdict.textContent = 'Checking…';
          try {
            const r = await api('/api/activity/verify');
            verdict.textContent = r.text;
            verdict.className = r.ok ? 'signal' : 'err';
          } catch (e) { fail(e, verdict); }
        }),
        btn('Export JSON', 'sm', async function () { try { await download('/api/activity/export?format=json&' + query, 'morsec-receipts.json'); } catch (e) { fail(e, verdict); } }),
        btn('Export CSV', 'sm', async function () { try { await download('/api/activity/export?format=csv&' + query, 'morsec-receipts.csv'); } catch (e) { fail(e, verdict); } })),
      verdict);
    out.appendChild(el('section', 'row bar', tools));
    const [tr, tb] = wide('rows');
    if (error) {
      tb.appendChild(txt('p', 'err count', (error.message || 'The filter could not be applied.') + ' Change the filters and press Apply.'));
      out.appendChild(tr);
      return out;
    }
    tb.appendChild(txt('p', 'muted count', v.rows.length < v.matched
      ? 'Showing ' + num(v.rows.length) + ' of ' + num(v.matched) + '. Narrow the filters to see older ones.'
      : 'Showing ' + num(v.rows.length) + ' of ' + num(v.matched) + '.'));
    tb.appendChild(activityTable(v.rows));
    out.appendChild(tr);
    return out;
  }

  // A connect or disconnect plan: each file and its changed lines, redacted by msd (L35).
  function planBox(p) {
    const box = el('div', 'plan');
    for (const f of p.files) {
      const own = f.verb === 'write' || f.verb === 'keep' || f.verb === 'drop';
      const label = { create: 'Create', change: 'Change', remove: 'Remove', write: 'Write', keep: 'Keep', drop: 'Remove' }[f.verb] || f.verb;
      box.appendChild(el('p', own ? 'muted' : null, txt('span', 'lbl', label + ' '), pathText(f.path)));
      if (f.too_large) box.appendChild(txt('p', 'muted', 'Too large to show line by line.'));
      if (f.lines.length) {
        const pre = el('div', 'diff');
        for (const l of f.lines) {
          pre.appendChild(el('div', l.sign === '+' ? 'add' : 'del', txt('span', 'ln', l.sign + String(l.n).padStart(4, ' ')), txt('code', null, ' ' + l.text)));
        }
        box.appendChild(pre);
      }
    }
    if (p.notes.length) box.appendChild(list(p.notes, ''));
    return box;
  }

  // Connect or Disconnect: preview, then apply with Touch ID (L35 SPEC D-1, D-19).
  function agentAction(a, panel) {
    const off = a.connected;
    const base = '/api/agents/' + enc(a.id) + '/' + (off ? 'disconnect' : 'connect');
    const msg = txt('p', 'muted', '');
    const show = async function () {
      panel.replaceChildren(msg);
      const r = await run(msg, false, function () { return act(base + '/preview'); });
      // Refused here (a terminal-only setup, no ms next to msd…): the terminal command stays.
      if (!r || !r.preview) { panel.appendChild(copyline(a.command, 'Run it in Terminal instead.')); return; }
      const p = r.preview;
      msg.textContent = '';
      if (p.nothing_to_do) {
        panel.replaceChildren(txt('p', 'muted', off ? a.name + ' is not connected; nothing to do.' : a.name + ' is already connected; nothing to change.'));
        return;
      }
      const out = txt('p', 'muted', '');
      const apply = btn(off ? 'Disconnect with Touch ID' : 'Connect with Touch ID', off ? 'sm deny' : 'sm solid', function () {
        run(out, true, function () { return act(base, { plan: p.plan }); }).then(function (x) {
          if (x) rerender('agents', x);
          else if (out.dataset.code === 'changed') after(1200, show);
        });
      });
      panel.replaceChildren(
        txt('p', null, off
          ? 'This removes morsec from ' + a.name + '’s settings, including its sandbox: its requests stop going through morsec.'
          : 'These are the changes to ' + a.name + '’s settings. Values that are yours are shown as “…”.'),
        planBox(p),
        el('div', 'actions', apply, btn('Cancel', 'sm ghost', function () { panel.replaceChildren(); })),
        out,
        copyline(a.command, 'Or run it in Terminal, which shows the same changes.'));
    };
    return btn(off ? 'Disconnect' : 'Connect', off ? 'sm deny' : 'sm solid', show);
  }

  function agentsBody(v, out) {
    const g = el('div', 'tiles');
    v.agents.forEach(function (a, i) {
      const c = el('div', 'tile agent');
      c.appendChild(el('div', 'tt', txt('span', 'num', pad(i + 1)), a.connected ? tag('connected', 'good') : tag(a.installed ? 'not connected' : 'not installed', a.installed ? 'bad' : '')));
      c.appendChild(txt('h3', null, a.name));
      c.appendChild(el('span', 'rule'));
      c.appendChild(kv([
        ['Installed', a.installed ? 'yes' : 'no'],
        ['Sessions', num(a.sessions)],
        ['Blocked', num(a.blocked)],
        ['Last seen', when(a.last_seen_unix_ms)],
      ]));
      if (a.command) {
        c.appendChild(txt('p', 'muted', a.connected
          ? 'Disconnecting removes its sandbox and proxy settings. You see the change first, then confirm with Touch ID.'
          : 'Connecting edits its settings. You see the change first, then confirm with Touch ID.'));
        const panel = el('div', 'panel');
        c.appendChild(el('div', 'actions', agentAction(a, panel)));
        c.appendChild(panel);
      } else c.appendChild(txt('p', 'muted', 'Install ' + a.name + ' first; then it can be connected here.'));
      g.appendChild(c);
    });
    out.appendChild(el('section', 'row', el('div', 'tilewrap', g)));
    if (v.warnings.length) {
      const [wr, w] = part('Warnings', null, null);
      w.appendChild(el('p', null, plural(v.warnings.length, 'warning needs', 'warnings need') + ' you. '));
      w.appendChild(linkBtn('/', 'See them on Home', 'sm'));
      out.appendChild(wr);
    }
    const [cr, ch] = part('msd’s checks', null, null);
    const ul = el('ol', 'list checks');
    for (const c of v.checks) ul.appendChild(el('li', c.ok ? null : 'bad', txt('span', 'grow', c.text)));
    ch.appendChild(v.checks.length ? ul : txt('p', 'muted', 'No checks.'));
    ch.appendChild(txt('p', 'muted', 'The full check, including each agent’s settings, runs in Terminal:'));
    ch.appendChild(copyline('ms doctor'));
    out.appendChild(cr);
  }

  async function agents() {
    const v = await api('/api/agents');
    const out = sheet();
    out.id = 'agents';
    out.appendChild(head('Agents', 'Agents', 'Which coding agents send their requests through morsec.', '04'));
    const msg = txt('p', 'muted', '');
    const bar = el('div', 'cell', el('div', 'actions', btn('Re-check', 'sm solid', function () {
      run(msg, false, async function () {
        const r = await act('/api/agents/recheck');
        return { message: recheckMessage(r), agents: r.agents };
      }).then(function (r) {
        // The screen is drawn again from msd's new answer, with the result under Re-check.
        if (r && r.agents) rerender('recheck', r);
      });
    })), msg);
    bar.id = 'recheck';
    out.appendChild(el('section', 'row bar', bar));
    agentsBody(v, out);
    return out;
  }

  function scanBody(v) {
    const out = el('div', 'body');
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
    out.appendChild(txt('h3', 'h3s', s.findings.length ? 'Found' : 'Nothing found'));
    if (s.findings.length) {
      out.appendChild(table(['Transcript', 'Line', 'Key', 'Form'], s.findings.map(function (f) {
        return { href: '#/secret/' + enc(f.key), cells: [mono(f.file), num(f.line), ref(f.key), f.encoding] };
      }), { num: true, go: true }));
      out.appendChild(txt('p', 'err', 'Each key found leaked into a transcript: rotate it at its provider, then replace it here.'));
    }
    if (s.skipped_keys.length) out.appendChild(el('p', 'muted', 'Too short to search: ', mono(s.skipped_keys.join(', '))));
    if (s.notes.length) out.appendChild(list(s.notes, ''));
    return out;
  }

  async function scan() {
    const v = await api('/api/scan');
    const out = sheet();
    out.appendChild(head('Scan', 'Leak scan', 'Searches your agents’ transcripts for your keys’ values. It reads every value, so it asks for Touch ID.', '05'));
    const msg = txt('p', 'muted', '');
    const [br, bc] = part('Last scan', null, null);
    const body = el('div', null, scanBody(v));
    const poll = async function () {
      try {
        const n = await api('/api/scan');
        body.replaceChildren(scanBody(n));
        if (n.running) after(2000, poll);
      } catch (e) { fail(e, msg); }
    };
    if (v.running) after(2000, poll);
    bc.appendChild(el('div', 'actions', btn('Run scan', 'solid', function () {
      // The Scanning box below is the one sign it runs (V3).
      run(msg, true, function () { return act('/api/scan/run'); }).then(function (r) { if (r) { msg.textContent = ''; msg.className = 'muted'; poll(); } });
    })));
    bc.appendChild(msg);
    bc.appendChild(body);
    out.appendChild(br);
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
  // The rail entry each screen sits under.
  const RAIL = { '/': '/', '/projects': '/projects', '/project': '/projects', '/secret': '/projects', '/activity': '/activity', '/agents': '/agents', '/scan': '/scan' };

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
    const s = sheet();
    s.appendChild(head('Error', 'This screen could not load.', txt('p', 'lede err', m), null, {
      after: el('div', 'actions', btn('Try again', 'solid', render), linkBtn('/', 'Home')),
    }));
    main.replaceChildren(s);
  }

  let seq = 0;
  async function render() {
    hideValue();
    live.textContent = '';
    for (const t of timers) clearTimeout(t);
    timers = [];
    const [name, arg, q] = parseHash();
    const view = Object.prototype.hasOwnProperty.call(routes, name) ? routes[name] : null;
    const group = Object.prototype.hasOwnProperty.call(RAIL, name) ? RAIL[name] : null;
    for (const a of document.querySelectorAll('#nav a.scr')) {
      const r = a.getAttribute('data-route');
      if (r === name) a.setAttribute('aria-current', 'page');
      else if (r === group) a.setAttribute('aria-current', 'true');
      else a.removeAttribute('aria-current');
    }
    railCtx = {};
    const mine = ++seq;
    if (!view) {
      const s = sheet();
      s.appendChild(head('Not found', 'No such screen.', null, null, { after: el('div', 'actions', linkBtn('/', 'Go to Home', 'solid')) }));
      main.replaceChildren(s);
      return;
    }
    main.setAttribute('aria-busy', 'true');
    if (!main.firstChild || !main.firstChild.classList || !main.firstChild.classList.contains('sheet')) main.replaceChildren(txt('p', 'muted loading', 'Loading…'));
    try {
      const node = await view(arg, q);
      if (mine === seq) { main.replaceChildren(node); showFlash(); main.focus({ preventScroll: true }); }
      if (mine === seq) refreshRail();
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
    const s = sheet();
    const lede = el('div', null);
    if (why === 'closed') lede.appendChild(txt('p', 'lede', 'The dashboard closed: it was idle for 30 minutes, or morsec stopped.'));
    if (why === 'another tab') lede.appendChild(txt('p', 'lede', 'It was opened again in another tab, which signed this one out.'));
    lede.appendChild(txt('p', 'lede', 'This page signs in with a one-time link that works once, for a minute. Run this to get a new one:'));
    s.appendChild(head('Signed out', 'Open the dashboard from Terminal.', lede, null, { after: copyline('ms dashboard') }));
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
    window.addEventListener('hashchange', function () {
      if (flash && flash.nav) flash.nav = false; else flash = null;
      stateNote = null;
      renderState();
      render();
    });
    render();
  }

  boot();
})();
