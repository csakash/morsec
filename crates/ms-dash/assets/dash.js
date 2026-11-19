// morsec dashboard (L32, read-only). Plain script, no framework, nothing fetched but /api/.
// Every string from a file, an agent or a user reaches the page through textContent only
// (design §6.3); links are built from fixed routes and encodeURIComponent.
'use strict';

(function () {
  const state = { csrf: null };
  const main = document.getElementById('main');
  const stateBox = document.getElementById('state');

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
  function cmd(s) { return txt('code', 'cmd', s); }
  function enc(s) { return encodeURIComponent(String(s)); }
  function when(ms) {
    if (!ms) return '';
    try { return new Date(ms).toLocaleString(); } catch (e) { return String(ms); }
  }
  function table(headers, rows) {
    const t = el('table', null);
    const thead = el('thead', null);
    const hr = el('tr', null);
    for (const h of headers) hr.appendChild(txt('th', null, h));
    thead.appendChild(hr);
    t.appendChild(thead);
    const tb = el('tbody', null);
    for (const r of rows) {
      const tr = el('tr', null);
      for (const c of r) {
        if (c instanceof Node) {
          const td = el('td', null);
          td.appendChild(c);
          tr.appendChild(td);
        } else {
          tr.appendChild(txt('td', null, c));
        }
      }
      tb.appendChild(tr);
    }
    t.appendChild(tb);
    return el('div', 'tw', t);
  }
  function stat(label, n, warn) {
    const d = el('div', 'stat' + (warn && n > 0 ? ' warn' : ''));
    d.appendChild(txt('span', 'lbl', label));
    d.appendChild(txt('span', 'n', n));
    return d;
  }
  function badge(s, kind) { return txt('span', 'badge' + (kind ? ' ' + kind : ''), s); }
  function status(s) {
    const cls = s === 'protected' ? 'st-protected' : /^needs |^not stored/.test(String(s)) ? 'st-needs' : '';
    return txt('span', cls, s);
  }
  function result(s) { return txt('span', 'st-' + String(s).replace(/[^a-z]/g, ''), s); }
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
  function list(items, empty) {
    if (!items || items.length === 0) return txt('p', 'muted', empty);
    const u = el('ul', 'plain');
    for (const i of items) {
      const li = el('li', null);
      if (i instanceof Node) li.appendChild(i); else li.textContent = String(i);
      u.appendChild(li);
    }
    return u;
  }
  function mono(s) { return txt('span', 'mono', s); }

  // ---- API ----------------------------------------------------------------------------------
  class SignedOut extends Error {}
  // A request that never got an answer: the listener closed (idle, or msd stopped).
  async function send(path) {
    try {
      return await fetch(path, {
        headers: { 'X-Morsec-CSRF': state.csrf || '' },
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

  // ---- screens ------------------------------------------------------------------------------
  async function home() {
    const h = await api('/api/home');
    setPill(h.running);
    const out = el('section', null);
    out.appendChild(txt('h1', null, h.running ? 'morsec is on.' : 'morsec is stopped.'));
    out.appendChild(txt('p', 'lead', h.running
      ? 'Agents use your secrets through morsec without ever seeing them.'
      : 'Every key is refused until you resume.'));
    if (!h.running) {
      out.appendChild(el('p', 'lead', 'Resume in your terminal: ', cmd('ms start'), ' (Touch ID)'));
    }
    if (h.pending) {
      const p = h.pending;
      const b = el('div', 'box alert');
      b.appendChild(txt('h3', null, 'A request is waiting for your approval'));
      b.appendChild(kv([
        ['Agent', p.agent],
        ['Key', mono(p.key)],
        ['Tier', p.tier],
        ['Command', mono(p.command.join(' '))],
        ['Folder', mono(p.cwd)],
        ['Expires', when(p.expires_unix_ms)],
      ]));
      b.appendChild(el('p', null, 'Answer it in your terminal: ', cmd('ms approve')));
      out.appendChild(b);
    }
    const g = el('div', 'grid counts');
    g.appendChild(stat('Projects', h.projects));
    g.appendChild(stat('Protected', h.protected));
    g.appendChild(stat('Need a host or command', h.needs_website, true));
    g.appendChild(stat('Blocked in 24 h', h.blocked_24h, true));
    out.appendChild(g);
    if (h.projects_unreadable) {
      out.appendChild(txt('p', 'err', 'The project records failed their integrity check, so they are not shown. Your keys and rules keep working.'));
    }
    if (h.alerts.length) {
      const b = el('div', 'box alert');
      b.appendChild(txt('h3', null, 'Look at these'));
      b.appendChild(list(h.alerts, ''));
      out.appendChild(b);
    }
    out.appendChild(txt('h2', null, 'Agents'));
    out.appendChild(agentList(h.agents));
    out.appendChild(txt('p', 'muted', 'msd ' + h.version + ' · vault: ' + h.vault + ' · ' + h.keys + ' keys'));
    return out;
  }

  function agentList(agents) {
    return list(agents.map(function (a) {
      const li = el('div', null);
      li.appendChild(txt('strong', null, a.name));
      li.appendChild(txt('span', 'muted', ' · '));
      li.appendChild(a.connected ? badge('connected', 'good') : badge(a.installed ? 'not connected' : 'not installed', a.installed ? 'bad' : ''));
      return li;
    }), 'No supported agent found.');
  }

  async function projects() {
    const v = await api('/api/projects');
    const out = el('section', null);
    out.appendChild(txt('h1', null, 'Projects'));
    if (v.unreadable) out.appendChild(txt('p', 'err', v.unreadable));
    if (v.projects.length === 0 && !v.unreadable) {
      out.appendChild(el('p', 'lead', 'No projects yet. Run ', cmd('ms init'), ' inside a project.'));
    }
    if (v.projects.length) {
      const g = el('div', 'grid cards');
      for (const p of v.projects) {
        const c = el('div', 'card');
        c.appendChild(txt('h3', null, p.display));
        c.appendChild(mono(p.root));
        c.appendChild(txt('p', null, p.protected + ' protected · ' + p.needs_website + ' need a website'));
        const b = el('div', 'badges');
        if (p.needs_website) b.appendChild(badge('needs a website', 'bad'));
        if (p.findings) b.appendChild(badge(p.findings + ' in code', 'bad'));
        if (p.committed_files) b.appendChild(badge('committed to git', 'bad'));
        if (p.stopped_early) b.appendChild(badge('scan stopped early', 'bad'));
        c.appendChild(b);
        c.appendChild(link('/project/' + enc(p.slug), 'Open', 'open'));
        g.appendChild(c);
      }
      out.appendChild(g);
    }
    out.appendChild(txt('h2', null, 'Not in a project'));
    if (v.loose.length === 0) {
      out.appendChild(txt('p', 'muted', 'None.'));
    } else {
      out.appendChild(table(['Key', 'Mode', 'Tier', 'Status', 'Hosts or folders'], v.loose.map(function (k) {
        return [link('/secret/' + enc(k.key), k.key, 'mono'), k.mode || '', k.tier || '',
          status(k.status), k.targets.join(', ')];
      })));
    }
    return out;
  }

  async function project(slug) {
    const p = await api('/api/projects/' + enc(slug));
    const out = el('section', null);
    out.appendChild(el('p', 'crumbs', link('/projects', 'Projects')));
    out.appendChild(txt('h1', null, p.display));
    out.appendChild(el('p', 'lead', mono(p.root)));
    if (p.stopped_early) {
      out.appendChild(el('p', 'err', 'The scan stopped after ' + p.scan_entries + ' files. Run ', cmd('ms init --project PATH'), ' on a subfolder.'));
    }
    out.appendChild(txt('h2', null, 'Secrets'));
    if (p.rows.length === 0) {
      out.appendChild(txt('p', 'muted', 'No secrets were found in this project.'));
    } else {
      out.appendChild(table(['Variable', 'File', 'Key', 'Provider', 'Tier', 'Mode', 'Status', 'Last activity'], p.rows.map(function (r) {
        return [mono(r.var), mono(r.file + ':' + r.line), link('/secret/' + enc(r.key), r.key, 'mono'),
          r.provider || '', r.tier || '', r.mode || '', status(r.status), when(r.last_use_unix_ms)];
      })));
      if (p.rows.some(function (r) { return /^needs /.test(r.status); })) {
        out.appendChild(el('p', 'muted', 'A key that needs a website or a command is never used until you add one: ', cmd('ms rules KEY --add-host HOST')));
      }
    }
    out.appendChild(txt('h2', null, 'Keys written into code'));
    out.appendChild(list(p.findings.map(function (f) {
      return el('div', null, mono(f.path + ':' + f.line), ' · ' + f.provider + ' · ', mono(f.masked));
    }), 'None found.'));
    if (p.findings.length) out.appendChild(el('p', 'muted', 'Move each into .env, then run ', cmd('ms init'), ' in the project again.'));
    out.appendChild(txt('h2', null, 'Committed to git'));
    out.appendChild(list(p.committed.map(function (c) {
      return el('div', null, mono(c.path), ' is in ' + c.commits + (c.commits === 1 ? ' commit' : ' commits') + ': rotate these keys at each provider');
    }), 'No env file is in the git history.'));
    if (p.hints.length) {
      out.appendChild(txt('h2', null, 'Agent hints'));
      out.appendChild(list(p.hints, ''));
    }
    out.appendChild(kv([
      ['Set up', when(p.created_unix_ms)],
      ['Last scan', p.scan_entries + ' entries in ' + p.scan_ms + ' ms'],
      ['Scan again', cmd('ms init')],
    ]));
    return out;
  }

  async function secret(key) {
    const s = await api('/api/keys/' + enc(key));
    const out = el('section', null);
    out.appendChild(el('p', 'crumbs', link('/projects', 'Projects')));
    out.appendChild(txt('h1', 'mono', s.key));
    out.appendChild(kv([
      ['Provider', s.provider || 'unknown'],
      ['Tier', s.tier || 'no rule'],
      ['Mode', s.mode || 'no rule'],
      ['Value', txt('span', 'muted', s.stored ? 'hidden (never sent to this page)' : 'not in the vault')],
      ['Status', status(s.status)],
      ['Added', when(s.created_unix_ms)],
      ['Hosts', s.hosts.length ? mono(s.hosts.join(', ')) : txt('span', 'muted', 'none')],
      ['Git hosts', s.git_hosts.length ? mono(s.git_hosts.join(', ')) : txt('span', 'muted', 'none')],
      ['Commands', s.commands.length ? mono(s.commands.join(' ; ')) : txt('span', 'muted', 'none')],
      ['Folders', s.roots.length ? mono(s.roots.join(', ')) : txt('span', 'muted', 'none')],
      ['Variables', s.env.length ? mono(s.env.join(', ')) : txt('span', 'muted', 'none')],
    ]));
    out.appendChild(el('p', 'muted', 'Change its rules in your terminal: ', cmd('ms rules ' + s.key)));
    out.appendChild(txt('h2', null, 'Used in'));
    out.appendChild(list(s.used_in.map(function (u) {
      return el('div', null, link('/project/' + enc(u.project), u.project), ' · ', mono(u.file + ':' + u.line), ' · ', mono(u.var));
    }), 'No project file refers to it.'));
    out.appendChild(txt('h2', null, 'Last 20 uses'));
    out.appendChild(activityTable(s.uses));
    return out;
  }

  function activityTable(rows) {
    if (!rows.length) return txt('p', 'muted', 'Nothing recorded.');
    return table(['Time', 'Agent', 'Key', 'How', 'Target', 'Result'], rows.map(function (r) {
      return [when(r.time_unix_ms), r.agent + (r.pid ? ' (' + r.pid + ')' : ''),
        r.key ? link('/secret/' + enc(r.key), r.key, 'mono') : '', r.mechanism, mono(r.target),
        result(r.result + (r.reason ? ': ' + r.reason : ''))];
    }));
  }

  const filters = { since: '24h', result: '', agent: '', key: '', project: '' };
  function query() {
    const q = [];
    for (const k of Object.keys(filters)) if (filters[k]) q.push(k + '=' + enc(filters[k]));
    return q.join('&');
  }
  function select(label, name, options) {
    const [w, s] = field(label, 'select', name, null);
    for (const [value, label] of options) {
      const o = txt('option', null, label);
      o.value = value;
      if (filters[name] === value) o.selected = true;
      s.appendChild(o);
    }
    return w;
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

  async function activity() {
    const out = el('section', null);
    out.appendChild(txt('h1', null, 'Activity'));
    out.appendChild(txt('p', 'lead', 'Every use of a key, and every refusal, as msd recorded it.'));
    const f = el('form', 'fields');
    f.appendChild((select('Since', 'since', [['1h', 'Last hour'], ['24h', 'Last 24 h'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['', 'All']])));
    f.appendChild((select('Result', 'result', [['', 'Any'], ['allowed', 'Allowed'], ['approved', 'Approved'], ['blocked', 'Blocked'], ['denied', 'Denied'], ['failed', 'Failed'], ['alert', 'Alert']])));
    f.appendChild((select('Agent', 'agent', [['', 'Any'], ['claude-code', 'Claude Code'], ['codex', 'Codex'], ['cursor', 'Cursor'], ['gemini-cli', 'Gemini CLI']])));
    const [kw, key] = field('Key', 'input', 'key', 'For example shop/stripe-secret-key');
    key.value = filters.key;
    f.appendChild(kw);
    const [pw, proj] = field('Project', 'input', 'project', 'For example shop');
    proj.value = filters.project;
    f.appendChild(pw);
    f.appendChild(txt('button', 'btn', 'Filter'));
    f.addEventListener('submit', function (e) {
      e.preventDefault();
      for (const k of Object.keys(filters)) {
        const c = f.elements.namedItem(k);
        if (c) filters[k] = c.value.trim();
      }
      render();
    });
    out.appendChild(f);
    const acts = el('div', 'actions');
    const verify = txt('button', 'btn', 'Verify the chain');
    const verdict = txt('p', null, '');
    verify.setAttribute('type', 'button');
    verify.addEventListener('click', async function () {
      verdict.textContent = 'Checking…';
      try {
        const r = await api('/api/activity/verify');
        verdict.textContent = r.text;
        verdict.className = r.ok ? 'signal' : 'err';
      } catch (e) { fail(e, verdict); }
    });
    acts.appendChild(verify);
    for (const fmt of ['json', 'csv']) {
      const b = txt('button', 'btn', 'Export ' + fmt.toUpperCase());
      b.setAttribute('type', 'button');
      b.addEventListener('click', async function () {
        try { await download('/api/activity/export?format=' + fmt + '&' + query(), 'morsec-receipts.' + fmt); } catch (e) { fail(e, verdict); }
      });
      acts.appendChild(b);
    }
    out.appendChild(acts);
    out.appendChild(verdict);
    // A bad filter shows its error under the form, which stays usable (review R2).
    try {
      const v = await api('/api/activity?' + query());
      out.appendChild(txt('p', 'muted', v.rows.length + ' shown of ' + v.matched + ' matching (' + v.total + ' in all)'));
      out.appendChild(activityTable(v.rows));
    } catch (e) {
      if (e instanceof SignedOut) throw e;
      out.appendChild(txt('p', 'err', e && e.message ? e.message : 'The filter could not be applied.'));
    }
    return out;
  }

  async function agents() {
    const v = await api('/api/agents');
    const out = el('section', null);
    out.appendChild(txt('h1', null, 'Agents'));
    out.appendChild(table(['Agent', 'Installed', 'Connected', 'Sessions', 'Blocked', 'Last seen'], v.agents.map(function (a) {
      return [a.name, a.installed ? 'yes' : 'no', a.connected ? badge('connected', 'good') : badge('not connected', a.installed ? 'bad' : ''),
        String(a.sessions), String(a.blocked), when(a.last_seen_unix_ms)];
    })));
    out.appendChild(el('p', 'muted', 'Connect one in your terminal: ', cmd('ms connect claude-code')));
    out.appendChild(txt('h2', null, 'Checks'));
    out.appendChild(list(v.checks.map(function (c) {
      return el('div', c.ok ? null : 'err', c.ok ? 'ok · ' : 'problem · ', c.text);
    }), 'No checks.'));
    out.appendChild(el('p', 'muted', 'Every check, including each agent’s settings: ', cmd('ms doctor')));
    return out;
  }

  async function scan() {
    const v = await api('/api/scan');
    const out = el('section', null);
    out.appendChild(txt('h1', null, 'Leak scan'));
    out.appendChild(el('p', 'lead', 'Searches agent transcripts for your secret values. Run it in your terminal (Touch ID): ', cmd('ms scan')));
    const s = v.last;
    if (!s) {
      out.appendChild(txt('p', 'muted', 'No scan has run since morsec started.'));
      return out;
    }
    out.appendChild(kv([
      ['Ran', when(s.at_unix_ms)],
      ['Read', s.files_scanned + ' files, ' + s.bytes_scanned + ' bytes'],
      ['Keys searched', String(s.keys_checked)],
      ['Complete', s.complete ? 'yes' : 'no'],
    ]));
    out.appendChild(txt('h2', null, s.findings.length ? 'Found' : 'Nothing found'));
    if (s.findings.length) {
      out.appendChild(table(['Transcript', 'Line', 'Key', 'Form'], s.findings.map(function (f) {
        return [mono(f.file), String(f.line), link('/secret/' + enc(f.key), f.key, 'mono'), f.encoding];
      })));
      out.appendChild(txt('p', 'err', 'Rotate each key found at its provider.'));
    }
    if (s.skipped_keys.length) out.appendChild(el('p', 'muted', 'Too short to search: ', mono(s.skipped_keys.join(', '))));
    if (s.notes.length) out.appendChild(list(s.notes, ''));
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
    const parts = h.split('/').filter(Boolean);
    const name = parts.length ? '/' + parts[0] : '/';
    let arg = '';
    try { arg = parts.slice(1).map(decodeURIComponent).join('/'); } catch (e) { arg = ''; }
    return [name, arg];
  }

  function setPill(running) {
    stateBox.replaceChildren(txt('span', running ? 'word on' : 'word off', running ? 'On' : 'Stopped'));
  }

  function fail(e, where) {
    if (e instanceof SignedOut) { signedOut(e.message); return; }
    const p = txt('p', 'err', e && e.message ? e.message : 'Something went wrong.');
    if (where) { where.textContent = p.textContent; where.className = 'err'; } else { main.replaceChildren(p); }
  }

  let seq = 0;
  async function render() {
    const [name, arg] = parseHash();
    const view = Object.prototype.hasOwnProperty.call(routes, name) ? routes[name] : null;
    for (const a of document.querySelectorAll('#nav a')) {
      if (a.getAttribute('data-route') === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    const mine = ++seq;
    if (!view) { main.replaceChildren(txt('p', 'err', 'No such screen.')); return; }
    try {
      const node = await view(arg);
      if (mine === seq) { main.replaceChildren(node); main.focus({ preventScroll: true }); }
    } catch (e) {
      if (mine === seq) fail(e);
    }
  }

  function signedOut(why) {
    state.csrf = null;
    stateBox.replaceChildren();
    const s = el('section', null);
    s.appendChild(txt('h1', null, 'Open the dashboard from your terminal.'));
    if (why === 'closed') s.appendChild(txt('p', 'lead', 'The dashboard closed: it was idle for 30 minutes, or morsec stopped.'));
    if (why === 'another tab') s.appendChild(txt('p', 'lead', 'It was opened again in another tab, which signed this one out.'));
    s.appendChild(el('p', 'lead', 'This page signs in with a one-time link that only works once and only for a minute. Run ', cmd('ms dashboard'), ' to get a new one.'));
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
