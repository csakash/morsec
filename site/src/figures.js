/* morsec figures: isometric hairline scenes drawn with the @lucasmarkes/hairline kernel (MIT).
   The idea that runs through all of them: a reference travels the wires as Morse code. Where it is
   allowed, the broker decodes it into one unbroken line (the value). Where it is not, it piles up
   against a gate and goes dim. Values never travel toward the agent. */
(() => {
  const { Cam, fit, proj, facing, rings, prism, ringAt, rrect, run, hull, poly, open, seg, circ,
    mk, solid, put, register, flatDot, place, clamp, lerp, reducedMotion, inject } = HL;
  inject(document);

  // ---------- morse ----------
  const CODE = { a: ".-", b: "-...", c: "-.-.", d: "-..", e: ".", f: "..-.", g: "--.", h: "....", i: "..", j: ".---", k: "-.-",
    l: ".-..", m: "--", n: "-.", o: "---", p: ".--.", q: "--.-", r: ".-.", s: "...", t: "-", u: "..-", v: "...-", w: ".--",
    x: "-..-", y: "-.--", z: "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.", "/": "-..-.", ":": "---...", ".": ".-.-.-" };
  /** A word as marks: [start, length] in units, front of the train first (start 0 is the head). */
  function morse(word) {
    const out = []; let at = 0;
    for (const ch of word.toLowerCase()) {
      const c = CODE[ch]; if (!c) { at += 4; continue; }
      for (const m of c) { const l = m === "-" ? 3 : 1; out.push([at, l]); at += l + 1; }
      at += 2;
    }
    return { marks: out, len: at };
  }
  window.MORSE = CODE;

  // ---------- scene ----------
  function scene(stage, pts, opts = {}) {
    const svg = stage.querySelector("svg");
    const mw = opts.w || 330, mh = opts.h || 250, cy = opts.cy || 164;
    const C0 = Cam(45, 0.5, 1); fit(C0, pts, 200, cy);
    const P0 = proj(C0);
    let a = 1e9, b = -1e9, c = 1e9, d = -1e9;
    for (const p of pts) { const q = P0(p[0], p[1], p[2]); a = Math.min(a, q[0]); b = Math.max(b, q[0]); c = Math.min(c, q[1]); d = Math.max(d, q[1]); }
    const C = Cam(45, 0.5, Math.min(mw / (b - a), mh / (d - c)));
    fit(C, pts, 200, cy);
    const P = proj(C), front = facing(C);
    const ground = mk("g", {}, svg), body = mk("g", {}, svg), top = mk("g", {}, svg);
    return { svg, C, P, front, ground, body, top, stage };
  }
  /** A rounded solid; set(z0, z1) restands it. */
  function block(sc, x0, y0, x1, y1, z0, z1, r = 3, b = 1.1, parent) {
    const [ring, inner] = rings(x0, y0, x1, y1, r, b);
    const s = solid(parent || sc.body);
    const o = { s, ring, z0, z1, set(a, c) { if (a === o.z0 && c === o.z1 && o.drawn) return; o.z0 = a; o.z1 = c; o.drawn = true; put(s, prism(sc.P, sc.front, ring, inner, a, c)); } };
    o.set(z0, z1); return o;
  }
  /** A cylinder centred on (cx, cy). */
  function cyl(sc, cx, cy, R, z0, z1, parent) {
    const shift = (rg) => rg.map((q) => ({ u: q.u + cx, v: q.v + cy, nu: q.nu, nv: q.nv }));
    const ring = shift(circ(R, 48)), inner = shift(circ(Math.max(.4, R - 1.2), 48));
    const s = solid(parent || sc.body);
    const o = { s, z0, z1, set(a, c) { if (a === o.z0 && c === o.z1 && o.drawn) return; o.z0 = a; o.z1 = c; o.drawn = true; put(s, prism(sc.P, sc.front, ring, inner, a, c)); } };
    o.set(z0, z1); return o;
  }
  /** A flat ellipse ring on the ground (a ripple). */
  function groundRing(sc, cx, cy, parent) {
    const el = mk("path", { class: "nf lo" }, parent || sc.ground);
    return { el, set(R, cls) { el.setAttribute("d", R <= 0 ? "" : poly(circ(R, 48).map((q) => sc.P(q.u + cx, q.v + cy, 0)))); if (cls) el.setAttribute("class", cls); } };
  }
  /** A wire on the ground: a dashed guide, and the ability to draw any stretch of it. */
  function wire(sc, pts, z = 0) {
    const segs = []; let L = 0;
    for (let i = 1; i < pts.length; i++) { const l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]); segs.push([L, l]); L += l; }
    const at = (s) => {
      s = clamp(s, 0, L);
      for (let i = 0; i < segs.length; i++) {
        const [a, l] = segs[i];
        if (s <= a + l || i === segs.length - 1) { const t = l ? (s - a) / l : 0; return [lerp(pts[i][0], pts[i + 1][0], t), lerp(pts[i][1], pts[i + 1][1], t), z]; }
      }
    };
    const sub = (s0, s1) => {
      s0 = clamp(s0, 0, L); s1 = clamp(s1, 0, L); if (s1 - s0 < .05) return "";
      const out = [at(s0)];
      for (let i = 0; i < segs.length; i++) { const v = segs[i][0] + segs[i][1]; if (v > s0 && v < s1) out.push([...pts[i + 1], z]); }
      out.push(at(s1));
      return open(out.map((p) => sc.P(p[0], p[1], p[2])));
    };
    mk("path", { class: "nf dash", d: open(pts.map((p) => sc.P(p[0], p[1], z))) }, sc.ground);
    return { L, at, sub };
  }
  /** A morse train on a wire; head is the distance its front has run, u the world length of one unit. */
  function train(sc, w, word, u, cls = "sig") {
    const m = morse(word), el = mk("path", { class: cls }, sc.top);
    let last = "";
    return {
      len: m.len * u,
      el,
      draw(head, pile = Infinity, gapK = 1) {
        let d = "";
        if (head > 0) {
          for (const [a, l] of m.marks) {
            let s1 = head - a * u * gapK, s0 = s1 - l * u * gapK;
            if (s1 > pile) { const k = (s1 - pile); s1 = pile - k * 0.08; s0 = s1 - l * u * 0.35; }
            d += w.sub(s0, s1);
          }
        }
        if (d !== last) { el.setAttribute("d", d); last = d; }
      },
      cls(c) { el.setAttribute("class", c); },
    };
  }
  /** Lines on an upright face: plane x = const, rows along y. */
  const rowsX = (sc, x, y0, y1, zs, parent, cls = "nf lo") => mk("path", { class: cls, d: zs.map((z) => seg(sc.P(x, y0, z), sc.P(x, y1, z))).join("") }, parent || sc.body);
  const rowsY = (sc, y, x0, x1, zs, parent, cls = "nf lo") => mk("path", { class: cls, d: zs.map((z) => seg(sc.P(x0, y, z), sc.P(x1, y, z))).join("") }, parent || sc.body);
  function dots(sc, n, x, y, parent) {
    for (let i = 0; i < n; i++) { const d = flatDot(parent || sc.ground, sc.C, 0.9, "dot m"); place(d, sc.P(x + i * 3.2, y, 0)); }
  }

  const ease = (t) => 1 - Math.pow(1 - clamp(t, 0, 1), 3);
  const easeIO = (t) => { t = clamp(t, 0, 1); return t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  const ph = (t, a, b) => clamp((t - a) / (b - a), 0, 1);
  const tog = (el, c, on) => el.classList.toggle(c, !!on);

  /** Runs f(t) on the shared loop, looping every `cycle` seconds while visible; at rest under reduced motion. */
  function animate(stage, cycle, f, still) {
    if (reducedMotion()) { f(still, true); return; }
    let t0 = null;
    register(stage, (_dt, now) => { if (t0 === null) t0 = now; f(((now - t0) / 1000) % cycle, false); return true; });
  }

  // =====================================================================
  // HERO: agent, broker, Stripe, an unknown host, and the keychain
  // =====================================================================
  function hero(stage, hooks) {
    const sc = scene(stage, [[0, -12, 0], [170, 124, 0], [136, -12, 56], [0, 120, 44], [0, 130, 0], [172, 90, 0], [4, 76, 44]], { w: 368, h: 286, cy: 162 });
    const { P } = sc;
    // wires first: they lie on the ground under everything
    const W1 = wire(sc, [[26, 95], [34, 95], [34, 62], [42, 62]]);
    const W2 = wire(sc, [[72, 48], [94, 48], [94, 4], [112, 4]]);
    const W3 = wire(sc, [[72, 64], [112, 64], [112, 76], [146, 76]]);
    const W4 = wire(sc, [[88, 92], [88, 82], [62, 82], [62, 72]]);
    // the agent: a keyboard base and a screen whose rows are text the agent can read
    const agent = block(sc, 0, 70, 26, 120, 0, 3, 2, .8);
    const screen = block(sc, 6, 76, 9, 114, 3, 40, 1.2, .5);
    rowsX(sc, 9.4, 81, 101, [34, 30.5, 27, 23.5]);
    const ref = mk("path", { class: "ink", d: "" }, sc.body);
    // the reference as it sits on screen: a short morse word, not a value
    const mm = morse("ms"); let rd = "";
    for (const [a, l] of mm.marks) rd += seg(P(9.4, 81 + a * 1.4, 18), P(9.4, 81 + (a + l) * 1.4, 18));
    ref.setAttribute("d", rd);
    // the broker: a sealed slab with a lens on top
    const broker = block(sc, 42, 42, 72, 72, 0, 12, 6, 1.6);
    const seal = cyl(sc, 57, 57, 5.5, 12, 15);
    // Stripe: a rack with slots, and a lid that lifts when a value arrives
    const rack = block(sc, 112, -8, 136, 16, 0, 44, 3, 1.1);
    rowsY(sc, 16.2, 116, 132, [36, 30, 24, 18, 12]);
    rowsX(sc, 136.2, -4, 12, [36, 30, 24, 18, 12]);
    const lid = block(sc, 113, -7, 135, 15, 46, 48, 3, 1);
    // the gate across the way to the unknown host
    const gate = block(sc, 78, 54, 80.5, 74, 0, .01, .8, .4);
    // the keychain: a vault with a dial
    const vault = block(sc, 74, 92, 104, 118, 0, 12, 5, 1.4);
    const dial = cyl(sc, 89, 105, 5, 12, 14);
    // the unknown host: drawn only as a dashed outline, because nothing about it is known
    const evil = block(sc, 146, 66, 166, 86, 0, 30, 3, 1);
    evil.s.sil.setAttribute("class", "sil dash"); evil.s.cr.setAttribute("class", "nf dash");
    // legend dots on the ground, one to four
    dots(sc, 1, 4, 126); dots(sc, 2, 44, 78); dots(sc, 3, 112, 22); dots(sc, 4, 146, 92);
    // moving parts
    const A = train(sc, W1, "ms://", 1.15), B = train(sc, W1, "ms://", 1.15), B3 = train(sc, W3, "ms://", 1.15, "bad");
    const val = mk("path", { class: "sig" }, sc.top), key = mk("path", { class: "sig" }, sc.top);
    let lastStep = -1;
    const parts = { 1: [agent, screen], 2: [broker, seal], 3: [rack, lid], 4: [evil] };
    function step(n) { if (n === lastStep) return; lastStep = n; hooks && hooks.step && hooks.step(n); }
    function f(t, still) {
      // 1. the agent sends the reference
      A.draw(ph(t, .3, 2.0) * (W1.L + A.len));
      tog(ref, "on", t > .2 && t < 2.0);
      // 2. the broker asks the keychain
      const k = ph(t, 1.9, 2.6);
      key.setAttribute("d", k > 0 && k < 1 ? W4.sub(k * W4.L - 2.2, k * W4.L) : "");
      tog(dial.s.sil, "on", t > 1.8 && t < 2.8); tog(seal.s.sil, "on", t > 1.9 && t < 4.6);
      // 3. the value leaves as one unbroken line, only to Stripe
      const g = ease(ph(t, 2.6, 3.6)), r = ease(ph(t, 4.4, 5.0));
      val.setAttribute("d", g > 0 && r < 1 ? W2.sub(r * W2.L, g * W2.L) : "");
      const lift = ph(t, 3.5, 3.8) - ph(t, 4.2, 4.8);
      lid.set(46 + 5 * ease(lift), 48 + 5 * ease(lift)); tog(lid.s.sil, "on", lift > .05);
      // 4. a second send, toward the unknown host: the gate stands up and the marks pile against it
      B.draw(ph(t, 5.0, 6.6) * (W1.L + B.len));
      const gh = ease(ph(t, 5.4, 5.9)) * (1 - ease(ph(t, 8.6, 9.1)));
      gate.set(0, Math.max(.01, 18 * gh));
      B3.draw(ph(t, 6.1, 7.3) * (B3.len + 10), 5.4);
      tog(gate.s.sil, "deny", t > 6.9 && t < 8.6);
      B3.cls(t > 7.6 ? "bad thin" : "bad");
      if (t > 8.6) B3.draw(0);
      step(t < 1.9 ? 1 : t < 2.6 ? 2 : t < 5.0 ? 3 : t < 9.1 ? 4 : 0);
      if (hooks && hooks.tick) hooks.tick(t);
    }
    animate(stage, 9.6, f, 3.7);
    return { highlight(n, on) { (parts[n] || []).forEach((p) => tog(p.s.sil, "hi", on)); } };
  }

  // =====================================================================
  // TILES
  // =====================================================================
  /** 01 · .env lines give up their values to the vault and keep a morse reference. */
  function tileImport(stage) {
    const sc = scene(stage, [[0, 0, 0], [80, 70, 0], [0, 64, 46], [80, 0, 20]], { w: 350, h: 268 });
    const { P } = sc;
    const W = wire(sc, [[12, 30], [30, 30], [30, 44], [52, 44]]);
    block(sc, 0, 4, 12, 66, 0, 2.5, 2, .8);
    block(sc, 4, 8, 7, 62, 2.5, 46, 1.2, .5);
    const vault = block(sc, 52, 30, 80, 62, 0, 12, 5, 1.4);
    const dial = cyl(sc, 66, 46, 5.5, 12, 14.5);
    const lines = [38, 31, 24, 17], valEls = [], refEls = [];
    rowsX(sc, 7.4, 12, 22, lines, sc.body);
    lines.forEach((z) => {
      valEls.push(mk("path", { class: "sig" }, sc.top));
      const r = mk("path", { class: "ink" }, sc.body); refEls.push(r);
      const m = morse("ms"); let d = ""; for (const [a, l] of m.marks) d += seg(P(7.4, 25 + a * 1.25, z), P(7.4, 25 + (a + l) * 1.25, z));
      r.dataset.d = d;
    });
    function f(t) {
      lines.forEach((z, i) => {
        const t0 = .4 + i * .9, p = ph(t, t0, t0 + 1.1), reset = t > 6.4;
        const v = valEls[i], r = refEls[i];
        if (reset || p <= 0) { v.setAttribute("d", seg(P(7.4, 25, z), P(7.4, 40, z))); r.setAttribute("d", ""); return; }
        if (p >= 1) { v.setAttribute("d", ""); r.setAttribute("d", r.dataset.d); return; }
        // lift out of the face, fly in an arc over to the vault's dial, shrinking as it goes
        const e = easeIO(p), x = lerp(7.4, 66, e), y = lerp(25, 46, e), zz = lerp(z, 15, e) + Math.sin(e * Math.PI) * 14;
        const len = lerp(15, 2, e);
        v.setAttribute("d", seg(P(x, y, zz), P(x, y + len, zz)));
        if (p > .35) r.setAttribute("d", r.dataset.d);
      });
      tog(dial.s.sil, "on", [0, 1, 2, 3].some((i) => { const a = .4 + i * .9 + 1.0; return t > a && t < a + .35; }));
    }
    animate(stage, 7.2, f, 4.2);
  }

  /** 02 · morse in, one unbroken line out, to the bound host only. */
  function tileSwap(stage) {
    const sc = scene(stage, [[0, 30, 0], [96, 0, 0], [96, 24, 46], [20, 70, 0]], { w: 350, h: 268 });
    const Win = wire(sc, [[0, 52], [26, 52]]), Wout = wire(sc, [[52, 40], [70, 40], [70, 10], [80, 10]]);
    const broker = block(sc, 26, 26, 52, 52, 0, 11, 6, 1.6);
    const seal = cyl(sc, 39, 39, 5, 11, 14);
    const rack = block(sc, 80, -2, 100, 22, 0, 40, 3, 1.1);
    rowsY(sc, 22.2, 84, 96, [32, 26, 20, 14]);
    const lid = block(sc, 81, -1, 99, 21, 42, 44, 3, 1);
    const T = train(sc, Win, "ms", 1.6), val = mk("path", { class: "sig" }, sc.top);
    function f(t) {
      T.draw(ph(t, .2, 1.8) * (Win.L + T.len));
      tog(seal.s.sil, "on", t > 1.2 && t < 3.6);
      const g = ease(ph(t, 1.6, 2.6)), r = ease(ph(t, 3.4, 4.0));
      val.setAttribute("d", g > 0 && r < 1 ? Wout.sub(r * Wout.L, g * Wout.L) : "");
      const l = ease(ph(t, 2.5, 2.8) - ph(t, 3.2, 3.8)); lid.set(42 + 5 * l, 44 + 5 * l); tog(lid.s.sil, "on", l > .05);
    }
    animate(stage, 4.8, f, 2.7);
  }

  /** 03 · a gate stands up; the marks pile against it and go dim. */
  function tileBlock(stage) {
    const sc = scene(stage, [[0, 30, 0], [100, 10, 0], [100, 30, 36], [30, 70, 0], [60, 40, 26]], { w: 350, h: 268 });
    const Win = wire(sc, [[0, 46], [56, 46], [56, 30], [84, 30]]);
    const gate = block(sc, 40, 36, 42.5, 56, 0, .01, .8, .4);
    const host = block(sc, 84, 18, 104, 40, 0, 30, 3, 1);
    host.s.sil.setAttribute("class", "sil dash"); host.s.cr.setAttribute("class", "nf dash");
    const T = train(sc, Win, "ms://", 1.3, "bad");
    function f(t) {
      gate.set(0, Math.max(.01, 22 * ease(ph(t, .1, .7)) * (1 - ease(ph(t, 4.6, 5.1)))));
      T.draw(ph(t, .5, 2.2) * (T.len + 30), 38.5);
      T.cls(t > 2.6 ? "bad thin" : "bad");
      tog(gate.s.sil, "deny", t > 1.6 && t < 4.6);
      if (t > 4.6) T.draw(0);
    }
    animate(stage, 5.6, f, 2.4);
  }

  /** 04 · a production key waits at a gate until Touch ID; then one line reaches the database. */
  function tileApprove(stage) {
    const sc = scene(stage, [[-16, 40, 0], [104, 0, 0], [100, 20, 40], [20, 74, 0], [-16, 74, 0]], { w: 350, h: 268 });
    const Win = wire(sc, [[0, 34], [30, 34]]), Wout = wire(sc, [[33, 34], [60, 34], [60, 12], [78, 12]]);
    const gate = block(sc, 30.5, 26, 33, 42, 0, 16, .8, .4);
    const pad = cyl(sc, 12, 60, 10, 0, 5);
    const ripples = [0, 1, 2].map(() => groundRing(sc, 12, 60));
    const db = [0, 1, 2].map((i) => cyl(sc, 90, 12, 11, i * 11, i * 11 + 9));
    const T = train(sc, Win, "ms", 1.5), val = mk("path", { class: "sig" }, sc.top);
    function f(t) {
      T.draw(Math.min(ph(t, .2, 1.4) * (Win.L + T.len), Win.L + 2), Win.L - .6);
      const press = ph(t, 1.6, 1.85) - ph(t, 2.1, 2.5);
      pad.set(0, 5 - 2.4 * ease(press)); tog(pad.s.sil, "on", t > 1.6 && t < 3.2);
      ripples.forEach((rp, i) => { const p = ph(t, 1.8 + i * .22, 2.9 + i * .22); rp.set(p > 0 && p < 1 ? 11 + p * 26 : 0, p > .6 ? "nf lo" : "nf"); });
      gate.set(0, Math.max(.01, 16 * (1 - ease(ph(t, 2.4, 2.9))) + 16 * ease(ph(t, 5.0, 5.5))));
      if (t > 2.6) T.draw(0);
      const g = ease(ph(t, 2.7, 3.6)), r = ease(ph(t, 4.4, 5.0));
      val.setAttribute("d", g > 0 && r < 1 ? Wout.sub(r * Wout.L, g * Wout.L) : "");
      const l = ease(ph(t, 3.5, 3.8) - ph(t, 4.2, 4.8));
      db[2].set(22 + 4 * l, 31 + 4 * l); tog(db[2].s.sil, "on", l > .05);
    }
    animate(stage, 6.0, f, 3.7);
  }

  /** Release · two clean builds hash the same; then the signature stamps the one that ships. */
  function tileRelease(stage) {
    const sc = scene(stage, [[0, -12, 0], [76, 26, 0], [0, 0, 46], [74, -12, 48], [12, 26, 0]], { w: 330, h: 250 });
    const { P } = sc;
    const a = block(sc, 0, 0, 24, 24, 0, 20, 3, 1.1);
    const sa = mk("path", { class: "sig thin" }, sc.body);
    const b = block(sc, 50, -10, 74, 14, 0, 20, 3, 1.1);
    const sb = mk("path", { class: "sig thin" }, sc.body);
    const link = mk("path", { class: "nf dash" }, sc.ground);
    link.setAttribute("d", seg(P(12, 12, 20), P(62, 2, 20)));
    const match = mk("path", { class: "sig" }, sc.top);
    const stamp = cyl(sc, 62, 2, 6, 40, 46, sc.top);
    function scan(el, x0, y0, x1, y1, z) { el.setAttribute("d", z <= 0 ? "" : seg(P(x1, y0, z), P(x1, y1, z)) + seg(P(x0, y1, z), P(x1, y1, z))); }
    function f(t) {
      const h = ph(t, .3, 1.9), z = h > 0 && h < 1 ? 1 + 18 * easeIO(h) : 0;
      scan(sa, 0, 0, 24.3, 24.3, z); scan(sb, 50, -10, 74.3, 14.3, z);
      const m = ease(ph(t, 2.0, 2.6)) * (1 - ease(ph(t, 4.6, 5.0)));
      match.setAttribute("d", m > 0 ? open([P(12, 12, 20), P(lerp(12, 62, m), lerp(12, 2, m), 20)]) : "");
      tog(a.s.sil, "on", t > 2.5 && t < 4.6); tog(b.s.sil, "on", t > 2.5 && t < 5.4);
      const d = ease(ph(t, 2.9, 3.4)) - ease(ph(t, 3.7, 4.3));
      stamp.set(40 - 18 * d, 46 - 18 * d); tog(stamp.s.sil, "on", d > .9);
    }
    animate(stage, 6.0, f, 3.5);
  }

  window.MorsecFigures = { hero, tileImport, tileSwap, tileBlock, tileApprove, tileRelease, morse };
})();
