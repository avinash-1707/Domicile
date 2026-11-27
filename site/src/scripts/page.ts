import { initFields } from "./field";

// first thing: tells the head script's failsafe that the page script is running, so reveals stay armed
document.documentElement.classList.add("js-live");

const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");
const reduced = (): boolean => reduceMotion.matches;
const $$ = <T extends Element = HTMLElement>(sel: string, root: ParentNode = document): T[] =>
  Array.from(root.querySelectorAll<T>(sel));

function span(className: string, text: string): HTMLSpanElement {
  const s = document.createElement("span");
  s.className = className;
  s.textContent = text;
  return s;
}

/** Replaces an element's text with one span per word, keeping the spaces as text nodes so it still reads as prose. */
function splitWords(el: Element, className: string, start = 0): HTMLSpanElement[] {
  const words = (el.textContent ?? "").trim().split(/\s+/);
  const spans: HTMLSpanElement[] = [];
  const parts: Node[] = [];
  words.forEach((w, i) => {
    const s = span(className, w);
    s.style.setProperty("--i", String(start + i));
    spans.push(s);
    if (i > 0) parts.push(document.createTextNode(" "));
    parts.push(s);
  });
  el.replaceChildren(...parts);
  return spans;
}

/* ---------- fonts gate, shared by reveals ---------- */
function fontsReady(): Promise<void> {
  if (!document.fonts || !document.fonts.load) return Promise.resolve();
  const probes = [document.body, document.querySelector("h1"), document.querySelector("h2"), document.querySelector("code")].filter(
    (el): el is HTMLElement => el instanceof HTMLElement,
  );
  const loads = probes.map((el) => {
    const cs = getComputedStyle(el);
    return document.fonts.load(`${cs.fontWeight} 1em ${cs.fontFamily}`);
  });
  const cap = new Promise<void>((r) => setTimeout(r, 900));
  return Promise.race([Promise.all(loads).then(() => undefined), cap]).catch(() => undefined);
}

/* ---------- scroll reveals ---------- */
function initReveals(ready: Promise<void>): void {
  const root = document.documentElement;
  if (!root.classList.contains("reveal-ready")) return;
  if (!("IntersectionObserver" in window)) {
    root.classList.remove("reveal-ready");
    return;
  }
  $$('[data-reveal="words"]').forEach((el) => {
    // keep authored line breaks: split each .line on its own, numbering words across lines
    const lines = $$(".line", el);
    if (lines.length) {
      let i = 0;
      lines.forEach((line) => (i += splitWords(line, "w", i).length));
    } else splitWords(el, "w");
  });
  $$("[data-reveal-stagger]").forEach((group) => {
    $$(":scope > [data-reveal]", group).forEach((child, i) => {
      child.style.setProperty("--reveal-delay", `${Math.min(i * 60, 360)}ms`);
    });
  });
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("is-revealed");
          io.unobserve(e.target);
        }
      });
    },
    { threshold: 0, rootMargin: "0px 0px -10% 0px" },
  );
  void ready.then(() => $$("[data-reveal]").forEach((el) => io.observe(el)));
}

/* ---------- play-once figures: line draw-on and terminal typing ---------- */
function initPlayOnce(ready: Promise<void>): void {
  const figs = $$("[data-draw], [data-type]");
  figs.forEach((fig) => {
    // only the lines that draw on get a unit length; everything else keeps its real geometry (and its dashes)
    $$<SVGGeometryElement>(".fl-edge, .lan-up, .lan-fence", fig).forEach((p) => p.setAttribute("pathLength", "1"));
    $$(".tl", fig).forEach((line, i) => line.style.setProperty("--i", String(i)));
  });
  if (reduced() || !("IntersectionObserver" in window)) {
    figs.forEach((f) => f.classList.add("played"));
    return;
  }
  figs.forEach((f) => f.classList.add("will-play"));
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("played");
          io.unobserve(e.target);
        }
      });
    },
    { threshold: 0.35 },
  );
  void ready.then(() => figs.forEach((f) => io.observe(f)));
}

/* ---------- tagline: words light up as they cross a line ---------- */
function initTagline(): void {
  const el = document.querySelector<HTMLElement>("[data-tagline]");
  if (!el) return;
  const words = splitWords(el, "tw-word");
  if (reduced()) {
    words.forEach((w) => w.classList.add("on"));
    return;
  }
  let queued = false;
  const update = (): void => {
    queued = false;
    const line = window.innerHeight * 0.62;
    words.forEach((w) => w.classList.toggle("on", w.getBoundingClientRect().top < line));
  };
  const onScroll = (): void => {
    if (!queued) {
      queued = true;
      requestAnimationFrame(update);
    }
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll);
  update();
}

/* ---------- sliding indicator shared by each option group ---------- */
function initIndicators(): void {
  $$("[data-indicator-group]").forEach((g) => {
    const ind = g.querySelector<HTMLElement>(":scope > .ind");
    if (!ind) return;
    let active: HTMLElement | null = null;
    const rest = (): HTMLElement | null =>
      g.querySelector<HTMLElement>('[aria-current], [aria-selected="true"], [data-ind-current]');
    const place = (el: HTMLElement, snap: boolean): void => {
      if (snap) g.classList.add("ind-snap");
      const gr = g.getBoundingClientRect();
      const r = el.getBoundingClientRect();
      g.style.setProperty("--x", `${r.left - gr.left}px`);
      g.style.setProperty("--y", `${r.top - gr.top}px`);
      g.style.setProperty("--w", `${r.width}px`);
      g.style.setProperty("--h", `${r.height}px`);
      if (snap) {
        void ind.offsetWidth;
        g.classList.remove("ind-snap");
      }
      active = el;
    };
    const show = (el: HTMLElement): void => {
      const first = !g.classList.contains("ind-on");
      place(el, first);
      g.classList.add("ind-on");
    };
    const settle = (): void => {
      const c = rest();
      if (c) {
        place(c, false);
        g.classList.add("ind-on");
      } else {
        g.classList.remove("ind-on");
        active = null;
      }
    };
    const itemOf = (t: EventTarget | null): HTMLElement | null =>
      t instanceof Element ? t.closest<HTMLElement>("[data-ind-item]") : null;
    g.addEventListener("pointerover", (e) => {
      const it = itemOf(e.target);
      if (it && g.contains(it)) show(it);
    });
    g.addEventListener("pointerleave", settle);
    g.addEventListener("focusin", (e) => {
      const it = itemOf(e.target);
      if (it) show(it);
    });
    g.addEventListener("focusout", (e) => {
      const next = e.relatedTarget;
      if (!(next instanceof Node) || !g.contains(next)) settle();
    });
    g.addEventListener("ind:refresh", () => {
      if (!g.matches(":hover")) settle();
    });
    new ResizeObserver(() => {
      const el = active ?? rest();
      if (el && g.classList.contains("ind-on")) place(el, true);
    }).observe(g);
    const c0 = rest();
    if (c0) {
      place(c0, true);
      g.classList.add("ind-on");
    }
    void document.fonts?.ready.then(() => {
      const c = rest();
      if (c) place(c, true);
    });
  });
}

/* ---------- copy buttons ---------- */
function copyFallback(text: string): boolean {
  const prev = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "0";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus({ preventScroll: true });
  ta.select();
  let ok = false;
  try {
    // deprecated, but the only copy path on plain-http previews where navigator.clipboard is missing;
    // some browsers throw instead of returning false, and either way the button must show the failure
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  } finally {
    ta.remove();
    prev?.focus({ preventScroll: true });
  }
  return ok;
}

function initCopy(): void {
  const live = document.querySelector<HTMLElement>("[data-copy-status]");
  const announce = (msg: string): void => {
    if (!live) return;
    // clear first so the same message is announced again on a second copy
    live.textContent = "";
    window.setTimeout(() => (live.textContent = msg), 50);
  };
  $$<HTMLButtonElement>("button[data-copy]").forEach((btn) => {
    const label = btn.querySelector<HTMLElement>(".copy-label");
    let timer = 0;
    const setState = (state: "idle" | "done" | "failed"): void => {
      btn.dataset.state = state;
      if (label) label.textContent = state === "done" ? "Copied" : state === "failed" ? "Select and copy" : "Copy";
      window.clearTimeout(timer);
      if (state !== "idle") timer = window.setTimeout(() => setState("idle"), state === "done" ? 2000 : 4000);
    };
    btn.addEventListener("click", async () => {
      const text = btn.dataset.copy ?? "";
      let ok = false;
      if (navigator.clipboard && window.isSecureContext) {
        ok = await navigator.clipboard.writeText(text).then(
          () => true,
          () => false,
        );
      }
      if (!ok) ok = copyFallback(text);
      setState(ok ? "done" : "failed");
      if (ok) {
        announce("Copied");
        return;
      }
      const pre = btn.parentElement?.querySelector("pre");
      const sel = window.getSelection();
      if (pre && sel) {
        const range = document.createRange();
        range.selectNodeContents(pre);
        sel.removeAllRanges();
        sel.addRange(range);
        announce("Copy failed. The command is selected; press Command or Control and C to copy it.");
      } else announce("Copy failed.");
    });
  });
}

/* ---------- tabs ---------- */
function initTabs(): void {
  $$("[data-tabs]").forEach((root) => {
    const list = root.querySelector<HTMLElement>('[role="tablist"]');
    if (!list) return;
    const tabs = $$<HTMLButtonElement>('[role="tab"]', list);
    const select = (tab: HTMLButtonElement, focus: boolean): void => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(t.getAttribute("aria-controls") ?? "");
        if (panel) panel.hidden = !on;
      });
      if (focus) tab.focus();
      list.dispatchEvent(new Event("ind:refresh"));
    };
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => select(t, false));
      t.addEventListener("keydown", (e) => {
        const n = tabs.length;
        let next = -1;
        if (e.key === "ArrowRight") next = (i + 1) % n;
        else if (e.key === "ArrowLeft") next = (i - 1 + n) % n;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = n - 1;
        const target = tabs[next];
        if (target) {
          e.preventDefault();
          select(target, true);
        }
      });
    });
  });
}

/* ---------- the hero cross-section: packets follow the real routing rules ---------- */
type Route = "direct" | "home" | "refused";
interface Packet {
  host: string;
  route: Route;
  path: SVGPathElement;
  len: number;
  start: number;
  speed: number;
  el: SVGGElement;
  endedAt: number;
  /** distance from the packet's centre to its edge where the route ends, so it fades before touching the window */
  endReach: number;
  startReach: number;
  /** where a refused packet stops: just above the fail-closed gate */
  stopAt: number;
}

// every host has its own window and wire in the drawing; the rule chips cover the last three
const HOSTS = ["reddit.com", "api.anthropic.com", "linkedin.com", "github.com", "x.com"];
const SVGNS = "http://www.w3.org/2000/svg";

function initScene(): void {
  const wrap = document.querySelector<HTMLElement>("[data-scene]");
  const logEl = document.querySelector<HTMLOListElement>("[data-log]");
  const statusEl = document.querySelector<HTMLElement>("[data-status]");
  const exitSwitch = document.getElementById("exit-switch");
  if (!wrap || !logEl || !exitSwitch) return;

  const rules = new Set<string>();
  $$<HTMLButtonElement>("[data-rule]").forEach((b) => {
    if (b.getAttribute("aria-pressed") === "true") rules.add(b.dataset.rule ?? "");
  });
  let exitOnline = true;

  const routeFor = (host: string): Route => (rules.has(host) ? (exitOnline ? "home" : "refused") : "direct");

  const log = (host: string, route: Route): void => {
    const li = document.createElement("li");
    li.className = `log-${route}`;
    const val = (text: string): HTMLElement => {
      const b = document.createElement("b");
      b.textContent = text;
      return b;
    };
    const parts: Node[] = [span("k", "host="), document.createTextNode(`${host} `), span("k", "via="), val(route === "direct" ? "direct" : "home")];
    if (route === "refused") parts.push(document.createTextNode(" "), span("k", "result="), val("exit_down"));
    li.replaceChildren(...parts);
    logEl.appendChild(li);
    while (logEl.children.length > 4) logEl.firstElementChild?.remove();
  };

  // the wire a host currently uses is lit; the other one is drawn faint and dashed
  const syncWires = (): void => {
    $$<SVGPathElement>(".wire-dir[data-host]", wrap).forEach((p) =>
      p.classList.toggle("on", routeFor(p.dataset.host ?? "") === "direct"),
    );
    $$<SVGPathElement>(".wire-home[data-host]", wrap).forEach((p) =>
      p.classList.toggle("on", routeFor(p.dataset.host ?? "") !== "direct"),
    );
  };

  // whichever composition is showing (wide or tall)
  let svg: SVGSVGElement | null = null;
  let layer: SVGGElement | null = null;
  let dots = false;
  const packets: Packet[] = [];
  const pickScene = (): void => {
    const visible = $$<SVGSVGElement>("svg.scene", wrap).find((s) => s.getBoundingClientRect().width > 0) ?? null;
    if (visible === svg) return;
    if (layer) layer.replaceChildren();
    packets.length = 0;
    svg = visible;
    layer = svg?.querySelector<SVGGElement>(".packets") ?? null;
    // phones draw packets as dots: labels would crowd the narrow drawing, and the log names each host
    dots = svg?.classList.contains("scene-tall") ?? false;
  };
  const routePath = (host: string, kind: "direct" | "home"): SVGPathElement | null =>
    svg?.querySelector<SVGPathElement>(`.route[data-host="${host}"][data-kind="${kind}"]`) ?? null;

  let hostIdx = 0;
  // packets fade in once clear of the server and are gone by the time their edge meets a window
  const FADE = 28;
  const fadeFor = (pk: Packet, dist: number): string => {
    const end = pk.route === "refused" ? Infinity : pk.len - dist - pk.endReach;
    const o = Math.min(1, (dist - pk.startReach) / FADE, end / FADE);
    return o >= 1 ? "" : Math.max(0, o).toFixed(2);
  };
  // half the packet's extent along the direction the route travels where it ends
  const reachAt = (path: SVGPathElement, at: number, halfW: number, halfH: number): number => {
    const a = path.getPointAtLength(Math.max(0, at - 1));
    const b = path.getPointAtLength(at);
    return Math.abs(b.x - a.x) >= Math.abs(b.y - a.y) ? halfW + 2 : halfH + 2;
  };

  const makePacket = (host: string, startOffset: number, clock: number): Packet | null => {
    if (!layer) return null;
    const route = routeFor(host);
    const path = routePath(host, route === "direct" ? "direct" : "home");
    if (!path) return null;
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", `pk pk-${route}`);
    g.style.opacity = "0";
    let halfW: number;
    let halfH: number;
    if (dots) {
      const c = document.createElementNS(SVGNS, "circle");
      c.setAttribute("r", "4.5");
      g.append(c);
      layer.appendChild(g);
      halfW = halfH = 4.5;
    } else {
      const rect = document.createElementNS(SVGNS, "rect");
      const text = document.createElementNS(SVGNS, "text");
      text.textContent = host;
      g.append(rect, text);
      layer.appendChild(g);
      const w = text.getComputedTextLength() + 14;
      rect.setAttribute("x", String(-w / 2));
      rect.setAttribute("y", "-8");
      rect.setAttribute("width", String(w));
      rect.setAttribute("height", "16");
      rect.setAttribute("rx", "8");
      text.setAttribute("x", "0");
      text.setAttribute("y", "3.5");
      halfW = w / 2;
      halfH = 8;
    }
    const speed = route === "direct" ? 120 : 230;
    const len = path.getTotalLength();
    const pk: Packet = {
      host, route, path, len, start: clock - startOffset / speed, speed, el: g, endedAt: -1,
      endReach: reachAt(path, len, halfW, halfH),
      startReach: route === "direct" ? (dots ? 16 : 62) : 8,
      stopAt: Math.max(0, Number(path.dataset.gate ?? "28") - halfH - 10),
    };
    g.style.opacity = fadeFor(pk, startOffset);
    packets.push(pk);
    return pk;
  };

  const placeAt = (pk: Packet, dist: number): void => {
    const pt = pk.path.getPointAtLength(Math.min(dist, pk.len));
    pk.el.setAttribute("transform", `translate(${pt.x.toFixed(1)} ${pt.y.toFixed(1)})`);
  };

  const hitWindow = (host: string): void => {
    const g = svg?.querySelector<SVGGElement>(`[data-win="${host}"]`);
    if (!g) return;
    g.classList.remove("hit");
    void g.getBoundingClientRect();
    g.classList.add("hit");
  };

  /* static frame for reduced motion: one packet per host, parked on its own wire */
  const renderStatic = (): void => {
    pickScene();
    if (!layer) return;
    layer.replaceChildren();
    packets.length = 0;
    let homeSeen = 0;
    HOSTS.forEach((h) => {
      const pk = makePacket(h, 0, 0);
      if (!pk) return;
      let at: number;
      if (pk.route === "refused") at = pk.stopAt;
      // direct packets park at the last point where they are fully drawn, clear of their window
      else if (pk.route === "direct") at = pk.len - pk.endReach - FADE - 4;
      // home packets share the tunnel, so space them out along it
      else at = pk.len * [0.3, 0.55, 0.8][homeSeen++ % 3]!;
      placeAt(pk, at);
      pk.el.style.opacity = fadeFor(pk, at);
    });
  };

  let clock = 0;
  let last = 0;
  let nextSpawn = 0;
  let running = false;
  let rafId = 0;
  let inView = true;

  const frame = (now: number): void => {
    if (!running) {
      rafId = 0;
      return;
    }
    const dt = last ? Math.min((now - last) / 1000, 0.05) : 0;
    last = now;
    clock += dt;
    if (clock >= nextSpawn) {
      const host = HOSTS[hostIdx % HOSTS.length] ?? "reddit.com";
      hostIdx++;
      const pk = makePacket(host, 0, clock);
      if (pk) log(host, pk.route);
      nextSpawn = clock + 1.25;
    }
    for (let i = packets.length - 1; i >= 0; i--) {
      const pk = packets[i];
      if (!pk) continue;
      const dist = (clock - pk.start) * pk.speed;
      if (pk.endedAt < 0) pk.el.style.opacity = fadeFor(pk, dist);
      if (pk.route === "refused") {
        placeAt(pk, Math.min(dist, pk.stopAt));
        if (dist >= pk.stopAt && pk.endedAt < 0) {
          pk.endedAt = clock;
          pk.el.style.opacity = "";
          pk.el.classList.add("stopped");
        }
      } else {
        placeAt(pk, dist);
        if (dist >= pk.len && pk.endedAt < 0) {
          pk.endedAt = clock;
          pk.el.style.opacity = "";
          pk.el.classList.add("arrived");
          hitWindow(pk.host);
        }
      }
      if (pk.endedAt >= 0 && clock - pk.endedAt > (pk.route === "refused" ? 1.8 : 0.9)) {
        pk.el.remove();
        packets.splice(i, 1);
      }
    }
    rafId = requestAnimationFrame(frame);
  };

  const setRunning = (): void => {
    const should = !reduced() && inView && !document.hidden;
    if (should && !running) {
      running = true;
      last = 0;
      if (!rafId) rafId = requestAnimationFrame(frame);
    } else if (!should) {
      running = false;
    }
  };

  const prefill = (): void => {
    pickScene();
    // start mid-flow so the first frame is not empty
    [["reddit.com", 520], ["github.com", 60], ["linkedin.com", 140]].forEach(([h, off]) => {
      makePacket(String(h), Number(off), clock);
    });
  };

  const announce = (msg: string): void => {
    if (statusEl) statusEl.textContent = msg;
  };

  $$<HTMLButtonElement>("[data-rule]").forEach((b) => {
    b.addEventListener("click", () => {
      const host = b.dataset.rule ?? "";
      const on = b.getAttribute("aria-pressed") !== "true";
      b.setAttribute("aria-pressed", String(on));
      if (on) rules.add(host);
      else rules.delete(host);
      // packets already on the old wire finish where they were going; new ones take the new wire
      syncWires();
      announce(
        on
          ? exitOnline
            ? `${host} now goes through home.`
            : `${host} matches a rule, but the home exit is offline, so it is refused.`
          : `${host} now goes direct from the VPS.`,
      );
      log(host, routeFor(host));
      if (reduced()) renderStatic();
    });
  });

  exitSwitch.addEventListener("click", () => {
    exitOnline = exitSwitch.getAttribute("aria-checked") !== "true";
    exitSwitch.setAttribute("aria-checked", String(exitOnline));
    // the tunnel is gone, so connections already on their way home drop with it
    if (!exitOnline)
      packets.forEach((pk) => {
        if (pk.route === "home" && pk.endedAt < 0) {
          pk.endedAt = clock;
          pk.el.style.opacity = "";
          pk.el.classList.add("dropped");
        }
      });
    wrap.classList.toggle("exit-off", !exitOnline);
    syncWires();
    announce(
      exitOnline
        ? "Home exit online. Matched domains go through home."
        : "Home exit offline. Matched domains are refused instead of leaving from the datacenter IP.",
    );
    const host = [...rules][0];
    if (host) log(host, routeFor(host));
    if (reduced()) renderStatic();
  });

  // seed the log so it is never empty
  ["reddit.com", "api.anthropic.com", "github.com"].forEach((h) => log(h, routeFor(h)));
  syncWires();

  if (reduced()) renderStatic();
  else prefill();
  if ("IntersectionObserver" in window) {
    new IntersectionObserver((entries) => {
      inView = entries.some((e) => e.isIntersecting);
      setRunning();
    }).observe(wrap);
  }
  document.addEventListener("visibilitychange", setRunning);
  setRunning();

  // swapping between wide and tall compositions
  matchMedia("(max-width: 700px)").addEventListener("change", () => {
    if (reduced()) renderStatic();
    else {
      svg = null;
      pickScene();
      prefill();
    }
  });
  reduceMotion.addEventListener("change", () => {
    if (reduced()) {
      running = false;
      renderStatic();
    } else {
      layer?.replaceChildren();
      packets.length = 0;
      prefill();
      setRunning();
    }
  });
}

const ready = fontsReady();
initReveals(ready);
initPlayOnce(ready);
initTagline();
initIndicators();
initCopy();
initTabs();
initScene();
initFields(reduceMotion);
