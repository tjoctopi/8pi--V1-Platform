import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  TreeStructure, Play, Pause, SkipForward, ArrowCounterClockwise,
  MagnifyingGlassPlus, MagnifyingGlassMinus, ArrowsIn, Crosshair, Skull,
  LockKey, Package, Globe, ShieldCheck, Eye, EyeSlash,
} from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, ErrorBoundary } from "../../components/ui";

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

// classy rounded-elbow connector between a parent's bottom-centre and a child's
// top-centre; straightens when nearly vertical, shrinks the corner radius on
// tight runs so it never self-overlaps.
function edgePath(sx, y1, tx, y2) {
  const my = (y1 + y2) / 2;
  if (Math.abs(tx - sx) < 2) return `M ${sx} ${y1} L ${tx} ${y2}`;
  const dir = tx > sx ? 1 : -1;
  const r = Math.max(0, Math.min(9, Math.abs(tx - sx) / 2, Math.abs(y2 - y1) / 3));
  return `M ${sx} ${y1} L ${sx} ${my - r} Q ${sx} ${my} ${sx + r * dir} ${my} `
    + `L ${tx - r * dir} ${my} Q ${tx} ${my} ${tx} ${my + r} L ${tx} ${y2}`;
}

/* ─── layout constants ─────────────────────────────────────────────────────── */
const NODE_W = 176;
const NODE_H = 62;
const GAP_X = 30;
const LANE_H = 138;
const TOP_PAD = 54;
const H = 640;

const STATUS_DOT = { confirmed: "●", reachable: "◐", potential: "○" };

// plain-language, defensible caption for a node (drives the replay narration)
function caption(n) {
  switch (n.phase) {
    case "origin": return "Operation origin — authorized engagement entry.";
    case "recon": return `Reconnaissance — mapped host ${n.label}.`;
    case "initial-access":
      return `Initial access — ${n.label}${n.cvss ? ` (CVSS ${n.cvss})` : ""}.`;
    case "foothold": return `Foothold — live governed session as ${n.label}.`;
    case "post-ex": return `Post-exploitation — ${n.label} captured.`;
    case "escalate": return `Privilege escalation — owned ${n.label}.`;
    case "lateral": return `Lateral movement — ${n.label}.`;
    case "objective": return `Objective reached — ${n.label}.`;
    default: return n.label;
  }
}

/* ─── deterministic layered (Sugiyama-lite) layout ─────────────────────────── */
function useLayout(tree) {
  return useMemo(() => {
    if (!tree || !tree.nodes || tree.nodes.length === 0) return null;
    const { nodes, edges } = tree;
    const parents = {}, children = {};
    edges.forEach((e) => {
      (children[e.source] = children[e.source] || []).push(e.target);
      (parents[e.target] = parents[e.target] || []).push(e.source);
    });
    // present depths → compact lane rows
    const depths = [...new Set(nodes.map((n) => n.depth))].sort((a, b) => a - b);
    const laneRow = Object.fromEntries(depths.map((d, i) => [d, i]));
    const lanes = {};
    nodes.forEach((n) => { (lanes[n.depth] = lanes[n.depth] || []).push(n); });

    const px = {};  // per-node horizontal position (centered around 0)
    depths.forEach((d) => lanes[d].forEach((n, i) => { px[n.id] = i; }));
    // barycenter passes: pull each node over the mean of its parents, then re-space
    for (let pass = 0; pass < 4; pass++) {
      depths.forEach((d) => {
        const lane = lanes[d];
        lane.forEach((n) => {
          const ps = (parents[n.id] || []).map((p) => px[p]).filter((v) => v != null);
          n.__b = ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : px[n.id];
        });
        const sorted = [...lane].sort((a, b) => a.__b - b.__b);
        const totalW = sorted.length * NODE_W + (sorted.length - 1) * GAP_X;
        const start = -totalW / 2 + NODE_W / 2;
        sorted.forEach((n, i) => { px[n.id] = start + i * (NODE_W + GAP_X); });
      });
    }
    // absolute coords
    const pos = {};
    let minX = Infinity, maxX = -Infinity, maxRow = 0;
    nodes.forEach((n) => {
      const x = px[n.id];
      const y = TOP_PAD + laneRow[n.depth] * LANE_H;
      pos[n.id] = { x, y };
      minX = Math.min(minX, x); maxX = Math.max(maxX, x);
      maxRow = Math.max(maxRow, laneRow[n.depth]);
    });
    const contentW = (maxX - minX) + NODE_W + 220;   // room for left rail
    const contentH = TOP_PAD + maxRow * LANE_H + NODE_H + 40;
    const shift = -minX + 200;  // push everything right of the phase rail
    nodes.forEach((n) => { pos[n.id].x += shift; });
    const usedDepths = depths.map((d) => ({ depth: d, row: laneRow[d] }));
    return { pos, parents, children, contentW, contentH, usedDepths };
  }, [tree]);
}

/* ─── node card (pure SVG for crisp export + perf) ─────────────────────────── */
function NodeCard({ n, x, y, selected, active, dimmed, onClick, onHover }) {
  const solid = n.status === "confirmed";
  const color = n.phase_color || "#7A7A7A";
  const sev = SEV[n.severity];
  const meter = n.cvss != null ? Math.max(0, Math.min(1, n.cvss / 10))
    : { crit: 1, high: 0.8, med: 0.55, low: 0.3, info: 0.12 }[n.severity] || 0;
  const stroke = selected ? "#FFFFFF" : active ? "#FFFFFF" : color;
  const icon = { session: "▣", loot: "⛃", credential: "⚿", ad: "♛", objective: "★",
    origin: "◎", asset: "▪", finding: "◆" }[n.kind] || "◆";
  return (
    <g transform={`translate(${x - NODE_W / 2}, ${y - NODE_H / 2})`}
      style={{ cursor: "pointer", opacity: dimmed ? 0.28 : 1, transition: "opacity .3s" }}
      onClick={(e) => { e.stopPropagation(); onClick(n); }}
      onMouseEnter={() => onHover(n)} onMouseLeave={() => onHover(null)}
      data-testid={`tree-node-${n.id}`}>
      {/* incident glow */}
      {(solid && (n.kind === "session" || n.phase === "objective" || n.severity === "crit")) && (
        <rect x={-3} y={-3} width={NODE_W + 6} height={NODE_H + 6} rx={11}
          fill="none" stroke={color} strokeWidth={1.5} opacity={active ? 0.9 : 0.45}
          className="ae-glow" />
      )}
      <rect width={NODE_W} height={NODE_H} rx={9} fill="url(#ae-node)"
        stroke={stroke} strokeWidth={selected || active ? 2 : 1.2}
        strokeDasharray={solid ? "0" : "5 4"} filter="url(#ae-shadow)" />
      {/* subtle top inner highlight for depth */}
      <rect x={1} y={1} width={NODE_W - 2} height={1} rx={1} fill="#FFFFFF" opacity={0.05} />
      {/* phase accent bar */}
      <rect x={0} y={0} width={4} height={NODE_H} rx={2} fill={color} />
      <text x={13} y={19} fontSize={12} fill={color} fontFamily="JetBrains Mono, monospace">{icon}</text>
      <text x={30} y={19} fontSize={11.5} fill="#FFFFFF" fontFamily="JetBrains Mono, monospace">
        {(n.label || "").length > 20 ? n.label.slice(0, 19) + "…" : n.label}
      </text>
      {/* technique tag */}
      <text x={13} y={35} fontSize={9.5} fill="#7A7A7A" fontFamily="JetBrains Mono, monospace">
        {n.technique?.id || n.kind} {n.status === "confirmed" ? "" : `· ${n.status}`}
      </text>
      {/* CVSS / severity meter */}
      <rect x={13} y={44} width={NODE_W - 26} height={4} rx={2} fill="#1C1C22" />
      <rect x={13} y={44} width={(NODE_W - 26) * meter} height={4} rx={2}
        fill={sev?.color || color} />
      {/* status glyph top-right */}
      <text x={NODE_W - 12} y={19} fontSize={11} textAnchor="end"
        fill={solid ? "#FF2A2A" : n.status === "reachable" ? "#FFB020" : "#7A7A7A"}>
        {STATUS_DOT[n.status]}
      </text>
      {n.cvss != null && (
        <text x={NODE_W - 12} y={52} fontSize={9} textAnchor="end"
          fill={sev?.color || "#B4B4B4"} fontFamily="JetBrains Mono, monospace">{n.cvss}</text>
      )}
    </g>
  );
}

/* ─── the tree canvas ──────────────────────────────────────────────────────── */
function TreeCanvas({ tree, layout, w, sel, setSel, hover, setHover, active, motion }) {
  const [view, setView] = useState({ k: 1, tx: 0, ty: 0 });
  const drag = useRef(null);
  const fittedFor = useRef(0);
  const boxRef = useRef(null);

  // fit to container once we know the content + width
  const fit = useCallback(() => {
    if (!layout || !w) return;
    const k = clamp(Math.min(w / layout.contentW, H / layout.contentH), 0.35, 1.1);
    setView({ k, tx: (w - layout.contentW * k) / 2, ty: 16 });
  }, [layout, w]);
  useEffect(() => {
    if (layout && w && fittedFor.current !== layout.contentW) { fittedFor.current = layout.contentW; fit(); }
  }, [layout, w, fit]);

  // Zoom about a focal point (cursor for wheel, viewport centre for buttons) so
  // content stays put under the pointer instead of flying off-screen.
  const zoomAt = useCallback((factor, fx, fy) => {
    setView((v) => {
      const k = clamp(v.k * factor, 0.3, 3.5);
      const scale = k / v.k;
      return { k, tx: fx - (fx - v.tx) * scale, ty: fy - (fy - v.ty) * scale };
    });
  }, []);
  const zoomBtn = (factor) => zoomAt(factor, w / 2, H / 2);

  // Native, non-passive wheel listener: React's onWheel is passive, so its
  // preventDefault is ignored (the page scrolls / the view jumps). Binding here
  // lets us block page scroll and zoom smoothly to the cursor.
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  const onDown = (e) => { drag.current = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty }; };
  const onMove = (e) => {
    if (!drag.current) return;
    setView((v) => ({ ...v, tx: drag.current.tx + (e.clientX - drag.current.x), ty: drag.current.ty + (e.clientY - drag.current.y) }));
  };
  const onUp = () => { drag.current = null; };

  // ancestors of the highlighted (hover or replay-active) node → light the path
  const focusId = active?.id || hover?.id || null;
  const onPath = useMemo(() => {
    if (!focusId || !layout) return null;
    const set = new Set([focusId]);
    const walk = (id) => (layout.parents[id] || []).forEach((p) => { if (!set.has(p)) { set.add(p); walk(p); } });
    walk(focusId);
    return set;
  }, [focusId, layout]);

  if (!layout) return null;
  const { pos } = layout;
  const phaseMeta = Object.fromEntries((tree.phases || []).map((p) => [p.key, p]));

  return (
    <div ref={boxRef} className="relative" style={{ width: w, height: H, background: "#050506", overflow: "hidden" }}
      onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}
      onClick={() => setSel(null)} data-testid="attack-tree">
      <svg width={w} height={H} style={{ display: "block", cursor: drag.current ? "grabbing" : "grab" }}>
        <defs>
          <pattern id="ae-grid" width="34" height="34" patternUnits="userSpaceOnUse">
            <path d="M 34 0 L 0 0 0 34" fill="none" stroke="#12131A" strokeWidth="1" />
          </pattern>
          <linearGradient id="ae-node" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#12131B" />
            <stop offset="100%" stopColor="#08080C" />
          </linearGradient>
          <filter id="ae-shadow" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" floodColor="#000000" floodOpacity="0.55" />
          </filter>
          <radialGradient id="ae-vig" cx="50%" cy="42%" r="75%">
            <stop offset="55%" stopColor="#000000" stopOpacity="0" />
            <stop offset="100%" stopColor="#000000" stopOpacity="0.55" />
          </radialGradient>
        </defs>
        <rect x={0} y={0} width={w} height={H} fill="url(#ae-grid)" />
        <g transform={`translate(${view.tx}, ${view.ty}) scale(${view.k})`}>
          {/* phase swimlanes + left rail */}
          {layout.usedDepths.map(({ depth, row }) => {
            const key = (tree.nodes.find((n) => n.depth === depth) || {}).phase;
            const meta = phaseMeta[key] || {};
            const y = TOP_PAD + row * LANE_H;
            return (
              <g key={depth} data-testid={`tree-phase-${key}`}>
                <line x1={0} y1={y - NODE_H / 2 - 20} x2={layout.contentW} y2={y - NODE_H / 2 - 20}
                  stroke="#14151C" strokeWidth={1} />
                <rect x={0} y={y - NODE_H / 2 - 20} width={5} height={LANE_H - 8} fill={meta.color || "#7A7A7A"} opacity={0.5} />
                <text x={16} y={y - 4} fontSize={12} fill={meta.color || "#7A7A7A"}
                  fontFamily="Barlow Condensed, sans-serif" letterSpacing="1.5"
                  style={{ textTransform: "uppercase", fontWeight: 700 }}>{meta.label || key}</text>
                <text x={16} y={y + 12} fontSize={9} fill="#4A4A52" fontFamily="JetBrains Mono, monospace">{meta.tactic || ""}</text>
              </g>
            );
          })}
          {/* edges */}
          {tree.edges.map((e, i) => {
            const s = pos[e.source], t = pos[e.target];
            if (!s || !t) return null;
            const y1 = s.y + NODE_H / 2, y2 = t.y - NODE_H / 2;
            const d = edgePath(s.x, y1, t.x, y2);
            const confirmed = e.status === "confirmed";
            const lit = onPath && onPath.has(e.source) && onPath.has(e.target);
            return (
              <path key={i} d={d} fill="none"
                stroke={lit ? "#FF2A2A" : confirmed ? "#FF00A0" : "#33343E"}
                strokeWidth={lit ? 2.4 : confirmed ? 1.6 : 1}
                strokeDasharray={confirmed ? (motion ? "6 5" : "0") : "3 5"}
                opacity={confirmed ? 0.9 : 0.5}
                className={confirmed && motion ? "ae-flow" : ""} />
            );
          })}
          {/* origin pulse */}
          {tree.nodes.filter((n) => n.kind === "origin").map((n) => (
            <circle key="pulse" cx={pos[n.id].x} cy={pos[n.id].y} r={NODE_W / 1.7}
              fill="none" stroke="#FFFFFF" strokeWidth={1}
              className={motion ? "ae-pulse" : ""} opacity={0.16} />
          ))}
          {/* nodes */}
          {tree.nodes.map((n) => (
            <NodeCard key={n.id} n={n} x={pos[n.id].x} y={pos[n.id].y}
              selected={sel === n.id} active={active?.id === n.id}
              dimmed={!!focusId && onPath && !onPath.has(n.id)}
              onClick={(nn) => setSel(nn.id)} onHover={setHover} />
          ))}
        </g>
        <rect x={0} y={0} width={w} height={H} fill="url(#ae-vig)" pointerEvents="none" />
      </svg>
      {/* zoom controls */}
      <div className="absolute top-3 right-3 z-20 flex items-center gap-1">
        <Btn variant="dark" icon={MagnifyingGlassPlus} onClick={() => zoomBtn(1.25)} data-testid="tree-zoom-in" />
        <Btn variant="dark" icon={MagnifyingGlassMinus} onClick={() => zoomBtn(1 / 1.25)} data-testid="tree-zoom-out" />
        <Btn variant="dark" icon={ArrowsIn} onClick={fit} data-testid="tree-fit" />
      </div>
    </div>
  );
}

/* ─── node detail panel ────────────────────────────────────────────────────── */
function NodeDetail({ n }) {
  if (!n) return (
    <Panel className="p-5"><div className="text-sm text-muted">
      Click a node to inspect the finding, the live foothold, or the captured proof.
      Hover to trace its path from the origin.
    </div></Panel>
  );
  const d = n.detail || {};
  const sev = SEV[n.severity];
  return (
    <Panel className="p-5 fadein" data-testid="tree-node-detail">
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        <span className="label" style={{ color: n.phase_color }}>{n.phase}</span>
        {n.status === "confirmed" ? <Badge color="#FF2A2A" dot>CONFIRMED</Badge>
          : <Badge color={n.status === "reachable" ? "#FFB020" : "#7A7A7A"}>{n.status}</Badge>}
      </div>
      <div className="h-font text-lg text-white break-all">{n.label}</div>
      <div className="mt-3 space-y-2 text-sm">
        {n.technique?.id && (
          <div className="flex justify-between"><span className="text-muted">Technique</span>
            <span className="mono text-xs text-sub">{n.technique.id}</span></div>
        )}
        {n.cvss != null && (
          <div className="flex justify-between items-center"><span className="text-muted">CVSS</span>
            <Badge color={sev?.color}>{n.cvss} · {sev?.label || n.severity}</Badge></div>
        )}
        {n.cve_refs?.length > 0 && (
          <div className="flex justify-between"><span className="text-muted">CVE</span>
            <span className="mono text-xs text-volt">{n.cve_refs.join(", ")}</span></div>
        )}
        {d.reachability_reason && (
          <div><div className="label mt-2 mb-0.5">Reachability</div>
            <div className="text-xs text-sub">{d.reachability_reason}</div></div>
        )}
        {d.remediation && (
          <div><div className="label mt-2 mb-0.5">Remediation</div>
            <div className="text-xs text-sub">{d.remediation}</div></div>
        )}
        {/* live foothold proof */}
        {d.proof && Object.keys(d.proof).length > 0 && (
          <div className="mt-2"><div className="label mb-1 text-incident">Foothold proof</div>
            <div className="grid grid-cols-1 gap-1">
              {Object.entries(d.proof).map(([k, v]) => (
                <div key={k} className="bg-black border border-line px-2 py-1">
                  <span className="label text-[9px]">{k} </span>
                  <span className="mono text-[11px] text-volt break-all">{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {/* proof-of-impact showcase */}
        {d.loot?.length > 0 && (
          <div className="mt-2"><div className="label mb-1 flex items-center gap-1"><Package size={11} /> Auto-run loot</div>
            <div className="bg-black border border-line divide-y divide-white/5">
              {d.loot.map((l, i) => (
                <div key={i} className="px-2 py-1">
                  <div className="mono text-[10px] text-volt">$ {l.command}</div>
                  <div className="mono text-[11px] text-sub whitespace-pre-wrap break-all">{l.output || "(no output)"}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {d.site_content && (
          <div className="mt-2"><div className="label mb-1 flex items-center gap-1"><Globe size={11} /> Captured site content</div>
            <div className="mono text-[10px] text-muted mb-1">{d.site_content.url} · HTTP {d.site_content.status}</div>
            <pre className="bg-black border border-line p-2 text-[10px] mono text-sub max-h-40 overflow-auto whitespace-pre-wrap break-all">
              {d.site_content.snippet || "(empty)"}{d.site_content.truncated ? "\n…(truncated)" : ""}
            </pre>
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ─── main tab ─────────────────────────────────────────────────────────────── */
export default function ThreatMapTab({ eid }) {
  const [tree, setTree] = useState(null);
  const [sel, setSel] = useState(null);
  const [hover, setHover] = useState(null);
  const [w, setW] = useState(0);
  const [motion, setMotion] = useState(
    !(typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches)
  );
  const wrapRef = useRef(null);

  // replay state machine (mirrors AttackPathTab's play/step/pause)
  const [step, setStep] = useState(-1);
  const [playing, setPlaying] = useState(false);

  useEffect(() => { api.attackTree(eid).then(setTree).catch(() => setTree({ nodes: [], edges: [], phases: [], summary: {} })); }, [eid]);

  useEffect(() => {
    const measure = () => { if (wrapRef.current) setW(wrapRef.current.clientWidth); };
    measure();
    const ro = new ResizeObserver(measure);
    if (wrapRef.current) ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [tree]);

  const layout = useLayout(tree);

  // the confirmed breach sequence the replay walks (depth-ordered)
  const sequence = useMemo(() => {
    if (!tree) return [];
    return tree.nodes
      .filter((n) => n.status === "confirmed" && n.kind !== "origin")
      .sort((a, b) => a.depth - b.depth || (a.label < b.label ? -1 : 1));
  }, [tree]);

  useEffect(() => {
    if (!playing) return undefined;
    if (step >= sequence.length - 1) { setPlaying(false); return undefined; }
    const t = setTimeout(() => setStep((s) => s + 1), 1600);
    return () => clearTimeout(t);
  }, [playing, step, sequence.length]);

  const active = playing || step >= 0 ? sequence[Math.max(0, Math.min(step, sequence.length - 1))] : null;
  const play = () => { if (!sequence.length) return; setStep(0); setPlaying(true); setSel(null); };
  const pause = () => setPlaying(false);
  const stepFwd = () => { setPlaying(false); setStep((s) => Math.min(s + 1, sequence.length - 1)); };
  const reset = () => { setPlaying(false); setStep(-1); setSel(null); };

  if (!tree) return <Loading label="Building attack tree" />;
  if (!tree.nodes || tree.nodes.length <= 1) {
    return <Empty icon={TreeStructure} title="No attack tree yet"
      hint="Run Full Attack (or Sensing + Vuln Scan) on the Console — the engine confirms findings, lands footholds, and this builds the kill-chain tree from the real breach." />;
  }

  const s = tree.summary || {};
  const selNode = sel ? tree.nodes.find((n) => n.id === sel) : null;
  const focus = active || selNode;

  const TILES = [
    ["Entry points", s.entry_points || 0, "#00E5FF", Crosshair],
    ["Confirmed", s.confirmed_findings || 0, "#FF00A0", ShieldCheck],
    ["Live footholds", s.live_footholds || 0, "#FF2A2A", Skull],
    ["Crown reached", s.crown_reached || 0, "#FFB020", LockKey],
  ];

  return (
    <div className="grid lg:grid-cols-4 gap-6">
      <div className="lg:col-span-3 space-y-3">
        <SectionTitle
          sub="The whole attack as a kill-chain tree — origin → initial access → foothold → post-exploitation → objective, built from the engine's real breach. Solid = confirmed / live; dashed = reachable but not yet confirmed. Press Play to walk the breach."
          right={
            <div className="flex items-center gap-1">
              {!playing ? (
                <Btn variant="primary" icon={Play} onClick={play} data-testid="tree-play"
                  disabled={!sequence.length}>Play Breach</Btn>
              ) : (
                <Btn variant="dark" icon={Pause} onClick={pause} data-testid="tree-pause">Pause</Btn>
              )}
              <Btn variant="dark" icon={SkipForward} onClick={stepFwd} data-testid="tree-step" />
              <Btn variant="dark" icon={ArrowCounterClockwise} onClick={reset} data-testid="tree-reset" />
              <Btn variant="dark" icon={motion ? Eye : EyeSlash} onClick={() => setMotion((m) => !m)}
                data-testid="tree-motion" title={motion ? "Disable motion" : "Enable motion"} />
            </div>
          }
        >
          Attack Tree
        </SectionTitle>

        <div ref={wrapRef}>
          <Panel className="p-0 overflow-hidden" data-testid="attack-tree-canvas">
            <ErrorBoundary fallback={
              <div className="p-10 text-center text-muted text-sm">
                The attack tree hit a rendering issue. Reload the tab to rebuild it from the engine.
              </div>
            }>
              {w > 0 && (
                <TreeCanvas tree={tree} layout={layout} w={w} sel={sel} setSel={setSel}
                  hover={hover} setHover={setHover} active={active} motion={motion} />
              )}
            </ErrorBoundary>
          </Panel>
          {/* replay caption + legend */}
          <div className="flex flex-wrap items-center gap-4 mt-3 text-xs">
            {active ? (
              <div className="flex items-center gap-2 mono text-[11px]" data-testid="tree-caption">
                <span className="w-2 h-2 rounded-full bg-volt blink" />
                <span className="text-volt">HOP {step + 1}/{sequence.length}</span>
                <span className="text-sub">{caption(active)}</span>
              </div>
            ) : (
              <>
                <span className="flex items-center gap-1.5 text-sub"><span className="text-incident">●</span> confirmed / live</span>
                <span className="flex items-center gap-1.5 text-sub"><span className="text-warn">◐</span> reachable</span>
                <span className="flex items-center gap-1.5 text-muted"><span>○</span> potential</span>
                <span className="flex items-center gap-1.5 text-sub"><span style={{ color: "#FF00A0" }}>—</span> confirmed path</span>
                <span className="flex items-center gap-1.5 text-muted"><span>┈</span> potential next step</span>
              </>
            )}
            <span className="ml-auto text-muted mono text-[10px]">
              {tree.nodes.length} nodes · {tree.edges.length} edges
            </span>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {/* breach summary tiles */}
        <div className="grid grid-cols-2 gap-2">
          {TILES.map(([label, val, color, Icon]) => (
            <Panel key={label} className="p-3">
              <div className="flex items-center gap-1.5 mb-1"><Icon size={13} style={{ color }} weight="fill" />
                <span className="label text-[9px]">{label}</span></div>
              <div className="h-font text-2xl font-black" style={{ color }}>{val}</div>
            </Panel>
          ))}
        </div>
        {s.domain_admin && (
          <div className="kill-stripe p-0.5 rounded-sm" data-testid="tree-da-badge">
            <div className="bg-panel2 px-4 py-3 flex items-center gap-3">
              <LockKey size={20} className="text-incident" weight="fill" />
              <span className="text-sm text-white font-semibold">Objective reached — Domain Admin</span>
            </div>
          </div>
        )}

        <NodeDetail n={focus} />
      </div>

      {/* scoped animation keyframes (professional, subtle, reduced-motion aware) */}
      <style>{`
        @keyframes ae-flow { to { stroke-dashoffset: -22; } }
        .ae-flow { animation: ae-flow 1.1s linear infinite; }
        @keyframes ae-pulse { 0% { transform: scale(0.6); opacity: .28 } 100% { transform: scale(1.5); opacity: 0 } }
        .ae-pulse { transform-box: fill-box; transform-origin: center; animation: ae-pulse 3s ease-out infinite; }
        @keyframes ae-glow { 0%,100% { opacity: .35 } 50% { opacity: .75 } }
        .ae-glow { animation: ae-glow 2.2s ease-in-out infinite; }
        @media (prefers-reduced-motion: reduce) { .ae-flow, .ae-pulse, .ae-glow { animation: none !important; } }
      `}</style>
    </div>
  );
}
