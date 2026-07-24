import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, MiniMap, Panel as RFPanel,
  Handle, Position, useNodesState, useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  TreeStructure, Play, Pause, SkipForward, ArrowCounterClockwise,
  Crosshair, Skull, LockKey, Package, Globe, ShieldCheck, Eye, EyeSlash,
} from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty } from "../../components/ui";

/* ─── layout constants (deterministic layered / Sugiyama-lite) ─────────────── */
const NODE_W = 190;
const NODE_H = 66;
const GAP_X = 34;
const LANE_H = 150;
const TOP_PAD = 40;
const H = 640;

const STATUS_DOT = { confirmed: "●", reachable: "◐", potential: "○" };
const STATUS_COLOR = { confirmed: "#FF2A2A", reachable: "#FFB020", potential: "#7A7A7A" };
const KIND_ICON = { session: "▣", loot: "⛃", credential: "⚿", ad: "♛", objective: "★",
  origin: "◎", asset: "▪", finding: "◆" };

function caption(n) {
  switch (n.phase) {
    case "origin": return "Operation origin — authorized engagement entry.";
    case "recon": return `Reconnaissance — mapped host ${n.label}.`;
    case "initial-access": return `Initial access — ${n.label}${n.cvss ? ` (CVSS ${n.cvss})` : ""}.`;
    case "foothold": return `Foothold — live governed session as ${n.label}.`;
    case "post-ex": return `Post-exploitation — ${n.label} captured.`;
    case "escalate": return `Privilege escalation — owned ${n.label}.`;
    case "lateral": return `Lateral movement — ${n.label}.`;
    case "objective": return `Objective reached — ${n.label}.`;
    default: return n.label;
  }
}

/* ─── deterministic layered layout: node id → {x,y} centred per phase row ───── */
function computeLayout(tree) {
  if (!tree || !tree.nodes || tree.nodes.length === 0) return null;
  const { nodes, edges } = tree;
  const parents = {}, children = {};
  edges.forEach((e) => {
    (children[e.source] = children[e.source] || []).push(e.target);
    (parents[e.target] = parents[e.target] || []).push(e.source);
  });
  const depths = [...new Set(nodes.map((n) => n.depth))].sort((a, b) => a - b);
  const laneRow = Object.fromEntries(depths.map((d, i) => [d, i]));
  const lanes = {};
  nodes.forEach((n) => { (lanes[n.depth] = lanes[n.depth] || []).push(n); });
  const px = {};
  depths.forEach((d) => lanes[d].forEach((n, i) => { px[n.id] = i; }));
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
  const pos = {};
  nodes.forEach((n) => {
    pos[n.id] = { x: px[n.id], y: TOP_PAD + laneRow[n.depth] * LANE_H };
  });
  const xs = Object.values(pos).map((p) => p.x);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  return {
    pos, parents,
    lanes: depths.map((d) => ({ depth: d, y: TOP_PAD + laneRow[d] * LANE_H })),
    minX: minX - NODE_W / 2 - 30, maxX: maxX + NODE_W / 2 + 30,
  };
}

/* ─── custom React Flow node — HUD attack card ─────────────────────────────── */
const AttackNode = React.memo(function AttackNode({ data }) {
  const n = data.n;
  const solid = n.status === "confirmed";
  const color = n.phase_color || "#7A7A7A";
  const sev = SEV[n.severity];
  const meter = n.cvss != null ? Math.max(0, Math.min(1, n.cvss / 10))
    : ({ crit: 1, high: 0.8, med: 0.55, low: 0.3, info: 0.12 }[n.severity] || 0);
  const incident = solid && (n.kind === "session" || n.phase === "objective" || n.severity === "crit");
  return (
    <div
      style={{
        width: NODE_W, height: NODE_H, position: "relative",
        background: "linear-gradient(180deg,#12131B,#08080C)",
        border: `${data.selected || data.active ? 2 : 1.2}px ${solid ? "solid" : "dashed"} ${data.selected || data.active ? "#fff" : color}`,
        borderRadius: 9, opacity: data.dim ? 0.3 : 1,
        boxShadow: incident ? `0 0 0 1px ${color}55, 0 4px 14px ${color}33` : "0 4px 12px rgba(0,0,0,.5)",
        transition: "opacity .25s, border-color .2s", overflow: "hidden",
        fontFamily: "JetBrains Mono, monospace",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0, top: 0 }} />
      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 4, background: color }} />
      <div style={{ padding: "7px 10px 7px 13px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ color, fontSize: 12 }}>{KIND_ICON[n.kind] || "◆"}</span>
          <span style={{ color: "#fff", fontSize: 11.5, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flex: 1 }}>
            {n.label}
          </span>
          <span style={{ color: STATUS_COLOR[n.status], fontSize: 11 }}>{STATUS_DOT[n.status]}</span>
        </div>
        <div style={{ color: "#7A7A7A", fontSize: 9.5, marginTop: 3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {(n.technique && n.technique.id) || n.kind}{n.status !== "confirmed" ? ` · ${n.status}` : ""}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
          <div style={{ flex: 1, height: 4, background: "#1C1C22", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ width: `${meter * 100}%`, height: "100%", background: (sev && sev.color) || color }} />
          </div>
          {n.cvss != null && <span style={{ color: (sev && sev.color) || "#B4B4B4", fontSize: 9 }}>{n.cvss}</span>}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0, bottom: 0 }} />
    </div>
  );
});

/* ─── phase swimlane band (background, non-interactive) ─────────────────────── */
const LaneNode = React.memo(function LaneNode({ data }) {
  return (
    <div style={{ width: data.width, height: LANE_H - 12, pointerEvents: "none",
      borderTop: "1px solid #14151C", position: "relative" }}>
      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 4, background: data.color, opacity: 0.5 }} />
      <div style={{ position: "absolute", left: 14, top: 6, fontFamily: "Barlow Condensed, sans-serif",
        fontWeight: 700, letterSpacing: 1.5, textTransform: "uppercase", fontSize: 12, color: data.color }}>
        {data.label}
      </div>
      <div style={{ position: "absolute", left: 14, top: 24, fontFamily: "JetBrains Mono, monospace",
        fontSize: 9, color: "#4A4A52" }}>{data.tactic}</div>
    </div>
  );
});

const NODE_TYPES = { attack: AttackNode, lane: LaneNode };

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
  const [motion, setMotion] = useState(
    !(typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches)
  );
  const [step, setStep] = useState(-1);
  const [playing, setPlaying] = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    api.attackTree(eid).then(setTree).catch(() => setTree({ nodes: [], edges: [], phases: [], summary: {} }));
  }, [eid]);

  const layout = useMemo(() => computeLayout(tree), [tree]);
  const nodeById = useMemo(
    () => Object.fromEntries((tree?.nodes || []).map((n) => [n.id, n])), [tree]);
  const phaseMeta = useMemo(
    () => Object.fromEntries((tree?.phases || []).map((p) => [p.key, p])), [tree]);

  // the confirmed breach sequence the replay walks
  const sequence = useMemo(() => {
    if (!tree) return [];
    return tree.nodes
      .filter((n) => n.status === "confirmed" && n.kind !== "origin")
      .sort((a, b) => a.depth - b.depth || (a.label < b.label ? -1 : 1));
  }, [tree]);

  const active = playing || step >= 0 ? sequence[Math.max(0, Math.min(step, sequence.length - 1))] : null;
  const focusId = active?.id || hover?.id || null;
  const onPath = useMemo(() => {
    if (!focusId || !layout) return null;
    const set = new Set([focusId]);
    const walk = (id) => (layout.parents[id] || []).forEach((p) => { if (!set.has(p)) { set.add(p); walk(p); } });
    walk(focusId);
    return set;
  }, [focusId, layout]);

  // build the React Flow graph once the data + layout are ready
  useEffect(() => {
    if (!tree || !layout) { setNodes([]); setEdges([]); return; }
    const laneNodes = layout.lanes.map((ln) => {
      const key = (tree.nodes.find((n) => n.depth === ln.depth) || {}).phase;
      const m = phaseMeta[key] || {};
      return {
        id: `lane-${ln.depth}`, type: "lane", draggable: false, selectable: false,
        focusable: false, zIndex: 0,
        position: { x: layout.minX, y: ln.y - NODE_H / 2 - 18 },
        data: { width: layout.maxX - layout.minX, label: m.label || key, tactic: m.tactic || "", color: m.color || "#7A7A7A" },
      };
    });
    const attackNodes = tree.nodes.map((n) => ({
      id: n.id, type: "attack", draggable: false, zIndex: 1,
      position: { x: layout.pos[n.id].x - NODE_W / 2, y: layout.pos[n.id].y - NODE_H / 2 },
      data: { n, selected: false, active: false, dim: false },
    }));
    setNodes([...laneNodes, ...attackNodes]);
    setEdges(tree.edges.map((e) => ({
      id: `${e.source}->${e.target}`, source: e.source, target: e.target,
      type: "smoothstep",
      data: { confirmed: e.status === "confirmed" },
      style: { stroke: e.status === "confirmed" ? "#FF00A0" : "#33343E",
               strokeWidth: e.status === "confirmed" ? 1.6 : 1,
               strokeDasharray: e.status === "confirmed" ? undefined : "3 5" },
    })));
  }, [tree, layout, phaseMeta, setNodes, setEdges]);

  // reactive highlight (selection / hover / replay) without rebuilding positions
  useEffect(() => {
    setNodes((ns) => ns.map((rn) => rn.type !== "attack" ? rn : {
      ...rn,
      data: { ...rn.data, selected: sel === rn.id, active: active?.id === rn.id,
              dim: !!focusId && onPath && !onPath.has(rn.id) },
    }));
    setEdges((es) => es.map((e) => {
      const lit = onPath && onPath.has(e.source) && onPath.has(e.target);
      return {
        ...e, animated: !!(e.data?.confirmed && motion),
        style: { ...e.style,
                 stroke: lit ? "#FF2A2A" : e.data?.confirmed ? "#FF00A0" : "#33343E",
                 strokeWidth: lit ? 2.6 : e.data?.confirmed ? 1.6 : 1 },
      };
    }));
  }, [sel, hover, active, focusId, onPath, motion, setNodes, setEdges]);

  useEffect(() => {
    if (!playing) return undefined;
    if (step >= sequence.length - 1) { setPlaying(false); return undefined; }
    const t = setTimeout(() => setStep((s) => s + 1), 1600);
    return () => clearTimeout(t);
  }, [playing, step, sequence.length]);

  const play = () => { if (!sequence.length) return; setStep(0); setPlaying(true); setSel(null); };
  const pause = () => setPlaying(false);
  const stepFwd = () => { setPlaying(false); setStep((s) => Math.min(s + 1, sequence.length - 1)); };
  const reset = () => { setPlaying(false); setStep(-1); setSel(null); };

  const onNodeClick = useCallback((_e, node) => {
    if (node.type === "attack") setSel(node.id);
  }, []);
  const onNodeEnter = useCallback((_e, node) => { if (node.type === "attack") setHover(nodeById[node.id]); }, [nodeById]);
  const onNodeLeave = useCallback(() => setHover(null), []);

  if (!tree) return <Loading label="Building attack tree" />;
  if (!tree.nodes || tree.nodes.length <= 1) {
    return <Empty icon={TreeStructure} title="No attack tree yet"
      hint="Run Full Attack (or Sensing + Vuln Scan) on the Console — the engine confirms findings, lands footholds, and this builds the kill-chain tree from the real breach." />;
  }

  const s = tree.summary || {};
  const selNode = sel ? nodeById[sel] : null;
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
          sub="The whole attack as a kill-chain tree — origin → initial access → foothold → post-exploitation → objective, built from the engine's real breach. Solid = confirmed / live; dashed = reachable but not yet confirmed. Scroll to zoom · drag to pan · Play to walk the breach."
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

        <Panel className="p-0 overflow-hidden" data-testid="attack-tree-canvas">
          <div style={{ width: "100%", height: H, background: "#050506" }} data-testid="attack-tree">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={NODE_TYPES}
              onNodeClick={onNodeClick}
              onNodeMouseEnter={onNodeEnter}
              onNodeMouseLeave={onNodeLeave}
              onPaneClick={() => setSel(null)}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.2}
              maxZoom={2.5}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable
              proOptions={{ hideAttribution: true }}
              defaultEdgeOptions={{ type: "smoothstep" }}
            >
              <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="#15161D" />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable
                style={{ background: "#0A0A0C", border: "1px solid #1A1A1A" }}
                maskColor="rgba(0,0,0,0.6)"
                nodeColor={(nd) => (nd.type === "lane" ? "transparent" : (nd.data?.n?.phase_color || "#7A7A7A"))}
                nodeStrokeWidth={0} />
              <RFPanel position="bottom-center">
                <div className="flex flex-wrap items-center gap-4 px-3 py-1.5 text-[11px] mono bg-black/70 border border-line rounded-sm">
                  {active ? (
                    <span className="flex items-center gap-2" data-testid="tree-caption">
                      <span className="w-2 h-2 rounded-full bg-volt blink" />
                      <span className="text-volt">HOP {step + 1}/{sequence.length}</span>
                      <span className="text-sub">{caption(active)}</span>
                    </span>
                  ) : (
                    <>
                      <span className="text-sub"><span className="text-incident">●</span> confirmed / live</span>
                      <span className="text-sub"><span className="text-warn">◐</span> reachable</span>
                      <span className="text-muted"><span>○</span> potential</span>
                      <span className="text-sub"><span style={{ color: "#FF00A0" }}>—</span> confirmed path</span>
                      <span className="text-muted">┈ potential</span>
                    </>
                  )}
                </div>
              </RFPanel>
            </ReactFlow>
          </div>
        </Panel>
      </div>

      <div className="space-y-4">
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
    </div>
  );
}
