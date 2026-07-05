import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { Graph, ArrowsOutSimple, MagnifyingGlassPlus, MagnifyingGlassMinus, ArrowsInSimple, ArrowsClockwise, StackSimple } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { riskBucket } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty } from "../../components/ui";

/* — sizing hook (SVG-free, honors container width) — */
function useSize(defaultH = 560) {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver((e) => setW(e[0].contentRect.width));
    ro.observe(ref.current);
    setW(ref.current.clientWidth);
    return () => ro.disconnect();
  }, []);
  return [ref, w, defaultH];
}

/* — telemetry tooltip (React overlay, follows mouse) — */
function Tooltip({ node, x, y }) {
  if (!node) return null;
  const b = riskBucket(node.risk);
  return (
    <div
      className="absolute pointer-events-none z-40"
      style={{ left: x + 14, top: y + 14, transform: y > 400 ? "translateY(-100%)" : undefined }}
    >
      <div className="bg-black/95 border shadow-2xl px-3 py-2.5 min-w-[240px] max-w-[320px]"
        style={{ borderColor: node.layer_color }}>
        <div className="flex items-center gap-1.5 mb-1.5">
          <span className="w-2 h-2" style={{ background: node.layer_color, boxShadow: `0 0 6px ${node.layer_color}` }} />
          <span className="label" style={{ color: node.layer_color }}>{node.layer_label}</span>
          <span className="ml-auto label">{node.type}</span>
        </div>
        <div className="mono text-xs text-white break-all mb-1">{node.label}</div>
        <div className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2 text-[11px] mono">
          {node.product && (
            <div className="col-span-2"><span className="text-muted">stack </span><span className="text-white">{node.product}{node.version ? ` ${node.version}` : ""}</span></div>
          )}
          {node.port && <div><span className="text-muted">port </span><span className="text-info">{node.port}</span></div>}
          <div>
            <span className="text-muted">exposure </span>
            <span style={{ color: node.exposure === "external" ? "#FF00A0" : "#B4B4B4" }}>{node.exposure || "?"}</span>
          </div>
          <div>
            <span className="text-muted">risk </span>
            <span style={{ color: b.color, fontWeight: b.color === "#FF2A2A" ? 900 : 600 }}>{node.risk}</span>
          </div>
          <div>
            <span className="text-muted">findings </span>
            <span style={{ color: node.open_findings > 0 ? "#FFB020" : "#B4B4B4" }}>{node.open_findings || 0}</span>
          </div>
        </div>
        {node.top_finding && (
          <div className="mt-2 pt-2 border-t border-line">
            <div className="label mb-0.5">Top Finding</div>
            <div className="text-[11px] text-sub truncate">{node.top_finding.title}</div>
            <div className="flex items-center gap-1.5 mt-1 flex-wrap">
              <span
                className="text-[10px] uppercase font-bold px-1.5 py-0.5 border"
                style={{
                  color: node.top_finding.severity === "crit" ? "#FF2A2A" : node.top_finding.severity === "high" ? "#FF00A0" : "#FFB020",
                  borderColor: node.top_finding.severity === "crit" ? "#FF2A2A" : node.top_finding.severity === "high" ? "#FF00A0" : "#FFB020",
                  textShadow: node.top_finding.severity === "crit" ? "0 0 4px #FF2A2A" : undefined,
                }}
              >
                {node.top_finding.severity}
              </span>
              {node.top_finding.exploitability === "confirmed" && (
                <span className="text-[10px] uppercase font-black px-1.5 py-0.5 border"
                  style={{ color: "#FF2A2A", borderColor: "#FF2A2A", textShadow: "0 0 4px #FF2A2A" }}>
                  ▲ CONFIRMED
                </span>
              )}
              {node.top_finding.kev && (
                <span className="text-[10px] uppercase font-black px-1.5 py-0.5 border"
                  style={{ color: "#FF2A2A", borderColor: "#FF2A2A", textShadow: "0 0 4px #FF2A2A" }}>
                  ▲ CISA KEV
                </span>
              )}
              {node.top_finding.cve_refs?.[0] && (
                <span className="text-[10px] mono text-muted">{node.top_finding.cve_refs[0]}</span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* — layer legend with counts, filter-on-hover — */
function LayerLegend({ layers, hover, setHover, activeSet, onToggle }) {
  return (
    <Panel className="p-3">
      <div className="flex items-center gap-2 mb-3 px-1">
        <StackSimple size={14} weight="bold" className="text-sub" />
        <span className="label">Ecosystem Layers</span>
      </div>
      <div className="space-y-1.5">
        {layers.map((l) => {
          const on = hover === l.key;
          const active = activeSet.size === 0 || activeSet.has(l.key);
          return (
            <button
              key={l.key}
              onMouseEnter={() => setHover(l.key)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onToggle(l.key)}
              data-testid={`tm-layer-${l.key}`}
              className={`w-full text-left px-2.5 py-2 border transition-colors ${on ? "bg-white/5" : "hover:bg-white/5"} ${!active ? "opacity-40" : ""}`}
              style={{ borderColor: on ? l.color : "#1A1A1A" }}
            >
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 shrink-0" style={{ background: l.color, boxShadow: on ? `0 0 8px ${l.color}` : "none" }} />
                <span className="h-font text-sm uppercase tracking-widest2" style={{ color: on ? l.color : "#fff" }}>{l.label}</span>
                <span className="ml-auto mono text-[11px] text-muted">{l.count}</span>
              </div>
              <div className="flex items-center justify-between mt-1 ml-4.5">
                <span className="text-[10px] text-muted">
                  {l.external > 0 && <span className="text-volt">▲ {l.external} ext</span>}
                  {l.external > 0 && l.findings > 0 && <span className="text-muted"> · </span>}
                  {l.findings > 0 && <span className="text-warn">{l.findings} finding{l.findings !== 1 ? "s" : ""}</span>}
                  {!l.external && !l.findings && <span className="text-muted">clean</span>}
                </span>
                <span className="mono text-[10px] text-muted">R {l.risk}</span>
              </div>
            </button>
          );
        })}
      </div>
    </Panel>
  );
}

export default function ThreatMapTab({ eid }) {
  const [map, setMap] = useState(null);
  const [sel, setSel] = useState(null);
  const [hover, setHover] = useState(null);
  const [hoverPos, setHoverPos] = useState({ x: 0, y: 0 });
  const [hoverLayer, setHoverLayer] = useState(null);
  const [activeLayers, setActiveLayers] = useState(new Set());
  const [ref, w] = useSize();
  const H = 620;
  const fgRef = useRef(null);

  useEffect(() => { api.threatMap(eid).then(setMap); }, [eid]);

  const data = useMemo(() => {
    if (!map) return { nodes: [], links: [] };
    // Filter by active layers if any picked. Also filter edges to only visible nodes.
    const passes = (n) => (activeLayers.size === 0) || activeLayers.has(n.layer);
    const nodes = map.nodes.filter(passes).map((n) => ({ ...n, __r: riskBucket(n.risk) }));
    const nid = new Set(nodes.map((n) => n.id));
    const links = map.edges
      .filter((e) => nid.has(e.source) && nid.has(e.target))
      .map((e) => ({ source: e.source, target: e.target }));
    return { nodes, links };
  }, [map, activeLayers]);

  const nodeById = useMemo(() => Object.fromEntries((map?.nodes || []).map((n) => [n.id, n])), [map]);

  const paintNode = useCallback((n, ctx, scale) => {
    const isHost = !n.parent;
    const b = n.__r || riskBucket(n.risk);
    const baseR = isHost ? 8 : 5;
    const r = sel === n.id ? baseR + 3 : baseR;
    const dimmed = hoverLayer && n.layer !== hoverLayer;
    // dashed halo when externally exposed
    if (n.exposure === "external") {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 5, 0, 2 * Math.PI);
      ctx.setLineDash([2, 3]);
      ctx.strokeStyle = `${b.color}${dimmed ? "44" : "aa"}`;
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);
    }
    // pulsing red glow for confirmed / KEV / crit
    const incident = n.top_finding && (n.top_finding.exploitability === "confirmed" || n.top_finding.kev || n.top_finding.severity === "crit");
    if (incident) {
      const t = (Date.now() % 1400) / 1400;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 8 + t * 6, 0, 2 * Math.PI);
      ctx.strokeStyle = `#FF2A2A${Math.floor((1 - t) * 200).toString(16).padStart(2, "0")}`;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
    // node core — layer color if healthy, incident-red if incident, sized by risk bucket
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
    ctx.fillStyle = dimmed ? `${n.layer_color}33` : incident ? "#FF2A2A" : n.layer_color;
    ctx.fill();
    ctx.strokeStyle = sel === n.id ? "#FFFFFF" : incident ? "#FF2A2A" : n.layer_color;
    ctx.lineWidth = sel === n.id ? 2 : 1;
    ctx.stroke();
    if (n.risk > 60 || sel === n.id) {
      ctx.shadowColor = incident ? "#FF2A2A" : n.layer_color;
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r * 0.5, 0, 2 * Math.PI);
      ctx.fillStyle = incident ? "#FF2A2A" : n.layer_color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
    // label on host nodes when zoomed in enough
    if (isHost && scale > 0.7 && !dimmed) {
      const label = n.label.length > 22 ? n.label.slice(0, 20) + "…" : n.label;
      ctx.font = `${11 / scale}px JetBrains Mono, monospace`;
      ctx.fillStyle = "#B4B4B4";
      ctx.textAlign = "center";
      ctx.fillText(label, n.x, n.y + r + 12 / scale);
    }
  }, [sel, hoverLayer]);

  const paintLink = useCallback((link, ctx) => {
    const s = typeof link.source === "object" ? link.source : nodeById[link.source];
    const t = typeof link.target === "object" ? link.target : nodeById[link.target];
    if (!s || !t) return;
    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
    ctx.strokeStyle = "#33333388";
    ctx.lineWidth = 1;
    ctx.stroke();
  }, [nodeById]);

  const onNodeHover = useCallback((n) => {
    setHover(n || null);
    document.body.style.cursor = n ? "pointer" : "default";
  }, []);

  const onNodeClick = useCallback((n) => {
    setSel(n.id);
    fgRef.current?.centerAt(n.x, n.y, 800);
    fgRef.current?.zoom(2.2, 800);
  }, []);

  const toggleLayer = (key) => {
    setActiveLayers((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
    setSel(null);
  };

  useEffect(() => {
    // physics tune-up: keep it slightly loose, cap animation for perf
    const fg = fgRef.current;
    if (!fg) return;
    fg.d3Force("charge").strength(-140).distanceMax(400);
    fg.d3Force("link").distance((l) => (typeof l.source === "object" && !l.source.parent && typeof l.target === "object" && l.target.parent ? 34 : 90));
  }, [data.nodes.length]);

  if (!map) return <Loading label="Building risk map" />;
  if (map.nodes.length === 0)
    return <Empty icon={Graph} title="No risk map yet" hint="Run Sensing and a Vuln Scan to build the living threat map (C-08)." />;

  const selNode = sel ? nodeById[sel] : null;

  return (
    <div className="grid lg:grid-cols-4 gap-6">
      <div className="lg:col-span-3 space-y-3">
        <SectionTitle
          sub="Assets as nodes · relationships as edges · risk ranked by exploitable exposure (FR-TM-02). Scroll to zoom · drag to pan · drag nodes to reposition · hover for telemetry."
          right={
            <div className="flex items-center gap-1">
              <Btn variant="dark" icon={MagnifyingGlassPlus} onClick={() => fgRef.current?.zoom(fgRef.current.zoom() * 1.3, 300)} data-testid="tm-zoom-in" />
              <Btn variant="dark" icon={MagnifyingGlassMinus} onClick={() => fgRef.current?.zoom(fgRef.current.zoom() * 0.75, 300)} data-testid="tm-zoom-out" />
              <Btn variant="dark" icon={ArrowsInSimple} onClick={() => fgRef.current?.zoomToFit(600, 60)} data-testid="tm-fit" />
              <Btn variant="dark" icon={ArrowsClockwise} onClick={() => { setActiveLayers(new Set()); setSel(null); fgRef.current?.zoomToFit(600, 60); }} data-testid="tm-reset" />
              <Btn variant="dark" icon={ArrowsOutSimple} onClick={() => fgRef.current?.zoomToFit(600, 30)} data-testid="tm-expand" />
            </div>
          }
        >
          Living Threat Map
        </SectionTitle>
        <div ref={ref} className="relative">
          <Panel className="p-0 overflow-hidden" data-testid="threat-map-canvas">
            {w > 0 && (
              <div
                onMouseMove={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect();
                  setHoverPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
                }}
                style={{ width: w, height: H, background: "#050505" }}
              >
                <ForceGraph2D
                  ref={fgRef}
                  graphData={data}
                  width={w}
                  height={H}
                  backgroundColor="rgba(0,0,0,0)"
                  cooldownTicks={80}
                  d3AlphaDecay={0.02}
                  nodeCanvasObject={paintNode}
                  nodePointerAreaPaint={(n, color, ctx) => {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, 12, 0, 2 * Math.PI);
                    ctx.fillStyle = color;
                    ctx.fill();
                  }}
                  linkCanvasObject={paintLink}
                  onNodeHover={onNodeHover}
                  onNodeClick={onNodeClick}
                  enableNodeDrag
                  enableZoomInteraction
                  enablePanInteraction
                  minZoom={0.4}
                  maxZoom={6}
                  autoPauseRedraw={false}
                />
                <Tooltip node={hover} x={hoverPos.x} y={hoverPos.y} />
              </div>
            )}
          </Panel>
          {/* legend + hints */}
          <div className="flex flex-wrap gap-4 mt-3 text-xs">
            {[
              ["#FF2A2A", "critical / incident", true],
              ["#FF00A0", "elevated", false],
              ["#FFB020", "warning", false],
              ["#7A7A7A", "clean", false],
            ].map(([c, l, bold]) => (
              <div key={l} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5" style={{ background: c, boxShadow: bold ? `0 0 6px ${c}` : "none" }} />
                <span className={bold ? "text-incident font-bold" : "text-sub"} style={bold ? { textShadow: `0 0 4px ${c}` } : {}}>{l}</span>
              </div>
            ))}
            <div className="flex items-center gap-1.5"><span className="w-3 h-3 border border-dashed" style={{ borderColor: "#FF00A0" }} /><span className="text-sub">external exposure</span></div>
            <div className="ml-auto text-muted mono text-[10px]">{data.nodes.length} nodes · {data.links.length} links</div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <LayerLegend
          layers={map.layers || []}
          hover={hoverLayer}
          setHover={setHoverLayer}
          activeSet={activeLayers}
          onToggle={toggleLayer}
        />

        {selNode ? (
          <Panel className="p-5 fadein" data-testid="map-node-detail">
            <div className="label mb-2">Selected Asset</div>
            <div className="h-font text-lg text-white break-all">{selNode.label}</div>
            <div className="mt-3 space-y-2 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-muted">Layer</span>
                <Badge color={selNode.layer_color}>{selNode.layer_label}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted">Type</span>
                <span className="mono text-xs text-sub uppercase">{selNode.type}</span>
              </div>
              {selNode.product && (
                <div className="flex justify-between items-center gap-2">
                  <span className="text-muted">Stack</span>
                  <span className="mono text-xs text-white truncate">{selNode.product}{selNode.version ? ` ${selNode.version}` : ""}</span>
                </div>
              )}
              {selNode.port && (
                <div className="flex justify-between items-center">
                  <span className="text-muted">Port</span>
                  <span className="mono text-xs text-info">{selNode.port}</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-muted">Exposure</span>
                <Badge color={selNode.exposure === "external" ? "#FF00A0" : "#B4B4B4"}>{selNode.exposure}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted">Risk score</span>
                <Badge color={riskBucket(selNode.risk).color}>{selNode.risk}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted">Open findings</span>
                <span className="mono text-xs" style={{ color: selNode.open_findings > 0 ? "#FFB020" : "#B4B4B4" }}>{selNode.open_findings || 0}</span>
              </div>
            </div>
          </Panel>
        ) : (
          <Panel className="p-5">
            <div className="text-sm text-muted">Hover a node for telemetry, click to zoom in and inspect, drag nodes to reposition. Click a layer above to filter.</div>
          </Panel>
        )}

        <Panel className="p-5">
          <div className="label mb-3">Top Risk (ranked)</div>
          <div className="space-y-1">
            {map.risk.slice(0, 10).map((r) => {
              const n = nodeById[r.asset_id];
              const b = riskBucket(r.score);
              return (
                <button
                  key={r.asset_id}
                  onClick={() => n && onNodeClick(n)}
                  className="w-full flex items-center justify-between gap-2 text-left hover:bg-white/5 px-2 py-1.5 transition-colors"
                >
                  <div className="min-w-0">
                    <div className="mono text-xs text-white truncate">{n?.label || r.asset_id.slice(0, 8)}</div>
                    <div className="text-[10px]" style={{ color: n?.layer_color || "#7A7A7A" }}>{n?.layer_label || ""}</div>
                  </div>
                  <Badge color={b.color}>{r.score}</Badge>
                </button>
              );
            })}
            {map.risk.length === 0 && <div className="text-xs text-muted">No annotated risk yet — run a vuln scan.</div>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
