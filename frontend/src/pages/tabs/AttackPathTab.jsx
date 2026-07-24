/* eslint-disable react-hooks/exhaustive-deps -- intentional effect deps; preserved behavior */
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import Globe from "react-globe.gl";
import * as THREE from "three";
import { Target, ShieldWarning, LockKey, Lightning, Play, Pause, ArrowRight, StackSimple, MagnifyingGlassPlus, MagnifyingGlassMinus, ArrowsInSimple } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, ErrorBoundary, useToast, errMsg } from "../../components/ui";
import WORLD from "../../assets/world-countries.json";

const ROLE = {
  entry: { color: "#FFFFFF", label: "Entry Point", icon: Target },
  pivot: { color: "#7A7A7A", label: "Pivot", icon: ArrowRight },
  crown: { color: "#FF00A0", label: "Crown Jewel", icon: LockKey },
};

// dark stylised base material — no earth texture. Continents provide the visual.
const GLOBE_MATERIAL = new THREE.MeshPhongMaterial({
  color: 0x000000,
  emissive: 0x0a0a0a,
  shininess: 3,
  specular: 0x1a1a1a,
  transparent: false,
});

function webglOK() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
  } catch (_e) {
    return false;
  }
}

function useWidth() {
  const [w, setW] = useState(0);
  const roRef = useRef(null);
  // Callback ref so measurement happens when the node attaches — robust to the
  // component early-returning while data loads (a useEffect([]) can run with a
  // null ref and never re-measure once the container finally mounts).
  const ref = useCallback((node) => {
    if (roRef.current) { roRef.current.disconnect(); roRef.current = null; }
    if (!node) return;
    const measure = () => {
      const width =
        node.clientWidth ||
        Math.round(node.getBoundingClientRect().width) ||
        node.parentElement?.clientWidth ||
        0;
      if (width > 0) setW(width);
    };
    const ro = new ResizeObserver(measure);
    ro.observe(node);
    roRef.current = ro;
    measure();
    requestAnimationFrame(measure);
    setTimeout(measure, 150);
  }, []);
  return [ref, w];
}

function renderMd(text) {
  return text.split("\n").map((line, i) => {
    if (line.startsWith("## ")) return <div key={i} className="h-font text-base text-volt uppercase tracking-tight mt-3 mb-1">{line.slice(3)}</div>;
    if (line.startsWith("# ")) return <div key={i} className="h-font text-lg text-white uppercase tracking-tight mt-3 mb-1">{line.slice(2)}</div>;
    if (line.trim() === "---") return <div key={i} className="border-t border-line my-2" />;
    const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, j) => {
      if (p.startsWith("**") && p.endsWith("**")) return <b key={j} className="text-white">{p.slice(2, -2)}</b>;
      if (p.startsWith("`") && p.endsWith("`")) return <code key={j} className="text-white bg-black px-1 rounded-sm">{p.slice(1, -1)}</code>;
      return <span key={j}>{p}</span>;
    });
    return <div key={i} className="min-h-[2px]">{parts}</div>;
  });
}

function hexA(hex, alpha) {
  const a = Math.round(Math.max(0, Math.min(1, alpha)) * 255).toString(16).padStart(2, "0");
  return `${hex}${a}`;
}

function GlobeTelemetry({ point, x, y }) {
  if (!point) return null;
  return (
    <div
      className="absolute pointer-events-none z-40 fadein"
      style={{ left: x + 14, top: y + 14, transform: y > 380 ? "translateY(-100%) translateY(-28px)" : undefined }}
    >
      <div className="bg-black/95 border shadow-2xl px-3 py-2.5 min-w-[240px] max-w-[320px]"
        style={{ borderColor: point.color }}>
        <div className="flex items-center gap-1.5 mb-1">
          <span className="w-2 h-2" style={{ background: point.color, boxShadow: `0 0 6px ${point.color}` }} />
          <span className="label" style={{ color: point.color }}>{point.layer_label}</span>
          <span className="ml-auto label" style={{ color: point.role_color, fontWeight: point.role === "crown" ? 900 : 600 }}>
            {point.role === "crown" ? "▲ CROWN" : point.role.toUpperCase()}
          </span>
        </div>
        <div className="mono text-xs text-white break-all mb-1">{point.label}</div>
        <div className="grid grid-cols-2 gap-x-3 gap-y-1 mt-1 text-[11px] mono">
          <div>
            <span className="text-muted">exposure </span>
            <span style={{ color: point.exposure === "external" ? "#FF00A0" : "#B4B4B4" }}>{point.exposure || "?"}</span>
          </div>
          <div>
            <span className="text-muted">risk </span>
            <span style={{ color: point.risk >= 60 ? "#FF00A0" : "#FFB020" }}>{point.risk}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function EcosystemGlobe({ data, selPath, activeStep, hoverLayer }) {
  const [ref, w] = useWidth();
  const globeRef = useRef(null);
  const [paused, setPaused] = useState(false);
  const [hoverPoint, setHoverPoint] = useState(null);
  const [mouse, setMouse] = useState({ x: 0, y: 0 });

  const continents = data.continents || [];
  const crownRings = (data.points || []).filter((p) => p.role === "crown").map((p) => ({ lat: p.lat, lng: p.lng, big: false }));
  const origin = data.attacker_origin;

  const arcs = useMemo(() => {
    // No path selected → show the ambient geo "incoming breach" arcs from the ops
    // origin to every located target (the cinematic earth layer). A selected path
    // shows its kill-chain segments instead.
    if (!selPath) return data.geo_arcs || data.arcs || [];
    const segs = selPath.steps.slice(0, -1).map((s, i) => ({
      startLat: selPath.steps[i].geo[0], startLng: selPath.steps[i].geo[1],
      endLat: selPath.steps[i + 1].geo[0], endLng: selPath.steps[i + 1].geo[1],
      color: [selPath.steps[i].layer_color, selPath.steps[i + 1].layer_color],
      seg: i,
    }));
    return activeStep >= 0 ? segs.filter((a) => a.seg < activeStep) : segs;
  }, [selPath, activeStep, data.arcs]);

  const activeNode = selPath && activeStep >= 0 ? selPath.steps[activeStep] : null;
  const rings = useMemo(() => {
    const r = [...crownRings];
    if (origin) r.push({ lat: origin.lat, lng: origin.lng, big: true, ops: true });
    if (activeNode) r.push({ lat: activeNode.geo[0], lng: activeNode.geo[1], big: true });
    return r;
  }, [activeNode, origin]); // eslint-disable-line

  // country labels come from geo now; the ops origin gets a marker label.
  const continentLabels = useMemo(() =>
    origin ? [{ lat: origin.lat, lng: origin.lng, label: origin.label, sub: "", color: "#FFFFFF", key: "ops" }] : [],
  [origin]);

  // ─── centralised rotate control: pauses on hover, hover-layer, path selection, or user pause ───
  const shouldRotate = !paused && !selPath && !hoverPoint && !hoverLayer;
  useEffect(() => {
    if (!globeRef.current) return;
    const c = globeRef.current.controls();
    c.autoRotate = shouldRotate;
    c.autoRotateSpeed = 0.35;
    c.enableZoom = true;
    c.zoomSpeed = 1.4;
  }, [shouldRotate, w]);

  // ─── camera moves on path selection ───
  useEffect(() => {
    if (!globeRef.current || !selPath) return;
    const s = activeStep >= 0 ? selPath.steps[activeStep] : selPath.steps[0];
    globeRef.current.pointOfView({ lat: s.geo[0], lng: s.geo[1], altitude: activeStep >= 0 ? 1.7 : 2.3 }, 1400);
  }, [selPath, activeStep]);

  // ─── hover-layer camera nudge (only if not already navigating a path) ───
  useEffect(() => {
    if (!globeRef.current || selPath) return;
    if (!hoverLayer) return;
    const cont = continents.find((c) => c.key === hoverLayer);
    if (cont) globeRef.current.pointOfView({ lat: cont.center.lat, lng: cont.center.lng, altitude: 2.2 }, 900);
  }, [hoverLayer, selPath, continents]);

  useEffect(() => {
    return () => {
      try {
        const g = globeRef.current;
        const r = g && typeof g.renderer === "function" && g.renderer();
        if (r) {
          if (r.dispose) r.dispose();
          if (r.forceContextLoss) r.forceContextLoss();
        }
      } catch (_e) {}
    };
  }, []);

  const activeId = activeNode?.asset_id;

  const dim = (c) => {
    if (!hoverLayer && !selPath) return 1;
    if (selPath && c.key === activeNode?.layer) return 1;
    if (hoverLayer && c.key === hoverLayer) return 1;
    return 0.35;
  };

  const zoomBy = (factor) => {
    if (!globeRef.current) return;
    const pov = globeRef.current.pointOfView();
    globeRef.current.pointOfView({ ...pov, altitude: Math.max(0.6, Math.min(4, pov.altitude * factor)) }, 500);
  };
  const resetView = () => {
    setPaused(false);
    setHoverPoint(null);
    globeRef.current?.pointOfView({ lat: 20, lng: 0, altitude: 2.6 }, 900);
  };

  return (
    <div
      ref={ref}
      className="w-full relative"
      data-testid="attack-globe"
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        setMouse({ x: e.clientX - rect.left, y: e.clientY - rect.top });
      }}
      onMouseLeave={() => setHoverPoint(null)}
    >
      {/* Floating control bar — sits over the top-right of the globe */}
      <div className="absolute top-3 right-3 z-20 flex items-center gap-1">
        <Btn
          variant={paused ? "primary" : "dark"}
          icon={paused ? Play : Pause}
          onClick={() => setPaused((p) => !p)}
          data-testid="globe-pause-btn"
          title={paused ? "Resume auto-rotation" : "Pause auto-rotation"}
        >
          {paused ? "ROTATE" : "PAUSE"}
        </Btn>
        <Btn variant="dark" icon={MagnifyingGlassPlus} onClick={() => zoomBy(0.7)} data-testid="globe-zoom-in" title="Zoom in" />
        <Btn variant="dark" icon={MagnifyingGlassMinus} onClick={() => zoomBy(1.4)} data-testid="globe-zoom-out" title="Zoom out" />
        <Btn variant="dark" icon={ArrowsInSimple} onClick={resetView} data-testid="globe-reset-view" title="Reset view" />
      </div>

      {/* Status pill */}
      <div className="absolute top-3 left-3 z-20 mono text-[10px] uppercase tracking-widest2 px-2 py-1 bg-black/70 border border-line">
        {selPath ? (
          <span className="text-volt">▶ BREACH PATH LOCKED</span>
        ) : paused ? (
          <span className="text-warn">⏸ PAUSED</span>
        ) : hoverPoint || hoverLayer ? (
          <span className="text-info">◈ INSPECTING</span>
        ) : (
          <span className="text-live">↻ AUTO-ROTATING</span>
        )}
      </div>

      {w > 0 && (
        <Globe
          ref={globeRef}
          width={w}
          height={560}
          backgroundColor="rgba(0,0,0,0)"
          globeMaterial={GLOBE_MATERIAL}
          showAtmosphere
          atmosphereColor="#FF00A0"
          atmosphereAltitude={0.18}
          /* real earth landmasses — hex-polygon "movie" globe (Natural Earth) */
          hexPolygonsData={WORLD.features}
          hexPolygonResolution={3}
          hexPolygonMargin={0.28}
          hexPolygonAltitude={0.006}
          hexPolygonColor={() => "rgba(122,122,122,0.32)"}
          hexPolygonsTransitionDuration={0}
          /* ecosystem continents (overlay, usually empty) */
          polygonsData={continents}
          polygonGeoJsonGeometry={(d) => d.geometry}
          polygonCapColor={(d) => hexA(d.color, 0.32 * dim(d))}
          polygonSideColor={(d) => hexA(d.color, 0.18 * dim(d))}
          polygonStrokeColor={(d) => hexA(d.color, 0.95 * dim(d))}
          polygonAltitude={(d) => (hoverLayer === d.key || activeNode?.layer === d.key ? 0.024 : 0.012)}
          polygonLabel={(d) => `<div style="font-family:'Barlow Condensed',sans-serif;letter-spacing:.05em"><span style="color:${d.color};font-weight:800;text-transform:uppercase;text-shadow:0 0 6px ${d.color}">${d.label}</span><br/><span style="color:#B4B4B4;font-size:11px">${d.sub}</span></div>`}
          /* continent name labels */
          labelsData={continentLabels}
          labelLat="lat"
          labelLng="lng"
          labelText="label"
          labelSize={1.4}
          labelDotRadius={0}
          labelColor={(d) => hexA(d.color, hoverLayer === d.key || activeNode?.layer === d.key ? 1 : 0.75)}
          labelResolution={2}
          labelAltitude={0.03}
          /* assets */
          pointsData={data.points || []}
          pointLat="lat"
          pointLng="lng"
          pointColor={(d) => (activeId && d.id === activeId ? "#FFFFFF" : hoverPoint?.id === d.id ? "#FFFFFF" : d.color)}
          pointAltitude={(d) => (activeId && d.id === activeId ? d.size + 0.25 : hoverPoint?.id === d.id ? d.size + 0.06 : d.size)}
          pointRadius={(d) => (activeId && d.id === activeId ? 0.65 : hoverPoint?.id === d.id ? 0.5 : d.role === "crown" ? 0.42 : 0.28)}
          pointLabel={() => ""}   /* suppress default HTML tooltip — we render a rich React one */
          onPointHover={setHoverPoint}
          onPointClick={(p) => {
            setHoverPoint(p);
            globeRef.current?.pointOfView({ lat: p.lat, lng: p.lng, altitude: 1.6 }, 900);
          }}
          /* arcs — dim when unselected, magenta+red when a path is active */
          arcsData={arcs}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor={(a) => (selPath ? ["#FF00A0", "#FF2A2A"]
            : a.role === "entry" ? ["#FF00A0", "#FF2A2A"] : ["#00E5FF", "#FF00A0"])}
          arcStroke={selPath ? 1.3 : 0.55}
          arcDashLength={0.35}
          arcDashGap={0.12}
          arcDashInitialGap={() => Math.random()}
          arcDashAnimateTime={selPath ? 1200 : 2200}
          arcAltitudeAutoScale={0.5}
          /* rings on crown jewels + active hop */
          ringsData={rings}
          ringColor={(d) => (d.big ? "#FFFFFF" : "#FF2A2A")}
          ringMaxRadius={(d) => (d.big ? 7 : 4)}
          ringPropagationSpeed={(d) => (d.big ? 4 : 2)}
          ringRepeatPeriod={(d) => (d.big ? 500 : 900)}
        />
      )}

      <GlobeTelemetry point={hoverPoint} x={mouse.x} y={mouse.y} />
    </div>
  );
}

function LayerLegend({ stats, hover, setHover, active }) {
  const total = stats.reduce((s, l) => s + l.count, 0) || 1;
  return (
    <Panel className="p-3" data-testid="layer-legend">
      <div className="flex items-center gap-2 mb-3 px-1">
        <StackSimple size={14} weight="bold" className="text-sub" />
        <span className="label">Ecosystem Layers</span>
      </div>
      <div className="space-y-1.5">
        {stats.map((l) => {
          const pct = (l.count / total) * 100;
          const on = hover === l.key || active === l.key;
          return (
            <button
              key={l.key}
              onMouseEnter={() => setHover(l.key)}
              onMouseLeave={() => setHover(null)}
              data-testid={`layer-${l.key}`}
              className={`w-full text-left px-2.5 py-2 rounded-sm border transition-colors ${on ? "bg-white/5" : "hover:bg-white/5"}`}
              style={{ borderColor: on ? l.color : "rgba(255,255,255,0.08)" }}
            >
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: l.color, boxShadow: on ? `0 0 8px ${l.color}` : "none" }} />
                <span className="h-font text-sm uppercase tracking-tight" style={{ color: on ? l.color : "#fff" }}>{l.label}</span>
                <span className="ml-auto mono text-[11px] text-muted">{l.count}</span>
              </div>
              <div className="text-[10px] text-muted mt-1 ml-4.5 truncate">{l.sub}</div>
              <div className="h-1 mt-1.5 bg-black rounded-full overflow-hidden">
                <div className="h-full" style={{ width: `${pct}%`, background: l.color, opacity: on ? 1 : 0.55 }} />
              </div>
              {l.top && <div className="mono text-[10px] text-neutral mt-1 truncate">↳ {l.top}</div>}
            </button>
          );
        })}
      </div>
    </Panel>
  );
}

function LayerBadge({ layer, label, color }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded-sm border"
      style={{ color, borderColor: color, backgroundColor: `${color}1a` }}
      data-testid={`layer-badge-${layer}`}
    >
      <span className="w-1.5 h-1.5 rounded-sm" style={{ background: color }} />
      {label}
    </span>
  );
}

function PathCard({ p, idx, selected, activeStep, onSelect, onPlay, onStep, onExecute, executing }) {
  const layers = p.layers_traversed || p.steps.map((s) => s.layer);
  const runnable = p.kind === "chain" || p.kind === "identity";
  return (
    <Panel
      className={`p-4 transition-colors cursor-pointer ${selected ? "border-volt" : "hover:border-white/25"}`}
      onClick={() => onSelect(p)}
      data-testid={`attack-path-${p.id}`}
    >
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        <span className="h-font text-lg text-white">{p.kind === "chain" ? "Kill Chain" : p.kind === "identity" ? "Domain Path" : "Path"} {idx + 1}</span>
        <Badge color={SEV[p.severity]?.color}>{SEV[p.severity]?.label}</Badge>
        {p.is_realised && <Badge color="#FF2A2A" dot>REALISED</Badge>}
        <span className="mono text-[10px] text-muted">
          {layers.map((l, i) => (
            <span key={i}>{i > 0 ? " → " : ""}{l}</span>
          ))}
        </span>
        <span className="ml-auto mono text-[11px] text-muted">score {p.score}</span>
        <Btn variant={selected ? "primary" : "dark"} icon={Play} onClick={(e) => { e.stopPropagation(); onPlay(p); }} data-testid={`play-path-${p.id}`}>
          Play Breach
        </Btn>
        {runnable && onExecute && (
          <Btn variant="danger" icon={Lightning} loading={executing === p.id}
            disabled={!!executing}
            onClick={(e) => { e.stopPropagation(); onExecute(p); }} data-testid={`execute-${p.id}`}>
            {p.is_realised ? "Re-run Attack" : "Execute Attack"}
          </Btn>
        )}
      </div>
      {p.objective && <div className="text-xs text-sub mb-3 mono">▶ {p.objective}</div>}
      <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
        {p.steps.map((s, i) => {
          const R = ROLE[s.role];
          const isActive = selected && activeStep === i;
          const traversed = selected && activeStep >= 0 && i <= activeStep;
          return (
            <React.Fragment key={i}>
              <button
                onClick={(e) => { e.stopPropagation(); onStep(p, i); }}
                className={`flex-1 min-w-[160px] text-left bg-black border rounded-sm p-2.5 transition-all ${isActive ? "scale-[1.03]" : ""}`}
                style={{ borderColor: isActive ? "#fff" : traversed ? R.color : `${R.color}44`, boxShadow: isActive ? `0 0 14px ${R.color}` : "none", opacity: selected && activeStep >= 0 && !traversed ? 0.45 : 1 }}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="w-2 h-2 rounded-full" style={{ background: R.color, boxShadow: `0 0 6px ${R.color}` }} />
                  <span className="label" style={{ color: R.color }}>{R.label}</span>
                </div>
                <div className="mono text-xs text-white truncate">{s.label}</div>
                <div className="mt-1"><LayerBadge layer={s.layer} label={s.layer_label} color={s.layer_color} /></div>
                <div className="text-[10px] text-muted mono mt-1">{s.technique.id} · {s.technique.phase}</div>
                {s.cve_refs?.length > 0 && <div className="text-[10px] text-volt mono mt-0.5">{s.cve_refs.join(", ")}</div>}
              </button>
              {i < p.steps.length - 1 && <div className="flex items-center text-muted"><ArrowRight size={16} /></div>}
            </React.Fragment>
          );
        })}
      </div>
    </Panel>
  );
}

function BreachHop({ selPath, activeStep, playing }) {
  if (!selPath) {
    return <div className="text-sm text-muted">Select a candidate path or press <b className="text-white">Play Breach</b> to walk the kill-chain across ecosystem layers.</div>;
  }
  const idx = activeStep >= 0 ? activeStep : 0;
  const s = selPath.steps[idx];
  const R = ROLE[s.role];
  const total = selPath.steps.length;
  const done = activeStep >= total - 1 && !playing && activeStep >= 0;
  return (
    <div data-testid="breach-hop">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <span className="label" style={{ color: R.color }}>{R.label}</span>
          <LayerBadge layer={s.layer} label={s.layer_label} color={s.layer_color} />
          <span className="mono text-[11px] text-muted">HOP {idx + 1} / {total}</span>
        </div>
        {playing && <span className="flex items-center gap-1.5 text-[11px] mono text-volt"><span className="w-2 h-2 rounded-full bg-volt blink" /> BREACHING</span>}
        {done && <Badge color="#FF00A0" dot>CROWN JEWEL REACHED</Badge>}
      </div>
      <div className="flex gap-1 mb-3">
        {selPath.steps.map((step, i) => (
          <div key={i} className="h-1 flex-1 rounded-full transition-colors" style={{ background: activeStep >= 0 && i <= activeStep ? step.layer_color : "rgba(255,255,255,0.1)" }} />
        ))}
      </div>
      <div className="mono text-sm text-white break-all">{s.label}</div>
      <div className="text-xs text-sub mt-1">{s.technique.framework} · {s.technique.id} {s.technique.name}</div>
      <div className="mt-3 bg-black border-l-2 p-3" style={{ borderColor: s.layer_color }}>
        <div className="label mb-1">Leveraged Finding</div>
        {s.finding_title ? (
          <>
            <div className="text-sm text-white">{s.finding_title}</div>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              <Badge color={SEV[s.severity]?.color}>{SEV[s.severity]?.label}</Badge>
              <Badge color={s.exploitability === "confirmed" ? "#FF2A2A" : s.exploitability === "reachable" ? "#FFB020" : "#7A7A7A"}>{s.exploitability}</Badge>
              {s.cve_refs?.length > 0 && <span className="mono text-[11px] text-volt">{s.cve_refs.join(", ")}</span>}
            </div>
          </>
        ) : (
          <div className="text-sm text-muted">Reachable via observed exposure (no single CVE).</div>
        )}
      </div>
    </div>
  );
}

function WorldModelPanel({ wm }) {
  if (!wm) return null;
  const c = wm.counts || {};
  const stats = [
    ["Hypotheses", c.hypotheses || 0], ["Graduated", c.graduated || 0],
    ["Chains", c.chains || 0], ["Realised", c.chains_realised || 0],
    ["Owned", c.owned_principals || 0], ["DA Paths", c.da_paths || 0],
  ];
  const topHyps = (wm.hypotheses || []).slice(0, 8);
  return (
    <Panel className="p-4" data-testid="world-model-panel">
      <div className="flex items-center gap-2 mb-3">
        <span className="label text-volt">Attack Intelligence</span>
        <span className="ml-auto mono text-[10px] text-muted">{wm.reachable_assets || 0} reachable assets</span>
      </div>
      <div className="grid grid-cols-3 gap-2 mb-3">
        {stats.map(([l, v]) => (
          <div key={l} className="bg-black border border-line p-2 text-center">
            <div className="h-font text-xl font-black text-white">{v}</div>
            <div className="label text-[9px]">{l}</div>
          </div>
        ))}
      </div>
      {topHyps.length === 0 ? (
        <div className="text-xs text-muted">No beliefs yet — run Sensing / Vuln Scan / Full Attack to populate the model.</div>
      ) : (
        <div className="space-y-1.5">
          {topHyps.map((h) => (
            <div key={h.id} className="flex items-center gap-2 text-[11px] bg-black border border-line px-2 py-1.5" data-testid={`wm-hyp-${h.id}`}>
              <span className="mono uppercase text-[9px]" style={{ color: h.finding_id ? "#FF2A2A" : "#7A7A7A" }}>{h.kind}</span>
              <span className="text-sub truncate flex-1">{h.title}</span>
              <span className="mono text-muted">{Math.round((h.confidence || 0) * 100)}%</span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

export default function AttackPathTab({ eid }) {
  const toast = useToast();
  const [data, setData] = useState(null);
  const [wm, setWm] = useState(null);
  const [selPath, setSelPath] = useState(null);
  const [activeStep, setActiveStep] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const [hoverLayer, setHoverLayer] = useState(null);
  const [executing, setExecuting] = useState(null);

  // Execute a composed chain: start the attack along it (governed background job),
  // poll to completion, then refresh the path + world model so rungs light up / a
  // session appears.
  const executeChain = async (p) => {
    setExecuting(p.id);
    try {
      await api.executeChain(eid, p.id);
      for (let i = 0; i < 200; i++) {
        const jobs = await api.jobs(eid);
        const j = jobs.find((x) => x.kind === "chain-exec");
        if (j && j.status !== "running") {
          if (j.status === "error") throw new Error(j.detail || "chain execution failed");
          break;
        }
        await new Promise((r) => setTimeout(r, 3000));
      }
      toast.success("Attack executed along the chain");
      api.attackPath(eid).then(setData);
      api.worldModel(eid).then(setWm).catch(() => {});
    } catch (e) { toast.error(errMsg(e)); } finally { setExecuting(null); }
  };

  // AI stream
  const [streaming, setStreaming] = useState(false);
  const [shown, setShown] = useState("");
  const [meta, setMeta] = useState(null);
  const bufRef = useRef("");
  const esRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => { api.attackPath(eid).then(setData); }, [eid]);
  useEffect(() => { api.worldModel(eid).then(setWm).catch(() => setWm(null)); }, [eid]);
  useEffect(() => () => { esRef.current?.close(); clearInterval(timerRef.current); }, []);

  useEffect(() => {
    if (!playing || !selPath) return;
    if (activeStep >= selPath.steps.length - 1) { setPlaying(false); return; }
    const t = setTimeout(() => setActiveStep((s) => s + 1), 2600);
    return () => clearTimeout(t);
  }, [playing, activeStep, selPath]);

  const selectPath = (p) => { setSelPath(p); setActiveStep(-1); setPlaying(false); };
  const playPath = (p) => { setSelPath(p); setActiveStep(0); setPlaying(true); };
  const stepTo = (p, i) => { setSelPath(p); setActiveStep(i); setPlaying(false); };
  const resetView = () => { setSelPath(null); setActiveStep(-1); setPlaying(false); };

  const startStream = useCallback(() => {
    esRef.current?.close();
    clearInterval(timerRef.current);
    bufRef.current = ""; setShown(""); setMeta(null); setStreaming(true);
    const es = new EventSource(api.attackPathStreamUrl(eid));
    esRef.current = es;
    es.onmessage = (e) => { try { const m = JSON.parse(e.data); if (m.delta) bufRef.current += m.delta; if (m.done) { setMeta(m); es.close(); } } catch (_) {} };
    es.onerror = () => es.close();
    timerRef.current = setInterval(() => setShown((s) => (s.length < bufRef.current.length ? bufRef.current.slice(0, s.length + 4) : s)), 16);
  }, [eid]);

  useEffect(() => {
    if (meta && shown.length >= bufRef.current.length) { setStreaming(false); clearInterval(timerRef.current); }
  }, [shown, meta]);

  if (!data) return <Loading label="Mapping ecosystem" />;

  const layerStats = data.layer_stats || [];
  const activeLayerKey = selPath && activeStep >= 0 ? selPath.steps[activeStep].layer : null;

  return (
    <div className="grid lg:grid-cols-5 gap-6">
      <div className="lg:col-span-3 space-y-4">
        <SectionTitle sub="Client ecosystem projected onto the globe — each continent is an attack surface layer (Code, Dev, Cloud, SaaS, Endpoints, On-Prem, Edge/IoT/AI). Click a path or press Play to walk the breach across layers."
          right={selPath && <Btn variant="ghost" onClick={resetView} data-testid="reset-view-btn">Reset View</Btn>}>
          Ecosystem Attack Surface
        </SectionTitle>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="md:col-span-3">
            <Panel className="p-2 bg-panel overflow-hidden">
              {webglOK() ? (
                <ErrorBoundary fallback={<div className="p-10 text-center text-muted text-sm">Globe unavailable in this browser (no WebGL). Attack paths shown below.</div>}>
                  <EcosystemGlobe data={data} selPath={selPath} activeStep={activeStep} hoverLayer={hoverLayer} />
                </ErrorBoundary>
              ) : (
                <div className="p-10 text-center text-muted text-sm" data-testid="globe-fallback">WebGL not available — attack paths shown below.</div>
              )}
            </Panel>
          </div>
          <div className="md:col-span-1">
            <LayerLegend stats={layerStats} hover={hoverLayer} setHover={setHoverLayer} active={activeLayerKey} />
          </div>
        </div>

        <Panel className="p-4">
          <BreachHop selPath={selPath} activeStep={activeStep} playing={playing} />
        </Panel>

        <div className="grid grid-cols-4 gap-3">
          {[["Entry Points", data.stats.entry, "#B4B4B4"], ["Pivots", data.stats.pivot, "#B4B4B4"],
            ["Crown Jewels", data.stats.crown, "#FF00A0"], ["Paths", data.stats.paths, "#fff"]].map(([l, v, c]) => (
            <Panel key={l} className="p-3 text-center"><div className="h-font text-3xl font-black" style={{ color: c }}>{v}</div><div className="label mt-1">{l}</div></Panel>
          ))}
        </div>

        <div>
          <SectionTitle sub="Click to isolate on the globe · Play Breach to walk the kill-chain across ecosystem layers.">Candidate Attack Paths</SectionTitle>
          {data.paths.length === 0 ? (
            <Empty icon={ShieldWarning} title="No path to crown jewels" hint="Press Run Full Attack (or Sensing + Vuln Scan) on the Console so the engine confirms findings and chains them into a route across layers." />
          ) : (
            <div className="space-y-3">
              {data.paths.map((p, i) => (
                <PathCard key={p.id} p={p} idx={i} selected={selPath?.id === p.id} activeStep={selPath?.id === p.id ? activeStep : -1}
                  onSelect={selectPath} onPlay={playPath} onStep={stepTo} onExecute={executeChain} executing={executing} />
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="lg:col-span-2 space-y-4">
        <SectionTitle sub="Claude reasons over every finding + asset context + layer transitions, streamed live (BYOM Model Gateway).">AI Attack Path</SectionTitle>
        <Panel className="p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {meta && <Badge color={meta.route?.includes("hosted") ? "#B4B4B4" : "#FFFFFF"} dot>{meta.route}</Badge>}
              {streaming && <span className="flex items-center gap-1.5 text-[11px] mono text-volt"><span className="w-2 h-2 rounded-full bg-volt blink" /> STREAMING</span>}
            </div>
            <Btn icon={streaming ? Lightning : Play} onClick={startStream} disabled={streaming} loading={streaming} data-testid="generate-attack-path-btn">
              {shown ? "Regenerate" : "Generate Path"}
            </Btn>
          </div>
          {!shown && !streaming ? (
            meta?.empty ? (
              <Empty icon={ShieldWarning} title="Nothing to narrate yet"
                hint="Run a Vuln Scan or Run Full Attack so the engine confirms findings — then Claude walks the breach route over them." />
            ) : (
              <div className="text-sm text-muted leading-relaxed" data-testid="attack-path-cta">
                Press <b className="text-white">Generate Path</b> and Claude reasons over the
                engine's real findings + attack surface (BYOM Model Gateway), streaming the most
                probable breach route — initial access → pivots → crown jewel — in plain language.
              </div>
            )
          ) : (
            <div className="bg-black border border-line p-4 text-[13px] text-sub leading-relaxed max-h-[560px] overflow-y-auto" data-testid="attack-path-stream">
              {renderMd(shown)}
              {streaming && <span className="inline-block w-2 h-4 bg-volt blink align-middle ml-0.5" />}
              {meta && !streaming && (
                <div className="mt-3 pt-3 border-t border-line mono text-[11px] text-muted">
                  {meta.usage.token_in}→{meta.usage.token_out} tok · {meta.usage.latency_ms}ms · ${meta.usage.cost}
                </div>
              )}
            </div>
          )}
        </Panel>

        <SectionTitle sub="What the platform has learned about your environment — live hypotheses, attack chains, and the accounts/hosts it has taken control of — shared by every reasoning agent and the campaign.">Attack Intelligence</SectionTitle>
        <WorldModelPanel wm={wm} />
      </div>
    </div>
  );
}
