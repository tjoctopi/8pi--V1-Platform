import React, { useCallback, useEffect, useRef, useState } from "react";
import { Check } from "@phosphor-icons/react";
import { api } from "../lib/api";

const COLOR = { done: "#FF00A0", active: "#FFB020", pending: "#4A4A4A" };

// Live kill-chain progression bar. Self-contained: polls campaign-status so it
// advances on every step (recon → confirm → foothold → escalate → lateral →
// objective) whichever tab it sits in, backed by the engine's world model.
export default function KillChainProgress({ eid, className = "", compact = false }) {
  const [status, setStatus] = useState(null);
  const timer = useRef(null);

  const refresh = useCallback(() => {
    api.campaignStatus(eid).then(setStatus).catch(() => {});
  }, [eid]);

  useEffect(() => {
    refresh();
    // poll every 4s — light derived endpoint; keeps the bar live during long,
    // minutes-per-step recon/exploit runs without fighting the SSE event queue.
    timer.current = setInterval(refresh, 4000);
    return () => clearInterval(timer.current);
  }, [refresh]);

  if (!status) return null;
  const stages = status.stages || [];
  const doneCount = stages.filter((s) => s.status === "done").length;
  const pct = stages.length ? Math.round((doneCount / stages.length) * 100) : 0;

  // Compact one-line variant for the persistent engagement header.
  if (compact) {
    return (
      <div className={`flex items-center gap-3 ${className}`} data-testid="kill-chain-progress">
        <span className="label shrink-0">Kill Chain</span>
        <div className="flex items-stretch gap-1 flex-1 min-w-0">
          {stages.map((s) => {
            const c = COLOR[s.status] || COLOR.pending;
            const isCurrent = status.current === s.key;
            return (
              <div key={s.key} className="flex-1 min-w-0 flex items-center gap-1.5" title={`${s.label} — ${s.detail}`} data-testid={`stage-${s.key}`}>
                <span className="h-1.5 flex-1 rounded-full transition-colors" style={{ background: c, boxShadow: isCurrent ? `0 0 8px ${c}` : "none" }} />
                <span className="mono text-[9px] uppercase tracking-tight hidden md:inline shrink-0"
                  style={{ color: s.status === "pending" ? "#7A7A7A" : "#fff", fontWeight: isCurrent ? 800 : 500 }}>
                  {s.label}{s.status === "active" && " ●"}
                </span>
              </div>
            );
          })}
        </div>
        <span className="mono text-[10px] shrink-0" style={{ color: status.running ? "#FFB020" : "#7A7A7A" }}>
          {status.running ? `▶ ${status.active_phase}` : `${pct}%`}
        </span>
      </div>
    );
  }

  return (
    <div className={className} data-testid="kill-chain-progress">
      <div className="flex items-center gap-2 mb-2">
        <span className="label">Kill-Chain Progress</span>
        {status.running ? (
          <span className="flex items-center gap-1.5 text-[11px] mono text-warn">
            <span className="w-2 h-2 rounded-full bg-warn blink" /> RUNNING · {status.active_phase}
          </span>
        ) : (
          <span className="text-[11px] mono text-muted">idle</span>
        )}
        <span className="ml-auto mono text-[11px] text-muted">{doneCount}/{stages.length} · {pct}%</span>
      </div>
      <div className="flex items-stretch gap-1">
        {stages.map((s, i) => {
          const c = COLOR[s.status] || COLOR.pending;
          const isCurrent = status.current === s.key;
          return (
            <div key={s.key} className="flex-1 min-w-0" data-testid={`stage-${s.key}`} title={s.detail}>
              <div className="h-1.5 rounded-full transition-colors" style={{ background: c, boxShadow: isCurrent ? `0 0 8px ${c}` : "none" }} />
              <div className="mt-1.5 flex items-center gap-1">
                <span className="mono text-[10px] text-muted">{i + 1}</span>
                <span className="h-font text-xs uppercase tracking-tight truncate"
                  style={{ color: s.status === "pending" ? "#7A7A7A" : "#fff", fontWeight: isCurrent ? 800 : 500 }}>
                  {s.label}
                </span>
                {s.status === "done" && <Check size={11} className="text-volt shrink-0" weight="bold" />}
                {s.status === "active" && <span className="w-1.5 h-1.5 rounded-full bg-warn blink shrink-0" />}
              </div>
              {s.count > 0 && <div className="mono text-[9px] text-muted mt-0.5">{s.count}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
