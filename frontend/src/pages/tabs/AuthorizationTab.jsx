/* eslint-disable react-hooks/exhaustive-deps */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldCheck, LockKey, Lightning, Gavel, Prohibit, Detective } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { Panel, SectionTitle, Btn, Badge, Loading, useToast, errMsg } from "../../components/ui";
import { useAuth, roleAtLeast } from "../../lib/auth";

// status → colour + label. This mirrors the engine's AuthorizationPolicy exactly:
// autonomous = pre-authorized (runs unattended); gated = runs but human-approved;
// gated-evasion = defense-evasion, always gated; denied = tool off-limits.
const STATUS = {
  autonomous: { color: "#22C55E", label: "AUTONOMOUS", icon: Lightning },
  gated: { color: "#FFB020", label: "GATED", icon: Gavel },
  "gated-evasion": { color: "#FF2A2A", label: "GATED · EVASION", icon: Detective },
  denied: { color: "#FF2A2A", label: "DENIED", icon: Prohibit },
  allowed: { color: "#22C55E", label: "ALLOWED", icon: ShieldCheck },
};

function StatusPill({ status }) {
  const s = STATUS[status] || STATUS.gated;
  const Icon = s.icon;
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-sm border"
      style={{ color: s.color, borderColor: s.color, background: `${s.color}1a` }}>
      <Icon size={11} weight="bold" /> {s.label}
    </span>
  );
}

export default function AuthorizationTab({ eid }) {
  const toast = useToast();
  const { user } = useAuth();
  const canWrite = roleAtLeast(user, "operator");
  const [auth, setAuth] = useState(null);
  const [roe, setRoe] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [a, e] = await Promise.all([api.authorization(eid), api.engagement(eid)]);
    setAuth(a);
    setRoe(e.roe || {});
  }, [eid]);

  useEffect(() => { load().catch((e) => toast.error(errMsg(e))); }, [load]);

  const locked = !!roe?.signature; // signed RoE = authorizations immutable (by design)

  // toggles edit the RoE doc + PUT it (only possible while unsigned)
  const saveRoe = async (patch) => {
    setBusy(true);
    try {
      const next = {
        scope_allowlist: roe.scope_allowlist || [],
        scope_denylist: roe.scope_denylist || [],
        allowed_tools: roe.allowed_tools || [],
        forbidden_tools: roe.forbidden_tools || [],
        allowed_techniques: roe.allowed_techniques || [],
        max_intensity: roe.max_intensity || "recon",
        window_start: roe.window_start || null,
        window_end: roe.window_end || null,
        ...patch,
      };
      await api.updateRoe(eid, next);
      toast.success("Authorization updated");
      await load();
    } catch (e) { toast.error(errMsg(e)); } finally { setBusy(false); }
  };

  const toggleTechnique = (t) => {
    const cur = new Set(roe.allowed_techniques || []);
    if (cur.has(t.id)) cur.delete(t.id); else cur.add(t.id);
    saveRoe({ allowed_techniques: [...cur] });
  };
  const toggleTool = (tool) => {
    const cur = new Set(roe.forbidden_tools || []);
    if (cur.has(tool.tool)) cur.delete(tool.tool); else cur.add(tool.tool);
    saveRoe({ forbidden_tools: [...cur] });
  };

  const byTactic = useMemo(() => {
    const m = {};
    (auth?.techniques || []).forEach((t) => { (m[t.tactic] = m[t.tactic] || []).push(t); });
    return m;
  }, [auth]);

  if (!auth) return <Loading label="Reading rules of engagement" />;
  const c = auth.counts || {};

  return (
    <div className="space-y-6 fadein" data-testid="authorization-tab">
      {/* posture banner */}
      <Panel className="p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <ShieldCheck size={22} className="text-volt" weight="fill" />
          <span className="h-font text-lg uppercase tracking-tight text-white">Rules of Engagement — Authorization</span>
          <Badge color={auth.tier >= 1 ? "#22C55E" : "#7A7A7A"} dot>TIER {auth.tier}</Badge>
          <Badge color={auth.read_only ? "#FFB020" : "#FF00A0"}>{auth.read_only ? "READ-ONLY" : "ACTIVE-EXPLOIT"}</Badge>
          <Badge color={auth.signed ? "#22C55E" : "#7A7A7A"} dot>{auth.signed ? "SIGNED" : "UNSIGNED"}</Badge>
          {locked && (
            <span className="ml-auto flex items-center gap-1.5 text-[11px] mono text-muted">
              <LockKey size={13} /> signed — authorizations locked (edit before signing)
            </span>
          )}
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          {[["Autonomous", c.autonomous, "#22C55E"], ["Gated", c.gated, "#FFB020"],
            ["Tools Allowed", c.tools_allowed, "#22C55E"], ["Tools Denied", c.tools_denied, "#FF2A2A"]].map(([l, v, col]) => (
            <div key={l} className="bg-black border border-line p-3 text-center">
              <div className="h-font text-2xl font-black" style={{ color: col }}>{v ?? 0}</div>
              <div className="label mt-0.5">{l}</div>
            </div>
          ))}
        </div>
      </Panel>

      {/* techniques by tactic */}
      <div>
        <SectionTitle sub="Each ATT&CK technique the AI may use, classified by the signed RoE. Toggle Autonomous ⇄ Gated (before signing). Defense-evasion is always gated.">
          Techniques
        </SectionTitle>
        <div className="space-y-4">
          {Object.entries(byTactic).map(([tactic, techs]) => (
            <Panel key={tactic} className="p-3">
              <div className="label text-volt mb-2 uppercase">{tactic.replace(/-/g, " ")}</div>
              <div className="space-y-1.5">
                {techs.map((t) => (
                  <div key={t.id} className="flex items-center gap-3 py-1.5 border-b border-white/5 last:border-0" data-testid={`tech-${t.id}`}>
                    <span className="mono text-[11px] text-muted w-20 shrink-0">{t.id}</span>
                    <span className="text-sm text-white flex-1 truncate">{t.name}</span>
                    <StatusPill status={t.status} />
                    {!t.evasion && (
                      <Btn variant={t.status === "autonomous" ? "dark" : "primary"}
                        disabled={locked || !canWrite || busy}
                        onClick={() => toggleTechnique(t)} data-testid={`toggle-tech-${t.id}`}>
                        {t.status === "autonomous" ? "Gate" : "Allow"}
                      </Btn>
                    )}
                  </div>
                ))}
              </div>
            </Panel>
          ))}
        </div>
      </div>

      {/* tools */}
      <div>
        <SectionTitle sub="Tools the AI may run. Denylist wins; licensed tools stay locked until enabled. Toggle Allow ⇄ Deny (before signing).">
          Tools
        </SectionTitle>
        <Panel className="p-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
            {(auth.tools || []).map((tool) => (
              <div key={tool.tool} className="flex items-center gap-2 py-1.5 px-1 border-b border-white/5" data-testid={`tool-${tool.tool}`}>
                <span className="mono text-sm text-white flex-1 truncate">{tool.tool}</span>
                {tool.licensed && <Badge color="#B4B4B4">licensed</Badge>}
                <StatusPill status={tool.status} />
                <Btn variant={tool.status === "denied" ? "primary" : "dark"}
                  disabled={locked || !canWrite || busy}
                  onClick={() => toggleTool(tool)} data-testid={`toggle-tool-${tool.tool}`}>
                  {tool.status === "denied" ? "Allow" : "Deny"}
                </Btn>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* high-impact actions — always gated */}
      {(auth.actions || []).length > 0 && (
        <div>
          <SectionTitle sub="High-impact actions always require a human gate — even when otherwise pre-authorized. This is non-negotiable.">
            Gated High-Impact Actions
          </SectionTitle>
          <Panel className="p-3">
            <div className="flex flex-wrap gap-2">
              {auth.actions.map((a) => (
                <span key={a.action} className="inline-flex items-center gap-1.5 mono text-xs text-white bg-black border border-warn/50 px-2.5 py-1" data-testid={`action-${a.action}`}>
                  <Gavel size={12} className="text-warn" /> {a.action}
                </span>
              ))}
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
