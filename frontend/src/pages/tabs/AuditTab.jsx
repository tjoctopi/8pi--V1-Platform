import React, { useEffect, useState, useCallback } from "react";
import { ShieldCheck, ShieldSlash } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { Panel, SectionTitle, Btn, Badge, Loading, Select } from "../../components/ui";

const ACTOR_COLOR = { operator: "#B4B4B4", agent: "#B4B4B4", approver: "#FFFFFF", system: "#7A7A7A" };

export default function AuditTab({ eid }) {
  const [events, setEvents] = useState(null);
  const [verify, setVerify] = useState(null);
  const [ftype, setFtype] = useState("");
  const [factor, setFactor] = useState("");

  const load = useCallback(async () => {
    const [ev, v] = await Promise.all([
      api.audit(eid, {}),
      api.auditVerify(eid),
    ]);
    setEvents(ev);
    setVerify(v);
  }, [eid]);
  useEffect(() => { load(); }, [load]);

  if (!events) return <Loading label="Loading audit chain" />;

  // Filter client-side so both dropdowns always list the full set of options.
  const eventTypes = Array.from(new Set(events.map((e) => e.event_type))).sort();
  const shown = events.filter(
    (e) => (!ftype || e.event_type === ftype) && (!factor || e.actor === factor)
  );

  return (
    <div>
      <SectionTitle sub="Append-only, hash-chained audit of every model call, tool invocation, agent decision & approval (SEC-04)."
        right={
          verify && (
            <div className="flex items-center gap-2">
              {verify.valid ? (
                <Badge color="#FFFFFF" dot><ShieldCheck size={12} className="inline mr-1" />CHAIN VERIFIED</Badge>
              ) : (
                <Badge color="#FF00A0" dot><ShieldSlash size={12} className="inline mr-1" />CHAIN BROKEN @ {verify.broken_at_seq}</Badge>
              )}
              <span className="mono text-[11px] text-muted">{verify.count} events</span>
            </div>
          )
        }>
        Tamper-Evident Audit Log
      </SectionTitle>

      <div className="flex gap-2 mb-3">
        <Select value={factor} onChange={(e) => setFactor(e.target.value)} className="w-40" data-testid="audit-actor-filter">
          <option value="">All actors</option>
          {["operator", "agent", "approver", "system"].map((a) => <option key={a} value={a}>{a}</option>)}
        </Select>
        <Select value={ftype} onChange={(e) => setFtype(e.target.value)} className="w-56" data-testid="audit-type-filter">
          <option value="">All event types</option>
          {eventTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </Select>
        <Btn variant="ghost" onClick={load} data-testid="audit-verify-btn">Verify Chain</Btn>
      </div>

      <Panel className="bg-black p-0 overflow-hidden">
        <div className="max-h-[560px] overflow-y-auto p-4 mono text-xs leading-relaxed">
          {shown.map((e) => (
            <div key={e.id} className="flex flex-wrap items-baseline gap-x-2 py-1 border-b border-white/5 last:border-0" data-testid={`audit-event-${e.seq}`}>
              <span className="text-muted w-10">#{e.seq}</span>
              <span className="text-neutral">{new Date(e.ts).toLocaleTimeString()}</span>
              <span style={{ color: ACTOR_COLOR[e.actor] || "#fff" }} title={e.actor_id}>[{e.actor}:{e.actor_id}]</span>
              <span className="text-white font-semibold">{e.event_type}</span>
              <span className="text-white/70 truncate max-w-[280px]">{JSON.stringify(e.payload)}</span>
              <span className="ml-auto text-muted/60" title={`hash ${e.hash}\nprev ${e.prev_hash}`}>↳ {e.hash.slice(0, 10)}</span>
            </div>
          ))}
          {shown.length === 0 && <div className="text-muted py-6 text-center">No audit events match the filter.</div>}
        </div>
      </Panel>
      <div className="text-[11px] text-muted mono mt-2">
        Head hash: <span className="text-white">{verify?.head_hash?.slice(0, 32)}…</span>
      </div>
    </div>
  );
}
