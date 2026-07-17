import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Plus, Target, HardDrives, Bug, Gavel, Lightning, StackSimple, Archive, ArrowCounterClockwise,
} from "@phosphor-icons/react";
import { api } from "../lib/api";
import { SEV, STATUS, timeAgo } from "../lib/theme";
import {
  Panel, SectionTitle, Btn, Badge, Dot, Modal, Field, TextInput, Textarea, Loading, Empty, useToast, errMsg,
} from "../components/ui";

function Stat({ icon: Icon, label, value, color = "#fff", sub }) {
  return (
    <Panel className="p-5" data-testid={`stat-${label.toLowerCase().replace(/\s/g, "-")}`}>
      <div className="flex items-center justify-between">
        <div className="label">{label}</div>
        <Icon size={18} style={{ color }} weight="bold" />
      </div>
      <div className="mt-3 h-font text-4xl font-black leading-none" style={{ color }}>
        {value}
      </div>
      {sub && <div className="text-[11px] text-muted mt-1.5 mono">{sub}</div>}
    </Panel>
  );
}

function SevBar({ dist }) {
  const order = ["crit", "high", "med", "low", "info"];
  const total = Object.values(dist || {}).reduce((a, b) => a + b, 0);
  if (!total) return <div className="text-xs text-muted mono">no open findings</div>;
  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden rounded-sm border border-line">
        {order.map((k) =>
          dist[k] ? (
            <div key={k} style={{ width: `${(dist[k] / total) * 100}%`, background: SEV[k].color }} title={`${k}: ${dist[k]}`} />
          ) : null
        )}
      </div>
      <div className="flex flex-wrap gap-3 mt-3">
        {order.map((k) =>
          dist[k] ? (
            <div key={k} className="flex items-center gap-1.5 text-xs">
              <span className="w-2 h-2" style={{ background: SEV[k].color }} />
              <span className="text-sub">{SEV[k].label}</span>
              <span className="mono text-white">{dist[k]}</span>
            </div>
          ) : null
        )}
      </div>
    </div>
  );
}

const ACTOR_COLOR = { operator: "#00E5FF", agent: "#FF00A0", approver: "#22E85D", system: "#7A7A7A" };

/** REAL-INCIDENT audit events (blood red, bold, ▲ marker). An operator MUST notice these.
 *  Approval decisions (denied/approved) are ordinary workflow, NOT incidents. */
const INCIDENT_EVENTS = new Set([
  "human_halt",
  "engagement_halted",
  "kill_switch",
  "tool_refused_scope",
  "tool_refused_halt",
  "exploit_confirmed",
  "scope_violation",
  "audit_broken",
]);

function LiveLog({ eid }) {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try { const ev = await api.audit(eid, { limit: 5 }); if (alive) setEvents(ev); } catch (e) { if (alive) console.debug("live-log poll failed", e?.message); }
    };
    poll();
    const t = setInterval(poll, 4000);
    return () => { alive = false; clearInterval(t); };
  }, [eid]);
  const hasIncident = events.some((ev) => INCIDENT_EVENTS.has(ev.event_type));
  return (
    <div className="mt-3 pt-3 border-t border-line" data-testid={`live-log-${eid}`} onClick={(e) => e.stopPropagation()}>
      <div className="flex items-center gap-1.5 mb-1.5">
        <span
          className={hasIncident ? "w-1.5 h-1.5 rounded-full bg-incident blink" : "w-1.5 h-1.5 rounded-full bg-live blink"}
          style={{ boxShadow: hasIncident ? "0 0 8px #FF2A2A" : "0 0 6px #22E85D" }}
        />
        <span className="label" style={{ color: hasIncident ? "#FF2A2A" : "#22E85D" }}>
          {hasIncident ? "Live Activity · Incident" : "Live Activity"}
        </span>
      </div>
      <div className="bg-black border border-line px-2 py-1.5 h-[92px] overflow-hidden mono text-[10px] leading-[1.5]">
        {events.length === 0 ? (
          <div className="text-muted">awaiting events…</div>
        ) : (
          events.map((ev) => {
            const incident = INCIDENT_EVENTS.has(ev.event_type);
            return (
              <div key={ev.id} className="flex items-baseline gap-1.5 truncate fadein">
                <span className="text-muted">#{ev.seq}</span>
                <span style={{ color: ACTOR_COLOR[ev.actor] || "#fff" }}>{ev.actor}</span>
                {incident ? (
                  <span
                    className="font-black"
                    style={{ color: "#FF2A2A", textShadow: "0 0 4px #FF2A2A" }}
                  >
                    ▲ {ev.event_type}
                  </span>
                ) : (
                  <span className="text-sub">{ev.event_type}</span>
                )}
                <span className="ml-auto text-muted/60 shrink-0">{timeAgo(ev.ts)}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function EngagementCard({ e, onOpen, onArchive, pinned }) {
  const c = e.counts || {};
  return (
    <Panel
      className={`p-5 hover:border-white/25 transition-colors cursor-pointer group relative ${pinned ? "corner-frame" : ""}`}
      onClick={() => onOpen(e.id)}
      data-testid={`engagement-card-${e.id}`}
    >
      {pinned && (
        <div className="absolute -top-2 left-4 px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest2 bg-black border border-volt text-volt z-10">
          PINNED · DEMO
        </div>
      )}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <Dot color={STATUS[e.status]} pulse={e.status === "active"} />
            <span className="label" style={{ color: STATUS[e.status] }}>{e.status}</span>
            {e.roe_signed ? (
              <Badge color="#22E85D">RoE Signed</Badge>
            ) : (
              <Badge color="#7A7A7A">RoE Draft</Badge>
            )}
            {e.archived && <Badge color="#4A4A4A">Archived</Badge>}
          </div>
          <div className="h-font text-lg font-bold text-white truncate group-hover:text-volt transition-colors">
            {e.name}
          </div>
          <div className="text-[11px] text-muted mono mt-0.5">created {timeAgo(e.created_at)}</div>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          {e.max_intensity && <Badge color={SEV[e.max_intensity === "exploit" ? "crit" : e.max_intensity === "safe-active" ? "med" : "low"].color}>{e.max_intensity}</Badge>}
          <button
            onClick={(ev) => { ev.stopPropagation(); onArchive(e); }}
            data-testid={e.archived ? `unarchive-engagement-${e.id}` : `archive-engagement-${e.id}`}
            title={e.archived ? "Unarchive engagement" : "Archive engagement"}
            className="text-muted hover:text-white transition-colors p-1 -mr-1"
          >
            {e.archived ? <ArrowCounterClockwise size={15} weight="bold" /> : <Archive size={15} weight="bold" />}
          </button>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2 mt-4 pt-4 border-t border-line">
        <div><div className="mono text-xl text-white">{c.assets ?? 0}</div><div className="label mt-0.5">Assets</div></div>
        <div>
          <div className="mono text-xl" style={{ color: (c.findings || 0) > 0 ? "#FFB020" : "#FFFFFF" }}>{c.findings ?? 0}</div>
          <div className="label mt-0.5">Findings</div>
        </div>
        <div>
          <div className="mono text-xl" style={{ color: c.pending_approvals ? "#FFB020" : "#7A7A7A" }}>{c.pending_approvals ?? 0}</div>
          <div className="label mt-0.5">Approvals</div>
        </div>
      </div>
      {(e.status === "active" || e.status === "paused") && <LiveLog eid={e.id} />}
    </Panel>
  );
}

const STATUS_RANK = { active: 4, paused: 3, draft: 2, closed: 1 };

function sortEngagements(list) {
  return [...list].sort((a, b) => {
    // 1. Dogfood demo engagement always first (has the most seed data)
    const aDog = (a.name || "").toLowerCase().startsWith("dogfood");
    const bDog = (b.name || "").toLowerCase().startsWith("dogfood");
    if (aDog !== bDog) return aDog ? -1 : 1;
    // 2. by status rank (active > paused > draft > closed)
    const sr = (STATUS_RANK[b.status] || 0) - (STATUS_RANK[a.status] || 0);
    if (sr) return sr;
    // 3. newest first
    return new Date(b.created_at || 0) - new Date(a.created_at || 0);
  });
}

export default function Dashboard() {
  const nav = useNavigate();
  const toast = useToast();
  const [stats, setStats] = useState(null);
  const [engs, setEngs] = useState(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [seeds, setSeeds] = useState("");
  const [busy, setBusy] = useState(false);
  const [showArchived, setShowArchived] = useState(false);

  const load = async () => {
    const [s, e] = await Promise.all([api.stats(), api.engagements(showArchived)]);
    setStats(s);
    setEngs(e);
  };
  useEffect(() => {
    load().catch((err) => toast.error(errMsg(err)));
    // eslint-disable-next-line
  }, [showArchived]);

  const onArchive = async (e) => {
    try {
      if (e.archived) { await api.unarchiveEngagement(e.id); toast.success("Engagement unarchived"); }
      else { await api.archiveEngagement(e.id); toast.success("Engagement archived"); }
      await load();
    } catch (err) { toast.error(errMsg(err)); }
  };

  const create = async () => {
    if (!name.trim()) return toast.error("Engagement name required");
    setBusy(true);
    try {
      const e = await api.createEngagement({
        name: name.trim(),
        estate_seeds: seeds.split("\n").map((s) => s.trim()).filter(Boolean),
      });
      toast.success("Engagement created — sign the RoE to proceed");
      setOpen(false);
      setName("");
      setSeeds("");
      nav(`/engagements/${e.id}`);
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  if (!stats || !engs) return <Loading label="Loading operations console" />;

  const byStatus = stats.engagements_by_status || {};

  return (
    <div className="p-6 max-w-[1500px] mx-auto fadein">
      <SectionTitle
        sub="Scoped, authorized, fully-audited offensive engagements."
        right={
          <Btn icon={Plus} onClick={() => setOpen(true)} data-testid="new-engagement-btn">
            New Engagement
          </Btn>
        }
      >
        Operations
      </SectionTitle>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
        <Stat icon={Target} label="Engagements" value={stats.engagements} color="#22E85D"
          sub={`${byStatus.active || 0} active · ${byStatus.draft || 0} draft`} />
        <Stat icon={HardDrives} label="Assets" value={stats.assets} color="#FFFFFF" />
        <Stat icon={Bug} label="Open Findings" value={stats.findings_open}
          color={stats.findings_open > 20 ? "#FF00A0" : "#FFB020"} />
        <Stat icon={Gavel} label="Pending Approvals" value={stats.pending_approvals}
          color={stats.pending_approvals ? "#FFB020" : "#7A7A7A"} />
        <Stat icon={StackSimple} label="Tool Runs" value={stats.tool_invocations} color="#00E5FF" />
        <Stat icon={Lightning} label="Model Spend" value={`$${(stats.model_spend || 0).toFixed(3)}`}
          color="#22E85D" sub={`${stats.model_calls} calls · ${stats.agents} agents`} />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SectionTitle right={
            <button
              onClick={() => setShowArchived((v) => !v)}
              data-testid="toggle-archived"
              className={`inline-flex items-center gap-2 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-widest2 border transition-colors ${showArchived ? "border-volt text-volt bg-volt/10" : "border-line text-muted hover:text-white hover:border-white/25"}`}
            >
              <Archive size={13} weight="bold" /> {showArchived ? "Hide Archived" : "Show Archived"}
            </button>
          }>Engagements</SectionTitle>
          {engs.length === 0 ? (
            <Empty icon={Target} title="No engagements yet" hint="Create an engagement to begin scoping an offensive run."
              action={<Btn icon={Plus} onClick={() => setOpen(true)}>New Engagement</Btn>} />
          ) : (
            <div className="grid sm:grid-cols-2 gap-4">
              {sortEngagements(engs).map((e) => (
                <EngagementCard
                  key={e.id}
                  e={e}
                  onOpen={(id) => nav(`/engagements/${id}`)}
                  onArchive={onArchive}
                  pinned={(e.name || "").toLowerCase().startsWith("dogfood")}
                />
              ))}
            </div>
          )}
        </div>
        <div>
          <SectionTitle>Risk Posture</SectionTitle>
          <Panel className="p-5">
            <div className="label mb-3">Open Findings by Severity</div>
            <SevBar dist={stats.findings_by_severity} />
          </Panel>
          <Panel className="p-5 mt-4">
            <div className="label mb-3">Safety Controls</div>
            {[
              ["Signed RoE required", "SEC-01"],
              ["Scope enforced at boundary", "SEC-02"],
              ["Data-egress control", "SEC-05"],
              ["Human-in-the-loop approval", "SEC-06"],
              ["Tamper-evident audit", "SEC-04"],
              ["Kill switch", "SEC-10"],
            ].map(([label, id]) => (
              <div key={id} className="flex items-center justify-between py-2 border-b border-line last:border-0">
                <span className="text-sm text-sub">{label}</span>
                <Badge color="#22E85D" dot>{id}</Badge>
              </div>
            ))}
          </Panel>
        </div>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title="New Engagement">
        <div className="space-y-4">
          <Field label="Engagement Name">
            <TextInput data-testid="engagement-name-input" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Q3 External Perimeter — Acme" />
          </Field>
          <Field label="Estate Seeds" hint="One target per line — CIDR, hostname, or URL. Defines the initial scope allowlist.">
            <Textarea data-testid="engagement-seeds-input" value={seeds} onChange={(e) => setSeeds(e.target.value)}
              placeholder={"10.10.0.0/24\napp.example.com\nhttps://portal.example.com"} />
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <Btn variant="ghost" onClick={() => setOpen(false)}>Cancel</Btn>
            <Btn onClick={create} loading={busy} data-testid="create-engagement-submit">Create</Btn>
          </div>
        </div>
      </Modal>
    </div>
  );
}
