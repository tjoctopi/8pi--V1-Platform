import React, { useEffect, useState, useCallback } from "react";
import {
  MagnifyingGlass, ShieldWarning, Robot, CaretDown, CaretRight, Check, X as XIcon,
  Gavel, Lightning, Warning,
} from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { STATUS, INTENSITY, timeAgo } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Dot, Loading, Empty, Select, PreviewNotice, useToast, errMsg } from "../../components/ui";
import { useAuth, roleAtLeast } from "../../lib/auth";

function StepRow({ s }) {
  const color = STATUS[s.status] || "#7A7A7A";
  return (
    <div className="flex items-center gap-3 py-1.5 text-xs border-b border-white/5 last:border-0">
      <span className="w-24 shrink-0 label" style={{ color }}>{s.phase}</span>
      <span className="mono text-sub flex-1 truncate">{s.target || "—"}</span>
      {s.technique && <span className="mono text-[10px] text-muted hidden sm:inline">{s.technique.id}</span>}
      <span className="text-sub text-right">{s.result}</span>
    </div>
  );
}

function AgentRunCard({ run }) {
  const [open, setOpen] = useState(false);
  const color = run.role === "defensive" ? "#FFFFFF" : "#FF00A0";
  return (
    <Panel className="p-4" data-testid={`agent-run-${run.id}`}>
      <button className="w-full flex items-center gap-3 text-left" onClick={() => setOpen((o) => !o)}>
        {open ? <CaretDown size={14} className="text-muted" /> : <CaretRight size={14} className="text-muted" />}
        <Robot size={16} style={{ color }} weight="fill" />
        <span className="text-sm font-semibold text-white">{run.agent_name}</span>
        <Badge color={color}>{run.role}</Badge>
        <Badge color={STATUS[run.status]}>{run.status}</Badge>
        {run.role === "defensive" && run.detection_rate != null && <Badge color="#B4B4B4">{run.detection_rate}% caught</Badge>}
        <span className="ml-auto text-[11px] text-muted mono">{timeAgo(run.started_at)}</span>
      </button>
      {open && (
        <div className="mt-3 pl-6">
          {(run.steps || []).map((s, i) => <StepRow key={`${s.phase}-${s.ts || i}`} s={s} />)}
          {run.summary && (
            <div className="mt-3 p-3 bg-black border-l-2 border-volt text-xs text-sub">
              <span className="label text-volt">AI Analysis · Model Gateway</span>
              <p className="mt-1.5 leading-relaxed">{run.summary}</p>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

export default function ConsoleTab({ eid, engagement, roe, reload }) {
  const toast = useToast();
  const { user } = useAuth();
  const canApprove = roleAtLeast(user, "approver");
  const canWrite = roleAtLeast(user, "operator");
  const [agents, setAgents] = useState([]);
  const [runs, setRuns] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [invs, setInvs] = useState([]);
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    const [ag, r, ap, iv] = await Promise.all([api.agents(), api.agentRuns(eid), api.approvals(eid), api.invocations(eid)]);
    setAgents(ag);
    setRuns(r);
    setApprovals(ap);
    setInvs(iv);
    if (!pick) {
      const off = ag.find((a) => a.role !== "defensive" && a.promotion_state === "authorized");
      setPick(off?.id || (ag[0] && ag[0].id) || "");
    }
  }, [eid]); // eslint-disable-line

  useEffect(() => { load().catch((e) => toast.error(errMsg(e))); }, [load]); // eslint-disable-line

  const act = async (key, fn, msg) => {
    setBusy(key);
    try { await fn(); toast.success(msg); await load(); await reload(); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(""); }
  };

  const pending = approvals.filter((a) => a.status === "pending");
  const authorized = agents.filter((a) => a.promotion_state === "authorized");

  if (!agents) return <Loading />;

  return (
    <div className="space-y-6">
      {engagement.halted && (
        <div className="kill-stripe p-0.5 rounded-sm">
          <div className="bg-panel2 px-4 py-3 flex items-center gap-3">
            <Warning size={20} className="text-kill" weight="fill" />
            <span className="text-sm text-white font-semibold">Kill switch active — all agent & tool activity halted. Resume from the header to continue.</span>
          </div>
        </div>
      )}

      {/* pipeline */}
      <Panel className="p-5">
        <SectionTitle sub="Drive the engagement. Every action is scope-checked and audited.">Live Console</SectionTitle>
        <div className="flex flex-wrap items-center gap-3">
          <Btn icon={MagnifyingGlass} variant="dark" loading={busy === "sense"} disabled={engagement.halted || !canWrite}
            onClick={() => act("sense", () => api.sense(eid), "Sensing complete — asset graph updated")} data-testid="run-sensing-btn">Run Sensing</Btn>
          <Btn icon={ShieldWarning} variant="dark" loading={busy === "vuln"} disabled={engagement.halted || !canWrite}
            onClick={() => act("vuln", () => api.vulnScan(eid), "Vuln scan complete")} data-testid="run-vulnscan-btn">Vuln Scan</Btn>
          <div className="h-6 w-px bg-white/10" />
          <Select value={pick} onChange={(e) => setPick(e.target.value)} className="w-52" data-testid="agent-picker">
            {authorized.length === 0 && <option value="">No authorized agents</option>}
            {authorized.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.role}</option>)}
          </Select>
          <Btn icon={Robot} loading={busy === "run"} disabled={!pick || engagement.halted || !canWrite}
            onClick={() => act("run", () => api.runAgent(eid, pick), "Agent run complete")} data-testid="run-agent-btn">Run Agent</Btn>
        </div>
      </Panel>

      {/* approvals */}
      <div>
        <SectionTitle sub="Exploit / mutating actions block here until an approver releases them (SEC-06)."
          right={<Badge color={pending.length ? "#B4B4B4" : "#FFFFFF"} dot>{pending.length} PENDING</Badge>}>
          Approval Gate
        </SectionTitle>
        <PreviewNotice className="mb-3">
          Sense and Vuln Scan above are live against the real engine. Human approval gates and
          one-click agent-run dispatch aren't wired yet — those are not available in this build
          (the engine enforces gates today via signed scope + kill switch).
        </PreviewNotice>
        {pending.length === 0 ? (
          <Panel className="p-6"><div className="text-sm text-muted">No actions awaiting approval.</div></Panel>
        ) : (
          <div className="space-y-3">
            {!canApprove && (
              <div className="text-xs text-sub mono flex items-center gap-2"><Gavel size={14} /> You need the <b>approver</b> or <b>admin</b> role to release actions. Sign in with an approver account.</div>
            )}
            {pending.map((a) => (
              <Panel key={a.id} className="p-4" data-testid={`approval-${a.id}`}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge color="#FF00A0" dot>EXPLOIT</Badge>
                      <span className="mono text-sm text-white">{a.action.tool_id}</span>
                      <span className="text-muted">→</span>
                      <span className="mono text-sm text-sub truncate">{a.action.target}</span>
                    </div>
                    <div className="text-xs text-muted">{a.action.rationale}</div>
                    {a.action.technique && <div className="text-[11px] mono text-muted mt-1">{a.action.technique.framework} · {a.action.technique.id} {a.action.technique.name}</div>}
                  </div>
                  <div className="flex gap-2">
                    <Btn variant="success" icon={Check} disabled={!canApprove || busy}
                      onClick={() => act("ap" + a.id, () => api.approve(a.id), "Action approved & executed")} data-testid={`approve-${a.id}`}>Approve</Btn>
                    <Btn variant="danger" icon={XIcon} disabled={!canApprove || busy}
                      onClick={() => act("dn" + a.id, () => api.deny(a.id, "denied by approver"), "Action denied")} data-testid={`deny-${a.id}`}>Deny</Btn>
                  </div>
                </div>
              </Panel>
            ))}
          </div>
        )}
      </div>

      {/* agent runs */}
      <div>
        <SectionTitle>Agent Runs</SectionTitle>
        {runs.length === 0 ? (
          <Empty icon={Robot} title="No agent runs yet" hint="Run an authorized agent above to execute a scoped attack chain / detection pass." />
        ) : (
          <div className="space-y-2">{runs.map((r) => <AgentRunCard key={r.id} run={r} />)}</div>
        )}
      </div>

      {/* recent tool invocations */}
      <div>
        <SectionTitle right={<Badge color="#7A7A7A">{invs.length} total</Badge>}>Tool Invocations</SectionTitle>
        <Panel className="overflow-hidden">
          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-panel/90 backdrop-blur">
                <tr className="border-b border-line">{["Tool", "Target", "Intensity", "Scope", "Status", "When"].map((h) => <th key={h} className="text-left label px-4 py-2.5">{h}</th>)}</tr>
              </thead>
              <tbody>
                {invs.slice(0, 60).map((iv) => (
                  <tr key={iv.id} className="border-b border-white/5" data-testid={`invocation-${iv.id}`}>
                    <td className="px-4 py-2 mono text-white text-xs">{iv.tool_id}</td>
                    <td className="px-4 py-2 mono text-sub text-xs truncate max-w-[200px]">{iv.target}</td>
                    <td className="px-4 py-2"><Badge color={INTENSITY[iv.intensity]?.color || "#7A7A7A"}>{iv.intensity}</Badge></td>
                    <td className="px-4 py-2 mono text-[11px]" style={{ color: iv.scope_check_result?.allow ? "#FFFFFF" : "#FF2A2A", fontWeight: iv.scope_check_result?.allow ? 400 : 900, textShadow: iv.scope_check_result?.allow ? "none" : "0 0 4px #FF2A2A" }}>{iv.scope_check_result?.reason}</td>
                    <td className="px-4 py-2"><Badge color={STATUS[iv.status] || "#7A7A7A"}>{iv.status}</Badge></td>
                    <td className="px-4 py-2 mono text-[11px] text-muted">{timeAgo(iv.started_at)}</td>
                  </tr>
                ))}
                {invs.length === 0 && <tr><td colSpan={6} className="px-4 py-6 text-center text-muted text-sm">No tool activity yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
