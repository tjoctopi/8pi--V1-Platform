import React, { useEffect, useState, useCallback } from "react";
import {
  MagnifyingGlass, ShieldWarning, Robot, CaretDown, CaretRight, Check, X as XIcon,
  Gavel, Warning, Lightning, Crosshair, Terminal, Skull, Package, Globe,
} from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { STATUS, INTENSITY, timeAgo } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, Select, useToast, errMsg } from "../../components/ui";
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

const fmtRun = (s) => (s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`);

function SessionCard({ s, canWrite, onCommand, onTeardown, busy }) {
  const [cmd, setCmd] = useState("");
  const [out, setOut] = useState(null);
  const [running, setRunning] = useState(false);
  const closed = s.status === "closed";
  const run = async () => {
    if (!cmd.trim() || running) return;
    setRunning(true);
    try { const r = await onCommand(s.id, cmd); setOut(r); } finally { setRunning(false); }
  };
  return (
    <Panel className="p-4" data-testid={`session-${s.id}`}
      style={closed ? { opacity: 0.55 } : { borderColor: "#FF00A0" }}>
      <div className="flex items-center gap-2 flex-wrap mb-2">
        <Skull size={16} className="text-incident" weight="fill" />
        <span className="mono text-sm text-white">{s.host}</span>
        <Badge color={closed ? "#7A7A7A" : "#FF2A2A"} dot>{closed ? "closed" : "LIVE SESSION"}</Badge>
        <span className="mono text-[10px] text-muted">{s.technique}</span>
        <span className="ml-auto mono text-[10px] text-muted">{s.id}</span>
        {!closed && (
          <Btn variant="danger" icon={XIcon} disabled={!canWrite || busy}
            onClick={() => onTeardown(s.id)} data-testid={`teardown-${s.id}`}>Teardown</Btn>
        )}
      </div>
      {/* proof of impact — identity headline */}
      {s.proof && Object.keys(s.proof).length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
          {Object.entries(s.proof).map(([k, v]) => (
            <div key={k} className="bg-black border border-line px-2 py-1.5">
              <div className="label text-[9px]">{k}</div>
              <div className="mono text-[11px] text-volt truncate">{v}</div>
            </div>
          ))}
        </div>
      )}

      {/* proof of impact — what we captured (loot + live site content) */}
      {((s.loot && s.loot.length > 0) || s.site_content) && (
        <div className="mb-3 border border-incident/40 bg-black/40 rounded-sm">
          <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
            <Skull size={13} className="text-incident" weight="fill" />
            <span className="label text-incident text-[10px]">Proof of impact — what we achieved on {s.host}</span>
          </div>
          <div className="p-3 space-y-3">
            {s.loot && s.loot.length > 0 && (
              <div>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Package size={12} className="text-volt" />
                  <span className="label text-[9px] text-sub">Auto-run loot ({s.loot.length})</span>
                </div>
                <div className="bg-black border border-line divide-y divide-white/5">
                  {s.loot.map((l, i) => (
                    <div key={i} className="px-2 py-1.5" data-testid={`loot-${s.id}-${i}`}>
                      <div className="mono text-[10px] text-volt">$ {l.command}</div>
                      <div className="mono text-[11px] text-sub whitespace-pre-wrap break-all">{l.output || "(no output)"}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {s.site_content && (
              <div>
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Globe size={12} className="text-volt" />
                  <span className="label text-[9px] text-sub">Captured site content</span>
                  <a href={s.site_content.url} target="_blank" rel="noreferrer"
                    className="mono text-[10px] text-muted hover:text-volt truncate">{s.site_content.url}</a>
                  {s.site_content.status != null && <Badge color="#B4B4B4">HTTP {s.site_content.status}</Badge>}
                </div>
                <pre className="bg-black border border-line p-2 text-[10px] mono text-sub max-h-48 overflow-auto whitespace-pre-wrap break-all" data-testid={`site-content-${s.id}`}>
                  {s.site_content.snippet || "(empty response)"}{s.site_content.truncated ? "\n…(truncated)" : ""}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
      {/* post-ex command runner */}
      {!closed && (
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-muted shrink-0" />
          <input value={cmd} onChange={(e) => setCmd(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") run(); }}
            disabled={!canWrite}
            placeholder="post-ex command (e.g. id, uname -a) — scope-bound & audited"
            data-testid={`cmd-${s.id}`}
            className="flex-1 bg-black border border-line text-white text-xs mono px-2 py-1.5 focus:outline-none focus:border-volt placeholder:text-muted" />
          <Btn variant="dark" loading={running} disabled={!canWrite || !cmd.trim()} onClick={run} data-testid={`run-cmd-${s.id}`}>Run</Btn>
        </div>
      )}
      {out && (
        <pre className="mt-2 bg-black border-l-2 border-volt p-2 text-[11px] mono text-sub overflow-x-auto whitespace-pre-wrap" data-testid={`cmd-out-${s.id}`}>
          {out.command}{"\n"}{out.output || "(no output)"}
        </pre>
      )}
    </Panel>
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
  const [live, setLive] = useState([]);
  const [c2, setC2] = useState({ sessions: [], candidates: [] });
  const [runElapsed, setRunElapsed] = useState(0);

  // live elapsed timer while an operation runs, so a minutes-long scan visibly
  // progresses (the operator knows it isn't stuck).
  useEffect(() => {
    if (!busy) { setRunElapsed(0); return undefined; }
    const start = Date.now();
    const t = setInterval(() => setRunElapsed(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => clearInterval(t);
  }, [busy]);

  const loadC2 = useCallback(() => {
    api.sessions(eid).then(setC2).catch(() => {});
  }, [eid]);

  const load = useCallback(async () => {
    const [ag, r, ap, iv] = await Promise.all([api.agents(), api.agentRuns(eid), api.approvals(eid), api.invocations(eid)]);
    setAgents(ag);
    setRuns(r);
    setApprovals(ap);
    setInvs(iv);
    loadC2();
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

  // sense/vuln-scan run as background jobs (Docker-spawning, minutes-long).
  // Start the job, stream live progress over SSE, poll until it finishes, reload.
  const pollJob = async (kind) => {
    for (let i = 0; i < 400; i++) {
      const jobs = await api.jobs(eid);
      const j = jobs.find((x) => x.kind === kind);
      if (j && j.status !== "running") {
        if (j.status === "error") throw new Error(j.detail || "job failed");
        return;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    throw new Error("job timed out");
  };
  const actJob = async (key, kind, startFn, msg) => {
    setBusy(key); setLive([]);
    let es;
    try { es = new EventSource(api.engagementEventsUrl(eid)); } catch { es = null; }
    if (es) es.onmessage = (e) => {
      try { const m = JSON.parse(e.data); setLive((L) => [...L.slice(-49), m]); } catch { /* keep-alive */ }
    };
    try {
      await startFn();
      await pollJob(kind);
      toast.success(msg); await load(); await reload();
    } catch (e) { toast.error(errMsg(e)); }
    finally { if (es) es.close(); setBusy(""); }
  };

  // C2: establish runs as a governed background job (gate may park for approval)
  const establish = (fid) =>
    actJob("est" + fid, "foothold", () => api.establishFoothold(eid, fid),
      "Foothold established — live session opened").then(loadC2);
  const sessionCmd = async (sid, command) => {
    try { const r = await api.sessionCommand(eid, sid, command); return r; }
    catch (e) { toast.error(errMsg(e)); return { command, output: `error: ${errMsg(e)}` }; }
  };
  const teardown = (sid) =>
    act("td" + sid, () => api.teardownSession(eid, sid), "Session torn down").then(loadC2);

  const pending = approvals.filter((a) => a.status === "pending");
  const authorized = agents.filter((a) => a.promotion_state === "authorized");
  const liveSessions = (c2.sessions || []).filter((s) => s.status !== "closed");

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
        <SectionTitle sub="Drive the engagement — one autonomous kill chain, or step by step. Every action is scope-checked, gated, and audited.">Live Console</SectionTitle>
        <div className="flex flex-wrap items-center gap-3">
          <Btn icon={Lightning} variant="primary" loading={busy === "campaign"} disabled={engagement.halted || !canWrite || !!busy}
            onClick={() => actJob("campaign", "campaign", () => api.campaign(eid), "Full attack complete — findings & attack path updated")}
            data-testid="run-campaign-btn">Run Full Attack</Btn>
          <div className="h-6 w-px bg-white/10" />
          <Btn icon={MagnifyingGlass} variant="dark" loading={busy === "sense"} disabled={engagement.halted || !canWrite || !!busy}
            onClick={() => actJob("sense", "sense", () => api.sense(eid), "Sensing complete — asset graph updated")} data-testid="run-sensing-btn">Run Sensing</Btn>
          <Btn icon={ShieldWarning} variant="dark" loading={busy === "vuln"} disabled={engagement.halted || !canWrite || !!busy}
            onClick={() => actJob("vuln", "vuln-scan", () => api.vulnScan(eid), "Vuln scan complete")} data-testid="run-vulnscan-btn">Vuln Scan</Btn>
          <div className="h-6 w-px bg-white/10" />
          <Select value={pick} onChange={(e) => setPick(e.target.value)} className="w-52" data-testid="agent-picker">
            {authorized.length === 0 && <option value="">No authorized agents</option>}
            {authorized.map((a) => <option key={a.id} value={a.id}>{a.name} · {a.role}</option>)}
          </Select>
          <Btn icon={Robot} loading={busy === "run"} disabled={!pick || engagement.halted || !canWrite || !!busy}
            onClick={() => actJob("run", "agent-run", () => api.runAgent(eid, pick), "Agent run complete")} data-testid="run-agent-btn">Run Agent</Btn>
        </div>

        {(busy === "sense" || busy === "vuln" || busy === "campaign" || busy === "run" || live.length > 0) && (
          <div className="mt-4 border border-line bg-ink" data-testid="live-feed">
            <div className="flex items-center gap-2 px-3 py-2 border-b border-line">
              <span className="w-2 h-2 rounded-full bg-info blink" />
              <span className="label text-info">Live progress</span>
              <span className="ml-auto mono text-[10px]" style={{ color: busy ? "#FFB020" : "#7A7A7A" }}>
                {busy ? `running… ${fmtRun(runElapsed)}` : "done"}
              </span>
            </div>
            <div className="max-h-52 overflow-y-auto p-3 space-y-1 font-mono text-[11px]">
              {live.length === 0 ? (
                <div className="text-muted">waiting for the engine to emit events…</div>
              ) : live.map((m, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-volt shrink-0">{m.type}</span>
                  <span className="text-sub truncate">{m.target || (m.payload && (m.payload.tool || m.payload.kind || m.payload.detail)) || ""}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {/* offensive C2 — footholds & live sessions (the single foothold/C2 + proof showcase) */}
      <div>
        <SectionTitle sub="The one place for footholds & C2: turn a confirmed command-execution finding into a live, governed session (scope-checked, human-gated, audited, kill-switchable), then see exactly what we captured — auto-run loot and the live site content — the proof you put in front of the client."
          right={liveSessions.length > 0 ? <Badge color="#FF2A2A" dot>{liveSessions.length} LIVE</Badge> : null}>
          Footholds & C2
        </SectionTitle>
        {liveSessions.length > 0 && (
          <div className="kill-stripe p-0.5 rounded-sm mb-3">
            <div className="bg-panel2 px-4 py-3 flex items-center gap-3 flex-wrap" data-testid="breach-banner">
              <Skull size={20} className="text-incident" weight="fill" />
              <span className="text-sm text-white font-semibold">
                Breach achieved — {liveSessions.length} live foothold{liveSessions.length > 1 ? "s" : ""}
              </span>
              <span className="mono text-[11px] text-sub">
                {liveSessions.map((s) => `${s.proof?.whoami || "shell"}@${s.host}`).join("  ·  ")}
              </span>
            </div>
          </div>
        )}
        {(c2.candidates?.length > 0) && (
          <div className="space-y-2 mb-3">
            {c2.candidates.map((f) => (
              <Panel key={f.finding_id} className="p-3 flex items-center gap-3 flex-wrap" data-testid={`foothold-candidate-${f.finding_id}`}>
                <Crosshair size={16} className="text-volt" weight="fill" />
                <span className="text-sm text-white truncate">{f.title}</span>
                <Badge color="#FF2A2A">confirmed RCE</Badge>
                <span className="mono text-[11px] text-muted truncate">{f.host} · {f.param}</span>
                <Btn className="ml-auto" icon={Crosshair} loading={busy === "est" + f.finding_id}
                  disabled={engagement.halted || !canWrite || !!busy}
                  onClick={() => establish(f.finding_id)} data-testid={`establish-${f.finding_id}`}>
                  Establish Foothold
                </Btn>
              </Panel>
            ))}
          </div>
        )}
        {c2.sessions?.length > 0 ? (
          <div className="space-y-3">
            {c2.sessions.map((s) => (
              <SessionCard key={s.id} s={s} canWrite={canWrite} busy={busy}
                onCommand={sessionCmd} onTeardown={teardown} />
            ))}
          </div>
        ) : (c2.candidates?.length === 0 && (
          <Empty icon={Skull} title="No live footholds"
            hint="Run Full Attack / Vuln Scan to confirm a command-execution finding, then Establish Foothold to open a live session." />
        ))}
      </div>

      {/* approvals */}
      <div>
        <SectionTitle sub="Exploit / mutating actions block here until an approver releases them (SEC-06)."
          right={<Badge color={pending.length ? "#B4B4B4" : "#FFFFFF"} dot>{pending.length} PENDING</Badge>}>
          Approval Gate
        </SectionTitle>
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
