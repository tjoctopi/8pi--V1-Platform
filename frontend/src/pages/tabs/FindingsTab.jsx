import React, { useEffect, useState, useCallback } from "react";
import { Bug, Wrench, ArrowsClockwise, ShieldCheck, Warning, Target, ArrowRight, Info } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV, EXPLOIT, STATUS } from "../../lib/theme";
import { explainFinding, isReal, isConfirmed, isUnconfirmedCandidate, isFalsePositive } from "../../lib/vulnExplain";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, Modal, useToast, errMsg } from "../../components/ui";

// short "where" from a finding (endpoint/target), for the client brief
const whereOf = (f) => {
  const m = /(?:\bat\b|:)\s*(\/\S+|https?:\/\/\S+)/i.exec(f.title || "");
  return f.target || f.asset || (m && m[1]) || "the target";
};

function ExecSummary({ real, all }) {
  const bySev = real.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
  const confirmed = real.filter(isConfirmed).length;
  const unconfirmed = all.filter(isUnconfirmedCandidate).length;
  const discarded = all.filter(isFalsePositive).length;
  const top = [...real].sort((a, b) => sevRank(b.severity) - sevRank(a.severity))[0];
  const topBrief = top ? explainFinding(top) : null;
  return (
    <Panel className="p-5 mb-5 corner-frame" data-testid="exec-summary">
      <div className="flex items-center gap-2 mb-2"><Target size={16} className="text-volt" weight="fill" />
        <span className="h-font text-lg uppercase tracking-tight text-white">Executive Summary</span></div>
      {real.length === 0 ? (
        <p className="text-sm text-sub leading-relaxed">No reportable weaknesses in this engagement yet.
          {unconfirmed > 0 && <> The engine has <b className="text-white">{unconfirmed} candidate{unconfirmed === 1 ? "" : "s"} still being tested</b> (unproven — not yet confirmed).</>}
          {discarded > 0 && <> {discarded} candidate{discarded === 1 ? " was" : "s were"} tested and <b className="text-white">discarded as false positive{discarded === 1 ? "" : "s"}</b>.</>}
          {" "}Run <b className="text-white">Full Attack</b> or a Vuln Scan from the Console to probe deeper.</p>
      ) : (
        <>
          <p className="text-sm text-sub leading-relaxed">
            This engagement found <b className="text-white">{real.length} reportable weakness{real.length === 1 ? "" : "es"}</b>
            {confirmed > 0 && <> (<span className="text-incident font-semibold">{confirmed} exploit-confirmed</span>)</>}.
            {topBrief && <> The most serious is a <b className="text-white">{topBrief.name}</b> at <span className="mono text-sub">{whereOf(top)}</span> — {topBrief.what.toLowerCase()}</>}
          </p>
          <div className="flex flex-wrap gap-2 mt-3 items-center">
            {["crit", "high", "med", "low", "info"].filter((s) => bySev[s]).map((s) => (
              <Badge key={s} color={SEV[s]?.color}>{bySev[s]} {SEV[s]?.label}</Badge>
            ))}
            {unconfirmed > 0 && <span className="text-[11px] text-muted mono self-center">· {unconfirmed} unconfirmed candidate{unconfirmed === 1 ? "" : "s"}</span>}
            {discarded > 0 && <span className="text-[11px] text-muted mono self-center">· {discarded} false-positive{discarded === 1 ? "" : "s"} auto-discarded</span>}
          </div>
        </>
      )}
    </Panel>
  );
}

function NextStep({ real }) {
  const hasCmdExec = real.some((f) => isConfirmed(f) && /command|cmd|\brce\b|remote code|t1059/i.test(`${f.title} ${f.technique_ref}`));
  let msg, tone = "#00E5FF";
  if (real.length === 0) msg = "No reportable weaknesses yet — run Full Attack / Vuln Scan from the Console to go deeper.";
  else if (hasCmdExec) { msg = "A confirmed command-execution weakness was found — open a live foothold from the Console tab, then generate the client report."; tone = "#FF2A2A"; }
  else msg = "Review the weaknesses below (click any row for a client-ready brief), then open the Report tab to hand the client a fix-list.";
  return (
    <div className="flex items-start gap-2.5 border px-4 py-2.5 mb-5 rounded-sm" style={{ borderColor: `${tone}55`, background: `${tone}0f` }} data-testid="next-step">
      <ArrowRight size={15} style={{ color: tone }} weight="bold" className="mt-0.5 shrink-0" />
      <div className="text-sm text-sub"><b className="text-white uppercase text-[11px] tracking-wider mr-1.5">Next</b>{msg}</div>
    </div>
  );
}

function sevRank(s) { return { crit: 5, high: 4, med: 3, low: 2, info: 1 }[s] || 0; }

export default function FindingsTab({ eid, reload }) {
  const toast = useToast();
  const [findings, setFindings] = useState(null);
  const [err, setErr] = useState(null);
  const [view, setView] = useState("real"); // real | confirmed | all
  const [sel, setSel] = useState(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try { setErr(null); setFindings(await api.findings(eid)); }
    catch (e) { setErr(errMsg(e)); }
  }, [eid]);
  useEffect(() => { load(); }, [load]);

  const act = async (key, fn, msg) => {
    setBusy(key);
    try { const r = await fn(); toast.success(msg(r)); await load(); await reload(); if (sel) setSel(null); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(""); }
  };

  if (err) return <Empty icon={Bug} title="Couldn't load findings" hint={err} action={<Btn variant="ghost" onClick={load} data-testid="findings-retry">Retry</Btn>} />;
  if (!findings) return <Loading label="Loading findings" />;

  const real = findings.filter(isReal);
  const views = [
    { id: "real", label: `Real (${real.length})` },
    { id: "confirmed", label: `Confirmed (${findings.filter(isConfirmed).length})` },
    { id: "all", label: `All (${findings.length})` },
  ];
  const shown = view === "all" ? findings : view === "confirmed" ? findings.filter(isConfirmed) : real;

  if (findings.length === 0) return <Empty icon={Bug} title="No findings" hint="Run Full Attack / Vuln Scan from the Console to generate findings." />;

  const brief = sel ? explainFinding(sel) : null;

  return (
    <div>
      <SectionTitle sub="Weaknesses in plain language — what each one is, why it's exploitable, and how to fix it."
        right={
          <div className="flex gap-1" data-testid="finding-views">
            {views.map((v) => (
              <button key={v.id} onClick={() => setView(v.id)} data-testid={`finding-view-${v.id}`}
                className={`px-3 py-1.5 text-[11px] uppercase tracking-wider border rounded-sm transition-colors ${view === v.id ? "border-volt bg-volt/10 text-white" : "border-line text-muted hover:text-sub"}`}>{v.label}</button>
            ))}
          </div>
        }>
        Findings
      </SectionTitle>

      <ExecSummary real={real} all={findings} />
      <NextStep real={real} />

      {shown.length === 0 ? (
        <Empty icon={ShieldCheck} title={view === "confirmed" ? "No exploit-confirmed weaknesses" : "No real weaknesses in this view"}
          hint="Switch to 'All' to see every candidate the engine tested (including auto-discarded false positives)." />
      ) : (
        <Panel className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-line bg-panel/60">{["Sev", "Weakness", "Where", "Exploitability", "Status"].map((h) => <th key={h} className="text-left label px-4 py-3">{h}</th>)}</tr></thead>
              <tbody>
                {shown.map((f) => {
                  const b = explainFinding(f);
                  return (
                    <tr key={f.id} onClick={() => setSel(f)} className="border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer" data-testid={`finding-row-${f.id}`}>
                      <td className="px-4 py-3"><Badge color={SEV[f.severity]?.color}>{SEV[f.severity]?.label}</Badge></td>
                      <td className="px-4 py-3 text-white">{b.name}</td>
                      <td className="px-4 py-3 mono text-xs text-sub break-all max-w-[240px]">{whereOf(f)}</td>
                      <td className="px-4 py-3"><Badge color={EXPLOIT[f.exploitability]?.color || "#7A7A7A"}>{EXPLOIT[f.exploitability]?.label || f.exploitability}</Badge></td>
                      <td className="px-4 py-3"><Badge color={STATUS[f.status] || "#7A7A7A"}>{f.status}</Badge></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Modal open={!!sel} onClose={() => setSel(null)} title="Weakness Detail — Client Brief" maxW="max-w-2xl">
        {sel && brief && (
          <div data-testid="finding-brief">
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <Badge color={SEV[sel.severity]?.color}>{SEV[sel.severity]?.label}</Badge>
              <Badge color={EXPLOIT[sel.exploitability]?.color || "#7A7A7A"}>{EXPLOIT[sel.exploitability]?.label || sel.exploitability}</Badge>
              <Badge color={STATUS[sel.status] || "#7A7A7A"}>{sel.status}</Badge>
              {sel.kev && <Badge color="#FF2A2A" dot>CISA KEV</Badge>}
            </div>
            <h3 className="h-font text-xl text-white mb-1">{brief.name}</h3>
            <div className="mono text-xs text-sub mb-4 break-all">at {whereOf(sel)}{sel.technique_ref ? ` · MITRE ${sel.technique_ref}` : ""}{sel.cvss ? ` · CVSS ${sel.cvss}` : ""}</div>

            <BriefBlock icon={Info} color="#00E5FF" title="What it is">{brief.what}</BriefBlock>
            <BriefBlock icon={Warning} color="#FFB020" title="The loophole (why it's exploitable)">{brief.loophole}</BriefBlock>
            <BriefBlock icon={Bug} color="#FF00A0" title="Business impact">{brief.impact}</BriefBlock>

            <div className="mt-4">
              <div className="label mb-1.5 flex items-center gap-1.5"><ShieldCheck size={13} className="text-ok" /> How to fix it</div>
              <div className="text-sm text-sub bg-black border-l-2 border-ok px-3 py-2 leading-relaxed">{brief.fix}
                {brief.fixSource === "guidance" && <span className="block text-[10px] text-muted mono mt-1.5">Standard remediation guidance for this weakness class.</span>}</div>
            </div>

            <div className="mt-4">
              <div className="label mb-1.5">Proof / evidence</div>
              {(sel.evidence_refs || []).length > 0 ? (sel.evidence_refs || []).map((e, i) => (
                <div key={e.invocation_id || `${e.type}-${i}`} className="mono text-[11px] text-sub bg-black border border-line px-3 py-1.5 rounded-sm mb-1 break-all">{e.type}: {e.detail}</div>
              )) : <div className="text-xs text-muted">Confirmed by the engine's verification oracle (no raw artifact attached).</div>}
            </div>

            {((sel.cve_refs || []).length > 0 || sel.reachability_reason || sel.source) && (
              <div className="mt-4 pt-3 border-t border-line/60 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted mono" data-testid="finding-tech-refs">
                {(sel.cve_refs || []).length > 0 && <span>CVE: {(sel.cve_refs || []).join(", ")}</span>}
                {sel.reachability_reason && <span>Reachability: {sel.reachability_reason}</span>}
                {sel.source && <span>Source: {sel.source}</span>}
              </div>
            )}

            {(sel.status === "open" || sel.status === "retest" || sel.status === "remediating" || sel.status === "closed") && (
              <div className="flex justify-end gap-2 mt-5">
                {(sel.status === "open" || sel.status === "retest") && (
                  <Btn variant="dark" icon={Wrench} loading={busy === "rem"}
                    onClick={() => act("rem", () => api.remediate(sel.id), () => "Remediation proposed — re-test to verify")} data-testid="remediate-btn">Propose Remediation</Btn>
                )}
                {(sel.status === "remediating" || sel.status === "retest") && (
                  <Btn variant="success" icon={ArrowsClockwise} loading={busy === "ret"}
                    onClick={() => act("ret", () => api.retest(sel.id), (r) => r.closed ? "Re-test passed — finding closed" : "Still vulnerable")} data-testid="retest-btn">Re-test</Btn>
                )}
                {sel.status === "closed" && <Badge color="#FFFFFF" dot><ShieldCheck size={12} className="inline mr-1" />Remediated &amp; verified</Badge>}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

function BriefBlock({ icon: Icon, color, title, children }) {
  return (
    <div className="mt-4">
      <div className="label mb-1.5 flex items-center gap-1.5"><Icon size={13} style={{ color }} /> {title}</div>
      <div className="text-sm text-sub leading-relaxed">{children}</div>
    </div>
  );
}
