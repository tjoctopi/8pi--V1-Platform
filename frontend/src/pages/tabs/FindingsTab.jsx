import React, { useEffect, useState, useCallback } from "react";
import { Bug, Wrench, ArrowsClockwise, ShieldCheck } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV, EXPLOIT, STATUS, timeAgo } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, Modal, KV, useToast, errMsg } from "../../components/ui";

export default function FindingsTab({ eid, reload }) {
  const toast = useToast();
  const [findings, setFindings] = useState(null);
  const [err, setErr] = useState(null);
  const [sev, setSev] = useState("all");
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
  if (findings.length === 0) return <Empty icon={Bug} title="No findings" hint="Run a Vuln Scan and agents from the Console to generate findings." />;

  const sevs = ["all", "crit", "high", "med", "low"];
  const shown = sev === "all" ? findings : findings.filter((f) => f.severity === sev);

  return (
    <div>
      <SectionTitle sub={`${findings.length} findings · severity, exploitability, evidence & remediation.`}
        right={
          <div className="flex gap-1">
            {sevs.map((s) => (
              <button key={s} onClick={() => setSev(s)} data-testid={`finding-filter-${s}`}
                className={`px-3 py-1.5 text-[11px] uppercase tracking-wider border rounded-sm transition-colors ${sev === s ? "border-volt bg-volt/10 text-white" : "border-line text-muted hover:text-sub"}`}>{s}</button>
            ))}
          </div>
        }>
        Findings
      </SectionTitle>

      <Panel className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-line bg-panel/60">{["Sev", "Finding", "Exploitability", "Status", "CVE", "When"].map((h) => <th key={h} className="text-left label px-4 py-3">{h}</th>)}</tr></thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id} onClick={() => setSel(f)} className="border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer" data-testid={`finding-row-${f.id}`}>
                  <td className="px-4 py-3"><Badge color={SEV[f.severity]?.color}>{SEV[f.severity]?.label}</Badge></td>
                  <td className="px-4 py-3 text-white">{f.title}</td>
                  <td className="px-4 py-3"><Badge color={EXPLOIT[f.exploitability]?.color || "#7A7A7A"}>{EXPLOIT[f.exploitability]?.label || f.exploitability}</Badge></td>
                  <td className="px-4 py-3"><Badge color={STATUS[f.status] || "#7A7A7A"}>{f.status}</Badge></td>
                  <td className="px-4 py-3 mono text-xs text-sub">{(f.cve_refs || []).join(", ") || "—"}</td>
                  <td className="px-4 py-3 mono text-[11px] text-muted">{timeAgo(f.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Modal open={!!sel} onClose={() => setSel(null)} title="Finding Detail" maxW="max-w-2xl">
        {sel && (
          <div>
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <Badge color={SEV[sel.severity]?.color}>{SEV[sel.severity]?.label}</Badge>
              <Badge color={EXPLOIT[sel.exploitability]?.color || "#7A7A7A"}>{EXPLOIT[sel.exploitability]?.label || sel.exploitability}</Badge>
              <Badge color={STATUS[sel.status] || "#7A7A7A"}>{sel.status}</Badge>
              {sel.kev && <Badge color="#FF2A2A" dot>CISA KEV</Badge>}
            </div>
            <h3 className="h-font text-xl text-white mb-3">{sel.title}</h3>
            <KV k="CVSS" mono>{sel.cvss ?? "—"}</KV>
            <KV k="CVE" mono>{(sel.cve_refs || []).join(", ") || "—"}</KV>
            <KV k="Technique" mono>{sel.technique_ref || "—"}</KV>
            <KV k="Reachability">{sel.reachability_reason || "—"}</KV>
            <KV k="Source" mono>{sel.source}</KV>
            <div className="mt-4">
              <div className="label mb-1.5">Evidence</div>
              {(sel.evidence_refs || []).map((e, i) => (
                <div key={e.invocation_id || `${e.type}-${i}`} className="mono text-xs text-sub bg-black border border-line px-3 py-1.5 rounded-sm mb-1">{e.type}: {e.detail}</div>
              ))}
              {(sel.evidence_refs || []).length === 0 && <div className="text-xs text-muted">—</div>}
            </div>
            <div className="mt-4">
              <div className="label mb-1.5">Remediation</div>
              <div className="text-sm text-sub bg-black border-l-2 border-ok px-3 py-2">{sel.remediation || "—"}</div>
            </div>
            {sel.patched_version && (
              <div className="flex justify-end gap-2 mt-5">
                {(sel.status === "open" || sel.status === "retest") && (
                  <Btn variant="dark" icon={Wrench} loading={busy === "rem"}
                    onClick={() => act("rem", () => api.remediate(sel.id), () => "Remediation applied — re-test to verify")} data-testid="remediate-btn">Apply Remediation</Btn>
                )}
                {(sel.status === "remediating" || sel.status === "retest") && (
                  <Btn variant="success" icon={ArrowsClockwise} loading={busy === "ret"}
                    onClick={() => act("ret", () => api.retest(sel.id), (r) => r.closed ? "Re-test passed — finding closed" : "Still vulnerable")} data-testid="retest-btn">Re-test</Btn>
                )}
                {sel.status === "closed" && <Badge color="#FFFFFF" dot><ShieldCheck size={12} className="inline mr-1" />Remediated & verified</Badge>}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
