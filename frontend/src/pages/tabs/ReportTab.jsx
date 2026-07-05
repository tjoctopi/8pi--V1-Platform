import React, { useEffect, useState } from "react";
import { FileText, FileHtml, FilePdf, Code, ShieldCheck } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, KV } from "../../components/ui";

function Stat({ label, value, color = "#fff" }) {
  return (
    <Panel className="p-4">
      <div className="label">{label}</div>
      <div className="h-font text-3xl font-black mt-1.5" style={{ color }}>{value}</div>
    </Panel>
  );
}

export default function ReportTab({ eid }) {
  const [rep, setRep] = useState(null);
  const [showJson, setShowJson] = useState(false);
  useEffect(() => { api.report(eid).then(setRep); }, [eid]);
  if (!rep) return <Loading label="Compiling report" />;

  const s = rep.summary;
  const openBySev = s.findings_open_by_severity || {};

  return (
    <div className="space-y-6">
      <SectionTitle sub="Purple-team deliverable — scope, inventory, risk map, findings, remediation & re-test proof (C-10). Reproducible from the audit log."
        right={
          <div className="flex gap-2">
            <Btn variant="dark" icon={FileHtml} onClick={() => window.open(api.reportHtmlUrl(eid), "_blank")} data-testid="report-html-btn">HTML</Btn>
            <Btn variant="dark" icon={FilePdf} onClick={() => window.open(api.reportPdfUrl(eid), "_blank")} data-testid="report-pdf-btn">PDF</Btn>
            <Btn variant="ghost" icon={Code} onClick={() => setShowJson((v) => !v)} data-testid="report-json-btn">{showJson ? "Hide" : "JSON"}</Btn>
          </div>
        }>
        Engagement Report
      </SectionTitle>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Assets" value={s.assets} />
        <Stat label="Findings" value={s.findings_total} color="#B4B4B4" />
        <Stat label="Closed" value={s.findings_closed} color="#FFFFFF" />
        <Stat label="Agent Runs" value={s.agent_runs} color="#B4B4B4" />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Panel className="p-5">
          <div className="label mb-3">Scope / RoE</div>
          <KV k="Engagement">{rep.engagement.name}</KV>
          <KV k="Status"><Badge color={rep.engagement.status === "active" ? "#FFFFFF" : "#7A7A7A"}>{rep.engagement.status}</Badge></KV>
          <KV k="Max intensity" mono>{rep.roe?.max_intensity}</KV>
          <KV k="Signed by" mono>{rep.roe?.signed_by || "—"}</KV>
        </Panel>
        <Panel className="p-5">
          <div className="label mb-3">Open Findings</div>
          {Object.keys(openBySev).length === 0 ? <div className="text-sm text-muted">No open findings.</div> :
            Object.entries(openBySev).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between py-1.5 border-b border-white/5 last:border-0">
                <Badge color={SEV[k]?.color}>{SEV[k]?.label}</Badge>
                <span className="mono text-white">{v}</span>
              </div>
            ))}
        </Panel>
        <Panel className="p-5">
          <div className="label mb-3">Assurance</div>
          <div className="flex items-center gap-2 mb-2">
            <ShieldCheck size={18} className={s.audit_chain_valid ? "text-white" : "text-crit"} weight="fill" />
            <span className="text-sm text-white">Audit chain {s.audit_chain_valid ? "verified" : "BROKEN"}</span>
          </div>
          <KV k="Audit events" mono>{s.audit_events}</KV>
          <KV k="Generated" mono>{new Date(rep.generated_at).toLocaleString()}</KV>
        </Panel>
      </div>

      <div>
        <SectionTitle>Findings ({rep.findings.length})</SectionTitle>
        <Panel className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-line bg-panel/60">{["Sev", "Finding", "Exploitability", "Status", "Remediation"].map((h) => <th key={h} className="text-left label px-4 py-2.5">{h}</th>)}</tr></thead>
              <tbody>
                {rep.findings.map((f) => (
                  <tr key={f.id} className="border-b border-white/5">
                    <td className="px-4 py-2"><Badge color={SEV[f.severity]?.color}>{SEV[f.severity]?.label}</Badge></td>
                    <td className="px-4 py-2 text-white text-xs">{f.title}</td>
                    <td className="px-4 py-2 text-xs text-sub">{f.exploitability}</td>
                    <td className="px-4 py-2 text-xs text-sub">{f.status}</td>
                    <td className="px-4 py-2 text-xs text-muted max-w-md">{f.remediation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      {showJson && (
        <Panel className="bg-black p-4 overflow-hidden">
          <pre className="mono text-[11px] text-white/80 overflow-auto max-h-[500px]">{JSON.stringify(rep, null, 2)}</pre>
        </Panel>
      )}
    </div>
  );
}
