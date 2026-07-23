import React, { useEffect, useState, useCallback } from "react";
import { ShieldWarning, Wrench, ArrowsClockwise, ArrowClockwise } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV, EXPLOIT, STATUS } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, useToast, errMsg } from "../../components/ui";

function Stat({ label, value, color = "#fff" }) {
  return (
    <Panel className="p-4">
      <div className="label">{label}</div>
      <div className="h-font text-3xl font-black mt-1.5" style={{ color }}>{value}</div>
    </Panel>
  );
}

const LOOP = ["open", "remediating", "retest", "closed"];

export default function VulnTab({ eid, reload }) {
  const toast = useToast();
  const [findings, setFindings] = useState(null);
  const [cves, setCves] = useState([]);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      setErr(null);
      const [f, c] = await Promise.all([api.findings(eid), api.cveCache()]);
      setFindings(f);
      setCves(c);
    } catch (e) { setErr(errMsg(e)); }
  }, [eid]);
  useEffect(() => { load(); }, [load]);

  const act = async (key, fn, msg) => {
    setBusy(key);
    try { const r = await fn(); toast.success(msg(r)); await load(); await reload(); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(""); }
  };

  if (err) return <Empty icon={ShieldWarning} title="Couldn't load vulnerability loop" hint={err} action={<Btn variant="ghost" onClick={load} data-testid="vuln-retry">Retry</Btn>} />;
  if (!findings) return <Loading label="Loading vulnerability loop" />;

  const vulns = findings.filter((f) => f.source === "vuln-loop");
  const reachable = vulns.filter((f) => ["reachable", "confirmed"].includes(f.exploitability) && f.status !== "closed");
  const closed = vulns.filter((f) => f.status === "closed").length;

  return (
    <div className="space-y-6">
      <SectionTitle sub="Version tracking → CVE/KEV correlation → exploitable-by-reachability → remediate → re-test (C-09).">
        Vulnerability &amp; Patch Loop
      </SectionTitle>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Correlated Vulns" value={vulns.length} />
        <Stat label="Exploitable / Reachable" value={reachable.length} color="#B4B4B4" />
        <Stat label="Confirmed" value={vulns.filter((f) => f.exploitability === "confirmed").length} color="#FF2A2A" />
        <Stat label="Closed (re-tested)" value={closed} color="#FFFFFF" />
      </div>

      {vulns.length === 0 ? (
        <Empty icon={ShieldWarning} title="No correlated vulnerabilities" hint="Run a Vuln Scan from the Console to correlate SBOM versions against the CVE/KEV feed." />
      ) : (
        <div>
          <SectionTitle sub="Prioritized by exploitable exposure — not raw CVSS.">Exploitable Exposure</SectionTitle>
          <div className="space-y-3">
            {[...reachable, ...vulns.filter((f) => !reachable.includes(f) && f.status !== "closed")].map((f) => (
              <Panel key={f.id} className="p-4" data-testid={`vuln-${f.id}`}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <Badge color={SEV[f.severity]?.color}>{SEV[f.severity]?.label}</Badge>
                      <Badge color={EXPLOIT[f.exploitability]?.color}>{EXPLOIT[f.exploitability]?.label}</Badge>
                      {f.kev && <Badge color="#FF00A0" dot>KEV</Badge>}
                      <span className="mono text-sm text-white">{f.title}</span>
                    </div>
                    <div className="text-xs text-muted">Reachability: {f.reachability_reason}</div>
                    <div className="text-xs text-sub mt-1">{f.remediation}</div>
                    {/* loop progress */}
                    <div className="flex items-center gap-1 mt-2">
                      {LOOP.map((st, i) => {
                        const activeIdx = LOOP.indexOf(f.status === "false-positive" ? "closed" : f.status);
                        const done = i <= (activeIdx < 0 ? 0 : activeIdx);
                        return (
                          <React.Fragment key={st}>
                            <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded-sm ${done ? "text-white" : "text-muted"}`}
                              style={{ background: done ? (STATUS[st] + "33") : "transparent", color: done ? STATUS[st] : undefined }}>{st}</span>
                            {i < LOOP.length - 1 && <span className="text-muted text-[10px]">→</span>}
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {(f.status === "open" || f.status === "retest") && (
                      <Btn variant="dark" icon={Wrench} loading={busy === "r" + f.id}
                        onClick={() => act("r" + f.id, () => api.remediate(f.id), () => "Patch applied — re-test to verify")}
                        data-testid={`vuln-remediate-${f.id}`}>Remediate</Btn>
                    )}
                    {(f.status === "remediating" || f.status === "retest") && (
                      <Btn variant="success" icon={ArrowsClockwise} loading={busy === "t" + f.id}
                        onClick={() => act("t" + f.id, () => api.retest(f.id), (r) => r.closed ? "Re-test passed — closed with proof" : "Still vulnerable")}
                        data-testid={`vuln-retest-${f.id}`}>Re-test</Btn>
                    )}
                  </div>
                </div>
              </Panel>
            ))}
          </div>
        </div>
      )}

      <div>
        <SectionTitle sub="Local operational cache (DM-09). Live-feed use only — not model-training data (FR-VULN-07)."
          right={<Btn variant="ghost" icon={ArrowClockwise} onClick={() => act("cve", () => api.refreshCve(eid), () => "CVE cache refreshed")} loading={busy === "cve"} data-testid="refresh-cve-btn">Refresh Feed</Btn>}>
          CVE / KEV Feed
        </SectionTitle>
        <Panel className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-line bg-panel/60">{["CVE", "Product", "CVSS", "KEV", "Exploit", "Summary"].map((h) => <th key={h} className="text-left label px-4 py-2.5">{h}</th>)}</tr></thead>
              <tbody>
                {cves.map((c) => (
                  <tr key={c.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="px-4 py-2 mono text-xs text-volt">{c.cve_id}</td>
                    <td className="px-4 py-2 mono text-xs text-sub">{c.product} {c.versions?.join("/")}</td>
                    <td className="px-4 py-2 mono text-xs" style={{ color: SEV[c.cvss >= 9 ? "crit" : c.cvss >= 7 ? "high" : "med"].color }}>{c.cvss}</td>
                    <td className="px-4 py-2">{c.kev ? <Badge color="#FF00A0">KEV</Badge> : <span className="text-muted text-xs">—</span>}</td>
                    <td className="px-4 py-2">{c.exploit_known ? <Badge color="#B4B4B4">public</Badge> : <span className="text-muted text-xs">—</span>}</td>
                    <td className="px-4 py-2 text-xs text-muted max-w-sm">{c.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
