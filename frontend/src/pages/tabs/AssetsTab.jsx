import React, { useEffect, useState } from "react";
import { HardDrives, Globe, Cpu, Circuitry, Bug, TreeStructure } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { SEV, EXPLOIT, timeAgo } from "../../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, Modal, KV, Spinner, errMsg } from "../../components/ui";

const TYPE_ICON = { host: Circuitry, webapp: Globe, service: Cpu };
const EXP = { external: "#FF00A0", internal: "#B4B4B4", unknown: "#7A7A7A" };

function AssetDetail({ eid, aid }) {
  const [d, setD] = useState(null);
  const [derr, setDerr] = useState(null);
  useEffect(() => { setD(null); setDerr(null); api.assetDetail(eid, aid).then(setD).catch((e) => setDerr(errMsg(e))); }, [eid, aid]);
  if (derr) return <div className="py-10 text-center text-sm text-muted">Couldn't load asset detail: {derr}</div>;
  if (!d) return <div className="py-10 flex justify-center"><Spinner /></div>;
  const a = d.asset || {};
  const ident = a.identifiers || {};
  const dFindings = d.findings || [];
  const dChildren = d.children || [];
  const dInvocations = d.invocations || [];
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <Badge color={EXP[a.exposure]} dot>{a.exposure}</Badge>
        <Badge color="#7A7A7A">{a.type}</Badge>
      </div>
      <KV k="Identifier" mono>{ident.url || ident.host || ident.ip}{ident.port ? `:${ident.port}` : ""}</KV>
      <KV k="First seen" mono>{timeAgo(a.first_seen)}</KV>
      <KV k="Last seen" mono>{timeAgo(a.last_seen)}</KV>

      <div className="mt-4">
        <div className="label mb-1.5">Software / SBOM</div>
        <div className="flex flex-wrap gap-1">
          {(a.versions || []).map((v, i) => <span key={`${v.product}-${v.version}-${i}`} className="mono text-[11px] text-sub bg-black border border-line px-2 py-0.5 rounded-sm">{v.product} {v.version}{v.port ? ` :${v.port}` : ""}</span>)}
          {(a.versions || []).length === 0 && <span className="text-muted text-xs">—</span>}
        </div>
      </div>

      <div className="mt-4">
        <div className="label mb-1.5 flex items-center gap-1.5"><Bug size={13} /> Findings on this asset ({dFindings.length})</div>
        <div className="space-y-1.5">
          {dFindings.map((f) => (
            <div key={f.id} className="flex items-center gap-2 bg-black border border-line px-3 py-2 rounded-sm">
              <Badge color={SEV[f.severity]?.color}>{SEV[f.severity]?.label}</Badge>
              <span className="text-xs text-white flex-1 truncate">{f.title}</span>
              <Badge color={EXPLOIT[f.exploitability]?.color}>{EXPLOIT[f.exploitability]?.label}</Badge>
            </div>
          ))}
          {dFindings.length === 0 && <div className="text-xs text-muted">No findings on this asset.</div>}
        </div>
      </div>

      {(d.parent || dChildren.length > 0) && (
        <div className="mt-4">
          <div className="label mb-1.5 flex items-center gap-1.5"><TreeStructure size={13} /> Relationships</div>
          {d.parent && <div className="text-xs text-sub mono">↑ host: {d.parent.identifiers?.host || d.parent.identifiers?.ip || d.parent.identifiers?.url}</div>}
          {dChildren.map((c) => <div key={c.id} className="text-xs text-muted mono">↳ {c.identifiers?.service} :{c.identifiers?.port} ({(c.versions?.[0]?.product) || ""})</div>)}
        </div>
      )}

      {dInvocations.length > 0 && (
        <div className="mt-4">
          <div className="label mb-1.5">Tool activity</div>
          {dInvocations.slice(0, 6).map((iv) => (
            <div key={iv.id} className="flex items-center justify-between text-xs mono text-muted py-1 border-b border-white/5 last:border-0">
              <span className="text-sub">{iv.tool_id}</span><span>{iv.status}</span><span>{timeAgo(iv.started_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AssetsTab({ eid }) {
  const [assets, setAssets] = useState(null);
  const [err, setErr] = useState(null);
  const [filter, setFilter] = useState("all");
  const [sel, setSel] = useState(null);
  const loadAssets = React.useCallback(() => { setErr(null); api.assets(eid).then(setAssets).catch((e) => setErr(errMsg(e))); }, [eid]);
  useEffect(() => { loadAssets(); }, [loadAssets]);
  if (err) return <Empty icon={HardDrives} title="Couldn't load assets" hint={err} action={<Btn variant="ghost" onClick={loadAssets} data-testid="assets-retry">Retry</Btn>} />;
  if (!assets) return <Loading label="Loading asset graph" />;
  if (assets.length === 0) return <Empty icon={HardDrives} title="No assets discovered" hint="Run Sensing from the Console to populate the asset graph (C-01)." />;

  const types = ["all", ...Array.from(new Set(assets.map((a) => a.type)))];
  const shown = filter === "all" ? assets : assets.filter((a) => a.type === filter);

  return (
    <div>
      <SectionTitle sub={`${assets.length} assets · click a row to drill in — SBOM, findings & relationships.`}
        right={
          <div className="flex gap-1">
            {types.map((t) => (
              <button key={t} onClick={() => setFilter(t)} data-testid={`asset-filter-${t}`}
                className={`px-3 py-1.5 text-[11px] uppercase tracking-wider border rounded-sm transition-colors ${filter === t ? "border-volt bg-volt/10 text-white" : "border-line text-muted hover:text-sub"}`}>
                {t}
              </button>
            ))}
          </div>
        }>
        Asset Inventory
      </SectionTitle>

      <Panel className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line bg-panel/60">
                {["Type", "Identifier", "Exposure", "Software / Versions", "Last Seen"].map((h) => (
                  <th key={h} className="text-left label px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => {
                const Icon = TYPE_ICON[a.type] || HardDrives;
                const ident = a.identifiers?.url || a.identifiers?.host || a.identifiers?.ip || "—";
                return (
                  <tr key={a.id} onClick={() => setSel(a.id)} className="border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer" data-testid={`asset-row-${a.id}`}>
                    <td className="px-4 py-3"><div className="flex items-center gap-2"><Icon size={16} className="text-volt" /><span className="text-xs uppercase tracking-wider text-sub">{a.type}</span></div></td>
                    <td className="px-4 py-3 mono text-white text-xs break-all">
                      {ident}{a.identifiers?.port ? <span className="text-muted">:{a.identifiers.port}</span> : null}
                    </td>
                    <td className="px-4 py-3"><Badge color={EXP[a.exposure] || "#7A7A7A"} dot>{a.exposure}</Badge></td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(a.versions || []).slice(0, 4).map((v, i) => (
                          <span key={`${v.product}-${v.version}-${i}`} className="mono text-[11px] text-sub bg-black border border-line px-2 py-0.5 rounded-sm">{v.product} {v.version}</span>
                        ))}
                        {(a.versions || []).length === 0 && <span className="text-muted text-xs">—</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 mono text-xs text-muted">{timeAgo(a.last_seen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <Modal open={!!sel} onClose={() => setSel(null)} title="Asset Detail" maxW="max-w-2xl">
        {sel && <AssetDetail eid={eid} aid={sel} />}
      </Modal>
    </div>
  );
}
