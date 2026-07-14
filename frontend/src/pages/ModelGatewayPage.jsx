import React, { useEffect, useState } from "react";
import { Cpu, CloudArrowUp, HardDrive, Prohibit, PaperPlaneTilt, LockKey } from "@phosphor-icons/react";
import { api } from "../lib/api";
import { timeAgo } from "../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Field, Select, Textarea, PreviewNotice, useToast, errMsg } from "../components/ui";

const KIND_ICON = { hosted: CloudArrowUp, local: HardDrive, stub: Prohibit };
const KIND_COLOR = { hosted: "#B4B4B4", local: "#FFFFFF", stub: "#7A7A7A" };

function RouteCard({ r }) {
  const Icon = KIND_ICON[r.kind] || Cpu;
  return (
    <Panel className="p-5" data-testid={`route-${r.id}`}>
      <div className="flex items-start justify-between mb-2">
        <Icon size={22} style={{ color: KIND_COLOR[r.kind] }} weight="bold" />
        <Badge color={r.status === "live" ? "#FFFFFF" : "#7A7A7A"} dot>{r.status.replace("_", " ")}</Badge>
      </div>
      <div className="h-font text-lg text-white">{r.id}</div>
      <div className="mono text-xs text-volt mt-0.5">{r.model}</div>
      <p className="text-xs text-muted mt-2 leading-relaxed">{r.description}</p>
      <div className="flex items-center justify-between mt-3 pt-3 border-t border-white/5 text-xs">
        <span className="flex items-center gap-1.5 text-sub">
          {r.boundary === "external" ? <CloudArrowUp size={13} /> : <LockKey size={13} className="text-white" />}
          {r.boundary}
        </span>
        <span className="mono text-muted">${r.cost_per_1k}/1k</span>
      </div>
    </Panel>
  );
}

export default function ModelGatewayPage() {
  const toast = useToast();
  const [routes, setRoutes] = useState(null);
  const [calls, setCalls] = useState([]);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState(null);
  const [form, setForm] = useState({
    purpose: "analyst-query", task_class: "reason", sensitivity: "internal", route: "",
    message: "Summarize the risk of an internet-facing Apache httpd 2.4.49 host.",
  });

  const load = async () => {
    const [r, c] = await Promise.all([api.modelRoutes(), api.modelCalls()]);
    setRoutes(r);
    setCalls(c);
  };
  useEffect(() => { load().catch((e) => toast.error(errMsg(e))); }, []); // eslint-disable-line

  const run = async () => {
    setBusy(true);
    setRes(null);
    try {
      const out = await api.modelInfer({
        purpose: form.purpose, task_class: form.task_class, sensitivity: form.sensitivity,
        route: form.route || undefined,
        messages: [{ role: "user", content: form.message }],
        max_tokens: 400,
      });
      setRes(out);
      toast.success(`Routed to ${out.route}`);
      await load();
    } catch (e) { toast.error(errMsg(e)); setRes({ error: errMsg(e) }); } finally { setBusy(false); }
  };

  if (!routes) return <Loading label="Loading model gateway" />;

  return (
    <div className="p-6 max-w-[1500px] mx-auto fadein">
      <SectionTitle sub="BYOM — every model call flows through this single seam (IF-MODEL). Provider-agnostic routing by sensitivity, task class & cost.">
        Model Gateway
      </SectionTitle>

      <div className="grid md:grid-cols-3 gap-4 mb-8">
        {routes.map((r) => <RouteCard key={r.id} r={r} />)}
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <Panel className="p-6">
          <SectionTitle sub="Sensitive/airgapped traffic is pinned to local — never a hosted provider (SEC-05).">Test Inference</SectionTitle>
          <PreviewNotice className="mb-4">
            The interactive inference playground isn't wired to the engine yet — this data is not
            available in this build. The routes above are live from the real gateway.
          </PreviewNotice>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Task Class">
              <Select value={form.task_class} onChange={(e) => setForm({ ...form, task_class: e.target.value })} data-testid="mg-taskclass">
                {["reason", "triage", "summarize", "convert", "evaluate", "embed"].map((t) => <option key={t}>{t}</option>)}
              </Select>
            </Field>
            <Field label="Sensitivity">
              <Select value={form.sensitivity} onChange={(e) => setForm({ ...form, sensitivity: e.target.value })} data-testid="mg-sensitivity">
                {["public", "internal", "sensitive", "airgapped"].map((t) => <option key={t}>{t}</option>)}
              </Select>
            </Field>
          </div>
          <div className="mt-4">
            <Field label="Route Override" hint="Leave as policy-routed, or force a route. openmythos-7b returns 501 (C-11 hook).">
              <Select value={form.route} onChange={(e) => setForm({ ...form, route: e.target.value })} data-testid="mg-route">
                <option value="">policy-routed</option>
                {routes.map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
              </Select>
            </Field>
          </div>
          <div className="mt-4">
            <Field label="Message"><Textarea value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} data-testid="mg-message" /></Field>
          </div>
          {(form.sensitivity === "sensitive" || form.sensitivity === "airgapped") && (
            <div className="mt-3 text-[11px] text-white mono flex items-center gap-1.5"><LockKey size={13} /> SEC-05: this will route to local-openweight only.</div>
          )}
          <div className="flex justify-end mt-4">
            <Btn icon={PaperPlaneTilt} onClick={run} loading={busy} data-testid="mg-infer-btn">Run Inference</Btn>
          </div>

          {res && (
            <div className="mt-5 fadein">
              {res.error ? (
                <div className="bg-black border-l-2 border-crit p-3 text-sm text-crit">{res.error}</div>
              ) : (
                <div>
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <Badge color={res.route.includes("hosted") ? "#B4B4B4" : "#FFFFFF"} dot>{res.route}</Badge>
                    {res.redaction_applied && <Badge color="#B4B4B4">redacted</Badge>}
                    <span className="mono text-[11px] text-muted">{res.usage.token_in}→{res.usage.token_out} tok · {res.usage.latency_ms}ms · ${res.usage.cost}</span>
                  </div>
                  <div className="bg-black border border-line p-3 text-sm text-sub whitespace-pre-wrap max-h-64 overflow-auto">{res.text}</div>
                </div>
              )}
            </div>
          )}
        </Panel>

        <div>
          <SectionTitle right={<Badge color="#7A7A7A">{calls.length}</Badge>}>Recent Model Calls (DM-08)</SectionTitle>
          <Panel className="overflow-hidden">
            <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-panel/90 backdrop-blur">
                  <tr className="border-b border-line">{["Route", "Purpose", "Sens.", "Cost", "When"].map((h) => <th key={h} className="text-left label px-4 py-2.5">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {calls.map((c) => (
                    <tr key={c.id} className="border-b border-white/5">
                      <td className="px-4 py-2"><Badge color={c.route.includes("hosted") ? "#B4B4B4" : "#FFFFFF"}>{c.route}</Badge></td>
                      <td className="px-4 py-2 mono text-xs text-sub">{c.purpose}</td>
                      <td className="px-4 py-2 mono text-[11px]" style={{ color: ["sensitive", "airgapped"].includes(c.sensitivity) ? "#FFFFFF" : "#7A7A7A" }}>{c.sensitivity}</td>
                      <td className="px-4 py-2 mono text-xs text-muted">${c.cost}</td>
                      <td className="px-4 py-2 mono text-[11px] text-muted">{timeAgo(c.ts)}</td>
                    </tr>
                  ))}
                  {calls.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-muted text-sm">No model calls yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
