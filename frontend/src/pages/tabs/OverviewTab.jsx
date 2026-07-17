import React from "react";
import { HardDrives, Bug, StackSimple, Robot, Cpu, ArrowRight, ShieldCheck } from "@phosphor-icons/react";
import { Panel, KV, Badge, SectionTitle } from "../../components/ui";
import { INTENSITY, timeAgo } from "../../lib/theme";

export default function OverviewTab({ engagement: e, roe, counts, goTab }) {
  const metrics = [
    { icon: HardDrives, label: "Assets", value: counts.assets, tab: "assets" },
    { icon: Bug, label: "Findings", value: counts.findings, tab: "findings" },
    { icon: StackSimple, label: "Tool Runs", value: counts.invocations, tab: "console" },
    { icon: Robot, label: "Agent Runs", value: counts.agent_runs, tab: "console" },
    { icon: Cpu, label: "Model Calls", value: counts.model_calls, tab: "console" },
  ];
  return (
    <div className="grid lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2 space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          {metrics.map((m) => (
            <Panel key={m.label} className="p-4 hover:border-white/25 transition-colors cursor-pointer" onClick={() => goTab(m.tab)}>
              <m.icon size={18} className="text-volt" weight="bold" />
              <div className="h-font text-3xl font-black text-white mt-2 leading-none">{m.value ?? 0}</div>
              <div className="label mt-1">{m.label}</div>
            </Panel>
          ))}
        </div>

        <Panel className="p-6">
          <SectionTitle sub="Foundation → Minimum Lovable Platform workflow.">Engagement Pipeline</SectionTitle>
          <div className="space-y-3">
            {[
              ["1", "Sign Rules of Engagement", "Bind a signed, in-window RoE (SEC-01).", "roe"],
              ["2", "Sensing & Inventory", "Discover in-scope assets → asset graph (C-01).", "assets"],
              ["3", "Threat Map", "Living risk map ranked by exploitable exposure (C-08).", "map"],
              ["4", "Vuln & Patch Loop", "CVE/KEV correlation → exploitable flag → re-test (C-09).", "vuln"],
              ["5", "Offensive & Defensive Agents", "Scoped attack chain + detection, approval-gated (C-05/06).", "console"],
              ["6", "Report", "Offensive engagement deliverable, reproducible from audit (C-10).", "report"],
            ].map(([n, title, sub, tab]) => (
              <button key={n} onClick={() => goTab(tab)}
                className="w-full flex items-center gap-4 p-3 border border-line hover:border-volt/50 hover:bg-volt/5 transition-colors text-left group">
                <span className="h-font text-lg font-black text-volt w-6">{n}</span>
                <div className="flex-1">
                  <div className="text-sm font-semibold text-white">{title}</div>
                  <div className="text-xs text-muted">{sub}</div>
                </div>
                <ArrowRight size={16} className="text-muted group-hover:text-volt transition-colors" />
              </button>
            ))}
          </div>
        </Panel>
      </div>

      <div className="space-y-6">
        <Panel className="p-5">
          <SectionTitle>RoE Snapshot</SectionTitle>
          <KV k="Status">{roe?.signature ? <Badge color="#FFFFFF">Signed</Badge> : <Badge color="#B4B4B4">Draft</Badge>}</KV>
          <KV k="Max Intensity">
            <Badge color={INTENSITY[roe?.max_intensity]?.color || "#7A7A7A"}>{roe?.max_intensity || "—"}</Badge>
          </KV>
          <KV k="Signed by" mono>{roe?.signed_by || "—"}</KV>
          <KV k="Window ends" mono>{roe?.window_end ? new Date(roe.window_end).toLocaleDateString() : "—"}</KV>
          <KV k="Allowed tools" mono>{(roe?.allowed_tools || []).join(", ") || "—"}</KV>
          <KV k="Scope entries" mono>{(roe?.scope_allowlist || []).length} allow / {(roe?.scope_denylist || []).length} deny</KV>
        </Panel>

        <Panel className="p-5">
          <div className="flex items-center gap-2 mb-3">
            <ShieldCheck size={18} className="text-white" weight="fill" />
            <span className="h-font text-lg uppercase tracking-tight text-white">Estate Seeds</span>
          </div>
          <div className="space-y-1.5">
            {(e.estate?.seeds || []).map((s) => (
              <div key={s} className="mono text-xs text-sub bg-black border border-line px-3 py-1.5 rounded-sm">{s}</div>
            ))}
          </div>
          <div className="text-[11px] text-muted mt-3">created {timeAgo(e.created_at)}</div>
        </Panel>
      </div>
    </div>
  );
}
