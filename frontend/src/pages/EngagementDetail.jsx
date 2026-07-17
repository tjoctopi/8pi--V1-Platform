import React, { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Info, Certificate, HardDrives, Graph, Terminal, Bug, ShieldWarning, ListDashes, FileText,
  ArrowLeft, Warning, Play, Target,
} from "@phosphor-icons/react";
import { api } from "../lib/api";
import { STATUS } from "../lib/theme";
import { Btn, Badge, Dot, Tabs, Loading, Modal, useToast, errMsg, TextInput } from "../components/ui";

import OverviewTab from "./tabs/OverviewTab";
import RoeTab from "./tabs/RoeTab";
import AssetsTab from "./tabs/AssetsTab";
import ThreatMapTab from "./tabs/ThreatMapTab";
import AttackPathTab from "./tabs/AttackPathTab";
import ConsoleTab from "./tabs/ConsoleTab";
import FindingsTab from "./tabs/FindingsTab";
import VulnTab from "./tabs/VulnTab";
import AuditTab from "./tabs/AuditTab";
import ReportTab from "./tabs/ReportTab";

export default function EngagementDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const toast = useToast();
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("overview");
  const [killOpen, setKillOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const d = await api.engagement(id);
    setData(d);
  }, [id]);

  useEffect(() => {
    load().catch((e) => toast.error(errMsg(e)));
    // eslint-disable-next-line
  }, [id]);

  if (!data) return <Loading label="Loading engagement" />;
  const { engagement: e, roe, counts } = data;

  const doHalt = async () => {
    if (confirm !== "HALT") return toast.error('Type "HALT" to confirm');
    setBusy(true);
    try {
      await api.halt(id, "operator@8pi.internal");
      toast.success("Kill switch engaged — all activity halted");
      setKillOpen(false);
      setConfirm("");
      await load();
    } catch (err) {
      toast.error(errMsg(err));
    } finally {
      setBusy(false);
    }
  };
  const doResume = async () => {
    try {
      await api.resume(id);
      toast.success("Engagement resumed");
      await load();
    } catch (err) {
      toast.error(errMsg(err));
    }
  };

  const TABS = [
    { id: "overview", label: "Overview", icon: Info },
    { id: "roe", label: "RoE", icon: Certificate },
    { id: "assets", label: "Assets", icon: HardDrives, badge: counts.assets },
    { id: "map", label: "Threat Map", icon: Graph },
    { id: "attackpath", label: "Attack Path", icon: Target },
    { id: "console", label: "Console", icon: Terminal, badge: counts.pending_approvals },
    { id: "findings", label: "Findings", icon: Bug, badge: counts.findings },
    { id: "vuln", label: "Vuln Loop", icon: ShieldWarning },
    { id: "audit", label: "Audit", icon: ListDashes },
    { id: "report", label: "Report", icon: FileText },
  ];

  const intensityColor = { exploit: "#FF00A0", "safe-active": "#B4B4B4", recon: "#B4B4B4" }[roe?.max_intensity] || "#7A7A7A";

  return (
    <div className="fadein">
      {/* header */}
      <div className="border-b border-line bg-panel/60 backdrop-blur-xl sticky top-0 z-20">
        <div className="px-6 pt-4">
          <button onClick={() => nav("/")} className="flex items-center gap-1.5 text-xs text-muted hover:text-white transition-colors mb-3" data-testid="back-btn">
            <ArrowLeft size={14} /> Operations
          </button>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <Dot color={STATUS[e.status]} pulse={e.status === "active"} />
                <span className="label" style={{ color: STATUS[e.status] }}>{e.status}</span>
                {roe?.signature ? <Badge color="#FFFFFF" dot>RoE Signed</Badge> : <Badge color="#B4B4B4" dot>RoE Unsigned</Badge>}
                {roe?.max_intensity && <Badge color={intensityColor}>MAX {roe.max_intensity}</Badge>}
                {e.halted && <Badge color="#FF00A0" dot>HALTED</Badge>}
              </div>
              <h1 className="h-font text-3xl sm:text-4xl font-black uppercase tracking-tighter text-white leading-none">{e.name}</h1>
              <div className="text-xs text-muted mono mt-1.5">ENG {e.id.slice(0, 12)} · estate {e.estate?.id || "—"}</div>
            </div>
            <div className="flex items-center gap-2">
              {e.halted ? (
                <Btn variant="success" icon={Play} onClick={doResume} data-testid="resume-btn">Resume</Btn>
              ) : (
                <button
                  onClick={() => setKillOpen(true)}
                  data-testid="kill-switch-btn"
                  className="pulse-danger inline-flex items-center gap-2 px-5 py-2.5 bg-kill hover:bg-red-500 text-white font-bold uppercase tracking-wider text-xs border-2 border-red-300/40 rounded-sm transition-colors active:scale-[0.98]"
                >
                  <Warning size={16} weight="fill" /> Kill Switch
                </button>
              )}
            </div>
          </div>
        </div>
        <div className="px-6 mt-4">
          <Tabs tabs={TABS} active={tab} onChange={setTab} />
        </div>
      </div>

      {/* body */}
      <div className="p-6 max-w-[1500px] mx-auto">
        {tab === "overview" && <OverviewTab eid={id} engagement={e} roe={roe} counts={counts} reload={load} goTab={setTab} />}
        {tab === "roe" && <RoeTab eid={id} engagement={e} roe={roe} reload={load} />}
        {tab === "assets" && <AssetsTab eid={id} />}
        {tab === "map" && <ThreatMapTab eid={id} />}
        {tab === "attackpath" && <AttackPathTab eid={id} />}
        {tab === "console" && <ConsoleTab eid={id} engagement={e} roe={roe} reload={load} />}
        {tab === "findings" && <FindingsTab eid={id} reload={load} />}
        {tab === "vuln" && <VulnTab eid={id} reload={load} />}
        {tab === "audit" && <AuditTab eid={id} />}
        {tab === "report" && <ReportTab eid={id} />}
      </div>

      <Modal open={killOpen} onClose={() => setKillOpen(false)} title="Engage Kill Switch">
        <div className="kill-stripe h-2 mb-4 rounded-sm" />
        <p className="text-sm text-sub mb-2">
          <b className="text-white">SEC-10.</b> This immediately halts all agent & tool activity for this engagement,
          cancels pending approvals, and leaves the estate in a safe state. The action is audited.
        </p>
        <p className="text-xs text-muted mb-4 mono">Type <span className="text-kill">HALT</span> to confirm.</p>
        <TextInput data-testid="kill-confirm-input" value={confirm} onChange={(ev) => setConfirm(ev.target.value)} placeholder="HALT" />
        <div className="flex justify-end gap-2 mt-5">
          <Btn variant="ghost" onClick={() => setKillOpen(false)}>Cancel</Btn>
          <Btn variant="danger" onClick={doHalt} loading={busy} icon={Warning} data-testid="kill-confirm-btn">Halt Engagement</Btn>
        </div>
      </Modal>
    </div>
  );
}
