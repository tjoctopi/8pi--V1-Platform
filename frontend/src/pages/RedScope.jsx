/* eslint-disable react-hooks/exhaustive-deps -- intentional effect deps; preserved behavior */
import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Eye, WarningOctagon, Bug, Gavel, ArrowClockwise, PaperPlaneRight, Robot,
  FloppyDisk, Crosshair, Skull, Plus, X,
} from "@phosphor-icons/react";
import { api } from "../lib/api";
import {
  Panel, Btn, Badge, Loading, TextInput, Select, PreviewNotice, useToast, errMsg, IncidentText, Spinner,
} from "../components/ui";

const ALL_TOOLS = ["nmap", "nikto", "dirbust", "wpscan", "sqlmap"];

function IncidentStat({ icon: Icon, label, value }) {
  const hot = value > 0;
  return (
    <Panel className="p-4" data-testid={`redscope-stat-${label.toLowerCase().replace(/\s/g, "-")}`}
      style={hot ? { borderColor: "#FF2A2A", boxShadow: "0 0 12px rgba(255,42,42,0.25)" } : undefined}>
      <div className="flex items-center justify-between">
        <div className="label">{label}</div>
        <Icon size={17} style={{ color: hot ? "#FF2A2A" : "#7A7A7A" }} weight="bold" />
      </div>
      <div className="mt-2 h-font text-4xl font-black leading-none"
        style={{ color: hot ? "#FF2A2A" : "#4A4A4A", textShadow: hot ? "0 0 8px #FF2A2A" : undefined }}>
        {value}
      </div>
    </Panel>
  );
}

function FeedGroup({ icon: Icon, title, count, children }) {
  return (
    <Panel className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <Icon size={16} style={{ color: count > 0 ? "#FF2A2A" : "#7A7A7A" }} weight="fill" />
        <span className="label" style={{ color: count > 0 ? "#FF2A2A" : "#7A7A7A" }}>{title}</span>
        <span className="ml-auto mono text-xs" style={{ color: count > 0 ? "#FF2A2A" : "#4A4A4A" }}>{count}</span>
      </div>
      {count === 0 ? <div className="text-xs text-muted mono">clear</div> : <div className="space-y-2">{children}</div>}
    </Panel>
  );
}

function FeedItem({ testid, onOpen, onAdd, borderCls, children }) {
  return (
    <div data-testid={testid}
      className={`w-full bg-black border ${borderCls} px-3 py-2 flex items-start gap-2 transition-colors`}>
      <button onClick={onOpen} className="flex-1 text-left min-w-0">{children}</button>
      <button onClick={onAdd} title="Attach to copilot as target" data-testid={`${testid}-add`}
        className="shrink-0 mt-0.5 w-6 h-6 flex items-center justify-center border border-line text-muted hover:text-volt hover:border-volt transition-colors">
        <Plus size={13} weight="bold" />
      </button>
    </div>
  );
}

function DraftEditor({ draft, setDraft, onSave, saving }) {
  const toggle = (t) =>
    setDraft((d) => ({ ...d, tools: d.tools.includes(t) ? d.tools.filter((x) => x !== t) : [...d.tools, t] }));
  return (
    <div className="border border-incident/60 bg-incident/[0.04] p-4 mt-3" data-testid="red-scope-draft"
      style={{ boxShadow: "inset 0 0 16px rgba(255,42,42,0.12)" }}>
      <div className="flex items-center gap-2 mb-3">
        <Skull size={16} className="text-incident" weight="fill" />
        <span className="label text-incident">Proposed Agent</span>
        <Badge color="#7A7A7A" className="ml-auto">will save as · dev</Badge>
      </div>
      <div className="space-y-3">
        <div>
          <div className="label mb-1">Name</div>
          <TextInput data-testid="red-scope-draft-name" value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="label mb-1">Role</div>
            <Select value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value })} data-testid="red-scope-draft-role">
              <option value="offensive">offensive</option>
              <option value="defensive">defensive</option>
              <option value="recon">recon</option>
            </Select>
          </div>
          <div>
            <div className="label mb-1">Max Intensity</div>
            <Select value={draft.max_intensity} onChange={(e) => setDraft({ ...draft, max_intensity: e.target.value })} data-testid="red-scope-draft-intensity">
              <option value="recon">recon</option>
              <option value="safe-active">safe-active</option>
              <option value="exploit">exploit</option>
            </Select>
          </div>
        </div>
        <div>
          <div className="label mb-2">Tools</div>
          <div className="grid grid-cols-3 gap-2">
            {ALL_TOOLS.map((t) => (
              <button key={t} onClick={() => toggle(t)}
                className={`px-2 py-1.5 border text-xs mono transition-colors ${draft.tools.includes(t) ? "border-volt bg-volt/10 text-white" : "border-line text-sub hover:border-white/25"}`}>
                {t}
              </button>
            ))}
          </div>
        </div>
        {(draft.target || draft.technique) && (
          <div className="grid grid-cols-2 gap-3">
            {draft.target && <div><div className="label mb-1">Target</div><div className="mono text-xs text-sub break-all">{draft.target}</div></div>}
            {draft.technique && <div><div className="label mb-1">Technique</div><div className="mono text-xs text-sub break-all">{draft.technique}</div></div>}
          </div>
        )}
        {draft.rationale && (
          <div><div className="label mb-1">Rationale</div><div className="text-xs text-sub leading-relaxed">{draft.rationale}</div></div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Btn variant="ghost" onClick={() => setDraft(null)} data-testid="red-scope-draft-discard">Discard</Btn>
          <Btn icon={FloppyDisk} loading={saving} onClick={onSave} data-testid="red-scope-save-agent">Save to Registry</Btn>
        </div>
      </div>
    </div>
  );
}

const STARTERS = [
  "Recon the perimeter of app.example.com and map exposed services.",
  "Design an offensive chain to test SQL injection on the login portal.",
  "Build a safe-active web content-discovery agent for the staging host.",
];

export default function RedScope() {
  const nav = useNavigate();
  const toast = useToast();
  const [feed, setFeed] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);
  const [selected, setSelected] = useState([]);
  const scrollRef = useRef(null);
  const newMsg = (role, content) => ({ id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, role, content });

  const loadFeed = async () => {
    try { setFeed(await api.redScope()); } catch (e) { toast.error(errMsg(e)); }
  };
  useEffect(() => { loadFeed(); /* eslint-disable-next-line */ }, []);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, sending]);

  const addCtx = (item) => {
    setSelected((s) => (s.some((x) => x.key === item.key) ? s : [...s, item]));
    toast.success("Attached to copilot");
  };
  const removeCtx = (key) => setSelected((s) => s.filter((x) => x.key !== key));
  const addFinding = (f) => addCtx({ key: `f-${f.id}`, kind: "finding", label: f.title, detail: `severity=${f.severity}; exploitability=${f.exploitability || "n/a"}; target=${f.target || "unknown"}; engagement=${f.engagement_name || "?"}` });
  const addEngagement = (e) => addCtx({ key: `e-${e.id}`, kind: "engagement", label: e.name, detail: `status=${e.status}; HALTED (kill switch active)` });
  const addApproval = (a) => addCtx({ key: `a-${a.id}`, kind: "approval", label: `${a.action?.tool_id} → ${a.action?.target}`, detail: `pending exploit-intensity approval; engagement=${a.engagement_name || "?"}` });

  const send = async (text) => {
    const msg = (text ?? input).trim();
    const ctx = selected;
    if ((!msg && ctx.length === 0) || sending) return;
    const display = msg || `▶ Design an attack / pen-test agent for ${ctx.length} attached target(s)`;
    const next = [...messages, newMsg("user", display)];
    setMessages(next);
    setInput("");
    setSending(true);
    try {
      const res = await api.redScopeChat({ message: msg, history: messages, context: ctx });
      setMessages([...next, newMsg("assistant", res.reply || "(no response)")]);
      if (res.draft) setDraft(res.draft);
    } catch (e) {
      toast.error(errMsg(e));
      setMessages(next);
    } finally {
      setSending(false);
    }
  };

  const saveDraft = async () => {
    if (!draft?.name?.trim()) return toast.error("Agent name required");
    setSaving(true);
    try {
      const agent = await api.redScopeSaveAgent(draft);
      toast.success(`"${agent.name}" saved to registry (dev state)`);
      setDraft(null);
      setMessages((m) => [...m, newMsg("assistant", `✓ Agent "${agent.name}" saved to the registry. Promote it via the Agent Registry to run against an authorized estate.`)]);
    } catch (e) { toast.error(errMsg(e)); } finally { setSaving(false); }
  };

  if (!feed) return <Loading label="Scanning for blood-red signals" />;
  const c = feed.counts || {};

  return (
    <div className="p-6 max-w-[1500px] mx-auto fadein" data-testid="red-scope-page">
      <div className="flex items-end justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Eye size={26} className="text-incident" weight="fill" style={{ filter: "drop-shadow(0 0 6px #FF2A2A)" }} />
            <h2 className="h-font text-2xl font-black uppercase tracking-tight leading-none" style={{ color: "#FF2A2A", textShadow: "0 0 8px #FF2A2A" }}>
              Red Scope
            </h2>
          </div>
          <p className="text-sm text-sub mt-1">Incident hub — every blood-red signal, plus the adversary copilot that turns intent into a runnable agent.</p>
        </div>
        <Btn variant="ghost" icon={ArrowClockwise} onClick={loadFeed} data-testid="red-scope-refresh">Refresh</Btn>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <IncidentStat icon={WarningOctagon} label="Halted" value={c.halted || 0} />
        <IncidentStat icon={Bug} label="Critical Findings" value={c.critical_findings || 0} />
        <IncidentStat icon={Gavel} label="Exploit Approvals" value={c.exploit_approvals || 0} />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Incident feed */}
        <div className="space-y-4" data-testid="red-scope-feed">
          <FeedGroup icon={WarningOctagon} title="Halted Engagements" count={c.halted || 0}>
            {feed.halted_engagements.map((e) => (
              <FeedItem key={e.id} testid={`red-scope-halted-${e.id}`} borderCls="border-incident/40 hover:border-incident"
                onOpen={() => nav(`/engagements/${e.id}`)} onAdd={() => addEngagement(e)}>
                <div className="text-sm text-white truncate">{e.name}</div>
                <IncidentText className="text-[11px] mt-0.5">KILL SWITCH · {e.status}</IncidentText>
              </FeedItem>
            ))}
          </FeedGroup>

          <FeedGroup icon={Bug} title="Critical / Confirmed Findings" count={c.critical_findings || 0}>
            {feed.critical_findings.slice(0, 25).map((f) => (
              <FeedItem key={f.id} testid={`red-scope-finding-${f.id}`} borderCls="border-line hover:border-incident/60"
                onOpen={() => f.engagement_id && nav(`/engagements/${f.engagement_id}`)} onAdd={() => addFinding(f)}>
                <div className="text-sm text-white truncate">{f.title}</div>
                <div className="flex items-center gap-2 mt-1">
                  <Badge color="#FF2A2A">{f.exploitability === "confirmed" ? "confirmed" : f.severity}</Badge>
                  <span className="mono text-[10px] text-muted truncate">{f.engagement_name || "—"}</span>
                </div>
              </FeedItem>
            ))}
          </FeedGroup>

          <FeedGroup icon={Gavel} title="Pending Exploit Approvals" count={c.exploit_approvals || 0}>
            {feed.exploit_approvals.map((a) => (
              <FeedItem key={a.id} testid={`red-scope-approval-${a.id}`} borderCls="border-line hover:border-incident/60"
                onOpen={() => a.engagement_id && nav(`/engagements/${a.engagement_id}`)} onAdd={() => addApproval(a)}>
                <div className="mono text-xs text-white truncate">
                  {a.action?.tool_id} → {a.action?.target}
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <Badge color="#FF2A2A">exploit</Badge>
                  <span className="mono text-[10px] text-muted truncate">{a.engagement_name || "—"}</span>
                </div>
              </FeedItem>
            ))}
          </FeedGroup>
        </div>

        {/* Adversary copilot chat */}
        <div className="lg:col-span-2">
          <Panel className="flex flex-col" style={{ height: "calc(100vh - 320px)", minHeight: 460 }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b border-line">
              <Robot size={18} className="text-volt" weight="fill" />
              <span className="h-font text-sm uppercase tracking-widest2 text-white">Adversary Copilot</span>
              <span className="ml-auto text-[10px] mono text-muted">describe intent → review → save agent</span>
            </div>

            <PreviewNotice className="m-3">
              The Adversary Copilot chat isn't wired to the engine yet — this data is not available
              in this build. The incident hub on the left is live from real engagement state.
            </PreviewNotice>

            <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3" data-testid="red-scope-messages">
              {messages.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-center gap-4">
                  <Crosshair size={38} className="text-neutral" weight="thin" />
                  <div className="text-sm text-muted max-w-sm">Describe an attack objective in plain language. The copilot drafts a scoped agent config you can review and save to the registry.</div>
                  <div className="flex flex-col gap-2 w-full max-w-md">
                    {STARTERS.map((s) => (
                      <button key={s} onClick={() => send(s)}
                        className="text-left text-xs text-sub bg-black border border-line hover:border-volt px-3 py-2 transition-colors">
                        {s}
                      </button>
                    ))}
                  </div>
                  <div className="text-[11px] text-muted mono flex items-center gap-1.5">
                    <Plus size={12} weight="bold" className="text-incident" /> attach any finding, halted engagement, or approval on the left as a target
                  </div>
                </div>
              )}
              {messages.map((m) => (
                <div key={m.id} data-testid="red-scope-message"
                  className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                  <div className={`max-w-[85%] px-3 py-2 text-sm leading-relaxed whitespace-pre-wrap border ${m.role === "user" ? "bg-volt/10 border-volt/40 text-white" : "bg-black border-line text-sub"}`}>
                    {m.content}
                  </div>
                </div>
              ))}
              {sending && (
                <div className="flex justify-start"><div className="px-3 py-2 border border-line bg-black flex items-center gap-2 text-xs text-muted"><Spinner size={14} /> analyzing…</div></div>
              )}
              {draft && <DraftEditor draft={draft} setDraft={setDraft} onSave={saveDraft} saving={saving} />}
            </div>

            {selected.length > 0 && (
              <div className="border-t border-line px-3 pt-2.5 pb-1.5 flex flex-wrap gap-2 items-center" data-testid="red-scope-context">
                <span className="label text-incident">Targets · {selected.length}</span>
                {selected.map((s) => (
                  <span key={s.key} data-testid={`ctx-chip-${s.key}`} title={s.detail}
                    className="inline-flex items-center gap-1.5 max-w-[240px] bg-incident/10 border border-incident/50 px-2 py-0.5 text-[11px]">
                    <span className="uppercase text-[9px] text-incident/70">{s.kind}</span>
                    <span className="truncate text-white/90">{s.label}</span>
                    <button onClick={() => removeCtx(s.key)} data-testid={`ctx-remove-${s.key}`} className="text-incident/70 hover:text-white">
                      <X size={11} weight="bold" />
                    </button>
                  </span>
                ))}
                <button onClick={() => setSelected([])} className="ml-auto text-[10px] uppercase tracking-wider text-muted hover:text-white" data-testid="red-scope-context-clear">Clear</button>
              </div>
            )}
            <div className="border-t border-line p-3 flex items-center gap-2">
              <input
                data-testid="red-scope-chat-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
                placeholder="e.g. Design an agent to test SQLi on the customer portal…"
                className="flex-1 bg-black border border-line text-white text-sm px-3 py-2.5 focus:outline-none focus:border-volt placeholder:text-muted transition-colors"
              />
              <Btn icon={PaperPlaneRight} loading={sending} onClick={() => send()} data-testid="red-scope-send">Send</Btn>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
