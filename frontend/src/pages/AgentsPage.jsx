import React, { useEffect, useState, useCallback } from "react";
import { Robot, Plus, ArrowFatUp, ShieldCheck, Cube } from "@phosphor-icons/react";
import { api } from "../lib/api";
import { PROMOTION, INTENSITY, timeAgo } from "../lib/theme";
import { Panel, SectionTitle, Btn, Badge, Loading, Empty, Modal, Field, TextInput, Select, PreviewNotice, useToast, errMsg } from "../components/ui";

const ROLE_COLOR = { offensive: "#FF00A0", defensive: "#FFFFFF", recon: "#B4B4B4" };
const ALL_TOOLS = ["nmap", "nikto", "dirbust", "wpscan", "sqlmap"];

function AgentCard({ a, onSandbox, onPromote, busy }) {
  const g = a.spec?.guardrails || {};
  return (
    <Panel className="p-5" data-testid={`agent-card-${a.id}`}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <Robot size={22} style={{ color: ROLE_COLOR[a.role] }} weight="fill" />
          <div>
            <div className="h-font text-lg text-white leading-none">{a.name}</div>
            <div className="mono text-[11px] text-muted mt-0.5">v{a.version}</div>
          </div>
        </div>
        <Badge color={PROMOTION[a.promotion_state]} dot>{a.promotion_state}</Badge>
      </div>
      <div className="flex items-center gap-2 mb-3">
        <Badge color={ROLE_COLOR[a.role]}>{a.role}</Badge>
        <Badge color={INTENSITY[g.max_intensity]?.color || "#7A7A7A"}>max {g.max_intensity}</Badge>
      </div>
      <div className="flex flex-wrap gap-1 mb-4">
        {(a.spec?.tools || []).map((t) => <span key={t} className="mono text-[10px] text-sub bg-black border border-line px-1.5 py-0.5 rounded-sm">{t}</span>)}
        {(a.spec?.tools || []).length === 0 && <span className="text-xs text-muted">no tools</span>}
      </div>
      <div className="flex items-center justify-between pt-3 border-t border-white/5">
        <span className="text-[11px] text-muted mono">
          {a.last_sandbox_pass ? `sandbox ✓ ${timeAgo(a.last_sandbox_pass)}` : "no sandbox pass"}
        </span>
        <div className="flex gap-2">
          <Btn variant="ghost" icon={Cube} loading={busy === "s" + a.id} onClick={() => onSandbox(a)} data-testid={`sandbox-${a.id}`}>Sandbox</Btn>
          {a.promotion_state !== "authorized" && (
            <Btn variant="dark" icon={ArrowFatUp} loading={busy === "p" + a.id}
              onClick={() => onPromote(a, a.promotion_state === "dev" ? "sandbox" : "authorized")}
              data-testid={`promote-${a.id}`}>
              {a.promotion_state === "dev" ? "→ Sandbox" : "→ Authorize"}
            </Btn>
          )}
          {a.promotion_state === "authorized" && <Badge color="#FFFFFF" dot><ShieldCheck size={11} className="inline mr-1" />Authorized</Badge>}
        </div>
      </div>
    </Panel>
  );
}

export default function AgentsPage() {
  const toast = useToast();
  const [agents, setAgents] = useState(null);
  const [sbx, setSbx] = useState([]);
  const [busy, setBusy] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", role: "offensive", max_intensity: "safe-active", tools: ["nmap"] });

  const load = useCallback(async () => {
    const [a, t] = await Promise.all([api.agents(), api.sandboxTargets()]);
    setAgents(a);
    setSbx(t);
  }, []);
  useEffect(() => { load().catch((e) => toast.error(errMsg(e))); }, []); // eslint-disable-line

  const onSandbox = async (a) => {
    setBusy("s" + a.id);
    try { const r = await api.sandboxRun(a.id); toast.success(r.message); await load(); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(""); }
  };
  const onPromote = async (a, to) => {
    setBusy("p" + a.id);
    try { await api.promoteAgent(a.id, to); toast.success(`Promoted to ${to}`); await load(); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(""); }
  };
  const create = async () => {
    if (!form.name.trim()) return toast.error("Name required");
    try {
      await api.createAgent({ name: form.name.trim(), role: form.role, max_intensity: form.max_intensity, tools: form.tools });
      toast.success("Agent created (dev state)");
      setOpen(false);
      setForm({ name: "", role: "offensive", max_intensity: "safe-active", tools: ["nmap"] });
      await load();
    } catch (e) { toast.error(errMsg(e)); }
  };
  const toggle = (t) => setForm((f) => ({ ...f, tools: f.tools.includes(t) ? f.tools.filter((x) => x !== t) : [...f.tools, t] }));

  if (!agents) return <Loading label="Loading agent registry" />;

  return (
    <div className="p-6 max-w-[1500px] mx-auto fadein">
      <SectionTitle sub="Declarative, versioned agents. Only authorized agents may run against a real estate (FR-AGENT-02)."
        right={<Btn icon={Plus} onClick={() => setOpen(true)} data-testid="new-agent-btn">New Agent</Btn>}>
        Agent Registry
      </SectionTitle>

      <PreviewNotice className="mb-6">
        These are the engine's real built-in agent archetypes (Surface Mapper, Web Inquisitor,
        Exploit Confirmer, Converter). Authoring new agents and the sandbox → promotion flow
        aren't wired to the engine yet — those actions are not available in this build.
      </PreviewNotice>

      <div className="grid lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3">
          {agents.length === 0 ? <Empty icon={Robot} title="No agents" /> : (
            <div className="grid sm:grid-cols-2 gap-4">
              {agents.map((a) => <AgentCard key={a.id} a={a} onSandbox={onSandbox} onPromote={onPromote} busy={busy} />)}
            </div>
          )}
        </div>
        <div>
          <SectionTitle>Sandbox Range</SectionTitle>
          <Panel className="p-5">
            <p className="text-xs text-muted mb-3">Isolated, intentionally-vulnerable targets. A passing sandbox run gates promotion to <b className="text-white">authorized</b> (FR-AGENT-04).</p>
            <div className="space-y-2">
              {sbx.map((t) => (
                <div key={t.id} className="flex items-center gap-2 bg-black border border-line px-3 py-2 rounded-sm">
                  <Cube size={15} className="text-sub" />
                  <div className="min-w-0">
                    <div className="mono text-xs text-sub truncate">{t.label}</div>
                    <div className="text-[10px] text-muted">{t.profile}</div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title="New Agent Definition">
        <div className="space-y-4">
          <Field label="Name"><TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="web-recon-agent" data-testid="agent-name-input" /></Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Role">
              <Select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} data-testid="agent-role-select">
                <option value="offensive">offensive</option>
                <option value="defensive">defensive</option>
                <option value="recon">recon</option>
              </Select>
            </Field>
            <Field label="Max Intensity">
              <Select value={form.max_intensity} onChange={(e) => setForm({ ...form, max_intensity: e.target.value })}>
                <option value="recon">recon</option>
                <option value="safe-active">safe-active</option>
                <option value="exploit">exploit</option>
              </Select>
            </Field>
          </div>
          <div>
            <div className="label mb-2">Tools</div>
            <div className="grid grid-cols-3 gap-2">
              {ALL_TOOLS.map((t) => (
                <button key={t} onClick={() => toggle(t)}
                  className={`px-3 py-2 border rounded-sm text-xs mono transition-colors ${form.tools.includes(t) ? "border-volt bg-volt/10 text-white" : "border-line text-sub hover:border-white/25"}`}>{t}</button>
              ))}
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Btn variant="ghost" onClick={() => setOpen(false)}>Cancel</Btn>
            <Btn onClick={create} data-testid="create-agent-submit">Create</Btn>
          </div>
        </div>
      </Modal>
    </div>
  );
}
