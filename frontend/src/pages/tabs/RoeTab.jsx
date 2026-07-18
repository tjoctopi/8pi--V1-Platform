/* eslint-disable react-hooks/exhaustive-deps -- intentional effect deps; preserved behavior */
import React, { useEffect, useState } from "react";
import { Certificate, PencilSimple, Signature, Play, LockKey } from "@phosphor-icons/react";
import { api } from "../../lib/api";
import { Panel, SectionTitle, Btn, Badge, KV, Field, TextInput, Textarea, Select, Modal, useToast, errMsg } from "../../components/ui";

const toLocal = (iso) => (iso ? new Date(iso).toISOString().slice(0, 16) : "");

export default function RoeTab({ eid, engagement, roe, reload }) {
  const toast = useToast();
  const [tools, setTools] = useState([]);
  const [form, setForm] = useState(null);
  const [busy, setBusy] = useState(false);
  const [signOpen, setSignOpen] = useState(false);
  const [signer, setSigner] = useState("");

  useEffect(() => { api.tools().then(setTools).catch(() => {}); }, []);
  useEffect(() => {
    setForm({
      scope_allowlist: (roe.scope_allowlist || []).join("\n"),
      scope_denylist: (roe.scope_denylist || []).join("\n"),
      allowed_tools: roe.allowed_tools || [],
      allowed_techniques: (roe.allowed_techniques || []).join(", "),
      max_intensity: roe.max_intensity || "recon",
      window_start: toLocal(roe.window_start),
      window_end: toLocal(roe.window_end),
    });
  }, [roe.id, roe.signature]);

  if (!form) return null;
  const locked = !!roe.signature;

  const toggleTool = (t) =>
    setForm((f) => ({ ...f, allowed_tools: f.allowed_tools.includes(t) ? f.allowed_tools.filter((x) => x !== t) : [...f.allowed_tools, t] }));

  const save = async () => {
    setBusy(true);
    try {
      await api.updateRoe(eid, {
        scope_allowlist: form.scope_allowlist.split("\n").map((s) => s.trim()).filter(Boolean),
        scope_denylist: form.scope_denylist.split("\n").map((s) => s.trim()).filter(Boolean),
        allowed_tools: form.allowed_tools,
        allowed_techniques: form.allowed_techniques.split(",").map((s) => s.trim()).filter(Boolean),
        max_intensity: form.max_intensity,
        window_start: form.window_start ? new Date(form.window_start).toISOString() : null,
        window_end: form.window_end ? new Date(form.window_end).toISOString() : null,
      });
      toast.success("RoE draft saved");
      await reload();
    } catch (e) { toast.error(errMsg(e)); } finally { setBusy(false); }
  };

  const sign = async () => {
    if (!signer.trim()) return toast.error("Signer identity required");
    setBusy(true);
    try {
      await api.signRoe(eid, signer.trim());
      toast.success("RoE signed — now immutable");
      setSignOpen(false);
      await reload();
    } catch (e) { toast.error(errMsg(e)); } finally { setBusy(false); }
  };

  const activate = async () => {
    setBusy(true);
    try { await api.activate(eid); toast.success("Engagement activated"); await reload(); }
    catch (e) { toast.error(errMsg(e)); } finally { setBusy(false); }
  };

  const activateTest = async () => {
    setBusy(true);
    try {
      await api.activateTest(eid);
      toast.success("Engagement activated on test authorization");
      await reload();
    } catch (e) { toast.error(errMsg(e)); } finally { setBusy(false); }
  };

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2">
        <Panel className="p-6">
          <SectionTitle sub={locked ? "Signed RoE is immutable (DM-02). Create a new version to change scope." : "Define the authorized scope. Deny-by-default at the tool boundary (SEC-02)."}
            right={locked && <Badge color="#FFFFFF" dot>SIGNED · IMMUTABLE</Badge>}>
            Rules of Engagement
          </SectionTitle>

          <div className="grid sm:grid-cols-2 gap-5">
            <Field label="Scope Allowlist" hint="CIDR / hostname / URL — one per line">
              <Textarea disabled={locked} value={form.scope_allowlist} onChange={(e) => setForm({ ...form, scope_allowlist: e.target.value })} data-testid="roe-allowlist" />
            </Field>
            <Field label="Scope Denylist" hint="Explicitly excluded targets">
              <Textarea disabled={locked} value={form.scope_denylist} onChange={(e) => setForm({ ...form, scope_denylist: e.target.value })} data-testid="roe-denylist" />
            </Field>
          </div>

          <div className="mt-5">
            <div className="label mb-2">Allowed Tools</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {(Array.isArray(tools) ? tools : []).map((t) => {
                const on = form.allowed_tools.includes(t.tool_id);
                const licensed = !t.license_verified;
                return (
                  <button key={t.tool_id} disabled={locked || licensed} onClick={() => toggleTool(t.tool_id)}
                    data-testid={`roe-tool-${t.tool_id}`}
                    className={`flex items-center justify-between px-3 py-2 border rounded-sm text-xs transition-colors ${on ? "border-volt bg-volt/10 text-white" : "border-line text-sub hover:border-white/25"} ${(locked || licensed) ? "opacity-50 cursor-not-allowed" : ""}`}>
                    <span className="mono">{t.tool_id}</span>
                    {licensed ? <LockKey size={13} className="text-sub" /> : <Badge color={t.min_intensity === "exploit" ? "#FF00A0" : t.min_intensity === "safe-active" ? "#B4B4B4" : "#B4B4B4"}>{t.min_intensity}</Badge>}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid sm:grid-cols-3 gap-5 mt-5">
            <Field label="Max Intensity" hint="Intensity ceiling (SEC-03)">
              <Select disabled={locked} value={form.max_intensity} onChange={(e) => setForm({ ...form, max_intensity: e.target.value })} data-testid="roe-intensity">
                <option value="recon">recon</option>
                <option value="safe-active">safe-active</option>
                <option value="exploit">exploit</option>
              </Select>
            </Field>
            <Field label="Window Start"><TextInput type="datetime-local" disabled={locked} value={form.window_start} onChange={(e) => setForm({ ...form, window_start: e.target.value })} /></Field>
            <Field label="Window End"><TextInput type="datetime-local" disabled={locked} value={form.window_end} onChange={(e) => setForm({ ...form, window_end: e.target.value })} /></Field>
          </div>

          <div className="mt-5">
            <Field label="Allowed Techniques" hint="MITRE ATT&CK / OWASP refs — comma separated">
              <TextInput disabled={locked} value={form.allowed_techniques} onChange={(e) => setForm({ ...form, allowed_techniques: e.target.value })} placeholder="T1046, T1190, A03" />
            </Field>
          </div>

          {!locked && (
            <div className="flex justify-end gap-2 mt-6">
              <Btn variant="ghost" icon={PencilSimple} onClick={save} loading={busy} data-testid="roe-save-btn">Save Draft</Btn>
              <Btn icon={Signature} onClick={() => setSignOpen(true)} data-testid="roe-sign-open-btn">Sign RoE</Btn>
            </div>
          )}
        </Panel>
      </div>

      <div className="space-y-6">
        <Panel className="p-5">
          <div className="flex items-center gap-2 mb-3">
            <Certificate size={18} className="text-volt" weight="fill" />
            <span className="h-font text-lg uppercase tracking-tight text-white">Signature</span>
          </div>
          <KV k="Version" mono>{roe.version}</KV>
          <KV k="Signed by" mono>{roe.signed_by || "—"}</KV>
          <KV k="Signed at" mono>{roe.signed_at ? new Date(roe.signed_at).toLocaleString() : "—"}</KV>
          <KV k="Signature" mono>{roe.signature ? roe.signature.slice(0, 24) + "…" : "unsigned"}</KV>
        </Panel>

        <Panel className="p-5">
          <div className="label mb-3">Lifecycle</div>
          <p className="text-sm text-sub mb-4">
            An engagement cannot go <b className="text-white">active</b> without a signed, in-window RoE (SEC-01).
          </p>
          {roe.signature && engagement.status === "draft" && (
            <Btn variant="success" icon={Play} onClick={activate} loading={busy} className="w-full justify-center" data-testid="activate-btn">Activate Engagement</Btn>
          )}
          {engagement.status === "active" && <Badge color="#FFFFFF" dot>ENGAGEMENT ACTIVE</Badge>}
          {!roe.signature && engagement.status === "draft" && (
            <div className="mt-2">
              <div className="text-xs text-sub mono mb-2">Sign the RoE to enable activation — or, on a testing deployment, run gate-free:</div>
              <Btn variant="dark" icon={Play} onClick={activateTest} loading={busy} className="w-full justify-center" data-testid="activate-test-btn">Activate (Test Auth)</Btn>
              <div className="text-[10px] text-muted mono mt-1.5">Needs a scope allowlist. Requires AE_ALLOW_TEST_AUTH on the server; pilot only.</div>
            </div>
          )}
        </Panel>
      </div>

      <Modal open={signOpen} onClose={() => setSignOpen(false)} title="Sign Rules of Engagement">
        <p className="text-sm text-sub mb-4">Signing binds this scope and makes it immutable. Every subsequent action is validated against it at the tool boundary.</p>
        <Field label="Authorizing Identity"><TextInput value={signer} onChange={(e) => setSigner(e.target.value)} placeholder="ciso@org.com" data-testid="roe-signer-input" /></Field>
        <div className="flex justify-end gap-2 mt-5">
          <Btn variant="ghost" onClick={() => setSignOpen(false)}>Cancel</Btn>
          <Btn icon={Signature} onClick={sign} loading={busy} data-testid="roe-sign-btn">Sign</Btn>
        </div>
      </Modal>
    </div>
  );
}
