import React, { useCallback, useEffect, useState } from "react";
import { Users, Plus, Trash, ShieldCheck } from "@phosphor-icons/react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Panel, SectionTitle, Btn, Badge, Field, TextInput, Select, Modal, Loading, useToast, errMsg } from "../components/ui";

const ROLE_COLOR = { admin: "#FF00A0", approver: "#FFFFFF", operator: "#B4B4B4", viewer: "#7A7A7A" };

export default function UsersPage() {
  const { user: me } = useAuth();
  const toast = useToast();
  const [users, setUsers] = useState(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ email: "", password: "", name: "", role: "operator" });

  const load = useCallback(async () => {
    try {
      setUsers(await api.users());
    } catch (e) {
      toast.error(errMsg(e));
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      await api.createAuthUser(form);
      toast.success(`User ${form.email} created`);
      setOpen(false);
      setForm({ email: "", password: "", name: "", role: "operator" });
      await load();
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const del = async (u) => {
    if (u.id === me?.id) return;
    if (!window.confirm(`Delete ${u.email}? This cannot be undone.`)) return;
    try {
      await api.deleteAuthUser(u.id);
      toast.success("User deleted");
      await load();
    } catch (e) {
      toast.error(errMsg(e));
    }
  };

  if (!users) return <Loading label="Loading users" />;

  return (
    <div className="max-w-5xl mx-auto p-6" data-testid="users-page">
      <SectionTitle
        sub="Manage operator, approver, and viewer accounts. Only admins see this page."
        right={<Btn icon={Plus} onClick={() => setOpen(true)} data-testid="user-add-btn">New User</Btn>}
      >
        <span className="inline-flex items-center gap-2"><Users size={22} weight="bold" className="text-volt" /> User Management</span>
      </SectionTitle>

      <Panel className="overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-panel/70">
            <tr className="border-b border-line">
              {["Email", "Name", "Role", "Created", "Last Login", ""].map((h) => (
                <th key={h} className="text-left label px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-white/5" data-testid={`user-row-${u.id}`}>
                <td className="px-4 py-3 mono text-xs text-white">{u.email}</td>
                <td className="px-4 py-3 text-xs text-sub">{u.name || "—"}</td>
                <td className="px-4 py-3">
                  <Badge color={ROLE_COLOR[u.role]} dot>{u.role}</Badge>
                </td>
                <td className="px-4 py-3 mono text-[11px] text-muted">{u.created_at?.slice(0, 10) || "—"}</td>
                <td className="px-4 py-3 mono text-[11px] text-muted">{u.last_login?.slice(0, 16).replace("T", " ") || "never"}</td>
                <td className="px-4 py-3 text-right">
                  {u.id !== me?.id && (
                    <Btn variant="danger" icon={Trash} onClick={() => del(u)} data-testid={`user-delete-${u.id}`}>Delete</Btn>
                  )}
                  {u.id === me?.id && (
                    <span className="mono text-[10px] text-muted"><ShieldCheck size={11} className="inline" /> you</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Modal open={open} onClose={() => setOpen(false)} title="Create User" maxW="max-w-md">
        <div className="space-y-4">
          <Field label="Email">
            <TextInput
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              placeholder="operator@8pi.io"
              data-testid="user-form-email"
            />
          </Field>
          <Field label="Name">
            <TextInput
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Operator One"
              data-testid="user-form-name"
            />
          </Field>
          <Field label="Password" hint="Minimum 8 characters.">
            <TextInput
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              placeholder="••••••••"
              data-testid="user-form-password"
            />
          </Field>
          <Field label="Role">
            <Select
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
              data-testid="user-form-role"
            >
              <option value="viewer">viewer (read-only)</option>
              <option value="operator">operator (drive pipeline)</option>
              <option value="approver">approver (release exploits)</option>
              <option value="admin">admin (user management)</option>
            </Select>
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <Btn variant="ghost" onClick={() => setOpen(false)}>Cancel</Btn>
            <Btn onClick={create} loading={busy} disabled={busy || !form.email || form.password.length < 8} data-testid="user-form-submit">
              Create User
            </Btn>
          </div>
        </div>
      </Modal>
    </div>
  );
}
