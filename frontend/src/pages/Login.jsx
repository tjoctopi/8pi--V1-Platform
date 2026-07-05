import React, { useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { LockKey, User, ShieldCheck } from "@phosphor-icons/react";
import { useAuth } from "../lib/auth";
import { Panel, Btn, Field, TextInput } from "../components/ui";
import { EightPiLogo } from "../components/Logo";

export default function Login() {
  const { user, login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState(null);
  const loc = useLocation();
  const next = loc.state?.from || "/";

  if (user) return <Navigate to={next} replace />;

  const submit = async (e) => {
    e.preventDefault();
    setErr(null);
    setSubmitting(true);
    const r = await login(email.trim().toLowerCase(), password);
    setSubmitting(false);
    if (!r.ok) setErr(r.error || "Login failed");
  };

  return (
    <div className="min-h-screen bg-ink grid-bg flex items-center justify-center p-6 relative overflow-hidden" data-testid="login-page">
      <div className="absolute inset-0 vignette pointer-events-none" />
      <div className="w-full max-w-[440px] relative z-10">
        <div className="flex items-center gap-3 mb-8 justify-center flicker">
          <EightPiLogo size={72} tone="accent" glitch />
        </div>

        <Panel className="p-10 corner-frame scanlines">
          <div className="flex items-center gap-2 mb-6 relative z-10">
            <ShieldCheck size={18} weight="bold" className="text-volt" />
            <h1 className="h-font text-lg uppercase tracking-widest2 text-white">Operator Sign-In</h1>
          </div>

          <form onSubmit={submit} className="space-y-4 relative z-10">
            <Field label="Email">
              <div className="relative">
                <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <TextInput
                  type="email"
                  required
                  autoFocus
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@8pi.ai"
                  className="pl-9"
                  data-testid="login-email"
                />
              </div>
            </Field>
            <Field label="Password">
              <div className="relative">
                <LockKey size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <TextInput
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pl-9"
                  data-testid="login-password"
                />
              </div>
            </Field>

            {err && (
              <div
                className="text-xs mono text-volt bg-volt/10 border border-volt/50 px-3 py-2"
                data-testid="login-error"
              >
                {err}
              </div>
            )}

            <Btn
              type="submit"
              variant="primary"
              className="w-full justify-center"
              loading={submitting}
              disabled={submitting}
              data-testid="login-submit"
            >
              {submitting ? "AUTHENTICATING…" : "SIGN IN"}
            </Btn>
          </form>

          <div className="mt-6 pt-4 border-t border-line text-[10px] mono text-muted text-center relative z-10 uppercase tracking-widest2">
            v1 · JWT · Single-Tenant
          </div>
        </Panel>

        <div className="text-center mt-6 text-[9px] mono text-neutral uppercase tracking-widest3">
          Classification: Confidential · <span className="text-muted">app.8pi.ai</span>
        </div>
      </div>
    </div>
  );
}
