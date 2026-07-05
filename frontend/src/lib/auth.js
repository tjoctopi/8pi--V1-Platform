import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import axios from "axios";

const BASE = process.env.REACT_APP_BACKEND_URL;
const API = `${BASE}/api`;
const TOKEN_KEY = "8pi_token";
const REFRESH_KEY = "8pi_refresh";

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

// ---- token helpers (module-scope so api.js can read them too) ----
export const authStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  set: (t, r) => {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    if (r) localStorage.setItem(REFRESH_KEY, r);
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

// stand-alone axios instance used only for auth calls (no interceptor loops)
const authHttp = axios.create({ baseURL: API, withCredentials: true });

export function AuthProvider({ children }) {
  // null = checking session, false = not authed, object = user
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);

  const check = useCallback(async () => {
    const t = authStore.get();
    if (!t) {
      setUser(false);
      return;
    }
    try {
      const { data } = await authHttp.get("/auth/me", { headers: { Authorization: `Bearer ${t}` } });
      setUser(data.user);
    } catch (_e) {
      // try refresh once
      const r = authStore.getRefresh();
      if (r) {
        try {
          const { data } = await authHttp.post("/auth/refresh", { refresh_token: r });
          authStore.set(data.access_token, data.refresh_token);
          setUser(data.user);
          return;
        } catch (_e2) {}
      }
      authStore.clear();
      setUser(false);
    }
  }, []);

  useEffect(() => {
    check();
  }, [check]);

  const login = async (email, password) => {
    setError(null);
    try {
      const { data } = await authHttp.post("/auth/login", { email, password });
      authStore.set(data.access_token, data.refresh_token);
      setUser(data.user);
      return { ok: true };
    } catch (e) {
      const d = e?.response?.data?.detail;
      const msg = typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg || "").join(" ") : "Login failed";
      setError(msg);
      return { ok: false, error: msg };
    }
  };

  const logout = async () => {
    try {
      const t = authStore.get();
      if (t) await authHttp.post("/auth/logout", {}, { headers: { Authorization: `Bearer ${t}` } });
    } catch (_e) {}
    authStore.clear();
    setUser(false);
  };

  const changePassword = async (current_password, new_password) => {
    const t = authStore.get();
    const { data } = await authHttp.post(
      "/auth/change-password",
      { current_password, new_password },
      { headers: { Authorization: `Bearer ${t}` } }
    );
    return data;
  };

  const value = { user, error, login, logout, changePassword, recheck: check };
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

/** Convenience: role predicates identical to backend hierarchy admin > approver > operator > viewer */
export function roleAtLeast(user, min) {
  const rank = { viewer: 0, operator: 1, approver: 2, admin: 3 };
  return (rank[user?.role] ?? -1) >= (rank[min] ?? 99);
}
