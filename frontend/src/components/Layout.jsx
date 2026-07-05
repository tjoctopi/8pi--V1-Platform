import React, { useState, useRef, useEffect } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { GridFour, Robot, Cpu, CaretDown, User, SignOut, ShieldCheck, KeyReturn, Eye } from "@phosphor-icons/react";
import { cx } from "./ui";
import { EightPiLogo } from "./Logo";
import { useAuth } from "../lib/auth";

const NAV = [
  { to: "/", label: "Operations", icon: GridFour, end: true },
  { to: "/agents", label: "Agent Registry", icon: Robot },
  { to: "/model-gateway", label: "Model Gateway", icon: Cpu },
];

function Sidebar() {
  return (
    <aside className="w-[230px] shrink-0 bg-panel border-r border-line flex flex-col relative">
      <div className="px-5 py-6 border-b border-line corner-frame">
        <div className="flex items-center gap-1">
          <EightPiLogo size={34} tone="accent" glitch />
          <div className="ml-2">
            <div className="text-[9px] uppercase tracking-widest3 text-muted mt-0.5">Console</div>
            <div className="mono text-[9px] text-neutral">app.8pi.ai</div>
          </div>
        </div>
      </div>
      <nav className="flex-1 py-4">
        <NavLink
          to="/red-scope"
          data-testid="nav-red-scope"
          className={({ isActive }) =>
            cx(
              "flex items-center gap-3 px-5 py-3 mb-2 text-xs font-black uppercase tracking-widest2 transition-colors border-l-2",
              isActive
                ? "text-incident border-incident bg-incident/10"
                : "text-incident/80 border-transparent hover:bg-incident/10 hover:text-incident"
            )
          }
          style={{ textShadow: "0 0 6px rgba(255,42,42,0.5)" }}
        >
          <Eye size={17} weight="fill" />
          Red Scope
          <span className="ml-auto w-1.5 h-1.5 rounded-full bg-incident blink" style={{ boxShadow: "0 0 6px #FF2A2A" }} />
        </NavLink>
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            data-testid={`nav-${n.label.toLowerCase().replace(/\s/g, "-")}`}
            className={({ isActive }) =>
              cx(
                "flex items-center gap-3 px-5 py-3 text-xs font-semibold uppercase tracking-widest2 transition-colors border-l-2",
                isActive
                  ? "text-white border-volt bg-volt/10"
                  : "text-muted border-transparent hover:text-white hover:bg-white/5"
              )
            }
          >
            <n.icon size={17} weight="bold" />
            {n.label}
          </NavLink>
        ))}
      </nav>
      <div className="px-5 py-4 border-t border-line">
        <div className="label mb-1">Classification</div>
        <div className="text-[11px] mono text-sub">CONFIDENTIAL · v1</div>
      </div>
    </aside>
  );
}

const ROLE_COLOR = { admin: "#FF00A0", approver: "#22E85D", operator: "#00E5FF", viewer: "#7A7A7A" };

function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const menuRef = useRef(null);

  useEffect(() => {
    const onDoc = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  if (!user) return null;
  const color = ROLE_COLOR[user.role] || "#7A7A7A";

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen((o) => !o)}
        data-testid="user-menu"
        className="flex items-center gap-2 pl-2 pr-2.5 py-1.5 border border-line hover:border-white/30 rounded-sm text-xs transition-colors"
      >
        <span className="w-6 h-6 rounded-sm flex items-center justify-center" style={{ background: `${color}33`, color }}>
          <User size={14} weight="bold" />
        </span>
        <div className="hidden md:flex flex-col items-start">
          <span className="mono text-[10px] text-white leading-tight">{user.email}</span>
          <span className="uppercase tracking-wider text-[9px]" style={{ color }}>{user.role}</span>
        </div>
        <CaretDown size={12} className="text-muted" />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-64 bg-panel2 border border-line z-40 shadow-2xl">
          <div className="px-4 py-3 border-b border-line">
            <div className="mono text-xs text-white break-all">{user.email}</div>
            <div className="flex items-center gap-2 mt-1.5">
              <ShieldCheck size={12} style={{ color }} weight="fill" />
              <span className="uppercase tracking-wider text-[10px] font-semibold" style={{ color }}>
                {user.role}
              </span>
            </div>
          </div>
          {user.role === "admin" && (
            <button
              data-testid="user-menu-users"
              onClick={() => { setOpen(false); nav("/users"); }}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-xs uppercase tracking-wider text-sub hover:bg-white/5 hover:text-white transition-colors"
            >
              <KeyReturn size={13} weight="bold" /> User Management
            </button>
          )}
          <button
            data-testid="logout-btn"
            onClick={async () => { setOpen(false); await logout(); nav("/login"); }}
            className="w-full flex items-center gap-2 px-4 py-2.5 text-xs uppercase tracking-wider text-kill hover:bg-kill/10 transition-colors"
          >
            <SignOut size={13} weight="bold" /> Sign Out
          </button>
        </div>
      )}
    </div>
  );
}

function TopBar() {
  const loc = useLocation();
  const crumb =
    loc.pathname === "/"
      ? "Operations Console"
      : loc.pathname.startsWith("/red-scope")
      ? "Red Scope"
      : loc.pathname.startsWith("/engagements")
      ? "Engagement"
      : loc.pathname.startsWith("/agents")
      ? "Agent Registry"
      : loc.pathname.startsWith("/users")
      ? "User Management"
      : "Model Gateway";
  return (
    <header className="h-14 shrink-0 bg-panel/80 backdrop-blur-xl border-b border-line flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <span className="label">8π</span>
        <span className="text-muted">/</span>
        <span className="text-sm text-white uppercase tracking-widest2 h-font">{crumb}</span>
      </div>
      <div className="flex items-center gap-4">
        <div className="hidden sm:flex items-center gap-2 text-[11px] mono text-live">
          <span className="w-2 h-2 rounded-full bg-live blink" style={{ boxShadow: "0 0 8px #22E85D" }} /> CONTROL PLANE ONLINE
        </div>
        <UserMenu />
      </div>
    </header>
  );
}

export function Layout({ children }) {
  return (
    <div className="flex h-screen overflow-hidden bg-ink">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar />
        <main className="flex-1 overflow-y-auto grid-bg">{children}</main>
      </div>
    </div>
  );
}
