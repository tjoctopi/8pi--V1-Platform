import React, { createContext, useContext, useState, useCallback } from "react";
import { X, CircleNotch, CheckCircle, WarningCircle, Info } from "@phosphor-icons/react";

export const cx = (...a) => a.filter(Boolean).join(" ");

export function Panel({ className = "", children, ...p }) {
  return (
    <div className={cx("bg-panel2 border border-line", className)} {...p}>
      {children}
    </div>
  );
}

export function SectionTitle({ children, sub, right, className = "" }) {
  return (
    <div className={cx("flex items-end justify-between gap-4 mb-4", className)}>
      <div>
        <h2 className="h-font text-2xl font-bold uppercase tracking-tight text-white leading-none">{children}</h2>
        {sub && <p className="text-sm text-sub mt-1">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function Label({ children, className = "" }) {
  return <div className={cx("label", className)}>{children}</div>;
}

export function Spinner({ size = 18 }) {
  return <CircleNotch size={size} className="animate-spin text-volt" />;
}

export function Loading({ label = "Loading" }) {
  return (
    <div className="flex items-center gap-3 text-muted py-16 justify-center" data-testid="loading">
      <Spinner /> <span className="text-sm">{label}…</span>
    </div>
  );
}

export function Empty({ icon: Icon, title, hint, action }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-16 px-6 fadein" data-testid="empty-state">
      {Icon && <Icon size={40} className="text-neutral mb-4" weight="thin" />}
      <div className="h-font text-xl uppercase tracking-tight text-sub">{title}</div>
      {hint && <div className="text-sm text-muted mt-2 max-w-md">{hint}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

// Honest "this isn't wired to the engine yet" banner. Kept visible on purpose so
// a not-yet-available view reads as intentional, not broken.
export function PreviewNotice({ title = "Not available yet", children, className = "" }) {
  return (
    <div
      className={cx("flex items-start gap-3 border border-warn/40 bg-warn/5 px-4 py-3", className)}
      data-testid="preview-notice"
    >
      <WarningCircle size={18} weight="bold" className="text-warn shrink-0 mt-0.5" />
      <div>
        <div className="label text-warn">{title}</div>
        {children && <div className="text-sm text-sub mt-1 leading-relaxed">{children}</div>}
      </div>
    </div>
  );
}

const VARIANTS = {
  primary: "bg-volt hover:bg-voltbright text-black border-transparent font-black",
  ghost:   "bg-transparent hover:bg-white/10 text-sub hover:text-white border-line hover:border-volt",
  danger:  "bg-transparent hover:bg-volt/20 text-volt border-volt",
  success: "bg-white hover:bg-white/90 text-black border-transparent font-black",
  dark:    "bg-panel3 hover:border-volt text-white border-line",
};

export function Btn({ variant = "primary", className = "", children, loading, disabled, icon: Icon, ...p }) {
  return (
    <button
      disabled={disabled || loading}
      className={cx(
        "inline-flex items-center gap-2 px-4 py-2 text-[11px] font-semibold uppercase tracking-widest2 border",
        "transition-all duration-150 active:scale-[0.98] disabled:opacity-30 disabled:cursor-not-allowed",
        VARIANTS[variant], className
      )}
      {...p}
    >
      {loading ? <CircleNotch size={15} className="animate-spin" /> : Icon ? <Icon size={15} weight="bold" /> : null}
      {children}
    </button>
  );
}

// The ONE incident color — anything painted in this hue MUST be bold + glow (platform rule).
export const INCIDENT_HEX = "#FF2A2A";

/** True if the given hex color is the reserved blood-red incident marker. */
export function isIncident(hex) {
  return typeof hex === "string" && hex.toUpperCase() === INCIDENT_HEX;
}

export function Badge({ color = "#7A7A7A", children, className = "", dot = false, ...p }) {
  const incident = isIncident(color);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] uppercase tracking-widest2 border",
        incident ? "font-black" : "font-semibold",
        className
      )}
      style={{
        color,
        borderColor: color,
        backgroundColor: `${color}${incident ? "22" : "12"}`,
        boxShadow: incident ? `0 0 10px ${color}66, inset 0 0 8px ${color}33` : undefined,
        textShadow: incident ? `0 0 4px ${color}` : undefined,
      }}
      {...p}
    >
      {dot && (
        <span
          className={incident ? "w-1.5 h-1.5 blink" : "w-1.5 h-1.5"}
          style={{ background: color, boxShadow: incident ? `0 0 6px ${color}` : undefined }}
        />
      )}
      {children}
    </span>
  );
}

/**
 * IncidentText — inline text painted blood red with the required bold + glow treatment.
 * Use this anywhere an operator MUST notice a specific word/event (not just a badge).
 */
export function IncidentText({ children, className = "", withMarker = true, ...p }) {
  return (
    <span
      className={cx("font-black inline-flex items-center gap-1", className)}
      style={{ color: INCIDENT_HEX, textShadow: `0 0 4px ${INCIDENT_HEX}` }}
      {...p}
    >
      {withMarker && <span aria-hidden className="text-[0.85em] leading-none">▲</span>}
      {children}
    </span>
  );
}

export function Dot({ color = "#7A7A7A", pulse = false }) {
  return (
    <span
      className={cx("inline-block w-2 h-2 rounded-full", pulse && "blink")}
      style={{ background: color, boxShadow: `0 0 8px ${color}` }}
    />
  );
}

export function KV({ k, children, mono = false }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="label pt-0.5">{k}</span>
      <span className={cx("text-sm text-right text-white break-all", mono && "mono text-xs")}>{children}</span>
    </div>
  );
}

export function Field({ label, hint, children }) {
  return (
    <label className="block">
      <div className="label mb-1.5">{label}</div>
      {children}
      {hint && <div className="text-[11px] text-muted mt-1">{hint}</div>}
    </label>
  );
}

const inputCls =
  "w-full bg-black border border-line text-white text-sm px-3 py-2 mono " +
  "focus:outline-none focus:border-volt focus:ring-1 focus:ring-volt placeholder:text-muted transition-colors";

export function TextInput(props) {
  return <input className={inputCls} {...props} />;
}
export function Textarea(props) {
  return <textarea className={cx(inputCls, "min-h-[90px] resize-y")} {...props} />;
}
export function Select({ children, ...props }) {
  return (
    <select className={cx(inputCls, "font-sans")} {...props}>
      {children}
    </select>
  );
}

export function Modal({ open, onClose, title, children, maxW = "max-w-lg" }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm fadein" onClick={onClose}>
      <Panel className={cx("w-full bg-panel2 shadow-2xl corner-frame", maxW)} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-line">
          <h3 className="h-font text-xl uppercase tracking-widest2 text-white">{title}</h3>
          <button onClick={onClose} className="text-muted hover:text-volt transition-colors" data-testid="modal-close">
            <X size={20} />
          </button>
        </div>
        <div className="p-6 max-h-[75vh] overflow-y-auto">{children}</div>
      </Panel>
    </div>
  );
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="flex flex-wrap gap-0 border-b border-line overflow-x-auto">
      {tabs.map((t) => (
        <button
          key={t.id}
          data-testid={`tab-${t.id}`}
          onClick={() => onChange(t.id)}
          className={cx(
            "relative px-4 py-3 text-[11px] font-semibold uppercase tracking-widest2 whitespace-nowrap transition-colors flex items-center gap-2",
            active === t.id ? "text-white" : "text-muted hover:text-white"
          )}
        >
          {t.icon && <t.icon size={15} weight={active === t.id ? "fill" : "regular"} />}
          {t.label}
          {typeof t.badge === "number" && t.badge > 0 && (
            <span className="ml-1 text-[10px] px-1.5 py-0.5 bg-volt/20 text-volt border border-volt/50">{t.badge}</span>
          )}
          {active === t.id && <span className="absolute left-0 right-0 -bottom-px h-[2px] bg-volt" />}
        </button>
      ))}
    </div>
  );
}

/* ---------- toasts ---------- */
const ToastCtx = createContext(null);
export const useToast = () => useContext(ToastCtx);

const TOAST_ICON = { success: CheckCircle, error: WarningCircle, info: Info };
const TOAST_COLOR = { success: "#FFFFFF", error: "#FF00A0", info: "#B4B4B4" };

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((message, type = "info") => {
    const id = Math.random().toString(36).slice(2);
    setItems((x) => [...x, { id, message, type }]);
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), 4200);
  }, []);
  const toast = {
    success: (m) => push(m, "success"),
    error: (m) => push(m, "error"),
    info: (m) => push(m, "info"),
  };
  return (
    <ToastCtx.Provider value={toast}>
      {children}
      <div className="fixed bottom-5 right-5 z-[60] flex flex-col gap-2 w-[340px]">
        {items.map((t) => {
          const Icon = TOAST_ICON[t.type];
          const c = TOAST_COLOR[t.type];
          return (
            <div key={t.id} data-testid="toast" className="fadein bg-panel2 border border-line px-4 py-3 flex items-start gap-3 shadow-xl" style={{ borderLeft: `3px solid ${c}` }}>
              <Icon size={18} style={{ color: c }} weight="fill" className="mt-0.5 shrink-0" />
              <div className="text-sm text-white break-words">{t.message}</div>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}

export function errMsg(e) {
  return e?.response?.data?.detail || e?.message || "Request failed";
}

export class ErrorBoundary extends React.Component {
  constructor(p) { super(p); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (this.state.err) return this.props.fallback || <div className="p-6 text-sm text-muted">Visualization unavailable.</div>;
    return this.props.children;
  }
}
