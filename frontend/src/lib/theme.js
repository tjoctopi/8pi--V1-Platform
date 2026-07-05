// Shared visual token maps — B/W cyberpunk foundation + semantic signal palette.
//
//  incident  #FF2A2A  blood red   → REAL incidents only (attention grabber)
//                                    crit sev, KEV, halted, refused, confirmed exploit
//  brand     #FF00A0  hot magenta → brand accent: logo, primary CTAs, HIGH sev, breach anim
//  live      #22E85D  green       → alive: online, active, approved, signed, ok, authorized
//  info      #00E5FF  cyan        → motion: running, streaming, LOW sev, recon, operator
//  warn      #FFB020  amber       → attention: pending, retest, reachable, MEDIUM sev, sandbox
//  gray      #7A7A7A              → neutral: draft, closed, cancelled, info sev, viewer, dev

export const SEV = {
  crit: { color: "#FF2A2A", label: "CRITICAL" },     // real incident
  high: { color: "#FF00A0", label: "HIGH" },         // brand attention
  med:  { color: "#FFB020", label: "MEDIUM" },       // warn
  low:  { color: "#00E5FF", label: "LOW" },          // info
  info: { color: "#7A7A7A", label: "INFO" },         // neutral
};

export const INTENSITY = {
  recon:         { color: "#00E5FF", label: "RECON" },
  "safe-active": { color: "#FFB020", label: "SAFE-ACTIVE" },
  exploit:       { color: "#FF2A2A", label: "EXPLOIT" },      // real-incident-level danger
};

export const EXPLOIT = {
  unconfirmed: { color: "#7A7A7A", label: "UNCONFIRMED" },
  reachable:   { color: "#FFB020", label: "REACHABLE" },
  confirmed:   { color: "#FF2A2A", label: "CONFIRMED" },      // real incident
};

export const STATUS = {
  draft:            "#7A7A7A",
  active:           "#22E85D",   // alive
  paused:           "#FFB020",
  closed:           "#4A4A4A",
  open:             "#FFB020",   // attention: unremediated
  remediating:      "#00E5FF",   // in motion
  retest:           "#FFB020",
  "false-positive": "#4A4A4A",
  pending:          "#FFB020",
  approved:         "#22E85D",   // positive
  denied:           "#FFB020",
  cancelled:        "#4A4A4A",
  completed:        "#22E85D",
  running:          "#00E5FF",   // in motion
  refused:          "#FF2A2A",   // scope refusal = incident marker
  halted:           "#FF2A2A",   // kill switch = incident
};

export const PROMOTION = {
  dev:        "#7A7A7A",
  sandbox:    "#FFB020",
  authorized: "#22E85D",
};

export function riskBucket(score) {
  if (score >= 150) return { color: "#FF2A2A", label: "critical" };
  if (score >= 60)  return { color: "#FF00A0", label: "elevated" };
  if (score > 0)    return { color: "#FFB020", label: "low" };
  return { color: "#7A7A7A", label: "clean" };
}

export function timeAgo(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
