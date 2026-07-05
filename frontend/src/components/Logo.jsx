import React from "react";

/**
 * 8π wordmark logo — condensed 8 next to the Greek pi symbol.
 * `size`  → total height in px (width auto-scales)
 * `tone`  → "mono" (all white) | "accent" (pi in magenta) | "reverse" (all magenta)
 * `glitch` → adds a glitch-on-hover shift
 */
export function EightPiLogo({ size = 40, tone = "accent", glitch = false, className = "" }) {
  const w = size * 1.65; // aspect
  const accent = "#FF00A0";
  const piColor = tone === "reverse" ? accent : tone === "accent" ? accent : "#FFFFFF";
  const eightColor = tone === "reverse" ? accent : "#FFFFFF";
  return (
    <span
      className={`inline-flex items-baseline gap-[0.06em] leading-none select-none ${glitch ? "glitch" : ""} ${className}`}
      data-text="8π"
      style={{
        fontFamily: "'Barlow Condensed', sans-serif",
        fontWeight: 900,
        fontSize: size,
        lineHeight: 1,
        letterSpacing: "-0.03em",
        width: w,
      }}
      aria-label="8pi"
    >
      <span style={{ color: eightColor, fontStyle: "italic", transform: "skew(-6deg)", display: "inline-block" }}>
        8
      </span>
      <span
        style={{
          color: piColor,
          fontFamily: "'Space Mono', 'JetBrains Mono', monospace",
          fontWeight: 700,
          fontSize: size * 0.78,
          transform: "translateY(-1px)",
          display: "inline-block",
          textShadow: tone === "accent" ? `0 0 12px ${accent}55` : "none",
        }}
      >
        π
      </span>
    </span>
  );
}

/**
 * Small favicon-style bracketed mark: [8π]
 */
export function EightPiMark({ size = 20 }) {
  return (
    <span
      className="inline-flex items-center h-font"
      style={{
        color: "#FF00A0",
        fontWeight: 800,
        fontSize: size,
        letterSpacing: "-0.02em",
      }}
    >
      <span style={{ color: "#7A7A7A" }}>[</span>
      <EightPiLogo size={size} tone="accent" />
      <span style={{ color: "#7A7A7A" }}>]</span>
    </span>
  );
}
