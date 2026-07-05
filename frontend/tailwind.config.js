/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx}", "./public/index.html"],
  theme: {
    extend: {
      colors: {
        // ── surfaces (pure B/W cyberpunk) ──
        ink:     "#000000",
        panel:   "#050505",
        panel2:  "#0A0A0A",
        panel3:  "#101010",
        line:    "#1A1A1A",
        sub:     "#B4B4B4",
        muted:   "#7A7A7A",
        neutral: "#4A4A4A",

        // ── the brand accent (magenta) ──
        volt:        "#FF00A0",   // primary CTAs, brand, high severity, focus, breach anim
        voltbright:  "#FF3EBF",   // hover
        voltdim:     "#B3006E",

        // ── semantic signal palette ──
        // "live"     → alive / healthy / positive: online, active, approved, signed, ok
        // "info"     → motion / streaming / recon
        // "warn"     → warning / pending / medium severity
        // "incident" → REAL INCIDENT — reserved for attention-grabbing markers:
        //              crit severity, KEV, halted, refused, confirmed exploit, exploit intensity
        live:     "#22E85D",
        livedim:  "#0E7A32",
        info:     "#00E5FF",
        infodim:  "#0F6A78",
        warn:     "#FFB020",
        warndim:  "#7A5210",
        incident: "#FF2A2A",   // blood red — reserved
        incidentbright: "#FF4E4E",

        // ── severity aliases (map ordered high→low, referenced by SEV in theme.js) ──
        crit: "#FF2A2A",   // incident
        high: "#FF00A0",   // brand
        med:  "#FFB020",   // warn
        low:  "#00E5FF",   // info
        ok:   "#22E85D",
        kill: "#FF2A2A",
      },
      fontFamily: {
        head: ["'Barlow Condensed'", "sans-serif"],
        sans: ["'IBM Plex Sans'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      letterSpacing: { widest2: "0.22em", widest3: "0.32em" },
      borderRadius: { none: "0", sm: "0", md: "0", lg: "0", DEFAULT: "0" },
    },
  },
  plugins: [],
};
