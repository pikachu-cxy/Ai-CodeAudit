/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      colors: {
        surface: {
          DEFAULT: "var(--surface)",
          raised: "var(--surface-raised)",
          border: "var(--surface-border)",
        },
        accent: {
          DEFAULT: "#06b6d4",
          glow: "#22d3ee",
        },
        danger: "#ef4444",
        warning: "#f59e0b",
        success: "#22c55e",
      },
    },
  },
  plugins: [],
};
