/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
    "./hooks/**/*.{js,ts,jsx,tsx}",
    "./lib/**/*.{js,ts,jsx,tsx}",
    "./types/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e1a",
        card: "#111827",
        border: "#1f2937",
        cyan: "#00d4ff",
        green: "#00ff88",
        red: "#ff4444",
        orange: "#ffaa00",
        purple: "#a855f7",
        text: {
          primary: "#f1f5f9",
          secondary: "#94a3b8",
        },
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(0, 212, 255, 0.25), 0 0 35px rgba(0, 212, 255, 0.08)",
        rogue: "0 0 0 1px rgba(255, 68, 68, 0.3), 0 0 35px rgba(255, 68, 68, 0.12)",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "sans-serif"],
        mono: ["var(--font-jetbrains)", "monospace"],
      },
      keyframes: {
        pulseBorder: {
          "0%, 100%": { boxShadow: "0 0 0 1px rgba(255, 68, 68, 0.25)" },
          "50%": { boxShadow: "0 0 0 1px rgba(255, 68, 68, 0.7), 0 0 25px rgba(255, 68, 68, 0.25)" },
        },
      },
      animation: {
        pulseBorder: "pulseBorder 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
