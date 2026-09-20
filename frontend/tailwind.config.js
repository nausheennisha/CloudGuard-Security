/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}", "./public/index.html"],
  theme: {
    extend: {
      colors: {
        cg: {
          bg: "#0a0e14",
          panel: "#0f1420",
          panel2: "#161d2b",
          border: "#232c3d",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#38bdf8",
          info: "#64748b",
          accent: "#f0b429",
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
        sans: ["'Inter'", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
      },
    },
  },
  plugins: [],
};
