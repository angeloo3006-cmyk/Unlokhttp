/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx,js,jsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        ui:   ["Syne", "sans-serif"],
      },
      fontWeight: {
        700: "700",
      },
      colors: {
        background:     "hsl(var(--background))",
        surface:        "hsl(var(--surface))",
        foreground:     "hsl(var(--foreground))",
        accent:         "hsl(var(--accent))",
        border:         { dim: "hsl(var(--border))", bright: "hsl(var(--border-bright))" },
        "muted-foreground": "hsl(var(--muted-foreground))",
        danger:         "hsl(var(--danger))",
        success:        "hsl(var(--success))",
        warning:        "hsl(var(--warning))",
      },
      borderRadius: {
        DEFAULT: "var(--radius)",
        md: "var(--radius)",
        sm: "calc(var(--radius) - 2px)",
      },
    },
  },
  plugins: [],
};
