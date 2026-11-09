/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        risk: {
          low: "#10b981",         // Muted Green
          suspicious: "#f59e0b",  // Amber
          high: "#ea580c",        // Orange-Red
          malicious: "#b91c1c",   // Dark Red
          inconclusive: "#64748b" // Grey
        }
      }
    },
  },
  plugins: [],
}
