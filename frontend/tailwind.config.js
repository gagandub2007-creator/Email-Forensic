/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#f8fafc',
        foreground: '#0f172a',
        primary: {
          DEFAULT: '#2563eb',
          hover: '#1d4ed8'
        },
        border: '#e2e8f0',
        panel: '#ffffff',
        threat: {
          critical: '#dc2626',
          high: '#d97706',
          medium: '#0284c7',
          low: '#16a34a'
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
