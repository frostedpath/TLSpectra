/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    screens: {
      'sm': '360px',   // Mobile: 360–767px
      'md': '768px',   // Tablet: 768–1023px
      'lg': '1024px',  // Laptop: 1024–1439px
      'xl': '1440px',  // Desktop: 1440px+
    },
    extend: {
      colors: {
        primary: {
          DEFAULT: '#2357D6',
          hover: '#1D4ED8',
          light: '#EFF6FF',
        },
        secondary: {
          DEFAULT: '#0F766E',
          hover: '#115E59',
          light: '#CCFBF1',
        },
        accent: {
          DEFAULT: '#7C3AED',  // ML/Anomaly accent
          hover: '#6D28D9',
          light: '#F5F3FF',
        },
        background: '#F6F8FB',
        surface: '#FFFFFF',
        elevated: '#F8FAFC',
        border: '#D8DEE8',
        textPrimary: '#111827',
        textSecondary: '#4B5563',
        muted: '#6B7280',
        semantic: {
          success: '#15803D',
          warning: '#B45309',
          error: '#B91C1C',
          info: '#2563EB',
          unknown: '#64748B',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        sm: '4px',
        DEFAULT: '6px',
        md: '8px',
        lg: '12px',
      },
      boxShadow: {
        L0: 'none',
        L1: '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)',
        L2: '0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.08)',
        L3: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)',
      }
    },
  },
  plugins: [],
}
