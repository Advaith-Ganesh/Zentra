import type { Config } from 'tailwindcss';

/**
 * Zentra design tokens.
 *
 * Near-black ground, silver/white type, sharp geometry. Risk colours are
 * chosen for contrast against the dark surface and are always paired with a
 * text label and an icon, never used as the only signal.
 */
const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#08090b',
          900: '#0b0d10',
          850: '#101318',
          800: '#151920',
          750: '#1b2028',
          700: '#232932',
          600: '#2e3540',
          500: '#3d4552',
        },
        silver: {
          50: '#f7f8fa',
          100: '#eceef2',
          200: '#d7dbe2',
          300: '#b6bdc9',
          400: '#8e97a6',
          500: '#6b7484',
          600: '#4e5666',
        },
        risk: {
          low: '#3fbf87',
          'low-dim': '#173026',
          medium: '#e0b341',
          'medium-dim': '#33290f',
          high: '#e8813f',
          'high-dim': '#331e10',
          critical: '#e35d5d',
          'critical-dim': '#341518',
          unknown: '#7b8494',
          'unknown-dim': '#20242c',
        },
        accent: {
          DEFAULT: '#f2f4f7',
          muted: '#c4cad4',
        },
      },
      fontFamily: {
        sans: [
          'var(--font-sans)',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'SF Mono',
          'Menlo',
          'Consolas',
          'monospace',
        ],
      },
      borderRadius: {
        none: '0',
        sm: '2px',
        DEFAULT: '3px',
        md: '4px',
        lg: '6px',
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.06em' }],
      },
      letterSpacing: {
        brand: '0.24em',
        governance: '0.1em',
      },
      keyframes: {
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'none' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 180ms ease-out',
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins: [],
};

export default config;
