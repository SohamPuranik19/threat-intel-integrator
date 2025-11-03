/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/app/**/*.{ts,tsx,js,jsx}',
    './src/components/**/*.{ts,tsx,js,jsx}'
  ],
  theme: {
    extend: {
      colors: {
        primary: '#00d9ff',
        secondary: '#ff006e',
        accent: '#3a86ff',
        success: '#06d6a0',
        warning: '#ffd60a',
        danger: '#ef476f',
        dark: '#0a0e27',
        light: '#f0f3ff'
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Space Mono', 'ui-monospace', 'monospace']
      }
    }
  },
  plugins: [],
};
