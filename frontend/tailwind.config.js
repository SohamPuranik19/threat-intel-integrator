module.exports = {
  content: [
    './src/app/**/*.{js,ts,jsx,tsx}',
    './src/components/**/*.{js,ts,jsx,tsx}',
    './src/pages/**/*.{js,ts,jsx,tsx}',
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
        light: '#f0f3ff',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
      },
      backgroundImage: {
        'gradient-dark': 'linear-gradient(135deg, rgba(0, 217, 255, 0.06) 0%, rgba(255, 0, 110, 0.03) 100%)',
      }
    }
  },
  plugins: [],
}
