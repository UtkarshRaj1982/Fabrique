/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: 'class', // ✅ Enables class-based dark mode
  theme: {
    extend: {
      colors: {
        "rabbit-red": "#ea2e0e",
      },
    },
  },
  plugins: [],
};
