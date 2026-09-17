/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                threat: {
                    phishing: "#ef4444",
                    suspicious: "#f97316",
                    safe: "#22c55e",
                    unknown: "#94a3b8",
                },
                surface: {
                    50: "#f8fafc",
                    100: "#0f172a",
                    200: "#1e293b",
                    300: "#334155",
                    400: "#475569",
                },
                brand: {
                    primary: "#3b82f6",
                    secondary: "#8b5cf6",
                    accent: "#06b6d4",
                },
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
            },
            animation: {
                'slide-in': 'slideIn 0.3s ease-out',
                'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
            },
            keyframes: {
                slideIn: {
                    '0%': { transform: 'translateY(-20px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' },
                },
                pulseGlow: {
                    '0%, 100%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.3)' },
                    '50%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.5)' },
                },
            },
        },
    },
    plugins: [],
}
