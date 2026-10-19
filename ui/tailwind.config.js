/** @type {import('tailwind.config').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg: 'rgb(var(--bg) / <alpha-value>)',
        surface: {
          DEFAULT: 'rgb(var(--surface) / <alpha-value>)',
          hover: 'rgb(var(--surface-hover) / <alpha-value>)',
        },
        border: 'rgb(var(--border) / <alpha-value>)',
        text: {
          DEFAULT: 'rgb(var(--text) / <alpha-value>)',
          muted: 'rgb(var(--text-muted) / <alpha-value>)',
        },
        primary: {
          DEFAULT: 'rgb(var(--primary) / <alpha-value>)',
          hover: 'rgb(var(--primary-hover) / <alpha-value>)',
          light: 'rgb(var(--primary-light) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
          text: 'rgb(var(--accent-text) / <alpha-value>)',
          secondary: 'rgb(var(--accent-secondary) / <alpha-value>)',
        },
        success: 'rgb(var(--success) / <alpha-value>)',
        warning: 'rgb(var(--warning) / <alpha-value>)',
        danger: 'rgb(var(--danger) / <alpha-value>)',
        info: 'rgb(var(--info) / <alpha-value>)',

        // ── Aegis 独有语义色 ──────────────────────────────────────
        // 绝缘等级（design-spec.md §26 状态机）与守卫状态
        // （docs/DOWNSTREAM-GUARD.md）。进 Tailwind 色板是为了让页面只能写
        // `text-guard-ineffective`，写不出 `text-red-500` —— 后者会绕过
        // "危险程度由令牌统一定义"这条规矩。
        lv: {
          isolated: 'rgb(var(--lv-isolated) / <alpha-value>)',
          campus: 'rgb(var(--lv-campus) / <alpha-value>)',
          free: 'rgb(var(--lv-free) / <alpha-value>)',
          aggregated: 'rgb(var(--lv-aggregated) / <alpha-value>)',
          unknown: 'rgb(var(--lv-unknown) / <alpha-value>)',
        },
        guard: {
          effective: 'rgb(var(--guard-effective) / <alpha-value>)',
          ineffective: 'rgb(var(--guard-ineffective) / <alpha-value>)',
          unknown: 'rgb(var(--guard-unknown) / <alpha-value>)',
          off: 'rgb(var(--guard-off) / <alpha-value>)',
        },
      },
      borderRadius: {
        // 扁平体系：比参考项目小一档，要精密感
        card: '14px',
        element: '10px',
        pill: '999px',
      },
      fontFamily: {
        // Aegis 是 Windows-only 桌面程序，字体栈以 Segoe UI 打头
        sans: [
          '"Segoe UI"',
          'system-ui',
          '-apple-system',
          '"PingFang SC"',
          '"Microsoft YaHei"',
          '"Noto Sans SC"',
          'sans-serif',
        ],
        mono: ['"Cascadia Mono"', 'ui-monospace', 'Consolas', 'Menlo', 'monospace'],
      },
      boxShadow: {
        // 弹窗分层用。扁平体系里没有发光阴影，投影只服务于"谁在上面"
        panel: '0 4px 12px rgb(0 0 0 / 0.32), 0 16px 48px rgb(0 0 0 / 0.28)',
      },
    },
  },
  plugins: [],
};
