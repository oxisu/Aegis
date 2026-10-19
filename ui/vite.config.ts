import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// ── Tauri 相关（现在还没接，先把接缝留好）───────────────────────────
//
// `TAURI_ENV_*` 由 `@tauri-apps/cli` 注入。现在纯浏览器开发时它们不存在，
// 配置会退化成"普通 Vite 站点"，行为一致。
//
// ⚠ `build.target` 取 chrome105 而不是 esnext：Tauri 在 Windows 上跑的是
// **WebView2**（Chromium 105+ 内核），用 esnext 会产出 WebView2 还不支持的
// 语法，表现为"dev 好好的、打包后白屏"——这类问题很难往 target 上想。
const tauriPlatform = process.env.TAURI_ENV_PLATFORM;
const tauriDebug = !!process.env.TAURI_ENV_DEBUG;
const tauriDevHost = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [vue()],

  // Tauri 的 CLI 自己管终端输出，Vite 清屏会把它的提示刷掉
  clearScreen: false,

  server: {
    port: 1420,
    strictPort: true,
    host: tauriDevHost || false,
    watch: { ignored: ['**/src-tauri/**'] },
  },

  // 只把这两类前缀的变量暴露给前端代码，避免把构建机环境变量漏进包里
  envPrefix: ['VITE_', 'TAURI_ENV_'],

  build: {
    target: tauriPlatform === 'windows' ? 'chrome105' : 'esnext',
    minify: tauriDebug ? false : 'esbuild',
    sourcemap: tauriDebug,
    outDir: 'dist',
    watch: tauriDevHost ? { ignored: ['**/src-tauri/**'] } : null,
  },
});
