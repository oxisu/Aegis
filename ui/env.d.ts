/// <reference types="vite/client" />

// `.vue` 单文件组件的类型声明。
// 没有它，每个 `import X from './X.vue'` 都会被 TS 报"找不到模块"。
declare module '*.vue' {
  import type { DefineComponent } from 'vue';
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>;
  export default component;
}
