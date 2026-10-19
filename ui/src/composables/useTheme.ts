/**
 * 主题切换。
 *
 * ⚠ 两个钩子必须**同时**改：
 *   1. `<html data-theme="...">` —— 决定所有 `--*` 令牌的取值（我们的主题）；
 *   2. `<html class="dark">`     —— 只给 Tailwind `dark:` 变体用。
 *
 * 只改其中一个的表现是：颜色变了但某些 `dark:` 样式没跟上（或反过来），
 * 而且是"部分组件"不对，很难往"漏了一个钩子"上想。
 *
 * 主题列表与取值见 `src/styles/main.css`。**没有 light/dark 模式**——
 * 每套主题自带明暗，颜色全部由 `[data-theme]` 决定。
 */

import { ref, watch } from 'vue';

export const THEMES = [
  { key: 'aegis', label: 'Aegis（默认）' },
  { key: 'aurora', label: 'Aurora · 极光' },
  { key: 'midnight', label: 'Midnight · 子夜' },
  { key: 'cyber', label: 'Cyber · 赛博' },
  { key: 'nothing', label: 'Nothing · 极简' },
] as const;

export type ThemeKey = (typeof THEMES)[number]['key'];

const STORAGE_KEY = 'aegis.theme';
const root = document.documentElement;

function load(): ThemeKey {
  const saved = localStorage.getItem(STORAGE_KEY);
  const hit = THEMES.find((t) => t.key === saved);
  return hit ? hit.key : 'aegis';
}

const current = ref<ThemeKey>(load());

export function useTheme() {
  function apply(key: ThemeKey) {
    root.setAttribute('data-theme', key);
    // 全部主题都是深底浅字，所以 dark 恒为 true —— 保留这个 class 是为了
    // 让 Tailwind 的 `dark:` 变体可预测地命中，而不是"碰巧"。
    root.classList.add('dark');
    localStorage.setItem(STORAGE_KEY, key);
  }

  watch(current, apply, { immediate: true });

  return { theme: current, themes: THEMES, apply };
}
