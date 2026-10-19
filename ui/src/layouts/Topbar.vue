<script setup lang="ts">
/**
 * 顶栏。
 *
 * 右侧按"人为什么要看它"排：
 *   1. 连接状态 —— 连不上守护进程时，界面上所有数字都是过期的，必须先知道；
 *   2. 主题 —— 纯外观，放最后。
 *
 * ⚠ 这里**没有**手动刷新按钮：状态是轮询来的（1.5s），
 * 放一个刷新按钮会让人以为"不点就不更新"，也会让人以为点一下就能连上。
 */

import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import { Bars3Icon, SwatchIcon } from '@heroicons/vue/24/outline';
import { NAV } from '../router';
import { useTheme } from '../composables/useTheme';
import { useStatusStore } from '../stores/status';

const emit = defineEmits<{ toggleSidebar: [] }>();

const route = useRoute();
const { theme, themes, apply } = useTheme();
const status = useStatusStore();

const showThemeMenu = ref(false);
const themeMenuRef = ref<HTMLElement | null>(null);

const pageTitle = computed(() => NAV.find((n) => n.path === route.path)?.title ?? 'Aegis');

const currentThemeLabel = computed(
  () => themes.find((t) => t.key === theme.value)?.label ?? 'Aegis',
);

/** 连接状态的标签。⚠ "过期"和"未连接"是两回事，不能合成一个红点。 */
const connLabel = computed(() => {
  if (status.connected) return '已连接';
  return status.stale ? '已断开（显示旧值）' : '未连接';
});

function timeText(d: Date) {
  return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function handleClickOutside(e: MouseEvent) {
  const t = e.target as Node;
  if (themeMenuRef.value && !themeMenuRef.value.contains(t)) showThemeMenu.value = false;
}

onMounted(() => document.addEventListener('click', handleClickOutside));
onUnmounted(() => document.removeEventListener('click', handleClickOutside));
</script>

<template>
  <header
    class="h-16 flex items-center justify-between px-6 border-b border-border/40 panel sticky top-0 z-40"
  >
    <div class="flex items-center gap-4">
      <button
        class="lg:hidden p-2 rounded-element text-text-muted hover:bg-surface-hover hover:text-text transition-colors"
        @click="emit('toggleSidebar')"
      >
        <Bars3Icon class="w-5 h-5" />
      </button>
      <div>
        <div
          class="text-[10px] font-bold tracking-[0.13em] uppercase"
          style="color: rgb(var(--accent-text))"
        >
          Aegis
        </div>
        <h1 class="text-lg font-semibold leading-tight">{{ pageTitle }}</h1>
      </div>
    </div>

    <div class="flex items-center gap-2">
      <!-- 连接状态。⚠ 连不上时所有数字都是过期的，这是最该先看到的东西。
           颜色配文字，不单靠色点。 -->
      <span
        class="pill"
        :class="status.connected ? 'pill-ok' : 'pill-err'"
        :title="status.connected ? '已连上守护进程' : (status.error || '连不上守护进程')"
      >
        <span
          class="w-1.5 h-1.5 rounded-full bg-current"
          :class="{ 'animate-pulse': !status.connected }"
        />
        <span class="hidden sm:inline">{{ connLabel }}</span>
      </span>

      <span
        v-if="status.lastUpdated"
        class="hidden md:inline text-xs text-text-muted font-mono-num"
        :title="status.stale ? '这是最后一次成功取到状态的时间' : '最近一次刷新'"
      >
        {{ timeText(status.lastUpdated) }}
      </span>

      <!-- 主题 -->
      <div class="relative" ref="themeMenuRef">
        <button
          class="p-2.5 rounded-pill text-text-muted hover:bg-white/10 hover:text-text transition-all duration-150"
          :title="`当前主题：${currentThemeLabel}`"
          @click.stop="showThemeMenu = !showThemeMenu"
        >
          <SwatchIcon class="w-5 h-5" />
        </button>

        <Transition name="dropdown">
          <div
            v-if="showThemeMenu"
            class="absolute right-0 top-full mt-2 w-56 popover-panel p-3 z-50"
            @click.stop
          >
            <div class="text-[11px] font-medium text-text-muted uppercase tracking-wider mb-2 px-1">
              主题 · {{ themes.length }} 套
            </div>
            <div class="space-y-1.5 px-1">
              <button
                v-for="t in themes"
                :key="t.key"
                class="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-element text-sm transition-all"
                :class="theme === t.key ? 'text-text' : 'text-text-muted hover:text-text'"
                :style="{
                  background: theme === t.key ? 'var(--accent-bg)' : 'transparent',
                  border: `1px solid ${theme === t.key ? 'var(--accent-border)' : 'transparent'}`,
                }"
                @click="apply(t.key)"
              >
                <span class="flex-1 text-left">{{ t.label }}</span>
                <span
                  v-if="theme === t.key"
                  class="text-xs"
                  style="color: rgb(var(--accent-text))"
                  >✓</span
                >
              </button>
            </div>
          </div>
        </Transition>
      </div>
    </div>
  </header>
</template>

<style scoped>
.dropdown-enter-active,
.dropdown-leave-active {
  transition:
    opacity 0.15s ease,
    transform 0.15s ease;
}
.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
