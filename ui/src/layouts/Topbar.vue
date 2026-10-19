<script setup lang="ts">
/**
 * 顶栏。
 *
 * 右侧三件事按"人为什么要看它"排：
 *   1. 连接状态 —— 连不上守护进程时，界面上所有数字都是过期的，必须先知道；
 *   2. 假数据场景切换 —— 骨架阶段用来看每种状态长什么样（接真数据后整块删掉）；
 *   3. 主题 —— 纯外观，放最后。
 */

import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import { Bars3Icon, SwatchIcon } from '@heroicons/vue/24/outline';
import { NAV } from '../router';
import { useTheme } from '../composables/useTheme';
import { useStatusStore } from '../stores/status';
import type { Scenario } from '../stores/status';
import { MOCK } from '../data/mock';

const emit = defineEmits<{ toggleSidebar: [] }>();

const route = useRoute();
const { theme, themes, apply } = useTheme();
const status = useStatusStore();

const showThemeMenu = ref(false);
const showScenarioMenu = ref(false);
const themeMenuRef = ref<HTMLElement | null>(null);
const scenarioMenuRef = ref<HTMLElement | null>(null);

const pageTitle = computed(() => NAV.find((n) => n.path === route.path)?.title ?? 'Aegis');

const currentThemeLabel = computed(
  () => themes.find((t) => t.key === theme.value)?.label ?? 'Aegis',
);

const SCENARIOS: { key: Scenario; label: string; hint: string }[] = [
  { key: 'steady', label: '稳态', hint: '守卫判不了，未收紧' },
  { key: 'tightened', label: '已收紧', hint: '放行已撤销 —— 正在断网' },
  { key: 'needsHuman', label: '等人工', hint: '已停止自动动作' },
];

const currentScenarioLabel = computed(
  () => SCENARIOS.find((s) => s.key === status.scenario)?.label ?? '稳态',
);

function timeText(d: Date) {
  return d.toLocaleTimeString('zh-CN', { hour12: false });
}

function handleClickOutside(e: MouseEvent) {
  const t = e.target as Node;
  if (themeMenuRef.value && !themeMenuRef.value.contains(t)) showThemeMenu.value = false;
  if (scenarioMenuRef.value && !scenarioMenuRef.value.contains(t)) showScenarioMenu.value = false;
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
      <!-- 连接状态。⚠ 连不上时所有数字都是过期的，这是最该先看到的东西。 -->
      <span
        class="flex items-center gap-1.5 px-2.5 py-1 rounded-pill text-xs font-medium"
        :style="{
          border: `1px solid rgb(var(--${status.connected ? 'success' : 'danger'}) / 0.28)`,
          background: `rgb(var(--${status.connected ? 'success' : 'danger'}) / 0.12)`,
          color: `rgb(var(--${status.connected ? 'success' : 'danger'}))`,
        }"
        :title="status.connected ? '已连上守护进程' : '连不上守护进程 —— 下面的数字可能是过期的'"
      >
        <span
          class="w-2 h-2 rounded-full"
          :class="{ 'animate-pulse': !status.connected }"
          :style="{
            background: `rgb(var(--${status.connected ? 'success' : 'danger'}))`,
          }"
        />
        <span class="hidden sm:inline">{{ status.connected ? '已连接' : '未连接' }}</span>
      </span>

      <span class="hidden md:inline text-xs text-text-muted font-mono-num">
        {{ timeText(status.lastUpdated) }}
      </span>

      <!-- 假数据场景切换（MOCK 为 false 后整块消失） -->
      <div v-if="MOCK" class="relative" ref="scenarioMenuRef">
        <button
          class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-pill text-xs font-medium transition-all"
          style="
            border: 1px solid rgb(var(--warning) / 0.28);
            background: rgb(var(--warning) / 0.1);
            color: rgb(var(--warning));
          "
          title="骨架阶段切换场景 —— 接真数据后这里换成刷新"
          @click.stop="showScenarioMenu = !showScenarioMenu"
        >
          <span class="w-2 h-2 rounded-full" style="background: rgb(var(--warning))" />
          假数据 · {{ currentScenarioLabel }}
        </button>

        <Transition name="dropdown">
          <div
            v-if="showScenarioMenu"
            class="absolute right-0 top-full mt-2 w-64 popover-panel p-2 z-50"
            @click.stop
          >
            <div class="px-2 py-1 text-[11px] font-medium text-text-muted uppercase tracking-wider">
              场景
            </div>
            <button
              v-for="s in SCENARIOS"
              :key="s.key"
              class="w-full flex flex-col items-start gap-0.5 px-2.5 py-2 rounded-element text-sm transition-all"
              :class="status.scenario === s.key ? 'text-text' : 'text-text-muted hover:text-text'"
              :style="{
                background:
                  status.scenario === s.key ? 'rgb(var(--accent) / 0.14)' : 'transparent',
              }"
              @click="status.setScenario(s.key); showScenarioMenu = false"
            >
              <span>{{ s.label }}</span>
              <span class="text-[11px] text-text-muted">{{ s.hint }}</span>
            </button>
          </div>
        </Transition>
      </div>

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
                  background: theme === t.key ? 'rgb(var(--accent) / 0.14)' : 'transparent',
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
