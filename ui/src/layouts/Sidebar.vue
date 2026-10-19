<script setup lang="ts">
/**
 * 左侧导航。
 *
 * 顺序取自 `router/index.ts` 的 `NAV`（守卫紧跟总览），这里不再重写一份——
 * 两处各写一遍的下场是"加了页面但导航里没有"，而且不会报错。
 */

import { computed } from 'vue';
import type { Component } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ClipboardDocumentListIcon,
  Cog6ToothIcon,
  ServerStackIcon,
  ShieldCheckIcon,
  Squares2X2Icon,
} from '@heroicons/vue/24/outline';
import { NAV } from '../router';
import { MOCK } from '../data/mock';
import { useStatusStore } from '../stores/status';

defineProps<{ collapsed: boolean }>();
const emit = defineEmits<{ toggle: [] }>();

const router = useRouter();
const route = useRoute();
const status = useStatusStore();

const ICONS: Record<string, Component> = {
  squares: Squares2X2Icon,
  shield: ShieldCheckIcon,
  sitemap: ServerStackIcon,
  list: ClipboardDocumentListIcon,
  cog: Cog6ToothIcon,
};

const items = computed(() => NAV.map((n) => ({ ...n, icon: ICONS[n.icon] })));

function isActive(path: string) {
  return route.path === path;
}
</script>

<template>
  <aside
    :class="[
      'h-screen border-r flex flex-col transition-all duration-300 flex-shrink-0 panel',
      collapsed ? 'w-[72px]' : 'w-[248px]',
    ]"
  >
    <!-- 标识 -->
    <div class="h-16 flex items-center px-5 border-b border-border/40">
      <div class="flex items-center gap-3 overflow-hidden">
        <div
          class="w-9 h-9 rounded-element flex items-center justify-center flex-shrink-0"
          style="
            background: linear-gradient(135deg, rgb(var(--accent)), rgb(var(--accent-secondary)));
          "
        >
          <ShieldCheckIcon class="w-5 h-5 text-white" />
        </div>
        <div v-if="!collapsed" class="whitespace-nowrap">
          <div class="font-semibold text-sm leading-tight">Aegis</div>
          <div class="text-[11px] text-text-muted">宙斯的神盾</div>
        </div>
      </div>
    </div>

    <!-- 导航 -->
    <nav class="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
      <button
        v-for="item in items"
        :key="item.path"
        :class="[
          'w-full flex items-center gap-3 px-3 py-2.5 rounded-element text-sm font-medium transition-all duration-200',
          isActive(item.path)
            ? 'nav-active'
            : 'text-text-muted hover:bg-surface-hover/60 hover:text-text',
        ]"
        @click="router.push(item.path)"
      >
        <span class="relative flex-shrink-0">
          <component :is="item.icon" class="w-5 h-5" />
          <!-- ⚠ 守卫项上的红点：只在"已收紧 / 等人工"时出现。
               没有它，断了网的人得挨个点才知道守卫在报警。 -->
          <span
            v-if="item.path === '/guard' && status.needsAttention"
            class="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full"
            style="background: rgb(var(--guard-ineffective))"
          />
        </span>

        <span v-if="!collapsed">{{ item.title }}</span>
      </button>
    </nav>

    <!-- 底部：假数据标记 + 折叠 -->
    <div class="p-2 border-t border-border/40 space-y-1">
      <div
        v-if="MOCK && !collapsed"
        class="px-3 py-2 rounded-element text-[11px] leading-snug"
        :style="{
          background: 'rgb(var(--warning) / 0.12)',
          border: '1px solid rgb(var(--warning) / 0.28)',
          color: 'rgb(var(--warning))',
        }"
      >
        <div class="font-semibold">假数据</div>
        <div class="text-text-muted">未接守护进程</div>
      </div>
      <button
        class="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-element text-text-muted hover:bg-surface-hover/60 hover:text-text transition-all duration-150"
        @click="emit('toggle')"
      >
        <component :is="collapsed ? ChevronRightIcon : ChevronLeftIcon" class="w-5 h-5" />
        <span v-if="!collapsed" class="text-sm">收起</span>
      </button>
    </div>
  </aside>
</template>
