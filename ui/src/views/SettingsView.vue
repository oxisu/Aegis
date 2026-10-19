<script setup lang="ts">
/**
 * 设置。
 *
 * ⚠ 这一页**故意没有**任何"看起来能改、改了不生效"的控件。
 * 骨架阶段只放两样真东西：主题（纯前端，改了立刻生效）和关于信息。
 * 其余能力列在「还没接线」里——把未实现的开关画出来，是让人
 * 以为自己已经配置过了，那比没有开关更危险。
 */

import { Disclosure, DisclosureButton, DisclosurePanel } from '@headlessui/vue';
import { ChevronDownIcon } from '@heroicons/vue/24/outline';
import { useTheme } from '../composables/useTheme';
import { UI_VERSION } from '../version';

const { theme, themes, apply } = useTheme();

const REPO = 'https://github.com/oxisu/Aegis';

/** 还没接线的事。每条都写清"差在哪一步"，不写"敬请期待"这种空话。 */
const TODO = [
  {
    title: '接守护进程',
    body: '经命名管道 \\\\.\\pipe\\aegis-ctl 取 REQ_STATUS。浏览器开不了命名管道，所以要 Tauri 外壳（Rust 侧转发）。',
  },
  {
    title: '危险操作二次确认',
    body: '解除收紧 / 熔断这类操作要弹确认框，且按钮文案写明后果。目前按钮是禁用态。',
  },
  {
    title: '真实网卡表',
    body: '现在的表来自假数据。需要给 Status 加网卡字段，或新增一个 topology 请求 —— 界面不能自己造协议。',
  },
];
</script>

<template>
  <div class="space-y-6">
    <!-- 主题 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        外观
      </div>
      <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
        <button
          v-for="t in themes"
          :key="t.key"
          class="flex items-center gap-2.5 px-4 py-3 rounded-element text-sm text-left transition-all"
          :style="{
            background: theme === t.key ? 'rgb(var(--accent) / 0.14)' : 'rgb(var(--surface-hover))',
            border: `1px solid ${theme === t.key ? 'rgb(var(--accent) / 0.4)' : 'rgb(var(--border))'}`,
          }"
          @click="apply(t.key)"
        >
          <span class="flex-1">{{ t.label }}</span>
          <span v-if="theme === t.key" class="text-xs" style="color: rgb(var(--accent-text))"
            >✓</span
          >
        </button>
      </div>
      <p class="mt-3 text-xs text-text-muted leading-relaxed">
        每套主题自带明暗，没有独立的浅色/深色模式 —— 颜色全部由
        <code class="font-mono-num text-[11px]">[data-theme]</code> 决定。
      </p>
    </section>

    <!-- 还没接线 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        还没接线
      </div>
      <div class="space-y-2">
        <Disclosure v-for="item in TODO" :key="item.title" v-slot="{ open }">
          <div
            class="rounded-element overflow-hidden"
            style="border: 1px solid rgb(var(--border))"
          >
            <DisclosureButton
              class="w-full flex items-center gap-2 px-4 py-3 text-sm text-left hover:bg-surface-hover/40 transition-colors"
            >
              <ChevronDownIcon
                class="w-4 h-4 text-text-muted transition-transform flex-shrink-0"
                :class="open ? 'rotate-180' : ''"
              />
              <span class="font-medium">{{ item.title }}</span>
            </DisclosureButton>
            <DisclosurePanel class="px-4 pb-3 text-xs text-text-muted leading-relaxed">
              {{ item.body }}
            </DisclosurePanel>
          </div>
        </Disclosure>
      </div>
    </section>

    <!-- 关于 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        关于
      </div>
      <dl class="text-sm space-y-2">
        <div class="flex gap-3">
          <dt class="w-20 flex-shrink-0 text-text-muted">版本</dt>
          <dd class="font-mono-num">{{ UI_VERSION }}</dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-20 flex-shrink-0 text-text-muted">仓库</dt>
          <dd>
            <a
              :href="REPO"
              target="_blank"
              rel="noreferrer"
              class="underline"
              style="color: rgb(var(--accent-text))"
              >{{ REPO }}</a
            >
          </dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-20 flex-shrink-0 text-text-muted">许可</dt>
          <dd>AGPL-3.0</dd>
        </div>
      </dl>
      <p class="mt-4 text-xs text-text-muted leading-relaxed">
        界面层<strong class="font-medium">不提权</strong>：它只是个普通桌面窗口，
        所有特权动作都在 <code class="font-mono-num text-[11px]">aegisd</code> 里，
        经命名管道通信并用令牌鉴权。
      </p>
    </section>
  </div>
</template>
