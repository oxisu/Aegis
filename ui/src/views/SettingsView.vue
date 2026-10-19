<script setup lang="ts">
/**
 * 设置。
 *
 * ⚠ 这一页**故意没有**任何"看起来能改、改了不生效"的控件。
 * 只放三样真东西：主题（纯前端，改了立刻生效）、端点信息（排障）、
 * 关于信息。把未实现的开关画出来，是让人以为自己已经配置过了，
 * 那比没有开关更危险。
 */

import { Disclosure, DisclosureButton, DisclosurePanel } from '@headlessui/vue';
import { ChevronDownIcon } from '@heroicons/vue/24/outline';
import { useTheme } from '../composables/useTheme';
import { useStatusStore } from '../stores/status';
import { UI_VERSION } from '../version';

const { theme, themes, apply } = useTheme();
const status = useStatusStore();

const REPO = 'https://github.com/oxisu/Aegis';

/** 还没接线的事。每条都写清"差在哪一步"，不写"敬请期待"这种空话。 */
const TODO = [
  {
    title: '网卡明细表',
    body: 'Status 只给物理网卡的数量，不给逐张明细。要填那张表得先给状态文档加字段，或新增一个 topology 请求。',
  },
  {
    title: '审计明细表',
    body: 'Status 只给审计链长度。要填那张表得新增一个审计查询请求；接上时控制面事件（GUARD: / BOOT:）要默认过滤。',
  },
  {
    title: '打包与签名',
    body: 'Tauri 外壳能编译能跑，但还没配图标与安装包签名。签名不做的话 SmartScreen 会拦。',
  },
];
</script>

<template>
  <div class="space-y-6">
    <!-- 端点信息：排障时最想知道的就是"它到底在连哪儿" -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        连接端点
      </div>
      <dl v-if="status.endpoint" class="text-sm space-y-2">
        <div class="flex gap-3">
          <dt class="w-24 flex-shrink-0 text-text-muted">管道</dt>
          <dd class="font-mono-num text-xs selectable break-all">{{ status.endpoint.pipe }}</dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-24 flex-shrink-0 text-text-muted">token 文件</dt>
          <dd class="font-mono-num text-xs selectable break-all">
            {{ status.endpoint.token_file }}
          </dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-24 flex-shrink-0 text-text-muted">文件存在</dt>
          <dd :class="status.endpoint.token_file_present ? 'text-success' : 'text-danger'">
            {{ status.endpoint.token_file_present ? '是' : '否' }}
          </dd>
        </div>
      </dl>
      <p v-else class="text-xs text-text-muted">（端点信息还没取到）</p>
      <p class="mt-3 text-xs text-text-muted leading-relaxed">
        两者都可用环境变量覆盖：<code class="font-mono-num text-[11px]">AEGIS_PIPE</code> 与
        <code class="font-mono-num text-[11px]">AEGIS_TOKEN_FILE</code>。
        守护进程允许用 <code class="font-mono-num text-[11px]">--pipe</code> /
        <code class="font-mono-num text-[11px]">--data-dir</code> 换到别处，
        所以界面这边不能把路径写死。
      </p>
    </section>

    <!-- 主题 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        外观
      </div>
      <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
        <button
          v-for="t in themes"
          :key="t.key"
          class="opt-btn"
          :class="theme === t.key ? 'opt-btn-on' : ''"
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
          <div class="rounded-element overflow-hidden" style="border: 1px solid rgb(var(--border))">
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
        经命名管道通信并用 token 鉴权。也正因为不提权，
        <code class="font-mono-num text-[11px]">apply</code> /
        <code class="font-mono-num text-[11px]">rollback</code> 这类危险命令
        从界面里发不出去 —— 那是设计，不是缺陷。
      </p>
    </section>
  </div>
</template>
