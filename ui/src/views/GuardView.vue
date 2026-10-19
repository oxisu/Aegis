<script setup lang="ts">
/**
 * 守卫页 —— 断网时给人看的第一屏。
 *
 * ⚠ 这一页的**唯一任务**是让人在 5 秒内明白：
 *   1. 断网是 Aegis 干的，不是网线掉了、不是校园网崩了；
 *   2. 它凭什么这么干（reason 全文，不截断）；
 *   3. 现在该怎么办。
 * 做不到这三点，用户的下一步就是卸载。
 *
 * 三条不能写错的语义（与 `docs/DOWNSTREAM-GUARD.md` 同源）：
 *   · 收紧 = **撤销已下发的放行**，不是新增拒绝规则；
 *   · `unknown`（判不了）按设计**永不收紧**——"判不了 ≠ 通过"；
 *   · `needs_human` 一旦置上**不自动清除**，只能人工确认。
 */

import { computed } from 'vue';
import {
  CheckCircleIcon,
  CommandLineIcon,
  ExclamationTriangleIcon,
  QuestionMarkCircleIcon,
} from '@heroicons/vue/24/outline';
import { useStatusStore } from '../stores/status';
import DaemonUnreachable from '../components/DaemonUnreachable.vue';
import { guardVerdictClass, guardVerdictText } from '../utils/format';

const status = useStatusStore();
const g = computed(() => status.snapshot?.guard);

const VERDICT_ICON = {
  effective: CheckCircleIcon,
  ineffective: ExclamationTriangleIcon,
  unknown: QuestionMarkCircleIcon,
  off: QuestionMarkCircleIcon,
} as const;

const icon = computed(() =>
  g.value ? (VERDICT_ICON[g.value.verdict as keyof typeof VERDICT_ICON] ?? QuestionMarkCircleIcon) : QuestionMarkCircleIcon,
);

const facts = computed(() => {
  if (!g.value) return [];
  return [
    {
      label: '已收紧放行',
      on: g.value.tightened,
      yes: '放行票据已挂起（permits_suspended）',
      no: '没有挂起任何放行',
      note: '收紧 = 撤销已下发的放行，**不是**新增拒绝规则。',
    },
    {
      label: '等人工处理',
      on: g.value.needs_human,
      yes: '已停止自动动作',
      no: '仍在自动动作',
      note: '一旦置上不会自动清除 —— 只能人确认。',
    },
  ];
});

/**
 * 危险命令的提示。
 *
 * ⚠ 这里**故意不画按钮**：`aegis_ipc::peer::Risk::Dangerous`（apply/confirm/rollback）
 * 要求**对端进程已提权**，而界面按设计不提权，所以从界面里根本发不出去。
 * 画一个按钮就是"点了没反应"——危险操作一旦看起来能点，
 * 人就会以为已经恢复了。给命令让人去管理员终端跑，才是真的能走通的路。
 */
const DANGEROUS_HINT = [
  { word: 'rollback', what: '立即拆除绝缘笼（恢复网络）' },
  { word: 'apply', what: '下发绝缘笼；10 秒内要再跑 confirm，否则自动撤销' },
];
</script>

<template>
  <div class="space-y-6">
    <DaemonUnreachable v-if="!status.connected" />

    <template v-if="g">
      <!-- 结论 -->
      <section class="surface-card rise-in">
        <div class="flex items-start gap-4">
          <component
            :is="icon"
            class="w-9 h-9 flex-shrink-0 mt-0.5"
            :class="guardVerdictClass(g.verdict)"
          />
          <div class="min-w-0 flex-1">
            <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">
              守卫结论
            </div>
            <div class="mt-1 text-2xl font-semibold" :class="guardVerdictClass(g.verdict)">
              {{ guardVerdictText(g.verdict) }}
            </div>

            <!-- ⚠ reason 不截断：它是"凭什么断我网"的唯一凭据 -->
            <p
              class="mt-3 text-sm leading-relaxed selectable"
              :class="g.tightened ? '' : 'text-text-muted'"
            >
              {{ g.reason || '（守护进程没有给出原因）' }}
            </p>
          </div>
        </div>
      </section>

      <!-- 事实 -->
      <section class="grid md:grid-cols-2 gap-4">
        <div v-for="f in facts" :key="f.label" class="surface-card rise-in">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium">{{ f.label }}</span>
            <span
              class="px-2 py-0.5 rounded-pill text-xs font-medium"
              :style="{
                background: `rgb(var(--${f.on ? 'danger' : 'success'}) / 0.14)`,
                color: `rgb(var(--${f.on ? 'danger' : 'success'}))`,
              }"
            >
              {{ f.on ? f.yes : f.no }}
            </span>
          </div>
          <p class="mt-2 text-xs text-text-muted leading-relaxed">{{ f.note }}</p>
        </div>
      </section>
    </template>

    <!-- 「判不了 ≠ 通过」——这条最容易被误读，单独讲 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        三种结论分别是什么意思
      </div>
      <dl class="space-y-3 text-sm">
        <div class="flex gap-3">
          <dt class="w-28 flex-shrink-0 font-medium text-guard-effective">生效</dt>
          <dd class="text-text-muted">下游规则确实在工作，放行照常。</dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-28 flex-shrink-0 font-medium text-guard-ineffective">未生效</dt>
          <dd class="text-text-muted">
            下游规则没起作用 → 已收紧放行。这是<strong class="font-medium">正在断网</strong>的状态。
          </dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-28 flex-shrink-0 font-medium text-guard-unknown">判不了</dt>
          <dd class="text-text-muted">
            守卫拿不到判据（比如没配
            <code class="font-mono-num text-xs">control_addr</code>）。
            按设计<strong class="font-medium">不动手</strong>：判不了 ≠ 通过。
          </dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-28 flex-shrink-0 font-medium text-guard-off">未启用</dt>
          <dd class="text-text-muted">老版本守护进程没上报守卫字段，或守卫未配置。</dd>
        </div>
      </dl>
    </section>

    <!-- 危险操作：给命令，不给按钮 -->
    <section class="surface-card rise-in">
      <div class="flex items-center gap-2 mb-3">
        <CommandLineIcon class="w-5 h-5 text-text-muted flex-shrink-0" />
        <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">
          要动手，请用管理员终端
        </div>
      </div>
      <p class="text-xs text-text-muted leading-relaxed">
        <strong class="font-medium">界面里没有"解除收紧"按钮，这是权限模型决定的</strong>：
        <code class="font-mono-num">apply</code> /
        <code class="font-mono-num">confirm</code> /
        <code class="font-mono-num">rollback</code>
        属于 <code class="font-mono-num">Risk::Dangerous</code>，
        守护进程要求对端进程<strong class="font-medium">已提权</strong>；
        而界面按设计不提权，所以发得出去才不正常。
        画一个按钮只会得到"点了没反应"，而人会以为什么都没做就已经恢复了。
      </p>
      <ul class="mt-3 space-y-2">
        <li v-for="d in DANGEROUS_HINT" :key="d.word" class="text-xs">
          <code
            class="code-chip"
            >aegisctl {{ d.word }} --token-file &lt;路径&gt;</code
          >
          <span class="ml-2 text-text-muted">{{ d.what }}</span>
        </li>
      </ul>
      <p class="mt-3 text-xs text-text-muted leading-relaxed">
        token 文件路径见设置页；不写 <code class="font-mono-num">--token-file</code>
        时默认取 <code class="font-mono-num">&lt;data-dir&gt;/ipc.token</code>。
      </p>
    </section>
  </div>
</template>
