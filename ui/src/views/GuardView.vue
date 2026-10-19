<script setup lang="ts">
/**
 * 守卫页 —— 断网时给人看的第一屏。
 *
 * ⚠ 这一页的**唯一任务**是让人在 5 秒内明白：
 *   1. 断网是 Aegis 干的，不是网线掉了、不是校园网崩了；
 *   2. 它凭什么这么干（reason 全文，不截断）；
 *   3. 现在该点哪个按钮。
 * 做不到这三点，用户的下一步就是卸载。
 *
 * 三条不能写错的语义（与 `docs/DOWNSTREAM-GUARD.md` 同源）：
 *   · 收紧 = **撤销已下发的放行**，不是新增拒绝规则；
 *   · `unknown`（判不了）按设计**永不收紧**——"判不了 ≠ 通过"；
 *   · `needs_human` 一旦置上**不自动清除**，只能人工确认。
 */

import { computed } from 'vue';
import { CheckCircleIcon, ExclamationTriangleIcon, QuestionMarkCircleIcon } from '@heroicons/vue/24/outline';
import { useStatusStore } from '../stores/status';
import { guardVerdictClass, guardVerdictText } from '../utils/format';

const status = useStatusStore();
const g = computed(() => status.snapshot.guard);

const VERDICT_ICON = {
  effective: CheckCircleIcon,
  ineffective: ExclamationTriangleIcon,
  unknown: QuestionMarkCircleIcon,
  off: QuestionMarkCircleIcon,
} as const;

const icon = computed(() => VERDICT_ICON[g.value.verdict] ?? QuestionMarkCircleIcon);

const facts = computed(() => [
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
]);
</script>

<template>
  <div class="space-y-6">
    <!-- 结论 -->
    <section class="surface-card rise-in">
      <div class="flex items-start gap-4">
        <component :is="icon" class="w-9 h-9 flex-shrink-0 mt-0.5" :class="guardVerdictClass(g.verdict)" />
        <div class="min-w-0 flex-1">
          <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">
            守卫结论
          </div>
          <div class="mt-1 text-2xl font-semibold" :class="guardVerdictClass(g.verdict)">
            {{ guardVerdictText(g.verdict) }}
          </div>

          <!-- ⚠ reason 不截断：它是"凭什么断我网"的唯一凭据 -->
          <p class="mt-3 text-sm leading-relaxed selectable" :class="g.tightened ? '' : 'text-text-muted'">
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
            守卫拿不到判据（比如没配 <code class="font-mono-num text-xs">control_addr</code>）。
            按设计<strong class="font-medium">不动手</strong>：判不了 ≠ 通过。
          </dd>
        </div>
        <div class="flex gap-3">
          <dt class="w-28 flex-shrink-0 font-medium text-guard-off">未启用</dt>
          <dd class="text-text-muted">老版本守护进程没上报守卫字段，或守卫未配置。</dd>
        </div>
      </dl>
    </section>

    <!-- 操作。⚠ 骨架阶段全部禁用并写明原因，不做"点了没反应"的假按钮。 -->
    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">操作</div>
      <div class="flex flex-wrap gap-3">
        <button class="btn-danger" disabled title="骨架阶段未接 IPC：接上后需二次确认才会解除收紧">
          解除收紧
        </button>
        <button class="btn-secondary" disabled title="骨架阶段未接 IPC">
          重新核验下游规则
        </button>
      </div>
      <p class="mt-3 text-xs text-text-muted leading-relaxed">
        两个按钮都是禁用态，不是坏了 —— 骨架阶段还没接守护进程。
        <strong class="font-medium">不做"点了没反应"的假按钮</strong>：
        危险操作一旦看起来能点而实际不生效，人就会以为已经恢复了。
      </p>
    </section>
  </div>
</template>
