<script setup lang="ts">
/**
 * 审计（内核出站事件）。
 *
 * ⚠ 控制面事件（`GUARD:` / `BOOT:` 前缀）默认**单独过滤掉**：
 * 它们不是真实连接，`src` 是 `127.0.0.1:0`，混在数据面里会让核对证据的人看不懂，
 * 也会让"今天丢了多少包"这个数字虚高。
 */

import { computed, ref } from 'vue';
import { useStatusStore } from '../stores/status';
import { auditRows } from '../data/mock';
import { num } from '../utils/format';

const status = useStatusStore();

const hideControlPlane = ref(true);

const CONTROL_PREFIXES = ['GUARD:', 'BOOT:'];

function isControlPlane(rule: string) {
  return CONTROL_PREFIXES.some((p) => rule.startsWith(p));
}

const rows = computed(() =>
  hideControlPlane.value ? auditRows.filter((r) => !isControlPlane(r.rule)) : auditRows,
);

const controlCount = computed(() => auditRows.filter((r) => isControlPlane(r.rule)).length);
</script>

<template>
  <div class="space-y-6">
    <section class="surface-card rise-in">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">审计</div>
          <div class="mt-1 text-sm text-text-muted">
            守护进程累计 {{ num(status.snapshot.audit_len) }} 条
          </div>
        </div>
        <label class="flex items-center gap-2 text-xs text-text-muted cursor-pointer select-none">
          <input v-model="hideControlPlane" type="checkbox" class="rounded" />
          隐藏控制面事件（{{ controlCount }} 条）
        </label>
      </div>

      <div class="overflow-x-auto -mx-2">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-[11px] uppercase tracking-wider text-text-muted">
              <th class="px-2 py-2 font-medium">#</th>
              <th class="px-2 py-2 font-medium">时间</th>
              <th class="px-2 py-2 font-medium">动作</th>
              <th class="px-2 py-2 font-medium">源</th>
              <th class="px-2 py-2 font-medium">目的</th>
              <th class="px-2 py-2 font-medium">命中规则</th>
              <th class="px-2 py-2 font-medium">进程</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in rows"
              :key="r.seq"
              class="border-t border-border/40 hover:bg-surface-hover/40 transition-colors"
            >
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">{{ r.seq }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">{{ r.time }}</td>
              <td class="px-2 py-2.5">
                <span
                  class="px-1.5 py-0.5 rounded-pill text-[10px] font-medium"
                  :style="{
                    background: `rgb(var(--${r.action === 'Drop' ? 'danger' : 'success'}) / 0.14)`,
                    color: `rgb(var(--${r.action === 'Drop' ? 'danger' : 'success'}))`,
                  }"
                >
                  {{ r.action === 'Drop' ? '阻断' : '放行' }}
                </span>
              </td>
              <td class="px-2 py-2.5 font-mono-num text-xs">{{ r.src }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs">{{ r.dst }}</td>
              <td class="px-2 py-2.5">
                <span :class="isControlPlane(r.rule) ? 'text-text-muted' : ''">{{ r.rule }}</span>
              </td>
              <td class="px-2 py-2.5 text-xs text-text-muted">{{ r.process }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="mt-4 text-xs text-text-muted leading-relaxed">
        骨架阶段这张表是样本数据，不是本机的真实连接记录。
        接真数据后这里应当支持按时间 / 规则 / 进程过滤，以及导出证据包
        （导出时控制面事件<strong class="font-medium">默认不导出</strong>）。
      </p>
    </section>
  </div>
</template>
