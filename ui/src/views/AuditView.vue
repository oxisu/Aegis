<script setup lang="ts">
/**
 * 审计（内核出站事件）。
 *
 * ⚠ 这一页**目前没有数据源**：`Status` 只给审计链的**长度**
 * （`audit_len`），不给逐条事件。要填这张表得新增一个查询请求。
 * 界面不能自己造协议，所以这里宁可是空的。
 *
 * 另外记一条将来一定用得上的规则：控制面事件（`GUARD:` / `BOOT:` 前缀）
 * 导出时要**过滤掉**。它们不是真实连接，`src` 是 `127.0.0.1:0`，
 * 混在数据面里会让核对证据的人看不懂，也会让"今天丢了多少包"虚高。
 */

import { useStatusStore } from '../stores/status';
import { num } from '../utils/format';
import type { AuditRow } from '../types';

const status = useStatusStore();

/** 接上数据源之前恒为空。别在这里塞假数据——见文件头。 */
const rows: AuditRow[] = [];
</script>

<template>
  <div class="space-y-6">
    <section class="surface-card rise-in">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">审计</div>
          <div class="mt-1 text-sm text-text-muted">
            守护进程累计
            <span class="font-mono-num">{{ num(status.snapshot?.audit_len ?? 0) }}</span> 条
          </div>
        </div>
      </div>

      <div class="overflow-x-auto -mx-2">
        <table class="data-table">
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
            <tr v-for="r in rows" :key="r.seq" class="border-t border-border">
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">{{ r.seq }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">{{ r.time }}</td>
              <td class="px-2 py-2.5 text-xs">{{ r.action }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs">{{ r.src }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs">{{ r.dst }}</td>
              <td class="px-2 py-2.5 text-xs">{{ r.rule }}</td>
              <td class="px-2 py-2.5 text-xs text-text-muted">{{ r.process }}</td>
            </tr>
            <tr v-if="rows.length === 0">
              <td colspan="7" class="px-2 py-8 text-center">
                <div class="text-sm" style="color: rgb(var(--warning))">还没有数据源</div>
                <p class="mt-2 text-xs text-text-muted leading-relaxed max-w-xl mx-auto">
                  <code class="font-mono-num">Status</code> 只报审计链的<strong
                    class="font-medium"
                    >长度</strong
                  >，不报明细。要填这张表，得给守护进程加一个审计查询请求。
                  接上时记得把控制面事件（<code class="font-mono-num">GUARD:</code> /
                  <code class="font-mono-num">BOOT:</code> 前缀）默认过滤掉。
                </p>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="mt-4 text-xs text-text-muted leading-relaxed">
        接上数据后这里应当支持按时间 / 规则 / 进程过滤，以及导出证据包
        （导出时控制面事件<strong class="font-medium">默认不导出</strong>）。
      </p>
    </section>
  </div>
</template>
