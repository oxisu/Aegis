<script setup lang="ts">
/**
 * 网卡与角色。
 *
 * ⚠ 这一页**目前没有数据源**：`Status` 里只有物理网卡的**数量**，
 * 没有逐张网卡的明细。要接真数据得先给 `Status` 加字段（或新增一个
 * topology 请求）——**界面不能自己造协议**，所以这里宁可是空的。
 *
 * 表头留着是有意的：列定义本身就是设计（哪一列叫什么、按什么排序、
 * 度量那一列为什么叫"合成度量"），空表比假数据诚实。
 *
 * 关于"合成度量"：`MIB_IPFORWARD_ROW2.Metric` 只是**路由度量偏移**，
 * 自动度量下恒为 0，真正的选路度量 = 接口度量 + 偏移。只看偏移会把
 * 默认出口判错（本机实测以太网 25 vs WLAN 55，只看偏移会误判成 WLAN）。
 */

import { useStatusStore } from '../stores/status';
import type { NicInfo } from '../types';

const status = useStatusStore();

/** 接上数据源之前恒为空。别在这里塞假数据——见文件头。 */
const rows: NicInfo[] = [];
</script>

<template>
  <div class="space-y-6">
    <section class="surface-card rise-in">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">网卡</div>
          <div class="mt-1 text-sm text-text-muted">
            物理网卡 <span class="font-mono-num">{{ status.snapshot?.physical_nics ?? '—' }}</span> 张
            （<span class="font-mono-num">{{ status.snapshot?.pending_confirm ?? '—' }}</span>
            张待人工分配角色）
          </div>
        </div>
      </div>

      <div class="overflow-x-auto -mx-2">
        <table class="data-table">
          <thead>
            <tr class="text-left text-[11px] uppercase tracking-wider text-text-muted">
              <th class="px-2 py-2 font-medium">名称</th>
              <th class="px-2 py-2 font-medium">LUID</th>
              <th class="px-2 py-2 font-medium">类型</th>
              <th class="px-2 py-2 font-medium">角色</th>
              <th class="px-2 py-2 font-medium">来源</th>
              <th class="px-2 py-2 font-medium">状态</th>
              <th class="px-2 py-2 font-medium text-right">合成度量</th>
              <th class="px-2 py-2 font-medium">网关</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in rows" :key="n.luid" class="border-t border-border">
              <td class="px-2 py-2.5">{{ n.name }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">{{ n.luid }}</td>
              <td class="px-2 py-2.5 text-xs">{{ n.physical ? '物理' : '伪接口' }}</td>
              <td class="px-2 py-2.5">{{ n.role }}</td>
              <td class="px-2 py-2.5 text-xs text-text-muted">{{ n.origin }}</td>
              <td class="px-2 py-2.5 text-xs">{{ n.up ? 'Up' : 'Down' }}</td>
              <td class="px-2 py-2.5 text-right font-mono-num text-xs">{{ n.metric ?? '—' }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">
                {{ n.gateway ?? '—' }}
              </td>
            </tr>
            <tr v-if="rows.length === 0">
              <td colspan="8" class="px-2 py-8 text-center">
                <div class="text-sm" style="color: rgb(var(--warning))">
                  还没有数据源
                </div>
                <p class="mt-2 text-xs text-text-muted leading-relaxed max-w-xl mx-auto">
                  <code class="font-mono-num">Status</code> 目前只给物理网卡的<strong
                    class="font-medium"
                    >数量</strong
                  >，不给逐张明细。要填这张表，得先给守护进程的状态文档加字段
                  （或新增一个 topology 请求）——
                  <strong class="font-medium">界面不能自己造协议</strong>，
                  否则它就成了第二个事实来源。
                </p>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="surface-card rise-in">
      <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
        角色是怎么定下来的
      </div>
      <p class="text-xs text-text-muted leading-relaxed">
        角色由 <strong class="font-medium">策略层</strong>（<code class="font-mono-num">aegis-core</code>）
        裁决，感知层只负责描述"网卡长什么样"——两者分开是为了让感知层能只读干跑。
        判定失败时角色是<strong class="font-medium">待人工分配</strong>，
        <strong class="font-medium">不会猜一个出来</strong>；猜错的代价是整个分流方向反了。
      </p>
    </section>
  </div>
</template>
