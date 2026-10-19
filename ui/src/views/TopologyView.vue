<script setup lang="ts">
/**
 * 网卡与角色。
 *
 * 这一页最容易写错的地方是**度量**：
 * `MIB_IPFORWARD_ROW2.Metric` 只是"路由度量偏移"，自动度量下恒为 0，
 * 真正的选路度量 = 接口度量 + 偏移。只看偏移会把默认出口判错
 * （本机实测以太网 25 vs WLAN 55，只看偏移会误判成 WLAN）。
 * 所以表里那列叫"合成度量"，不叫"路由度量"。
 */

import { computed, ref } from 'vue';
import { useStatusStore } from '../stores/status';
import { nics } from '../data/mock';
import { luidHex, originText, roleLevel, roleText } from '../utils/format';
import type { NicInfo } from '../types';

const status = useStatusStore();

/** 只显示物理网卡？默认关 —— 伪接口看不到会让人以为机器只有 3 张网卡。 */
const physicalOnly = ref(false);

const rows = computed(() => (physicalOnly.value ? nics.filter((n) => n.physical) : nics));

function roleClass(n: NicInfo) {
  return `text-lv-${roleLevel(n.role)}`;
}
</script>

<template>
  <div class="space-y-6">
    <section class="surface-card rise-in">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted">网卡</div>
          <div class="mt-1 text-sm text-text-muted">
            共 {{ nics.length }} 张，其中物理 {{ nics.filter((n) => n.physical).length }} 张
          </div>
        </div>
        <label class="flex items-center gap-2 text-xs text-text-muted cursor-pointer select-none">
          <input v-model="physicalOnly" type="checkbox" class="rounded" />
          只看物理网卡
        </label>
      </div>

      <div class="overflow-x-auto -mx-2">
        <table class="w-full text-sm">
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
            <tr
              v-for="n in rows"
              :key="n.luid"
              class="border-t border-border/40 hover:bg-surface-hover/40 transition-colors"
            >
              <td class="px-2 py-2.5">
                <div class="flex items-center gap-2">
                  <span class="font-medium">{{ n.name }}</span>
                  <!-- 默认出口标记 -->
                  <span
                    v-if="n.luid === status.snapshot.egress_luid"
                    class="px-1.5 py-0.5 rounded-pill text-[10px] font-medium"
                    style="
                      background: rgb(var(--accent) / 0.18);
                      color: rgb(var(--accent-text));
                    "
                    >默认出口</span
                  >
                </div>
                <div class="text-[11px] text-text-muted mt-0.5">{{ n.evidence }}</div>
              </td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">
                {{ luidHex(n.luid) }}
              </td>
              <td class="px-2 py-2.5 text-xs">
                <span :class="n.physical ? 'text-text' : 'text-text-muted'">
                  {{ n.physical ? '物理' : '伪接口' }}
                </span>
              </td>
              <td class="px-2 py-2.5 font-medium" :class="roleClass(n)">{{ roleText(n.role) }}</td>
              <td class="px-2 py-2.5 text-xs text-text-muted">{{ originText(n.origin) }}</td>
              <td class="px-2 py-2.5 text-xs">
                <span :class="n.up ? 'text-success' : 'text-text-muted'">
                  {{ n.up ? 'Up' : 'Down' }}
                </span>
              </td>
              <td class="px-2 py-2.5 text-right font-mono-num text-xs">{{ n.metric ?? '—' }}</td>
              <td class="px-2 py-2.5 font-mono-num text-xs text-text-muted">
                {{ n.gateway ?? '—' }}
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
        判定失败时角色是 <span class="text-lv-campus font-medium">待人工分配</span>，
        <strong class="font-medium">不会猜一个出来</strong>；猜错的代价是整个分流方向反了。
      </p>
    </section>
  </div>
</template>
