<script setup lang="ts">
/**
 * 总览。
 *
 * 排布原则：**第一眼要能回答"我现在是不是断着网"**。
 * 所以最上面是状态机 + 绝缘等级两个大字，守卫结论紧跟其后；
 * 计数类指标（规则数、审计条数）往下压——它们是"确认用的"，不是"决策用的"。
 */

import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { ArrowRightIcon } from '@heroicons/vue/24/outline';
import { useStatusStore } from '../stores/status';
import DaemonUnreachable from '../components/DaemonUnreachable.vue';
import {
  guardVerdictClass,
  guardVerdictText,
  insulationClass,
  luidHex,
  num,
  shortHex,
} from '../utils/format';

const status = useStatusStore();
const router = useRouter();

const s = computed(() => status.snapshot);

const metrics = computed(() => {
  if (!s.value) return [];
  return [
    { label: '物理网卡', value: num(s.value.physical_nics), hint: '只算物理 Up 网卡' },
    { label: '默认出口', value: luidHex(s.value.egress_luid), hint: '合成选路度量最小者' },
    { label: '待人工确认', value: num(s.value.pending_confirm), hint: '角色还没定下来的网卡' },
    { label: '审计条数', value: num(s.value.audit_len), hint: '内核出站事件累计' },
    { label: 'WFP 规则', value: num(s.value.wfp_rules), hint: '当前会话下发的条数' },
  ];
});
</script>

<template>
  <div class="space-y-6">
    <!-- 连不上时：线索全摆出来，但**不清空**已经拿到的快照 -->
    <DaemonUnreachable v-if="!status.connected" />

    <template v-if="s">
      <!-- 大字状态：这两个值决定"我现在能不能上网" -->
      <section class="surface-card rise-in">
        <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-3">
          当前状态
          <span v-if="status.stale" class="ml-2 normal-case tracking-normal text-danger">
            · 数据已过期（{{ status.lastUpdated?.toLocaleTimeString('zh-CN') }}）
          </span>
        </div>
        <div class="flex flex-wrap items-end gap-x-10 gap-y-4">
          <div>
            <div class="text-[11px] text-text-muted mb-1">状态机</div>
            <div class="text-2xl font-semibold">{{ s.state }}</div>
          </div>
          <div>
            <div class="text-[11px] text-text-muted mb-1">绝缘等级</div>
            <div class="text-2xl font-semibold" :class="insulationClass(s.insulation)">
              {{ s.insulation }}
            </div>
          </div>
          <div>
            <div class="text-[11px] text-text-muted mb-1">绝缘笼自检</div>
            <div
              class="text-2xl font-semibold"
              :class="s.wfp_invariants_ok ? 'text-success' : 'text-danger'"
            >
              {{ s.wfp_invariants_ok ? '通过' : '不通过' }}
            </div>
          </div>
        </div>

        <!-- 守卫摘要：一行 + 跳转 -->
        <button
          class="mt-5 w-full flex items-center gap-3 px-4 py-3 rounded-element text-left transition-colors hover:bg-surface-hover/50"
          style="border: 1px solid rgb(var(--border))"
          @click="router.push('/guard')"
        >
          <span class="text-[11px] text-text-muted flex-shrink-0">守卫</span>
          <span class="text-sm font-medium" :class="guardVerdictClass(s.guard.verdict)">
            {{ guardVerdictText(s.guard.verdict) }}
          </span>
          <span class="text-xs text-text-muted truncate flex-1">{{ s.guard.reason }}</span>
          <ArrowRightIcon class="w-4 h-4 text-text-muted flex-shrink-0" />
        </button>
      </section>

      <!-- 计数指标 -->
      <section class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <div v-for="m in metrics" :key="m.label" class="surface-card rise-in" :title="m.hint">
          <div class="text-[11px] text-text-muted">{{ m.label }}</div>
          <div class="mt-1 text-lg font-semibold font-mono-num truncate">{{ m.value }}</div>
        </div>
      </section>

      <!-- 拓扑指纹 -->
      <section class="surface-card rise-in">
        <div class="text-[11px] font-bold tracking-[0.13em] uppercase text-text-muted mb-2">
          拓扑指纹
        </div>
        <div
          class="font-mono-num text-sm selectable"
          :title="s.fingerprint"
        >
          {{ shortHex(s.fingerprint, 24) }}
        </div>
        <p class="mt-3 text-xs text-text-muted leading-relaxed">
          只按<strong class="font-medium">物理 Up 网卡</strong>计算。伪接口（过滤器 / 隧道 / 回环）
          不计入——它们每次插拔、每次开代理都会变，算进去会造成假漂移，
          而假漂移会让 Aegis 反复打断人确认，后果是"无脑点确认"，零信任就废了。
        </p>
      </section>
    </template>
  </div>
</template>
