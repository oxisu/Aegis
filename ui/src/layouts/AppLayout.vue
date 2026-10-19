<script setup lang="ts">
/**
 * 外壳：侧栏 + 顶栏 + 内容区。
 *
 * ⚠ 顶部那条横幅是**守卫专用**的，不是通用通知位。
 * 理由（`docs/DOWNSTREAM-GUARD.md` §5.2）：用户不知道为什么断网就会卸载 Aegis。
 * 所以"已收紧"这件事不能只躺在守卫页里等人翻到，也不能做成一条能被
 * 划掉的 toast —— 它是**当前事实**，只要还成立就必须一直在那儿。
 */

import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { ExclamationTriangleIcon } from '@heroicons/vue/24/outline';
import Sidebar from './Sidebar.vue';
import Topbar from './Topbar.vue';
import { useStatusStore } from '../stores/status';
import { guardVerdictText } from '../utils/format';

const collapsed = ref(false);
const router = useRouter();
const status = useStatusStore();

/** 横幅文案。⚠ 必须说清"是谁干的"，不能只写"网络异常"——那是逼人卸载。 */
const bannerText = computed(() => {
  const g = status.snapshot?.guard;
  if (!g) return '';
  if (g.needs_human) return '守卫已停止自动动作，等人工处理';
  if (g.tightened) return `守卫已收紧放行（${guardVerdictText(g.verdict)}）`;
  return '';
});
</script>

<template>
  <div class="flex h-screen overflow-hidden relative">
    <div class="relative z-10 flex h-screen overflow-hidden w-full">
      <Sidebar :collapsed="collapsed" @toggle="collapsed = !collapsed" />
      <div class="flex-1 flex flex-col overflow-hidden">
        <Topbar @toggle-sidebar="collapsed = !collapsed" />

        <!-- 守卫横幅：只要条件还成立就一直在，不可关闭 -->
        <div
          v-if="bannerText"
          class="px-6 py-2.5 flex items-center gap-3 text-sm border-b flex-shrink-0 cursor-pointer transition-colors"
          :style="{
            background: 'rgb(var(--guard-ineffective) / 0.14)',
            borderColor: 'rgb(var(--guard-ineffective) / 0.3)',
            color: 'rgb(var(--guard-ineffective))',
          }"
          @click="router.push('/guard')"
        >
          <ExclamationTriangleIcon class="w-5 h-5 flex-shrink-0" />
          <span class="font-medium">{{ bannerText }}</span>
          <span class="text-xs text-text-muted truncate">{{ status.snapshot?.guard.reason }}</span>
          <span class="ml-auto text-xs underline flex-shrink-0">查看详情</span>
        </div>

        <main class="flex-1 overflow-y-auto p-6 lg:p-8">
          <div class="max-w-[1440px] mx-auto">
            <RouterView />
          </div>
        </main>
      </div>
    </div>
  </div>
</template>
