<script setup lang="ts">
/**
 * 连不上守护进程时的大空态。
 *
 * ⚠ 这个组件的作用不是"显示一个错误"，而是**把线索全摆出来**：
 * 管道名、token 路径、token 文件在不在、原始错误。
 * 少了任何一样，人就得去翻日志或者猜——而"服务明明在跑却连不上"
 * 这种问题，光看"连接失败"四个字是查不出来的。
 */

import { computed } from 'vue';
import { ExclamationCircleIcon } from '@heroicons/vue/24/outline';
import { useStatusStore } from '../stores/status';

const status = useStatusStore();

const tokenPresent = computed(() => status.endpoint?.token_file_present);

/**
 * 按 token 文件在不在给不同的下一步。
 * 这两种的处置动作完全不同：没有文件 → 服务没跑（或换了 data-dir）；
 * 有文件 → 服务在跑，是管道名或 token 对不上。
 */
const nextStep = computed(() => {
  if (tokenPresent.value === false) {
    return 'token 文件不存在 —— 它是在守护进程启动时写的。多半是服务没在跑，'
      + '或者它用了别的 --data-dir / --token-file。';
  }
  if (tokenPresent.value === true) {
    return 'token 文件在，说明服务起来过。那就看管道名对不对'
      + '（服务可能用了 --pipe），或者它是重启过、而这里读到的是旧文件。';
  }
  return '（端点信息还没取到，无法判断是哪一种）';
});
</script>

<template>
  <div class="surface-card rise-in">
    <div class="flex items-start gap-3">
      <ExclamationCircleIcon class="w-6 h-6 flex-shrink-0 mt-0.5 text-danger" />
      <div class="min-w-0 flex-1">
        <div class="text-base font-semibold">连不上守护进程</div>
        <p class="mt-1 text-xs text-text-muted">
          下面这些数字（如果有）是<strong class="font-medium">最后一次成功取到的</strong>，
          不是当前状态。
        </p>
      </div>
    </div>

    <div
      v-if="status.error"
      class="mt-4 px-3 py-2.5 rounded-element text-xs leading-relaxed whitespace-pre-line selectable"
      style="
        background: rgb(var(--danger) / 0.1);
        border: 1px solid rgb(var(--danger) / 0.25);
        color: rgb(var(--text));
      "
    >
      {{ status.error }}
    </div>

    <p class="mt-3 text-xs leading-relaxed selectable" style="color: rgb(var(--warning))">
      {{ nextStep }}
    </p>

    <dl v-if="status.endpoint" class="mt-4 text-xs space-y-1.5">
      <div class="flex gap-3">
        <dt class="w-24 flex-shrink-0 text-text-muted">管道</dt>
        <dd class="font-mono-num selectable">{{ status.endpoint.pipe }}</dd>
      </div>
      <div class="flex gap-3">
        <dt class="w-24 flex-shrink-0 text-text-muted">token 文件</dt>
        <dd class="font-mono-num selectable break-all">{{ status.endpoint.token_file }}</dd>
      </div>
      <div class="flex gap-3">
        <dt class="w-24 flex-shrink-0 text-text-muted">文件存在</dt>
        <dd :class="tokenPresent ? 'text-success' : 'text-danger'">
          {{ tokenPresent ? '是' : '否' }}
        </dd>
      </div>
    </dl>
  </div>
</template>
