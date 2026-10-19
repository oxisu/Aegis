<script setup lang="ts">
/**
 * 轮询在这里起停，不在各个页面里。
 *
 * 页面各自起一份的下场是：切一次路由就多一条轮询，
 * 而它们写的是同一个 store，表现为"数字自己跳"，排查时会一路查错方向。
 */

import { onMounted, onUnmounted } from 'vue';
import AppLayout from './layouts/AppLayout.vue';
import { useStatusStore } from './stores/status';

const status = useStatusStore();

onMounted(() => status.startPolling());
onUnmounted(() => status.stopPolling());
</script>

<template>
  <AppLayout />
</template>
