<script setup lang="ts">
// 根组件只做一件事：把布局和路由接起来。
// 不放任何业务判断——否则"当前是什么状态"会有两个来源（这里和 store）。
import AppLayout from './layouts/AppLayout.vue';
</script>

<template>
  <AppLayout />
</template>
