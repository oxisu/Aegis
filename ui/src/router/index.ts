/**
 * 路由。
 *
 * 顺序即左侧导航顺序。**守卫排第二**（紧跟总览）——它是"断网时给人看的
 * 第一屏"：`docs/DOWNSTREAM-GUARD.md` §5.2 说过，用户不知道为什么断
 * 就会卸载 Aegis，所以这个页面不能藏在第三层菜单里。
 */

import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue'),
    meta: { title: '总览', icon: 'squares' },
  },
  {
    path: '/guard',
    name: 'guard',
    component: () => import('../views/GuardView.vue'),
    meta: { title: '守卫', icon: 'shield' },
  },
  {
    path: '/topology',
    name: 'topology',
    component: () => import('../views/TopologyView.vue'),
    meta: { title: '网卡与角色', icon: 'sitemap' },
  },
  {
    path: '/audit',
    name: 'audit',
    component: () => import('../views/AuditView.vue'),
    meta: { title: '审计', icon: 'list' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/SettingsView.vue'),
    meta: { title: '设置', icon: 'cog' },
  },
];

export const NAV = routes.map((r) => ({
  name: r.name as string,
  path: r.path,
  title: r.meta?.title as string,
  icon: r.meta?.icon as string,
}));

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
