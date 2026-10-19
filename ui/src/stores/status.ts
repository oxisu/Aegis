/**
 * 状态存储。
 *
 * 骨架阶段的数据源是 `data/mock.ts` 的三种场景，可切换是为了**看清楚
 * 每种状态长什么样**——尤其是"已收紧（正在断网）"这一屏，真机上要等
 * 下游代理真的挂掉才会出现，平时根本看不到。
 *
 * ⚠ 接真数据后，这个 store 只保留 `snapshot` 与 `connected`，
 * `scenario` 与 `refresh()` 一并删掉（换成轮询 IPC）。
 */

import { computed, ref } from 'vue';
import { defineStore } from 'pinia';
import type { StatusSnapshot } from '../types';
import { statusNeedsHuman, statusSteady, statusTightened } from '../data/mock';

export type Scenario = 'steady' | 'tightened' | 'needsHuman';

const SCENARIOS: Record<Scenario, StatusSnapshot> = {
  steady: statusSteady,
  tightened: statusTightened,
  needsHuman: statusNeedsHuman,
};

export const useStatusStore = defineStore('status', () => {
  const scenario = ref<Scenario>('steady');
  /** 是否连得上守护进程。假数据阶段恒为 true；接真 IPC 后由连接结果决定。 */
  const connected = ref(true);
  const lastUpdated = ref(new Date());

  const snapshot = computed(() => SCENARIOS[scenario.value]);

  /** 守卫是否处于"需要人看一眼"的状态：已收紧，或已停止自动动作。 */
  const needsAttention = computed(
    () => snapshot.value.guard.tightened || snapshot.value.guard.needs_human,
  );

  function setScenario(s: Scenario) {
    scenario.value = s;
    lastUpdated.value = new Date();
  }

  function refresh() {
    lastUpdated.value = new Date();
  }

  return { scenario, connected, lastUpdated, snapshot, needsAttention, setScenario, refresh };
});
