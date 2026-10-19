/**
 * 状态存储。数据源是守护进程（经 Tauri 外壳的命名管道）。
 *
 * # ⚠ 断连后**必须保留**上一次快照
 *
 * 断网时人要看的正是"为什么断"。连不上守护进程就把界面清空，
 * 等于把唯一线索一起清了——那正是 `docs/DOWNSTREAM-GUARD.md` §5.2
 * 说的"不知道为什么断就会卸载"。所以这里永不把 `snapshot` 置回 null，
 * 而是用 `stale` 标出来，让界面显示"以下是最后一次成功的快照（时间）"。
 */

import { computed, ref } from 'vue';
import { defineStore } from 'pinia';
import type { EndpointInfo, StatusSnapshot } from '../types';
import { fetchEndpoint, fetchStatus } from '../ipc';

/** 连着的时候的轮询间隔。 */
const ALIVE_MS = 1500;
/**
 * 断着的时候放慢。每次尝试都要读一次 token 文件、再试着连管道，
 * 对着一个不在的管道 1.5 秒撞一次没有意义，也徒增日志噪音。
 */
const DEAD_MS = 4000;

export const useStatusStore = defineStore('status', () => {
  /** ⚠ 一旦拿到就**不再清空**，见文件头。 */
  const snapshot = ref<StatusSnapshot | null>(null);
  const connected = ref(false);
  /** 最后一次失败的原因。Rust 侧已经写成能给人看的一句话，这里原样显示。 */
  const error = ref('');
  const lastUpdated = ref<Date | null>(null);
  /** 端点信息（排障用：它到底在连哪儿）。 */
  const endpoint = ref<EndpointInfo | null>(null);

  const polling = ref(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  /** 有快照但已经连不上了 —— 界面要显式说"这是过期的"。 */
  const stale = computed(() => !connected.value && snapshot.value !== null);

  /** 守卫是否在报警：已收紧，或已停止自动动作。 */
  const needsAttention = computed(() => {
    const g = snapshot.value?.guard;
    return !!g && (g.tightened || g.needs_human);
  });

  async function refresh() {
    try {
      snapshot.value = await fetchStatus();
      connected.value = true;
      error.value = '';
      lastUpdated.value = new Date();
    } catch (e) {
      connected.value = false;
      error.value = e instanceof Error ? e.message : String(e);
    }
  }

  /** 端点信息单独取：取不到不影响状态，但排障时它是最有用的那一行。 */
  async function loadEndpoint() {
    try {
      endpoint.value = await fetchEndpoint();
    } catch {
      endpoint.value = null;
    }
  }

  function startPolling() {
    if (timer !== null) return;
    polling.value = true;
    // 用递归 setTimeout 而不是 setInterval：请求是异步的，
    // setInterval 会在上一次还没回来时就发下一次，请求叠起来。
    const tick = async () => {
      await refresh();
      if (!polling.value) return;
      timer = setTimeout(tick, connected.value ? ALIVE_MS : DEAD_MS);
    };
    void tick();
    void loadEndpoint();
  }

  function stopPolling() {
    polling.value = false;
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  }

  return {
    snapshot,
    connected,
    error,
    lastUpdated,
    endpoint,
    polling,
    stale,
    needsAttention,
    refresh,
    loadEndpoint,
    startPolling,
    stopPolling,
  };
});
