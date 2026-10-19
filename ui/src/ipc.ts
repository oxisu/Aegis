/**
 * 界面 ↔ 守护进程 的桥。
 *
 * # ⚠ 这里**没有**任何协议实现
 *
 * 状态字段的解析全在 Rust 侧（`aegis_ipc::Status::from_text`），
 * 序列化由派生保证（`aegis-ipc` 的 `json` feature）。界面只消费 JSON。
 * 若在这里再写一份 `key=value` 的解析，字段就有了两处定义——
 * 改一处漏一处不会报错，只会"界面上少一列但没人知道"。
 *
 * # ⚠ 只有只读命令
 *
 * `apply` / `confirm` / `rollback` **没有**对应的函数，这是权限模型决定的：
 * `aegis_ipc::peer::Risk::Dangerous` 要求对端进程已提权，而 GUI 按设计
 * 不提权。界面上也不会出现这些按钮——不是"还没接线"，是发不出去。
 */

import { invoke } from '@tauri-apps/api/core';
import type { EndpointInfo, StatusSnapshot } from './types';

/** 是否跑在 Tauri 外壳里（纯 `vite dev` 时是 false）。 */
export function inShell(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/**
 * 桥接失败。
 *
 * ⚠ `detail` 是直接给人看的一句话，不经任何包装——
 * Rust 侧已经把"管道名 / token 路径 / 下一步"写进去了，
 * 界面再润色一遍只会把这些线索弄丢。
 */
export class BridgeError extends Error {
  constructor(
    message: string,
    /** 是不是"连不上"这一类（区别于"命令被拒绝"）。决定界面给什么提示。 */
    readonly unreachable: boolean,
  ) {
    super(message);
    this.name = 'BridgeError';
  }
}

async function call<T>(cmd: string): Promise<T> {
  if (!inShell()) {
    // 纯浏览器：打不开命名管道（实测），这不是权限问题是能力问题。
    throw new BridgeError(
      '不在 Aegis 外壳里：浏览器打不开命名管道。请用 npm run tauri dev 启动。',
      true,
    );
  }
  try {
    return await invoke<T>(cmd);
  } catch (e) {
    throw new BridgeError(String(e), true);
  }
}

/** 取守护进程状态。 */
export function fetchStatus(): Promise<StatusSnapshot> {
  return call<StatusSnapshot>('status');
}

/** 心跳：只验链路与鉴权是否还活着。 */
export function fetchPing(): Promise<string> {
  return call<string>('ping');
}

/** 端点信息（管道名 / token 路径 / token 文件在不在）——排障用。 */
export function fetchEndpoint(): Promise<EndpointInfo> {
  return call<EndpointInfo>('endpoint_info');
}
