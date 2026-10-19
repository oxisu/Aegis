/**
 * 显示格式化。
 *
 * ⚠ 这个文件里有一条贯穿的铁律，与 `aegisctl` 的 `verdict_text` 同源：
 * **认不出的取值绝不能显示成"正常"或"未知"就完事，必须把原值打出来**。
 * 那是把未知说成已知；而守卫/绝缘等级这类取值一旦新增（比如以后加个
 * `degraded`），界面就该显式暴露出来，而不是悄悄归到某一档。
 */

import type { GuardVerdict, RoleKey } from '../types';

/** 绝缘等级 → 语义色键。对应 `aegis-core::state::Insulation` 的 Display 串。 */
export type InsulationLevel = 'isolated' | 'captive' | 'none' | 'unknown';

export function insulationLevel(insulation: string): InsulationLevel {
  switch (insulation) {
    case '完全绝缘':
      return 'isolated';
    case '仅认证沙盒':
      return 'captive';
    case '按角色放行':
      return 'none';
    default:
      return 'unknown';
  }
}

/** 绝缘等级 → Tailwind 色板上的类名（见 tailwind.config.js 的 lv-*）。 */
export function insulationClass(insulation: string): string {
  return `text-lv-${insulationLevel(insulation)}`;
}

/**
 * 守卫结论 → 人话。
 *
 * ⚠ 认不出的取值返回 `**未知取值** x`，**不**回退成"生效"。
 * 回退成"生效"的后果是：守卫其实在报一个新的状态，而界面显示一切正常。
 */
export function guardVerdictText(v: string): string {
  switch (v) {
    case 'effective':
      return '生效';
    case 'ineffective':
      return '未生效';
    case 'unknown':
      return '判不了（不会收紧）';
    case 'off':
      return '未启用';
    case '':
      return '（守护进程未上报）';
    default:
      return `**未知取值** ${v}`;
  }
}

/** 守卫结论 → Tailwind 色板上的类名（见 tailwind.config.js 的 guard-*）。 */
export function guardVerdictClass(v: string): string {
  const known: Record<GuardVerdict, string> = {
    effective: 'text-guard-effective',
    ineffective: 'text-guard-ineffective',
    unknown: 'text-guard-unknown',
    off: 'text-guard-off',
  };
  return known[v as GuardVerdict] ?? 'text-guard-unknown';
}

/** 网卡角色 → 中文名。对应 `aegis-core::role::InterfaceRole`。 */
export function roleText(r: RoleKey): string {
  switch (r) {
    case 'CampusStrict':
      return '校园网严格';
    case 'FreeOutbound':
      return '自由出海';
    case 'Aggregated':
      return '聚合';
    case 'Isolated':
      return '彻底绝缘';
    default:
      return `**未知角色** ${r}`;
  }
}

/** 网卡角色 → 语义色键（与绝缘等级共用一组 lv-*）。 */
export function roleLevel(r: RoleKey): 'isolated' | 'campus' | 'free' | 'aggregated' | 'unknown' {
  switch (r) {
    case 'Isolated':
      return 'isolated';
    case 'CampusStrict':
      return 'campus';
    case 'FreeOutbound':
      return 'free';
    case 'Aggregated':
      return 'aggregated';
    default:
      return 'unknown';
  }
}

/** 角色来源 → 中文。 */
export function originText(o: 'manual' | 'inferred' | 'undecided'): string {
  switch (o) {
    case 'manual':
      return '用户指定';
    case 'inferred':
      return '策略推断';
    case 'undecided':
      return '待人工分配';
  }
}

/** LUID 显示成十六进制——Rust 侧日志与配置里都是这个形式，人对得上。 */
export function luidHex(n: number): string {
  if (n === 0) return '0（无默认路由）';
  return `0x${n.toString(16)}`;
}

/** 指纹太长，默认截头；完整值放在 title 里供复制。 */
export function shortHex(s: string, head = 12): string {
  return s.length <= head ? s : `${s.slice(0, head)}…`;
}

/** 千分位。审计条数会涨到几十万，不加分隔读不出来。 */
export function num(n: number): string {
  return n.toLocaleString('zh-CN');
}
