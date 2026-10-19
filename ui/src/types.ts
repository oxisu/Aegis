/**
 * 数据契约 —— 与 `aegis-ipc` 的 `Status` **逐字段对应**。
 *
 * ⚠ 这个文件是两端的接缝。改字段必须同时改 `crates/aegis-ipc/src/ctl.rs`
 * 的 `Status::to_text` / `from_text`，否则会出现"界面上少了一列但没人报错"。
 * 文本协议是 `key=value` 行式（`STATUS_V1` 抬头），未知字段会被跳过——
 * 那是**向前兼容**的设计：老守护进程没有 `guard_*` 四行时，这里要按
 * "守卫没在干活"处理，而不是报错。
 */

/** 守卫结论。取值来自 `aegis_ipc::{GUARD_EFFECTIVE, GUARD_INEFFECTIVE, GUARD_UNKNOWN, GUARD_OFF}`。 */
export type GuardVerdict = 'effective' | 'ineffective' | 'unknown' | 'off';

export interface GuardView {
  /** 放行是否**真的**被撤了（取自票据的 `permits_suspended`，不是"打算收紧"）。 */
  tightened: boolean;
  /** 已停止自动动作，等人工。⚠ 一旦置上不自动清除。 */
  needs_human: boolean;
  verdict: GuardVerdict;
  /** 人话原因。收紧时**必须**非空——断网不给理由会逼人卸载。 */
  reason: string;
}

export interface StatusSnapshot {
  /** 状态机状态。守护进程直接发中文显示串（见 `aegis-core::state::State` 的 Display）。 */
  state: string;
  /** 绝缘等级。同为中文显示串（`Insulation` 的 Display）。 */
  insulation: string;
  /** 默认出口网卡 LUID。⚠ 0 表示"没有默认路由"，不是一张叫 0 的网卡。 */
  egress_luid: number;
  /** 拓扑指纹（SHA-256 hex）。只算物理 Up 网卡。 */
  fingerprint: string;
  physical_nics: number;
  pending_confirm: number;
  audit_len: number;
  wfp_rules: number;
  /** 绝缘笼计划的静态自检（`aegis_wfp::verify` 的不变量）。 */
  wfp_invariants_ok: boolean;
  guard: GuardView;
}

/** 守卫没在干活时的默认值（对应 `GuardView::off`）。 */
export const GUARD_OFF: GuardView = {
  tightened: false,
  needs_human: false,
  verdict: 'off',
  reason: '',
};

/**
 * 端点信息 —— 排障时最想知道的就是"它到底在连哪儿"。
 * 对应 `ui/src-tauri/src/lib.rs` 的 `EndpointInfo`。
 */
export interface EndpointInfo {
  /** 命名管道完整路径。 */
  pipe: string;
  /** token 文件路径。 */
  token_file: string;
  /**
   * token 文件在不在。⚠ 它决定界面给的是"服务没在跑"
   * 还是"路径指错了"——这两种的下一步完全不同。
   */
  token_file_present: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// 以下两组**还没有**对应的 IPC 字段。
//
// ⚠ 它们只用于**定义列结构**，界面上这两张表目前是空的（显示"还没有数据源"）。
// 要填数据必须先给 `Status` 加字段（或新增 topology / audit 请求），
// 不要在这里自己造协议——界面不能成为第二个事实来源。
// 塞假数据的代价是人以为看到的是本机状态，对安全底座来说那是事故。
// ─────────────────────────────────────────────────────────────────────────────

/** 网卡角色。对应 `aegis-core::role::InterfaceRole`。 */
export type RoleKey = 'CampusStrict' | 'FreeOutbound' | 'Aggregated' | 'Isolated';

export interface NicInfo {
  luid: number;
  name: string;
  /** 是否物理网卡。伪接口（过滤器/隧道/回环）不计入指纹。 */
  physical: boolean;
  role: RoleKey;
  /** 角色是怎么定下来的：用户指定 / 策略推断 / 还没定。 */
  origin: 'manual' | 'inferred' | 'undecided';
  /** 判定依据，给人看的（例："网关地址落在校园网常见私有网段"）。 */
  evidence: string;
  up: boolean;
  /** 合成选路度量 = 接口度量 + 路由偏移。⚠ 只看偏移会误判默认出口。 */
  metric: number | null;
  gateway: string | null;
}

export interface AuditRow {
  seq: number;
  time: string;
  /** `aegis_audit::Action`。 */
  action: 'Allow' | 'Drop';
  src: string;
  dst: string;
  /** 命中的规则名。控制面事件带 `BOOT:` / `GUARD:` 前缀，导出证据包时要过滤掉。 */
  rule: string;
  process: string;
}
