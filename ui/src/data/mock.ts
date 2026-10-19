/**
 * 假数据 —— 骨架阶段唯一的数据源。
 *
 * ⚠ 这里的数字**不能**让人误以为是真的。所以：
 *   · `MOCK` 常量显式导出，界面顶部要挂"假数据"标记（见 AppLayout.vue）；
 *   · 取值刻意取自本机实测过的量级（44 张网卡 / 3 张物理 / 10 条规则），
 *     免得照着假数据做出的布局在真数据下崩掉。
 *
 * 接真数据后这个文件整个删掉，不留开关 —— 留开关的下场是某天忘了切，
 * 界面显示的是编的数字而人以为是本机状态。对安全底座来说那是事故。
 */

import type { AuditRow, NicInfo, StatusSnapshot } from '../types';

export const MOCK = true;

/** 场景一：稳态（守卫判不了，因为没配 control_addr）。 */
export const statusSteady: StatusSnapshot = {
  state: '受控放行',
  insulation: '按角色放行',
  egress_luid: 1_689_399_750_295_552,
  fingerprint: '1c1401a86db5513753b7c7ca13b7b047ddd032f8e0f4db324106e617d400e339',
  physical_nics: 3,
  pending_confirm: 3,
  audit_len: 1,
  wfp_rules: 10,
  wfp_invariants_ok: true,
  guard: {
    tightened: false,
    needs_human: false,
    verdict: 'unknown',
    reason: '判不了（代理可达性判不了：未配置 proxy.control_addr，或适配器未实现 Op::Health）→ 不动手',
  },
};

/** 场景二：已收紧 —— 断网中。这是"给人看的第一屏"，必须最显眼。 */
export const statusTightened: StatusSnapshot = {
  ...statusSteady,
  state: '监控降级（仍绝缘）',
  insulation: '完全绝缘',
  audit_len: 4,
  guard: {
    tightened: true,
    needs_human: false,
    verdict: 'ineffective',
    reason: '下游规则未生效：1 项未通过 [代理可达]',
  },
};

/** 场景三：已停止自动动作，需要人来处理。 */
export const statusNeedsHuman: StatusSnapshot = {
  ...statusSteady,
  state: '监控降级（仍绝缘）',
  insulation: '完全绝缘',
  audit_len: 9,
  guard: {
    tightened: true,
    needs_human: true,
    verdict: 'ineffective',
    reason: '下游规则未生效：1 项未通过 [代理可达]',
  },
};

export const nics: NicInfo[] = [
  {
    luid: 1_689_399_750_295_552,
    name: '以太网 4',
    physical: true,
    role: 'CampusStrict',
    origin: 'inferred',
    evidence: '网关地址落在校园网常见私有网段',
    up: true,
    metric: 35,
    gateway: '10.41.0.1',
  },
  {
    luid: 1_689_395_631_011_611_136,
    name: 'WLAN',
    physical: true,
    role: 'Isolated',
    origin: 'undecided',
    evidence: '无 SSID（有线或未关联无线）；也没有网关 —— 需人工分配角色',
    up: false,
    metric: 55,
    gateway: null,
  },
  {
    luid: 1_689_395_631_011_611_137,
    name: '以太网',
    physical: true,
    role: 'Isolated',
    origin: 'undecided',
    evidence: '无 SSID（有线或未关联无线）；也没有网关 —— 需人工分配角色',
    up: false,
    metric: 25,
    gateway: null,
  },
];

export const auditRows: AuditRow[] = [
  {
    seq: 1,
    time: '2026-10-19 13:31:02',
    action: 'Allow',
    src: '127.0.0.1:54321',
    dst: '127.0.0.1:19827',
    rule: '回环放行',
    process: 'aegisctl.exe',
  },
  {
    seq: 2,
    time: '2026-10-19 13:31:11',
    action: 'Drop',
    src: '10.41.22.7:51022',
    dst: '223.5.5.5:53',
    rule: '物理 53 封锁',
    process: 'svchost.exe',
  },
  {
    seq: 3,
    time: '2026-10-19 13:31:40',
    action: 'Allow',
    src: '10.41.22.7:51030',
    dst: '10.254.1.1:443',
    rule: '始终白名单·校园网认证页',
    process: 'msedge.exe',
  },
  // ⚠ 控制面事件：导出证据包时要按 `GUARD:` 前缀过滤掉，
  // 它不是真实连接，src 是 127.0.0.1:0，核对证据的人会看不懂。
  {
    seq: 4,
    time: '2026-10-19 13:31:55',
    action: 'Allow',
    src: '127.0.0.1:0',
    dst: '127.0.0.1:0',
    rule: 'GUARD:TIGHTEN',
    process: 'aegisd.exe',
  },
];
