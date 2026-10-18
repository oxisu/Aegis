//! **真实下发与回滚**（§20.2 / §28.2）—— 本 crate 里唯一会改变系统状态的地方。
//!
//! # 这是全项目最危险的一段代码
//!
//! 装错一条规则的后果不是报错，是**整机断网**；而 `Tier::Boot` 的规则
//! 装错了，重启都清不掉。所以这里的每一条设计都围绕"怎么让它装不错、
//! 装错了怎么拆"。
//!
//! ## 四道防线
//!
//! 1. **只装 [`Tier::Runtime`]**。Boot 背板**不在本函数的能力范围内**——
//!    它要显式单独走一条流程，且必须人工确认。这里遇到 Boot 直接拒绝。
//! 2. **条件映射表是白名单，不是尽力而为**。
//!    [`mappable`] 认不出的条件**一律拒绝下发**，绝不"差不多地"翻译成
//!    另一个字段。翻译错一条条件，造成的就是"该放行的被拦、该拦的被放行"。
//! 3. **动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`）。进程崩溃、被杀、
//!    甚至只是退出，内核都会**自动清空**这次会话里装的所有规则。
//!    这是最后一道兜底：就算上层逻辑全错，重启进程就能恢复网络。
//! 4. **两阶段确认**（[`ApplyTicket`]）。装完不立刻算数，开一个倒计时窗口；
//!    窗口内没人确认就自动回滚。人在外面、手滑装错了也不至于被锁在外面。
//!
//! ## 为什么回执必须留着
//!
//! [`ApplyReceipt`] 里存的是内核返回的 `filterId`。没有它就只能"再枚举一遍
//! 按名字猜哪些是自己装的"——而猜错的下场是删掉别人的规则。
//! 回滚只认 id，不认名字。

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::error::WfpError;
use crate::plan::{Condition, FilterSpec, Tier};
use crate::session::Session;

/// 两阶段确认的默认窗口（毫秒）。
///
/// 10 秒的依据：够一个人发现"咦，网断了"并执行 `aegisctl confirm`，
/// 又短到不至于让一台装错了的机器长时间处于断网状态。
pub const CONFIRM_WINDOW_MS: u64 = 10_000;

/// 下发回执。**回滚只认这里面的 id。**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReceipt {
    /// 会话显示名（`netsh wfp show state` 里能认出来）。
    pub session_name: String,
    /// 内核返回的过滤器 id，顺序与计划一致。
    pub filter_ids: Vec<u64>,
    /// 安装时刻（毫秒）。
    pub installed_at_ms: u64,
}

impl ApplyReceipt {
    pub fn len(&self) -> usize {
        self.filter_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.filter_ids.is_empty()
    }
}

// ── 两阶段确认的状态机（纯逻辑，完整单测）─────────────────────────────

/// 一次下发处于哪个阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 已装好，等确认。**倒计时结束前没确认就回滚。**
    Pending,
    /// 人在窗口内确认了，规则留下。
    Committed,
    /// 已回滚（超时或主动撤除）。
    RolledBack,
}

/// 确认失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    #[error("确认来晚了 {late_by_ms} 毫秒：窗口已关闭，规则已回滚")]
    Expired { late_by_ms: u64 },
    #[error("这次下发已经有结论了（{phase:?}），不能再确认")]
    AlreadyDecided { phase: Phase },
}

/// 两阶段下发的票据。**纯数据**，可以跨线程共享（回执里的 id 只是 u64）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyTicket {
    pub phase: Phase,
    /// 截止时刻（毫秒）。
    pub deadline_ms: u64,
    pub filter_ids: Vec<u64>,
    /// 有人主动要求拆除（不是超时，是 `rollback` 命令）。
    pub abort_requested: bool,
    /// **紧急强拆**：不管当前处于哪个阶段，下一次巡检立即拆除。
    ///
    /// 这是 SECURITY.md 兜底手册里"人在现场发现不对"的那条通道。
    /// 它和 [`Self::abort_requested`] 的区别在于：后者只作用于
    /// `Pending`（不能把已确认的规则悄悄撤掉，否则 `rollback` 等于一条
    /// 能远程断网的命令），而强拆是**显式、单独、可审计**的动作。
    pub force_teardown: bool,
    /// 给人看的说明（为什么回滚 / 谁确认的）。
    pub note: String,
}

impl ApplyTicket {
    /// 开一个待确认的票据。
    pub fn pending(now_ms: u64, window_ms: u64, filter_ids: Vec<u64>) -> Self {
        Self {
            phase: Phase::Pending,
            deadline_ms: now_ms.saturating_add(window_ms),
            filter_ids,
            abort_requested: false,
            force_teardown: false,
            note: String::new(),
        }
    }

    /// 还剩多少毫秒。过了截止时刻就是 0，**不会是负数**（`u64` 下溢会变成
    /// 一个巨大的数，进而让"过期"判断整个反过来）。
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.deadline_ms
    }

    /// 窗口内确认。
    ///
    /// ⚠ **过期后确认必须失败**，否则倒计时形同虚设：
    /// 装错了 → 超时自动回滚 → 人再确认一次 → 又装回去，而这次没人再兜底了。
    pub fn confirm(&mut self, now_ms: u64) -> Result<(), ConfirmError> {
        if self.phase != Phase::Pending {
            return Err(ConfirmError::AlreadyDecided { phase: self.phase });
        }
        if self.is_expired(now_ms) {
            return Err(ConfirmError::Expired {
                late_by_ms: now_ms - self.deadline_ms,
            });
        }
        self.phase = Phase::Committed;
        self.note = "已在窗口内确认，规则保留".to_string();
        Ok(())
    }

    /// 标记已回滚。**同时清掉强拆标记**——否则下一次巡检会照着同一个
    /// 标记再删一遍，而第二次删的可能是别人的规则（id 复用的情况下尤其致命）。
    pub fn mark_rolled_back(&mut self, why: impl Into<String>) {
        self.phase = Phase::RolledBack;
        self.force_teardown = false;
        self.note = why.into();
    }

    /// 主动要求拆除。
    pub fn request_abort(&mut self) {
        self.abort_requested = true;
    }

    /// 紧急强拆：不管处于哪个阶段，下一次巡检立即拆除。
    ///
    /// ⚠ 它能把**已确认**的规则撤掉，这是刻意的——绝缘笼装错了的时候，
    /// 是一条命令能把网络救回来，还是必须重启机器，决定了事故等级。
    /// 调用方必须已通过对端提权检查（见 `aegis-ipc::peer`）。
    pub fn force_teardown(&mut self) {
        self.force_teardown = true;
    }

    /// 该回滚了吗：**强拆** > **超时** > **有人主动要求**。
    ///
    /// 除强拆外只对 `Pending` 为真：已经确认过或已经回滚过就不再重复动作，
    /// 否则"回滚"会被执行两次，而第二次可能删到别人的规则。
    pub fn must_roll_back(&self, now_ms: u64) -> bool {
        if self.force_teardown {
            return true;
        }
        self.phase == Phase::Pending && (self.is_expired(now_ms) || self.abort_requested)
    }
}

// ── 条件映射白名单 ────────────────────────────────────────────────────

/// 这个条件能不能被**精确**翻译成 WFP 字段。
///
/// 认不出的一律拒绝下发（见 [`unmappable_conditions`]）。
/// 理由写在模块头：翻译错一条条件 = 该放行的被拦、该拦的被放行。
pub fn mappable(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::RemotePort(_)
            | Condition::LocalPort(_)
            | Condition::RemoteAddrV4(_)
            | Condition::Loopback
            | Condition::SystemServiceHost
    )
}

/// 挑出计划里**所有**无法精确映射的条件。
///
/// 返回全部而不是第一个：排障时"有 3 条规则装不了，分别是这几个条件"
/// 比"装不了"有用得多。
pub fn unmappable_conditions(plan: &[FilterSpec]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for spec in plan {
        for cond in &spec.conditions {
            if !mappable(cond) && !out.contains(&describe(cond)) {
                out.push(describe(cond));
            }
        }
    }
    out
}

/// 计划里有没有 [`Tier::Boot`] 规则。**有就不能走这条路。**
pub fn has_boot_rules(plan: &[FilterSpec]) -> bool {
    plan.iter().any(|f| f.tier == Tier::Boot)
}

fn describe(cond: &Condition) -> &'static str {
    match cond {
        Condition::ProcessId(_) => "ProcessId",
        Condition::PhysicalInterface => "PhysicalInterface",
        _ => "可映射",
    }
}

/// 系统服务宿主（`svchost.exe`）的完整路径。
///
/// 用 `GetSystemDirectoryW` 现取而**不是**拼 `C:\Windows\system32`：
/// 系统盘不总在 C:，拼错的下场是 `FwpmGetAppIdFromFileName0` 返回
/// "文件不存在"，进而让整批下发失败（已装的会被回滚，不会留下半套）。
#[cfg_attr(test, mutants::skip)]
fn system_service_host_path() -> String {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return String::new();
    }
    let dir = String::from_utf16_lossy(&buf[..n]);
    format!(r"{dir}\svchost.exe")
}

/// 把一个可执行文件路径翻译成 WFP 的 `ALE_APP_ID` blob。
///
/// 返回的指针**归调用方**：用完必须 `FwpmFreeMemory0`。
/// 拿不到返回 `None`——由调用方决定是拒绝还是回滚，绝不塞一个空 blob
/// 充数（空 blob 会匹配"没有 AppId"的流量，那是把放行面悄悄放大）。
#[cfg_attr(test, mutants::skip)]
fn app_id_blob(path: &str) -> Option<*mut wfp::FWP_BYTE_BLOB> {
    let mut wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob: *mut wfp::FWP_BYTE_BLOB = std::ptr::null_mut();
    let rc = unsafe { wfp::FwpmGetAppIdFromFileName0(PCWSTR(wide.as_mut_ptr()), &mut blob) };
    if rc != 0 || blob.is_null() {
        return None;
    }
    Some(blob)
}

// ── 真实下发 / 回滚（需要提权，单测覆盖不到）──────────────────────────

/// 拒绝下发的原因。**在碰 WFP 之前**就要判掉。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefuseReason {
    #[error("计划里有 {count} 条 Boot 层规则：装错了重启都清不掉，本接口不下发")]
    BootRulesPresent { count: usize },
    #[error("有无法精确映射的条件 {conds:?}：宁可不装，也不装成另一个意思")]
    UnmappableConditions { conds: Vec<&'static str> },
    #[error("系统服务宿主 {path} 不存在，无法解析 ALE AppId（下发会在装到一半时失败）")]
    ServiceHostMissing { path: String },
}

/// 下发前的自检。**不碰引擎**。
pub fn preflight(plan: &[FilterSpec]) -> Result<(), RefuseReason> {
    if has_boot_rules(plan) {
        return Err(RefuseReason::BootRulesPresent {
            count: plan.iter().filter(|f| f.tier == Tier::Boot).count(),
        });
    }
    let bad = unmappable_conditions(plan);
    if !bad.is_empty() {
        return Err(RefuseReason::UnmappableConditions { conds: bad });
    }
    // AppId 要在下发**前**确认能解析：装到一半才发现解析不了，
    // 会留下半套规则——半套规则就是断网。
    //
    // 这里只查**路径存在**，不调 `FwpmGetAppIdFromFileName0`：
    // [preflight] 的契约是"不碰引擎"，而那个 API 需要一个已打开的会话。
    // 真正的解析留到下发时，失败则整批回滚（见 [apply]）。
    if plan.iter().any(|f| f.conditions.contains(&Condition::SystemServiceHost)) {
        let path = system_service_host_path();
        if path.is_empty() || !std::path::Path::new(&path).exists() {
            return Err(RefuseReason::ServiceHostMissing { path });
        }
    }
    Ok(())
}

/// 真实下发。**需要提权。**
///
/// 返回会话与回执：会话必须**一直持有**到确认或回滚为止——
/// 它一旦关闭（哪怕只是离开作用域），内核就会把这次装的所有规则清掉，
/// 而那时上层还以为规则在生效。
#[cfg_attr(test, mutants::skip)]
pub fn apply(plan: &[FilterSpec], now_ms: u64) -> Result<(Session, ApplyReceipt), WfpError> {
    let session_name = format!("aegis-cage-{}", now_ms);
    let session = Session::open(&session_name)?;

    let mut ids = Vec::with_capacity(plan.len());
    let mut result: Result<(), WfpError> = Ok(());

    for spec in plan {
        match add_one(&session, spec) {
            Ok(id) => ids.push(id),
            Err(e) => {
                result = Err(e);
                break;
            },
        }
    }

    if let Err(e) = result {
        // ⚠ 装到一半失败：**必须**把已经装上的撤掉。
        // 半套绝缘笼比整套更危险——默认拒绝装上了、回环放行没装上，
        // 等于把自己锁在门外。
        let _ = rollback(&session, &ids);
        return Err(e);
    }

    Ok((
        session,
        ApplyReceipt {
            session_name,
            filter_ids: ids,
            installed_at_ms: now_ms,
        },
    ))
}

/// 按回撤单条条删除。**只认 id**——按名字删会误伤别人的规则。
#[cfg_attr(test, mutants::skip)]
pub fn rollback(session: &Session, filter_ids: &[u64]) -> Result<usize, WfpError> {
    let mut removed = 0usize;
    for &id in filter_ids {
        let rc = unsafe { wfp::FwpmFilterDeleteById0(session.handle(), id) };
        if rc == 0 {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg_attr(test, mutants::skip)]
fn add_one(session: &Session, spec: &FilterSpec) -> Result<u64, WfpError> {
    let mut name_w: Vec<u16> = spec.name.encode_utf16().chain(std::iter::once(0)).collect();

    // ── 第一遍：把每条条件翻译成 (字段 GUID, 匹配类型, 值) ──────────────
    let mut translated: Vec<(GUID, wfp::FWP_MATCH_TYPE, FwpValue)> = Vec::new();
    // AppId blob 由 WFP 分配，必须活到 `FwpmFilterAdd0` 返回之后再释放
    let mut owned_blobs: Vec<*mut wfp::FWP_BYTE_BLOB> = Vec::new();
    for cond in &spec.conditions {
        match cond {
            Condition::RemotePort(p) => translated.push((
                wfp::FWPM_CONDITION_IP_REMOTE_PORT,
                wfp::FWP_MATCH_EQUAL,
                FwpValue::Uint16(*p),
            )),
            Condition::LocalPort(p) => translated.push((
                wfp::FWPM_CONDITION_IP_LOCAL_PORT,
                wfp::FWP_MATCH_EQUAL,
                FwpValue::Uint16(*p),
            )),
            // ⚠ 目的地址用的是 `FWPM_CONDITION_IP_REMOTE_ADDRESS`（UINT32），
            // **不是** `..._ADDRESS_V4`（`FWP_V4_ADDR_MASK`）。
            // 真机实测：`ALE_AUTH_CONNECT_V4` 的字段表里**没有**
            // `IP_REMOTE_ADDRESS_V4`，内核会回 `0x80320002`
            // （`FWP_E_CONDITION_NOT_FOUND`）。而"层支持哪些字段"是会变的，
            // 所以这条不是从文档背下来的，是用 `Session::fields` 问出来的。
            Condition::RemoteAddrV4(a) => translated.push((
                wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                wfp::FWP_MATCH_EQUAL,
                FwpValue::Uint32(u32::from(*a)),
            )),
            // 回环用 FLAGS 字段判 IS_LOOPBACK，比"目的地址是 127.0.0.0/8"精确：
            // 后者在 IPv6 与部分隧道场景下判不准，而判不准的下场是把自己锁在门外。
            Condition::Loopback => translated.push((
                wfp::FWPM_CONDITION_FLAGS,
                wfp::FWP_MATCH_FLAGS_ALL_SET,
                FwpValue::Uint32(wfp::FWP_CONDITION_FLAG_IS_LOOPBACK),
            )),
            // ⚠ `ALE_APP_ID` 的值是**字节 blob**（进程映像路径），不是整数。
            // 第一版往这里塞了 `UINT64(pid)`，内核直接回
            // `0x80320027`（`FWP_E_TYPE_MISMATCH`）。blob 必须活到
            // `FwpmFilterAdd0` 返回之后，所以指针先收进 `owned_blobs`。
            Condition::SystemServiceHost => {
                let path = system_service_host_path();
                match app_id_blob(&path) {
                    Some(blob) => {
                        owned_blobs.push(blob);
                        translated.push((
                            wfp::FWPM_CONDITION_ALE_APP_ID,
                            wfp::FWP_MATCH_EQUAL,
                            FwpValue::Blob(blob),
                        ))
                    },
                    None => {
                        return Err(WfpError::UnsupportedCondition {
                            name: "SystemServiceHost(AppId 解析失败)",
                        })
                    },
                }
            },
            // 走到这里说明 preflight 漏了。**绝不猜一个字段**。
            other => {
                return Err(WfpError::UnsupportedCondition {
                    name: describe(other),
                })
            },
        }
    }

    // 地址现在是 UINT32 标量（见下面的 `RemoteAddrV4` 分支），
    // 不再需要单独分配缓冲区去放 `FWP_V4_ADDR_AND_MASK`。
    // ── 第三遍：构造条件数组 ────────────────────────────────────────────
    let mut conds: Vec<wfp::FWPM_FILTER_CONDITION0> = Vec::with_capacity(translated.len());
    for (field, match_type, value) in &translated {
        let mut cv = wfp::FWP_CONDITION_VALUE0::default();
        match value {
            FwpValue::Uint16(v) => {
                cv.r#type = wfp::FWP_UINT16;
                cv.Anonymous.uint16 = *v;
            },
            FwpValue::Uint32(v) => {
                cv.r#type = wfp::FWP_UINT32;
                cv.Anonymous.uint32 = *v;
            },
            FwpValue::Blob(p) => {
                cv.r#type = wfp::FWP_BYTE_BLOB_TYPE;
                cv.Anonymous.byteBlob = *p;
            },
        }
        conds.push(wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: *field,
            matchType: *match_type,
            conditionValue: cv,
        });
    }

    // union 用结构体字面量一次构造完，不用 `default()` 再逐个赋值：
    // 后者会被 clippy 判成 field_reassign_with_default，而更重要的理由是
    // union 的字段赋值在语义上就是"整体替换"，写成一次构造更贴近真相。
    let weight = wfp::FWP_VALUE0 {
        r#type: wfp::FWP_UINT8,
        Anonymous: wfp::FWP_VALUE0_0 {
            uint8: spec.weight,
        },
    };

    let mut filter = wfp::FWPM_FILTER0::default();
    filter.displayData.name = PWSTR(name_w.as_mut_ptr());
    filter.layerKey = spec.layer.guid();
    filter.subLayerKey = GUID::zeroed();
    filter.weight = weight;
    filter.numFilterConditions = conds.len() as u32;
    filter.filterCondition = conds.as_mut_ptr();
    filter.action = wfp::FWPM_ACTION0 {
        r#type: match spec.action {
            crate::plan::Action::Permit => wfp::FWP_ACTION_PERMIT,
            crate::plan::Action::Block => wfp::FWP_ACTION_BLOCK,
        },
        Anonymous: wfp::FWPM_ACTION0_0::default(),
    };

    let mut id = 0u64;
    let rc = unsafe { wfp::FwpmFilterAdd0(session.handle(), &filter, None, Some(&mut id)) };

    // AppId blob 是 WFP 分配的，内核复制完就可以还回去
    for mut b in owned_blobs {
        unsafe {
            wfp::FwpmFreeMemory0(&mut b as *mut _ as *mut *mut core::ffi::c_void);
        }
    }

    if rc != 0 {
        return Err(WfpError::FilterAdd(rc));
    }
    Ok(id)
}

/// 一次"装一条再拆掉"的诊断结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// 内核分配的过滤器 id。
    pub filter_id: u64,
    /// 随后被删除的条数（**必须是 1**，否则说明删错了东西）。
    pub removed: usize,
    pub session_name: String,
}

/// **无害探针**：装一条规则，立刻按 id 拆掉。
///
/// ```text
/// cargo run -p aegis-wfp --example apply_probe
/// ```
///
/// # 为什么要有它
///
/// `apply` 是"装错一条就断网"的操作，没人应该靠"跑一次试试"来验证
/// 翻译层对不对。而 WFP **没有**"试算一下不下发"的接口——
/// `FwpmFilterAdd0` 要么成功，要么报错，没有 dry-run。
///
/// 于是用一条**结构上无害**的规则来验证整条通路（会话 → 条件翻译 →
/// 下发 → 按 id 删除）：放行类规则只会**扩大**放行面，不会收窄；
/// 且这里选的是"回环放行"，在默认策略下本来就是放行的，装上去等于
/// 什么都没变。**它不能验证阻断规则**，但能验证"翻译 + 下发 + 回滚"
/// 这套机械动作本身是通的。
///
/// ⚠ **调用方责任**：传入的 spec 必须是放行类且无副作用的。
/// 传一条 Block 规则进来，等于真的拦一次流量。
#[cfg_attr(test, mutants::skip)]
pub fn probe_add_then_remove(spec: &FilterSpec) -> Result<ProbeResult, WfpError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let session_name = format!("aegis-probe-{now}");
    let session = Session::open(&session_name)?;

    let id = add_one(&session, spec)?;
    let removed = rollback(&session, &[id])?;

    Ok(ProbeResult {
        filter_id: id,
        removed,
        session_name,
    })
}

enum FwpValue {
    Uint16(u16),
    Uint32(u32),
    /// `ALE_APP_ID` 用的字节 blob。指针归 `owned_blobs` 管理。
    Blob(*mut wfp::FWP_BYTE_BLOB),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Action, CagePolicy, Layer};

    fn now() -> u64 {
        1_700_000_000_000
    }

    fn ticket(window: u64) -> ApplyTicket {
        ApplyTicket::pending(now(), window, vec![1, 2, 3])
    }

    #[test]
    fn a_fresh_ticket_is_pending_and_not_expired() {
        let t = ticket(CONFIRM_WINDOW_MS);
        assert_eq!(t.phase, Phase::Pending);
        assert!(!t.is_expired(now()));
        assert_eq!(t.remaining_ms(now()), CONFIRM_WINDOW_MS);
    }

    #[test]
    fn confirming_within_the_window_commits() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        assert!(t.confirm(now() + 1_000).is_ok());
        assert_eq!(t.phase, Phase::Committed);
        assert!(t.note.contains("确认"));
    }

    /// ⚠ 这条是倒计时的意义所在：过期后确认必须失败。
    /// 否则"超时自动回滚 → 人再确认一次 → 又装回去"，而这第二次没人兜底。
    #[test]
    fn confirming_after_the_window_is_rejected() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        let late = now() + CONFIRM_WINDOW_MS + 500;
        assert_eq!(
            t.confirm(late),
            Err(ConfirmError::Expired { late_by_ms: 500 })
        );
        assert_eq!(t.phase, Phase::Pending, "失败的确认不能改变状态");
    }

    #[test]
    fn an_expired_pending_ticket_must_be_rolled_back() {
        let t = ticket(CONFIRM_WINDOW_MS);
        assert!(!t.must_roll_back(now()));
        assert!(t.must_roll_back(now() + CONFIRM_WINDOW_MS + 1));
    }

    /// 已确认的**不能**因为超时又被回滚，已回滚的不能回滚第二次。
    /// 重复执行"删除"会删到别的规则。
    #[test]
    fn a_decided_ticket_is_never_rolled_back_again() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        t.confirm(now()).unwrap();
        assert!(!t.must_roll_back(now() + CONFIRM_WINDOW_MS * 10));

        let mut t2 = ticket(CONFIRM_WINDOW_MS);
        t2.mark_rolled_back("超时");
        assert!(!t2.must_roll_back(now() + CONFIRM_WINDOW_MS * 10));
        assert_eq!(t2.phase, Phase::RolledBack);
    }

    /// 主动 rollback 不等超时——人在现场发现不对，不该被倒计时挡着。
    #[test]
    fn an_abort_request_rolls_back_immediately() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        assert!(!t.must_roll_back(now()));
        t.request_abort();
        assert!(t.must_roll_back(now()), "主动拆除不该等超时");
    }

    /// 已经确认过的不能再被"主动拆除"推翻成回滚——
    /// 那样 `rollback` 就等于一个能远程断网的命令。
    #[test]
    fn an_abort_after_commit_does_not_undo_the_decision() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        t.confirm(now()).unwrap();
        t.request_abort();
        assert!(!t.must_roll_back(now()));
    }

    /// 强拆是兜底手册的命脉：已**确认**的规则也必须能被一条命令撤掉。
    /// `request_abort` 做不到这件事（见上一条测试），强拆可以。
    #[test]
    fn a_force_teardown_undoes_even_a_committed_ticket() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        t.confirm(now()).unwrap();
        assert!(!t.must_roll_back(now()), "普通拆除不该推翻已确认的决定");
        t.force_teardown();
        assert!(t.must_roll_back(now()), "强拆必须立即生效，不看阶段也不看倒计时");
    }

    /// 撤完之后不能照着同一个强拆标记再撤一遍——
    /// 第二次删除在 id 被复用的情况下会删到别人的规则。
    #[test]
    fn a_force_teardown_is_cleared_once_it_has_been_carried_out() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        t.force_teardown();
        assert!(t.must_roll_back(now()));
        t.mark_rolled_back("强拆完成");
        assert!(!t.must_roll_back(now()), "已回滚的不能再回滚");
        assert!(!t.force_teardown);
        assert_eq!(t.phase, Phase::RolledBack);
    }

    #[test]
    fn a_fresh_ticket_is_not_marked_for_teardown() {
        assert!(!ticket(CONFIRM_WINDOW_MS).force_teardown);
    }

    #[test]
    fn confirming_twice_is_an_error() {
        let mut t = ticket(CONFIRM_WINDOW_MS);
        t.confirm(now()).unwrap();
        assert_eq!(
            t.confirm(now() + 1),
            Err(ConfirmError::AlreadyDecided {
                phase: Phase::Committed
            })
        );
    }

    /// `u64` 下溢会把"还剩多少"变成一个天文数字，进而让过期判断整个反过来。
    #[test]
    fn remaining_ms_never_underflows() {
        let t = ticket(1_000);
        assert_eq!(t.remaining_ms(now() + 5_000), 0, "过期后必须是 0，不是负数回绕");
    }

    // ── 条件白名单 ────────────────────────────────────────────────────

    #[test]
    fn mappable_conditions_are_exactly_the_five_we_can_translate() {
        assert!(mappable(&Condition::RemotePort(53)));
        assert!(mappable(&Condition::LocalPort(68)));
        assert!(mappable(&Condition::RemoteAddrV4(std::net::Ipv4Addr::new(127, 0, 0, 1))));
        assert!(mappable(&Condition::Loopback));
        assert!(mappable(&Condition::SystemServiceHost));
        assert!(!mappable(&Condition::ProcessId(1)));
        assert!(!mappable(&Condition::PhysicalInterface));
    }

    /// **回归**：`ServicePid` 那个版本把 `ALE_APP_ID` 填成了 `UINT64(pid)`，
    /// 真机下发时内核回 `0x80320027`（类型不匹配）。枚举里已经没有 PID 了，
    /// 这条测试钉住"按进程身份"只能走 AppId blob 这一条路。
    #[test]
    fn the_only_process_condition_we_claim_is_the_app_id_blob() {
        assert!(Condition::SystemServiceHost.is_mappable_process_identity());
        assert!(!Condition::ProcessId(1).is_mappable_process_identity());
    }

    /// Boot 层不允许任何"按进程"的条件——引导时间还没有进程，
    /// 写上去就是一条永不匹配的死规则，表现是开机即断网。
    #[test]
    fn process_identity_conditions_are_never_static() {
        assert!(!Condition::SystemServiceHost.is_static());
        assert!(!Condition::ProcessId(1).is_static());
    }

    #[test]
    fn unmappable_conditions_are_all_reported_not_just_the_first() {
        let plan = vec![
            FilterSpec {
                name: "a",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: 1,
                conditions: vec![Condition::PhysicalInterface],
                tier: Tier::Runtime,
            },
            FilterSpec {
                name: "b",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: 1,
                conditions: vec![Condition::ProcessId(9)],
                tier: Tier::Runtime,
            },
        ];
        let bad = unmappable_conditions(&plan);
        assert_eq!(bad, vec!["PhysicalInterface", "ProcessId"]);
    }

    /// Boot 规则不能被这条路装上去：装错了重启都清不掉。
    #[test]
    fn boot_rules_are_detected_before_anything_is_installed() {
        let plan = vec![FilterSpec {
            name: "boot",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: 1,
            conditions: vec![],
            tier: Tier::Boot,
        }];
        assert!(has_boot_rules(&plan));
        assert_eq!(
            preflight(&plan),
            Err(RefuseReason::BootRulesPresent { count: 1 })
        );
    }

    /// 默认策略产出的计划里没有 Boot 规则，也不该有映射不了的条件——
    /// 否则 `aegisctl apply` 从第一天起就是个摆设。
    #[test]
    fn the_default_cage_plan_passes_the_condition_preflight() {
        let plan = crate::plan::cage_plan(CagePolicy::default());
        assert!(!has_boot_rules(&plan));
        let bad = unmappable_conditions(&plan);
        assert!(bad.is_empty(), "默认计划含无法映射的条件：{bad:?}");
    }
}
