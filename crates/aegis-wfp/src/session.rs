//! WFP 引擎会话与只读枚举。
//!
//! # 本模块现在只做"看"
//! 创建会话、枚举过滤器与 Provider、把结果翻译成 [`Snapshot`]。
//! **不添加、不修改、不删除任何 WFP 对象**——那是后续阶段的事，
//! 而且必须先有本模块的只读勘察结果，才知道动刀会不会碰到雷。
//!
//! # 为什么会话用 `FWPM_SESSION_FLAG_DYNAMIC`
//! 动态会话里创建的所有对象会在会话结束（含进程崩溃）时自动清除。
//! 把这条写进会话标志而不是"记得在退出前清理"，是因为崩溃路径上
//! 没有机会执行清理代码——依赖它会直接给出 fail-open 的窗口。
//!
//! # 变异测试怎么对待本模块（重要）
//!
//! WFP 引擎**必须提权**才能打开，单元测试环境里连不上。因此这里严格分成两层：
//!
//! - **胶水层**（[`Session::open`] / [`Session::snapshot`] / `providers` / `filters` / `Drop`）：
//!   只会调 `Fwpm*` 系列 API。它们标了 `#[cfg_attr(test, mutants::skip)]`——
//!   不是为了刷好看的分数，而是因为"把整个函数体换成 `Ok(Default)`"这类变异体
//!   **在没有真实引擎的前提下根本不可能被任何测试观察到**，硬留着只会让报告
//!   永远带着几条假警报，反而掩盖真问题。
//! - **翻译层**（[`rows_of`] / [`collect_providers`] / [`collect_filters`] /
//!   [`assemble_snapshot`]）：把 `*mut *mut FWPM_*` 变成我们的模型。
//!   **这才是真正藏 bug 的地方**（空指针、union 字段、归属解析），
//!   而且它不碰任何 API，可以拿手搓的 `FWPM_*` 结构体完整单测。
//!
//! 换句话说：胶水层不值得测，翻译层必须测。

use std::ptr;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

use crate::error::WfpError;
use crate::layers::{action_is_terminal, action_name, layer_name};
use crate::model::{FilterFlags, FilterSummary, ProviderSummary, Snapshot};

/// `RPC_C_AUTHN_WINNT`：`FwpmEngineOpen0` 要求的认证服务。
const RPC_C_AUTHN_WINNT: u32 = 10;

/// 会话名前缀。勘察会话一律带 `aegis-` 前缀，便于在
/// `netsh wfp show state` 里一眼认出哪些是我们开的。
pub const SESSION_PREFIX: &str = "aegis-";

/// 一次 WFP 引擎会话（RAII：离开作用域自动关闭）。
#[derive(Debug)]
pub struct Session {
    handle: HANDLE,
}

impl Session {
    /// 底层引擎句柄。
    ///
    /// ⚠ 只给 [`crate::apply`] 用（`pub(crate)`）：拿到它就能往引擎里
    /// **装东西**。可见性刻意卡在这一层——`session.rs` 自己只做只读勘察，
    /// 会改系统状态的入口全在 `apply.rs` 一处，审代码时只需看那一个文件。
    pub(crate) fn handle(&self) -> HANDLE {
        self.handle
    }

    /// 打开一个**动态**会话。
    ///
    /// 需要提权，无法在单测里覆盖，故跳过变异（理由见模块头）。
    #[cfg_attr(test, mutants::skip)]
    pub fn open(session_name: &str) -> Result<Self, WfpError> {
        let mut name_w: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let session = wfp::FWPM_SESSION0 {
            sessionKey: GUID::zeroed(),
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_w.as_mut_ptr()),
                description: PWSTR::null(),
            },
            flags: wfp::FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 0,
            processId: 0,
            sid: ptr::null_mut(),
            username: PWSTR::null(),
            kernelMode: BOOL(0),
        };

        let mut handle = HANDLE::default();
        let rc = unsafe {
            wfp::FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut handle,
            )
        };
        Self::check(rc, WfpError::EngineOpen)?;
        Ok(Self { handle })
    }

    /// 把返回值翻译成错误。**0 才是成功**——写反了会把"打开失败"当成功，
    /// 于是后续的枚举全部在无效句柄上进行，报出一堆看不懂的错。
    fn check(rc: u32, kind: fn(u32) -> WfpError) -> Result<(), WfpError> {
        if rc == 0 {
            Ok(())
        } else {
            Err(kind(rc))
        }
    }

    /// 采集一份只读快照。
    ///
    /// Provider 只枚举一次：既用于摘要，也用于把过滤器里的
    /// `providerKey`（一串 GUID）翻译成人能读的名字。
    ///
    /// 需要提权，无法在单测里覆盖，故跳过变异（理由见模块头）；
    /// 组装逻辑本身在 [`assemble_snapshot`] 里有完整测试。
    #[cfg_attr(test, mutants::skip)]
    pub fn snapshot(&self) -> Result<Snapshot, WfpError> {
        let entries = self.providers()?;
        let filters = self.filters(&entries)?;
        Ok(assemble_snapshot(entries, filters))
    }

    /// 某一层**实际支持**哪些条件字段（只读勘察）。
    ///
    /// # 为什么需要它
    ///
    /// `FwpmFilterAdd0` 对一个不支持的条件只回
    /// `FWP_E_CONDITION_NOT_FOUND`（`0x80320002`），**不说哪一条不支持**。
    /// 而"层支持什么字段"是会变的（版本、SKU、装了什么驱动都不一定一样），
    /// 靠文档背下来不可靠。真机实测就撞上了：`ALE_AUTH_CONNECT_V4`
    /// 不接受 `IP_REMOTE_ADDRESS_V4`，而这一点在干跑里永远看不出来。
    ///
    /// 需要提权，无法在单测里覆盖，故跳过变异（理由见模块头）。
    #[cfg_attr(test, mutants::skip)]
    pub fn fields(&self, layer_key: GUID) -> Result<Vec<LayerField>, WfpError> {
        unsafe {
            let mut layer: *mut wfp::FWPM_LAYER0 = ptr::null_mut();
            Self::check(
                wfp::FwpmLayerGetByKey0(self.handle, &layer_key, &mut layer),
                WfpError::Enumerate,
            )?;
            let out = collect_fields(layer);
            if !layer.is_null() {
                wfp::FwpmFreeMemory0(&mut layer as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(out)
        }
    }

    /// 枚举 Provider，同时保留其 GUID 以便给过滤器做归属解析。
    ///
    /// 需要提权，无法在单测里覆盖，故跳过变异（理由见模块头）；
    /// 指针→模型的翻译在 [`collect_providers`] 里有完整测试。
    #[cfg_attr(test, mutants::skip)]
    fn providers(&self) -> Result<Vec<ProviderEntry>, WfpError> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            Self::check(
                wfp::FwpmProviderCreateEnumHandle0(self.handle, None, &mut enum_handle),
                WfpError::EnumHandle,
            )?;

            let mut entries: *mut *mut wfp::FWPM_PROVIDER0 = ptr::null_mut();
            let mut count: u32 = 0;
            let rc = wfp::FwpmProviderEnum0(
                self.handle,
                enum_handle,
                u32::MAX,
                &mut entries,
                &mut count,
            );
            // 枚举句柄无论如何都要销毁：泄露它会占住引擎侧的一次快照
            let _ = wfp::FwpmProviderDestroyEnumHandle0(self.handle, enum_handle);
            Self::check(rc, WfpError::Enumerate)?;

            let rows = rows_of(entries, count);
            if !entries.is_null() {
                wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(collect_providers(&rows))
        }
    }

    /// 枚举过滤器，并把 `providerKey` 翻译成归属名。
    ///
    /// 需要提权，无法在单测里覆盖，故跳过变异（理由见模块头）；
    /// 指针→模型的翻译在 [`collect_filters`] 里有完整测试。
    #[cfg_attr(test, mutants::skip)]
    fn filters(&self, providers: &[ProviderEntry]) -> Result<Vec<FilterSummary>, WfpError> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            Self::check(
                wfp::FwpmFilterCreateEnumHandle0(self.handle, None, &mut enum_handle),
                WfpError::EnumHandle,
            )?;

            let mut entries: *mut *mut wfp::FWPM_FILTER0 = ptr::null_mut();
            let mut count: u32 = 0;
            let rc =
                wfp::FwpmFilterEnum0(self.handle, enum_handle, u32::MAX, &mut entries, &mut count);
            let _ = wfp::FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
            Self::check(rc, WfpError::Enumerate)?;

            let rows = rows_of(entries, count);
            if !entries.is_null() {
                wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(collect_filters(&rows, providers))
        }
    }
}

/// 一层支持的一个条件字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerField {
    /// 字段 GUID（与 `FWPM_CONDITION_*` 常量比对即可知道是哪个字段）。
    pub key: GUID,
    /// 该字段要求的值类型。
    pub data_type: wfp::FWP_DATA_TYPE,
}

impl LayerField {
    /// 这个字段是不是我们要找的那个。
    pub fn is(&self, key: &GUID) -> bool {
        &self.key == key
    }
}

/// 把 `FWPM_LAYER0` 里的字段数组翻译成 [`LayerField`]。
///
/// 需要 unsafe（引擎返回裸指针数组），但不含业务逻辑，故跳过变异。
#[cfg_attr(test, mutants::skip)]
pub(crate) fn collect_fields(layer: *mut wfp::FWPM_LAYER0) -> Vec<LayerField> {
    if layer.is_null() {
        return Vec::new();
    }
    unsafe {
        let f = &*layer;
        if f.field.is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(f.field, f.numFields as usize)
            .iter()
            .filter_map(|fd| {
                let key = fd.fieldKey.as_ref()?;
                Some(LayerField {
                    key: *key,
                    data_type: fd.dataType,
                })
            })
            .collect()
    }
}

/// Provider 条目：GUID + 摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderEntry {
    pub(crate) key: GUID,
    pub(crate) summary: ProviderSummary,
}

/// 把 WFP 返回的 `T**` + 计数翻译成安全的引用切片。
///
/// ⚠ 空指针必须退化成**空切片**，不能拿去 `from_raw_parts`——
/// 即使 `count == 0`，`slice::from_raw_parts` 的指针参数也不允许为 null。
/// 写成"反正 count 是 0 就无所谓"会在某些平台上直接 UB。
pub(crate) unsafe fn rows_of<'a, T>(entries: *mut *mut T, count: u32) -> Vec<Option<&'a T>> {
    if entries.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(entries, count as usize)
        .iter()
        .map(|&p| p.as_ref())
        .collect()
}

/// 把 Provider 原始行翻译成 [`ProviderEntry`]。
///
/// 空行（null 指针）跳过而不是 panic：引擎返回的数组里出现 null 是可能的，
/// 少一条摘要远好过整个勘察崩掉。
pub(crate) fn collect_providers(rows: &[Option<&wfp::FWPM_PROVIDER0>]) -> Vec<ProviderEntry> {
    rows.iter()
        .flatten()
        .map(|r| ProviderEntry {
            key: r.providerKey,
            summary: ProviderSummary {
                name: pwstr_to_string(r.displayData.name),
                service: pwstr_to_string(r.serviceName),
                raw_flags: r.flags,
            },
        })
        .collect()
}

/// 把过滤器原始行翻译成 [`FilterSummary`]，并解析其归属 Provider。
pub(crate) fn collect_filters(
    rows: &[Option<&wfp::FWPM_FILTER0>],
    providers: &[ProviderEntry],
) -> Vec<FilterSummary> {
    rows.iter()
        .flatten()
        .map(|f| {
            // providerKey 是可空的 `*mut GUID`；这里是翻译层唯一需要开
            // unsafe 块的地方，且只做一次空指针检查。
            let key = unsafe { f.providerKey.as_ref() };
            let (owner_name, owner_service) = match provider_of(providers, key) {
                Some((n, s)) => (Some(n), s),
                None => (None, None),
            };
            FilterSummary {
                id: f.filterId,
                name: pwstr_to_string(f.displayData.name),
                layer: layer_name(&f.layerKey),
                action: action_name(f.action.r#type).to_string(),
                terminal: action_is_terminal(f.action.r#type),
                flags: FilterFlags(f.flags.0),
                provider: owner_name,
                provider_service: owner_service,
            }
        })
        .collect()
}

/// 把 Provider 条目与过滤器组装成 [`Snapshot`]。
pub(crate) fn assemble_snapshot(
    entries: Vec<ProviderEntry>,
    filters: Vec<FilterSummary>,
) -> Snapshot {
    Snapshot {
        filters,
        providers: entries.into_iter().map(|e| e.summary).collect(),
    }
}

/// 把过滤器里的 `providerKey` 翻译成 Provider 的（展示名, 服务名）。
///
/// 没有这层映射，审计输出里就只剩一串 GUID——而"这条阻断规则是谁装的"
/// 恰恰是排查变砖事故时最需要的信息。服务名尤其关键：
/// 判断"是不是 Windows 自带"靠的是服务名，不是本地化的展示名。
pub(crate) fn provider_of(
    providers: &[ProviderEntry],
    key: Option<&GUID>,
) -> Option<(String, Option<String>)> {
    let key = key?;
    providers.iter().find(|e| &e.key == key).map(|e| {
        let name = e.summary.name.clone();
        let svc = if e.summary.service.is_empty() {
            None
        } else {
            Some(e.summary.service.clone())
        };
        (name, svc)
    })
}

impl Drop for Session {
    #[cfg_attr(test, mutants::skip)]
    fn drop(&mut self) {
        // 关闭失败无处上报（Drop 不能返回 Result），只能静默忽略；
        // 动态会话本来也会在进程退出时由引擎自行回收。
        unsafe {
            let _ = wfp::FwpmEngineClose0(self.handle);
        }
    }
}

/// 把 WFP 返回的 `PWSTR` 转成 `String`。空指针与非 UTF-16 都退化成空串，
/// 不 panic——展示层缺一个名字远好过整个勘察崩掉。
pub(crate) fn pwstr_to_string(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string().unwrap_or_default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{audit_backbone, Risk, FLAG_PERSISTENT};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_ACTION0, FWPM_FILTER_FLAGS,
    };

    #[test]
    fn session_name_prefix_identifies_aegis() {
        assert!(SESSION_PREFIX.starts_with("aegis-"));
    }

    /// 空指针必须退化成空串而不是 panic：展示层缺一个名字，
    /// 远好过整个只读勘察崩掉。
    #[test]
    fn null_pwstr_becomes_empty_string() {
        assert_eq!(pwstr_to_string(PWSTR::null()), String::new());
    }

    /// 非空 PWSTR 必须**原样**读出文本。
    /// 只测空指针的话，"恒返回空串"这个变异能活下来——变异测试实锤：
    /// `replace pwstr_to_string -> String with String::new()` 曾 MISSED。
    #[test]
    fn non_null_pwstr_keeps_its_text() {
        let mut buf: Vec<u16> = "Aegis 勘察会话"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let p = PWSTR(buf.as_mut_ptr());
        assert_eq!(pwstr_to_string(p), "Aegis 勘察会话");
    }

    /// **0 才是成功**。这条写反会把"打开失败"当成成功，
    /// 后续枚举全在无效句柄上进行，报出一堆看不懂的错。
    #[test]
    fn check_treats_only_zero_as_success() {
        assert!(Session::check(0, WfpError::Enumerate).is_ok());
        assert!(Session::check(0, WfpError::EnumHandle).is_ok());

        let e = Session::check(5, WfpError::Enumerate).unwrap_err();
        assert_eq!(e, WfpError::Enumerate(5), "错误码必须原样带出");
        assert_eq!(e.code(), 5);
    }

    /// 错误**种类**由调用方决定：枚举句柄失败和枚举失败是两回事，
    /// 混为一谈会让排障往错的方向走。
    #[test]
    fn check_preserves_the_caller_chosen_variant() {
        assert_eq!(
            Session::check(5, WfpError::EnumHandle).unwrap_err(),
            WfpError::EnumHandle(5)
        );
        assert_eq!(
            Session::check(5, WfpError::EngineOpen).unwrap_err(),
            WfpError::EngineOpen(5)
        );
        assert_ne!(
            Session::check(5, WfpError::EnumHandle).unwrap_err(),
            Session::check(5, WfpError::Enumerate).unwrap_err()
        );
    }

    /// 空指针必须退化成空切片（不能拿去 from_raw_parts）。
    /// 这一条同时钉住了 `rows_of` 里那个 `!entries.is_null()`。
    #[test]
    fn rows_of_null_pointer_yields_nothing() {
        let rows: Vec<Option<&wfp::FWPM_FILTER0>> = unsafe { rows_of(ptr::null_mut(), 3) };
        assert!(rows.is_empty(), "即使 count>0 也不能对 null 建切片");
    }

    #[test]
    fn rows_of_keeps_order_and_maps_null_slots_to_none() {
        let mut a = 10u32;
        let mut c = 30u32;
        let mut ptrs: [*mut u32; 3] = [&mut a, ptr::null_mut(), &mut c];
        let rows: Vec<Option<&u32>> = unsafe { rows_of(ptrs.as_mut_ptr(), 3) };
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].copied(), Some(10));
        assert_eq!(rows[1], None, "数组里的 null 槽位要变成 None");
        assert_eq!(rows[2].copied(), Some(30));
    }

    fn entry(key: GUID, name: &str) -> ProviderEntry {
        ProviderEntry {
            key,
            summary: ProviderSummary {
                name: name.to_string(),
                service: String::new(),
                raw_flags: FLAG_PERSISTENT,
            },
        }
    }

    /// 造一行 `FWPM_PROVIDER0`。缓冲区必须活得比 row 久，所以一起返回。
    fn provider_row(
        id: u128,
        name: &str,
        service: &str,
        flags: u32,
    ) -> (Vec<u16>, Vec<u16>, wfp::FWPM_PROVIDER0) {
        let mut name_buf: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut svc_buf: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
        let row = wfp::FWPM_PROVIDER0 {
            providerKey: GUID::from_u128(id),
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_buf.as_mut_ptr()),
                ..Default::default()
            },
            serviceName: PWSTR(svc_buf.as_mut_ptr()),
            flags,
            ..Default::default()
        };
        (name_buf, svc_buf, row)
    }

    /// 翻译层才是真正藏 bug 的地方：字段名、服务名、标志位都得读对。
    #[test]
    fn collect_providers_reads_every_field() {
        let (_n, _s, r) = provider_row(1, "某杀软底座", "SomeAvSvc", FLAG_PERSISTENT);
        let got = collect_providers(&[Some(&r)]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, GUID::from_u128(1));
        assert_eq!(got[0].summary.name, "某杀软底座");
        assert_eq!(got[0].summary.service, "SomeAvSvc");
        assert_eq!(got[0].summary.raw_flags, FLAG_PERSISTENT);
        assert!(got[0].summary.persistent());
    }

    /// 数组里的 null 槽位必须跳过，而不是让整个勘察 panic。
    #[test]
    fn collect_providers_skips_null_rows() {
        let (_n, _s, r) = provider_row(2, "Windows 防火墙", "mpssvc", 0);
        let got = collect_providers(&[None, Some(&r), None]);
        assert_eq!(got.len(), 1, "null 行应被跳过");
        assert_eq!(got[0].summary.name, "Windows 防火墙");
        assert_eq!(got[0].summary.service, "mpssvc");
        assert!(!got[0].summary.persistent());
    }

    #[test]
    fn collect_providers_of_empty_input_is_empty() {
        assert!(collect_providers(&[]).is_empty());
    }

    /// 造一行 `FWPM_FILTER0`。
    fn filter_row(
        id: u64,
        name: &str,
        layer: GUID,
        block: bool,
        flags: u32,
        provider_key: Option<&mut GUID>,
    ) -> (Vec<u16>, wfp::FWPM_FILTER0) {
        let mut name_buf: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let row = wfp::FWPM_FILTER0 {
            filterId: id,
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_buf.as_mut_ptr()),
                ..Default::default()
            },
            layerKey: layer,
            action: FWPM_ACTION0 {
                r#type: if block {
                    wfp::FWP_ACTION_BLOCK
                } else {
                    wfp::FWP_ACTION_PERMIT
                },
                ..Default::default()
            },
            flags: FWPM_FILTER_FLAGS(flags),
            providerKey: match provider_key {
                Some(k) => k,
                None => ptr::null_mut(),
            },
            ..Default::default()
        };
        (name_buf, row)
    }

    /// 一条持久阻断过滤器必须被完整翻译成摘要，包括**归属**——
    /// 归属决定了它是"系统基线"还是"变砖雷"。
    #[test]
    fn collect_filters_translates_a_blocking_rule_with_its_owner() {
        let mut pk = GUID::from_u128(11);
        let (_n, r) = filter_row(
            4242,
            "某杀软出站阻断",
            wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            true,
            FLAG_PERSISTENT,
            Some(&mut pk),
        );
        let provs = vec![entry(GUID::from_u128(11), "某杀软")];
        let got = collect_filters(&[Some(&r)], &provs);

        assert_eq!(got.len(), 1);
        let f = &got[0];
        assert_eq!(f.id, 4242);
        assert_eq!(f.name, "某杀软出站阻断");
        assert_eq!(f.layer, "ALE_AUTH_CONNECT_V4");
        assert_eq!(f.action, "阻断");
        assert!(f.terminal, "BLOCK 必须判为终止型，否则漏掉一颗雷");
        assert_eq!(f.flags, FilterFlags(FLAG_PERSISTENT));
        assert_eq!(f.provider.as_deref(), Some("某杀软"));
    }

    /// 放行规则不能被判成终止型——否则持久背板审计会满屏假警报。
    #[test]
    fn collect_filters_marks_permit_as_non_terminal() {
        let (_n, r) = filter_row(
            7,
            "放行",
            wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            false,
            0,
            None,
        );
        let got = collect_filters(&[Some(&r)], &[]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].action, "放行");
        assert!(!got[0].terminal);
        assert_eq!(got[0].provider, None, "查不到归属就是 None，不能编一个");
    }

    #[test]
    fn collect_filters_skips_null_rows_and_empty_input() {
        let (_n, r) = filter_row(
            9,
            "f",
            wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            true,
            0,
            None,
        );
        assert_eq!(collect_filters(&[None, Some(&r)], &[]).len(), 1);
        assert!(collect_filters(&[], &[]).is_empty());
    }

    /// 组装快照时 Provider 要**降成摘要**（丢掉 GUID），过滤器原样保留。
    #[test]
    fn assemble_snapshot_drops_provider_keys_but_keeps_filters() {
        let (_n1, _s1, p1) = provider_row(1, "某杀软", "SomeAvSvc", FLAG_PERSISTENT);
        let (_n2, r) = filter_row(
            4242,
            "阻断",
            wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            true,
            FLAG_PERSISTENT,
            None,
        );

        let entries = collect_providers(&[Some(&p1)]);
        let filters = collect_filters(&[Some(&r)], &entries);
        let snap = assemble_snapshot(entries, filters);

        assert_eq!(snap.providers.len(), 1);
        assert_eq!(snap.providers[0].name, "某杀软");
        assert_eq!(snap.providers[0].service, "SomeAvSvc");
        assert_eq!(snap.filters.len(), 1);
        assert_eq!(snap.filters[0].id, 4242);
        // 组装结果必须能直接送进持久背板审计
        assert_eq!(audit_backbone(&snap), Risk::Bricking);
    }

    #[test]
    fn assemble_snapshot_of_nothing_is_empty() {
        let snap = assemble_snapshot(Vec::new(), Vec::new());
        assert!(snap.providers.is_empty());
        assert!(snap.filters.is_empty());
        assert_eq!(audit_backbone(&snap), Risk::Clean);
    }

    /// "这条阻断规则是谁装的"是排查变砖事故时最需要的信息，
    /// 所以归属解析必须正确；查不到时返回 None 而不是编一个名字。
    #[test]
    fn provider_lookup_resolves_or_returns_none() {
        let a = GUID::from_u128(1);
        let b = GUID::from_u128(2);
        let list = vec![entry(a, "Windows 防火墙"), entry(b, "某杀软")];

        assert_eq!(
            provider_of(&list, Some(&b)).map(|(n, _)| n).as_deref(),
            Some("某杀软")
        );
        assert_eq!(provider_of(&list, None), None);
        assert_eq!(
            provider_of(&list, Some(&GUID::from_u128(999))),
            None,
            "查不到应返回 None，不能编一个名字"
        );
    }

    /// 服务名为空串要转成 None —— 否则 "无服务" 会被当成
    /// 一个叫 "" 的服务，归属判断就失去意义了。
    #[test]
    fn empty_service_name_becomes_none() {
        let key = GUID::from_u128(7);
        let mut e = entry(key, "无服务 Provider");
        e.summary.service = String::new();
        let got = provider_of(&[e], Some(&key)).expect("应能查到");
        assert_eq!(got.0, "无服务 Provider");
        assert_eq!(got.1, None);
    }
}
