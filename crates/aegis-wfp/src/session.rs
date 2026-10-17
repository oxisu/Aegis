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
    /// 打开一个**动态**会话。
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
        if rc != 0 {
            return Err(WfpError::EngineOpen(rc));
        }
        Ok(Self { handle })
    }

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
    pub fn snapshot(&self) -> Result<Snapshot, WfpError> {
        let entries = self.providers()?;
        let filters = self.filters(&entries)?;
        let providers = entries.into_iter().map(|e| e.summary).collect();
        Ok(Snapshot { filters, providers })
    }

    /// 枚举 Provider，同时保留其 GUID 以便给过滤器做归属解析。
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

            let mut out = Vec::new();
            if !entries.is_null() {
                for &p in std::slice::from_raw_parts(entries, count as usize) {
                    if p.is_null() {
                        continue;
                    }
                    let r = &*p;
                    out.push(ProviderEntry {
                        key: r.providerKey,
                        summary: ProviderSummary {
                            name: pwstr_to_string(r.displayData.name),
                            service: pwstr_to_string(r.serviceName),
                            raw_flags: r.flags,
                        },
                    });
                }
                wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(out)
        }
    }

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

            let mut out = Vec::new();
            if !entries.is_null() {
                for &p in std::slice::from_raw_parts(entries, count as usize) {
                    if p.is_null() {
                        continue;
                    }
                    let f = &*p;
                    let (owner_name, owner_service) =
                        match provider_of(providers, f.providerKey.as_ref()) {
                            Some((n, s)) => (Some(n), s),
                            None => (None, None),
                        };
                    out.push(FilterSummary {
                        id: f.filterId,
                        name: pwstr_to_string(f.displayData.name),
                        layer: layer_name(&f.layerKey),
                        action: action_name(f.action.r#type).to_string(),
                        terminal: action_is_terminal(f.action.r#type),
                        flags: FilterFlags(f.flags.0),
                        provider: owner_name,
                        provider_service: owner_service,
                    });
                }
                wfp::FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            Ok(out)
        }
    }
}

/// Provider 条目：GUID + 摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderEntry {
    pub(crate) key: GUID,
    pub(crate) summary: ProviderSummary,
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
    use crate::model::FLAG_PERSISTENT;

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
