//! WFP 调用错误。
//!
//! # 为什么不做 panic
//! 守护进程 panic = 绝缘笼可能没来得及装好 = fail-open 的那一瞬间。
//! 因此所有 Win32 / WFP 失败都原样带上错误码向上传递，由调用方决定
//! 是降级还是退出。
//!
//! # 为什么要给错误码配人类可读的提示
//! 光有 `0x5` 没人知道该怎么办。枚举 WFP 在有机器上需要提权，
//! 而"需要管理员权限"和"WFP 服务没启动"两种失败的处置完全不同。

use std::fmt;

/// WFP 操作失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpError {
    /// `FwpmEngineOpen0` 失败
    EngineOpen(u32),
    /// 创建枚举句柄失败
    EnumHandle(u32),
    /// 枚举过程失败
    Enumerate(u32),
    /// 关闭引擎失败（通常在 Drop 里，仅记录）
    EngineClose(u32),
    /// `FwpmFilterAdd0` 失败
    FilterAdd(u32),
    /// `FwpmFilterDeleteById0` / `FwpmProviderDeleteByKey0` 失败
    Delete(u32),
    /// `FwpmProviderAdd0` 失败
    ProviderAdd(u32),
    /// 遇到了无法精确映射成 WFP 字段的条件。
    ///
    /// ⚠ 出现这个错误意味着**没有下发任何规则**——宁可不装，
    /// 也不把条件翻译成"差不多"的另一个字段。
    ///
    /// 名字用 `&'static str` 而不是 `String`：`WfpError` 是 `Copy`，
    /// 调用方到处按值传。为一个只在拒绝路径出现的错误破掉 `Copy`
    /// 不划算，而这些名字本来就是有限的几个常量。
    UnsupportedCondition { name: &'static str },
}

impl WfpError {
    /// 原始错误码。
    pub fn code(self) -> u32 {
        match self {
            Self::EngineOpen(c)
            | Self::EnumHandle(c)
            | Self::Enumerate(c)
            | Self::EngineClose(c)
            | Self::FilterAdd(c)
            | Self::Delete(c)
            | Self::ProviderAdd(c) => c,
            Self::UnsupportedCondition { .. } => 0,
        }
    }

    /// 是否为 WFP 自己的错误码（`FWP_E_*`，以 HRESULT 形式返回）。
    ///
    /// 区分这个很重要：Win32 错误码和 WFP 错误码的数值空间重叠语义完全不同，
    /// 混着排查会把人带偏。
    pub fn is_wfp_code(self) -> bool {
        self.code() >= 0x8000_0000
    }

    /// 针对已知错误码给出处置建议。
    pub fn hint(self) -> Option<&'static str> {
        match self.code() {
            5 => Some("访问被拒绝：枚举 WFP 通常需要管理员权限。请以管理员身份运行；Aegis 的只读勘察在权限不足时会明确报出，而不会假装什么都看不到。"),
            740 => Some("需要 UAC 提升。"),
            1060 => Some("WFP 相关服务（BFE）可能未运行。"),
            1757 => Some("基础筛选引擎（BFE）未运行或不可达。"),
            _ => None,
        }
    }
}

impl fmt::Display for WfpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::EngineOpen(_) => "打开 WFP 引擎",
            Self::EnumHandle(_) => "创建枚举句柄",
            Self::Enumerate(_) => "枚举",
            Self::EngineClose(_) => "关闭 WFP 引擎",
            Self::FilterAdd(_) => "下发 WFP 规则",
            Self::Delete(_) => "删除 WFP 对象",
            Self::ProviderAdd(_) => "注册 WFP Provider",
            Self::UnsupportedCondition { name } => {
                return write!(
                    f,
                    "条件无法精确映射到 WFP 字段：{name}（本次未下发任何规则）"
                )
            },
        };
        write!(f, "{what}失败（错误码 0x{:08X}", self.code())?;
        if self.is_wfp_code() {
            write!(f, "，WFP 错误码")?;
        }
        write!(f, ")")?;
        if let Some(h) = self.hint() {
            write!(f, "：{h}")?;
        }
        Ok(())
    }
}

impl std::error::Error for WfpError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_is_exposed_regardless_of_variant() {
        assert_eq!(WfpError::EngineOpen(5).code(), 5);
        assert_eq!(WfpError::Enumerate(0x8032_0009).code(), 0x8032_0009);
    }

    /// Win32 错误码与 WFP HRESULT 必须能分开——混着排查会把人带偏。
    #[test]
    fn distinguishes_win32_from_wfp_error_space() {
        assert!(!WfpError::EngineOpen(5).is_wfp_code());
        assert!(!WfpError::EngineOpen(740).is_wfp_code());
        assert!(WfpError::Enumerate(0x8032_0009).is_wfp_code());
    }

    #[test]
    fn access_denied_gets_an_actionable_hint() {
        let e = WfpError::EngineOpen(5);
        assert!(e.hint().is_some());
        assert!(e.to_string().contains("管理员"));
        assert!(e.to_string().contains("0x00000005"));
    }

    /// 每一个登记过的错误码都要有自己的处置建议，且各不相同。
    ///
    /// "需要 UAC 提升"和"BFE 没运行"是两种完全不同的失败，共用一条提示
    /// 会让用户照着错误的方向排查。变异测试曾把其中三条 match arm
    /// 整条删掉而测试仍然全绿——因为原测试只断言了错误码 5 那一条。
    #[test]
    fn every_documented_code_has_its_own_hint() {
        let cases: &[(u32, &str)] = &[(5, "管理员"), (740, "UAC"), (1060, "BFE"), (1757, "BFE")];
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (code, keyword) in cases {
            let hint = WfpError::EngineOpen(*code)
                .hint()
                .unwrap_or_else(|| panic!("错误码 {code} 缺少处置建议"));
            assert!(
                hint.contains(keyword),
                "错误码 {code} 的提示应提到 {keyword}：{hint}"
            );
            assert!(
                seen.insert(hint),
                "错误码 {code} 的提示与其他码重复：{hint}"
            );
        }
    }

    /// 提示必须与"哪个码"绑死：删掉任意一条 match arm 都要被抓到。
    #[test]
    fn hints_differ_per_code() {
        assert_ne!(
            WfpError::EngineOpen(1060).hint(),
            WfpError::EngineOpen(1757).hint()
        );
        assert_ne!(
            WfpError::EngineOpen(5).hint(),
            WfpError::EngineOpen(740).hint()
        );
        assert!(WfpError::EngineOpen(1060).hint().unwrap().contains("服务"));
        assert!(WfpError::EngineOpen(1757).hint().unwrap().contains("引擎"));
    }

    #[test]
    fn unknown_codes_have_no_hint_but_still_print() {
        let e = WfpError::Enumerate(0x8032_0009);
        assert!(e.hint().is_none());
        let s = e.to_string();
        assert!(s.contains("0x80320009"), "{s}");
        assert!(s.contains("WFP 错误码"), "{s}");
    }
}
