//! `aegis-orchestrator` —— 应用层适配器的 **SPI**（design-spec §2A.4）。
//!
//! # 它要解决的问题
//!
//! Aegis 的底座（WFP 绝缘笼、53 封锁、网口熔断）不依赖任何上层代理软件。
//! 但"出海"这件事终究要有个软件来做（Clash / sing-box / HypoMux）。
//! 于是需要一个**适配器层**把上层软件接进来——同时保证：
//! **接不好不会变成漏流量。**
//!
//! # 三个必须守住的判断
//!
//! 1. **SPI 按"能力"切，不按"软件"切**（[`capability`]）。
//!    按软件切的下场是换个软件就改 trait，那不叫可插拔。
//! 2. **"不支持"与"失败"是两个东西**（[`error`]）。
//!    混在一起的后果不是代码难看，是"Aegis 一直重试一个永远不可能成功的能力"
//!    和"适配器真挂了却被当成本来就不支持而静默吞掉"。
//! 3. **能力缺失时怎么办，必须写死在代码里**（[`Capability::fallback`]）。
//!    "Fail-Closed 或告警"留给运行时判断，就会出现
//!    "本该断网的时候只是弹了个提示"。
//!
//! # 关于"能不能确保适配"
//!
//! **不能。** 薄适配器永远无法"确保"适配任意软件——内部配置格式与生命周期
//! 差异太大，追求这一点只会被逼回源码内嵌。所以本 crate 的目标不是"确保适配"，
//! 而是两件事：
//!
//! - 把"适配"变成可判定的命题：**同一组 fixture 过没过**（[`contract`]）；
//! - 不适配时给出明确的错误码与处置（[`AdapterError::disposition`]），
//!   而不是含糊的"适配器错误"。
//!
//! # 边界
//!
//! 本 crate **不碰系统、不启进程、不提权**。参考实现是一个由场景驱动的纯模型
//! （[`reference`]）：契约测试要验的是适配器的**语义**，不是"这个软件装没装"。

pub mod capability;
pub mod contract;
pub mod error;
pub mod op;
pub mod reference;
pub mod spi;

pub use capability::{Capability, Fallback};
pub use contract::{
    check, run, CaseResult, ContractCase, ContractReport, Expect, Input, UNPERMITTED_TUN,
};
pub use error::{invariant, AdapterError};
pub use op::{Op, Outcome};
pub use reference::{fragment_text, ReferenceAdapter, Scenario};
pub use spi::{
    audit_declaration, has_harmless_probe, invoke_checked, matrix, Adapter, DeclarationCheck,
    Matrix, MatrixRow,
};

use aegis_version as version;

/// 本 crate 所属项目的完整版本号。
pub fn full_version() -> String {
    version::full()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_version_is_the_project_version_not_a_placeholder() {
        let v = full_version();
        assert!(!v.is_empty());
        assert_ne!(v, "xyzzy");
        assert!(v.starts_with("0."), "{v}");
    }

    /// 端到端：一个诚实的适配器 → 能力矩阵无 Fail-Closed 缺口 → 契约全绿
    /// → 声明自检通过。这是"接进来"这件事的完整判定链，缺任何一环都不算适配好。
    ///
    /// ⚠ **顺序不可调换**：[`audit_declaration`] 会真的 reload 一次（这是它的
    /// 意义所在），之后健康检查就报新版本号了。放在契约之前跑，会让契约里
    /// "健康检查报当前版本"这条用例假红。
    #[test]
    fn end_to_end_from_declaration_to_contract() {
        let adapter = ReferenceAdapter::new("ref", Scenario::sample());

        let m = matrix(&adapter);
        assert!(m.fail_closed_gaps().is_empty(), "{:?}", m.fail_closed_gaps());
        assert!(m.usable());

        let report = check(&adapter, &Scenario::sample());
        assert!(report.passed(), "{}", report.summary());

        let checks = audit_declaration(&adapter);
        assert!(checks.iter().all(DeclarationCheck::is_honest), "{checks:?}");
    }

    /// 反面：一个"有 TUN、能接管出口，但没人管 53"的适配器——
    /// 缺 DNS 所有权是 Fail-Closed 缺口，出口必须判不可用，
    /// 哪怕它自己的契约一条都没红。
    ///
    /// 这两件事必须分开看：**契约过**说明适配器诚实，**矩阵可用**说明能力够。
    /// 诚实但能力不够，仍然是不能用。
    #[test]
    fn an_honest_adapter_with_a_fail_closed_gap_is_still_unusable() {
        let mut adapter = ReferenceAdapter::new("ref", Scenario::sample());
        adapter.declare(&[Capability::TunInterfacePresent, Capability::ConfigFragmentGenerate]);

        // 它的契约全绿（没声明的能力都老老实实回 Unsupported）
        assert!(check(&adapter, &Scenario::sample()).passed());

        // 但矩阵说不行
        let m = matrix(&adapter);
        assert_eq!(
            m.fail_closed_gaps(),
            vec![
                Capability::DefaultEgress,
                Capability::ConfigFragmentGenerate,
                Capability::DnsOwnership,
            ]
            .into_iter()
            .filter(|c| c.fallback().is_fail_closed())
            .collect::<Vec<_>>()
        );
        assert!(!m.usable());
    }
}
