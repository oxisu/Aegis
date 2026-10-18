//! 网口变动通知的**分类与是否响应**（纯逻辑，不调用任何 Win32 API）。
//!
//! # 为什么"要不要响应"必须是纯函数
//!
//! 这条判断会跑在系统回调里，而回调里出错的代价极高：
//! - 把**初始通知**当成真实变动 → 服务一启动就拉绝缘 → 用户一开机就断网，
//!   而且看不出为什么（日志上只是"检测到网口变动"）
//! - 把**真实变动**当噪声丢掉 → 熔断晚了一个窗口 → 漏包恰恰发生在这几十毫秒里
//!
//! 两种错法的后果都不小，所以判断逻辑必须能脱离回调、脱离 Win32 单测。
//! 真正的回调只留三行：`from_raw` → `should_react` → `signal()`。

/// `MIB_NOTIFICATION_TYPE` 的原始取值（netioapi.h）。
///
/// 用裸 `i32` 镜像一份，是为了让本模块能在没有 `windows` crate 的情况下
/// 被推演；是否漂移由 tests::constants_match_windows_headers 守着。
pub mod raw {
    /// 已存在条目的某个参数变了（例如路由度量改了 → 默认出口可能变了）
    pub const PARAMETER: i32 = 0;
    /// 新增条目
    pub const ADD: i32 = 1;
    /// 删除条目
    pub const DELETE: i32 = 2;
    /// 注册时给的**初始**通知——它不是"变化"
    pub const INITIAL: i32 = 3;
}

/// 一次网口变动通知的种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// 已有条目的参数变了（度量、MTU …）
    Parameter,
    /// 新增了一个 IP 接口
    Add,
    /// 删掉了一个 IP 接口
    Delete,
    /// 注册回调时同步发来的初始通知。**不是变动。**
    Initial,
    /// 未登记的值。宁可标成未知并照常响应，也不要当成噪声丢掉。
    Unknown(i32),
}

impl ChangeKind {
    /// 从 `MIB_NOTIFICATION_TYPE` 的原始值翻译过来。
    pub fn from_raw(v: i32) -> Self {
        match v {
            raw::PARAMETER => Self::Parameter,
            raw::ADD => Self::Add,
            raw::DELETE => Self::Delete,
            raw::INITIAL => Self::Initial,
            other => Self::Unknown(other),
        }
    }

    /// 是否为注册时的初始通知。
    pub fn is_initial(&self) -> bool {
        matches!(self, Self::Initial)
    }

    /// 是否为**结构**变化（接口增删）。
    ///
    /// 结构变化比参数变化严重得多：新增接口意味着可能出现一条新的默认路由，
    /// 而那正是"流量从没被授权的口子出去"的场景。
    pub fn is_structural(&self) -> bool {
        matches!(self, Self::Add | Self::Delete)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Parameter => "参数变化",
            Self::Add => "新增接口",
            Self::Delete => "删除接口",
            Self::Initial => "初始通知（非变动）",
            Self::Unknown(_) => "未知类型",
        }
    }
}

impl core::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// 这次通知**该不该触发熔断链路**。
///
/// 唯一的排除项是初始通知：注册时若开了 `initialnotification`，系统会立刻
/// 把所有现存接口喂一遍，那不是"拓扑变了"。响应它会让服务一启动就拉绝缘。
///
/// 未登记的值**照常响应**：宁可多熔断一次让用户确认，也不能因为"不认识"
/// 就把真实变动当噪声丢掉——后者是静默的，没人会知道漏了。
pub fn should_react(kind: ChangeKind) -> bool {
    !kind.is_initial()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::IpHelper::{
        MibAddInstance, MibDeleteInstance, MibInitialNotification, MibParameterNotification,
    };

    /// 镜像常量必须与头文件一致，否则会把"新增接口"判成别的类型。
    #[test]
    fn constants_match_windows_headers() {
        assert_eq!(raw::PARAMETER, MibParameterNotification.0);
        assert_eq!(raw::ADD, MibAddInstance.0);
        assert_eq!(raw::DELETE, MibDeleteInstance.0);
        assert_eq!(raw::INITIAL, MibInitialNotification.0);
    }

    #[test]
    fn from_raw_maps_every_documented_value() {
        assert_eq!(ChangeKind::from_raw(0), ChangeKind::Parameter);
        assert_eq!(ChangeKind::from_raw(1), ChangeKind::Add);
        assert_eq!(ChangeKind::from_raw(2), ChangeKind::Delete);
        assert_eq!(ChangeKind::from_raw(3), ChangeKind::Initial);
    }

    /// 未登记的值必须保留原始值，不能悄悄折叠成某个已知类型。
    #[test]
    fn unknown_values_keep_their_raw_number() {
        assert_eq!(ChangeKind::from_raw(99), ChangeKind::Unknown(99));
        assert_eq!(ChangeKind::from_raw(-1), ChangeKind::Unknown(-1));
    }

    /// **最要紧的一条**：初始通知不是变动。响应它会让服务一启动就拉绝缘，
    /// 用户一开机就断网，且日志上只写"检测到网口变动"，看不出为什么。
    #[test]
    fn initial_notification_is_not_a_change() {
        assert!(!should_react(ChangeKind::Initial));
        assert!(ChangeKind::Initial.is_initial());
    }

    #[test]
    fn real_changes_do_react() {
        assert!(should_react(ChangeKind::Add));
        assert!(should_react(ChangeKind::Delete));
        assert!(should_react(ChangeKind::Parameter));
    }

    /// 不认识的类型也响应：漏掉真实变动是静默失败，多熔断一次不是。
    #[test]
    fn unknown_kind_still_reacts() {
        assert!(should_react(ChangeKind::Unknown(4242)));
    }

    #[test]
    fn structural_detects_interface_add_remove() {
        assert!(ChangeKind::Add.is_structural());
        assert!(ChangeKind::Delete.is_structural());
        assert!(!ChangeKind::Parameter.is_structural());
        assert!(!ChangeKind::Initial.is_structural());
        assert!(!ChangeKind::Unknown(0).is_structural());
    }

    #[test]
    fn labels_are_readable_and_distinct() {
        assert_eq!(ChangeKind::Add.label(), "新增接口");
        assert_eq!(ChangeKind::Delete.label(), "删除接口");
        assert_eq!(ChangeKind::Parameter.label(), "参数变化");
        assert_eq!(
            ChangeKind::Initial.label(),
            "初始通知（非变动）",
            "文案里要写明'非变动'，否则看日志的人会以为真出事了"
        );
        assert_eq!(ChangeKind::Unknown(1).label(), "未知类型");

        let all = [
            ChangeKind::Parameter,
            ChangeKind::Add,
            ChangeKind::Delete,
            ChangeKind::Initial,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in all {
            assert!(seen.insert(k.label()), "文案重复：{}", k.label());
        }
    }
}
