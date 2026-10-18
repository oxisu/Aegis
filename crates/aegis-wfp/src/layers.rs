//! WFP 层标识与动作的可读化（纯逻辑，不调用任何 Win32 API）。
//!
//! # 为什么单独抽出来
//! 枚举出来的过滤器只有一串 GUID，直接打给人看等于没有信息。
//! 但把 GUID 翻译成名字这件事**不需要任何权限**，可以脱离 Windows
//! 权限环境完整单测——所以放进独立模块而不是混在枚举代码里。
//!
//! # 只登记 Aegis 真正关心的层
//! WFP 有一百多层，全登记既没必要也维护不动。这里只放与"出站拦截"
//! 相关的几个：出站连接授权、出站传输、入站传输、入站连接授权。
//! 其余层原样回退成 GUID 字符串，宁可显示得朴素，也不要显示错。

use windows::core::GUID;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

/// 已知层的可读名。
const KNOWN: &[(GUID, &str, &str)] = &[
    (
        wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        "ALE_AUTH_CONNECT_V4",
        "出站连接授权（IPv4）：Aegis 阻断策略的主战场",
    ),
    (
        wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        "ALE_AUTH_CONNECT_V6",
        "出站连接授权（IPv6）",
    ),
    (
        wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        "ALE_AUTH_RECV_ACCEPT_V4",
        "入站连接授权（IPv4）",
    ),
    (
        wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        "OUTBOUND_TRANSPORT_V4",
        "出站传输层（IPv4）：包离开网卡前的最后一道",
    ),
    (
        wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        "OUTBOUND_TRANSPORT_V6",
        "出站传输层（IPv6）",
    ),
    (
        wfp::FWPM_LAYER_INBOUND_TRANSPORT_V4,
        "INBOUND_TRANSPORT_V4",
        "入站传输层（IPv4）",
    ),
    (
        wfp::FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        "ALE_FLOW_ESTABLISHED_V4",
        "连接建立完成：适合做审计而非阻断",
    ),
];

/// 把层 GUID 翻译成可读名；未知层回退为 GUID 字符串。
pub fn layer_name(key: &GUID) -> String {
    KNOWN
        .iter()
        .find(|(g, _, _)| g == key)
        .map(|(_, n, _)| (*n).to_string())
        .unwrap_or_else(|| format!("{{{key:?}}}"))
}

/// 该层是否为 Aegis 关注的层。
pub fn is_known(key: &GUID) -> bool {
    KNOWN.iter().any(|(g, _, _)| g == key)
}

/// 已知层的用途说明；未知层返回 `None`。
pub fn layer_purpose(key: &GUID) -> Option<&'static str> {
    KNOWN.iter().find(|(g, _, _)| g == key).map(|(_, _, p)| *p)
}

/// Aegis 关注的全部层（用于"按层分组"与自检）。
pub fn watched_layers() -> impl Iterator<Item = (GUID, &'static str)> {
    KNOWN.iter().map(|(g, n, _)| (*g, *n))
}

/// 动作类型的可读名。
pub fn action_name(t: wfp::FWP_ACTION_TYPE) -> &'static str {
    match t {
        wfp::FWP_ACTION_BLOCK => "阻断",
        wfp::FWP_ACTION_PERMIT => "放行",
        wfp::FWP_ACTION_CALLOUT_TERMINATING => "终结型 Callout",
        wfp::FWP_ACTION_CALLOUT_INSPECTION => "检查型 Callout",
        wfp::FWP_ACTION_CALLOUT_UNKNOWN => "未知 Callout",
        _ => "其他",
    }
}

/// 该动作是否会终止数据包（阻断或终结型 Callout）。
pub fn action_is_terminal(t: wfp::FWP_ACTION_TYPE) -> bool {
    matches!(
        t,
        wfp::FWP_ACTION_BLOCK | wfp::FWP_ACTION_CALLOUT_TERMINATING
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_layers_have_readable_names() {
        assert_eq!(
            layer_name(&wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4),
            "ALE_AUTH_CONNECT_V4"
        );
        assert_eq!(
            layer_name(&wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V4),
            "OUTBOUND_TRANSPORT_V4"
        );
        assert!(is_known(&wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6));
    }

    /// 未知层必须回退成 GUID 而不是报错或返回空串——
    /// 宁可显示得朴素，也不要显示错。
    #[test]
    fn unknown_layer_falls_back_to_guid() {
        let g = GUID::zeroed();
        assert!(!is_known(&g));
        let s = layer_name(&g);
        assert!(!s.is_empty(), "未知层也要有可读输出：{s}");
        assert!(s.starts_with('{'), "{s}");
        assert_eq!(layer_purpose(&g), None);
    }

    #[test]
    fn watched_layers_covers_outbound_paths() {
        let names: Vec<_> = watched_layers().map(|(_, n)| n).collect();
        assert!(names.contains(&"ALE_AUTH_CONNECT_V4"));
        assert!(names.contains(&"ALE_AUTH_CONNECT_V6"));
        assert!(names.contains(&"OUTBOUND_TRANSPORT_V4"));
        assert!(names.contains(&"OUTBOUND_TRANSPORT_V6"));
    }

    /// 已知层必须都有用途说明——之前只测了"未知层返回 None"，
    /// 于是"恒返回 None"这个变异活了下来（变异测试实锤）。
    #[test]
    fn known_layers_all_have_a_purpose() {
        for (g, n) in watched_layers() {
            let p = layer_purpose(&g);
            assert!(p.is_some(), "{n} 缺用途说明");
            assert!(!p.unwrap().is_empty(), "{n} 用途说明为空");
        }
    }

    #[test]
    fn layer_purpose_of_a_known_layer_describes_it() {
        let p = layer_purpose(&wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4).unwrap();
        assert!(p.contains("出站"), "{p}");
        assert_eq!(layer_purpose(&GUID::zeroed()), None);
    }

    #[test]
    fn action_names_cover_every_callout_type() {
        assert_eq!(
            action_name(wfp::FWP_ACTION_CALLOUT_INSPECTION),
            "检查型 Callout"
        );
        assert_eq!(action_name(wfp::FWP_ACTION_CALLOUT_UNKNOWN), "未知 Callout");
    }

    #[test]
    fn action_names_are_chinese_and_stable() {
        assert_eq!(action_name(wfp::FWP_ACTION_BLOCK), "阻断");
        assert_eq!(action_name(wfp::FWP_ACTION_PERMIT), "放行");
        assert_eq!(
            action_name(wfp::FWP_ACTION_CALLOUT_TERMINATING),
            "终结型 Callout"
        );
        assert_eq!(action_name(wfp::FWP_ACTION_TYPE(0xDEAD)), "其他");
    }

    /// "会不会终止数据包"是判断一条过滤器是否构成阻断的关键，
    /// 不能只看"是不是 BLOCK"——终结型 Callout 一样能拦。
    #[test]
    fn terminal_actions_include_terminating_callouts() {
        assert!(action_is_terminal(wfp::FWP_ACTION_BLOCK));
        assert!(action_is_terminal(wfp::FWP_ACTION_CALLOUT_TERMINATING));
        assert!(!action_is_terminal(wfp::FWP_ACTION_PERMIT));
        assert!(!action_is_terminal(wfp::FWP_ACTION_CALLOUT_INSPECTION));
    }
}
