//! 拓扑指纹（对应 design-spec.md §20.4 拓扑指纹防伪）。
//!
//! ```text
//! Fingerprint = SHA256( Σ (NET_LUID + MAC + SSID/Profile + Gateway_IP) )
//! ```
//!
//! 语义：仅当"当前指纹 == 上次用户确认过的信任指纹"时编排器才自动放行；
//! 任何断开 / 新插网口 / 换 Wi-Fi 都会改变参与集合，从而判定为**拓扑漂移**并重新锁定。
//!
//! 实现要点：
//! - 只有 `OperStatus::Up` 的接口参与计算（§20.4 "对所有 Up 状态网卡"）；
//! - 按 LUID 排序后累加，保证不同枚举顺序下结果稳定（可重复、可落盘比对）；
//! - 各分量之间用分隔符拼接，避免 "A+B" 与 "AB" 这类拼串碰撞。

use sha2::{Digest, Sha256};

use crate::model::InterfaceInfo;

const FINGERPRINT_VERSION: u8 = 1;

/// 计算当前拓扑指纹，返回十六进制（小写）SHA-256 字符串。
pub fn compute_fingerprint(interfaces: &[InterfaceInfo]) -> String {
    let mut hasher = Sha256::new();

    // 版本字节保留给未来扩展（新增分量时递增，避免旧指纹误判为漂移）
    hasher.update([FINGERPRINT_VERSION]);

    let mut up: Vec<&InterfaceInfo> = interfaces.iter().filter(|i| i.is_up()).collect();
    up.sort_by_key(|i| i.luid);

    for iface in up {
        hasher.update(iface.luid.to_be_bytes());
        hasher.update(b"|");

        match &iface.mac {
            Some(mac) => hasher.update(mac.0),
            None => hasher.update(b"-"),
        }
        hasher.update(b"|");

        match &iface.ssid {
            Some(ssid) => hasher.update(ssid.as_bytes()),
            None => hasher.update(b"-"),
        }
        hasher.update(b"|");
    }

    hex(&hasher.finalize())
}

/// 字节数组转小写十六进制字符串。
pub fn hex(bytes: &[u8]) -> String {
    const TBL: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(TBL[(b >> 4) as usize] as char);
        s.push(TBL[(b & 0x0f) as usize] as char);
    }
    s
}
