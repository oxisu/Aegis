//! [`crate::encode::canonical_bytes`] 的**解码器**。
//!
//! # 为什么有了编码器还要手写解码器
//!
//! 规范化编码最初只用于算哈希——那时不需要解码，哈希是单向的。一旦要落盘，
//! 就得能把字节读回来：不然审计日志是一串谁也读不了的 blob，
//! 而"读不了"的日志等于没有日志。
//!
//! 这里刻意**不**引入 serde：既然编码是我们自己定的、且带版本号，
//! 解码也必须是同一套约定的镜像，任何第三方库都只会多一处对不齐的地方。
//!
//! # 严格性
//!
//! 解码一律**严格**：长度不足、magic 不对、版本不认识、尾随多余字节、
//! 字段非法值——全部报错，绝不"尽力解析"。
//!
//! 审计场景下，宽容的代价是把一条损坏的记录渲染成**看起来正常**的记录。
//! 用户会据此判断"当时没有违规连接"，而真相是"这段数据我们读不出来"。
//! 宁可报"这里有 3 条读不出来"，也不能给一个假的完整清单。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::encode::{action_from_tag, role_from_tag, CANONICAL_VERSION};
use crate::event::{AuditEvent, Protocol};

// MAGIC 目前是 encode 模块私有的；解码器必须核对同一个字节串，
// 所以在这里重新声明一份并由测试钉住两者相等。
const DECODE_MAGIC: &[u8] = b"AEGIS-AUDIT-CANON";

/// 解码失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("数据不足：需要 {need} 字节，只剩 {have} 字节")]
    Truncated { need: usize, have: usize },
    #[error("流头不是审计事件的规范化编码")]
    BadMagic,
    #[error("不支持的规范化编码版本 {0}（本实现只认 v{CANONICAL_VERSION}）")]
    UnsupportedVersion(u32),
    #[error("地址族非法：{0}（只认 4 与 6）")]
    BadAddressFamily(u8),
    #[error("存在位非法：{0}（只认 0 与 1）")]
    BadPresenceByte(u8),
    #[error("网卡角色编号非法：{0}")]
    BadRoleTag(u8),
    #[error("动作编号非法：{0}")]
    BadActionTag(u8),
    #[error("文本字段不是合法 UTF-8")]
    BadUtf8,
    #[error("解码后还剩 {0} 字节（字节流被追加过）")]
    TrailingBytes(usize),
}

/// 把规范化字节解回一条审计事件。
pub fn decode(bytes: &[u8]) -> Result<AuditEvent, DecodeError> {
    let mut c = Cursor { buf: bytes, pos: 0 };

    let magic = c.take(DECODE_MAGIC.len())?;
    if magic != DECODE_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = c.u32()?;
    if version != CANONICAL_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let ts_ms = c.u64()?;
    let pid = c.u32()?;
    let process_path = c.str()?;
    let src = c.addr()?;
    let dst = c.addr()?;
    let protocol = Protocol::from_number(c.u8()?);
    let host = c.opt_str()?;
    let rule = c.opt_str()?;
    let luid = c.u64()?;
    let role = role_from_tag(c.u8()?).ok_or(DecodeError::BadRoleTag(c.peek_last()))?;
    let action = action_from_tag(c.u8()?).ok_or(DecodeError::BadActionTag(c.peek_last()))?;

    if c.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes(bytes.len() - c.pos));
    }

    Ok(AuditEvent {
        ts_ms,
        pid,
        process_path,
        src,
        dst,
        protocol,
        host,
        rule,
        luid,
        role,
        action,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DecodeError> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len());
        match end {
            Some(e) => {
                let out = &self.buf[self.pos..e];
                self.pos = e;
                Ok(out)
            },
            None => Err(DecodeError::Truncated {
                need: n,
                have: self.buf.len() - self.pos,
            }),
        }
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("长度已检查"),
        ))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("长度已检查"),
        ))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("长度已检查"),
        ))
    }

    /// 长度前缀文本。长度本身也做了上界检查，防止一个恶意的巨大长度
    /// 触发巨量分配（`take` 会在剩余不足时报错，这里再挡一道更明确）。
    fn str(&mut self) -> Result<String, DecodeError> {
        let len = self.u32()? as usize;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(ToOwned::to_owned)
            .map_err(|_| DecodeError::BadUtf8)
    }

    fn opt_str(&mut self) -> Result<Option<String>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.str()?)),
            other => Err(DecodeError::BadPresenceByte(other)),
        }
    }

    fn addr(&mut self) -> Result<SocketAddr, DecodeError> {
        let family = self.u8()?;
        let ip = match family {
            4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(self.take(4)?).expect("长度已检查"),
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(self.take(16)?).expect("长度已检查"),
            )),
            other => return Err(DecodeError::BadAddressFamily(other)),
        };
        let port = self.u16()?;
        Ok(SocketAddr::new(ip, port))
    }

    /// 取刚才读走的那一个字节。只用于报错时把非法值带出去。
    fn peek_last(&self) -> u8 {
        self.buf[self.pos.saturating_sub(1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{canonical_bytes, MAGIC};
    use crate::event::Action;
    use aegis_core::InterfaceRole;

    fn event() -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000,
            pid: 4242,
            process_path: r"C:\App\app.exe".to_string(),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 51234),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: None,
            luid: 1689395631011611136,
            role: InterfaceRole::CampusStrict,
            action: Action::Reject,
        }
    }

    /// 解码器与编码器核对的是同一个字节串。
    #[test]
    fn decoder_magic_matches_the_encoder() {
        assert_eq!(DECODE_MAGIC, MAGIC);
    }

    #[test]
    fn roundtrip_recovers_the_event_exactly() {
        let e = event();
        assert_eq!(decode(&canonical_bytes(&e)), Ok(e));
    }

    /// 各种边界组合都要能对回来：v6、可空字段两种取值、未知协议、全部角色与动作。
    #[test]
    fn roundtrip_holds_for_every_field_combination() {
        let mut base = event();
        for host in [None, Some(String::new()), Some("例え.com".to_string())] {
            for rule in [None, Some("FINAL,REJECT".to_string())] {
                for role in [
                    InterfaceRole::CampusStrict,
                    InterfaceRole::FreeOutbound,
                    InterfaceRole::Aggregated,
                    InterfaceRole::Isolated,
                    InterfaceRole::Unknown,
                ] {
                    for action in [
                        Action::Allow,
                        Action::Reject,
                        Action::FirewallBlock,
                        Action::PlaintextBlock,
                        Action::Observed,
                    ] {
                        base.host = host.clone();
                        base.rule = rule.clone();
                        base.role = role;
                        base.action = action;
                        let bytes = canonical_bytes(&base);
                        assert_eq!(decode(&bytes), Ok(base.clone()), "{role} / {action}");

                        // v6 与未知协议也一起验
                        let mut v6 = base.clone();
                        v6.dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443);
                        v6.protocol = Protocol::Other(47);
                        assert_eq!(decode(&canonical_bytes(&v6)), Ok(v6));
                    }
                }
            }
        }
    }

    #[test]
    fn empty_input_is_truncated_not_ok() {
        assert_eq!(
            decode(&[]),
            Err(DecodeError::Truncated { need: 17, have: 0 })
        );
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut b = canonical_bytes(&event()).to_vec();
        b[0] ^= 0xFF;
        assert_eq!(decode(&b), Err(DecodeError::BadMagic));
    }

    #[test]
    fn future_version_is_rejected_loudly() {
        let mut b = canonical_bytes(&event()).to_vec();
        let at = DECODE_MAGIC.len();
        b[at..at + 4].copy_from_slice(&(CANONICAL_VERSION + 1).to_le_bytes());
        assert_eq!(
            decode(&b),
            Err(DecodeError::UnsupportedVersion(CANONICAL_VERSION + 1))
        );
    }

    /// 截断必须报错，而不是"尽力解析"出一条看起来正常的记录。
    #[test]
    fn cut_off_tail_is_an_error_not_a_partial_record() {
        let b = canonical_bytes(&event());
        for cut in 1..b.len() {
            assert!(
                matches!(decode(&b[..cut]), Err(DecodeError::Truncated { .. })),
                "截断到 {cut} 字节竟被接受"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut b = canonical_bytes(&event()).to_vec();
        b.push(0x00);
        assert_eq!(decode(&b), Err(DecodeError::TrailingBytes(1)));
    }

    /// 尾随字节的**个数**必须报准。
    ///
    /// 只追加 1 个字节时，"剩余 = 总长 - 位置"和"剩余 = 总长 / 位置"
    /// 恰好都等于 1，一个把减法写成除法的实现能蒙混过关。多加几个字节，
    /// 两种算法立刻分开。这类"只在某个取值上等价"的算术错误，
    /// 只有把确切值钉住才抓得到。
    #[test]
    fn the_number_of_trailing_bytes_is_reported_exactly() {
        let mut b = canonical_bytes(&event()).to_vec();
        b.extend_from_slice(&[0x00, 0x01, 0x02]);
        assert_eq!(decode(&b), Err(DecodeError::TrailingBytes(3)));

        let mut b = canonical_bytes(&event()).to_vec();
        b.extend_from_slice(&[0x00; 9]);
        assert_eq!(decode(&b), Err(DecodeError::TrailingBytes(9)));
    }

    /// `have` 是"还剩几个字节"，不是"缓冲区总长"。
    ///
    /// 只验 `matches!(.., Truncated { .. })` 抓不到把它算错的实现，
    /// 而报错里那个数是排查"这段日志为什么读不出来"的唯一线索——
    /// 报成几百（总长）会直接把人引到错的偏移量上。
    #[test]
    fn a_truncation_reports_how_many_bytes_are_actually_left() {
        let b = canonical_bytes(&event()).to_vec();
        // MAGIC 17 字节之后紧跟一个 u32：切到 20 字节时还差 1 字节
        assert_eq!(
            decode(&b[..20]),
            Err(DecodeError::Truncated { need: 4, have: 3 })
        );
        assert_eq!(
            decode(&b[..17]),
            Err(DecodeError::Truncated { need: 4, have: 0 })
        );
    }

    #[test]
    fn illegal_field_values_are_rejected() {
        let mut b = canonical_bytes(&event()).to_vec();
        // 角色编号是本编码最后一个字节
        let role_at = b.len() - 2;
        b[role_at] = 99;
        assert_eq!(decode(&b), Err(DecodeError::BadRoleTag(99)));

        let mut b = canonical_bytes(&event()).to_vec();
        let action_at = b.len() - 1;
        b[action_at] = 99;
        assert_eq!(decode(&b), Err(DecodeError::BadActionTag(99)));
    }
}
