//! 证据链：把审计事件串成一条**改动即可被发现**的哈希链（§F3「防篡改」）。
//!
//! # 它到底证明了什么、证明不了什么
//！
//! 每条记录的哈希 = `SHA-256(前一条哈希 ‖ 本条规范化字节)`。于是：
//!
//! - ✅ **能**证明"中间某条被改过"：改一条，它后面所有哈希全断。
//! - ❌ **不能**证明"尾部没被删"：把最后 100 条连着删掉，剩下的部分
//!   仍然是**自洽**的一条链——链头就变成了剩下那部分的最后一条。
//!   这是哈希链的固有性质，不是实现缺陷。
//!
//! 尾部截断的唯一缓解是把**链头定期外置**（打印、写只读归档、上报）。
//! 删了尾部，链头就对不上外置的那份。这一点必须在文档里说清楚，
//! 否则"我们上了防篡改"会变成虚假的安全感 —— 而虚假安全感比没有更危险。
//!
//! 同理，它也不防"持有密钥者整链重算"。防篡改 ≠ 防伪造；要防伪造得上签名，
//! 那是后话，先把"改动可检测"做实。

use sha2::{Digest, Sha256};

use crate::encode::canonical_bytes;
use crate::event::AuditEvent;

/// 哈希长度（SHA-256）。
pub const HASH_LEN: usize = 32;

/// 链哈希。
pub type Hash = [u8; HASH_LEN];

/// 创世哈希：全零。刻意不是某个随机盐——链必须能被独立重算校验，
/// 而随机盐得跟着存，存的地方又成了新的信任根。
pub const GENESIS: Hash = [0u8; HASH_LEN];

/// 链上的一节。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// 序号，从 1 开始（"第 N 条记录"是给人看的编号）
    pub seq: u64,
    pub ts_ms: u64,
    /// 前一条的哈希；第一条是 [`GENESIS`]
    pub prev: Hash,
    /// `SHA-256(prev ‖ canonical_bytes(event))`
    pub hash: Hash,
}

/// 一条追加式证据链。**只保存链头**，不保存全部事件——
/// 事件本体由落盘层负责，链只负责把它们的顺序钉死。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceChain {
    head: Hash,
    len: u64,
}

impl EvidenceChain {
    pub fn new() -> Self {
        Self {
            head: GENESIS,
            len: 0,
        }
    }

    /// 当前链头。定期把它外置（打印 / 只读归档）是防尾部截断**唯一**的缓解手段。
    pub fn head(&self) -> Hash {
        self.head
    }

    /// 已追加的条数。
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 算出下一条链节（**不改状态**）。
    ///
    /// 与 [`Self::commit`] 分开，是为了支持"先落盘、再进链"：调用方可以先把
    /// 链节写出去，确认写成功了再 `commit`。反过来（先进链再写盘）会在写盘
    /// 失败时留下"链上有、盘上没有"的空洞，而空洞在校验时表现为断链，
    /// 看起来像是有人删了记录。
    pub fn next(&self, event: &AuditEvent) -> Link {
        let prev = self.head;
        Link {
            seq: self.len + 1,
            ts_ms: event.ts_ms,
            prev,
            hash: link_hash(prev, event),
        }
    }

    /// 提交一条**已经落盘**的链节。
    ///
    /// 校验前驱与序号，对不上就拒绝——这能挡住"把两天的日志拼在一起"这类
    /// 拼装错误，而不是让链悄悄接上一个不相干的头。
    pub fn commit(&mut self, link: Link) -> Result<(), ChainError> {
        if link.seq != self.len + 1 {
            return Err(ChainError::SeqMismatch { seq: link.seq });
        }
        if link.prev != self.head {
            return Err(ChainError::PrevMismatch { seq: link.seq });
        }
        self.head = link.hash;
        self.len += 1;
        Ok(())
    }

    /// 把链**强行推进到**某个状态：已有 `len` 条、链头是 `head`。
    ///
    /// 用于续接分片：前一个分片读到第 N 条、链头是 H，那么本分片的链必须
    /// 从这个状态起步，否则每条都会被"前驱对不上"拒掉。
    /// 调用方负责保证这个状态确实来自同一条链。
    pub fn advance_to(&mut self, len: u64, head: Hash) {
        self.head = head;
        self.len = len;
    }

    /// 追加一条事件，返回链节（内存用法：算与提交一起做）。
    pub fn append(&mut self, event: &AuditEvent) -> Link {
        let link = self.next(event);
        // next 出来的链节必然与当前状态吻合，不可能失败
        let _ = self.commit(link);
        link
    }
}

impl Default for EvidenceChain {
    fn default() -> Self {
        Self::new()
    }
}

/// 计算一条链节的哈希。纯函数，可脱离任何状态验证。
pub fn link_hash(prev: Hash, event: &AuditEvent) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(canonical_bytes(event));
    hasher.finalize().into()
}

/// 校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("事件 {events} 条与链节 {links} 条数量不符")]
    LengthMismatch { events: usize, links: usize },
    #[error("第 {seq} 条：序号与位置不符（链被重排过）")]
    SeqMismatch { seq: u64 },
    #[error("第 {seq} 条：前驱哈希对不上（前面被插入或删除过）")]
    PrevMismatch { seq: u64 },
    #[error("第 {seq} 条：内容哈希对不上（这条记录被改过）")]
    HashMismatch { seq: u64 },
}

/// 从创世哈希重放校验。
///
/// `events` 与 `links` **一一对应**（第 i 条事件 ↔ 第 i 个链节）。
/// 空输入视为合法——没有记录就没有可篡改的东西。
pub fn verify(events: &[AuditEvent], links: &[Link]) -> Result<(), ChainError> {
    if events.len() != links.len() {
        return Err(ChainError::LengthMismatch {
            events: events.len(),
            links: links.len(),
        });
    }
    let mut prev = GENESIS;
    for (i, (event, link)) in events.iter().zip(links.iter()).enumerate() {
        let expected_seq = i as u64 + 1;
        if link.seq != expected_seq {
            return Err(ChainError::SeqMismatch { seq: link.seq });
        }
        if link.prev != prev {
            return Err(ChainError::PrevMismatch { seq: link.seq });
        }
        let recomputed = link_hash(prev, event);
        if recomputed != link.hash {
            return Err(ChainError::HashMismatch { seq: link.seq });
        }
        prev = link.hash;
    }
    Ok(())
}

/// 哈希的十六进制表示（证据导出 / 日志比对用）。
pub fn hex(hash: &Hash) -> String {
    let mut s = String::with_capacity(HASH_LEN * 2);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Protocol};
    use aegis_core::InterfaceRole;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event(n: u8) -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000 + u64::from(n),
            pid: 1000 + u32::from(n),
            process_path: format!(r"C:\App\app{n}.exe"),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)), 5000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: None,
            rule: None,
            luid: 42,
            role: InterfaceRole::CampusStrict,
            action: Action::Reject,
        }
    }

    fn build(n: u8) -> (Vec<AuditEvent>, Vec<Link>) {
        let mut chain = EvidenceChain::new();
        let mut events = Vec::new();
        let mut links = Vec::new();
        for i in 0..n {
            let e = event(i);
            links.push(chain.append(&e));
            events.push(e);
        }
        (events, links)
    }

    #[test]
    fn empty_chain_starts_at_genesis() {
        let c = EvidenceChain::new();
        assert_eq!(c.head(), GENESIS);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
    }

    /// `is_empty` 只测"空的时候为真"是不够的——一个恒返回 `true` 的实现
    /// 照样通过。而它的用途恰恰是"有记录时不能说自己是空的"：
    /// 校验前的快速判空一旦恒真，空证据包会被当成"校验通过"。
    #[test]
    fn a_chain_that_has_records_is_not_empty() {
        let mut c = EvidenceChain::new();
        assert!(c.is_empty());

        c.append(&event(1));
        assert!(!c.is_empty(), "追加过记录就不能再说自己是空的");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn empty_input_verifies() {
        assert_eq!(verify(&[], &[]), Ok(()));
    }

    #[test]
    fn seq_starts_at_one_and_matches_len() {
        let (_, links) = build(3);
        assert_eq!(links[0].seq, 1);
        assert_eq!(links[2].seq, 3);
        assert_eq!(links[0].prev, GENESIS, "第一条的前驱是创世哈希");
    }

    #[test]
    fn a_fresh_chain_verifies() {
        let (events, links) = build(8);
        assert_eq!(verify(&events, &links), Ok(()));
    }

    /// 核心保证：改一条记录的**任一字段**，校验必须失败。
    #[test]
    fn tampering_with_any_record_is_detected() {
        for slot in 0..5u8 {
            let (mut events, links) = build(5);
            events[slot as usize].process_path.push('X');
            assert_eq!(
                verify(&events, &links),
                Err(ChainError::HashMismatch {
                    seq: u64::from(slot) + 1
                }),
                "改第 {} 条必须被抓",
                slot + 1
            );
        }
    }

    /// 改动作也要被抓：把"放行"改成"阻断"是攻击者最想做的事
    /// （反过来改则能让违规连接看起来从未发生）。
    #[test]
    fn flipping_a_blocked_action_to_allow_is_detected() {
        let (mut events, links) = build(3);
        events[1].action = Action::Allow;
        assert_eq!(verify(&events, &links), Err(ChainError::HashMismatch { seq: 2 }));
    }

    /// 头部删一条：序号先露出马脚（剩下的第一条序号是 2，位置却是 1）。
    #[test]
    fn removing_a_leading_record_is_detected_by_seq() {
        let (events, links) = build(4);
        assert_eq!(
            verify(&events[1..], &links[1..]),
            Err(ChainError::SeqMismatch { seq: 2 })
        );
    }

    /// 更狡猾的一种：删掉头部**并且**把序号重新编过，让序号看起来连续。
    /// 这时序号骗不过去，但前驱哈希骗不过——剩下那部分的第一条，
    /// 前驱不再是创世哈希。
    #[test]
    fn removing_a_leading_record_and_renumbering_is_still_detected() {
        let (events, links) = build(4);
        let mut forged = links[1..].to_vec();
        for (i, link) in forged.iter_mut().enumerate() {
            link.seq = i as u64 + 1;
        }
        assert_eq!(
            verify(&events[1..], &forged),
            Err(ChainError::PrevMismatch { seq: 1 })
        );
    }

    /// 尾部截断**抓不住**——这是哈希链的固有性质，用测试把它钉成文档。
    /// 谁要是以为"上了链就防删"，这条会提醒他。
    #[test]
    fn trailing_truncation_is_inherently_undetectable() {
        let (events, links) = build(4);
        assert_eq!(
            verify(&events[..2], &links[..2]),
            Ok(()),
            "尾部截断后剩下的部分仍是自洽的链 —— 所以链头必须定期外置"
        );
    }

    #[test]
    fn reordering_is_detected() {
        let (events, links) = build(3);
        let swapped = vec![events[1].clone(), events[0].clone(), events[2].clone()];
        assert!(matches!(
            verify(&swapped, &links),
            Err(ChainError::HashMismatch { seq: 1 })
        ));
    }

    #[test]
    fn length_mismatch_is_reported_before_anything_else() {
        let (events, links) = build(3);
        assert_eq!(
            verify(&events[..2], &links),
            Err(ChainError::LengthMismatch {
                events: 2,
                links: 3
            })
        );
    }

    /// 链头推进：追加会改变链头，这正是"链头外置"能抓截断的原因。
    #[test]
    fn head_advances_with_every_append() {
        let mut c = EvidenceChain::new();
        let mut heads = vec![c.head()];
        for i in 0..4u8 {
            c.append(&event(i));
            heads.push(c.head());
        }
        assert_eq!(c.len(), 4);
        for w in heads.windows(2) {
            assert_ne!(w[0], w[1]);
        }
    }

    /// 先算后提交：算的时候链**不动**，这样写盘失败就能什么都不做。
    #[test]
    fn next_does_not_advance_the_chain_but_commit_does() {
        let mut c = EvidenceChain::new();
        let link = c.next(&event(0));
        assert_eq!(c.len(), 0, "next 不该改状态");
        assert_eq!(c.head(), GENESIS);
        assert_eq!(link.seq, 1);
        assert_eq!(link.prev, GENESIS);

        c.commit(link).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c.head(), link.hash);
    }

    #[test]
    fn commit_rejects_a_link_that_does_not_follow_the_head() {
        let mut c = EvidenceChain::new();
        c.append(&event(0));
        let second = c.next(&event(1));

        // 跳号
        let mut skipped = second;
        skipped.seq = 99;
        assert_eq!(c.commit(skipped), Err(ChainError::SeqMismatch { seq: 99 }));

        // 前驱对不上：接在一个不相干的头上（例如把另一段日志的链拼过来）
        let mut wrong_prev = second;
        wrong_prev.prev = link_hash(GENESIS, &event(9));
        assert_ne!(wrong_prev.prev, c.head());
        assert_eq!(c.commit(wrong_prev), Err(ChainError::PrevMismatch { seq: 2 }));

        assert_eq!(c.len(), 1, "被拒的提交不该改变链");
    }

    #[test]
    fn hex_is_64_lowercase_chars() {
        let (_, links) = build(1);
        let s = hex(&links[0].hash);
        assert_eq!(s.len(), HASH_LEN * 2);
        assert!(s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
