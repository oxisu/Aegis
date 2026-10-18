//! 审计日志落盘：**只追加**的二进制文件 + 跨分片连续的证据链（§15）。
//!
//! # 为什么不是 SQLite
//!
//! 设计文档 §15 写的是 SQLite。这里先不上，理由是**构建成本**：
//! `rusqlite` 走 bundled 就要编译一份 C 的 SQLite，而这正是我们刚在
//! `aegis-model` 那次重构里费力清掉的东西（策略层构建从 22s 降回 3.9s）。
//! 检索与索引可以后补；先把"证据落得下来、重开接得上"做实。
//!
//! # 三条硬约束
//!
//! 1. **只追加，绝不改写**。改写已写出的记录意味着"证据可被事后修订"，
//!    那整个证据链就没有意义了。
//! 2. **重开必须接着走**（[`AuditLog::open`]）。重放已有记录把链头恢复出来，
//!    绝不能从 [`GENESIS`] 重新开始——服务每重启一次，
//!    历史记录与链就断一次，而断链看起来正像是"有人删了记录"。
//! 3. **分片边界不能断链**（[`AuditLog::rotate`]）。新分片的第一条，
//!    前驱仍是上一个分片的链头。分片只是文件边界，不是证据边界。
//!
//! # 崩溃语义
//!
//! [`AuditLog::append`] 之后调用 [`AuditLog::flush`] 只保证数据进了 OS，
//! 不保证落盘。要保证落盘得调用 [`AuditLog::sync`]。默认策略是
//! **定期 sync 而不是每条 sync**：每条都 sync 会把 WFP 事件速率直接压到
//! 磁盘速率上。代价是掉电可能丢最后几条——这必须说清楚，
//! 不能让"我们已经落盘了"变成一个未经说明的假设。

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::chain::{link_hash, EvidenceChain, Hash, Link, HASH_LEN, GENESIS};
use crate::decode::{decode, DecodeError};
use crate::encode::canonical_bytes;
use crate::event::AuditEvent;

/// 日志文件头。
pub const LOG_MAGIC: &[u8] = b"AEGIS-AUDIT-LOG";
/// 日志文件格式版本。
pub const LOG_VERSION: u32 = 1;

/// 文件头长度：magic + 版本号。
const HEADER_LEN: usize = LOG_MAGIC.len() + 4;
/// 一条记录里链节占的字节：seq(u64) + prev(32) + hash(32)。
const LINK_LEN: usize = 8 + HASH_LEN + HASH_LEN;

/// 读日志失败。
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("IO 失败：{0}")]
    Io(#[from] io::Error),
    #[error("不是 Aegis 审计日志（流头不对）")]
    BadMagic,
    #[error("不支持的日志格式版本 {0}（本实现只认 v{LOG_VERSION}）")]
    UnsupportedVersion(u32),
    #[error("第 {index} 条记录在偏移 {offset} 处损坏：{reason}")]
    Corrupt {
        index: u64,
        offset: u64,
        reason: String,
    },
}

/// 日志里的一条记录：事件本体 + 它的链节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub event: AuditEvent,
    pub link: Link,
}

/// 读一个分片时的**起始上下文**：这条链接下来该是第几号、前驱哈希是什么。
///
/// 分片里的序号是**全局连续**的（见 [`AuditLog::rotate`]），所以单独打开
/// 第二个分片时不能假设它从 1 号、从 [`GENESIS`] 开始——那样每个分片都会
/// 报"序号是 N，应为 1"。上下文必须从钱一个分片的末尾传过来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCtx {
    /// 期望的第一条序号
    pub next_seq: u64,
    /// 期望的第一条的前驱哈希
    pub prev: Hash,
}

impl ReadCtx {
    /// 从一条完整日志的开头读起。
    pub fn genesis() -> Self {
        Self {
            next_seq: 1,
            prev: GENESIS,
        }
    }

    /// 接着某个分片读完的地方继续。
    pub fn after(records: &[Record]) -> Self {
        match records.last() {
            Some(last) => Self {
                next_seq: last.link.seq + 1,
                prev: last.link.hash,
            },
            None => Self::genesis(),
        }
    }
}

/// 只追加的审计日志。
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    chain: EvidenceChain,
    bytes: u64,
}

impl AuditLog {
    /// 新建一个日志。**文件已存在则失败**——覆盖已有日志等于销毁证据，
    /// 这种事不能静默发生。
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .read(true)
            .open(&path)?;
        file.write_all(LOG_MAGIC)?;
        file.write_all(&LOG_VERSION.to_le_bytes())?;
        file.flush()?;
        Ok(Self {
            path,
            file,
            chain: EvidenceChain::new(),
            bytes: HEADER_LEN as u64,
        })
    }

    /// 打开已有日志续写。**重放已有记录**把链头与计数恢复出来。
    ///
    /// 这一步是必需的：不重放就只能从 [`GENESIS`] 重新开始，于是服务每次
    /// 重启都会让历史记录与新链脱节——而脱节的表现正是"有人删了记录"。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReadError> {
        Self::open_with(path, ReadCtx::genesis())
    }

    /// 打开一个**续接**的分片（前一个分片之后）。链头与计数接着传进来的上下文走。
    pub fn open_with(path: impl AsRef<Path>, ctx: ReadCtx) -> Result<Self, ReadError> {
        let path = path.as_ref().to_path_buf();
        let records = read_records_with(&path, ctx)?;
        let mut chain = EvidenceChain::new();
        // 把起始上下文先灌进链：否则 commit 会以 GENESIS 为前驱而全部拒绝
        chain.advance_to(ctx.next_seq.saturating_sub(1), ctx.prev);
        for r in &records {
            chain.commit(r.link).map_err(|e| ReadError::Corrupt {
                index: r.link.seq,
                offset: 0,
                reason: e.to_string(),
            })?;
        }

        let mut file = OpenOptions::new().append(true).read(true).open(&path)?;
        let bytes = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            chain,
            bytes,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 当前链头。跨 [`Self::rotate`] 与 [`Self::open`] 都连续。
    pub fn head(&self) -> Hash {
        self.chain.head()
    }

    /// 已写出的记录条数。
    pub fn len(&self) -> u64 {
        self.chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// 当前分片已写字节数。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// 追加一条事件。顺序是**先算出链节 → 写盘 → 成功才进链**。
    ///
    /// 写盘失败时链不动，于是"链上有的"必然是"盘上有的"。
    pub fn append(&mut self, event: &AuditEvent) -> io::Result<Link> {
        let link = self.chain.next(event);
        let canonical = canonical_bytes(event);

        let payload_len = canonical.len() + LINK_LEN;
        let mut buf = Vec::with_capacity(4 + payload_len);
        buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
        buf.extend_from_slice(&canonical);
        buf.extend_from_slice(&link.seq.to_le_bytes());
        buf.extend_from_slice(&link.prev);
        buf.extend_from_slice(&link.hash);

        self.file.write_all(&buf)?;
        self.bytes += buf.len() as u64;

        // 只有写成功了才推进链
        self.chain
            .commit(link)
            .expect("由 next 产生的链节必然能提交");
        Ok(link)
    }

    /// 刷到 OS（不保证落盘）。
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// 真正落盘。开销大，按节奏调用，不要每条都调。
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// 切到新分片。**链头必须跟着带过去**。
    ///
    /// 分片只是文件边界，不是证据边界：新分片的第一条，前驱仍是上一个分片的
    /// 链头。若在新分片里重新从 [`GENESIS`] 开始，每个分片边界都会变成一个
    /// 断链点，而"分片处断链"看起来跟"有人删了整个分片"一模一样。
    pub fn rotate(&mut self, new_path: impl AsRef<Path>) -> io::Result<()> {
        let new_path = new_path.as_ref().to_path_buf();
        self.flush()?;

        let head_before = self.chain.head();
        let len_before = self.chain.len();

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .read(true)
            .open(&new_path)?;
        file.write_all(LOG_MAGIC)?;
        file.write_all(&LOG_VERSION.to_le_bytes())?;
        file.flush()?;

        self.file = file;
        self.path = new_path;
        self.bytes = HEADER_LEN as u64;
        // 链状态原样保留：这里刻意不动 chain
        assert_eq!(self.chain.head(), head_before);
        assert_eq!(self.chain.len(), len_before);
        Ok(())
    }
}

/// 读出日志里的全部记录，并顺带把链节校验一遍（只校验链节自身的连续性）。
///
/// 遇到损坏**停下并报错**，不跳过继续：跳过会让后面所有记录的前驱都对不上，
/// 而用户看到的是"链断了"，却不知道断是因为少读了几条。
pub fn read_records(path: &Path) -> Result<Vec<Record>, ReadError> {
    read_records_with(path, ReadCtx::genesis())
}

/// 按给定的起始上下文读一个分片。
pub fn read_records_with(path: &Path, ctx: ReadCtx) -> Result<Vec<Record>, ReadError> {
    let mut f = File::open(path)?;

    let mut header = [0u8; HEADER_LEN];
    let got = f.read(&mut header)?;
    if got < HEADER_LEN {
        return Err(ReadError::Corrupt {
            index: 0,
            offset: 0,
            reason: "文件头不完整".to_string(),
        });
    }
    if &header[..LOG_MAGIC.len()] != LOG_MAGIC {
        return Err(ReadError::BadMagic);
    }
    let version = u32::from_le_bytes(
        header[LOG_MAGIC.len()..]
            .try_into()
            .expect("长度已检查"),
    );
    if version != LOG_VERSION {
        return Err(ReadError::UnsupportedVersion(version));
    }

    let mut rest = Vec::new();
    f.read_to_end(&mut rest)?;

    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut expect_seq = ctx.next_seq;
    let mut prev = ctx.prev;

    while pos < rest.len() {
        let offset = (HEADER_LEN + pos) as u64;
        if rest.len() - pos < 4 {
            return Err(ReadError::Corrupt {
                index: expect_seq,
                offset,
                reason: "长度前缀不完整".to_string(),
            });
        }
        let payload_len =
            u32::from_le_bytes(rest[pos..pos + 4].try_into().expect("长度已检查")) as usize;
        pos += 4;
        if payload_len < LINK_LEN || rest.len() - pos < payload_len {
            return Err(ReadError::Corrupt {
                index: expect_seq,
                offset,
                reason: format!("声明 {payload_len} 字节，实际不足"),
            });
        }
        let payload = &rest[pos..pos + payload_len];
        pos += payload_len;

        let canonical = &payload[..payload.len() - LINK_LEN];
        let tail = &payload[payload.len() - LINK_LEN..];
        let seq = u64::from_le_bytes(tail[..8].try_into().expect("长度已检查"));
        let link_prev: Hash = tail[8..8 + HASH_LEN].try_into().expect("长度已检查");
        let hash: Hash = tail[8 + HASH_LEN..].try_into().expect("长度已检查");

        let event = decode(canonical).map_err(|e: DecodeError| ReadError::Corrupt {
            index: expect_seq,
            offset,
            reason: e.to_string(),
        })?;

        if seq != expect_seq {
            return Err(ReadError::Corrupt {
                index: expect_seq,
                offset,
                reason: format!("序号是 {seq}，应为 {expect_seq}"),
            });
        }
        if link_prev != prev {
            return Err(ReadError::Corrupt {
                index: expect_seq,
                offset,
                reason: "前驱哈希与链不连续".to_string(),
            });
        }
        if hash != link_hash(prev, &event) {
            return Err(ReadError::Corrupt {
                index: expect_seq,
                offset,
                reason: "内容哈希对不上：这条记录被改过".to_string(),
            });
        }

        // 先取出 ts 再 move：struct 字面量里字段按书写顺序求值，
        // 写在后面的 `event.ts_ms` 会撞上已经被移走的 event
        let ts_ms = event.ts_ms;
        out.push(Record {
            event,
            link: Link {
                seq,
                ts_ms,
                prev: link_prev,
                hash,
            },
        });
        prev = hash;
        expect_seq += 1;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Protocol};
    use aegis_core::InterfaceRole;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event(n: u16) -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000 + u64::from(n),
            pid: 1000 + u32::from(n),
            process_path: format!(r"C:\App\app{n}.exe"),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000 + n),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: None,
            rule: None,
            luid: 42,
            role: InterfaceRole::CampusStrict,
            action: Action::Reject,
        }
    }

    /// 每个测试一套独立路径：进程内并行跑测试不能互相踩文件。
    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("aegis-audit-{tag}-{}-{nanos}.log", std::process::id()));
        p
    }

    #[test]
    fn create_then_append_then_read_back() {
        let path = tmp("basic");
        let _guard = RemoveOnDrop(&path);

        let mut log = AuditLog::create(&path).expect("新建应成功");
        assert_eq!(log.len(), 0);
        assert_eq!(log.head(), GENESIS);

        let mut links = Vec::new();
        for i in 0..4u16 {
            links.push(log.append(&event(i)).expect("追加应成功"));
        }
        log.flush().unwrap();
        assert_eq!(log.len(), 4);

        let records = read_records(&path).expect("读回应成功");
        assert_eq!(records.len(), 4);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.event, event(i as u16));
            assert_eq!(r.link, links[i]);
        }
    }

    /// 最重要的一条：重开必须**接着走**，不能从 GENESIS 重新开始。
    #[test]
    fn reopening_resumes_the_chain_instead_of_restarting_it() {
        let path = tmp("reopen");
        let _guard = RemoveOnDrop(&path);

        let head_after_first = {
            let mut log = AuditLog::create(&path).unwrap();
            for i in 0..5u16 {
                log.append(&event(i)).unwrap();
            }
            log.flush().unwrap();
            log.head()
        };

        let mut reopened = AuditLog::open(&path).expect("重开应成功");
        assert_eq!(reopened.len(), 5, "计数必须恢复");
        assert_eq!(reopened.head(), head_after_first, "链头必须恢复");
        assert_ne!(reopened.head(), GENESIS);

        // 续写一条，它的前驱是重开前那条的哈希
        let link = reopened.append(&event(5)).unwrap();
        assert_eq!(link.seq, 6);
        assert_eq!(link.prev, head_after_first);
        reopened.flush().unwrap();

        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 6);
        assert_eq!(
            crate::chain::verify(
                &records.iter().map(|r| r.event.clone()).collect::<Vec<_>>(),
                &records.iter().map(|r| r.link).collect::<Vec<_>>()
            ),
            Ok(()),
            "跨重开的整条链必须仍然自洽"
        );
    }

    /// 分片只是文件边界，不是证据边界。
    #[test]
    fn rotation_carries_the_chain_head_over() {
        let a = tmp("rot-a");
        let b = tmp("rot-b");
        let _ga = RemoveOnDrop(&a);
        let _gb = RemoveOnDrop(&b);

        let mut log = AuditLog::create(&a).unwrap();
        for i in 0..3u16 {
            log.append(&event(i)).unwrap();
        }
        let head_before = log.head();
        log.rotate(&b).unwrap();
        assert_eq!(log.head(), head_before, "轮换不该重置链");
        assert_eq!(log.len(), 3);

        let link = log.append(&event(3)).unwrap();
        assert_eq!(link.seq, 4);
        assert_eq!(link.prev, head_before, "新分片首条的前驱是旧分片的链头");
        log.flush().unwrap();

        // 两个分片读出来的记录拼起来，链必须仍然连续。
        // 第二个分片必须带着第一个分片的上下文读——它的序号是全局接着走的
        let first = read_records(&a).unwrap();
        let mut all = first.clone();
        all.extend(read_records_with(&b, ReadCtx::after(&first)).unwrap());
        assert_eq!(all.len(), 4);
        assert_eq!(
            crate::chain::verify(
                &all.iter().map(|r| r.event.clone()).collect::<Vec<_>>(),
                &all.iter().map(|r| r.link).collect::<Vec<_>>()
            ),
            Ok(())
        );
    }

    /// 服务重启后接着上一个分片写：必须 `open_with`，不能用 `open`
    /// （后者假定从头开始，会把续接分片判成损坏）。
    #[test]
    fn reopening_a_continuation_segment_works_with_the_right_ctx() {
        let a = tmp("cont-a");
        let b = tmp("cont-b");
        let _ga = RemoveOnDrop(&a);
        let _gb = RemoveOnDrop(&b);

        let mut log = AuditLog::create(&a).unwrap();
        for i in 0..3u16 {
            log.append(&event(i)).unwrap();
        }
        log.rotate(&b).unwrap();
        log.append(&event(3)).unwrap();
        log.flush().unwrap();

        let first = read_records(&a).unwrap();
        let ctx = ReadCtx::after(&first);
        assert_eq!(ctx.next_seq, 4);

        let mut cont = AuditLog::open_with(&b, ctx).expect("续接分片应能打开");
        assert_eq!(cont.len(), 4, "计数要接着前面的 3 条");
        assert_eq!(cont.head(), log.head());

        let link = cont.append(&event(4)).unwrap();
        assert_eq!(link.seq, 5);
        cont.flush().unwrap();

        let mut all = first;
        all.extend(read_records_with(&b, ctx).unwrap());
        assert_eq!(all.len(), 5);
        assert_eq!(
            crate::chain::verify(
                &all.iter().map(|r| r.event.clone()).collect::<Vec<_>>(),
                &all.iter().map(|r| r.link).collect::<Vec<_>>()
            ),
            Ok(())
        );
    }

    /// 改文件里的一个字节 → 读回必须报错，不能"尽力解析"出一条正常记录。
    #[test]
    fn tampering_with_the_file_is_detected_on_read_back() {
        let path = tmp("tamper");
        let _guard = RemoveOnDrop(&path);

        {
            let mut log = AuditLog::create(&path).unwrap();
            for i in 0..6u16 {
                log.append(&event(i)).unwrap();
            }
            log.sync().unwrap();
        }

        let mut raw = std::fs::read(&path).unwrap();
        // 改文件体中间的一个字节（跳过 19 字节头）
        let at = HEADER_LEN + 40;
        raw[at] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();

        let err = read_records(&path).expect_err("篡改必须被抓");
        let msg = err.to_string();
        assert!(
            msg.contains("损坏") || msg.contains("哈希"),
            "错误信息要说清是数据问题：{msg}"
        );
    }

    /// 尾部截断的文件：读回要么少几条，要么报错，**绝不能**谎称完整。
    #[test]
    fn truncated_tail_is_not_silently_accepted_as_complete() {
        let path = tmp("trunc");
        let _guard = RemoveOnDrop(&path);

        {
            let mut log = AuditLog::create(&path).unwrap();
            for i in 0..6u16 {
                log.append(&event(i)).unwrap();
            }
            log.sync().unwrap();
        }

        let raw = std::fs::read(&path).unwrap();
        std::fs::write(&path, &raw[..raw.len() - 30]).unwrap();

        match read_records(&path) {
            Ok(records) => assert!(records.len() < 6, "截断后不该仍报 6 条"),
            Err(ReadError::Corrupt { .. }) => {}
            Err(e) => panic!("截断应报损坏：{e}"),
        }
    }

    /// 建日志时若文件已存在必须失败：覆盖已有日志等于销毁证据。
    #[test]
    fn create_refuses_to_clobber_an_existing_log() {
        let path = tmp("clobber");
        let _guard = RemoveOnDrop(&path);
        {
            let mut log = AuditLog::create(&path).unwrap();
            log.append(&event(0)).unwrap();
            log.flush().unwrap();
        }
        assert!(
            AuditLog::create(&path).is_err(),
            "重复 create 必须失败，不能静默覆盖证据"
        );
    }

    #[test]
    fn empty_log_reads_back_as_no_records() {
        let path = tmp("empty");
        let _guard = RemoveOnDrop(&path);
        {
            AuditLog::create(&path).unwrap().flush().unwrap();
        }
        assert!(read_records(&path).unwrap().is_empty());
        let log = AuditLog::open(&path).unwrap();
        assert!(log.is_empty());
        assert_eq!(log.head(), GENESIS);
    }

    /// 不是本项目的文件要被认出来，别当成"0 条记录"。
    #[test]
    fn a_foreign_file_is_rejected_not_treated_as_empty() {
        let path = tmp("foreign");
        let _guard = RemoveOnDrop(&path);
        std::fs::write(&path, b"hello, not an audit log at all!!").unwrap();
        assert!(matches!(read_records(&path), Err(ReadError::BadMagic)));
    }

    struct RemoveOnDrop<'a>(&'a Path);
    impl Drop for RemoveOnDrop<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
}
