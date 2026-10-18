//! Aegis 本地 IPC：协议帧编解码 + 版本握手。
//!
//! # 边界
//!
//! | 模块 | 依赖 Win32 | 职责 |
//! |---|---|---|
//! | 帧编解码 / 版本握手（本文件） | 否 | 定长头 + 校验和 + 版本兼容判定 |
//! | [`endpoint`] | 否 | 管道名与 SDDL 常量 |
//! | [`token`] | 部分（仅随机数） | 一次性 token 与**常量时间**比对 |
//! | [`pipe`] | **是** | 建管道 / 连管道 / 收发帧 |
//!
//! 帧格式、版本判定、token 比对都不碰 Win32，因此能脱离权限环境完整测试；
//! `unsafe` 压在 [`pipe`] 一个文件里。
//!
//! ⚠ 管道**鉴权流程**（收到 AUTH 帧后校验 token、失败即断开）属于
//! `aegisd` 的服务端主循环，不在本 crate —— 这里只提供零件。
//!
//! # 为什么刻意不用 serde / bincode
//! 帧布局是**跨进程二进制契约**：`aegisd`（SYSTEM）与 `aegisctl`（普通权限）
//! 是两个独立编译、可能不同版本的二进制。一旦把布局交给序列化库，
//! 库的一次升级就可能悄悄改变线上帧布局，而两端升级节奏不一致时会
//! 解析出错——**IPC 解析错误在安全底座上就是安全漏洞**。
//! 因此这里手写定长头 + 显式校验和，格式完全由本项目掌控。
//!
//! # 帧布局（网络字节序 / 大端）
//! ```text
//!  0  4  魔数 b"AEG1"
//!  4  1  消息类型（见 [msg_type]）
//!  5  1  标志位
//!  6  2  保留，必须为 0（不为 0 即视为不兼容实现）
//!  8  4  seq（请求-响应配对）
//! 12  4  载荷长度 N（字节）
//! 16  N  载荷
//! 16+N 4  载荷校验和（FNV-1a 32）
//! ```

pub mod endpoint;
pub mod ctl;
pub mod peer;
pub mod pipe;
pub mod token;
pub mod tokenfile;
pub mod version;

pub use ctl::{
    classify, risk_of, Status, StatusError, DENY_PREFIX, OK_PREFIX, REQ_APPLY, REQ_CONFIRM,
    REQ_PING, REQ_ROLLBACK, REQ_STATUS, STATUS_V1,
};
pub use peer::{allows, is_elevated, Risk};
pub use tokenfile::{write_protected, TokenFileError};
pub use endpoint::{PIPE_NAME, PIPE_SDDL, TOKEN_FILE_SDDL};
pub use pipe::{PipeClient, PipeEnd, PipeError, PipeServer};
pub use token::{constant_time_eq, IpcToken, TokenError, TOKEN_BYTES, TOKEN_HEX_LEN};
pub use version::{
    check_compat, HandshakePayload, Note, ParseError, RejectReason, Verdict, VersionTriple,
};

/// 帧魔数。
pub const MAGIC: [u8; 4] = *b"AEG1";
/// 定长头长度。
pub const HEADER_LEN: usize = 16;
/// 校验和尾部长度。
pub const TRAILER_LEN: usize = 4;
/// 单帧载荷上限。IPC 只传控制指令与状态，64 KiB 已远超需要；
/// 设上限是为了让"对端被攻破后发一个巨大长度字段"无法导致 OOM。
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// 读缓冲区上限（超过即判定协议失步）。
pub const MAX_BUFFER: usize = 1024 * 1024;

/// 消息类型。
pub mod msg_type {
    /// 握手：载荷为 [`HandshakePayload`] 编码后的 16 字节
    pub const HANDSHAKE: u8 = 1;
    /// 请求（控制端 → 守护进程）
    pub const REQUEST: u8 = 2;
    /// 响应（守护进程 → 控制端）
    pub const RESPONSE: u8 = 3;
    /// 守护进程主动推送的状态事件
    pub const EVENT: u8 = 4;
    /// 心跳
    pub const PING: u8 = 5;
    /// 心跳应答
    pub const PONG: u8 = 6;
    /// 鉴权：载荷为 [`crate::token::IpcToken`] 的 hex 文本（64 字节 ASCII）。
    /// 服务端校验失败必须**立刻断开**，不回任何响应。
    pub const AUTH: u8 = 7;
    /// 鉴权结果
    pub const AUTH_RESULT: u8 = 8;
}

/// 帧错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("帧不完整：至少需要 {need} 字节，实际 {got} 字节")]
    TooShort { need: usize, got: usize },
    #[error("魔数不匹配：不是 Aegis 帧")]
    BadMagic,
    #[error("保留位非 0：来自不兼容的实现或数据已损坏")]
    BadReserved,
    #[error("声明载荷 {declared} 字节，实际只有 {available} 字节")]
    LengthMismatch { declared: usize, available: usize },
    #[error("载荷超过上限 {limit} 字节")]
    PayloadTooLarge { limit: usize },
    #[error("校验和不匹配：载荷在传输中被篡改或截断")]
    BadChecksum,
    #[error("读缓冲区超过 {limit} 字节，协议已失步")]
    BufferOverflow { limit: usize },
}

/// FNV-1a 32 位校验和。
///
/// 选它而不是 CRC32：Aegis 的 IPC 走的是同机管道，不存在真实的
/// 信道噪声，校验和的目的是**抓实现 bug 与截断**，不是纠错。
/// 因此用 10 行可完整单测的哈希比引入一张 CRC 表更合适。
pub fn checksum(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// 解码出的帧（借自输入缓冲区，零拷贝）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub msg_type: u8,
    pub flags: u8,
    pub seq: u32,
    pub payload: &'a [u8],
}

impl Frame<'_> {
    /// 转成拥有载荷所有权的帧（跨函数边界传递时用）。
    pub fn to_owned(&self) -> OwnedFrame {
        OwnedFrame {
            msg_type: self.msg_type,
            flags: self.flags,
            seq: self.seq,
            payload: self.payload.to_vec(),
        }
    }
}

/// 拥有载荷所有权的帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFrame {
    pub msg_type: u8,
    pub flags: u8,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// 把一帧追加到 `out`。
pub fn encode_into(
    out: &mut Vec<u8>,
    msg_type: u8,
    flags: u8,
    seq: u32,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge { limit: MAX_PAYLOAD });
    }
    out.extend_from_slice(&MAGIC);
    out.push(msg_type);
    out.push(flags);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&checksum(payload).to_be_bytes());
    Ok(())
}

/// 编码一帧（便捷入口）。
pub fn encode(msg_type: u8, flags: u8, seq: u32, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + TRAILER_LEN);
    encode_into(&mut out, msg_type, flags, seq, payload)?;
    Ok(out)
}

/// 解码一帧。只消费缓冲区中的**第一帧**，剩余字节由调用方/阅读器处理。
pub fn decode(buf: &[u8]) -> Result<Frame<'_>, FrameError> {
    let need = HEADER_LEN + TRAILER_LEN;
    if buf.len() < need {
        return Err(FrameError::TooShort {
            need,
            got: buf.len(),
        });
    }
    if buf[0..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if u16::from_be_bytes([buf[6], buf[7]]) != 0 {
        return Err(FrameError::BadReserved);
    }

    let declared = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
    if declared > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge { limit: MAX_PAYLOAD });
    }
    if buf.len() < HEADER_LEN + declared + TRAILER_LEN {
        return Err(FrameError::LengthMismatch {
            declared,
            available: buf.len().saturating_sub(need),
        });
    }

    let payload = &buf[HEADER_LEN..HEADER_LEN + declared];
    let want = u32::from_be_bytes([
        buf[HEADER_LEN + declared],
        buf[HEADER_LEN + declared + 1],
        buf[HEADER_LEN + declared + 2],
        buf[HEADER_LEN + declared + 3],
    ]);
    if checksum(payload) != want {
        return Err(FrameError::BadChecksum);
    }

    Ok(Frame {
        msg_type: buf[4],
        flags: buf[5],
        seq: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        payload,
    })
}

/// 流式帧阅读器。
///
/// 命名管道是字节流，**一次 read 不保证拿到的字节数正好是一帧**。
/// 直接对单次 read 的结果调 [`decode`] 会在分片时误判为坏帧——
/// 这是手写协议最常见的 bug。这里把缓冲与切帧收进一个类型，
/// 让"分片/粘包"成为被测试覆盖过的行为，而不是每个调用方各自踩一遍。
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    pos: usize,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// 尚未消费的字节数。
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// 追加新到达的字节。
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        if self.pending().saturating_add(bytes.len()) > MAX_BUFFER {
            return Err(FrameError::BufferOverflow { limit: MAX_BUFFER });
        }
        self.compact();
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// 取出一帧；缓冲区不足一帧时返回 `None`。
    pub fn pop(&mut self) -> Option<Result<OwnedFrame, FrameError>> {
        // 借用与推进位置必须分开：帧借自缓冲区，而推进位置需要 &mut self。
        // 这里在块内结束借用，把结果"搬运"出来后再改状态。
        let outcome = {
            let rest = &self.buf[self.pos..];
            match decode(rest) {
                Ok(f) => {
                    let consumed = HEADER_LEN + f.payload.len() + TRAILER_LEN;
                    (Some(Ok(f.to_owned())), consumed)
                },
                // 数据还不够凑出一帧：不是错误，等下一次 feed
                Err(FrameError::TooShort { .. } | FrameError::LengthMismatch { .. }) => (None, 0),
                Err(e) => (Some(Err(e)), 0),
            }
        };
        match outcome {
            (None, _) => None,
            (Some(result), consumed) => {
                self.pos += consumed;
                self.compact();
                Some(result)
            },
        }
    }

    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        self.buf.drain(..self.pos);
        self.pos = 0;
    }
}

/// 本进程的版本三段（`aegis-version` 的 `VERSION` 解析结果）。
pub fn local_version() -> VersionTriple {
    VersionTriple::parse(aegis_version::VERSION).unwrap_or(VersionTriple {
        major: 0,
        minor: 0,
        patch: 0,
        prerelease: true,
    })
}

/// 编码一条握手帧，载荷为本进程版本的定长编码。
pub fn encode_handshake(seq: u32) -> Result<Vec<u8>, FrameError> {
    encode(
        msg_type::HANDSHAKE,
        0,
        seq,
        &HandshakePayload::from_triple(local_version()).encode(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a 32 的标准测试向量。校验和写错而无人发现的话，
    /// "校验和"就只是四个无意义的字节。
    #[test]
    fn checksum_matches_known_vectors() {
        assert_eq!(checksum(b""), 0x811c_9dc5);
        assert_eq!(checksum(b"a"), 0xe40c_292c);
        assert_eq!(checksum(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let bytes = encode(msg_type::REQUEST, 0xAB, 42, b"hello").unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + 5 + TRAILER_LEN);
        let f = decode(&bytes).unwrap();
        assert_eq!(f.msg_type, msg_type::REQUEST);
        assert_eq!(f.flags, 0xAB);
        assert_eq!(f.seq, 42);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn empty_payload_roundtrips() {
        let bytes = encode(msg_type::PING, 0, 0, b"").unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + TRAILER_LEN);
        assert_eq!(decode(&bytes).unwrap().payload.len(), 0);
    }

    #[test]
    fn header_uses_big_endian_and_magic() {
        let bytes = encode(msg_type::EVENT, 0, 0x0102_0304, b"x").unwrap();
        assert_eq!(&bytes[0..4], b"AEG1");
        assert_eq!(bytes[4], msg_type::EVENT);
        assert_eq!(&bytes[6..8], &[0, 0]);
        assert_eq!(&bytes[8..12], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 1]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = encode(msg_type::PING, 0, 0, b"").unwrap();
        bytes[2] = 0xFF;
        assert_eq!(decode(&bytes), Err(FrameError::BadMagic));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut bytes = encode(msg_type::PING, 0, 0, b"").unwrap();
        bytes[7] = 1;
        assert_eq!(decode(&bytes), Err(FrameError::BadReserved));
    }

    #[test]
    fn rejects_truncated_frame() {
        assert!(matches!(
            decode(&[0u8; 4]),
            Err(FrameError::TooShort { .. })
        ));
        let bytes = encode(msg_type::REQUEST, 0, 0, b"payload").unwrap();
        assert!(matches!(
            decode(&bytes[..bytes.len() - 1]),
            Err(FrameError::LengthMismatch { .. })
        ));
    }

    /// 篡改载荷必须被校验和抓住——这正是校验和存在的唯一理由。
    #[test]
    fn rejects_tampered_payload() {
        let mut bytes = encode(msg_type::REQUEST, 0, 7, b"allow").unwrap();
        let last = bytes.len() - 1;
        bytes[last - 1] ^= 0xFF;
        assert_eq!(decode(&bytes), Err(FrameError::BadChecksum));
    }

    #[test]
    fn rejects_oversized_payload_on_both_sides() {
        assert_eq!(
            encode(msg_type::REQUEST, 0, 0, &vec![0u8; MAX_PAYLOAD + 1]),
            Err(FrameError::PayloadTooLarge { limit: MAX_PAYLOAD })
        );
        // 对端伪造一个超大长度字段，同样不得放行
        let mut bytes = encode(msg_type::REQUEST, 0, 0, b"").unwrap();
        bytes[12..16].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        assert_eq!(
            decode(&bytes),
            Err(FrameError::PayloadTooLarge { limit: MAX_PAYLOAD })
        );
    }

    /// 分片与粘包：管道一次 read 的边界和帧边界没有任何关系。
    #[test]
    fn reader_handles_fragmentation_and_coalescing() {
        let a = encode(msg_type::REQUEST, 1, 1, b"one").unwrap();
        let b = encode(msg_type::RESPONSE, 2, 2, b"two!!!").unwrap();
        let c = encode(msg_type::EVENT, 3, 3, b"").unwrap();

        // 先粘包喂入两帧，再把第三帧逐字节喂入
        let mut r = FrameReader::new();
        let mut joined = a.clone();
        joined.extend_from_slice(&b);
        r.feed(&joined).unwrap();
        for byte in &c {
            r.feed(std::slice::from_ref(byte)).unwrap();
        }

        let fa = r.pop().unwrap().unwrap();
        assert_eq!((fa.msg_type, fa.flags, fa.seq), (msg_type::REQUEST, 1, 1));
        assert_eq!(fa.payload, b"one");
        assert!(r.pending() > 0, "第二帧应仍在缓冲区中");

        let fb = r.pop().unwrap().unwrap();
        assert_eq!(fb.payload, b"two!!!");

        let fc = r.pop().unwrap().unwrap();
        assert_eq!((fc.msg_type, fc.flags, fc.seq), (msg_type::EVENT, 3, 3));
        assert_eq!(fc.payload.len(), 0);

        assert!(r.pop().is_none(), "取完后不应再有帧");
        assert_eq!(r.pending(), 0, "缓冲区应已排空");
    }

    #[test]
    fn reader_reports_corrupt_frame_rather_than_stalling() {
        let mut r = FrameReader::new();
        r.feed(b"NOTAFRAME................").unwrap();
        assert_eq!(r.pop(), Some(Err(FrameError::BadMagic)));
    }

    #[test]
    fn handshake_frame_carries_local_version() {
        let bytes = encode_handshake(9).unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.msg_type, msg_type::HANDSHAKE);
        assert_eq!(f.seq, 9);

        let peer = HandshakePayload::decode(f.payload).unwrap().to_triple();
        assert_eq!(peer, local_version());
        assert_eq!(
            check_compat(peer, local_version()),
            Verdict::Warn(Note::Prerelease)
        );
    }
}
