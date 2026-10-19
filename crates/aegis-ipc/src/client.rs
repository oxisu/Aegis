//! 客户端会话：连管道 → 版本握手 → token 鉴权 → 请求 / 应答。
//!
//! # 为什么要有这个模块
//!
//! 这套流程原先只存在于 `aegisctl` 的 `main` 里。等 GUI 出现，它就是
//! **第二个**调用方，于是同一段流程要写第二遍。写第二遍本身问题不大，
//! 问题在于这段流程里有两条纪律，而它们**违反时不会报错，只会变弱**：
//!
//! 1. **握手必须在鉴权之前**——版本谈不拢就不能把 token 送过去，
//!    因为对面是老版本时，它未必会用常量时间比对来验 token。
//! 2. **鉴权失败不许重试**——自动重试会把"token 不对"变成一次
//!    慢速的拒绝服务，也更容易撞上服务端的防爆破策略。
//!
//! 抄一遍的时候注释丢一半的概率很高，而且丢完照样能跑、照样连得上，
//! 只是安全性悄悄降了一档。所以把它收进库，并且**用类型状态把顺序钉死**。
//!
//! # 类型状态：顺序错了编译不过
//!
//! ```text
//! Session<Connected> ──handshake()──▶ Session<Handshook> ──authenticate()──▶ Session<Ready>
//!                                                                                  │
//!                                                                            request() 只挂在这里
//! ```
//!
//! 没握手就拿不到 [`Handshook`]，没鉴权就拿不到 [`Ready`]，而
//! [`Session::request`] 只实现在 `Session<Ready>` 上。**顺序写反是编译错误**，
//! 不是"记得别写反"。
//!
//! ```compile_fail
//! use aegis_ipc::client::Session;
//! // 没握手、没鉴权就想发请求：类型上根本没有 `request`，编译不过。
//! let mut s = Session::connect(r"\\.\pipe\aegis-does-not-exist").unwrap();
//! let _ = s.request("status");
//! ```
//!
//! # 想省事就用 [`talk`]
//!
//! 一次调用走完全流程。它内部同样按上面的顺序走，所以纪律不会丢；
//! 代价是拿不到分步信息（对端版本、鉴权结果），需要自己打印过程的
//! 命令行工具请用分步接口。

use crate::{
    check_compat, classify, encode_handshake, local_version, msg_type, FrameError, FrameReader,
    HandshakePayload, IpcToken, ParseError, PipeClient, PipeEnd, PipeError, RejectReason, Verdict,
    VersionTriple,
};

/// 一次会话的失败原因。
///
/// 刻意**不合并**成笼统的 "protocol error"：`aegisctl` 要给每一类
/// 配不同的退出码和不同的提示，而"连不上管道"和"token 不对"
/// 对人的处置动作完全不同（前者去看服务起没起，后者去看 token 文件）。
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("连不上管道：{0}")]
    Connect(#[source] PipeError),
    #[error("编码握手帧失败：{0}")]
    EncodeHandshake(#[source] FrameError),
    #[error("发握手失败：{0}")]
    SendHandshake(#[source] PipeError),
    #[error("收握手应答失败：{0}")]
    RecvHandshake(#[source] PipeError),
    // ParseError 只实现 Display（不实现 std::error::Error），所以用 `{0}`
    // 直接格式化，不标 `#[source]`。
    #[error("握手应答解析失败：{0}")]
    DecodeHandshake(ParseError),
    /// 版本谈不拢。**带上对端版本**：调用方要能打印"服务端版本 x.y.z：Reject(...)"，
    /// 否则人只看到一句"版本不兼容"，不知道该升级谁。
    #[error("版本不兼容：{reason}")]
    Incompatible {
        peer: VersionTriple,
        reason: RejectReason,
    },
    #[error("发鉴权失败：{0}")]
    SendAuth(#[source] PipeError),
    /// 服务端对鉴权失败的处理是**立刻断开、不回任何响应**，
    /// 所以收不到应答的第一嫌疑就是 token 不对。
    #[error("没收到鉴权应答：{0}")]
    NoAuthReply(#[source] PipeError),
    #[error("鉴权失败：{0}")]
    AuthDenied(String),
    #[error("发请求失败：{0}")]
    SendRequest(#[source] PipeError),
    #[error("收应答失败：{0}")]
    RecvResponse(#[source] PipeError),
    /// 服务端按 `denied ` 前缀明确拒绝了（与"协议出错"不是一回事：
    /// 协议出错是链路问题，被拒绝是**服务端想清楚了才拒的**）。
    #[error("{0}")]
    Rejected(String),
}

// ── 状态标记 ─────────────────────────────────────────────────────────

/// 已连上，还没握手。
#[derive(Debug)]
pub struct Connected;

/// 已握手，还没鉴权。带着对端版本，供调用方打印/判断。
#[derive(Debug, Clone, Copy)]
pub struct Handshook {
    peer: VersionTriple,
}

impl Handshook {
    /// 对端（服务端）的版本。
    pub fn peer(&self) -> VersionTriple {
        self.peer
    }

    /// 本端对对端版本的兼容性结论。
    ///
    /// 刻意**每次重算**而不是把 `Verdict` 存下来：握手时已经判过一次
    /// （不兼容就直接返回 [`ClientError::Incompatible`]），这里再算一次
    /// 的开销可以忽略，但能保证调用方拿到的结论和本端版本永远一致。
    pub fn verdict(&self) -> Verdict {
        check_compat(self.peer, local_version())
    }
}

/// 已鉴权，可以发请求了。
#[derive(Debug)]
pub struct Ready;

/// 一条 IPC 客户端会话。`S` 是进行到哪一步。
///
/// ⚠ `_client` **必须活得比 `end` 久**：[`PipeEnd`] 不拥有句柄，
/// 句柄的生命周期归 [`PipeClient`]。把两者一起收进同一个结构体，
/// 是为了让"句柄被提前关掉"这件事在类型上就不可能发生。
#[derive(Debug)]
pub struct Session<S = Connected> {
    _client: PipeClient,
    end: PipeEnd,
    reader: FrameReader,
    state: S,
}

impl Session<Connected> {
    /// 连上指定管道。**只建连接**，不动协议。
    pub fn connect(pipe: &str) -> Result<Self, ClientError> {
        let client = PipeClient::connect_named(pipe).map_err(ClientError::Connect)?;
        Ok(Self {
            end: client.end(),
            _client: client,
            reader: FrameReader::new(),
            state: Connected,
        })
    }

    /// 版本握手。**必须在鉴权之前**——这是类型状态存在的首要理由。
    ///
    /// 不兼容时返回 [`ClientError::Incompatible`]，此刻 token 还**没有**
    /// 被送出去。
    pub fn handshake(mut self) -> Result<Session<Handshook>, ClientError> {
        let bytes = encode_handshake(1).map_err(ClientError::EncodeHandshake)?;
        self.end
            .send_raw(&bytes)
            .map_err(ClientError::SendHandshake)?;

        let reply = self
            .end
            .recv(&mut self.reader)
            .map_err(ClientError::RecvHandshake)?;
        let peer = HandshakePayload::decode(&reply.payload)
            .map_err(ClientError::DecodeHandshake)?
            .to_triple();

        if let Verdict::Reject(reason) = check_compat(peer, local_version()) {
            return Err(ClientError::Incompatible { peer, reason });
        }

        Ok(Session {
            _client: self._client,
            end: self.end,
            reader: self.reader,
            state: Handshook { peer },
        })
    }
}

impl Session<Handshook> {
    /// 对端版本与兼容结论。
    pub fn handshake(&self) -> &Handshook {
        &self.state
    }

    /// 带上 token 做鉴权。
    ///
    /// ⚠ **失败不许重试**：服务端对鉴权失败是立刻断开且不回响应，
    /// 重试只是把一次失败变成一串失败，还会撞上防爆破策略。
    /// 这里返回 `Err` 就结束了，没有任何重试逻辑——调用方想重试
    /// 也得自己重新走一遍 `connect`，那等于新建连接，语义是清楚的。
    pub fn authenticate(mut self, token: &IpcToken) -> Result<Session<Ready>, ClientError> {
        self.end
            .send(msg_type::AUTH, 0, 2, token.to_hex().as_bytes())
            .map_err(ClientError::SendAuth)?;

        let auth = self
            .end
            .recv(&mut self.reader)
            .map_err(ClientError::NoAuthReply)?;
        if auth.payload != b"ok" {
            return Err(ClientError::AuthDenied(
                String::from_utf8_lossy(&auth.payload).to_string(),
            ));
        }

        Ok(Session {
            _client: self._client,
            end: self.end,
            reader: self.reader,
            state: Ready,
        })
    }
}

impl Session<Ready> {
    /// 发一个请求词，返回**去掉前缀的正文**。
    ///
    /// 成败按**前缀**判（[`classify`]），不靠在正文里搜"失败"两个字——
    /// 靠搜的下场是服务端哪天把拒绝原因写成"未执行"，这里就当成功，
    /// 而人拿着绿色的结果以为规则已经装上。
    pub fn request(&mut self, word: &str) -> Result<String, ClientError> {
        self.end
            .send(msg_type::REQUEST, 0, 3, word.as_bytes())
            .map_err(ClientError::SendRequest)?;

        let resp = self
            .end
            .recv(&mut self.reader)
            .map_err(ClientError::RecvResponse)?;
        let text = String::from_utf8_lossy(&resp.payload);

        match classify(&text) {
            Ok(body) => Ok(body.to_string()),
            Err(reason) => Err(ClientError::Rejected(reason.to_string())),
        }
    }
}

/// 一步到位：连管道 → 握手 → 鉴权 → 发一个请求。
///
/// 内部严格按 [`Session`] 的类型状态顺序走，所以两条纪律一样不丢。
/// 需要分步打印过程的调用方（比如 `aegisctl`）请用分步接口。
pub fn talk(pipe: &str, token: &IpcToken, word: &str) -> Result<String, ClientError> {
    let mut ready = Session::connect(pipe)?.handshake()?.authenticate(token)?;
    ready.request(word)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PipeServer;
    use std::sync::mpsc;
    use std::thread;

    /// 测试用独立管道名：避免与真实服务或其它测试抢 `FIRST_PIPE_INSTANCE`。
    fn test_name(tag: &str) -> String {
        format!(r"\\.\pipe\aegis-client-{tag}-{}", std::process::id())
    }

    /// 起一个服务端线程，走完握手 → 鉴权 → 应答。
    ///
    /// `auth_ok = false` 时**什么都不回**就结束线程——复现服务端对鉴权失败
    /// "立刻断开且不回响应"的真实行为，客户端应当收到"断开"而不是卡住。
    fn spawn_server(name: &str, auth_ok: bool, reply: &'static str) {
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let owned = name.to_string();
        thread::spawn(move || {
            let srv = PipeServer::bind_named(&owned).expect("建管道应成功");
            // 客户端必须等管道真的存在才能连，否则 CreateFileW 直接
            // ERROR_FILE_NOT_FOUND。用 channel 把这件事变成确定性的。
            let _ = ready_tx.send(());

            let end = srv.accept().expect("accept 应成功");
            let mut r = FrameReader::new();

            // 握手
            let hs = end.recv(&mut r).expect("应收握手");
            let _ = HandshakePayload::decode(&hs.payload).expect("握手载荷应可解析");
            let back = encode_handshake(hs.seq).expect("编码握手应答");
            end.send_raw(&back).expect("回握手应成功");

            // 鉴权
            let _auth = end.recv(&mut r).expect("应收鉴权");
            if !auth_ok {
                return; // 直接断开，不回任何响应
            }
            end.send(msg_type::AUTH_RESULT, 0, 2, b"ok")
                .expect("回鉴权应成功");

            // 请求 / 应答
            let req = end.recv(&mut r).expect("应收请求");
            end.send(msg_type::RESPONSE, 0, req.seq, reply.as_bytes())
                .expect("回应答应成功");
        });
        ready_rx.recv().expect("等服务端就绪");
    }

    #[test]
    fn talk_returns_the_body_with_the_ok_prefix_stripped() {
        let name = test_name("ok");
        spawn_server(&name, true, "ok hello");

        let token = IpcToken::generate().expect("随机数源应可用");
        let body = talk(&name, &token, "ping").expect("应成功");
        assert_eq!(body, "hello");
    }

    /// 服务端按 `denied ` 前缀拒绝，必须变成 `Rejected` 而不是"协议错误"——
    /// 这两者对人的处置动作完全不同。
    #[test]
    fn a_denied_reply_surfaces_as_rejected_not_as_a_protocol_error() {
        let name = test_name("denied");
        spawn_server(&name, true, "denied 需要管理员权限");

        let token = IpcToken::generate().expect("随机数源应可用");
        match talk(&name, &token, "apply") {
            Err(ClientError::Rejected(reason)) => assert_eq!(reason, "需要管理员权限"),
            other => panic!("应为 Rejected，实际 {other:?}"),
        }
    }

    /// 服务端不回鉴权应答（真实行为：立刻断开）。客户端必须报"没收到应答"，
    /// 而且**不许重试**——重试在这条路径上只会拖慢失败。
    #[test]
    fn a_vanishing_server_reports_no_auth_reply() {
        let name = test_name("noauth");
        spawn_server(&name, false, "ok:never-sent");

        let token = IpcToken::generate().expect("随机数源应可用");
        match talk(&name, &token, "status") {
            Err(ClientError::NoAuthReply(_)) => {},
            other => panic!("应为 NoAuthReply，实际 {other:?}"),
        }
    }

    /// 连不存在的管道必须是 `Connect`，不能和"鉴权失败"混为一谈。
    #[test]
    fn a_missing_pipe_is_a_connect_failure() {
        let token = IpcToken::generate().expect("随机数源应可用");
        match talk(r"\\.\pipe\aegis-definitely-not-here", &token, "status") {
            Err(ClientError::Connect(_)) => {},
            other => panic!("应为 Connect，实际 {other:?}"),
        }
    }

    /// 分步接口要能拿到对端版本——`aegisctl` 靠它打印"服务端版本 x.y.z"。
    #[test]
    fn the_stepwise_api_exposes_the_peer_version() {
        let name = test_name("stepwise");
        spawn_server(&name, true, "ok pong");

        let token = IpcToken::generate().expect("随机数源应可用");
        let hs = Session::connect(&name)
            .expect("应连上")
            .handshake()
            .expect("握手应成功");
        assert_eq!(hs.handshake().peer(), local_version());
        assert!(hs.handshake().verdict().is_allowed());

        let mut ready = hs.authenticate(&token).expect("鉴权应通过");
        assert_eq!(ready.request("ping").expect("请求应成功"), "pong");
    }

    #[test]
    fn every_error_variant_has_a_non_empty_message() {
        // 空错误消息在排障时等于没有消息：人会看到 `[FATAL] ` 然后不知所措。
        let pipe_error = PipeError::Disconnected;
        let cases = [
            ClientError::Connect(pipe_error.clone()),
            ClientError::SendHandshake(pipe_error.clone()),
            ClientError::RecvHandshake(pipe_error.clone()),
            ClientError::NoAuthReply(pipe_error.clone()),
            ClientError::SendAuth(pipe_error.clone()),
            ClientError::SendRequest(pipe_error.clone()),
            ClientError::RecvResponse(pipe_error),
            ClientError::Incompatible {
                peer: local_version(),
                reason: RejectReason::MajorMismatch,
            },
            ClientError::AuthDenied("bad token".to_string()),
            ClientError::Rejected("需要管理员".to_string()),
        ];
        for c in &cases {
            assert!(!c.to_string().is_empty(), "{c:?} 的错误消息为空");
            assert!(!c.to_string().starts_with(':'), "{c:?} 的消息格式不对");
        }
    }
}
