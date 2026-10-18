//! 命名管道的创建、连接与帧收发 —— **本 crate 唯一出现 `unsafe` 的模块**。
//!
//! # 三个不能省的安全属性
//!
//! 1. **显式 DACL**（[`crate::endpoint::PIPE_SDDL`]）。不传安全属性就会继承
//!    创建者（SYSTEM）的默认 DACL，标准用户连不上，且失败只是"连接被拒绝"，
//!    看不出是 ACL 的锅。
//! 2. **`FILE_FLAG_FIRST_PIPE_INSTANCE`**。少了这个标志，任何进程都能**抢先
//!    建同名管道**冒充服务（管道抢占 / squatting）。GUI 不提权，它无法区分
//!    真假服务 —— 这是第一个能被提权的口子。
//! 3. **句柄不可继承**（`bInheritHandle = false`）。否则服务启动的子进程会
//!    继承管道句柄，鉴权等于开了后门。
//!
//! # 为什么用字节流模式而不是消息模式
//!
//! 帧本身带长度前缀（[`crate::HEADER_LEN`]），分片/粘包由
//! [`crate::FrameReader`] 处理——那本来就是它存在的理由。消息模式会引入
//! `ERROR_MORE_DATA` 那套半截读的语义，反而多一处容易写错的地方。

use std::mem::size_of;

use windows::core::{Error as WinError, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, ERROR_BROKEN_PIPE,
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
};
use windows::Win32::Security::{
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
};

use crate::endpoint::{DEFAULT_TIMEOUT_MS, MAX_INSTANCES, PIPE_NAME, PIPE_SDDL};
use crate::{encode, FrameError, FrameReader, OwnedFrame, HEADER_LEN, MAX_PAYLOAD, TRAILER_LEN};

/// 管道缓冲区大小：一帧最大 = 头 + 载荷上限 + 校验和尾。
const BUFFER_SIZE: u32 = (HEADER_LEN + MAX_PAYLOAD + TRAILER_LEN) as u32;
/// 单次 read 的临时缓冲区。
const READ_CHUNK: usize = 4096;
/// 字节流模式（`PIPE_TYPE_BYTE | PIPE_READMODE_BYTE` 皆为 0）。
const PIPE_MODE_BYTE: NAMED_PIPE_MODE = NAMED_PIPE_MODE(0);

/// 管道操作失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipeError {
    #[error("SDDL 无效或转换失败：{0}")]
    BadSddl(String),
    #[error("创建命名管道失败：{0}")]
    CreateFailed(String),
    #[error("等待客户端连接失败：{0}")]
    AcceptFailed(String),
    #[error("连接命名管道失败：{0}")]
    ConnectFailed(String),
    #[error("读管道失败：{0}")]
    ReadFailed(String),
    #[error("写管道失败：{0}")]
    WriteFailed(String),
    #[error("对端已断开")]
    Disconnected,
    #[error("帧错误：{0}")]
    Frame(#[from] FrameError),
}

fn os_error() -> String {
    std::io::Error::last_os_error().to_string()
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 这个 Win32 错误是不是"对端没了"。
///
/// 实测出来的三种情形：客户端 `CloseHandle` 之后，阻塞中的 `ReadFile`
/// **不会** 返回 `got == 0`，而是直接以 `ERROR_BROKEN_PIPE`（109）失败；
/// 对端尚未连上 / 已断开时读写则是 `ERROR_PIPE_NOT_CONNECTED`（233）。
/// 不映射这两者，长连接主循环会把"客户端正常退出"误判成协议故障，
/// 然后去告警、去重连 —— 而它只是关了个窗口。
fn is_disconnect(error: &WinError) -> bool {
    let code = error.code();
    code == HRESULT::from_win32(ERROR_BROKEN_PIPE.0)
        || code == HRESULT::from_win32(ERROR_PIPE_NOT_CONNECTED.0)
}

/// 把"对端没了"归一化成 [`PipeError::Disconnected`]，其余错误原样包装。
fn classify(error: &WinError, other: PipeError) -> PipeError {
    if is_disconnect(error) {
        PipeError::Disconnected
    } else {
        other
    }
}

/// `ConnectNamedPipe` 返回 FALSE 时的裁决。
///
/// 两个必须单独处理的码，否则服务会在竞态窗口里随机拒绝合法客户端：
/// - `ERROR_PIPE_CONNECTED`（535）：客户端在 `CreateNamedPipeW` 与
///   `ConnectNamedPipe` 之间就连上了 —— 这是**成功**。
/// - `ERROR_NO_DATA`（232）：连上了又立刻断开 —— 归为 `Disconnected`，
///   而不是"等待连接失败"。
fn accept_outcome(error: &WinError) -> Result<(), PipeError> {
    let code = error.code();
    if code == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
        Ok(())
    } else if code == HRESULT::from_win32(ERROR_NO_DATA.0) {
        Err(PipeError::Disconnected)
    } else {
        Err(PipeError::AcceptFailed(error.to_string()))
    }
}

/// 由 SDDL 生成的 Windows 安全描述符（RAII：离开作用域 `LocalFree`）。
///
/// 必须在 `CreateNamedPipeW` 调用期间保持有效；内核会在创建对象时把 DACL
/// **复制**进内核对象，因此调用返回后即可释放。
#[derive(Debug)]
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, PipeError> {
        let wide = to_wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd,
                None,
            )
            .map_err(|e| PipeError::BadSddl(e.to_string()))?
        };
        Ok(Self(sd))
    }

    fn as_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            // 不可继承：否则服务启动的子进程会继承管道句柄，鉴权形同虚设
            bInheritHandle: BOOL(0),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

/// 服务端：持有管道监听句柄。
#[derive(Debug)]
pub struct PipeServer {
    handle: HANDLE,
}

impl PipeServer {
    /// 建管道。需要能创建第一个实例；普通权限下也能建（只要名字没被占用）。
    pub fn bind() -> Result<Self, PipeError> {
        Self::bind_named(PIPE_NAME)
    }

    pub fn bind_named(name: &str) -> Result<Self, PipeError> {
        let wide = to_wide(name);
        let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
        let attrs = sd.as_attributes();

        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_MODE_BYTE,
                MAX_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                DEFAULT_TIMEOUT_MS,
                Some(&attrs),
            )
        };
        // 内核已在创建时复制 DACL，此处可安全释放
        drop(sd);

        if handle == INVALID_HANDLE_VALUE {
            return Err(PipeError::CreateFailed(os_error()));
        }
        Ok(Self { handle })
    }

    /// 阻塞等待一个客户端连上。
    pub fn accept(&self) -> Result<PipeEnd, PipeError> {
        match unsafe { ConnectNamedPipe(self.handle, None) } {
            Ok(()) => {}
            Err(e) => accept_outcome(&e)?,
        };
        Ok(PipeEnd { handle: self.handle })
    }

    /// 断开当前客户端，之后可再次 [`Self::accept`]。
    pub fn disconnect(&self) -> Result<(), PipeError> {
        unsafe { DisconnectNamedPipe(self.handle).map_err(|_| PipeError::Disconnected) }
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// 客户端：连到服务端的管道。
#[derive(Debug)]
pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    pub fn connect() -> Result<Self, PipeError> {
        Self::connect_named(PIPE_NAME)
    }

    pub fn connect_named(name: &str) -> Result<Self, PipeError> {
        let wide = to_wide(name);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
            .map_err(|e| PipeError::ConnectFailed(e.to_string()))?
        };
        Ok(Self { handle })
    }

    pub fn end(&self) -> PipeEnd {
        PipeEnd { handle: self.handle }
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// 管道的一端（服务端接受的、或客户端连上的）。
///
/// ⚠ **不拥有句柄**：生命周期由 [`PipeServer`] / [`PipeClient`] 管。
/// 这样 `accept()` 可以反复调用而不必把句柄所有权搬来搬去。
#[derive(Debug, Clone, Copy)]
pub struct PipeEnd {
    handle: HANDLE,
}

impl PipeEnd {
    /// 发一帧。
    pub fn send(&self, msg_type: u8, flags: u8, seq: u32, payload: &[u8]) -> Result<(), PipeError> {
        let bytes = encode(msg_type, flags, seq, payload)?;
        self.send_raw(&bytes)
    }

    /// 直接发一段**已编码好**的帧字节（`encode` / `encode_handshake` 的产物）。
    pub fn send_raw(&self, bytes: &[u8]) -> Result<(), PipeError> {
        let mut written = 0u32;
        unsafe {
            WriteFile(self.handle, Some(bytes), Some(&mut written), None)
                .map_err(|e| classify(&e, PipeError::WriteFailed(e.to_string())))?
        };
        if written as usize != bytes.len() {
            return Err(PipeError::WriteFailed(format!(
                "短写：应写 {} 字节，实际 {} 字节",
                bytes.len(),
                written
            )));
        }
        // 立刻推给对端：控制指令不该在缓冲区里攒着
        let _ = unsafe { FlushFileBuffers(self.handle) };
        Ok(())
    }

    /// 收一帧。数据不够就继续读；对端断开返回 [`PipeError::Disconnected`]。
    pub fn recv(&self, reader: &mut FrameReader) -> Result<OwnedFrame, PipeError> {
        loop {
            if let Some(frame) = reader.pop() {
                return frame.map_err(PipeError::Frame);
            }
            let mut buf = [0u8; READ_CHUNK];
            let mut got = 0u32;
            unsafe {
                ReadFile(self.handle, Some(&mut buf), Some(&mut got), None)
                    .map_err(|e| classify(&e, PipeError::ReadFailed(e.to_string())))?
            };
            if got == 0 {
                return Err(PipeError::Disconnected);
            }
            reader.feed(&buf[..got as usize])?;
        }
    }

    /// 收一帧，但对端断开时不视为错误（返回 `None`）。
    /// 长连接主循环用这个：正常退出和协议错误要区分开。
    pub fn try_recv(&self, reader: &mut FrameReader) -> Result<Option<OwnedFrame>, PipeError> {
        match self.recv(reader) {
            Ok(f) => Ok(Some(f)),
            Err(PipeError::Disconnected) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg_type;

    /// 测试用独立管道名：避免与真实服务或其它测试抢 `FIRST_PIPE_INSTANCE`。
    fn test_name(tag: &str) -> String {
        format!(r"\\.\pipe\aegis-test-{tag}-{}", std::process::id())
    }

    #[test]
    fn bind_connect_and_exchange_frames() {
        let name = test_name("basic");
        let server = PipeServer::bind_named(&name).expect("建管道应成功");

        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let c = PipeClient::connect_named(&client_name).expect("连接应成功");
            let end = c.end();
            end.send(msg_type::PING, 0, 7, b"hi").expect("发送应成功");
            let mut r = FrameReader::new();
            end.recv(&mut r).expect("应收响应")
        });

        let end = server.accept().expect("accept 应成功");
        let mut reader = FrameReader::new();
        let got = end.recv(&mut reader).expect("应收请求");
        assert_eq!(got.msg_type, msg_type::PING);
        assert_eq!(got.seq, 7);
        assert_eq!(got.payload, b"hi");

        end.send(msg_type::PONG, 0, 7, b"ok").expect("回响应应成功");
        let resp = client.join().expect("客户端线程不应 panic");
        assert_eq!(resp.msg_type, msg_type::PONG);
        assert_eq!(resp.seq, 7);
        assert_eq!(resp.payload, b"ok");
    }

    /// 一次写入两帧、对端分两次取：验证字节流模式下帧边界由 FrameReader
    /// 负责，而不是靠"一次 write = 一次 read"这种假设。
    #[test]
    fn two_frames_in_one_write_are_read_back_separately() {
        let name = test_name("coalesce");
        let server = PipeServer::bind_named(&name).expect("建管道应成功");

        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let c = PipeClient::connect_named(&client_name).expect("连接应成功");
            let end = c.end();
            let a = crate::encode(msg_type::REQUEST, 0, 1, b"first").unwrap();
            let b = crate::encode(msg_type::EVENT, 0, 2, b"second").unwrap();
            let mut joined = a;
            joined.extend_from_slice(&b);
            // 粘在一起一次写出
            let mut written = 0u32;
            unsafe {
                WriteFile(end.handle, Some(&joined), Some(&mut written), None).unwrap();
            }
            let _ = unsafe { FlushFileBuffers(end.handle) };
        });

        let end = server.accept().expect("accept 应成功");
        let mut reader = FrameReader::new();
        let f1 = end.recv(&mut reader).unwrap();
        let f2 = end.recv(&mut reader).unwrap();
        assert_eq!(f1.payload, b"first");
        assert_eq!(f2.payload, b"second");
        assert_eq!(f2.msg_type, msg_type::EVENT);
        client.join().unwrap();
    }

    /// 对端关闭后 recv 必须给出 `Disconnected`，而不是卡死或返回垃圾帧。
    #[test]
    fn recv_after_peer_closes_reports_disconnected() {
        let name = test_name("close");
        let server = PipeServer::bind_named(&name).expect("建管道应成功");

        let client_name = name.clone();
        std::thread::spawn(move || {
            let c = PipeClient::connect_named(&client_name).expect("连接应成功");
            // 立刻离开作用域 → CloseHandle
            drop(c);
        });

        let end = server.accept().expect("accept 应成功");
        let mut reader = FrameReader::new();
        assert_eq!(end.recv(&mut reader), Err(PipeError::Disconnected));
        assert_eq!(end.try_recv(&mut reader), Ok(None), "try_recv 应把断开当正常退出");
    }

    /// 纯函数层：不需要真管道就能验证"什么算断开"。
    /// 这几个判定是长连接主循环正确与否的分水岭，必须能独立测。
    fn err(code: u32) -> WinError {
        WinError::from_hresult(HRESULT::from_win32(code))
    }

    #[test]
    fn broken_pipe_and_not_connected_count_as_disconnect() {
        assert!(is_disconnect(&err(ERROR_BROKEN_PIPE.0)));
        assert!(is_disconnect(&err(ERROR_PIPE_NOT_CONNECTED.0)));
        // 反例：真正的故障不能被吞成"断开"
        assert!(!is_disconnect(&err(ERROR_NO_DATA.0)));
        assert!(!is_disconnect(&err(5))); // ERROR_ACCESS_DENIED
    }

    #[test]
    fn classify_downgrades_only_disconnect() {
        let got = classify(&err(ERROR_BROKEN_PIPE.0), PipeError::ReadFailed("x".into()));
        assert_eq!(got, PipeError::Disconnected);
        let kept = classify(&err(5), PipeError::ReadFailed("x".into()));
        assert_eq!(kept, PipeError::ReadFailed("x".into()));
    }

    #[test]
    fn accept_treats_pipe_connected_as_success_and_no_data_as_disconnect() {
        assert_eq!(accept_outcome(&err(ERROR_PIPE_CONNECTED.0)), Ok(()));
        assert_eq!(
            accept_outcome(&err(ERROR_NO_DATA.0)),
            Err(PipeError::Disconnected)
        );
        assert!(matches!(
            accept_outcome(&err(5)),
            Err(PipeError::AcceptFailed(_))
        ));
    }

    /// SDDL 写错必须**报错**，不能悄悄退化成"继承默认 DACL"——
    /// 那正是 GUI 连不上且看不出原因的失败模式。
    #[test]
    fn invalid_sddl_is_rejected_loudly() {
        let name = test_name("badsddl");
        // 直接走底层：用一个非法 SDDL 串，确认转换失败而不是静默通过
        let r = SecurityDescriptor::from_sddl("this is not sddl");
        assert!(matches!(r, Err(PipeError::BadSddl(_))), "非法 SDDL 应报错：{r:?}");
        let _ = name;
    }

    /// 建两次同名管道必须失败（FIRST_PIPE_INSTANCE）。
    /// 少了这个标志，任何进程都能抢先建同名管道冒充服务，而 GUI 不提权、
    /// 无法区分真假。
    #[test]
    fn second_bind_of_the_same_name_is_refused() {
        let name = test_name("squat");
        let _first = PipeServer::bind_named(&name).expect("第一个应成功");
        let second = PipeServer::bind_named(&name);
        assert!(
            matches!(second, Err(PipeError::CreateFailed(_))),
            "同名第二个实例应被拒：{second:?}"
        );
    }
}
