//! 极小 HTTP/1.1 客户端 —— **只**够跟本机 mihomo 控制口说话。
//!
//! # 为什么不用 reqwest（这是个有意识的取舍）
//!
//! design-spec §5 当初写的是 reqwest + tokio-tungstenize。实测之后改了：
//!
//! 1. **控制口只在 `127.0.0.1`，而且是明文 http。** `allow-lan: false`
//!    意味着它根本不该被网络访问，也就没有 TLS 的需求。
//! 2. reqwest 会拖进 tokio + hyper + TLS 栈（几十个 crate），换来的能力
//!    （重定向池、HTTP/2、TLS、中间件）**一个都用不上**——我们要的就是
//!    "GET 一个 JSON"。
//! 3. 本 crate 的其余部分全是同步代码。引入异步运行时会顺着
//!    `Send`/`Future` 把整个 SPI 拖进异步，而 SPI 本身没有异步的必要。
//!
//! 代价说清楚：**这个客户端只支持明文 HTTP/1.1，不支持 HTTPS**。
//! 哪天控制口要暴露到网络上，正确做法是换库，不是给这里加 TLS。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// 控制口响应的最大字节数。**必须有上限**。
///
/// mihomo 的 `/connections` 在连接多时能到几十 MB（每条连接带完整 metadata）。
/// 一个 GET 就能把守护进程的记忆吃干净——而这个调用发生在轮询路径上。
/// 超限就当失败，让调用方看到"读不到"，而不是"读到一半"。
const MAX_BODY: usize = 8 * 1024 * 1024;

/// 单次请求的总超时（连接 + 读 + 写）。
///
/// ⚠ **必须显著小于守卫观测周期（3s）**。这个调用发生在守卫线程里：
///   超时设成 5s 的话，一次控制口卡住就把观测周期从 3s 撑到 5s+，
///   泄漏窗口（`threshold × 周期`）跟着变长——**为了看清状态而放宽了防线**。
///   控制口在 localhost，正常响应是毫秒级，1s 足够分辨"慢"与"挂"。
const TIMEOUT: Duration = Duration::from_secs(1);

/// HTTP 方法。我们只需要这三种。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Put,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

/// 一次请求失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("控制口地址无法解析：{0}")]
    Resolve(String),
    #[error("连不上控制口 {addr}：{source}（它开着吗？external-controller 配了吗？）")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("控制口超时（{TIMEOUT:?}）：{0}")]
    Timeout(String),
    #[error("IO 失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("响应不是合法 HTTP：{0}")]
    BadResponse(String),
    #[error("控制口返回 {status}：{body}")]
    Status { status: u16, body: String },
    #[error("响应体过大（>{MAX_BODY} 字节），拒绝读入")]
    TooLarge,
}

/// 一次成功请求的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    /// mihomo 约定：204 或 2xx 都算成功，且成功时 body 常常是空的。
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 拆出 `127.0.0.1:9097` 里的主机与端口。
///
/// ⚠ 刻意**不**接受 `https://` 与路径：控制口就是 `host:port`，
///   写错形式时立刻报错比"悄悄改成别的协议"安全。
pub fn split_addr(addr: &str) -> Result<(&str, u16), HttpError> {
    let a = addr.trim();
    if a.contains("://") {
        return Err(HttpError::Resolve(format!(
            "{a}? 控制口只接受 host:port，不接受带协议的 URL"
        )));
    }
    let (host, port) = a
        .rsplit_once(':')
        .ok_or_else(|| HttpError::Resolve(format!("{a} 缺少端口（应形如 127.0.0.1:9097）")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| HttpError::Resolve(format!("端口 {port:?} 不是合法 u16")))?;
    if host.is_empty() {
        return Err(HttpError::Resolve("主机名为空".into()));
    }
    Ok((host, port))
}

/// 发一次请求。`body` 为 `None` 时不发 `Content-Length`。
///
/// ⚠ **不做重试**：所有调用都在轮询路径上，重试会把"控制口挂了"
///   放大成 N 倍的连接风暴。失败就如实返回，让上层决定要不要退避。
pub fn request(
    addr: &str,
    method: Method,
    path: &str,
    secret: Option<&str>,
    body: Option<&str>,
) -> Result<Response, HttpError> {
    let (host, port) = split_addr(addr)?;
    let connect_addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| HttpError::Resolve(format!("{host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| HttpError::Resolve(format!("{host}:{port} 没有解析到地址")))?;

    let mut stream = TcpStream::connect_timeout(&connect_addr, TIMEOUT).map_err(|source| {
        HttpError::Connect {
            addr: format!("{host}:{port}"),
            source,
        }
    })?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(HttpError::Io)?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(HttpError::Io)?;
    // 控制口在 localhost，关掉 Nagle：请求都很小，攒着等反而更慢。
    let _ = stream.set_nodelay(true);

    // ── 拼请求 ────────────────────────────────────────────────────────
    let body_bytes = body.unwrap_or("");
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
        method.as_str(),
        path,
        host,
        port
    );
    if let Some(s) = secret.filter(|s| !s.is_empty()) {
        // mihomo 的鉴权头就是这个；空 secret 时不带头（带空 Bearer 反而会被拒）
        req.push_str(&format!("Authorization: Bearer {s}\r\n"));
    }
    if let Some(b) = body {
        if !b.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
    }
    req.push_str("\r\n");
    req.push_str(body_bytes);

    stream.write_all(req.as_bytes()).map_err(HttpError::Io)?;
    stream.flush().map_err(HttpError::Io)?;

    // ── 读响应 ────────────────────────────────────────────────────────
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(HttpError::Io)?;
    // "HTTP/1.1 200 OK" → 状态码是第 2 段
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpError::BadResponse(format!("没有状态码：{line:?}")))?;

    let mut chunked = false;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).map_err(HttpError::Io)?;
        if n == 0 || header.trim().is_empty() {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }

    let body = if chunked {
        read_chunked(&mut reader)?
    } else {
        read_to_end(&mut reader)?
    };

    let resp = Response { status, body };
    if resp.is_success() {
        Ok(resp)
    } else {
        Err(HttpError::Status {
            status: resp.status,
            // 错误体可能很长，但截断后仍然有用（mihomo 的错误是 JSON）
            body: truncate(&resp.body, 300),
        })
    }
}

fn read_to_end(reader: &mut impl Read) -> Result<String, HttpError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).map_err(HttpError::Io)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_BODY {
            return Err(HttpError::TooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf).map_err(|e| HttpError::BadResponse(format!("body 不是 UTF-8：{e}")))
}

/// chunked 传输解码。
///
/// mihomo 在 `/connections` 这种大响应上会用 chunked，而 `Connection: close`
/// 让我们拿不到 Content-Length——所以这两条路径都得实现。
fn read_chunked(reader: &mut impl BufRead) -> Result<String, HttpError> {
    let mut out = String::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).map_err(HttpError::Io)? == 0 {
            break;
        }
        // chunk 长度行后面可能带扩展（";ext"），取分号前那段
        let size_hex = size_line.trim().split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| HttpError::BadResponse(format!("chunk 长度不是十六进制：{size_hex:?}")))?;
        if size == 0 {
            break;
        }
        if out.len() + size > MAX_BODY {
            return Err(HttpError::TooLarge);
        }
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf).map_err(HttpError::Io)?;
        out.push_str(
            &String::from_utf8(buf)
                .map_err(|e| HttpError::BadResponse(format!("chunk 不是 UTF-8：{e}")))?,
        );
        // chunk 之后有一行 CRLF，必须吃掉，否则下次的 size 行会读错
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf);
    }
    Ok(out)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let cut: String = s.chars().take(n).collect();
    format!("{cut}…（已截断）")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_accepts_host_port() {
        assert_eq!(split_addr("127.0.0.1:9097").unwrap(), ("127.0.0.1", 9097));
        assert_eq!(split_addr(" localhost:80 ").unwrap(), ("localhost", 80));
    }

    // 静默改成 https 会让人以为"配了 TLS 更安全"，而控制口根本不该暴露到网络
    #[test]
    fn addr_rejects_url_form() {
        let e = split_addr("http://127.0.0.1:9097").unwrap_err().to_string();
        assert!(e.contains("不接受带协议的 URL"), "{e}");
        assert!(split_addr("127.0.0.1").is_err());
        assert!(split_addr("127.0.0.1:notaport").is_err());
    }

    #[test]
    fn success_is_2xx() {
        assert!(Response {
            status: 204,
            body: String::new()
        }
        .is_success());
        assert!(Response {
            status: 200,
            body: String::new()
        }
        .is_success());
        assert!(!Response {
            status: 401,
            body: String::new()
        }
        .is_success());
        assert!(!Response {
            status: 404,
            body: String::new()
        }
        .is_success());
    }

    #[test]
    fn body_limit_is_enforced() {
        // 用一个会"无限"吐 8KB 块、直到累计超过 MAX_BODY 的假 reader，
        // 验证 read_to_end 在超限时返回 TooLarge（而不是读到一半或吃光内存）。
        struct Endless {
            chunk: Vec<u8>,
        }
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&self.chunk[..n]);
                Ok(n)
            }
        }
        let mut r = Endless {
            chunk: vec![b'x'; 8192],
        };
        match read_to_end(&mut r) {
            Err(HttpError::TooLarge) => {},
            other => panic!("预期 TooLarge，实际 {other:?}"),
        }
    }

    #[test]
    fn truncate_marks_that_it_cut() {
        assert_eq!(truncate("abc", 10), "abc");
        assert!(truncate("abcdef", 3).starts_with("abc…"));
    }
}
