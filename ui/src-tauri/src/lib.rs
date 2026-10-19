//! Aegis 控制台 —— **Tauri 外壳的 Rust 侧**。
//!
//! # ⚠ 这个进程不提权，也不做任何特权动作
//!
//! 它的全部职责是把界面的请求翻译成命名管道上的 IPC 调用。所有特权动作
//! 都在 `aegisd`（SYSTEM）里，界面的窗口从头到尾拿不到 token、连不到管道。
//!
//! # ⚠ 这里只暴露**只读**命令（`status` / `ping`），这是权限模型决定的
//!
//! `aegis_ipc::peer::Risk::Dangerous`（`apply` / `confirm` / `rollback`）
//! 要求**对端进程已提权**，而 GUI 按设计**不提权**。所以危险命令从界面里
//! 根本发不出去——不是"还没接线"，是这个模型下不应该接。
//! 界面该做的是告诉人"这一步要用管理员身份的 `aegisctl` 跑"，而不是
//! 画一个点了没反应的按钮。

use std::path::{Path, PathBuf};

use aegis_ipc::{ClientError, IpcToken};
use serde::Serialize;

/// 环境变量：管道名（默认 [`aegis_ipc::PIPE_NAME`]）。
pub const ENV_PIPE: &str = "AEGIS_PIPE";
/// 环境变量：token 文件路径。
pub const ENV_TOKEN_FILE: &str = "AEGIS_TOKEN_FILE";
/// 环境变量：token 文件的默认父目录（默认 `%PROGRAMDATA%`）。
pub const ENV_PROGRAMDATA: &str = "PROGRAMDATA";

/// token 文件在默认目录下的相对位置。
const TOKEN_REL: &str = "Aegis/ipc.token";
/// `PROGRAMDATA` 都拿不到时的最后退路。**不静默失败**：宁可指向一个
/// 一定存在但多半读不到 token 的路径，让人在界面上看到"读不到 token"
/// 并附完整路径，也不要让路径变成空串。
const PROGRAMDATA_FALLBACK: &str = r"C:\ProgramData";

/// 守护进程 IPC 端点的位置。
///
/// ⚠ **刻意不做成全局常量**：守护进程允许用 `--pipe` / `--data-dir` 改到
/// 别处（多实例、排障都会用）。硬编一个路径会让"服务在那边、界面连这边"
/// 这种问题完全没有排查入口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// 命名管道完整路径（已归一）。
    pub pipe: String,
    /// token 文件路径。
    pub token_file: PathBuf,
}

impl Endpoint {
    /// 从真实进程环境读。
    pub fn from_env() -> Self {
        Self::resolve(|k| std::env::var(k).ok())
    }

    /// 从一个"取环境变量"的函数读 —— 抽出来是为了能测，
    /// 否则每条路径都得真的去改进程环境（还会互相干扰）。
    pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Self {
        let pipe = match get(ENV_PIPE) {
            Some(p) if !p.trim().is_empty() => aegis_ipc::normalize_pipe_name(p.trim()),
            // 裸名/空串一律走归一：Git Bash 会吃掉一个反斜杠，
            // "让用户自己写对"这条路走不通，只能在程序里补。
            _ => aegis_ipc::PIPE_NAME.to_string(),
        };
        let token_file = match get(ENV_TOKEN_FILE) {
            Some(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
            _ => {
                let base = get(ENV_PROGRAMDATA)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| PROGRAMDATA_FALLBACK.to_string());
                PathBuf::from(base.trim()).join(TOKEN_REL)
            },
        };
        Self { pipe, token_file }
    }
}

/// 读 token 失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenReadError {
    /// 文件不存在或读不了。**最常见的真因是守护进程没在跑**——token 是它
    /// 启动时写的，它没起来就没有这个文件。
    Unreadable { path: String, detail: String },
    /// 读到了但内容不是合法的 token hex。
    Malformed { path: String },
}

impl std::fmt::Display for TokenReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, detail } => {
                write!(f, "读不到 IPC token（{path}）：{detail}")
            },
            Self::Malformed { path } => {
                write!(f, "IPC token 文件内容不是合法的 hex（{path}）")
            },
        }
    }
}

impl std::error::Error for TokenReadError {}

/// 读 token 文件。
///
/// ⚠ **每次请求都重读，不缓存**：守护进程每次启动都会换 token
/// （落盘用 `CREATE_ALWAYS`，旧的必须失效）。缓存的话，服务重启之后界面
/// 会一直拿旧 token 去连，失败原因是"鉴权失败"，而人看到的是
/// "服务明明在跑却连不上"——排障方向会被带偏。重读没有失效窗口。
pub fn load_token(path: &Path) -> Result<IpcToken, TokenReadError> {
    let text = std::fs::read_to_string(path).map_err(|e| TokenReadError::Unreadable {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    // 文件末尾可能有换行，`to_string()` 不会替我们去掉
    IpcToken::from_hex(text.trim()).ok_or_else(|| TokenReadError::Malformed {
        path: path.display().to_string(),
    })
}

/// 把 `ClientError` 翻成**能让人接着查下去**的话。
///
/// ⚠ 为什么不用 `Display` 直接抛给界面：`ClientError` 的文案是站在
/// 库的角度写的（"连接管道失败"），界面上光看这句不知道该去哪查。
/// 至少要把**管道名**和**下一步**带上。
fn explain(e: &ClientError, ep: &Endpoint) -> String {
    match e {
        ClientError::Connect(_) => format!(
            "连不上守护进程（管道 {}）。服务可能没在跑，\n\
             也可能它用了别的 --pipe / --data-dir（可用 {} 与 {} 指过来）。\n\
             原始错误：{e}",
            ep.pipe, ENV_PIPE, ENV_TOKEN_FILE
        ),
        ClientError::AuthDenied(msg) => format!(
            "守护进程拒绝了 token：{msg}\n\
             token 文件：{}\n\
             服务重启会换 token；若这台机器上跑着多个实例，可能是读错了那个。",
            ep.token_file.display()
        ),
        ClientError::NoAuthReply(_) => format!(
            "没收到鉴权应答（{e}）。\n\
             服务端对鉴权失败是**立刻断开且不回响应**，所以第一嫌疑是 token 不对。\n\
             token 文件：{}",
            ep.token_file.display()
        ),
        ClientError::Incompatible { peer, reason } => format!(
            "版本谈不拢：对端 {peer}，原因 {reason:?}。\n\
             外壳与守护进程的版本号必须兼容。"
        ),
        _ => format!("IPC 失败（管道 {}）：{e}", ep.pipe),
    }
}

/// 一次"取状态"的完整流程：读 token → 连 → 握手 → 鉴权 → 请求 → 解析。
///
/// 返回 `Status` 的 JSON，字段与 `aegis_ipc::Status` **同源**（派生序列化），
/// 界面那边不手写映射。
pub fn fetch_status(ep: &Endpoint) -> Result<serde_json::Value, String> {
    let token = load_token(&ep.token_file).map_err(|e| e.to_string())?;
    let body =
        aegis_ipc::talk(&ep.pipe, &token, aegis_ipc::REQ_STATUS).map_err(|e| explain(&e, ep))?;
    let status =
        aegis_ipc::Status::from_text(&body).map_err(|e| format!("状态文档解析失败：{e}"))?;
    serde_json::to_value(status).map_err(|e| format!("状态序列化失败：{e}"))
}

/// 心跳：只验链路与鉴权是否还活着。
pub fn fetch_ping(ep: &Endpoint) -> Result<String, String> {
    let token = load_token(&ep.token_file).map_err(|e| e.to_string())?;
    aegis_ipc::talk(&ep.pipe, &token, aegis_ipc::REQ_PING).map_err(|e| explain(&e, ep))
}

/// 端点信息，给界面"关于/设置"页显示——排障时最想知道的就是"它在连哪儿"。
#[derive(Debug, Clone, Serialize)]
pub struct EndpointInfo {
    pub pipe: String,
    pub token_file: String,
    /// token 文件有没有读到。读不到时界面要给出可操作的提示，
    /// 而不是只显示一个路径让人自己猜。
    pub token_file_present: bool,
}

impl EndpointInfo {
    pub fn of(ep: &Endpoint) -> Self {
        Self {
            pipe: ep.pipe.clone(),
            token_file: ep.token_file.display().to_string(),
            token_file_present: ep.token_file.exists(),
        }
    }
}

// ── Tauri 命令 ────────────────────────────────────────────────────────────
// 只有三个，全是只读。危险命令不在这里，理由见文件头。

#[tauri::command]
fn status(endpoint: tauri::State<'_, Endpoint>) -> Result<serde_json::Value, String> {
    fetch_status(&endpoint)
}

#[tauri::command]
fn ping(endpoint: tauri::State<'_, Endpoint>) -> Result<String, String> {
    fetch_ping(&endpoint)
}

#[tauri::command]
fn endpoint_info(endpoint: tauri::State<'_, Endpoint>) -> EndpointInfo {
    EndpointInfo::of(&endpoint)
}

/// 启动外壳。
pub fn run() {
    tauri::Builder::default()
        // 端点在启动时解析一次；token 本身仍每次请求重读（见 `load_token`）
        .manage(Endpoint::from_env())
        .invoke_handler(tauri::generate_handler![status, ping, endpoint_info])
        .run(tauri::generate_context!())
        .expect("启动 Aegis 控制台外壳失败");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ipc::PipeError;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(a, _)| *a == k)
                .map(|(_, b)| b.to_string())
        }
    }

    #[test]
    fn with_nothing_set_it_falls_back_to_the_daemon_defaults() {
        let ep = Endpoint::resolve(env(&[]));
        assert_eq!(ep.pipe, aegis_ipc::PIPE_NAME);
        assert!(ep.token_file.ends_with("Aegis/ipc.token"));
    }

    /// `PROGRAMDATA` 拿不到时也不能让路径变空串——界面上会显示成一个
    /// 什么都没有的"读不到 token"，人根本无从下手。
    #[test]
    fn a_missing_programdata_still_yields_a_usable_path() {
        let ep = Endpoint::resolve(env(&[]));
        assert!(!ep.token_file.as_os_str().is_empty());
        assert!(ep.token_file.is_absolute(), "{:?}", ep.token_file);
    }

    #[test]
    fn explicit_env_overrides_both() {
        let ep = Endpoint::resolve(env(&[
            (ENV_PIPE, "aegis-ob"),
            (ENV_TOKEN_FILE, r"D:\run\ipc.token"),
        ]));
        assert_eq!(ep.pipe, r"\\.\pipe\aegis-ob");
        assert_eq!(ep.token_file, PathBuf::from(r"D:\run\ipc.token"));
    }

    /// 裸名必须被补成完整 Win32 路径：`--pipe aegis-ob` 原样交给
    /// CreateNamedPipeW 会报 os error 123，而提示语会指向"端口被占用"。
    #[test]
    fn a_bare_pipe_name_is_normalized() {
        let ep = Endpoint::resolve(env(&[(ENV_PIPE, "aegis-ob")]));
        assert_eq!(ep.pipe, aegis_ipc::normalize_pipe_name("aegis-ob"));
    }

    #[test]
    fn blank_values_are_treated_as_unset() {
        let ep = Endpoint::resolve(env(&[(ENV_PIPE, "   "), (ENV_TOKEN_FILE, "")]));
        assert_eq!(ep.pipe, aegis_ipc::PIPE_NAME);
        assert!(ep.token_file.ends_with("Aegis/ipc.token"));
    }

    #[test]
    fn a_token_file_with_a_trailing_newline_still_parses() {
        let dir = std::env::temp_dir().join(format!("aegis-console-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ipc.token");
        let t = IpcToken::generate().unwrap();
        std::fs::write(&p, format!("{}\n", t.to_hex())).unwrap();

        assert_eq!(load_token(&p).unwrap().to_hex(), t.to_hex());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_token_file_is_reported_with_its_path() {
        let p = std::env::temp_dir()
            .join(format!("aegis-none-{}-{}", std::process::id(), line!()))
            .join("ipc.token");
        let e = load_token(&p).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains(&p.display().to_string()), "{msg}");
        assert!(msg.contains("读不到"), "{msg}");
    }

    #[test]
    fn garbage_content_is_called_malformed_not_unreadable() {
        let dir = std::env::temp_dir().join(format!("aegis-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ipc.token");
        std::fs::write(&p, "not-hex-at-all").unwrap();

        assert!(matches!(
            load_token(&p),
            Err(TokenReadError::Malformed { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 端点信息里的 `token_file_present` 必须真的去查文件系统——
    /// 它决定界面上给的是"服务没在跑"还是"换个路径"。
    #[test]
    fn endpoint_info_reports_whether_the_token_file_is_there() {
        let dir = std::env::temp_dir().join(format!("aegis-ei-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ipc.token");
        std::fs::write(&p, "x").unwrap();

        let ep = Endpoint {
            pipe: aegis_ipc::PIPE_NAME.to_string(),
            token_file: p.clone(),
        };
        assert!(EndpointInfo::of(&ep).token_file_present);

        let gone = Endpoint {
            pipe: ep.pipe.clone(),
            token_file: dir.join("nope.token"),
        };
        assert!(!EndpointInfo::of(&gone).token_file_present);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 连不上时给的话必须带上管道名——否则界面上只有"连接失败"四个字，
    /// 人不知道该去看服务、还是去看管道名写错了。
    #[test]
    fn a_connect_failure_names_the_pipe() {
        let ep = Endpoint {
            pipe: r"\\.\pipe\aegis".to_string(),
            token_file: PathBuf::from("t"),
        };
        let msg = explain(
            &ClientError::Connect(PipeError::ConnectFailed("模拟失败".into())),
            &ep,
        );
        assert!(msg.contains(r"\\.\pipe\aegis"), "{msg}");
        assert!(msg.contains(ENV_PIPE), "{msg}");
    }

    /// 鉴权失败的提示必须指向 token 文件，否则排障会一路查错方向。
    #[test]
    fn an_auth_failure_points_at_the_token_file() {
        let ep = Endpoint {
            pipe: aegis_ipc::PIPE_NAME.to_string(),
            token_file: PathBuf::from(r"D:\run\ipc.token"),
        };
        let msg = explain(&ClientError::AuthDenied("x".into()), &ep);
        assert!(msg.contains(r"D:\run\ipc.token"), "{msg}");
    }
}
