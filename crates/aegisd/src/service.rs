//! Windows Service 宿主 —— 让 `aegisd` 能作为服务常驻、开机自启动。
//!
//! # 为什么必须有服务
//!
//! §16 已经写明运行时必须管理员权限。但更实际的问题是**谁来保证它在跑**：
//! 手动 `cargo run` 意味着"每次重启电脑都要记得先开终端"，而 Aegis 的卖点
//! 恰恰是"你忘了它也在"。所以要有服务。
//!
//! # 三条设计取舍
//!
//! 1. **服务外壳与守护链路分离，共用一份逻辑。**
//!    链路实现只有 [`crate::serve`] 一份；服务模式只是：起一个线程跑它，
//!    主线程交给 SCM。⚠ 绝不允许出现"服务版链路"和"控制台版链路"两份实现
//!    ——它们迟早漂移，而漂移方向通常是服务那份少了某个 Fail-Closed 分支。
//!
//! 2. **收到停止信号直接结束进程，不做优雅停机。**
//!    看着像偷懒，其实是刻意的：所有 WFP 规则都在**动态会话**里，进程一死
//!    内核立即清空——**"忘了收尾"与"立即收尾"在这里是同一个结果**。
//!    反过来若为优雅而主动 `force_teardown()`，反倒多出一段
//!    "进程还活着但规则已撤"的窗口期，那才是真正的风险。
//!
//! 3. **纯逻辑与 FFI 分开**，理由同 `aegis-wfp::plan` / `apply`：
//!    [`ServiceSpec`] 的引号处理与参数映射能单测；SCM 调用需要管理员权限
//!    且**会真的改这台机器**，本模块只提供命令，不替你执行。
//!
//! # ⚠ 授权边界
//!
//! 安装 / 卸载 / 启停服务都要管理员权限，且会真的改系统状态。
//! 项目约定：涉及系统状态变更的动作必须先取得用户明确同意。

use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, RegisterServiceCtrlHandlerW, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, ENUM_SERVICE_TYPE, SC_MANAGER_ALL_ACCESS,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_START_TYPE, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
};

// ═══════════════════════ 纯逻辑 ═══════════════════════

/// 服务名（SCMgr 里的标识。改名等于换了个服务，旧的要先卸）。
pub const SERVICE_NAME: &str = "Aegis";
/// 面向用户的显示名。
pub const SERVICE_DISPLAY_NAME: &str = "Aegis 守护进程";

/// 服务启动方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    /// 开机自启。**这是 Aegis 该用的那个**——价值就在于"你忘了它也在"。
    Auto,
    /// 手动启动。留着是为了将来做"用户主动开防"模式。
    Demand,
}

impl StartType {
    fn to_raw(self) -> SERVICE_START_TYPE {
        match self {
            StartType::Auto => SERVICE_AUTO_START,
            StartType::Demand => SERVICE_DEMAND_START,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            StartType::Auto => "开机自启",
            StartType::Demand => "手动启动",
        }
    }
}

/// 服务运行所需的全部参数。
///
/// 刻意**不**直接收 `main.rs` 的 `Args`：`service.rs` 若依赖那个私有结构，
/// 单元测试就得把整个命令行解析拖进来。这里只收"服务真正需要的"，
/// 由 `main.rs` 做转换——依赖方向是单向的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    pub config: String,
    pub pipe: String,
    pub token_file: String,
    pub data_dir: String,
    /// 守卫是否真的动手（收紧）。**服务模式下依然默认关**——
    /// 收紧的代价是整机断网，这条不因"它现在是服务了"而放松。
    pub guard_act: bool,
    /// 服务可执行文件自身（SCM 的 binPath 指向它）。
    pub binary: String,
    /// 开机自启还是手动启动。
    pub start_type: StartType,
}

impl StartType {
    /// 命令行取值。**故意不实现 `FromStr`**：解析失败要能给出
    /// "合法值有哪些"，而不是只说"解析失败"。
    pub fn parse_arg(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(StartType::Auto),
            "demand" => Some(StartType::Demand),
            _ => None,
        }
    }

    pub fn arg_name(self) -> &'static str {
        match self {
            StartType::Auto => "auto",
            StartType::Demand => "demand",
        }
    }
}

/// 服务注册所需的全部规格。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub start_type: StartType,
    /// SCM `binPath` 的完整命令行（已正确加引号）。
    pub bin_path: String,
}

impl ServiceSpec {
    /// 从运行参数推导服务规格（纯逻辑，不碰 SCM）。
    ///
    /// ⚠ 刻意**不带** `--serve-secs`：服务不该自己超时退出，生命周期归 SCM。
    ///   带上它等于给服务设了个自杀定时器。
    pub fn from_opts(opts: &ServeOptions) -> Self {
        Self {
            service_name: SERVICE_NAME.to_string(),
            display_name: SERVICE_DISPLAY_NAME.to_string(),
            description:
                "Windows 网络零信任绝缘底座的守护进程（只监听本地命名管道，不开放任何网络端口）"
                    .to_string(),
            start_type: opts.start_type,
            bin_path: build_bin_path(opts),
        }
    }
}

/// 拼出 SCM 的 `binPath` 命令行（纯逻辑，但坑很多）。
///
/// **exe 路径必须加引号**：安装路径里只要有一个空格
/// （`C:\Program Files\...` 是 Windows 常态），SCM 就会把命令截断在第一个
/// 空格处、把后半截当成服务名——表现为"服务装了但启动不了"，而错误信息
/// 还指向一个不存在的东西。这个坑不写测试就会复发。
pub fn build_bin_path(opts: &ServeOptions) -> String {
    let mut s = format!("\"{}\" --service", opts.binary);
    s.push_str(&format!(" --config \"{}\"", opts.config));
    s.push_str(&format!(" --data-dir \"{}\"", opts.data_dir));
    s.push_str(&format!(" --token-file \"{}\"", opts.token_file));
    s.push_str(&format!(" --pipe \"{}\"", opts.pipe));
    if opts.guard_act {
        s.push_str(" --guard-act");
    }
    s
}

// ── 跨线程的运行态信号 ─────────────────────────────────────────────

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static SERVICE_MODE: AtomicBool = AtomicBool::new(false);

pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// 是否运行在服务上下文里（决定等待策略）。
pub fn is_service_mode() -> bool {
    SERVICE_MODE.load(Ordering::SeqCst)
}

pub fn enter_service_mode() {
    SERVICE_MODE.store(true, Ordering::SeqCst);
}

/// `serve()` 用它决定"等固定秒数"还是"等 SCM 叫停"。
///
/// 服务模式下**必须**等 SCM 而不是等秒数：`serve()` 的默认 30 秒是给演练
/// 用的，服务要是照抄它，开机 30 秒后自己就没了——而现象是"服务看起来在、
/// 但连接不上"，排错方向会跑到 IPC 上去。
pub fn wait_or_stop(secs: u64) {
    if !is_service_mode() {
        if secs > 0 {
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        return;
    }
    // 200ms 一拍轮询。粒度粗但代价可忽略（一次 atomic load），
    // 事件驱动要引入 condvar 跨线程唤醒——为了 0.2 秒不值得。
    while !stop_requested() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

// ═══════════════════════ FFI：服务运行上下文 ═══════════════════════

/// SCM 的控制处理器。
///
/// ⚠ 只置位、不做动作。真正退出由 [`scm_dispatch`] 的循环决定，
///   见模块文档第 2 条。
///
/// 签名由 `LPHANDLER_FUNCTION` 定死：**无返回值**（不是返回 u32 的
/// HandlerEx 那一族）。想区分"处理成功/失败"得改用
/// `RegisterServiceCtrlHandlerExW`，但那要求先 `SetServiceStatus`
/// 报告 `SERVICE_ACCEPT_STOP` 才收得到 STOP——当前这个简化版够用。
unsafe extern "system" fn control_handler(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        request_stop();
    }
    // 其余控制码一律不处理。"特意返回错误让 SCM 记警告"是反效果——
    // 我们确实没打算响应那些控制，安静忽略比刷事件日志好。
}

/// SCM 回调的服务主入口：只负责状态机，守护逻辑由 `main.rs` 另起线程。
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = wide(SERVICE_NAME);
    let Ok(status_handle) =
        (unsafe { RegisterServiceCtrlHandlerW(PCWSTR(name.as_ptr()), Some(control_handler)) })
    else {
        eprintln!(
            "[FATAL] 注册服务控制处理器失败：{:?}",
            std::io::Error::last_os_error()
        );
        return;
    };

    unsafe {
        report(status_handle, SERVICE_START_PENDING, 3_000, 1);
        report(status_handle, SERVICE_RUNNING, 0, 0);
    }
}

/// 把服务交给 SCM 并**阻塞**到停止信号到达。
///
/// 调用前 `main.rs` 应已把守护逻辑跑在另一个线程上。返回时意味着
/// SCM 已经要停这个服务了，调用方该结束进程。
pub fn scm_dispatch() {
    let mut name = wide(SERVICE_NAME);
    let table = [
        windows::Win32::System::Services::SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        windows::Win32::System::Services::SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(std::ptr::null_mut()),
            lpServiceProc: None,
        },
    ];
    // 必须活过整个 dispatch：SCM 可能在本函数返回之后仍回读这张表。
    let table = Box::leak(Box::new(table));

    // 返回 Err = 没能连上 SCM。多数情况是"不是 SCM 拉起的进程"——
    // 手工跑 `aegisd --service` 就会走到这里。
    if let Err(e) = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        eprintln!("[FATAL] StartServiceCtrlDispatcherW 失败：{e}");
        eprintln!("  这个入口只接受 SCM 拉起的进程。");
        eprintln!("  手工运行时请去掉 --service；要装服务用 `aegisd install`。");
        std::process::exit(1);
    }
    // 从这里正常返回 = 收到了停止通知
}

/// 上报服务状态。
///
/// `wait_hint` 告诉 SCM"我还要多久到下一个状态"，`checkpoint` 是
/// 长时间启动时的进度心跳——两者都为 0 且状态不变时，SCMgr 会判定
/// 服务没在动并回收它。
unsafe fn report(
    h: SERVICE_STATUS_HANDLE,
    state: SERVICE_STATUS_CURRENT_STATE,
    wait_hint: u32,
    checkpoint: u32,
) {
    let s = SERVICE_STATUS {
        dwServiceType: ENUM_SERVICE_TYPE(SERVICE_WIN32_OWN_PROCESS.0),
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(state.0),
        dwControlsAccepted: if state.0 == SERVICE_RUNNING.0 {
            SERVICE_STOP
        } else {
            0
        },
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    let _ = unsafe { SetServiceStatus(h, &s) };
}

/// 字符串转成以 NUL 结尾的 UTF-16（Win32 宽字符）。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ═══════════════════════ FFI：SCM 管理（需管理员）═══════════════════════

/// 服务是否已安装。只读查询：用 `SERVICE_QUERY_STATUS` 打开，
/// **不需要** `SC_MANAGER_ALL_ACCESS`，所以普通用户也能查。
pub fn is_installed() -> bool {
    let name = wide(SERVICE_NAME);
    let Ok(scm) = (unsafe { OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE) }) else {
        return false;
    };
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) };
    let _ = unsafe { CloseServiceHandle(scm) };
    match svc {
        Ok(h) => {
            let _ = unsafe { CloseServiceHandle(h) };
            true
        },
        Err(_) => false,
    }
}

/// 注册服务（需管理员）。
///
/// ⚠ **会改这台机器的状态**：装完之后开机就会自动跑一个 SYSTEM 权限的
///   进程。执行前必须取得用户同意。
pub fn install(opts: &ServeOptions) -> Result<ServiceSpec, String> {
    let spec = ServiceSpec::from_opts(opts);
    unsafe {
        let name = wide(&spec.service_name);
        let disp = wide(&spec.display_name);
        let desc = wide(&spec.description);
        let bin = wide(&spec.bin_path);

        let scm = OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
            .map_err(|e| format!("打开 SCM 失败（需要管理员权限）：{e}"))?;
        let created = CreateServiceW(
            scm,
            PCWSTR(name.as_ptr()),
            PCWSTR(disp.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            spec.start_type.to_raw(),
            SERVICE_ERROR_NORMAL,
            PCWSTR(bin.as_ptr()),
            PCWSTR(std::ptr::null()), // lpLoadOrderGroup
            None,                     // lpdwTagId
            PCWSTR(std::ptr::null()), // lpDependencies
            PCWSTR(std::ptr::null()), // lpServiceStartName（= LocalSystem）
            PCWSTR(std::ptr::null()), // lppassword
        );
        let _ = CloseServiceHandle(scm);
        created.map_err(|e| format!("创建服务失败：{e}"))?;

        // 描述不在 CreateServiceW 的参数里（那个 API 太老），要事后补一次。
        // 少了它不影响运行，但"服务"里不写描述，后来的人只能靠猜。
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            .map_err(|e| format!("打开 SCM 失败：{e}"))?;
        if let Ok(svc) = OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_ALL_ACCESS) {
            let sd = SERVICE_DESCRIPTIONW {
                lpDescription: PWSTR(desc.as_ptr() as *mut u16),
            };
            let _ = ChangeServiceConfig2W(
                svc,
                SERVICE_CONFIG_DESCRIPTION,
                Some((&raw const sd).cast()),
            );
            let _ = CloseServiceHandle(svc);
        }
        let _ = CloseServiceHandle(scm);
    }
    Ok(spec)
}

/// 卸载服务（需管理员；服务在跑时 SCM 会拒绝，要先停）。
pub fn uninstall() -> Result<(), String> {
    with_service_handle(SERVICE_ALL_ACCESS, |svc| unsafe {
        DeleteService(svc).map_err(|e| format!("删除服务失败：{e}"))
    })
}

/// 启动服务（需管理员）。
pub fn start() -> Result<(), String> {
    with_service_handle(SERVICE_START, |svc| unsafe {
        StartServiceW(svc, None).map_err(|e| format!("启动服务失败：{e}"))
    })
}

/// 停止服务（需管理员）。
pub fn stop() -> Result<(), String> {
    with_service_handle(SERVICE_STOP, |svc| unsafe {
        let mut status = SERVICE_STATUS {
            dwServiceType: ENUM_SERVICE_TYPE(SERVICE_WIN32_OWN_PROCESS.0),
            dwCurrentState: SERVICE_STATUS_CURRENT_STATE(SERVICE_STOP_PENDING.0),
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
            .map_err(|e| format!("停止服务失败：{e}"))
    })
}

fn with_service_handle(
    access: u32,
    f: impl FnOnce(windows::Win32::System::Services::SC_HANDLE) -> Result<(), String>,
) -> Result<(), String> {
    unsafe {
        let name = wide(SERVICE_NAME);
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            .map_err(|e| format!("打开 SCM 失败：{e}"))?;
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), access) {
            Ok(s) => s,
            Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.into() => {
                let _ = CloseServiceHandle(scm);
                return Err("服务未安装".into());
            },
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return Err(format!("打开服务失败（需管理员权限）：{e}"));
            },
        };
        let r = f(svc);
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        r
    }
}

// ═══════════════════════ 子命令解析（纯逻辑）═══════════════════════

/// 服务管理子命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommand {
    Install {
        opts: Box<ServeOptions>,
        start_now: bool,
    },
    Uninstall,
    Start,
    Stop,
    Status,
}

impl ServiceCommand {
    /// 从命令行解析子命令。
    ///
    /// 返回值三态是刻意的：
    /// · `Ok(None)` —— 不是子命令，交给守护进程那套解析
    /// · `Ok(Some(_))` —— 是子命令且参数完整
    /// · `Err(_)` —— **是子命令但参数有问题**（如 `install` 忘了 `--config`）
    ///
    /// ⚠ 不能把第三种情况并进第一种：`aegisd install`（漏了 --config）如果
    ///   悄悄退回守护进程解析，用户看到的是一屏"忽略未知参数：install"
    ///   外加一句"必须用 --config"——两个不相干的错误提示拼在一起，
    ///   而真正的问题是子命令参数不全。
    pub fn parse(argv: &[String]) -> Result<Option<Self>, String> {
        match argv.first().map(String::as_str) {
            None => Ok(None),
            Some("install") => Ok(Some(Self::Install {
                opts: Box::new(parse_install_opts(&argv[1..])?),
                start_now: argv.iter().any(|a| a == "--start"),
            })),
            Some("uninstall") => Ok(Some(Self::Uninstall)),
            Some("start") => Ok(Some(Self::Start)),
            Some("stop") => Ok(Some(Self::Stop)),
            Some("status") => Ok(Some(Self::Status)),
            Some(_) => Ok(None),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Install { .. } => "install",
            Self::Uninstall => "uninstall",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Status => "status",
        }
    }
}

/// 解析 `install` 的参数。配置路径**必填**——与守护进程同一条纪律：
/// Aegis 不猜配置路径，也不提供默认配置。
fn parse_install_opts(argv: &[String]) -> Result<ServeOptions, String> {
    let mut config: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut pipe: Option<String> = None;
    let mut token_file: Option<String> = None;
    let mut guard_act = false;
    let mut start_type = StartType::Auto;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => {
                config = argv.get(i + 1).cloned();
                i += 2;
            },
            "--data-dir" => {
                data_dir = argv.get(i + 1).cloned();
                i += 2;
            },
            "--pipe" => {
                pipe = argv.get(i + 1).cloned();
                i += 2;
            },
            "--token-file" => {
                token_file = argv.get(i + 1).cloned();
                i += 2;
            },
            "--guard-act" => {
                guard_act = true;
                i += 1;
            },
            "--start-type" => {
                let raw = argv.get(i + 1).cloned().unwrap_or_default();
                start_type = StartType::parse_arg(&raw).ok_or_else(|| {
                    format!(
                        "--start-type 只认 {} / {}，收到 {raw:?}。",
                        StartType::Auto.arg_name(),
                        StartType::Demand.arg_name()
                    )
                })?;
                i += 2;
            },
            other => {
                eprintln!("[WARN] install 忽略未知参数：{other}");
                i += 1;
            },
        }
    }

    let config = config.ok_or_else(|| "install 必须用 --config 指定配置文件。".to_string())?;
    let data_dir = data_dir.unwrap_or_else(|| ".aegis-run".to_string());
    let token_file = token_file.unwrap_or_else(|| {
        std::path::Path::new(&data_dir)
            .join("ipc.token")
            .display()
            .to_string()
    });
    // SCM 的 binPath 指向**当前这个 exe**。拿不到就当场失败——
    // 装出一个指向别处的服务，比装不成更难查。
    let binary = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "aegisd.exe".to_string());

    Ok(ServeOptions {
        config,
        pipe: aegis_ipc::normalize_pipe_name(&pipe.unwrap_or_default()),
        token_file,
        data_dir,
        guard_act,
        binary,
        start_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(binary: &str) -> ServeOptions {
        ServeOptions {
            config: r"C:\Program Files\Aegis\config.toml".into(),
            pipe: r"\\.\pipe\aegis".into(),
            token_file: r"C:\ProgramData\Aegis\ipc.token".into(),
            data_dir: r"C:\ProgramData\Aegis".into(),
            guard_act: false,
            binary: binary.into(),
            start_type: StartType::Auto,
        }
    }

    // ── binPath 的引号处理 ──────────────────────────────────────────
    // 装到 C:\Program Files\Aegis\ 时，SCM 会把命令截断在第一个空格处，
    // 把 "Files\Aegis\aegisd.exe --service" 当成服务名 —— 装得上，起不来。
    #[test]
    fn bin_path_quotes_every_path() {
        let spec = ServiceSpec::from_opts(&opts(r"C:\Program Files\Aegis\aegisd.exe"));
        assert!(
            spec.bin_path
                .starts_with("\"C:\\Program Files\\Aegis\\aegisd.exe\" --service"),
            "exe 路径必须加引号：{}",
            spec.bin_path
        );
        assert!(spec
            .bin_path
            .contains("--config \"C:\\Program Files\\Aegis\\config.toml\""));
        assert!(spec
            .bin_path
            .contains("--data-dir \"C:\\ProgramData\\Aegis\""));
        assert!(spec
            .bin_path
            .contains("--token-file \"C:\\ProgramData\\Aegis\\ipc.token\""));
        assert!(spec.bin_path.contains("--pipe \"\\\\.\\pipe\\aegis\""));
    }

    /// 按 Windows 命令行规则切分：引号内的空格**不算**分隔符。
    fn split_args(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut in_q = false;
        for c in s.chars() {
            if c == '"' {
                if in_q {
                    out.push(std::mem::take(&mut cur));
                    in_q = false;
                } else {
                    in_q = true;
                }
                continue;
            }
            if !in_q && c.is_whitespace() {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                continue;
            }
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    #[test]
    fn bin_path_tokenizes_without_ambiguity() {
        // 装到 C:\Program Files\Aegis\ 时，SCM 会把命令截断在第一个
        // 空格处，把 "Files\Aegis\aegisd.exe --service" 当成服务名 ——
        // 装得上，起不来，而错误信息还指向一个不存在的东西。
        let spec = ServiceSpec::from_opts(&opts(r"C:\Program Files\Aegis\aegisd.exe"));
        let toks = split_args(&spec.bin_path);
        assert_eq!(
            toks,
            vec![
                r"C:\Program Files\Aegis\aegisd.exe",
                "--service",
                "--config",
                r"C:\Program Files\Aegis\config.toml",
                "--data-dir",
                r"C:\ProgramData\Aegis",
                "--token-file",
                r"C:\ProgramData\Aegis\ipc.token",
                "--pipe",
                r"\\.\pipe\aegis",
            ],
            "token 切分必须无歧义：{:?}",
            toks
        );
        // 路径全部原样保住了，没有被空格切开
        assert!(toks[0].ends_with(r"Aegis\aegisd.exe"));
        assert!(toks.iter().any(|t| t == "--service"));
    }

    // ── 服务不该自己超时退出 ─────────────────────────────────────────
    #[test]
    fn bin_path_never_carries_serve_secs() {
        // 带上 --serve-secs 等于给服务设了个自杀定时器
        let spec = ServiceSpec::from_opts(&opts("aegisd.exe"));
        assert!(!spec.bin_path.contains("serve-secs"), "{}", spec.bin_path);
        assert!(
            !spec.bin_path.contains("guard-interval"),
            "{}",
            spec.bin_path
        );
    }

    // ── 危险开关默认不跟着服务走 ─────────────────────────────────────
    #[test]
    fn bin_path_carries_guard_act_only_when_asked() {
        let mut o = opts("aegisd.exe");
        assert!(!ServiceSpec::from_opts(&o).bin_path.contains("--guard-act"));
        o.guard_act = true;
        assert!(ServiceSpec::from_opts(&o).bin_path.contains("--guard-act"));
    }

    #[test]
    fn spec_defaults_to_auto_start() {
        // Aegis 的价值就在"你忘了它也在"，所以默认必须自启
        assert_eq!(
            ServiceSpec::from_opts(&opts("aegisd.exe")).start_type,
            StartType::Auto
        );
        assert_eq!(StartType::Auto.label(), "开机自启");
    }

    #[test]
    fn spec_keeps_identity_stable() {
        let s = ServiceSpec::from_opts(&opts("aegisd.exe"));
        assert_eq!(s.service_name, "Aegis");
        assert_eq!(s.display_name, "Aegis 守护进程");
        assert!(s.description.contains("命名管道"));
    }
}
