//! 采集/还原后端抽象。
//!
//! [`SnapshotGuard`] 的**逻辑**（改前快照、改后还原、崩溃兜底、幂等）必须
//! 脱离 Win32 完整单测——否则"一键复原"这件事本身就是没被测过的空话。
//! 因此把"读系统 / 写系统"抽成 trait，测试用 [`MockBackend`] 造假数据，
//! 真实 Windows 实现在 [`WindowsBackend`](crate::WindowsBackend)。

use aegis_model::NetSnapshot;

use crate::error::NetCfgError;

/// 非 WFP 网络设置的采集/还原后端。
pub trait NetCfgBackend {
    /// 采集当前非 WFP 网络设置，作为"改前基线"。
    fn capture(&self) -> Result<NetSnapshot, NetCfgError>;
    /// 把一份快照**写回**系统（还原）。必须是幂等的：同一份快照写多次，
    /// 结果与写一次相同——崩溃兜底可能在任意时刻补刀，不能假设只跑一遍。
    fn apply(&self, snap: &NetSnapshot) -> Result<(), NetCfgError>;
}

/// 测试用的内存后端：把采集/还原降级成对内存变量的读写，
/// 让 [`SnapshotGuard`] 的逻辑能被断言覆盖。
#[derive(Debug, Default)]
pub struct MockBackend {
    /// `capture()` 要返回的内容。
    pub captured: Option<NetSnapshot>,
    /// `apply()` 收到的最后一份快照（断言"还原写了什么"用）。
    pub applied: Vec<NetSnapshot>,
    /// `capture()` 是否报错。
    pub fail_capture: bool,
    /// `apply()` 是否报错。
    pub fail_apply: bool,
}

impl MockBackend {
    pub fn new(captured: NetSnapshot) -> Self {
        Self {
            captured: Some(captured),
            ..Self::default()
        }
    }

    pub fn failing_capture() -> Self {
        Self {
            fail_capture: true,
            ..Self::default()
        }
    }
}

impl NetCfgBackend for MockBackend {
    fn capture(&self) -> Result<NetSnapshot, NetCfgError> {
        if self.fail_capture {
            return Err(NetCfgError::ProxyRead("mock".into()));
        }
        self.captured
            .clone()
            .ok_or_else(|| NetCfgError::ProxyRead("mock 未配置 captured".into()))
    }

    fn apply(&self, snap: &NetSnapshot) -> Result<(), NetCfgError> {
        if self.fail_apply {
            return Err(NetCfgError::ProxyWrite("mock".into()));
        }
        // `apply` 取 &self，这里用 RefCell 记账；单测单线程，安全。
        // （真实后端走 Win32，不需要 interior mutability。）
        let _ = snap;
        Ok(())
    }
}

/// 可变体：需要记录 apply 内容的场景用这个（`apply` 签名是 `&self`，
/// 但测试要能回看"写回了什么"）。
#[derive(Debug, Default)]
pub struct RecordingBackend {
    pub captured: Option<NetSnapshot>,
    pub applied: std::cell::RefCell<Vec<NetSnapshot>>,
    pub fail_apply: bool,
}

impl RecordingBackend {
    pub fn new(captured: NetSnapshot) -> Self {
        Self {
            captured: Some(captured),
            applied: std::cell::RefCell::new(Vec::new()),
            fail_apply: false,
        }
    }

    pub fn applied(&self) -> Vec<NetSnapshot> {
        self.applied.borrow().clone()
    }
}

impl NetCfgBackend for RecordingBackend {
    fn capture(&self) -> Result<NetSnapshot, NetCfgError> {
        self.captured
            .clone()
            .ok_or_else(|| NetCfgError::ProxyRead("recording 未配置 captured".into()))
    }

    fn apply(&self, snap: &NetSnapshot) -> Result<(), NetCfgError> {
        if self.fail_apply {
            return Err(NetCfgError::ProxyWrite("mock".into()));
        }
        self.applied.borrow_mut().push(snap.clone());
        Ok(())
    }
}

/// 引用也可作后端：让 [`SnapshotGuard`](crate::SnapshotGuard) 只借不拥，
/// 测试便能在守卫析构后回看"写回了什么"（Drop 兜底测试的关键）。
impl<T: NetCfgBackend + ?Sized> NetCfgBackend for &T {
    fn capture(&self) -> Result<NetSnapshot, NetCfgError> {
        (**self).capture()
    }

    fn apply(&self, snap: &NetSnapshot) -> Result<(), NetCfgError> {
        (**self).apply(snap)
    }
}
