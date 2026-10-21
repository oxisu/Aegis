//! 基线快照的**落盘 / 读回 / 清除**（崩溃恢复用）。
//!
//! # 为什么需要它
//! [`SnapshotGuard`](crate::SnapshotGuard) 的 `Drop` 兜底只在**正常退出**时
//! 执行；`taskkill` / 蓝屏 / 断电不会跑 `Drop`。所以 Aegis 真要改非 WFP 项
//! 时，必须在改动前把基线**落盘**——下次启动发现"有基线文件却没人来还原"，
//! 就意味着上一轮改到一半被强杀，此时按基线还原，杜绝断网残留。
//!
//! # 原子写
//! 先写 `.json.tmp` 再 `rename` 覆盖。半途崩溃最多留下一个孤立的 tmp，
//! 真正的基线文件要么是旧的、要么是新的，绝不会是写一半的损坏 JSON——
//! "还原时读到坏快照"比"没有快照"更糟（会把人导向错误的网络状态）。

use std::path::Path;

use aegis_model::NetSnapshot;

use crate::error::NetCfgError;

/// 把基线快照原子写入 `path`。
pub fn save_baseline(path: &Path, snap: &NetSnapshot) -> Result<(), NetCfgError> {
    let json =
        serde_json::to_vec_pretty(snap).map_err(|e| NetCfgError::SnapshotFile(e.to_string()))?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json).map_err(|e| NetCfgError::SnapshotFile(e.to_string()))?;
    // rename 在同一目录内是原子操作；跨设备才会退化成拷贝（这里同目录，安全）。
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        NetCfgError::SnapshotFile(e.to_string())
    })?;
    Ok(())
}

/// 读回基线快照；文件不存在返回 `Ok(None)`（不是错误——本就没改过）。
pub fn load_baseline(path: &Path) -> Result<Option<NetSnapshot>, NetCfgError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let snap = serde_json::from_slice(&bytes)
                .map_err(|e| NetCfgError::SnapshotFile(format!("{}（{} 字节）", e, bytes.len())))?;
            Ok(Some(snap))
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(NetCfgError::SnapshotFile(e.to_string())),
    }
}

/// 删除基线文件；不存在时视为已清除（`Ok`）。
pub fn clear_baseline(path: &Path) -> Result<(), NetCfgError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NetCfgError::SnapshotFile(e.to_string())),
    }
}

fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_model::{RouteEntry, SystemProxy};
    use std::net::Ipv4Addr;

    fn sample() -> NetSnapshot {
        NetSnapshot::new(
            1_769_000_000_000,
            SystemProxy {
                enabled: true,
                server: "127.0.0.1:7890".to_string(),
                override_: "<local>".to_string(),
                autoconfig_url: None,
            },
            vec![RouteEntry {
                destination: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                interface_luid: 7,
                metric: 25,
            }],
        )
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aegis-netcfg-test-{}-{}.json",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// 落盘再读回必须无损——它是崩溃恢复的唯一依据。
    #[test]
    fn save_then_load_round_trips() {
        let p = temp_path("roundtrip");
        let snap = sample();
        save_baseline(&p, &snap).unwrap();
        let back = load_baseline(&p).unwrap().expect("应存在");
        assert_eq!(back, snap);
        clear_baseline(&p).unwrap();
    }

    /// 文件不存在 = 没改过，`Ok(None)`，绝不是错误。
    #[test]
    fn load_missing_is_none_not_error() {
        let p = temp_path("missing");
        let _ = std::fs::remove_file(&p);
        assert_eq!(load_baseline(&p).unwrap(), None);
    }

    /// 清一个不存在的文件也算成功（幂等清除）。
    #[test]
    fn clear_missing_is_ok() {
        let p = temp_path("clearmissing");
        let _ = std::fs::remove_file(&p);
        assert!(clear_baseline(&p).is_ok());
    }

    /// 原子写的临时文件不应残留在目标路径旁。
    #[test]
    fn no_tmp_left_behind() {
        let p = temp_path("notmp");
        save_baseline(&p, &sample()).unwrap();
        assert!(!tmp_path(&p).exists(), "rename 后不应留下 .tmp");
        clear_baseline(&p).unwrap();
    }

    /// 读到损坏的 JSON 必须报错，而不是还原成一台错的网络。
    #[test]
    fn corrupt_file_is_an_error_not_a_silent_empty() {
        let p = temp_path("corrupt");
        std::fs::write(&p, b"{ this is not json").unwrap();
        assert!(matches!(
            load_baseline(&p),
            Err(NetCfgError::SnapshotFile(_))
        ));
        let _ = std::fs::remove_file(&p);
    }
}
