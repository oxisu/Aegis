//! 构建期采集 Git 元数据，供 `aegis-version` 在运行时拼出完整版本号。
//!
//! 设计取舍：**不启动任何子进程**（不调 `git rev-parse`）。
//! 原因：构建脚本起子进程在受限环境下可能长时间挂起，而这里需要的信息
//! 完全可以直接读 `.git` 目录下的文件得到，既快又不会卡住构建。
//!
//! 失败一律降级为 `unknown`，绝不让版本号问题阻断编译。

use std::fs;
use std::path::{Path, PathBuf};

const SHORT_HASH_LEN: usize = 7;

fn main() {
    // 重跑触发点：仅这几个文件变化时才有必要重算
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../VERSION");
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| String::from(".")));
    // crates/aegis-version -> 仓库根
    let repo_root = manifest_dir.join("..").join("..");

    let git_dir = resolve_git_dir(&repo_root);

    // 关键：一旦声明了 rerun-if-changed，Cargo 就**只在**这些文件变化时才重跑
    // build.rs。`.git/HEAD` 在切分支时会变，但**同分支上新增提交时它不变**
    // （变的只有 refs/heads/<branch>）。不把引用文件也列进来的话，
    // 版本号里的 Git 哈希会一直停在首次构建那次提交上。
    if let Some(gd) = &git_dir {
        println!("cargo:rerun-if-changed={}", gd.join("HEAD").display());
        if let Ok(head) = fs::read_to_string(gd.join("HEAD")) {
            if let Some(reference) = head.trim().strip_prefix("ref: ") {
                println!(
                    "cargo:rerun-if-changed={}",
                    gd.join(reference.replace('/', std::path::MAIN_SEPARATOR_STR))
                        .display()
                );
            }
        }
        println!(
            "cargo:rerun-if-changed={}",
            gd.join("packed-refs").display()
        );
    }

    let branch = git_dir
        .as_deref()
        .and_then(read_branch)
        .unwrap_or_else(|| "unknown".to_string());
    let hash = git_dir
        .as_deref()
        .and_then(read_head_hash)
        .unwrap_or_else(|| "unknown".to_string());

    // TARGET 只在构建脚本执行期间可见，crate 编译期拿不到，
    // 所以在这里采集后转成 rustc-env 再透给 lib.rs。
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=AEGIS_GIT_BRANCH={branch}");
    println!("cargo:rustc-env=AEGIS_GIT_HASH={hash}");
    println!("cargo:rustc-env=AEGIS_TARGET_TRIPLE={target}");
}

/// `.git` 可能是目录（常规克隆），也可能是文件（worktree / submodule 指向）。
fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let content = fs::read_to_string(&dot_git).ok()?;
    let tail = content.strip_prefix("gitdir:")?.trim();
    let p = PathBuf::from(tail);
    if p.is_absolute() {
        Some(p)
    } else {
        Some(repo_root.join(p))
    }
}

/// 读 HEAD：可能是 `ref: refs/heads/xxx`（需再解引用），也可能是裸哈希（detached HEAD）。
fn read_branch(git_dir: &Path) -> Option<String> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    match head.strip_prefix("ref: ") {
        // detached HEAD 没有分支名，如实反映
        None => Some("detached".to_string()),
        Some(r) => Some(r.rsplit('/').next().unwrap_or(r).to_string()),
    }
}

fn read_head_hash(git_dir: &Path) -> Option<String> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();

    let raw = match head.strip_prefix("ref: ") {
        // 直接就是提交哈希（detached HEAD）
        None => head.to_string(),
        Some(reference) => {
            // Git 引用路径里一律用 '/'，落到本地文件系统时才换成平台分隔符
            let ref_path = git_dir.join(reference.replace('/', std::path::MAIN_SEPARATOR_STR));
            match fs::read_to_string(&ref_path) {
                Ok(v) => v.trim().to_string(),
                Err(_) => lookup_packed_refs(git_dir, reference)?,
            }
        },
    };

    if raw.is_empty() {
        return None;
    }
    // 取前 7 位作为短哈希；不足则原样返回
    let end = raw.len().min(SHORT_HASH_LEN);
    Some(raw[..end].to_string())
}

/// 引用被 gc 打包后不在 refs/ 下，而在 packed-refs 里。
fn lookup_packed_refs(git_dir: &Path, reference: &str) -> Option<String> {
    let packed = fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    for line in packed.lines() {
        if line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut it = line.split_whitespace();
        if let (Some(hash), Some(name)) = (it.next(), it.next()) {
            if name == reference {
                return Some(hash.to_string());
            }
        }
    }
    None
}
