//! 打印 Aegis 的完整版本号。
//!
//! ```text
//! cargo run -p aegis-version --example version
//! cargo run -p aegis-version --example version -- --verbose
//! ```
//!
//! CI 用这个例子把当次构建的精确版本号写进构建日志，
//! 以便事后把任意一个二进制回溯到对应的提交。

use std::io::Write;

fn main() {
    let verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    let out = if verbose {
        aegis_version::banner_long()
    } else {
        aegis_version::banner()
    };

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{out}");
    let _ = lock.flush();
}
