//! 一次性 IPC token（§23.1 的第二道门）。
//!
//! # 为什么 ACL 之外还需要 token
//!
//! 管道 DACL 放行的是 `Authenticated Users`——那是**本机所有已登录用户**，
//! 域环境下还包括域用户。ACL 只能回答"你能不能连上管道"，回答不了
//! "你是不是我的 GUI"。所以服务每次启动生成一个随机 token，握手时比对。
//!
//! # 为什么比对必须常量时间
//!
//! 普通 `==` 在第一个不同字节就会返回。攻击者逐个字节猜 token，靠**响应
//! 时间差**就能一个字节一个字节地把 32 字节试出来。本机攻击听起来很远，
//! 但这个底座的威胁模型里"同机其它进程"恰恰是被防范的对象。
//!
//! # 为什么是 32 字节
//!
//! 256 位，远超过"在线爆破可行"的量级。§23.1 写的是 32 字节随机 hex，
//! 这里照办（hex 文本 64 字符）。

use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

/// token 的字节长度。
pub const TOKEN_BYTES: usize = 32;
/// token 的 hex 文本长度（`TOKEN_BYTES * 2`）。
pub const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// 生成随机数失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("生成 IPC token 失败：系统随机数源返回 0x{status:08X}")]
pub struct TokenError {
    pub status: u32,
}

/// 一次性 IPC token。
#[derive(Clone)]
pub struct IpcToken([u8; TOKEN_BYTES]);

impl IpcToken {
    /// 从系统随机数源生成一个新 token。
    pub fn generate() -> Result<Self, TokenError> {
        let mut buf = [0u8; TOKEN_BYTES];
        let status = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status.0 != 0 {
            return Err(TokenError {
                status: status.0 as u32,
            });
        }
        Ok(Self(buf))
    }

    /// 从 hex 文本还原。长度不对或含非 hex 字符一律拒绝，
    /// 不做"宽容解析"——token 格式只有一种。
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex_decode(s)?;
        if bytes.len() != TOKEN_BYTES {
            return None;
        }
        let mut out = [0u8; TOKEN_BYTES];
        out.copy_from_slice(&bytes);
        Some(Self(out))
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }

    /// 校验对端送来的 hex token。**常量时间比对。**
    ///
    /// 解析失败与比对失败返回同一个 `false`：不区分"格式不对"和"值不对"，
    /// 免得给试探者额外信息。
    pub fn verify_hex(&self, presented: &str) -> bool {
        match Self::from_hex(presented) {
            Some(other) => constant_time_eq(&self.0, &other.0),
            None => false,
        }
    }
}

impl core::fmt::Debug for IpcToken {
    /// **绝不**打印 token 本体。日志会被收集、会被贴到 issue 里。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IpcToken(..)")
    }
}

/// 常量时间字节比较。
///
/// `acc |= x ^ y` 是**累积**而不是覆盖：改成 `acc = x ^ y` 就只剩最后一个
/// 字节起作用，前面的差异全被丢掉（有专门的测试钉住这一点）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const TBL: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TBL[(b >> 4) as usize] as char);
        out.push(TBL[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        out.push((nibble(b[i])? << 4) | nibble(b[i + 1])?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        // 只接受小写：token 是我们自己生成的，格式只有一种
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两次生成必须不同——否则"一次性"就是假的。
    #[test]
    fn generated_tokens_differ() {
        let a = IpcToken::generate().expect("系统随机数源应可用");
        let b = IpcToken::generate().expect("系统随机数源应可用");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.to_hex(), b.to_hex());
    }

    #[test]
    fn hex_roundtrip() {
        let t = IpcToken::generate().unwrap();
        let hex = t.to_hex();
        assert_eq!(hex.len(), TOKEN_HEX_LEN);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let back = IpcToken::from_hex(&hex).expect("自己编的码必须能解回来");
        assert_eq!(back.as_bytes(), t.as_bytes());
        assert!(t.verify_hex(&hex));
    }

    /// Debug 输出绝不能带上 token 本体：日志会被贴到 issue 里。
    #[test]
    fn debug_never_leaks_the_token() {
        let t = IpcToken::generate().unwrap();
        let dbg = format!("{t:?}");
        assert_eq!(dbg, "IpcToken(..)");
        assert!(!dbg.contains(&t.to_hex()), "Debug 泄露了 token");
    }

    #[test]
    fn verify_hex_accepts_only_the_exact_token() {
        let t = IpcToken::from_hex(&"a".repeat(TOKEN_HEX_LEN)).unwrap();
        assert!(t.verify_hex(&"a".repeat(TOKEN_HEX_LEN)));
        assert!(!t.verify_hex(&"b".repeat(TOKEN_HEX_LEN)));
    }

    /// 长度不对一律拒绝——短一个字符也不行，否则等于放宽了门闩。
    #[test]
    fn verify_hex_rejects_wrong_length() {
        let t = IpcToken::generate().unwrap();
        let hex = t.to_hex();
        assert!(!t.verify_hex(&hex[..hex.len() - 1]), "截断的应拒绝");
        assert!(!t.verify_hex(&hex[..hex.len() - 2]), "截断的应拒绝");
        assert!(!t.verify_hex(&format!("{hex}aa")), "加长的应拒绝");
        assert!(!t.verify_hex(""));
    }

    /// 非 hex 字符、大写、奇数长度都拒绝。格式只有一种，不做宽容解析。
    #[test]
    fn from_hex_rejects_malformed_input() {
        assert!(IpcToken::from_hex(&"z".repeat(TOKEN_HEX_LEN)).is_none());
        assert!(IpcToken::from_hex("abcd").is_none(), "长度不足");
        assert!(IpcToken::from_hex("abc").is_none(), "奇数长度");
        assert!(
            IpcToken::from_hex(&"A".repeat(TOKEN_HEX_LEN)).is_none(),
            "只接受小写"
        );
    }

    /// 常量时间比较：只差**第一个**字节也必须判不等。
    /// 若实现写成 `acc = x ^ y`（覆盖而非累积），这条会挂。
    #[test]
    fn constant_time_eq_catches_a_difference_in_the_first_byte() {
        let mut a = [0u8; 32];
        let b = [0u8; 32];
        a[0] = 0x01;
        assert!(!constant_time_eq(&a, &b));
    }

    /// 同理，只差**中间**一个字节也要判不等。
    #[test]
    fn constant_time_eq_catches_a_difference_in_the_middle() {
        let mut a = [0u8; 32];
        let b = [0u8; 32];
        a[16] = 0xFF;
        assert!(!constant_time_eq(&a, &b));
    }

    /// 只差**最后一个**字节也要判不等（覆盖式写法反而能抓到这个，
    /// 所以必须三个位置都测）。
    #[test]
    fn constant_time_eq_catches_a_difference_in_the_last_byte() {
        let mut a = [0u8; 32];
        let b = [0u8; 32];
        a[31] = 0x80;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"ab"), "长度不同即不等");
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn hex_encode_matches_known_values() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0x10, 0xff]), "000f10ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_decode_matches_known_values() {
        assert_eq!(
            hex_decode("000f10ff").unwrap(),
            vec![0x00, 0x0f, 0x10, 0xff]
        );
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert!(hex_decode("0g").is_none());
    }
}
