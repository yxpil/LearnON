//! 运行时全局设置：连接、超时、TLS、优雅停机等运维参数。
//!
//! 配置指令（顶层，与 nginx 同名）：
//! ```text
//! worker_connections 10240;
//! client_header_timeout 15s;
//! client_body_timeout 30s;
//! keepalive_timeout 65s;
//! keepalive_requests 1000;
//! tls_handshake_timeout 10s;
//! shutdown_grace 30s;
//! server_tokens on;
//! tcp_nodelay on;
//! accept_backlog 512;
//! ```

use std::time::Duration;

use learnon_config::Config;

#[derive(Debug, Clone)]
pub struct Settings {
    /// 全局并发连接上限（对标 nginx worker_connections，此处为整个进程）
    pub worker_connections: usize,
    /// 读请求头超时
    pub client_header_timeout: Duration,
    /// 读请求体超时（单帧之间的最大间隔）
    pub client_body_timeout: Duration,
    /// keep-alive 空闲超时
    pub keepalive_timeout: Duration,
    /// 单连接最多处理多少请求后关闭
    pub keepalive_requests: usize,
    /// TLS 握手超时
    pub tls_handshake_timeout: Duration,
    /// 收到停机信号后等在途请求的最长时间，超时后强制断开
    pub shutdown_grace: Duration,
    /// 是否在响应里带 Server 头
    pub server_tokens: bool,
    pub tcp_nodelay: bool,
    pub accept_backlog: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            worker_connections: 10240,
            client_header_timeout: Duration::from_secs(15),
            client_body_timeout: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(65),
            keepalive_requests: 1000,
            tls_handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(30),
            server_tokens: true,
            tcp_nodelay: true,
            accept_backlog: 512,
        }
    }
}

/// 解析 nginx 风格时间：`500ms` / `15s` / `1m` / `2h` / 纯数字按秒
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n.trim(), 1_000_000u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n.trim(), 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n.trim(), 60_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n.trim(), 3_600_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('d') {
        (n.trim(), 86_400_000_000_000u64)
    } else {
        (s, 1_000_000_000u64)
    };
    num.parse::<f64>()
        .ok()
        .filter(|v| *v >= 0.0 && *v < 86_400.0 * 365.0)
        .map(|v| Duration::from_nanos((v * mult as f64) as u64))
}

fn on_off(v: Option<&str>) -> Option<bool> {
    match v?.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

impl Settings {
    /// 从配置读取设置；无法识别或非法的值不致命，作为告警返回（对标 nginx 的 warn 日志）
    pub fn from_config(config: &Config) -> (Settings, Vec<String>) {
        let mut s = Settings::default();
        let mut warnings = Vec::new();

        if let Some(d) = config.find("worker_connections") {
            match d.arg(0).and_then(|v| v.parse::<usize>().ok()) {
                Some(n) if n > 0 => s.worker_connections = n,
                _ => warnings.push("worker_connections 取值非法，使用默认值".to_string()),
            }
        }
        for (name, slot) in [
            ("client_header_timeout", &mut s.client_header_timeout),
            ("client_body_timeout", &mut s.client_body_timeout),
            ("keepalive_timeout", &mut s.keepalive_timeout),
            ("tls_handshake_timeout", &mut s.tls_handshake_timeout),
            ("shutdown_grace", &mut s.shutdown_grace),
        ] {
            if let Some(v) = config.find(name).and_then(|d| d.arg(0)) {
                match parse_duration(v) {
                    Some(d) => *slot = d,
                    None => warnings.push(format!("{name} 时间格式非法: {v}")),
                }
            }
        }
        if let Some(v) = config.find("keepalive_requests").and_then(|d| d.arg(0)) {
            s.keepalive_requests = v.parse::<usize>().unwrap_or(1000).max(1);
        }
        for (name, slot) in [
            ("server_tokens", &mut s.server_tokens),
            ("tcp_nodelay", &mut s.tcp_nodelay),
        ] {
            if let Some(d) = config.find(name) {
                match on_off(d.arg(0)) {
                    Some(v) => *slot = v,
                    None => warnings.push(format!("{name} 只接受 on/off，已忽略")),
                }
            }
        }
        if let Some(v) = config.find("accept_backlog").and_then(|d| d.arg(0)) {
            s.accept_backlog = v.parse::<u32>().unwrap_or(512).clamp(16, 65535);
        }

        // hyper 的 http1 只有一个读头超时，它同时覆盖"慢速发头"与"keep-alive 空闲"，
        // 因此取两者较大值：否则 keep-alive 空闲会被 header 超时提前掐断导致频繁重连。
        s.client_header_timeout = s.client_header_timeout.max(s.keepalive_timeout);
        (s, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("1500ms"), Some(Duration::from_millis(1500)));
        assert_eq!(parse_duration("15s"), Some(Duration::from_secs(15)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("10"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("-5s"), None);
    }

    #[test]
    fn header_timeout_at_least_keepalive() {
        let cfg = Config::parse("client_header_timeout 5s; keepalive_timeout 60s;").unwrap();
        let (s, _) = Settings::from_config(&cfg);
        assert_eq!(s.client_header_timeout, Duration::from_secs(60));
        assert_eq!(s.keepalive_timeout, Duration::from_secs(60));
    }
}
