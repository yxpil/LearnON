//! 请求路由与配置模型：监听端点 / server 块 / location 匹配（nginx 语义）。
//!
//! location 匹配算法（与 nginx 一致）：
//!   1. `= /exact` 精确匹配命中 → 直接使用
//!   2. 记录最长前缀匹配；若该前缀带 `^~` → 直接使用（跳过正则）
//!   3. 否则按配置顺序找第一个命中的正则（`~` 或 `~*`）→ 使用
//!   4. 都没有 → 用第 2 步的最长前缀
//!
//! server 匹配：先按**实际监听地址**（ip:port）取该端点的 vhost 集合，
//! 再按 Host 匹配：精确名 > 通配符（`*.example.com` / `example.*`）> `default_server` > 第一个。
//!
//! `listen` 支持的形态：
//! ```text
//! listen 8080;                       # 0.0.0.0:8080（与 nginx 一致）
//! listen 127.0.0.1:8080;             # 指定地址
//! listen [::]:8080;                  # IPv6
//! listen 8443 ssl http2;             # TLS + ALPN h2
//! listen 8443 ssl default_server;    # 该端点的默认 vhost
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use learnon_config::{Config, Directive};

use crate::certs::{CertSpec, TlsOptions, TlsProtocols, TlsVersion};
use crate::engine::{HandlerSpec, Phase, ReturnAction, RewriteFlag, RewriteRule};
use crate::limit::{ConnRule, ReqRule};
use crate::lua_engine::LuaSource;
use crate::proxy_tls::TlsPolicy;
use crate::AppError;

// ---------- location 匹配 ----------

#[derive(Debug, Clone)]
pub enum LocationKind {
    /// `location = /exact`
    Exact(String),
    /// `location /prefix`（`^~`：命中即赢过正则）
    Prefix { path: String, caret: bool },
    /// `location ~ regex`
    Regex(regex::Regex),
    /// `location ~* regex`
    RegexI(regex::Regex),
}

impl LocationKind {
    fn parse(modifier: Option<&str>, pattern: &str) -> Result<Self, AppError> {
        Ok(match modifier {
            Some("=") => LocationKind::Exact(pattern.to_string()),
            Some("^~") => LocationKind::Prefix {
                path: pattern.to_string(),
                caret: true,
            },
            Some("~") => LocationKind::Regex(regex::Regex::new(pattern)
                .map_err(|e| AppError::Other(format!("location 正则错误 {pattern}: {e}")))?),
            Some("~*") => LocationKind::RegexI(
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| AppError::Other(format!("location 正则错误 {pattern}: {e}")))?,
            ),
            None => LocationKind::Prefix {
                path: pattern.to_string(),
                caret: false,
            },
            Some(other) => {
                return Err(AppError::Other(format!(
                    "暂不支持的 location 修饰符 '{other}'（支持 = / ^~ / ~ / ~*）"
                )))
            }
        })
    }

    fn prefix_path(&self) -> Option<&str> {
        match self {
            LocationKind::Prefix { path, .. } => Some(path),
            _ => None,
        }
    }

    fn is_caret(&self) -> bool {
        matches!(self, LocationKind::Prefix { caret: true, .. })
    }

    fn is_regex(&self) -> bool {
        matches!(self, LocationKind::Regex(_) | LocationKind::RegexI(_))
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub kind: LocationKind,
    /// 原始 pattern（日志/调试/alias 前缀剥离/proxy URI 替换）
    pub pattern: String,
    pub rewrites: Vec<RewriteRule>,
    pub ret: Option<ReturnAction>,
    pub proxy_pass: Option<String>,
    pub proxy_set_headers: Vec<(String, String)>,
    pub proxy_read_timeout: u64,
    pub proxy_connect_timeout: u64,
    pub proxy_send_timeout: u64,
    /// `proxy_next_upstream off | error | timeout | http_500 | ...`（默认 error,timeout）
    pub proxy_next_upstream: Vec<String>,
    /// `proxy_request_buffering on|off`（默认 on）。off 且该 location 有 proxy_pass 时，
    /// 请求体边收边转发给后端，网关不再整体缓冲（nginx 语义）。
    pub proxy_request_buffering: bool,
    pub rust_phases: Vec<(Phase, HandlerSpec)>,
    pub lua_phases: Vec<(Phase, String, LuaSource)>,
    pub root: Option<PathBuf>,
    pub alias: Option<PathBuf>,
    pub index: Option<Vec<String>>,
    pub try_files: Option<Vec<String>>,
    pub autoindex: bool,
    pub error_pages: HashMap<u16, String>,
    pub add_headers: Vec<(String, String)>,
    /// PREACCESS 阶段限流
    pub limit_req: Vec<ReqRule>,
    /// `internal;` 只允许内部重定向访问
    pub internal: bool,
    /// `client_max_body_size` 的 location 级覆盖
    pub client_max_body_size: Option<u64>,
    /// ACCESS 阶段 IP 白/黑名单（allow/deny，有序，第一条命中生效，无命中默认放行）
    pub access_rules: Vec<crate::access::AccessRule>,
    /// `auth_basic "realm";`；None = 未启用。字面量 `off`/空串视为关闭。
    pub auth_basic_realm: Option<String>,
    /// `auth_basic_user_file <path>;` 解析后的绝对路径
    pub auth_basic_user_file: Option<PathBuf>,
    /// `proxy_cache <zone>|off;`：Some(zone) 启用命名缓存区，None 关闭
    pub proxy_cache: Option<String>,
    /// `proxy_cache_key <模板>;`，默认 `$scheme$proxy_host$request_uri`
    pub proxy_cache_key: String,
    /// `proxy_cache_methods`（默认 GET HEAD）
    pub proxy_cache_methods: Vec<String>,
    /// `proxy_cache_valid` 拆分后的 (状态码集合, ttl)；空表示仅按上游 Cache 头
    pub proxy_cache_valid: Vec<(Vec<String>, std::time::Duration)>,
    /// `proxy_cache_min_uses N`（默认 1）：同一 key 第 N 次起才写入
    pub proxy_cache_min_uses: u32,
    /// `proxy_ssl_*`：https/wss 后端的客户端 TLS 策略
    pub proxy_tls: TlsPolicy,
}

#[derive(Debug, Clone)]
pub struct Server {
    /// `server_name` 的首个值，用于日志与告警
    pub server_name: String,
    pub server_names: Vec<String>,
    /// `listen ... default_server`：Host 匹配不上时的兜底 vhost
    pub is_default_server: bool,
    pub locations: Vec<Location>,
    pub root: Option<PathBuf>,
    pub index: Vec<String>,
    pub autoindex: bool,
    pub error_pages: HashMap<u16, String>,
    pub client_max_body_size: Option<u64>,
    pub add_headers: Vec<(String, String)>,
    /// server 级 proxy_set_header，作为 location 的默认值
    pub proxy_set_headers: Vec<(String, String)>,
    /// server 级并发限制
    pub limit_conn: Vec<ConnRule>,
    /// server 级 ACCESS IP 规则：location 无自身规则时继承（nginx 语义）
    pub access_rules: Vec<crate::access::AccessRule>,
    pub auth_basic_realm: Option<String>,
    pub auth_basic_user_file: Option<PathBuf>,
}

/// 一个真实监听端点
#[derive(Debug, Clone)]
pub struct Listener {
    pub addr: SocketAddr,
    pub tls: Option<TlsOptions>,
    /// 明文监听是否接受 h2c（prior-knowledge）；TLS 监听的 h2 由 tls.http2 决定
    pub http2: bool,
    /// `listen ... quic`：该端点用 QUIC/HTTP/3 服务（UDP），隐含 tls=Some。
    /// 同一 addr 的 TCP 监听照常存在；QUIC 端点在 server.rs 里另起 UDP accept 循环。
    pub quic: bool,
    /// `listen ... backlog=N`；None 用全局 accept_backlog
    pub backlog: Option<u32>,
    /// `listen [::]:80 ipv6only=off` 等；None = 默认（仅 IPv6）
    pub ipv6only: Option<bool>,
}

/// 某监听地址上的一组虚拟主机；`servers[0]` 是默认 vhost
#[derive(Debug)]
pub struct AddrGroup {
    pub servers: Vec<Arc<Server>>,
}

#[derive(Debug)]
pub struct Router {
    pub groups: HashMap<SocketAddr, AddrGroup>,
    pub listeners: Vec<Listener>,
    pub warnings: Vec<String>,
}

/// 一个 server 块里除 listen 之外的所有配置模板
struct ServerTemplate {
    server_name: String,
    server_names: Vec<String>,
    locations: Vec<Location>,
    root: Option<PathBuf>,
    index: Vec<String>,
    autoindex: bool,
    error_pages: HashMap<u16, String>,
    client_max_body_size: Option<u64>,
    add_headers: Vec<(String, String)>,
    proxy_set_headers: Vec<(String, String)>,
    proxy_connect_timeout: u64,
    proxy_read_timeout: u64,
    proxy_send_timeout: u64,
    proxy_request_buffering: bool,
    proxy_cache: Option<String>,
    proxy_cache_key: String,
    proxy_cache_methods: Vec<String>,
    proxy_cache_valid: Vec<(Vec<String>, std::time::Duration)>,
    proxy_cache_min_uses: u32,
    proxy_tls: TlsPolicy,
    limit_conn: Vec<ConnRule>,
    access_rules: Vec<crate::access::AccessRule>,
    auth_basic_realm: Option<String>,
    auth_basic_user_file: Option<PathBuf>,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
    protocols: TlsProtocols,
    http2: bool,
}

#[derive(Debug, Clone, Default)]
struct ListenFlags {
    ssl: bool,
    http2: bool,
    quic: bool,
    default_server: bool,
    backlog: Option<u32>,
    ipv6only: Option<bool>,
}

/// 解析 `listen` 的第一个参数为 SocketAddr
pub fn parse_listen_addr(arg: &str) -> Option<SocketAddr> {
    let a = arg.trim();
    if a.is_empty() {
        return None;
    }
    if let Ok(p) = a.parse::<u16>() {
        return Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, p)));
    }
    if let Some(rest) = a.strip_prefix("*:") {
        let p = rest.parse::<u16>().ok()?;
        return Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, p)));
    }
    a.parse::<SocketAddr>().ok().or_else(|| {
        // `1.2.3.4 8080` 之类的分隔写法不支持；给个明确错误提示
        None
    })
}

fn parse_listen(directive: &Directive) -> Result<(SocketAddr, ListenFlags), AppError> {
    let arg = directive
        .arg(0)
        .ok_or_else(|| AppError::Other("listen 缺少地址/端口".into()))?;
    let addr = parse_listen_addr(arg).ok_or_else(|| {
        AppError::Other(format!(
            "listen 参数无法解析: '{arg}'（支持 8080 / 127.0.0.1:8080 / [::]:8080 / *:8080）"
        ))
    })?;
    let mut f = ListenFlags::default();
    for a in directive.args.iter().skip(1) {
        match a.as_str() {
            "ssl" => f.ssl = true,
            "http2" => f.http2 = true,
            // QUIC 传输强制 TLS1.3（RFC 9001），`quic` 隐含 `ssl`：证书缺失时报错同 ssl 路径
            "quic" => {
                f.quic = true;
                f.ssl = true;
            }
            "default_server" => f.default_server = true,
            other => {
                if let Some(v) = other.strip_prefix("backlog=") {
                    f.backlog = Some(v.parse().map_err(|_| {
                        AppError::Other(format!("listen backlog 取值非法: {other}"))
                    })?);
                } else if let Some(v) = other.strip_prefix("ipv6only=") {
                    f.ipv6only = Some(match v {
                        "on" => true,
                        "off" => false,
                        _ => {
                            return Err(AppError::Other(format!(
                                "listen ipv6only 只接受 on/off，收到 '{v}'"
                            )))
                        }
                    });
                } else {
                    // reuseport/proxy_protocol/setfib 等尚未实现，明确报错而不是静默忽略
                    return Err(AppError::Other(format!(
                        "listen 暂不支持参数 '{other}'（已支持 ssl / http2 / quic / default_server / backlog=N / ipv6only=on|off）"
                    )));
                }
            }
        }
    }
    Ok((addr, f))
}

/// 解析 error_page 指令组：`error_page 404 403 /x.html;`
fn parse_error_pages(d: &Directive) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for ep in collect_error_pages(d) {
        let args: Vec<&str> = ep.args.iter().map(String::as_str).collect();
        let Some(target) = args.iter().rev().find(|a| a.starts_with('/')) else {
            continue;
        };
        for a in &args {
            if let Ok(code) = a.parse::<u16>() {
                map.insert(code, target.to_string());
            }
        }
    }
    map
}

/// error_page 可能出现在块里（server 块）也可能被 include 展开到别处，统一收集
fn collect_error_pages(d: &Directive) -> Vec<&Directive> {
    d.block.iter().filter(|x| x.name == "error_page").collect()
}

/// 解析 nginx 大小后缀：1m / 10k / 1g / 纯字节
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix(['k', 'K']) {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix(['m', 'M']) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix(['g', 'G']) {
        (n, 1024 * 1024 * 1024u64)
    } else {
        (s, 1u64)
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

fn parse_time_secs(v: &str, default: u64) -> u64 {
    crate::settings::parse_duration(v)
        .map(|d| d.as_secs())
        .unwrap_or(default)
}

fn parse_on_off(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" => Some(true),
        "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// 解析 `proxy_ssl_*`：把 https/wss 后端的客户端 TLS 策略就地应用到 `policy`。
/// server 与 location 级共用；未写的指令保持传入值（location 缺省继承 server 级）。
/// - `proxy_ssl_verify on|off`（默认 on）：off → 不校验后端证书（自签/内网）
/// - `proxy_ssl_server_name on|off`（默认 on）：本实现下 rustls 客户端总会发 SNI，故仅作记录
/// - `proxy_ssl_name <host>`：覆盖 SNI/校验主机名（默认取 proxy_pass 的 host）
/// - `proxy_ssl_trusted_certificate <path>`：PEM CA 束（verify on 时必需；相对 conf 目录解析）
fn parse_proxy_ssl_directives(
    d: &Directive,
    base_dir: &PathBuf,
    warnings: &mut Vec<String>,
    policy: &mut TlsPolicy,
) {
    if let Some(v) = d.find("proxy_ssl_verify").and_then(|x| x.arg(0)) {
        match parse_on_off(v) {
            Some(b) => policy.verify = b,
            None => warnings.push(format!(
                "proxy_ssl_verify 只接受 on/off（收到 '{v}'），保持 {}",
                if policy.verify { "on" } else { "off" }
            )),
        }
    }
    if let Some(v) = d.find("proxy_ssl_server_name").and_then(|x| x.arg(0)) {
        match parse_on_off(v) {
            Some(b) => policy.send_sni = b,
            None => warnings.push(format!(
                "proxy_ssl_server_name 只接受 on/off（收到 '{v}'），保持 {}",
                if policy.send_sni { "on" } else { "off" }
            )),
        }
    }
    if let Some(v) = d.find("proxy_ssl_name").and_then(|x| x.arg(0)) {
        policy.server_name = Some(v.to_string());
    }
    if let Some(v) = d.find("proxy_ssl_trusted_certificate").and_then(|x| x.arg(0)) {
        let p = crate::resolve_path(v, base_dir);
        policy.trusted_cert = Some(p.to_string_lossy().into_owned());
    }
}

/// `proxy_cache*` 指令的解析产物：字段用 Option 表示"本块是否显式指定"，
/// 以便 location 缺省时继承 server 级（nginx 的 location 可覆盖 http/server 值）。
struct CacheSettings {
    /// None=未写；Some(None)=写了 `off`；Some(Some(zone))=写了区名
    zone: Option<Option<String>>,
    key: Option<String>,
    methods: Option<Vec<String>>,
    valid: Vec<(Vec<String>, std::time::Duration)>,
    has_valid: bool,
    min_uses: Option<u32>,
}

fn parse_cache_directives(d: &Directive, warnings: &mut Vec<String>) -> CacheSettings {
    let mut cs = CacheSettings {
        zone: None,
        key: None,
        methods: None,
        valid: Vec::new(),
        has_valid: false,
        min_uses: None,
    };
    if let Some(v) = d.find("proxy_cache").and_then(|x| x.arg(0)) {
        cs.zone = Some(if v.eq_ignore_ascii_case("off") {
            None
        } else {
            Some(v.to_string())
        });
    }
    if let Some(v) = d.find("proxy_cache_key").and_then(|x| x.arg(0)) {
        cs.key = Some(v.to_string());
    }
    if let Some(m) = d.find("proxy_cache_methods") {
        if !m.args.is_empty() {
            cs.methods = Some(m.args.iter().map(|a| a.to_ascii_uppercase()).collect());
        }
    }
    // proxy_cache_valid 可多行：`proxy_cache_valid 200 302 10m;` / `proxy_cache_valid any 1m;`
    for vd in d.block.iter().filter(|x| x.name == "proxy_cache_valid") {
        if vd.args.len() < 2 {
            warnings.push(format!(
                "第 {} 行 proxy_cache_valid 需要 `<码...> <时长>`，已忽略",
                vd.line
            ));
            continue;
        }
        let (time_arg, code_args) = vd.args.split_last().unwrap();
        match crate::settings::parse_duration(time_arg) {
            Some(dur) => cs.valid.push((code_args.to_vec(), dur)),
            None => warnings.push(format!(
                "第 {} 行 proxy_cache_valid 时长非法 '{time_arg}'，已忽略",
                vd.line
            )),
        }
        cs.has_valid = true;
    }
    if let Some(v) = d.find("proxy_cache_min_uses").and_then(|x| x.arg(0)) {
        match v.parse::<u32>() {
            Ok(n) if n >= 1 => cs.min_uses = Some(n),
            _ => warnings.push(format!("proxy_cache_min_uses 需为 ≥1 整数，已忽略 '{v}'")),
        }
    }
    cs
}

impl Router {
    pub fn build(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        Self::build_with_listeners(config, base_dir, None)
    }

    /// 热重载：复用进程已绑定的监听集合，只按新配置重建 vhost/location 路由表。
    /// reload 期间从不触碰 listen socket（无 accept 空窗），因此新增/改动的
    /// server/location 对新请求立即生效；配置里新引入的监听地址不会被绑定（需重启）。
    pub fn rebuild_routing(
        config: &Config,
        base_dir: &PathBuf,
        listeners: &[Listener],
    ) -> Result<Self, AppError> {
        Self::build_with_listeners(config, base_dir, Some(listeners.to_vec()))
    }

    fn build_with_listeners(
        config: &Config,
        base_dir: &PathBuf,
        listener_override: Option<Vec<Listener>>,
    ) -> Result<Self, AppError> {
        let mut warnings: Vec<String> = Vec::new();
        // addr -> servers
        let mut groups: HashMap<SocketAddr, Vec<Arc<Server>>> = HashMap::new();
        // addr -> 默认 vhost 下标标记
        let mut defaults: HashMap<SocketAddr, usize> = HashMap::new();
        // addr -> TLS 证书集合
        let mut tls_specs: HashMap<SocketAddr, Vec<CertSpec>> = HashMap::new();
        // addr -> (是否 ssl, 是否 http2, 最低 TLS 版本)
        struct Endpoint {
            ssl: bool,
            http2: bool,
            quic: bool,
            protocols: TlsProtocols,
            backlog: Option<u32>,
            ipv6only: Option<bool>,
        }
        let mut endpoints: HashMap<SocketAddr, Endpoint> = HashMap::new();
        // 配置里 listen 首次出现的顺序（HashMap 遍历顺序不定，监听顺序必须可复现）
        let mut order: Vec<SocketAddr> = Vec::new();
        let mut plain_conflicts: Vec<SocketAddr> = Vec::new();

        let limits_declared: Vec<String> = config
            .root
            .block
            .iter()
            .filter(|d| d.name == "limit_req_zone" || d.name == "limit_conn_zone")
            .filter_map(|d| d.args.iter().find_map(|a| a.strip_prefix("zone="))
                .map(|z| z.split(':').next().unwrap_or(z).to_string()))
            .collect();

        for d in config.servers() {
            Self::warn_unknown(
                d,
                &["listen", "server_name", "root", "index", "autoindex", "try_files",
                   "error_page", "client_max_body_size", "return", "rewrite", "add_header",
                   "proxy_pass", "proxy_set_header", "proxy_read_timeout", "proxy_connect_timeout",
                   "proxy_send_timeout", "proxy_next_upstream", "proxy_request_buffering", "limit_conn", "http2",
                   "proxy_cache", "proxy_cache_key", "proxy_cache_methods", "proxy_cache_valid", "proxy_cache_min_uses",
                   "proxy_ssl_verify", "proxy_ssl_server_name", "proxy_ssl_name", "proxy_ssl_trusted_certificate",
                   "ssl_certificate", "ssl_certificate_key", "ssl_min_version", "ssl_protocols",
                   "location", "content_by_lua", "content_by_lua_file", "access_by_lua",
                   "access_by_lua_file", "rewrite_by_lua", "rewrite_by_lua_file",
                   "header_filter_by_lua", "header_filter_by_lua_file",
                   "body_filter_by_lua", "body_filter_by_lua_file",
                   "log_by_lua", "log_by_lua_file",
                   "content_by_rust", "access_by_rust", "rewrite_by_rust", "log_by_rust",
                   "allow", "deny", "auth_basic", "auth_basic_user_file"],
                "server",
                &mut warnings,
            );

            let tmpl = Self::build_template(d, base_dir, &limits_declared, &mut warnings)?;

            let mut listens: Vec<(SocketAddr, ListenFlags)> = Vec::new();
            for l in d.block.iter().filter(|x| x.name == "listen") {
                listens.push(parse_listen(l)?);
            }
            if listens.is_empty() {
                listens.push((
                    SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 8080)),
                    ListenFlags::default(),
                ));
                warnings.push(format!(
                    "server '{}'（第 {} 行）没有 listen 指令，默认监听 0.0.0.0:8080",
                    tmpl.server_name, d.line
                ));
            }

            for (addr, flags) in listens {
                if !order.contains(&addr) {
                    order.push(addr);
                }
                let ep = endpoints.entry(addr).or_insert(Endpoint {
                    ssl: false,
                    http2: false,
                    quic: false,
                    protocols: tmpl.protocols.clone(),
                    backlog: None,
                    ipv6only: None,
                });
                if flags.backlog.is_some() {
                    ep.backlog = flags.backlog;
                }
                if flags.ipv6only.is_some() {
                    ep.ipv6only = flags.ipv6only;
                }
                if flags.ssl {
                    if ep.ssl {
                        // 同一地址已有 ssl server，确保证书齐全
                    }
                    ep.ssl = true;
                    let cert = tmpl
                        .ssl_cert
                        .clone()
                        .ok_or_else(|| AppError::Other(format!(
                            "{addr} 声明了 listen ssl，但 server '{}' 缺少 ssl_certificate",
                            tmpl.server_name
                        )))?;
                    let key = tmpl.ssl_key.clone().ok_or_else(|| AppError::Other(format!(
                        "{addr} 声明了 listen ssl，但 server '{}' 缺少 ssl_certificate_key",
                        tmpl.server_name
                    )))?;
                    tls_specs.entry(addr).or_default().push(CertSpec {
                        names: tmpl.server_names.clone(),
                        cert,
                        key,
                    });
                } else if ep.ssl {
                    // 该端点已被其他 server 要求 TLS：这个 vhost 复用同一监听 socket，
                    // 只能走 HTTPS（与 nginx 行为一致：同一地址不能同时有明文与 TLS）
                    plain_conflicts.push(addr);
                }
                ep.http2 |= flags.http2 || tmpl.http2;
                ep.quic |= flags.quic;
                // 同一 socket 上多个 server 的 ssl_protocols 取并集
                ep.protocols.union_with(&tmpl.protocols);

                let server = Server {
                    server_name: tmpl.server_name.clone(),
                    server_names: tmpl.server_names.clone(),
                    is_default_server: flags.default_server,
                    locations: tmpl.locations.clone(),
                    root: tmpl.root.clone(),
                    index: tmpl.index.clone(),
                    autoindex: tmpl.autoindex,
                    error_pages: tmpl.error_pages.clone(),
                    client_max_body_size: tmpl.client_max_body_size,
                    add_headers: tmpl.add_headers.clone(),
                    proxy_set_headers: tmpl.proxy_set_headers.clone(),
                    limit_conn: tmpl.limit_conn.clone(),
                    access_rules: tmpl.access_rules.clone(),
                    auth_basic_realm: tmpl.auth_basic_realm.clone(),
                    auth_basic_user_file: tmpl.auth_basic_user_file.clone(),
                };
                let list = groups.entry(addr).or_default();
                if flags.default_server {
                    if defaults.contains_key(&addr) {
                        return Err(AppError::Other(format!(
                            "{addr} 上配置了多个 default_server，只能有一个"
                        )));
                    }
                    defaults.insert(addr, list.len());
                }
                list.push(Arc::new(server));
            }
        }

        // 按配置顺序组装监听端点
        let mut listeners = Vec::new();
        for addr in order {
            let ep = endpoints.get(&addr);
            let tls = ep.filter(|e| e.ssl).map(|e| TlsOptions {
                specs: tls_specs.remove(&addr).unwrap_or_default(),
                http2: e.http2,
                protocols: e.protocols.clone(),
            });
            if ep.map(|e| e.ssl).unwrap_or(false) && tls.as_ref().map(|t| t.specs.is_empty()).unwrap_or(true) {
                return Err(AppError::Other(format!("{addr} 需要 TLS 但没有加载到证书")));
            }
            listeners.push(Listener {
                addr,
                tls,
                http2: ep.map(|e| e.http2).unwrap_or(false),
                quic: ep.map(|e| e.quic).unwrap_or(false),
                backlog: ep.and_then(|e| e.backlog),
                ipv6only: ep.and_then(|e| e.ipv6only),
            });
        }

        // 默认 vhost 放到下标 0
        for (addr, idx) in &defaults {
            if let Some(list) = groups.get_mut(addr) {
                if *idx < list.len() && *idx != 0 {
                    list.swap(0, *idx);
                }
            }
        }
        // 没有显式 default_server 时，把"名字最少/第一个"的放前面（nginx：配置顺序第一个）
        let out_groups: HashMap<SocketAddr, AddrGroup> = groups
            .into_iter()
            .map(|(a, servers)| (a, AddrGroup { servers }))
            .collect();

        if !plain_conflicts.is_empty() {
            warnings.push(format!(
                "端点 {plain_conflicts:?} 同时被声明为明文与 TLS 监听，统一按 HTTPS 提供服务"
            ));
        }

        Ok(Router {
            groups: out_groups,
            listeners: listener_override.unwrap_or(listeners),
            warnings,
        })
    }

    /// 未知指令告警：拼错的指令静默失效是网关最难排查的一类故障
    fn warn_unknown(
        d: &Directive,
        known: &[&str],
        ctx: &str,
        warnings: &mut Vec<String>,
    ) {
        for child in &d.block {
            if child.name == "location" {
                continue;
            }
            if !known.contains(&child.name.as_str()) {
                warnings.push(format!(
                    "{ctx} 块第 {} 行：未知指令 '{name}'（已忽略，请检查拼写或是否尚未支持）",
                    child.line,
                    name = child.name
                ));
            }
        }
    }

    fn build_template(
        d: &Directive,
        base_dir: &PathBuf,
        limits: &[String],
        warnings: &mut Vec<String>,
    ) -> Result<ServerTemplate, AppError> {
        let mut tmpl = ServerTemplate {
            server_name: "localhost".to_string(),
            server_names: vec!["localhost".to_string()],
            locations: Vec::new(),
            root: None,
            index: vec!["index.html".to_string()],
            autoindex: false,
            error_pages: HashMap::new(),
            client_max_body_size: None,
            add_headers: Vec::new(),
            proxy_set_headers: Vec::new(),
            proxy_connect_timeout: 3,
            proxy_read_timeout: 60,
            proxy_send_timeout: 60,
            proxy_request_buffering: true,
            proxy_cache: None,
            proxy_cache_key: "$scheme$proxy_host$request_uri".to_string(),
            proxy_cache_methods: vec!["GET".to_string(), "HEAD".to_string()],
            proxy_cache_valid: Vec::new(),
            proxy_cache_min_uses: 1,
            proxy_tls: TlsPolicy::default(),
            limit_conn: Vec::new(),
            access_rules: Vec::new(),
            auth_basic_realm: None,
            auth_basic_user_file: None,
            ssl_cert: None,
            ssl_key: None,
            protocols: TlsProtocols::default(),
            http2: false,
        };
        if let Some(sn) = d.find("server_name") {
            let names: Vec<String> = sn
                .args
                .iter()
                .filter(|n| !n.eq_ignore_ascii_case("default_server"))
                .cloned()
                .collect();
            if !names.is_empty() {
                tmpl.server_names = names.clone();
                tmpl.server_name = names[0].clone();
            }
        }
        if let Some(root) = d.find("root").and_then(|x| x.arg(0)) {
            tmpl.root = Some(crate::resolve_path(root, base_dir));
        }
        if let Some(ix) = d.find("index") {
            let names: Vec<String> = ix.args.clone();
            if !names.is_empty() {
                tmpl.index = names;
            }
        }
        if let Some(ai) = d.find("autoindex") {
            tmpl.autoindex = ai.arg(0) == Some("on");
        }
        if let Some(v) = d
            .find("client_max_body_size")
            .and_then(|x| x.arg(0))
            .and_then(parse_size)
        {
            tmpl.client_max_body_size = Some(v);
        }
        if let Some(cert) = d.find("ssl_certificate").and_then(|x| x.arg(0)) {
            tmpl.ssl_cert = Some(crate::resolve_path(cert, base_dir));
        }
        if let Some(key) = d.find("ssl_certificate_key").and_then(|x| x.arg(0)) {
            tmpl.ssl_key = Some(crate::resolve_path(key, base_dir));
        }
        // ssl_min_version：等价于"该版本及以上全部启用"（向后兼容别名）。
        if let Some(v) = d.find("ssl_min_version").and_then(|x| x.arg(0)) {
            match TlsVersion::from_nginx_token(v) {
                Some(ver) => tmpl.protocols = TlsProtocols::from_min(ver),
                None => warnings.push(format!(
                    "ssl_min_version 不支持 '{v}'（可用 TLSv1/TLSv1.1/TLSv1.2/TLSv1.3），按 TLS1.2"
                )),
            }
        }
        // ssl_protocols：显式启用集合（nginx 语义），出现即以它为准，覆盖 ssl_min_version。
        if let Some(p) = d.find("ssl_protocols") {
            let mut set = TlsProtocols { enabled: Vec::new() };
            for tok in &p.args {
                match TlsVersion::from_nginx_token(tok) {
                    Some(ver) => set.set(ver),
                    None => {
                        let lk = tok.to_ascii_lowercase();
                        if lk == "sslv3" || lk == "ssl" {
                            warnings.push(format!(
                                "ssl_protocols 忽略 '{tok}'：SSLv3 已废弃且无任何后端支持"
                            ));
                        } else {
                            warnings.push(format!("ssl_protocols 无法识别的协议 '{tok}'"));
                        }
                    }
                }
            }
            if set.enabled.is_empty() {
                warnings.push("ssl_protocols 未列出任何可用协议，回落默认 TLSv1.2 TLSv1.3".to_string());
            } else {
                tmpl.protocols = set;
            }
        }
        if let Some(v) = d.find("http2").and_then(|x| x.arg(0)) {
            tmpl.http2 = v == "on" || v == "1.3.0" || v == "true";
        }
        for h in d.block.iter().filter(|x| x.name == "proxy_set_header") {
            if let (Some(k), Some(v)) = (h.arg(0), h.arg(1)) {
                tmpl.proxy_set_headers.push((k.to_string(), v.to_string()));
            }
        }
        for (name, slot) in [
            ("proxy_connect_timeout", &mut tmpl.proxy_connect_timeout),
            ("proxy_read_timeout", &mut tmpl.proxy_read_timeout),
            ("proxy_send_timeout", &mut tmpl.proxy_send_timeout),
        ] {
            if let Some(v) = d.find(name).and_then(|x| x.arg(0)) {
                *slot = parse_time_secs(v, *slot);
            }
        }
        if let Some(v) = d.find("proxy_request_buffering").and_then(|x| x.arg(0)) {
            match parse_on_off(v) {
                Some(b) => tmpl.proxy_request_buffering = b,
                None => warnings.push(format!(
                    "proxy_request_buffering 只接受 on/off（收到 '{v}'），保持 on"
                )),
            }
        }
        parse_proxy_ssl_directives(d, base_dir, warnings, &mut tmpl.proxy_tls);
        let cs = parse_cache_directives(d, warnings);
        if let Some(z) = cs.zone {
            tmpl.proxy_cache = z;
        }
        if cs.key.is_some() {
            tmpl.proxy_cache_key = cs.key.unwrap();
        }
        if cs.methods.is_some() {
            tmpl.proxy_cache_methods = cs.methods.unwrap();
        }
        if cs.has_valid {
            tmpl.proxy_cache_valid = cs.valid;
        }
        if cs.min_uses.is_some() {
            tmpl.proxy_cache_min_uses = cs.min_uses.unwrap();
        }
        for c in d.block.iter().filter(|x| x.name == "limit_conn") {
            match crate::limit::parse_conn_rule(c) {
                Some(rule) => {
                    if !limits.contains(&rule.zone) {
                        return Err(AppError::Other(format!(
                            "第 {} 行 limit_conn 引用了未声明的区域 '{}'",
                            c.line, rule.zone
                        )));
                    }
                    tmpl.limit_conn.push(rule);
                }
                None => {
                    return Err(AppError::Other(format!(
                        "第 {} 行 limit_conn 需要 `<zone> <number>`",
                        c.line
                    )))
                }
            }
        }
        tmpl.error_pages = parse_error_pages(d);
        tmpl.add_headers = parse_add_headers(d);
        let (a_rules, a_realm, a_file) =
            parse_access_directives(d, base_dir, "server", warnings)?;
        tmpl.access_rules = a_rules;
        tmpl.auth_basic_realm = a_realm;
        tmpl.auth_basic_user_file = a_file;

        for loc in d.block.iter().filter(|x| x.name == "location") {
            tmpl.locations
                .push(Self::build_location(loc, base_dir, &tmpl, limits, warnings)?);
        }
        Ok(tmpl)
    }

    fn build_location(
        d: &Directive,
        base_dir: &PathBuf,
        tmpl: &ServerTemplate,
        limits: &[String],
        warnings: &mut Vec<String>,
    ) -> Result<Location, AppError> {
        let (modifier, pattern) = match (d.arg(0), d.arg(1)) {
            (Some(m), Some(p)) if ["=", "^~", "~", "~*"].contains(&m) => (Some(m), p),
            (Some(p), _) => (None, p),
            _ => return Err(AppError::Other("location 缺少 pattern".into())),
        };
        let mut loc = Location {
            kind: LocationKind::parse(modifier, pattern)?,
            pattern: pattern.to_string(),
            rewrites: Vec::new(),
            ret: None,
            proxy_pass: None,
            proxy_set_headers: Vec::new(),
            proxy_read_timeout: tmpl.proxy_read_timeout,
            proxy_connect_timeout: tmpl.proxy_connect_timeout,
            proxy_send_timeout: tmpl.proxy_send_timeout,
            proxy_next_upstream: vec!["error".to_string(), "timeout".to_string()],
            proxy_request_buffering: tmpl.proxy_request_buffering,
            proxy_cache: tmpl.proxy_cache.clone(),
            proxy_cache_key: tmpl.proxy_cache_key.clone(),
            proxy_cache_methods: tmpl.proxy_cache_methods.clone(),
            proxy_cache_valid: tmpl.proxy_cache_valid.clone(),
            proxy_cache_min_uses: tmpl.proxy_cache_min_uses,
            proxy_tls: tmpl.proxy_tls.clone(),
            rust_phases: Vec::new(),
            lua_phases: Vec::new(),
            root: None,
            alias: None,
            index: None,
            try_files: None,
            autoindex: false,
            error_pages: HashMap::new(),
            add_headers: parse_add_headers(d),
            limit_req: Vec::new(),
            internal: false,
            client_max_body_size: None,
            access_rules: Vec::new(),
            auth_basic_realm: None,
            auth_basic_user_file: None,
        };
        Self::warn_unknown(
            d,
            &["rewrite", "return", "proxy_pass", "proxy_set_header", "proxy_read_timeout",
               "proxy_connect_timeout", "proxy_send_timeout", "proxy_next_upstream",
               "proxy_request_buffering",
               "proxy_cache", "proxy_cache_key", "proxy_cache_methods", "proxy_cache_valid", "proxy_cache_min_uses",
               "proxy_ssl_verify", "proxy_ssl_server_name", "proxy_ssl_name", "proxy_ssl_trusted_certificate",
               "root",
               "alias", "index", "try_files", "autoindex", "error_page", "add_header",
               "limit_req", "internal", "client_max_body_size", "content_by_lua",
               "content_by_lua_file", "access_by_lua", "access_by_lua_file", "rewrite_by_lua",
               "rewrite_by_lua_file", "header_filter_by_lua", "header_filter_by_lua_file",
               "body_filter_by_lua", "body_filter_by_lua_file",
               "log_by_lua", "log_by_lua_file",
               "balancer_by_lua", "balancer_by_lua_file",
               "content_by_rust", "access_by_rust", "rewrite_by_rust", "log_by_rust",
               "allow", "deny", "auth_basic", "auth_basic_user_file"],
            &format!("location '{}'", loc.pattern),
            warnings,
        );
        if let Some(v) = d.find("root").and_then(|x| x.arg(0)) {
            loc.root = Some(crate::resolve_path(v, base_dir));
        }
        if let Some(v) = d.find("alias").and_then(|x| x.arg(0)) {
            loc.alias = Some(crate::resolve_path(v, base_dir));
        }
        if let Some(ix) = d.find("index") {
            if !ix.args.is_empty() {
                loc.index = Some(ix.args.clone());
            }
        }
        if let Some(tf) = d.find("try_files") {
            if tf.args.len() >= 2 {
                loc.try_files = Some(tf.args.clone());
            } else {
                return Err(AppError::Other(format!(
                    "第 {} 行 try_files 至少需要一个文件和一个兜底项",
                    tf.line
                )));
            }
        }
        if let Some(ai) = d.find("autoindex") {
            loc.autoindex = ai.arg(0) == Some("on");
        }
        if d.find("internal").is_some() {
            loc.internal = true;
        }
        if let Some(v) = d
            .find("client_max_body_size")
            .and_then(|x| x.arg(0))
            .and_then(parse_size)
        {
            loc.client_max_body_size = Some(v);
        }
        let (rules, realm, user_file) =
            parse_access_directives(d, base_dir, &format!("location '{}'", loc.pattern), warnings)?;
        loc.access_rules = rules;
        loc.auth_basic_realm = realm;
        loc.auth_basic_user_file = user_file;
        loc.error_pages = parse_error_pages(d);
        if let Some(pp) = d.find("proxy_pass").and_then(|x| x.arg(0)) {
            loc.proxy_pass = Some(pp.to_string());
        }
        for h in d.block.iter().filter(|x| x.name == "proxy_set_header") {
            if let (Some(k), Some(v)) = (h.arg(0), h.arg(1)) {
                loc.proxy_set_headers.push((k.to_string(), v.to_string()));
            }
        }
        for (name, slot) in [
            ("proxy_connect_timeout", &mut loc.proxy_connect_timeout),
            ("proxy_read_timeout", &mut loc.proxy_read_timeout),
            ("proxy_send_timeout", &mut loc.proxy_send_timeout),
        ] {
            if let Some(v) = d.find(name).and_then(|x| x.arg(0)) {
                *slot = parse_time_secs(v, *slot);
            }
        }
        if let Some(nu) = d.find("proxy_next_upstream") {
            loc.proxy_next_upstream = nu.args.clone();
        }
        if let Some(v) = d.find("proxy_request_buffering").and_then(|x| x.arg(0)) {
            match parse_on_off(v) {
                Some(b) => loc.proxy_request_buffering = b,
                None => warnings.push(format!(
                    "proxy_request_buffering 只接受 on/off（收到 '{v}'），保持 {}",
                    if loc.proxy_request_buffering { "on" } else { "off" }
                )),
            }
        }
        parse_proxy_ssl_directives(d, base_dir, warnings, &mut loc.proxy_tls);
        let lcs = parse_cache_directives(d, warnings);
        if let Some(z) = lcs.zone {
            loc.proxy_cache = z;
        }
        if lcs.key.is_some() {
            loc.proxy_cache_key = lcs.key.unwrap();
        }
        if lcs.methods.is_some() {
            loc.proxy_cache_methods = lcs.methods.unwrap();
        }
        if lcs.has_valid {
            loc.proxy_cache_valid = lcs.valid;
        }
        if lcs.min_uses.is_some() {
            loc.proxy_cache_min_uses = lcs.min_uses.unwrap();
        }
        for r in d.block.iter().filter(|x| x.name == "limit_req") {
            match crate::limit::parse_req_rule(r) {
                Some(rule) => {
                    if !limits.contains(&rule.zone) {
                        return Err(AppError::Other(format!(
                            "location '{}' 第 {} 行 limit_req 引用了未声明的区域 '{}'",
                            loc.pattern, r.line, rule.zone
                        )));
                    }
                    loc.limit_req.push(rule);
                }
                None => {
                    return Err(AppError::Other(format!(
                        "第 {} 行 limit_req 需要 `zone=<name> [burst=n]`",
                        r.line
                    )))
                }
            }
        }
        for r in d.block.iter().filter(|x| x.name == "rewrite") {
            let pattern = r
                .arg(0)
                .ok_or_else(|| AppError::Other(format!("第 {} 行 rewrite 缺少 pattern", r.line)))?;
            let replacement = r
                .arg(1)
                .ok_or_else(|| AppError::Other(format!("第 {} 行 rewrite 缺少 replacement", r.line)))?;
            let flag = match r.arg(2) {
                Some("last") => RewriteFlag::Last,
                Some("break") => RewriteFlag::Break,
                Some("redirect") => RewriteFlag::Redirect,
                Some("permanent") => RewriteFlag::Permanent,
                None => RewriteFlag::Last,
                Some(other) => {
                    warnings.push(format!(
                        "rewrite 标志 '{other}'（第 {} 行）不支持，按 last 处理",
                        r.line
                    ));
                    RewriteFlag::Last
                }
            };
            loc.rewrites.push(RewriteRule {
                pattern: regex::Regex::new(pattern)
                    .map_err(|e| AppError::Other(format!("rewrite 正则错误 {pattern}: {e}")))?,
                replacement: replacement.to_string(),
                flag,
            });
        }
        if let Some(ret) = d.find("return") {
            match ret.arg(0).and_then(|s| s.parse::<u16>().ok()) {
                Some(code) => {
                    loc.ret = Some(ReturnAction {
                        code,
                        text: ret.arg(1).map(|s| s.to_string()),
                    });
                }
                None => {
                    if let Some(url) = ret.arg(0) {
                        loc.ret = Some(ReturnAction {
                            code: 302,
                            text: Some(url.to_string()),
                        });
                    } else {
                        return Err(AppError::Other(format!("第 {} 行 return 缺少参数", ret.line)));
                    }
                }
            }
        }
        for name in Phase::directive_names() {
            if let Some(dir) = d.find(name) {
                let phase = Phase::from_directive(name).unwrap();
                if let Some(spec) = crate::engine::spec_from_directive(dir) {
                    loc.rust_phases.push((phase, spec));
                }
            }
        }
        for name in [
            "rewrite_by_lua",
            "rewrite_by_lua_file",
            "access_by_lua",
            "access_by_lua_file",
            "content_by_lua",
            "content_by_lua_file",
            "header_filter_by_lua",
            "header_filter_by_lua_file",
            "body_filter_by_lua",
            "body_filter_by_lua_file",
            "log_by_lua",
            "log_by_lua_file",
            "balancer_by_lua",
            "balancer_by_lua_file",
        ] {
            if let Some(dir) = d.find(name) {
                let phase = match name.split('_').next().unwrap() {
                    "rewrite" => Phase::Rewrite,
                    "access" => Phase::Access,
                    "log" => Phase::Log,
                    "balancer" => Phase::Balancer,
                    _ => Phase::Content,
                };
                if let Some(src) = LuaSource::from_directive(dir, base_dir) {
                    loc.lua_phases.push((phase, name.to_string(), src));
                }
            }
        }
        Ok(loc)
    }

    /// 按真实监听地址 + Host 选 server（nginx ngx_http_find_virtual_server 的顺序）：
    /// 精确名 > `*.example.com`（最长）> `example.*`（最长）> default_server > 配置顺序第一个
    pub fn match_server(&self, local: SocketAddr, host: Option<&str>) -> Option<&Arc<Server>> {
        let group = self
            .groups
            .get(&local)
            // 兜底：同一端口其他地址绑定时共享 vhost 集合（例如 0.0.0.0 与 127.0.0.1 混配）
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|(a, _)| a.port() == local.port())
                    .map(|(_, g)| g)
            })?;
        let servers = &group.servers;
        if let Some(h) = host.map(strip_port).filter(|h| !h.is_empty()) {
            if let Some(s) = servers
                .iter()
                .find(|s| s.server_names.iter().any(|n| n.eq_ignore_ascii_case(h)))
            {
                return Some(s);
            }
            if let Some(s) = best_wildcard(servers, h, true) {
                return Some(s);
            }
            if let Some(s) = best_wildcard(servers, h, false) {
                return Some(s);
            }
        }
        servers
            .iter()
            .find(|s| s.is_default_server)
            .or(servers.first())
    }

    /// 启动/`-t` 用：每个监听端点上的 vhost 概况（运维只需看日志就知道 Host 会落到哪）
    pub fn describe_listeners(&self) -> Vec<String> {
        let mut out = Vec::new();
        for l in &self.listeners {
            let tls = match &l.tls {
                Some(_) => " TLS",
                None => "",
            };
            let names = self.groups.get(&l.addr).map_or(String::new(), |g| {
                g.servers
                    .iter()
                    .map(|s| {
                        if s.is_default_server {
                            format!("{}(default)", s.server_name)
                        } else {
                            s.server_name.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            out.push(format!("{}{tls} -> [{names}]", l.addr));
        }
        out
    }

    /// 选择 location（nginx 算法）
    pub fn match_location<'s>(server: &'s Server, path: &str) -> Option<&'s Location> {
        if let Some(l) = server.locations.iter().find(|l| {
            matches!(&l.kind, LocationKind::Exact(p) if p == path)
        }) {
            return Some(l);
        }
        let mut best_prefix: Option<(&Location, usize)> = None;
        for l in &server.locations {
            if let Some(p) = l.kind.prefix_path() {
                if path.starts_with(p) && best_prefix.map_or(true, |(_, len)| p.len() > len) {
                    best_prefix = Some((l, p.len()));
                }
            }
        }
        if let Some((l, _)) = best_prefix {
            if l.kind.is_caret() {
                return Some(l);
            }
        }
        for l in &server.locations {
            if !l.kind.is_regex() {
                continue;
            }
            let hit = match &l.kind {
                LocationKind::Regex(re) | LocationKind::RegexI(re) => re.is_match(path),
                _ => false,
            };
            if hit {
                return Some(l);
            }
        }
        best_prefix.map(|(l, _)| l)
    }
}

fn strip_port(host: &str) -> &str {
    if let Some((h, _)) = host.rsplit_once(']') {
        return h;
    }
    host.split(':').next().unwrap_or(host)
}

/// server_name 通配符：`*.example.com` / `example.*`
fn wildcard_match(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    if let Some(suf) = p.strip_prefix("*.") {
        h.ends_with(&format!(".{suf}"))
    } else if let Some(pre) = p.strip_suffix(".*") {
        h.starts_with(&format!("{pre}."))
    } else {
        false
    }
}

/// 通配符 vhost 里取最长匹配者：`prefix_form=true` 看 `*.example.com`，false 看 `example.*`
fn best_wildcard<'a>(
    servers: &'a [Arc<Server>],
    host: &str,
    prefix_form: bool,
) -> Option<&'a Arc<Server>> {
    let mut best: Option<(usize, &'a Arc<Server>)> = None;
    for s in servers {
        for n in &s.server_names {
            let form_ok = if prefix_form {
                n.starts_with("*.")
            } else {
                n.ends_with(".*")
            };
            if !form_ok || !wildcard_match(n, host) {
                continue;
            }
            if best.map_or(true, |(len, _)| n.len() > len) {
                best = Some((n.len(), s));
            }
        }
    }
    best.map(|(_, s)| s)
}

/// location 级 add_header 为空时回退到 server 级（nginx：location 一旦有 add_header 就完全覆盖 server 级）
pub fn effective_add_headers<'a>(
    loc: Option<&'a Location>,
    server: &'a Server,
) -> Vec<&'a (String, String)> {
    let mut out: Vec<&(String, String)> = Vec::new();
    if let Some(l) = loc {
        if !l.add_headers.is_empty() {
            out.extend(l.add_headers.iter());
            return out;
        }
    }
    out.extend(server.add_headers.iter());
    out
}

fn parse_add_headers(d: &Directive) -> Vec<(String, String)> {
    d.block
        .iter()
        .filter(|x| x.name == "add_header")
        .filter_map(|h| Some((h.arg(0)?.to_string(), h.arg(1)?.to_string())))
        .collect()
}

/// 解析 ACCESS 阶段指令：有序的 `allow`/`deny`，以及 `auth_basic`/`auth_basic_user_file`。
/// location 与 server 级共用。非法地址报错（与 nginx 启动期校验一致）；realm 的字面量
/// `off` 或空串视为关闭。
fn parse_access_directives(
    d: &Directive,
    base_dir: &PathBuf,
    where_name: &str,
    warnings: &mut Vec<String>,
) -> Result<(Vec<crate::access::AccessRule>, Option<String>, Option<PathBuf>), AppError> {
    let mut rules = Vec::new();
    // 保持 allow/deny 出现的相对顺序：遍历 block，按 name 分派
    for x in d.block.iter().filter(|x| x.name == "allow" || x.name == "deny") {
        let allow = x.name == "allow";
        if x.args.is_empty() {
            warnings.push(format!("{where_name} 第 {} 行 {} 缺少地址参数，忽略", x.line, x.name));
            continue;
        }
        let refs: Vec<&str> = x.args.iter().map(|s| s.as_str()).collect();
        match crate::access::parse_allow_arg(allow, &refs) {
            Some(rule) => rules.push(rule),
            None => {
                return Err(AppError::Other(format!(
                    "{where_name} 第 {} 行 {} 的地址无法解析（需 IPv4/IPv6/CIDR/all，收到 {:?}）",
                    x.line,
                    x.name,
                    x.args
                )))
            }
        }
    }

    // realm 三态：None=本层未设置（继承上层），Some("off")=显式关闭，Some(其它)=启用
    let realm = d
        .find("auth_basic")
        .and_then(|a| a.arg(0))
        .map(|s| {
            let t = s.trim();
            if t.is_empty() || t.eq_ignore_ascii_case("off") {
                "off".to_string()
            } else {
                t.to_string()
            }
        });
    let user_file = d
        .find("auth_basic_user_file")
        .and_then(|a| a.arg(0))
        .map(|p| crate::resolve_path(p, base_dir));

    if realm.as_deref().is_some_and(|v| v != "off") && user_file.is_none() {
        warnings.push(format!("{where_name} 配置了 auth_basic 却没有 auth_basic_user_file，认证将始终失败"));
    }
    Ok((rules, realm, user_file))
}

/// `proxy_set_header` 合并：server 级为默认，location 级同名覆盖
pub fn effective_proxy_headers<'a>(
    loc: &'a Location,
    server: &'a Server,
) -> Vec<(&'a str, &'a str)> {
    let mut out: Vec<(&str, &str)> = server
        .proxy_set_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    for (k, v) in &loc.proxy_set_headers {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
            *slot = (k.as_str(), v.as_str());
        } else {
            out.push((k.as_str(), v.as_str()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(s: &str) -> Config {
        Config::parse(s).unwrap()
    }

    fn build(s: &str) -> Router {
        Router::build(&cfg(s), &PathBuf::from(".")).unwrap()
    }

    const TWO_HOSTS: &str = r#"
        server {
            listen 127.0.0.1:18080;
            server_name a.example.com;
            location = /x { return 200 "a"; }
        }
        server {
            listen 127.0.0.1:18080;
            server_name b.example.com;
            location = /x { return 200 "b"; }
        }
        server {
            listen 127.0.0.1:18081 default_server;
            server_name c.example.com;
            location = /x { return 200 "c"; }
        }
    "#;

    #[test]
    fn routes_by_actual_listen_address_not_just_port() {
        let r = build(TWO_HOSTS);
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:18081".parse().unwrap();
        assert_eq!(
            r.match_server(a, Some("b.example.com")).unwrap().server_name,
            "b.example.com"
        );
        assert_eq!(
            r.match_server(b, Some("b.example.com")).unwrap().server_name,
            "c.example.com",
            "另一个监听地址上的 vhost 不应串到这里"
        );
    }

    #[test]
    fn host_with_port_still_matches() {
        let r = build(TWO_HOSTS);
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(
            r.match_server(a, Some("a.example.com:18080")).unwrap().server_name,
            "a.example.com"
        );
    }

    #[test]
    fn wildcard_vhost_prefers_exact_then_longest_wildcard_then_default() {
        let r = build(
            r#"server { listen 127.0.0.1:18087; server_name www.*; location / { return 200 suffix; } }
               server { listen 127.0.0.1:18087; server_name *.a.example.com; location / { return 200 short; } }
               server { listen 127.0.0.1:18087; server_name hit.example.com; location / { return 200 exact; } }
               server { listen 127.0.0.1:18087 default_server; server_name fallback; location / { return 200 default; } }"#,
        );
        let addr: SocketAddr = "127.0.0.1:18087".parse().unwrap();
        let pick =
            |h: &str| r.match_server(addr, Some(h)).unwrap().server_name.to_string();
        // 1. 精确名赢过所有通配
        assert_eq!(pick("hit.example.com"), "hit.example.com");
        // 2. 前缀通配命中
        assert_eq!(pick("q.a.example.com"), "*.a.example.com");
        // 3. 后缀通配命中
        assert_eq!(pick("www.long.io"), "www.*");
        // 4. 通配只匹配子域：*.a.example.com 不命中 a.example.com
        assert_eq!(pick("a.example.com"), "fallback");
        // 5. 都不匹配时走 default_server（不是配置顺序第一个）
        assert_eq!(pick("nothing.here"), "fallback");
        // 6. 大小写无关；没有 Host 头也走 default_server
        assert_eq!(pick("HIT.EXAMPLE.COM"), "hit.example.com");
        assert_eq!(r.match_server(addr, None).unwrap().server_name, "fallback");
    }

    #[test]
    fn unknown_directive_is_warned_not_silently_dropped() {
        let r = build(
            r#"server { listen 127.0.0.1:18099; server_name w; prxoy_pass http://127.0.0.1:1; }"#,
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("prxoy_pass")),
            "实际告警: {:?}",
            r.warnings
        );
    }

    #[test]
    fn rejects_unknown_listen_parameter() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080 spdy; }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("spdy"));
    }

    #[test]
    fn listen_backlog_and_ipv6only_flags_reach_the_listener() {
        let r = build("server { listen 18080 backlog=2048 ipv6only=off; }");
        let l = &r.listeners[0];
        assert_eq!(l.backlog, Some(2048));
        assert_eq!(l.ipv6only, Some(false));
        assert_eq!(l.addr, "0.0.0.0:18080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn listeners_follow_config_order() {
        let r = build(
            "server { listen 18082; } server { listen 18081; } server { listen 18083; }",
        );
        let ports: Vec<u16> = r.listeners.iter().map(|l| l.addr.port()).collect();
        assert_eq!(ports, vec![18082, 18081, 18083]);
    }

    #[test]
    fn multiple_listen_lines_share_one_server_block() {
        let r = build("server { listen 18084; listen 18085; server_name m; }");
        let ports: Vec<u16> = r.listeners.iter().map(|l| l.addr.port()).collect();
        assert!(ports.contains(&18084) && ports.contains(&18085));
        // 同一个 server 块要出现在两个监听端点的 vhost 集合里
        for port in [18084u16, 18085] {
            let s = r
                .match_server(format!("127.0.0.1:{port}").parse().unwrap(), Some("m"))
                .unwrap_or_else(|| panic!("{port} 上没有 vhost"));
            assert_eq!(s.server_name, "m");
        }
    }

    #[test]
    fn two_default_servers_on_one_endpoint_is_fatal() {
        let err = Router::build(
            &cfg(
                "server { listen 127.0.0.1:18080 default_server; } server { listen 127.0.0.1:18080 default_server; }",
            ),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("default_server"));
    }

    #[test]
    fn listen_forms() {
        assert_eq!(
            parse_listen_addr("8080").unwrap(),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("[::]:8080").unwrap(),
            "[::]:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(parse_listen_addr("nonsense"), None);
    }

    #[test]
    fn location_priority_matches_nginx() {
        let r = build(
            r#"server { listen 127.0.0.1:18080;
                 location / { return 200 root; }
                 location = /a/b/c/d { return 200 exact; }
                 location /a/ { return 200 prefix; }
                 location ^~ /a/b/ { return 200 caret; }
                 location ~ ^/a/b/c { return 200 regex1; }
                 location ~ ^/a/o { return 200 regex2; }
               }"#,
        );
        let s = r
            .match_server("127.0.0.1:18080".parse().unwrap(), None)
            .unwrap()
            .clone();
        let pick = |p: &str| Router::match_location(&s, p).unwrap().pattern.clone();
        // 精确匹配优先于一切（这里同时命中 ^~ 前缀与正则）
        assert_eq!(pick("/a/b/c/d"), "/a/b/c/d");
        // ^~ 前缀命中后不再检查正则（nginx：`^~` 只在"它是最长前缀"时抑制正则）
        assert_eq!(pick("/a/b/c/x"), "/a/b/");
        // 最长前缀不是 ^~ 时，按配置顺序取第一个命中的正则
        assert_eq!(pick("/a/other"), "^/a/o");
        assert_eq!(pick("/a/xyz"), "/a/");
        assert_eq!(pick("/zzz"), "/");
    }

    #[test]
    fn server_level_proxy_headers_merge_with_location() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_set_header X-A 1; proxy_set_header X-B 1;
                 location /p/ { proxy_pass http://127.0.0.1:1; proxy_set_header X-B 2; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        let loc = Router::match_location(&s, "/p/x").unwrap();
        let merged = effective_proxy_headers(loc, &s);
        assert!(merged.contains(&("X-A", "1")));
        assert!(merged.contains(&("X-B", "2")));
        assert!(!merged.contains(&("X-B", "1")));
    }

    #[test]
    fn proxy_request_buffering_defaults_on_and_inherits_overrides() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_request_buffering off;
                 location /inherited { proxy_pass http://127.0.0.1:1; }
                 location /forced-on  { proxy_pass http://127.0.0.1:1; proxy_request_buffering on; } }
            server { listen 127.0.0.1:18081; location / { proxy_pass http://127.0.0.1:1; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        // server 级 off 被 location 继承
        assert!(!Router::match_location(&s, "/inherited").unwrap().proxy_request_buffering);
        // location 级 on 覆盖 server 级 off
        assert!(Router::match_location(&s, "/forced-on").unwrap().proxy_request_buffering);
        // 未声明时默认 on（nginx 一致）
        let s2 = r.match_server("127.0.0.1:18081".parse().unwrap(), None).unwrap().clone();
        assert!(Router::match_location(&s2, "/").unwrap().proxy_request_buffering);
    }

    #[test]
    fn proxy_request_buffering_rejects_bad_value_keeps_default() {
        let r = build(
            "server { listen 127.0.0.1:18080; proxy_request_buffering maybe; location / { proxy_pass http://127.0.0.1:1; } }",
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        assert!(Router::match_location(&s, "/").unwrap().proxy_request_buffering, "非法取值应回落默认 on");
        assert!(r.warnings.iter().any(|w| w.contains("proxy_request_buffering")), "{:?}", r.warnings);
    }

    #[test]
    fn proxy_ssl_directives_parse_and_inherit() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; proxy_ssl_verify off;
                 proxy_ssl_name from-server;
                 location /inherited { proxy_pass https://127.0.0.1:1; }
                 location /override { proxy_pass https://127.0.0.1:1;
                     proxy_ssl_verify on; proxy_ssl_name from-loc; } }
            server { listen 127.0.0.1:18081; location / { proxy_pass http://127.0.0.1:1; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        // server 级 off + name 被 location 继承
        let inh = Router::match_location(&s, "/inherited").unwrap();
        assert!(!inh.proxy_tls.verify);
        assert_eq!(inh.proxy_tls.server_name.as_deref(), Some("from-server"));
        // location 级覆盖 server 级
        let ovr = Router::match_location(&s, "/override").unwrap();
        assert!(ovr.proxy_tls.verify);
        assert_eq!(ovr.proxy_tls.server_name.as_deref(), Some("from-loc"));
        // 未声明时默认 verify on、发 SNI、无覆盖名/无 trusted cert
        let s2 = r.match_server("127.0.0.1:18081".parse().unwrap(), None).unwrap().clone();
        let dflt = Router::match_location(&s2, "/").unwrap();
        assert!(dflt.proxy_tls.verify);
        assert!(dflt.proxy_tls.send_sni);
        assert_eq!(dflt.proxy_tls.server_name, None);
        assert_eq!(dflt.proxy_tls.trusted_cert, None);
    }

    #[test]
    fn proxy_ssl_rejects_bad_verify_value_keeps_default() {
        let r = build(
            "server { listen 127.0.0.1:18080; proxy_ssl_verify maybe; location / { proxy_pass https://127.0.0.1:1; } }",
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        assert!(
            Router::match_location(&s, "/").unwrap().proxy_tls.verify,
            "非法取值应回落默认 verify on"
        );
        assert!(r.warnings.iter().any(|w| w.contains("proxy_ssl_verify")), "{:?}", r.warnings);
    }

    #[test]
    fn limit_req_must_reference_declared_zone() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080; location / { limit_req zone=nope; } }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("未声明的区域"));
    }

    #[test]
    fn add_header_location_overrides_server() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; add_header X-S 1;
                 location /a { add_header X-L 1; }
                 location /b { return 200 x; } }"#,
        );
        let s = r.match_server("127.0.0.1:18080".parse().unwrap(), None).unwrap().clone();
        let loc_a = Router::match_location(&s, "/a").unwrap();
        assert_eq!(effective_add_headers(Some(loc_a), &s).len(), 1);
        let loc_b = Router::match_location(&s, "/b").unwrap();
        assert_eq!(effective_add_headers(Some(loc_b), &s).len(), 1);
    }

    #[test]
    fn try_files_needs_fallback() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18080; location / { try_files $uri; } }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("try_files"));
    }

    #[test]
    fn ssl_listen_without_cert_is_fatal() {
        let err = Router::build(
            &cfg("server { listen 127.0.0.1:18443 ssl; server_name x; }"),
            &PathBuf::from("."),
        )
        .unwrap_err();
        assert!(err.to_string().contains("ssl_certificate"));
    }

    #[test]
    fn quic_listen_implies_ssl_and_marks_the_listener() {
        let r = build(
            r#"server {
                listen 127.0.0.1:18443 quic;
                server_name x;
                ssl_certificate c.pem;
                ssl_certificate_key k.pem;
            }"#,
        );
        let l = &r.listeners[0];
        assert!(l.quic, "listen quic 应把 Listener.quic 置为 true");
        assert!(l.tls.is_some(), "quic 隐含 ssl：必须带 TLS 配置");
        // quic 但不带 http2（h2 走 TCP，h3 走 QUIC）
        assert!(!l.http2);
    }

    #[test]
    fn ssl_protocols_parses_explicit_set() {
        let tls_of = |conf: &str| {
            let r = build(conf);
            r.listeners[0].tls.as_ref().unwrap().protocols.clone()
        };

        // 显式单版本集合：可裁剪掉另一版本
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_protocols TLSv1.2; }"#)
                .enabled,
            vec![TlsVersion::Tls12]
        );
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_protocols TLSv1.3; }"#)
                .enabled,
            vec![TlsVersion::Tls13]
        );
        // 四个都写：升序去重，含旧版本
        let all = tls_of(
            r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem; ssl_certificate_key k.pem;
                 ssl_protocols TLSv1.3 TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; }"#,
        );
        assert_eq!(
            all.enabled,
            vec![TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13]
        );
        assert!(all.wants_legacy());

        // 默认（不写任何 TLS 协议指令）= TLS1.2 + TLS1.3
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; }"#)
                .enabled,
            vec![TlsVersion::Tls12, TlsVersion::Tls13]
        );

        // ssl_min_version 别名仍生效：min=TLSv1.3 → 只剩 1.3
        assert_eq!(
            tls_of(r#"server { listen 127.0.0.1:18443 ssl; ssl_certificate c.pem;
                 ssl_certificate_key k.pem; ssl_min_version TLSv1.3; }"#)
                .enabled,
            vec![TlsVersion::Tls13]
        );

        // 同一 socket 上两个 server 的 ssl_protocols 取并集
        let merged = tls_of(
            r#"server { listen 127.0.0.1:18443 ssl; server_name a; ssl_certificate c.pem;
                     ssl_certificate_key k.pem; ssl_protocols TLSv1.2; }
               server { listen 127.0.0.1:18443 ssl; server_name b; ssl_certificate c.pem;
                     ssl_certificate_key k.pem; ssl_protocols TLSv1.3; }"#,
        );
        assert_eq!(merged.enabled, vec![TlsVersion::Tls12, TlsVersion::Tls13]);
    }

    #[test]
    fn default_server_goes_first() {
        let r = build(
            r#"server { listen 127.0.0.1:18080; server_name first; }
               server { listen 127.0.0.1:18080 default_server; server_name chosen; }"#,
        );
        let a: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        assert_eq!(r.match_server(a, Some("unknown.com")).unwrap().server_name, "chosen");
        assert_eq!(r.match_server(a, None).unwrap().server_name, "chosen");
    }

    #[test]
    fn rebuild_routing_updates_locations_but_keeps_bound_listeners() {
        let base = r#"
            server {
                listen 127.0.0.1:18090;
                server_name reload.test;
                location = /x { return 200 "old"; }
            }
        "#;
        let r0 = build(base);
        // 模拟进程实际绑定的监听集合（reload 期间不得改变）
        let bound = r0.listeners.clone();

        let updated = r#"
            server {
                listen 127.0.0.1:18090;
                server_name reload.test;
                location = /x { return 200 "new"; }
                location = /added { return 200 "added"; }
            }
        "#;
        let r1 = Router::rebuild_routing(&cfg(updated), &PathBuf::from("."), &bound).unwrap();

        let a: SocketAddr = "127.0.0.1:18090".parse().unwrap();
        // 路由表更新：新增的 location 现在能命中，正文也换成新值
        let srv = r1.match_server(a, Some("reload.test")).unwrap();
        let loc = Router::match_location(srv, "/added").unwrap();
        assert!(loc.ret.as_ref().and_then(|r| r.text.as_ref()).is_some_and(|b| b.contains("added")));
        let loc_x = Router::match_location(srv, "/x").unwrap();
        assert!(loc_x.ret.as_ref().and_then(|r| r.text.as_ref()).is_some_and(|b| b.contains("new")));

        // 监听集合原样保留（即便新配置里没提这个地址，也不新增/删除 socket）
        let addrs = |ls: &[Listener]| ls.iter().map(|l| l.addr).collect::<Vec<_>>();
        assert_eq!(addrs(&r1.listeners), addrs(&bound));

        // 新配置引入了一个**未绑定**的监听地址：rebuild_routing 不应把它加进来
        let with_new_port = r#"
            server { listen 127.0.0.1:18090; location = /x { return 200 "a"; } }
            server { listen 127.0.0.1:18099; location = /x { return 200 "b"; } }
        "#;
        let r2 = Router::rebuild_routing(&cfg(with_new_port), &PathBuf::from("."), &bound).unwrap();
        assert_eq!(addrs(&r2.listeners), addrs(&bound), "热重载不绑定新监听地址（需重启）");
        // 已绑定的 18090 仍能正常路由
        assert!(r2.match_server(a, None).is_some());
    }
}
