//! 请求路由与配置模型：server 块 / location 匹配（nginx 语义）。
//!
//! location 匹配算法（与 nginx 一致）：
//!   1. `= /exact` 精确匹配命中 → 直接使用
//!   2. 记录最长前缀匹配；若该前缀带 `^~` → 直接使用（跳过正则）
//!   3. 否则按配置顺序找第一个命中的正则（`~` 或 `~*`）→ 使用
//!   4. 都没有 → 用第 2 步的最长前缀
//!
//! server 匹配（Host）：精确名 > 通配符（*.example.com / example.*）> 默认第一个
//!
//! 支持 nginx 指令：listen、server_name（多值+通配符）、root、alias、index、
//! autoindex、try_files、error_page、client_max_body_size、return、rewrite、
//! add_header、proxy_pass、proxy_set_header、proxy_read_timeout、
//! *_by_lua[_file]、*_by_rust、ssl_certificate[_key]。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use learnon_config::{Config, Directive};

use crate::engine::{HandlerSpec, Phase, ReturnAction, RewriteFlag, RewriteRule};
use crate::lua_engine::LuaSource;
use crate::upstream::UpstreamPool;
use crate::AppError;

// ---------- location 匹配 ----------

#[derive(Debug, Clone)]
pub enum LocationKind {
    /// `location = /exact`
    Exact(String),
    /// `location /prefix`（caret = `^~`：命中即赢过正则）
    Prefix { path: String, caret: bool },
    /// `location ~ regex`（区分大小写）
    Regex(regex::Regex),
    /// `location ~* regex`（不区分大小写）
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
            Some("~") => LocationKind::Regex(regex::Regex::new(pattern).map_err(|e| {
                AppError::Other(format!("location 正则错误 {pattern}: {e}"))
            })?),
            Some("~*") => LocationKind::RegexI(
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| {
                        AppError::Other(format!("location 正则错误 {pattern}: {e}"))
                    })?,
            ),
            None => LocationKind::Prefix {
                path: pattern.to_string(),
                caret: false,
            },
            Some(other) => {
                return Err(AppError::Other(format!(
                    "暂不支持的 location 修饰符 '{other}'"
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
    /// 原始 pattern（日志/调试/alias 前缀剥离）
    pub pattern: String,
    /// rewrite 规则（按配置顺序）
    pub rewrites: Vec<RewriteRule>,
    pub ret: Option<ReturnAction>,
    pub proxy_pass: Option<String>,
    pub proxy_set_headers: Vec<(String, String)>,
    pub proxy_read_timeout: u64,
    /// rust 原生阶段（rewrite/access/content_by_rust）
    pub rust_phases: Vec<(Phase, HandlerSpec)>,
    /// lua 阶段（rewrite/access/content_by_lua[_file]）
    pub lua_phases: Vec<(Phase, String, LuaSource)>,
    /// `root <dir>`：URI 完整路径追加到 root 后（nginx 语义）
    pub root: Option<PathBuf>,
    /// `alias <dir>`：location 前缀之后的部分映射到 alias（nginx 语义）
    pub alias: Option<PathBuf>,
    /// `index <file>...`；None 继承 server 级
    pub index: Option<Vec<String>>,
    /// `try_files <file>... <fallback>`
    pub try_files: Option<Vec<String>>,
    /// `autoindex on`
    pub autoindex: bool,
    /// `error_page <code>... <uri>`
    pub error_pages: HashMap<u16, String>,
    pub add_headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub listen: u16,
    /// 第一个 server_name（兼容字段）
    pub server_name: String,
    /// 全部 server_name（支持通配符）
    pub server_names: Vec<String>,
    pub locations: Vec<Location>,
    pub root: Option<PathBuf>,
    pub index: Vec<String>,
    pub autoindex: bool,
    /// server 级 error_page（location 级优先）
    pub error_pages: HashMap<u16, String>,
    /// `client_max_body_size <size>`；None = 不限制
    pub client_max_body_size: Option<u64>,
    pub add_headers: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct Router {
    pub by_port: std::collections::HashMap<u16, Vec<Arc<Server>>>,
    pub listeners: Vec<Listener>,
}

/// 一个监听端口（可带 TLS 配置）
#[derive(Debug, Clone)]
pub struct Listener {
    pub addr: std::net::SocketAddr,
    /// `listen 8443 ssl` + ssl_certificate / ssl_certificate_key
    pub tls: Option<TlsPaths>,
}

#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// 解析 nginx 大小后缀：1m / 10k / 纯字节数
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix(['m', 'M']) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix(['k', 'K']) {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix(['g', 'G']) {
        (n, 1024 * 1024 * 1024u64)
    } else {
        (s, 1u64)
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// 解析 error_page 指令组：`error_page 404 403 /x.html;`（`=` 覆盖码形式暂按目标处理）
fn parse_error_pages(d: &Directive) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    for ep in d.block.iter().filter(|x| x.name == "error_page") {
        let args: Vec<&str> = ep.args.iter().map(|s| s.as_str()).collect();
        // 最后一个以 '/' 开头的参数作为目标 URI
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

impl Router {
    pub fn build(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        let mut by_port = std::collections::HashMap::new();
        let mut listeners = Vec::new();
        for d in config.servers() {
            // 一个 server 块可有多条 listen（如 8080 + 8443 ssl）
            for (s, tls) in Self::build_server(d, base_dir)? {
                let s = Arc::new(s);
                if !by_port.contains_key(&s.listen) {
                    listeners.push(Listener {
                        addr: std::net::SocketAddr::from(([127, 0, 0, 1], s.listen)),
                        tls,
                    });
                }
                by_port.entry(s.listen).or_insert_with(Vec::new).push(s);
            }
        }
        Ok(Router { by_port, listeners })
    }

    fn build_server(
        d: &Directive,
        base_dir: &PathBuf,
    ) -> Result<Vec<(Server, Option<TlsPaths>)>, AppError> {
        let mut server = Server {
            listen: 8080,
            server_name: "localhost".to_string(),
            server_names: vec!["localhost".to_string()],
            locations: Vec::new(),
            root: None,
            index: vec!["index.html".to_string()],
            autoindex: false,
            error_pages: HashMap::new(),
            client_max_body_size: None,
            add_headers: Vec::new(),
        };
        // TLS：收集全部 listen 指令；`listen <port> ssl` 需要 ssl_certificate / ssl_certificate_key
        let mut listens: Vec<(u16, bool)> = Vec::new();
        for l in d.block.iter().filter(|x| x.name == "listen") {
            if let Some(port) = l
                .arg(0)
                .and_then(|s| s.split(':').next_back())
                .and_then(|s| s.parse().ok())
            {
                let ssl = l.args.iter().skip(1).any(|a| a == "ssl");
                listens.push((port, ssl));
            }
        }
        if listens.is_empty() {
            listens.push((8080, false));
        }
        let tls_of = |ssl: bool| -> Result<Option<TlsPaths>, AppError> {
            if !ssl {
                return Ok(None);
            }
            let cert = d
                .find("ssl_certificate")
                .and_then(|x| x.arg(0))
                .ok_or_else(|| AppError::Other("listen ssl 缺少 ssl_certificate".into()))?;
            let key = d
                .find("ssl_certificate_key")
                .and_then(|x| x.arg(0))
                .ok_or_else(|| AppError::Other("listen ssl 缺少 ssl_certificate_key".into()))?;
            Ok(Some(TlsPaths {
                cert: crate::resolve_path(cert, base_dir),
                key: crate::resolve_path(key, base_dir),
            }))
        };
        // server_name：多值 + 通配符（*.example.com / example.*）
        if let Some(sn) = d.find("server_name") {
            let names: Vec<String> = sn
                .args
                .iter()
                .filter(|n| !n.eq_ignore_ascii_case("default_server"))
                .map(|n| n.to_string())
                .collect();
            if !names.is_empty() {
                server.server_names = names.clone();
                server.server_name = names[0].clone();
            }
        }
        if let Some(root) = d.find("root").and_then(|x| x.arg(0)) {
            server.root = Some(crate::resolve_path(root, base_dir));
        }
        if let Some(ix) = d.find("index") {
            let names: Vec<String> = ix.args.iter().map(|s| s.to_string()).collect();
            if !names.is_empty() {
                server.index = names;
            }
        }
        if let Some(ai) = d.find("autoindex") {
            server.autoindex = ai.arg(0) == Some("on");
        }
        if let Some(cms) = d
            .find("client_max_body_size")
            .and_then(|x| x.arg(0))
            .and_then(parse_size)
        {
            server.client_max_body_size = Some(cms);
        }
        server.error_pages = parse_error_pages(d);
        server.add_headers = parse_add_headers(d);

        for loc in d.block.iter().filter(|x| x.name == "location") {
            server.locations.push(Self::build_location(loc, base_dir)?);
        }
        // 每个 listen 端口生成一个 Server 实例（TLS 只挂在 ssl 端口上）
        let mut out = Vec::new();
        for (port, ssl) in &listens {
            let mut s = server.clone();
            s.listen = *port;
            out.push((s, tls_of(*ssl)?));
        }
        Ok(out)
    }

    fn build_location(d: &Directive, base_dir: &PathBuf) -> Result<Location, AppError> {
        // location [=|^~|~|~*] pattern
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
            proxy_read_timeout: 60,
            rust_phases: Vec::new(),
            lua_phases: Vec::new(),
            root: None,
            alias: None,
            index: None,
            try_files: None,
            autoindex: false,
            error_pages: HashMap::new(),
            add_headers: parse_add_headers(d),
        };
        if let Some(root) = d.find("root").and_then(|x| x.arg(0)) {
            loc.root = Some(crate::resolve_path(root, base_dir));
        }
        if let Some(alias) = d.find("alias").and_then(|x| x.arg(0)) {
            loc.alias = Some(crate::resolve_path(alias, base_dir));
        }
        if let Some(ix) = d.find("index") {
            let names: Vec<String> = ix.args.iter().map(|s| s.to_string()).collect();
            if !names.is_empty() {
                loc.index = Some(names);
            }
        }
        if let Some(tf) = d.find("try_files") {
            let v: Vec<String> = tf.args.iter().map(|s| s.to_string()).collect();
            if v.len() >= 2 {
                loc.try_files = Some(v);
            }
        }
        if let Some(ai) = d.find("autoindex") {
            loc.autoindex = ai.arg(0) == Some("on");
        }
        loc.error_pages = parse_error_pages(d);
        if let Some(pp) = d.find("proxy_pass").and_then(|x| x.arg(0)) {
            loc.proxy_pass = Some(pp.to_string());
        }
        for h in d.block.iter().filter(|x| x.name == "proxy_set_header") {
            if let (Some(k), Some(v)) = (h.arg(0), h.arg(1)) {
                loc.proxy_set_headers.push((k.to_string(), v.to_string()));
            }
        }
        if let Some(t) = d.find("proxy_read_timeout").and_then(|x| x.arg(0)) {
            loc.proxy_read_timeout = t.parse().unwrap_or(60);
        }
        for r in d.block.iter().filter(|x| x.name == "rewrite") {
            let pattern = r.arg(0).ok_or_else(|| AppError::Other("rewrite 缺少 pattern".into()))?;
            let replacement = r.arg(1).ok_or_else(|| AppError::Other("rewrite 缺少 replacement".into()))?;
            let flag = match r.arg(2) {
                Some("last") => RewriteFlag::Last,
                Some("break") => RewriteFlag::Break,
                Some("redirect") => RewriteFlag::Redirect,
                Some("permanent") => RewriteFlag::Permanent,
                None | Some(_) => RewriteFlag::Last,
            };
            loc.rewrites.push(RewriteRule {
                pattern: regex::Regex::new(pattern)
                    .map_err(|e| AppError::Other(format!("rewrite 正则错误 {pattern}: {e}")))?,
                replacement: replacement.to_string(),
                flag,
            });
        }
        if let Some(ret) = d.find("return") {
            // nginx 语义：`return <code> [text|URL]`；`return <URL>` 等价 302 重定向
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
                    }
                }
            }
        }
        // *_by_rust 处理器
        for name in Phase::directive_names() {
            if let Some(dir) = d.find(name) {
                let phase = Phase::from_directive(name).unwrap();
                if let Some(spec) = crate::engine::spec_from_directive(dir) {
                    loc.rust_phases.push((phase, spec));
                }
            }
        }
        // *_by_lua / *_by_lua_file 脚本
        for name in ["rewrite_by_lua", "rewrite_by_lua_file", "access_by_lua", "access_by_lua_file", "content_by_lua", "content_by_lua_file"] {
            if let Some(dir) = d.find(name) {
                let phase = match name.split('_').next().unwrap() {
                    "rewrite" => Phase::Rewrite,
                    "access" => Phase::Access,
                    _ => Phase::Content,
                };
                if let Some(src) = LuaSource::from_directive(dir, base_dir) {
                    loc.lua_phases.push((phase, name.to_string(), src));
                }
            }
        }
        Ok(loc)
    }

    /// server_name 通配符匹配：`*.example.com` / `example.*`
    fn wildcard_match(pattern: &str, host: &str) -> bool {
        if let Some(suf) = pattern.strip_prefix("*.") {
            host.to_ascii_lowercase().ends_with(&format!(".{}", suf.to_ascii_lowercase()))
        } else if let Some(pre) = pattern.strip_suffix(".*") {
            host.to_ascii_lowercase().starts_with(&format!("{}.", pre.to_ascii_lowercase()))
        } else {
            false
        }
    }

    /// 选择 server（Host 匹配，nginx 优先级）：精确名 > 通配符 > 第一个
    pub fn match_server(&self, port: u16, host: Option<&str>) -> Option<&Arc<Server>> {
        let servers = self.by_port.get(&port)?;
        let host = host.map(|h| h.split(':').next().unwrap_or(h)).unwrap_or("");
        if !host.is_empty() {
            if let Some(s) = servers
                .iter()
                .find(|s| s.server_names.iter().any(|n| n.eq_ignore_ascii_case(host)))
            {
                return Some(s);
            }
            if let Some(s) = servers
                .iter()
                .find(|s| s.server_names.iter().any(|n| Self::wildcard_match(n, host)))
            {
                return Some(s);
            }
        }
        servers.first()
    }

    /// 选择 location（nginx 算法）：
    /// 精确 → 最长前缀（`^~` 则跳过正则）→ 配置顺序第一个正则 → 最长前缀
    pub fn match_location<'s>(server: &'s Server, path: &str) -> Option<&'s Location> {
        // 1. 精确匹配
        if let Some(l) = server.locations.iter().find(|l| {
            matches!(&l.kind, LocationKind::Exact(p) if p == path)
        }) {
            return Some(l);
        }
        // 2. 最长前缀
        let mut best_prefix: Option<(&Location, usize)> = None;
        for l in &server.locations {
            if let Some(p) = l.kind.prefix_path() {
                if path.starts_with(p)
                    && best_prefix.map_or(true, |(_, len)| p.len() > len)
                {
                    best_prefix = Some((l, p.len()));
                }
            }
        }
        if let Some((l, _)) = best_prefix {
            if l.kind.is_caret() {
                return Some(l); // ^~：赢过正则
            }
        }
        // 3. 按配置顺序找第一个命中的正则
        for l in &server.locations {
            if !l.kind.is_regex() {
                continue;
            }
            let hit = match &l.kind {
                LocationKind::Regex(re) => re.is_match(path),
                LocationKind::RegexI(re) => re.is_match(path),
                _ => false,
            };
            if hit {
                return Some(l);
            }
        }
        // 4. 最长前缀兜底
        best_prefix.map(|(l, _)| l)
    }
}

fn parse_add_headers(d: &Directive) -> Vec<(String, String)> {
    d.block
        .iter()
        .filter(|x| x.name == "add_header")
        .filter_map(|h| Some((h.arg(0)?.to_string(), h.arg(1)?.to_string())))
        .collect()
}

// 保留 upstream 引用避免未使用告警（proxy 引擎持有 pool，Router 不直接用）
pub type _PoolRef = UpstreamPool;
