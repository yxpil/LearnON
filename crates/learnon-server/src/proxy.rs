//! 反向代理：对标 Nginx 的 `proxy_pass`。
//!
//! - 支持 `proxy_pass http://upstream_name`（走 upstream 负载均衡）
//! - 支持 `proxy_pass http://host:port`（直连）
//! - 支持 `proxy_set_header` 覆盖/新增转发头（含 $remote_addr/$host/$scheme/$server_port/
//!   $proxy_add_x_forwarded_for 插值）
//! - `proxy_connect_timeout` 控制连接超时，`proxy_read_timeout` 控制等待响应头的超时
//! - `proxy_next_upstream error timeout ...` 决定是否换节点重试
//!
//! 与 nginx 的差异（有意为之，避免踩坑）：
//! - 请求体先缓冲再转发（Lua/限流/体大小检查都需要完整体），因此
//!   `proxy_send_timeout` 无法单独生效；响应体仍是流式转发。
//! - 转发时重算 `Content-Length`：客户端谎报长度或同时带 TE/CL 时不能把畸形透传给后端。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue, CONTENT_LENGTH, HOST};
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use http_body_util::Full;

use crate::engine::RequestCtx;
use crate::upstream::{UpstreamGuard, UpstreamPool};
use crate::{log_warn};

type HyperClient = Client<HttpConnector, Full<Bytes>>;

/// 每个代理 location 的超时（连接级 + 读响应头级）
#[derive(Debug, Clone, Copy)]
pub struct ProxyTimeouts {
    pub connect: Duration,
    pub read: Duration,
}

/// `forward` 的可选参数包（避免 6 个位置参数互相混淆）
pub struct ProxyOpts<'a> {
    /// 已按 server/location 合并好的 proxy_set_header
    pub set_headers: &'a [(&'a str, &'a str)],
    pub timeouts: ProxyTimeouts,
    /// `proxy_next_upstream` 的取值列表
    pub next_upstream: &'a [String],
}

/// 每个监听进程一个共享连接池客户端；连接池按 connect 超时分组
pub struct ProxyEngine {
    pool: Arc<UpstreamPool>,
    clients: Mutex<HashMap<u64, HyperClient>>,
}

impl ProxyEngine {
    pub fn new(pool: Arc<UpstreamPool>) -> Self {
        ProxyEngine {
            pool,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// 同一 connect 超时复用同一个客户端（= 同一个连接池），避免每个 location 建一套池
    fn client(&self, connect: Duration) -> HyperClient {
        let key = connect.as_millis() as u64;
        let mut map = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = map.get(&key) {
            return c.clone();
        }
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .build(connector);
        map.insert(key, client.clone());
        client
    }

    /// 执行反代。`target` 是 proxy_pass 的值（http:// 后面的部分），
    /// 与 upstream 名匹配时走负载均衡，否则当作 host:port 直连。
    pub async fn forward(
        &self,
        ctx: &RequestCtx,
        target: &str,
        loc_prefix: &str,
        opts: &ProxyOpts<'_>,
        raw_body: Option<Bytes>,
    ) -> Result<Response<Incoming>, String> {
        if target.starts_with("https://") {
            return Err(
                "proxy_pass 暂不支持 https 后端（需要可信根证书库，当前离线依赖里没有）".to_string(),
            );
        }
        // 解析目标：http://host[:port][/path]
        // 带路径时替换 location 前缀（对标 nginx proxy_pass 的 URI 语义）
        let rest = target.trim_start_matches("http://");
        let (host_part, uri_part) = match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), Some(format!("/{p}"))),
            None => (rest.to_string(), None),
        };
        // upstream 负载均衡：guard 存活期间连接计数 +1，并用于健康检查上报
        let mut guard_holder: Option<UpstreamGuard> = None;
        let backend = if let Some(up) = self.pool.get(&host_part) {
            let g = up.acquire(&ctx.remote_addr);
            let addr = (*g).clone();
            guard_holder = Some(g);
            addr
        } else {
            host_part.clone()
        };
        // 健康上报：模块级函数避免闭包借用与 async 冲突
        fn note(guard_holder: &Option<UpstreamGuard>, ok: bool) {
            if let Some(g) = guard_holder {
                if ok {
                    g.note_success();
                } else {
                    g.note_failure();
                }
            }
        }

        let out_path = match uri_part {
            Some(repl) => {
                let rel = match ctx.effective_path().strip_prefix(loc_prefix) {
                    Some(r) => r,
                    None => ctx.effective_path(),
                };
                let rel = if rel.is_empty() { "/" } else { rel };
                let base = repl.trim_end_matches('/');
                if rel.starts_with('/') {
                    format!("{base}{rel}")
                } else {
                    format!("{base}/{rel}")
                }
            }
            None => ctx.effective_path().to_string(),
        };
        let query = if ctx.query.is_empty() {
            String::new()
        } else {
            format!("?{}", ctx.query)
        };

        // 转发请求头：复制后按 proxy_set_header 覆盖（构建一次，重试时 clone）
        let mut headers = HeaderMap::new();
        for (k, v) in &ctx.req_headers {
            if is_hop_by_hop(k) || k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("expect")
            {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_bytes()),
                HeaderValue::try_from(v.as_str()),
            ) {
                headers.append(name, val);
            }
        }
        for (k, v) in opts.set_headers {
            let name = hyper::header::HeaderName::try_from(*k)
                .map_err(|e| format!("非法的 proxy_set_header 名 {k}: {e}"))?;
            let val = interpolate_vars(v, ctx);
            headers.insert(name, HeaderValue::try_from(val).map_err(|e| e.to_string())?);
        }
        if !headers.contains_key(HOST) {
            // nginx 默认把 Host 改写成后端主机名；LearnON 保留客户端 Host（后端虚拟主机更常用），
            // 需要 nginx 行为时显式写 `proxy_set_header Host <后端名>;`
            if let Some(h) = &ctx.host {
                headers.insert(HOST, HeaderValue::try_from(h.as_str()).unwrap());
            }
        }

        // 请求体已由 server 层缓冲后传入：Content-Length 按真实字节数重算
        let body_bytes = raw_body.unwrap_or_default();
        if !(ctx.is_bodyless_method() || body_bytes.is_empty()) {
            if let Ok(v) = HeaderValue::try_from(body_bytes.len().to_string()) {
                headers.insert(CONTENT_LENGTH, v);
            }
        }

        // proxy_next_upstream：off 完全禁止换节点；非幂等请求（POST/LOCK/PATCH）默认不重试
        let next = opts.next_upstream;
        let next_off = next.iter().any(|v| v == "off");
        let on_error = !next_off && next.iter().any(|v| v == "error");
        let on_timeout = !next_off && next.iter().any(|v| v == "timeout");
        let idempotent = is_idempotent(&ctx.method);

        let mut backend = backend;
        let mut last_err = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                if let Some(up) = self.pool.get(&host_part) {
                    let g = up.acquire(&ctx.remote_addr);
                    backend = (*g).clone();
                    guard_holder = Some(g);
                }
                log_warn!("upstream {host_part} 换节点重试: {backend}");
            }
            let uri = format!(
                "http://{backend}{}{query}",
                encode_path(&out_path),
            );
            let mut req = Request::builder()
                .method(ctx.method.as_str())
                .uri(&uri)
                .version(hyper::Version::HTTP_11)
                .body(Full::new(body_bytes.clone()))
                .map_err(|e| e.to_string())?;
            *req.headers_mut() = headers.clone();

            let client = self.client(opts.timeouts.connect);
            // 整体作为"连接+发送+等响应头"一次等待；read 超时单独判定以便区分错误类型
            match tokio::time::timeout(opts.timeouts.read, client.request(req)).await {
                Ok(Ok(r)) => {
                    note(&guard_holder, true);
                    return Ok(r);
                }
                Ok(Err(e)) => {
                    note(&guard_holder, false);
                    last_err = format!("代理请求失败 {backend}: {e} | 根因: {}", error_root(&e));
                    if idempotent && on_error && attempt == 0 {
                        continue;
                    }
                    return Err(last_err);
                }
                Err(_) => {
                    note(&guard_holder, false);
                    last_err = format!("proxy_read_timeout ({:?}) 超时: {backend}", opts.timeouts.read);
                    if idempotent && on_timeout && attempt == 0 {
                        continue;
                    }
                    return Err(last_err);
                }
            }
        }
        Err(last_err)
    }
}

/// 路径按段重新做百分号编码后转发：
/// location 匹配用的是解码后的路径，而 URI 语法不允许空格/控制字符/裸 UTF-8 字节，
/// 直接把解码结果拼进转发 URI 会让后端收到非法请求行（含中文文件名、带空格的路径必现）。
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(crate::lua_engine::escape_uri)
        .collect::<Vec<_>>()
        .join("/")
}

/// nginx：非幂等请求（有副作用的）默认不参与 next_upstream 重试
fn is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PROPFIND" | "COPY" | "MOVE" | "MKCOL" | "LOCK"
            | "UNLOCK" | "SEARCH"
    )
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization"
            | "te" | "trailer" | "transfer-encoding" | "upgrade"
    )
}

/// 展开错误源链，便于诊断
fn error_root(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    loop {
        match cur.source() {
            Some(s) => cur = s,
            None => return cur.to_string(),
        }
    }
}

/// 配置值里的内置变量插值（proxy_set_header 与 rust handler 共用）
pub fn interpolate_vars(template: &str, ctx: &RequestCtx) -> String {
    let xff = {
        let existing = ctx
            .req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if existing.is_empty() {
            ctx.remote_addr.clone()
        } else {
            format!("{existing}, {}", ctx.remote_addr)
        }
    };
    let mut out = template
        .replace("$remote_addr", &ctx.remote_addr)
        .replace("$remote_port", &ctx.remote_port.to_string())
        .replace("$host", ctx.host.as_deref().unwrap_or("unknown"))
        .replace("$scheme", &ctx.scheme)
        .replace("$server_port", &ctx.server_port.to_string())
        .replace("$proxy_add_x_forwarded_for", &xff)
        .replace("$request_uri", &ctx.uri)
        .replace("$uri", ctx.effective_path())
        .replace("$args", &ctx.query);
    if out.contains("$http_") {
        out = expand_http_vars(&out, ctx);
    }
    out
}

/// `$http_x_xx` / `$http_user_agent` 形态的请求头变量
fn expand_http_vars(template: &str, ctx: &RequestCtx) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && template[i..].starts_with("$http_") {
            let rest = &template[i + 6..];
            let name_len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = rest[..name_len].replace('_', "-");
            let value = ctx
                .header(&name)
                .map(|s| s.to_string())
                .unwrap_or_default();
            out.push_str(&value);
            i += 6 + name_len;
        } else {
            // 按 char 边界推进，避免把多字节字符切碎
            let ch = template[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::RequestCtx;

    fn ctx() -> RequestCtx {
        RequestCtx {
            method: "GET".to_string(),
            path: "/api/x".to_string(),
            query: "a=1".to_string(),
            uri: "/api/x?a=1".to_string(),
            host: Some("www.example.com".to_string()),
            remote_addr: "10.0.0.9".to_string(),
            remote_port: 54321,
            server_port: 8080,
            req_headers: vec![
                ("user-agent".to_string(), "curl/8".to_string()),
                ("x-forwarded-for".to_string(), "1.1.1.1".to_string()),
            ],
            resp_headers: Vec::new(),
            rewritten_path: None,
            status: 200,
            body: None,
            done: false,
            internal_redirect: false,
            req_body: Vec::new(),
            exec_depth: 0,
            redirect: None,
            scheme: "https".to_string(),
            internal_request: false,
        }
    }

    #[test]
    fn interpolates_core_variables() {
        let c = ctx();
        assert_eq!(
            interpolate_vars("$scheme://$host:$server_port$uri?$args", &c),
            "https://www.example.com:8080/api/x?a=1"
        );
        assert_eq!(interpolate_vars("$remote_addr:$remote_port", &c), "10.0.0.9:54321");
        assert_eq!(
            interpolate_vars("$proxy_add_x_forwarded_for", &c),
            "1.1.1.1, 10.0.0.9"
        );
    }

    #[test]
    fn expands_http_header_vars() {
        let c = ctx();
        assert_eq!(interpolate_vars("[$http_user_agent|$http_missing]", &c), "[curl/8|]");
        // 变量名里下划线代表连字符
        assert_eq!(interpolate_vars("$http_x_forwarded_for", &c), "1.1.1.1");
    }

    #[test]
    fn forwarded_path_is_reencoded_per_segment() {
        // 解码后的中文/空格必须重新编码，否则后端拿到非法请求行
        assert_eq!(encode_path("/a b/中文.html"), "/a%20b/%E4%B8%AD%E6%96%87.html");
        // 原本就是转义形式的 '%' 不能二次误解
        assert_eq!(encode_path("/100%25/"), "/100%2525/");
        assert_eq!(encode_path("/"), "/");
    }

    #[test]
    fn only_idempotent_methods_retry() {
        assert!(is_idempotent("GET"));
        assert!(is_idempotent("HEAD"));
        assert!(!is_idempotent("POST"));
        assert!(!is_idempotent("PATCH"));
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        for h in ["connection", "Transfer-Encoding", "Upgrade", "keep-alive"] {
            assert!(is_hop_by_hop(h), "{h}");
        }
        assert!(!is_hop_by_hop("x-request-id"));
    }

    #[test]
    fn clients_are_shared_per_connect_timeout() {
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let a = e.client(Duration::from_secs(3));
        let b = e.client(Duration::from_secs(3));
        let c = e.client(Duration::from_secs(7));
        let _ = (&a, &b, &c);
        let n = e.clients.lock().unwrap().len();
        assert_eq!(n, 2, "两个不同的 connect 超时应有两个客户端池");
    }

    #[tokio::test]
    async fn https_backend_fails_with_clear_message() {
        let pool = Arc::new(UpstreamPool::default());
        let e = ProxyEngine::new(pool);
        let c = ctx();
        let opts = ProxyOpts {
            set_headers: &[],
            timeouts: ProxyTimeouts {
                connect: Duration::from_secs(1),
                read: Duration::from_secs(1),
            },
            next_upstream: &[],
        };
        let err = e.forward(&c, "https://example.com", "/api", &opts, None).await.unwrap_err();
        assert!(err.contains("https"), "{err}");
    }
}
