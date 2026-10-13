//! 反向代理：对标 Nginx 的 `proxy_pass`。
//!
//! - 支持 `proxy_pass http://upstream_name`（走 upstream 负载均衡）
//! - 支持 `proxy_pass http://host:port`（直连）
//! - 支持 `proxy_set_header` 覆盖/新增转发头（含 $remote_addr/$host/$proxy_add_x_forwarded_for 插值）
//! - `proxy_read_timeout` 控制读超时；请求体当前缓冲后转发（路线图：流式）

use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Incoming, Bytes};
use hyper::header::{HeaderMap, HeaderValue, HOST};
use hyper::{Request, Response};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

use crate::engine::RequestCtx;
use crate::upstream::{UpstreamGuard, UpstreamPool};

type HyperClient = Client<HttpConnector, Full<Bytes>>;
use http_body_util::Full;

/// 每个监听进程一个共享连接池客户端
pub struct ProxyEngine {
    client: HyperClient,
    pool: Arc<UpstreamPool>,
}

impl ProxyEngine {
    pub fn new(pool: Arc<UpstreamPool>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        ProxyEngine { client, pool }
    }

    /// 执行反代。`target` 是 proxy_pass 的值（http:// 后面的部分），
    /// 与 upstream 名匹配时走负载均衡，否则当作 host:port 直连。
    pub async fn forward(
        &self,
        ctx: &mut RequestCtx,
        target: &str,
        loc_prefix: &str,
        set_headers: &[(String, String)],
        read_timeout: Duration,
        raw_body: Option<Bytes>,
    ) -> Result<Response<Incoming>, String> {
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
            if is_hop_by_hop(k) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_bytes()),
                HeaderValue::try_from(v.as_str()),
            ) {
                headers.insert(name, val);
            }
        }
        for (k, v) in set_headers {
            let name = hyper::header::HeaderName::try_from(k.as_str())
                .map_err(|e| format!("非法的 proxy_set_header 名 {k}: {e}"))?;
            let val = interpolate_vars(v, ctx);
            headers.insert(name, HeaderValue::try_from(val).map_err(|e| e.to_string())?);
        }
        if !headers.contains_key(HOST) {
            if let Some(h) = &ctx.host {
                headers.insert(HOST, HeaderValue::try_from(h.as_str()).unwrap());
            }
        }

        // 请求体已由 server 层缓冲后传入（流式转发在路线图中）
        let body_bytes = raw_body.unwrap_or_default();

        // nginx proxy_next_upstream 语义：连接级失败时换下一节点重试一次
        // （典型场景：后端不支持 keep-alive，连接池命中已关闭的陈旧连接）
        let mut backend = backend;
        let mut resp = None;
        for attempt in 0..2 {
            if attempt > 0 {
                if let Some(up) = self.pool.get(&host_part) {
                    let g = up.acquire(&ctx.remote_addr);
                    backend = (*g).clone();
                    guard_holder = Some(g);
                }
                eprintln!("[learnon] upstream {backend} 连接失败，重试下一节点");
            }
            let uri = format!("http://{backend}{out_path}{query}");
            let mut req = Request::builder()
                .method(ctx.method.as_str())
                .uri(&uri)
                .version(hyper::Version::HTTP_11)
                .body(Full::new(body_bytes.clone()))
                .map_err(|e| e.to_string())?;
            *req.headers_mut() = headers.clone();
            match tokio::time::timeout(read_timeout, self.client.request(req)).await {
                Ok(Ok(r)) => {
                    note(&guard_holder, true);
                    resp = Some(r);
                    break;
                }
                Ok(Err(e)) => {
                    note(&guard_holder, false);
                    if attempt == 1 {
                        return Err(format!(
                            "代理请求失败 {backend}: {} | 根因: {}",
                            e,
                            error_root(&e)
                        ));
                    }
                }
                Err(_) => {
                    note(&guard_holder, false);
                    return Err(format!("proxy_read_timeout ({read_timeout:?}) 超时: {backend}"));
                }
            }
        }

        Ok(resp.unwrap())
    }
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
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
    template
        .replace("$remote_addr", &ctx.remote_addr)
        .replace("$host", ctx.host.as_deref().unwrap_or("unknown"))
        .replace("$proxy_add_x_forwarded_for", &xff)
        .replace("$request_uri", &ctx.effective_uri())
        .replace("$uri", ctx.effective_path())
        .replace("$args", &ctx.query)
}
