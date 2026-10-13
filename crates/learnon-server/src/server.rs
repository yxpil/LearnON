//! HTTP 层与请求管线（对标 Nginx 的 phase 处理流程）：
//!
//!   1. server 块匹配（端口 + Host）
//!   2. rewrite 阶段（location 内 rewrite 规则，支持 last 内部重定向 / redirect）
//!   3. access 阶段（*_by_lua / access_by_rust，鉴权等）
//!   4. content 阶段决策：proxy_pass > content_by_lua > content_by_rust > 静态文件
//!   5. add_header + access_log

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::access_log::AccessLog;
use crate::engine::{self, HandlerRegistry, Phase, RequestCtx};
use crate::lua_engine::LuaEngine;
use crate::proxy::ProxyEngine;
use crate::router::{Location, Router, Server};

pub type RespBody = BoxBody<Bytes, hyper::Error>;
pub type BoxResponse = Response<RespBody>;

/// 所有响应统一携带的品牌头（对标 nginx 的 Server 头）
pub const SERVER_HEADER: &str = concat!("LearnON/", env!("CARGO_PKG_VERSION"));

pub struct AppState {
    pub router: Router,
    pub handlers: Arc<HandlerRegistry>,
    pub lua: Arc<LuaEngine>,
    pub proxy: Arc<ProxyEngine>,
    pub access_log: Arc<AccessLog>,
    #[allow(dead_code)]
    pub base_dir: std::path::PathBuf,
}

pub fn full_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into())
        .map_err(|never| match never {})
        .boxed()
}

pub async fn serve(
    state: Arc<AppState>,
    listener: crate::router::Listener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.addr;
    let tls_acceptor = match &listener.tls {
        Some(paths) => Some(load_tls_acceptor(paths)?),
        None => None,
    };
    let scheme = if tls_acceptor.is_some() { "https" } else { "http" };
    println!("[learnon] listening on {scheme}://{addr}");
    let tcp = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = tcp.accept().await?;
        let peer = stream.peer_addr().ok();
        let state = Arc::clone(&state);
        match &tls_acceptor {
            Some(acceptor) => {
                let acceptor = acceptor.clone();
                tokio::task::spawn(async move {
                    let _ = stream.set_nodelay(true); // 低延迟：禁用 Nagle
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req| {
                                let state = Arc::clone(&state);
                                async move { handle_request(state, req, peer).await }
                            });
                            if let Err(e) =
                                http1::Builder::new().serve_connection(io, service).await
                            {
                                eprintln!("[learnon] connection error: {e}");
                            }
                        }
                        Err(e) => eprintln!("[learnon] TLS handshake 失败: {e}"),
                    }
                });
            }
            None => {
                let _ = stream.set_nodelay(true); // 低延迟：禁用 Nagle
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    let service = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        async move { handle_request(state, req, peer).await }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        eprintln!("[learnon] connection error: {e}");
                    }
                });
            }
        }
    }
}

/// 加载 PEM 证书/私钥，构建 TLS acceptor
fn load_tls_acceptor(
    paths: &crate::router::TlsPaths,
) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_reader = std::fs::File::open(&paths.cert)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_reader))
        .collect::<Result<_, _>>()?;
    let key_reader = std::fs::File::open(&paths.key)?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_reader))?
        .ok_or("ssl_certificate_key 中未找到私钥")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.clone_key())?;
    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

async fn handle_request(
    state: Arc<AppState>,
    req: Request<Incoming>,
    peer: Option<std::net::SocketAddr>,
) -> Result<BoxResponse, std::convert::Infallible> {
    let started = std::time::Instant::now();

    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    let port = req
        .uri()
        .port_u16()
        .or_else(|| state.router.listeners.first().map(|a| a.addr.port()))
        .unwrap_or(8080);

    // client_max_body_size（nginx 语义：Content-Length 超限直接 413，读体前拦截）
    if let Some(srv) = state.router.match_server(port, host.as_deref()) {
        if let Some(limit) = srv.client_max_body_size {
            let oversized = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse::<u64>().ok())
                .map(|n| n > limit)
                .unwrap_or(false);
            if oversized {
                let mut c413 = RequestCtx {
                    method: method.clone(),
                    path: path.clone(),
                    query: query.clone(),
                    uri: uri.clone(),
                    host: host.clone(),
                    remote_addr: peer
                        .map(|p| p.ip().to_string())
                        .unwrap_or_default(),
                    req_headers: headers.clone(),
                    status: 413,
                    ..Default::default()
                };
                state.access_log.log_request(&c413, 413, 0);
                return Ok(error_response(&mut c413, srv, None, 413));
            }
        }
    }

    let mut ctx = RequestCtx {
        method,
        path,
        query,
        uri,
        host,
        remote_addr: peer
            .map(|p| p.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".into()),
        req_headers: headers,
        status: 200,
        ..Default::default()
    };

    // 缓冲请求体（供 Lua get_body_data 与代理转发使用）
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    ctx.req_body = body_bytes.to_vec();

    let resp = process(&state, &mut ctx, port, body_bytes).await;
    let status = resp.as_ref().map(|r| r.status().as_u16()).unwrap_or(500);
    state.access_log.log_request(&ctx, status, started.elapsed().as_millis() as usize);
    resp
}

async fn process(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    port: u16,
    body: Bytes,
) -> Result<BoxResponse, std::convert::Infallible> {
    let server = match state.router.match_server(port, ctx.host.as_deref()) {
        Some(s) => Arc::clone(s),
        None => return Ok(error_page(StatusCode::NOT_FOUND)),
    };

    // ---- rewrite + access 循环（rewrite last / ngx.exec 触发内部重定向，
    //      最多 10 跳防死循环） ----
    let mut current_loc: Option<&Location> = None;
    for _ in 0..10 {
        let loc = Router::match_location(&server, ctx.effective_path());
        current_loc = loc;
        if let Some(loc) = loc {
            if !loc.rewrites.is_empty() && engine::apply_rewrites(ctx, &loc.rewrites) {
                if let Some((code, target)) = ctx.redirect.take() {
                    return Ok(redirect_response(code, &target));
                }
                if ctx.internal_redirect {
                    ctx.internal_redirect = false;
                    continue; // rewrite ... last：重新匹配 location
                }
                // break：留在当前 location
            }
        }

        // ---- access 阶段 ----
        if let Some(loc) = current_loc {
            if let Some(ret) = &loc.ret {
                engine::apply_return(ctx, ret);
            }
            for (phase, spec) in &loc.rust_phases {
                if *phase != Phase::Access || ctx.done {
                    continue;
                }
                if let Err(e) = state.handlers.run_phase(*phase, spec, ctx).await {
                    return Ok(error_response(ctx, &server, current_loc, 500));
                }
            }
            for (phase, name, src) in &loc.lua_phases {
                if *phase != Phase::Access || ctx.done {
                    continue;
                }
                let shared = Arc::new(std::sync::Mutex::new(std::mem::take(ctx)));
                let r = state.lua.run_phase(name, src, Arc::clone(&shared)).await;
                *ctx = shared.lock().unwrap().clone();
                if let Err(e) = r {
                    return Ok(error_response(ctx, &server, current_loc, 500));
                }
            }
        }
        if ctx.done {
            return Ok(finish_response(ctx, &server, current_loc));
        }
        // ngx.exec：内部重定向，重新匹配 location
        if ctx.internal_redirect {
            ctx.internal_redirect = false;
            continue;
        }
        break;
    }

    // ---- content 阶段决策 ----
    let Some(loc) = current_loc else {
        // 无 location：404
        ctx.status = 404;
        return Ok(error_page(StatusCode::NOT_FOUND));
    };

    // 1) proxy_pass 反向代理
    if let Some(target) = &loc.proxy_pass {
        match state
            .proxy
            .forward(
                ctx,
                target,
                &loc.pattern,
                &loc.proxy_set_headers,
                Duration::from_secs(loc.proxy_read_timeout),
                Some(body),
            )
            .await
        {
            Ok(upstream_resp) => {
                return Ok(convert_upstream_response(upstream_resp, loc, &server));
            }
            Err(e) => {
                eprintln!("[learnon] {e}");
                return Ok(error_response(ctx, &server, Some(loc), 502));
            }
        }
    }

    // 2) content_by_lua
    if let Some((_, name, src)) = loc.lua_phases.iter().find(|(p, _, _)| *p == Phase::Content) {
        let shared = Arc::new(std::sync::Mutex::new(std::mem::take(ctx)));
        let r = state.lua.run_phase(name, src, Arc::clone(&shared)).await;
        *ctx = shared.lock().unwrap().clone();
        if let Err(e) = r {
            return Ok(error_response(ctx, &server, current_loc, 500));
        }
        // content 阶段的 ngx.exec：内部重定向后重新处理（深度限制防死循环）
        if ctx.internal_redirect && ctx.exec_depth < 10 {
            ctx.internal_redirect = false;
            ctx.exec_depth += 1;
            return Box::pin(process(state, ctx, port, body)).await;
        }
        // content 阶段的 ngx.redirect：外部重定向
        if let Some((code, target)) = ctx.redirect.take() {
            return Ok(redirect_response(code, &target));
        }
        if !ctx.body.as_ref().is_some_and(|b| !b.is_empty()) && !ctx.done {
            // Lua 没产出内容：落到静态/404
            return Ok(serve_static_flow(state, ctx, port, body, &server, loc).await);
        }
        return Ok(finish_response(ctx, &server, Some(loc)));
    }

    // 3) content_by_rust
    if let Some((_, spec)) = loc.rust_phases.iter().find(|(p, _)| *p == Phase::Content) {
        if let Err(e) = state.handlers.run_phase(Phase::Content, spec, ctx).await {
            return Ok(error_response(ctx, &server, current_loc, 500));
        }
        return Ok(finish_response(ctx, &server, Some(loc)));
    }

    // 4) 静态文件（nginx 语义：try_files / index / autoindex / alias）
    Ok(serve_static_flow(state, ctx, port, body, &server, loc).await)
}

/// 按 error_page 指令生成错误响应：目标文件存在则按原状态码返回，否则退回内置默认页
fn error_response(
    ctx: &mut RequestCtx,
    server: &Server,
    loc: Option<&Location>,
    code: u16,
) -> BoxResponse {
    ctx.status = code;
    let target = loc
        .and_then(|l| l.error_pages.get(&code))
        .or_else(|| server.error_pages.get(&code))
        .cloned();
    if let Some(t) = target {
        let base = loc
            .and_then(|l| l.root.as_ref().or(l.alias.as_ref()))
            .or(server.root.as_ref());
        if let Some(base) = base {
            let file = base.join(t.trim_start_matches('/'));
            if file.is_file() {
                let body = std::fs::read(&file).unwrap_or_default();
                return Response::builder()
                    .status(StatusCode::from_u16(code).unwrap_or(StatusCode::OK))
                    .header("content-type", mime_of(&file))
                    .header("server", SERVER_HEADER)
                    .body(full_body(body))
                    .unwrap();
            }
        }
    }
    error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 静态内容服务（nginx 语义）：try_files > 目录 index/autoindex > 文件；失败走 error_page
async fn serve_static_flow(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    port: u16,
    body: Bytes,
    server: &Server,
    loc: &Location,
) -> BoxResponse {
    // 收集快照（无阻塞），文件系统调用全部放入阻塞线程池：
    // 高负载下不再卡住 tokio worker 线程（性能分析结论）
    let Some(snap) = static_snapshot(ctx, server, loc) else {
        return error_response(ctx, server, Some(loc), 404);
    };
    let hit = tokio::task::spawn_blocking(move || resolve_snap(&snap))
        .await
        .unwrap_or(StaticHit::NotFound);
    match hit {
        StaticHit::File { code, mime, body: content } => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            Response::builder()
                .status(status)
                .header("content-type", mime)
                .header("server", SERVER_HEADER)
                .body(full_body(content))
                .unwrap()
        }
        StaticHit::Redirect(target) => redirect_response(301, &target),
        StaticHit::InternalRedirect(last) => {
            if ctx.exec_depth < 10 {
                ctx.rewritten_path = Some(last);
                ctx.exec_depth += 1;
                let r = Box::pin(process(state, ctx, port, body)).await;
                return match r {
                    Ok(resp) => resp,
                    Err(e) => match e {},
                };
            }
            error_response(ctx, server, Some(loc), 404)
        }
        StaticHit::NotFound => error_response(ctx, server, Some(loc), 404),
        StaticHit::Forbidden => error_response(ctx, server, Some(loc), 403),
    }
}

/// 静态解析结果（文件内容已读出，构建响应不再碰文件系统）
enum StaticHit {
    File { code: u16, mime: String, body: Vec<u8> },
    /// 目录存在但 URI 缺斜杠：301
    Redirect(String),
    /// try_files 兜底：内部重定向目标
    InternalRedirect(String),
    NotFound,
    Forbidden,
}

/// 静态解析快照：把 ctx/server/location 的相关数据抽成 owned 结构，
/// 便于整体丢进 spawn_blocking（阻塞分析：文件系统调用不能留在 worker 上）
struct StaticSnap {
    base: std::path::PathBuf,
    is_alias: bool,
    pattern: String,
    path: String,
    query: String,
    index: Vec<String>,
    autoindex: bool,
    try_files: Option<Vec<String>>,
}

fn static_snapshot(ctx: &RequestCtx, server: &Server, loc: &Location) -> Option<StaticSnap> {
    let (base, is_alias) = if let Some(alias) = &loc.alias {
        (alias.clone(), true)
    } else if let Some(root) = loc.root.as_ref().or(server.root.as_ref()) {
        (root.clone(), false)
    } else {
        return None;
    };
    Some(StaticSnap {
        base,
        is_alias,
        pattern: loc.pattern.clone(),
        path: ctx.effective_path().to_string(),
        query: ctx.query.clone(),
        index: loc.index.clone().unwrap_or_else(|| server.index.clone()),
        autoindex: loc.autoindex || server.autoindex,
        try_files: loc.try_files.clone(),
    })
}

impl StaticSnap {
    /// nginx 语义：alias 剥 location 前缀，root 追加完整 URI
    fn base_rel(&self, path: &str) -> (std::path::PathBuf, String) {
        if self.is_alias {
            let rel = path.strip_prefix(&self.pattern).unwrap_or(path);
            (self.base.clone(), rel.trim_start_matches('/').to_string())
        } else {
            (self.base.clone(), path.trim_start_matches('/').to_string())
        }
    }
}

/// 完整静态解析（含 try_files），运行在阻塞线程池中
fn resolve_snap(snap: &StaticSnap) -> StaticHit {
    // try_files：逐一探测，最后一个参数为内部重定向兜底
    if let Some(tf) = &snap.try_files {
        for cand in &tf[..tf.len() - 1] {
            let p = cand.replace("$uri", &snap.path);
            match resolve_one(snap, &p) {
                StaticHit::NotFound | StaticHit::Forbidden => continue,
                h => return h,
            }
        }
        let last = tf
            .last()
            .map(|s| s.replace("$uri", &snap.path))
            .unwrap_or_default();
        return if last.starts_with('/') {
            StaticHit::InternalRedirect(last)
        } else {
            StaticHit::NotFound
        };
    }
    resolve_one(snap, &snap.path)
}

fn resolve_one(snap: &StaticSnap, path: &str) -> StaticHit {
    let (base, rel) = snap.base_rel(path);
    let file_path = base.join(&rel);
    if rel.is_empty() || file_path.is_dir() {
        // 目录存在但 URI 不带斜杠：301 补斜杠（nginx 行为）
        if !path.ends_with('/') {
            let q = if snap.query.is_empty() {
                String::new()
            } else {
                format!("?{}", snap.query)
            };
            return StaticHit::Redirect(format!("{path}/{q}"));
        }
        // index 指令逐个探测
        for name in &snap.index {
            let cand = file_path.join(name);
            if cand.is_file() {
                return file_hit(&cand, 200);
            }
        }
        // autoindex on：目录列表
        if snap.autoindex {
            if let Some(html) = autoindex_html(&file_path, path) {
                return StaticHit::File {
                    code: 200,
                    mime: "text/html; charset=utf-8".to_string(),
                    body: html.into_bytes(),
                };
            }
        }
        // nginx：无 index 命中且 autoindex off → 403
        return StaticHit::Forbidden;
    }
    if file_path.is_file() {
        file_hit(&file_path, 200)
    } else {
        StaticHit::NotFound
    }
}

/// 静态文件内存缓存：小文件整体驻留内存，命中后零磁盘读。
/// 以 (mtime, size) 做失效校验（仍在 spawn_blocking 内 stat，代价远小于 read）。
const FILE_CACHE_MAX_FILE: u64 = 1024 * 1024; // 单文件上限 1MB
const FILE_CACHE_MAX_ENTRIES: usize = 512; // 缓存条目上限

type FileCacheInner = HashMap<
    std::path::PathBuf,
    (u64, u64, std::sync::Arc<Vec<u8>>), // (mtime_secs, size, body)
>;
static FILE_CACHE: std::sync::OnceLock<std::sync::RwLock<FileCacheInner>> =
    std::sync::OnceLock::new();

fn file_cache() -> &'static std::sync::RwLock<FileCacheInner> {
    FILE_CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

fn file_hit(path: &std::path::Path, code: u16) -> StaticHit {
    let Ok(meta) = std::fs::metadata(path) else {
        return StaticHit::NotFound;
    };
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if size <= FILE_CACHE_MAX_FILE {
        if let Some((m, sz, body)) = file_cache().read().unwrap().get(path) {
            if *m == mtime && *sz == size {
                return StaticHit::File {
                    code,
                    mime: mime_of(path).to_string(),
                    body: (**body).clone(),
                };
            }
        }
    }

    let body = std::fs::read(path).unwrap_or_default();
    if size <= FILE_CACHE_MAX_FILE {
        let mut cache = file_cache().write().unwrap();
        if cache.len() >= FILE_CACHE_MAX_ENTRIES {
            cache.clear(); // 简单淘汰：满即清空，热文件下一轮自动回填
        }
        cache.insert(path.to_path_buf(), (mtime, size, std::sync::Arc::new(body.clone())));
    }
    StaticHit::File {
        code,
        mime: mime_of(path).to_string(),
        body,
    }
}

/// autoindex：nginx 风格目录列表页
fn autoindex_html(dir: &std::path::Path, uri: &str) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for e in std::fs::read_dir(dir).ok()? {
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        let slash = if e.path().is_dir() { "/" } else { "" };
        entries.push(format!("<a href=\"{name}{slash}\">{name}{slash}</a>"));
    }
    Some(format!(
        "<html>\r\n<head><title>Index of {uri}</title></head>\r\n<body>\r\n<h1>Index of {uri}</h1><hr><pre>../\r\n{}</pre><hr><center>LearnON</center>\r\n</body>\r\n</html>\r\n",
        entries.join("\r\n")
    ))
}

fn convert_upstream_response(
    resp: Response<Incoming>,
    loc: &Location,
    server: &Server,
) -> BoxResponse {
    let (mut parts, body) = resp.into_parts();
    let mut builder = Response::builder().status(parts.status);
    {
        let hm = builder.headers_mut().unwrap();
        // Server 头统一改为 LearnON（覆盖上游的）
        if let Ok(v) = hyper::header::HeaderValue::from_str(SERVER_HEADER) {
            hm.insert(hyper::header::SERVER, v);
        }
        for (k, v) in parts.headers.drain() {
            if let Some(name) = k {
                // 过滤 hop-by-hop
                if is_hop_by_hop(name.as_str()) {
                    continue;
                }
                hm.insert(name, v);
            }
        }
        for (k, v) in loc.add_headers.iter().chain(server.add_headers.iter()) {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_str()),
                hyper::header::HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
    }
    builder.body(body.boxed()).unwrap()
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization"
            | "te" | "trailer" | "transfer-encoding" | "upgrade"
    )
}

fn finish_response(ctx: &RequestCtx, server: &Server, loc: Option<&Location>) -> BoxResponse {
    let status = StatusCode::from_u16(ctx.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    {
        let hm = builder.headers_mut().unwrap();
        for (k, v) in &ctx.resp_headers {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::try_from(k.as_str()),
                hyper::header::HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
        if let Some(loc) = loc {
            for (k, v) in loc.add_headers.iter().chain(server.add_headers.iter()) {
                if let (Ok(name), Ok(val)) = (
                    hyper::header::HeaderName::try_from(k.as_str()),
                    hyper::header::HeaderValue::try_from(v.as_str()),
                ) {
                    hm.insert(name, val);
                }
            }
        }
        if !hm.contains_key("content-type") && ctx.body.is_some() {
            hm.insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        if let Ok(v) = hyper::header::HeaderValue::from_str(SERVER_HEADER) {
            hm.insert(hyper::header::SERVER, v);
        }
    }
    builder
        .body(full_body(ctx.body.clone().unwrap_or_default()))
        .unwrap()
}

fn redirect_response(code: u16, target: &str) -> BoxResponse {
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND))
        .header("location", target)
        .header("server", SERVER_HEADER)
        .body(full_body(format!("{} {}", code, target)))
        .unwrap()
}

/// nginx/OpenResty 风格默认错误页，底部署名 LearnON
fn error_page(status: StatusCode) -> BoxResponse {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!(
        "<html>
<head><title>{code} {reason}</title></head>
<body>
<center><h1>{code} {reason}</h1></center>
<hr><center>LearnON</center>
</body>
</html>
"
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", SERVER_HEADER)
        .body(full_body(body))
        .unwrap()
}

fn mime_of(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "lua" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

// HashMap 由 router 使用；这里保留类型引用避免告警
pub type _Unused = HashMap<String, String>;
