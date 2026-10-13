//! 连接层 + 请求管线（对标 Nginx 的 accept/读写事件 + 11 个 HTTP 阶段）。
//!
//! 连接层职责：
//!   - 按配置地址绑定监听（backlog / ipv6only），一条 listen = 一个 accept 循环
//!   - 并发连接上限（worker_connections）+ 快速拒绝
//!   - TLS：多证书 SNI、ALPN 协商 h2/http1.1、握手超时
//!   - 读头超时、keep-alive 空闲与请求数上限、优雅停机
//!   - panic 隔离（单个请求崩溃不能带倒整个进程）
//!
//! 请求管线（阶段顺序与 nginx 一致）：
//!   POST_READ(校验/取 vhost) → FIND_CONFIG(location) → REWRITE(rewrite/last)
//!   → PREACCESS(limit_req) → ACCESS(limit_conn / *_by_*) → TRY_FILES/CONTENT
//!   → LOG(响应体生命周期结束时落访问日志)

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use http_body_util::{BodyExt, BodyStream, Empty, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue,SERVER};
use hyper::server::conn::{http1, http2};
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit};
use tokio_rustls::TlsAcceptor;

use crate::access_log::{AccessLog, LogRecord};
use crate::certs;
use crate::engine::{self, HandlerRegistry, Phase, RequestCtx};
use crate::lua_engine::LuaEngine;
use crate::proxy::{ProxyEngine, ProxyOpts, ProxyTimeouts};
use crate::router::{self, Location, Router, Server};
use crate::settings::Settings;
use crate::{log_debug, log_error, log_info, log_warn, AppError};

pub type RespBody = BoxBody<Bytes, hyper::Error>;
pub type BoxResponse = Response<RespBody>;
use http_body_util::combinators::BoxBody;

/// 所有响应统一携带的品牌头（对标 nginx 的 Server 头）
pub const SERVER_HEADER: &str = concat!("LearnON/", env!("CARGO_PKG_VERSION"));

/// location 匹配/内部重定向的最大跳数（nginx NGX_HTTP_MAX_URI_CHANGES = 10）
const MAX_URI_CHANGES: usize = 10;
/// 单个请求最多允许的头数量与总大小（hyper 默认 100 / 16KB，这里显式写出便于运维）
const MAX_REQUEST_HEADERS: usize = 100;
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// HTTP/2 并发流上限（nginx http2_max_concurrent_streams 默认 128）
const MAX_CONCURRENT_STREAMS: u32 = 128;

pub struct AppState {
    pub router: Router,
    pub handlers: Arc<HandlerRegistry>,
    pub lua: Arc<LuaEngine>,
    pub proxy: Arc<ProxyEngine>,
    pub access_log: Arc<AccessLog>,
    pub settings: Settings,
    pub limits: Arc<crate::limit::Limits>,
    /// 全局并发连接额度（worker_connections）
    pub permits: Arc<tokio::sync::Semaphore>,
}

/// 一条连接的可共享元信息（TLS/SNI 决定 scheme，vhost 匹配决定用哪个地址）
pub struct ConnMeta {
    /// 该连接所属监听端点的配置地址（vhost 分组键）
    pub listener: SocketAddr,
    pub peer: Option<SocketAddr>,
    pub scheme: &'static str,
    /// 是否 HTTP/1.x（keep-alive 上限用 `Connection: close` 实现；h2 用 GOAWAY）
    pub http1: bool,
    /// 本连接已处理的请求数（每个连接独享一份计数）
    pub requests: Arc<AtomicU64>,
}

pub fn full_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty_body() -> RespBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

// ==================== 监听与 accept 循环 ====================

/// 按配置地址创建监听 socket（backlog、ipv6only、SO_REUSEADDR）
pub fn bind_listener(l: &crate::router::Listener, default_backlog: u32) -> Result<TcpListener, AppError> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let addr = l.addr;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| AppError::Other(format!("创建监听 socket 失败 {addr}: {e}")))?;
    // 重启时尽快复用处于 TIME_WAIT 的端口（Windows 上 SO_REUSEADDR 语义是"可抢占"，不能用）
    #[cfg(not(windows))]
    if let Err(e) = socket.set_reuse_address(true) {
        log_warn!("{addr} 设置 SO_REUSEADDR 失败: {e}");
    }
    if addr.is_ipv6() {
        if let Some(v6only) = l.ipv6only {
            socket
                .set_only_v6(v6only)
                .map_err(|e| AppError::Other(format!("{addr} 设置 ipv6only 失败: {e}")))?;
        }
    }
    socket
        .set_nonblocking(true)
        .map_err(|e| AppError::Other(format!("{addr} 设置非阻塞失败: {e}")))?;
    let sa: SockAddr = addr.into();
    socket.bind(&sa).map_err(|e| {
        AppError::Other(format!(
            "绑定 {addr} 失败: {e}（端口已被占用，或需要管理员/root 权限绑定 <1024 端口）"
        ))
    })?;
    let backlog = l.backlog.unwrap_or(default_backlog);
    socket
        .listen(backlog as i32)
        .map_err(|e| AppError::Other(format!("{addr} listen(backlog={backlog}) 失败: {e}")))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| AppError::Other(format!("{addr} 交给 tokio 失败: {e}")))
}

/// 一个监听端点的 accept 循环；`shutdown` 置位后停止接收并优雅排空在途连接
pub async fn serve(
    state: Arc<AppState>,
    listener: crate::router::Listener,
    tcp: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let addr = listener.addr;
    let tls: Option<(TlsAcceptor, bool)> = match &listener.tls {
        Some(opts) => match certs::build_server_config(opts) {
            Ok(cfg) => {
                let http2 = opts.http2;
                let names: Vec<String> = opts
                    .specs
                    .iter()
                    .flat_map(|s| s.names.clone())
                    .collect();
                log_info!("{addr} TLS 就绪（ALPN {:?}，证书名 {names:?}）", if http2 { "h2,http/1.1" } else { "http/1.1" });
                Some((TlsAcceptor::from(Arc::new(cfg)), http2))
            }
            Err(e) => {
                // 证书有问题就不能"降级成明文"继续服务——那会让 https 的调用方拿到意外结果
                log_error!("{addr} TLS 配置无效: {e}，该监听退出");
                return;
            }
        },
        None => None,
    };
    let scheme = if tls.is_some() { "https" } else { "http" };
    log_info!("监听 {scheme}://{addr}（backlog={})", listener.backlog.unwrap_or(state.settings.accept_backlog));

    let mut tasks = tokio::task::JoinSet::new();
    let mut backoff = Duration::from_millis(1);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            r = tcp.accept() => r,
        };
        match accepted {
            Ok((stream, peer)) => {
                backoff = Duration::from_millis(1);
                spawn_connection(
                    &mut tasks,
                    Arc::clone(&state),
                    stream,
                    peer,
                    addr,
                    tls.clone(),
                    shutdown.clone(),
                );
            }
            Err(e) => {
                // fd 耗尽 / 监听队列异常：指数退避，避免刷错误日志把 CPU 打满
                log_warn!("{addr} accept 失败: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => break,
                }
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
        }
    }

    drain_connections(&mut tasks, state.settings.shutdown_grace, addr).await;
}

/// 停机时在 grace 期内等在途连接自然结束，超时后强制断开（nginx 的 graceful shutdown 语义）
async fn drain_connections(tasks: &mut tokio::task::JoinSet<()>, grace: Duration, addr: SocketAddr) {
    if tasks.is_empty() {
        return;
    }
    log_info!("{addr} 停止接收，等待 {} 条在途连接结束（最多 {grace:?}）", tasks.len());
    let started = Instant::now();
    while !tasks.is_empty() {
        let remaining = grace.saturating_sub(started.elapsed());
        tokio::select! {
            _ = tasks.join_next() => {}
            _ = tokio::time::sleep(remaining) => {
                if !tasks.is_empty() {
                    log_warn!("{addr} 优雅停机超时 {grace:?}，强制断开 {} 条连接", tasks.len());
                    tasks.abort_all();
                }
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn spawn_connection(
    tasks: &mut tokio::task::JoinSet<()>,
    state: Arc<AppState>,
    stream: TcpStream,
    peer: SocketAddr,
    listener: SocketAddr,
    tls: Option<(TlsAcceptor, bool)>,
    shutdown: watch::Receiver<bool>,
) {
    tasks.spawn(async move {
        // 连接额度：拿不到就快速拒绝，而不是排队（保护后端与自身 fd）
        let permit: Option<OwnedSemaphorePermit> = state.permits.clone().try_acquire_owned().ok();
        if permit.is_none() {
            match &tls {
                // 明文：回一个 503 让客户端知道是过载而不是网络故障；TLS：直接关闭（握手都还没做）
                None => reject_overloaded(stream).await,
                Some(_) => drop(stream),
            }
            log_debug!("连接数已达 worker_connections，拒绝 {peer}");
            return;
        }
        let _permit = permit.expect("checked above");
        let _ = stream.set_nodelay(state.settings.tcp_nodelay);
        match tls {
            None => {
                let meta = Arc::new(ConnMeta {
                    listener,
                    peer: Some(peer),
                    scheme: "http",
                    http1: true,
                    requests: Arc::new(AtomicU64::new(0)),
                });
                drive(state, TokioIo::new(stream), meta, shutdown).await;
            }
            Some((acceptor, _http2)) => {
                let handshake = tokio::time::timeout(state.settings.tls_handshake_timeout, acceptor.accept(stream));
                let tls_stream = match handshake.await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        log_debug!("TLS 握手失败 {peer}: {e}");
                        return;
                    }
                    Err(_) => {
                        log_debug!("TLS 握手超时（{:.0?}）{peer}", state.settings.tls_handshake_timeout);
                        return;
                    }
                };
                // ALPN 决定这条连接走 h2 还是 h1
                let h2 = tls_stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p == b"h2")
                    .unwrap_or(false);
                let meta = Arc::new(ConnMeta {
                    listener,
                    peer: Some(peer),
                    scheme: "https",
                    http1: !h2,
                    requests: Arc::new(AtomicU64::new(0)),
                });
                drive(state, TokioIo::new(tls_stream), meta, shutdown).await;
            }
        }
    });
}

/// 过载快速拒绝：写一个 503 并关闭
async fn reject_overloaded(mut stream: TcpStream) {
    use tokio::io::AsyncWriteExt;
    let body = b"service busy\r\n";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nserver: {SERVER_HEADER}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut buf = Vec::with_capacity(resp.len() + body.len());
    buf.extend_from_slice(resp.as_bytes());
    buf.extend_from_slice(body);
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&buf)).await;
    let _ = stream.shutdown().await;
}

/// 一条连接的读写循环：按 ALPN/明文选择 h1 或 h2，并在停机信号到来时优雅收尾
async fn drive<I>(
    state: Arc<AppState>,
    io: TokioIo<I>,
    meta: Arc<ConnMeta>,
    shutdown: watch::Receiver<bool>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = Gateway {
        state: Arc::clone(&state),
        meta: Arc::clone(&meta),
    };
    let timer = TokioTimer::new();
    if meta.http1 {
        let mut builder = http1::Builder::new();
        builder
            .timer(timer)
            // hyper 的读头超时同时覆盖"慢速发头"与 keep-alive 空闲等待
            .header_read_timeout(state.settings.client_header_timeout)
            .max_headers(MAX_REQUEST_HEADERS)
            .max_header_size(MAX_HEADER_BYTES)
            .ignore_invalid_headers(false)
            .title_case_headers(false)
            .writev(true);
        let conn = builder.serve_connection(io, service).with_upgrades();
        serve_conn(conn, shutdown, |c| c.graceful_shutdown()).await;
    } else {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(timer)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .adaptive_window(true)
            .keep_alive_interval(Some(state.settings.keepalive_timeout))
            .keep_alive_timeout(state.settings.client_body_timeout);
        let conn = builder.serve_connection(io, service);
        serve_conn(conn, shutdown, |c| c.graceful_shutdown()).await;
    }
}

/// 驱动一条连接直到结束；停机信号触发 `graceful` 后继续 poll 直到在途请求写完
async fn serve_conn<F, G>(conn: F, mut shutdown: watch::Receiver<bool>, graceful: G)
where
    F: Future<Output = Result<(), hyper::Error>>,
    G: Fn(Pin<&mut F>),
{
    let mut conn = Box::pin(conn);
    loop {
        tokio::select! {
            r = conn.as_mut() => {
                if let Err(e) = r {
                    // 客户端提前断开/畸形请求属于常态，落在 debug 级别避免日志被打满
                    log_debug!("连接结束: {e}");
                }
                break;
            }
            changed = shutdown.changed() => {
                // 只有真正进入停机状态才收尾，避免 receiver 被关闭时误触发
                if changed.is_ok() && *shutdown.borrow_and_update() {
                    graceful(conn.as_mut());
                }
            }
        }
    }
}

// ==================== Service：每请求一次 ====================

pub struct Gateway {
    pub state: Arc<AppState>,
    pub meta: Arc<ConnMeta>,
}

/// 请求句柄被丢弃（客户端断开、连接被取消）时补一条访问日志
struct EmitGuard {
    rec: Arc<LogRecord>,
    log: Arc<AccessLog>,
}

impl Drop for EmitGuard {
    fn drop(&mut self) {
        self.log.finish(&self.rec);
    }
}

impl Service<Request<Incoming>> for Gateway {
    type Response = BoxResponse;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<BoxResponse, Infallible>> + Send + 'static>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let meta = Arc::clone(&self.meta);
        let remote = meta
            .peer
            .map(|p| p.ip().to_string())
            .unwrap_or_else(|| "-".into());
        let rec = state.access_log.record(
            remote,
            req.method().as_str().to_string(),
            req.uri().to_string(),
            proto_name(req.version()).to_string(),
            header_of(&req, "referer").unwrap_or_else(|| "-".into()),
            header_of(&req, "user-agent").unwrap_or_else(|| "-".into()),
        );

        // keep-alive 请求数上限（nginx keepalive_requests）：第 N 条之后主动关闭连接。
        // h2 不能用 Connection 头，交由 keep_alive_interval / 停机时的 GOAWAY 处理。
        let seq = meta.requests.fetch_add(1, Ordering::Relaxed) + 1;
        let must_close = meta.http1 && seq >= state.settings.keepalive_requests as u64;

        Box::pin(async move {
            let _guard = EmitGuard {
                rec: Arc::clone(&rec),
                log: Arc::clone(&state.access_log),
            };
            let resp = match std::panic::AssertUnwindSafe(handle_request(
                Arc::clone(&state),
                Arc::clone(&meta),
                Arc::clone(&rec),
                req,
            ))
            .catch_unwind()
            .await
            {
                Ok(r) => r,
                Err(p) => {
                    log_error!("请求处理 panic（已隔离，返回 500）: {}", panic_text(&p));
                    error_page(StatusCode::INTERNAL_SERVER_ERROR)
                }
            };
            Ok(finalize(&state, &rec, resp, must_close))
        })
    }
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "未知 panic".to_string()
    }
}

/// 统一收尾：状态码记账、Server 头策略、过载关闭、响应体字节计数 + 落日志
fn finalize(state: &AppState, rec: &Arc<LogRecord>, resp: BoxResponse, must_close: bool) -> BoxResponse {
    rec.set_status(resp.status().as_u16());
    let (mut parts, body) = resp.into_parts();
    if state.settings.server_tokens {
        if !parts.headers.contains_key(SERVER) {
            if let Ok(v) = HeaderValue::from_str(SERVER_HEADER) {
                parts.headers.insert(SERVER, v);
            }
        }
    } else {
        parts.headers.remove(SERVER);
    }
    if must_close {
        parts.headers.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("close"),
        );
    }
    let head = rec.method == "HEAD";
    let body = if rec.mark_wrapped() {
        body
    } else {
        LoggedBody {
            inner: body,
            rec: Arc::clone(rec),
            log: Arc::clone(&state.access_log),
            count: !head,
        }
        .boxed()
    };
    Response::from_parts(parts, body)
}

/// 包一层响应体：累计真实写出的字节数，并在响应体生命周期结束时落访问日志
struct LoggedBody {
    inner: RespBody,
    rec: Arc<LogRecord>,
    log: Arc<AccessLog>,
    count: bool,
}

impl Body for LoggedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        // SAFETY: `inner` 是一个自创建起就被结构固定的 Pin<Box<..>>，这里只把它重新借成
        // Pin<&mut _> 交给 poll_frame，从不把字段移出 LoggedBody，不违反 pin 契约。
        let this = unsafe { self.get_unchecked_mut() };
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if this.count {
                    if let Some(bytes) = frame.data_ref().map(|d| d.len()) {
                        this.rec.add_bytes(bytes);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        self.rec.emit(&self.log);
    }
}

// ==================== 请求处理 ====================

async fn handle_request(
    state: Arc<AppState>,
    meta: Arc<ConnMeta>,
    rec: Arc<LogRecord>,
    req: Request<Incoming>
) -> BoxResponse {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let version = parts.version;
    let uri = parts.uri.clone();
    let headers = &parts.headers;

    // ---- POST_READ：畸形/越权请求直接在入口拒绝（对齐 nginx 的 400/414/501）----
    if !is_supported_method(&method) {
        return error_page(StatusCode::NOT_IMPLEMENTED);
    }
    let raw_path = uri.path().to_string();
    if raw_path.len() > 8192 || uri.query().map(|q| q.len()).unwrap_or(0) > 8192 {
        return error_page(StatusCode::URI_TOO_LONG);
    }
    if version == Version::HTTP_11 && headers.get(HOST_NAME).is_none() {
        return error_page(StatusCode::BAD_REQUEST);
    }
    // Transfer-Encoding：只接受纯 chunked；CL+TE 并存是请求走私的经典形态，一律拒绝
    let te = headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .map(|v| v.to_str().unwrap_or("").trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let chunked = te.iter().any(|v| v == "chunked");
    if !te.is_empty() && (!chunked || te.len() != 1 || te.iter().any(|v| v != "chunked")) {
        return error_page(StatusCode::BAD_REQUEST);
    }
    let cl_values: Vec<&HeaderValue> = headers.get_all(CONTENT_LENGTH).iter().collect();
    if cl_values.len() > 1 {
        return error_page(StatusCode::BAD_REQUEST);
    }
    if let Some(v) = cl_values.first() {
        if v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok()).is_none() {
            return error_page(StatusCode::BAD_REQUEST);
        }
    }

    // 匹配 location 之前先做 URL 解码 + dot-segment 归一化：
    // 匹配与静态文件解析用解码后的路径，转发/日志仍用原始 URI（nginx 的 r->uri / r->unparsed_uri 之分）
    let path = match decode_and_normalize(&raw_path) {
        Some(p) => p,
        None => return error_page(StatusCode::BAD_REQUEST),
    };
    let host = headers
        .get(HOST_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let server = match state.router.match_server(meta.listener, host.as_deref()) {
        Some(s) => Arc::clone(s),
        None => return error_page(StatusCode::NOT_FOUND),
    };

    let mut ctx = RequestCtx {
        method: method.as_str().to_string(),
        path,
        query: uri.query().unwrap_or("").to_string(),
        uri: uri.to_string(),
        host,
        remote_addr: rec.remote.clone(),
        remote_port: meta.peer.map(|p| p.port()).unwrap_or(0),
        server_port: meta.listener.port(),
        req_headers: header_pairs(headers),
        resp_headers: Vec::new(),
        rewritten_path: None,
        status: 200,
        body: None,
        done: false,
        internal_redirect: false,
        req_body: Vec::new(),
        exec_depth: 0,
        redirect: None,
        scheme: meta.scheme.to_string(),
        internal_request: false,
    };

    // ---- 并发连接限制（nginx limit_conn 在 ACCESS 之前，按 key 计数在途请求）----
    let mut conn_guards = Vec::new();
    for rule in &server.limit_conn {
        let guard = state
            .limits
            .conn_zone(&rule.zone)
            .and_then(|z| z.try_acquire(&ctx.remote_addr, rule.number));
        match guard {
            Some(g) => conn_guards.push(g),
            None => {
                log_debug!("limit_conn '{}' 命中: {}", rule.zone, ctx.remote_addr);
                return close_now(status_page(state.limits.conn_status));
            }
        }
    }

    // ---- 请求体：边读边限长（单靠 Content-Length 挡不住分块上传与谎报长度的客户端）----
    let loc0 = Router::match_location(&server, ctx.effective_path());
    let limit = loc0
        .and_then(|l| l.client_max_body_size)
        .or(server.client_max_body_size);
    let has_body = chunked || cl_values.first().is_some();
    let body_bytes = if has_body {
        match read_body(body, limit, state.settings.client_body_timeout).await {
            Ok(b) => b,
            Err(BodyFail::TooLarge) => {
                // 体没读完就返回：必须断开，否则残留字节会被当成下一个请求
                return close_now(error_page(StatusCode::PAYLOAD_TOO_LARGE));
            }
            Err(BodyFail::Timeout) => return close_now(error_page(StatusCode::REQUEST_TIMEOUT)),
            Err(BodyFail::Io) => return close_now(error_page(StatusCode::BAD_REQUEST)),
        }
    } else {
        Bytes::new()
    };
    ctx.req_body = body_bytes.to_vec();

    let resp = process(&state, &mut ctx, &server, body_bytes).await;
    // conn_guards 到这里才释放：整个请求处理期间都占着并发额度
    drop(conn_guards);
    resp
}

/// 有界 + 超时的请求体读取（chunked 与定长都适用）
enum BodyFail {
    TooLarge,
    Timeout,
    Io,
}

async fn read_body(body: Incoming, limit: Option<u64>, timeout: Duration) -> Result<Bytes, BodyFail> {
    let mut stream = BodyStream::new(body);
    let mut out: Vec<u8> = Vec::new();
    while let Some(frame) = tokio::time::timeout(timeout, stream.next()).await
        .map_err(|_| BodyFail::Timeout)?
    {
        match frame {
            Ok(f) => {
                if let Some(data) = f.into_data().ok() {
                    out.extend_from_slice(&data);
                    if let Some(max) = limit {
                        if out.len() as u64 > max {
                            return Err(BodyFail::TooLarge);
                        }
                    }
                }
            }
            Err(_) => return Err(BodyFail::Io),
        }
    }
    Ok(Bytes::from(out))
}

async fn process(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &Arc<Server>,
    body: Bytes,
) -> BoxResponse {
    // ---- REWRITE / POST_REWRITE / PREACCESS / ACCESS 循环 ----
    // rewrite ... last、ngx.exec、try_files 兜底都会重新匹配 location（最多 10 跳）
    let mut current_loc: Option<&Location> = None;
    // 停在"还在跳转"状态跑满 10 跳 = 配置成环（nginx: rewrite or internal redirection cycle → 500）
    let mut cycle = false;
    for _ in 0..MAX_URI_CHANGES {
        cycle = true;
        let loc = Router::match_location(server, ctx.effective_path());
        current_loc = loc;
        let Some(loc) = loc else {
            cycle = false;
            break;
        };

        // internal 只允许内部重定向命中（nginx：外部请求访问 internal location → 404）
        if loc.internal && !ctx.internal_request {
            return error_page(StatusCode::NOT_FOUND);
        }

        // 1) rewrite 指令
        if !loc.rewrites.is_empty() && engine::apply_rewrites(ctx, &loc.rewrites) {
            if let Some((code, target)) = ctx.redirect.take() {
                return redirect_response(code, &target);
            }
            if ctx.internal_redirect {
                ctx.internal_redirect = false;
                ctx.internal_request = true;
                continue;
            }
        }
        // 2) rewrite_by_rust / rewrite_by_lua
        if !run_phases(state, ctx, loc, Phase::Rewrite, server).await {
            if let Some((code, target)) = ctx.redirect.take() {
                return redirect_response(code, &target);
            }
            if ctx.done {
                return finish_response(ctx, server, current_loc);
            }
            if ctx.internal_redirect {
                ctx.internal_redirect = false;
                ctx.internal_request = true;
                ctx.exec_depth = ctx.exec_depth.saturating_add(1);
                continue;
            }
        }
        // 3) PREACCESS：limit_req
        if let Some(resp) = check_limit_req(state, ctx, loc) {
            return resp;
        }
        // 4) ACCESS：access_by_rust / access_by_lua
        if !run_phases(state, ctx, loc, Phase::Access, server).await {
            if let Some((code, target)) = ctx.redirect.take() {
                return redirect_response(code, &target);
            }
            if ctx.done {
                return finish_response(ctx, server, current_loc);
            }
            if ctx.internal_redirect {
                ctx.internal_redirect = false;
                ctx.internal_request = true;
                ctx.exec_depth = ctx.exec_depth.saturating_add(1);
                continue;
            }
        }
        cycle = false;
        break;
    }
    if cycle {
        log_error!(
            "内部重定向成环：'{}' 已跳满 {MAX_URI_CHANGES} 次（检查 rewrite ... last / ngx.exec）",
            ctx.effective_path()
        );
        return error_response(ctx, server, current_loc, 500).await;
    }

    let Some(loc) = current_loc else {
        ctx.status = 404;
        return error_page(StatusCode::NOT_FOUND);
    };

    // return 指令在 access 之前生效（nginx 的 return 属于 rewrite 阶段，这里保持原实现语义）
    if let Some(ret) = &loc.ret {
        engine::apply_return(ctx, ret);
        if let Some((code, target)) = ctx.redirect.take() {
            return redirect_response(code, &target);
        }
        return finish_response(ctx, server, Some(loc));
    }

    // ---- CONTENT ----
    if let Some(target) = &loc.proxy_pass {
        let headers = router::effective_proxy_headers(loc, server);
        let opts = ProxyOpts {
            set_headers: &headers,
            timeouts: ProxyTimeouts {
                connect: Duration::from_secs(loc.proxy_connect_timeout),
                read: Duration::from_secs(loc.proxy_read_timeout),
            },
            next_upstream: &loc.proxy_next_upstream,
        };
        return match state
            .proxy
            .forward(ctx, target, &loc.pattern, &opts, Some(body))
            .await
        {
            Ok(upstream_resp) => convert_upstream_response(upstream_resp, loc, server),
            Err(e) => {
                log_error!("代理失败 {}{}: {e}", target, ctx.effective_path());
                error_response(ctx, server, Some(loc), 502).await
            }
        };
    }

    if let Some((_, name, src)) = loc.lua_phases.iter().find(|(p, _, _)| *p == Phase::Content) {
        // 出错已由 run_lua 记账并置 500，这里只需处理脚本产生的跳转
        if run_lua(state, ctx, name, src).await {
            return finish_response(ctx, server, Some(loc));
        }
        if let Some((code, target)) = ctx.redirect.take() {
            return redirect_response(code, &target);
        }
        if ctx.internal_redirect && ctx.exec_depth < MAX_URI_CHANGES as u8 {
            ctx.internal_redirect = false;
            ctx.internal_request = true;
            ctx.exec_depth += 1;
            return Box::pin(process(state, ctx, server, body)).await;
        }
        // 脚本没产出任何响应体也没 exit：继续按静态兜底（对标 content_by_lua 未命中的常见写法）
        if !ctx.done && ctx.body.as_ref().map(|b| b.is_empty()).unwrap_or(true) {
            return serve_static_flow(state, ctx, server, loc, body).await;
        }
        return finish_response(ctx, server, Some(loc));
    }

    if let Some((_, spec)) = loc.rust_phases.iter().find(|(p, _)| *p == Phase::Content) {
        if let Err(e) = state.handlers.run_phase(Phase::Content, spec, ctx).await {
            log_error!("content_by_rust 失败: {e}");
            return error_response(ctx, server, Some(loc), 500).await;
        }
        return finish_response(ctx, server, Some(loc));
    }

    serve_static_flow(state, ctx, server, loc, body).await
}

/// 执行某个阶段的 rust + lua 处理器；返回 true 表示应当中止（出错）
async fn run_phases(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    loc: &Location,
    phase: Phase,
    server: &Arc<Server>,
) -> bool {
    for (p, spec) in &loc.rust_phases {
        if *p != phase || ctx.done {
            continue;
        }
        if let Err(e) = state.handlers.run_phase(phase, spec, ctx).await {
            log_error!("{phase:?} 阶段处理器 '{}' 失败: {e}", spec.name);
            ctx.status = 500;
            ctx.done = true;
            return true;
        }
    }
    for (p, name, src) in &loc.lua_phases {
        if *p != phase || ctx.done {
            continue;
        }
        if run_lua(state, ctx, name, src).await {
            return true;
        }
    }
    let _ = server;
    false
}

/// 运行一段 Lua；返回 true 表示出错。
/// ctx 通过 Arc<Mutex> 交给 Lua 线程：锁中毒（Lua 里 panic）不能带崩整个站，取回内部值继续。
async fn run_lua(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    name: &str,
    src: &crate::lua_engine::LuaSource,
) -> bool {
    let shared = Arc::new(Mutex::new(std::mem::take(ctx)));
    let r = state.lua.run_phase(name, src, Arc::clone(&shared)).await;
    // 取回 ctx：中毒锁也照常取（宁可带着略过的状态返回，也不要 panic）
    *ctx = match Arc::try_unwrap(shared) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
        // 仍有其他持有者（Lua 线程里残留引用）：克隆一份当前状态
        Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    };
    if let Err(e) = r {
        log_error!("{name} 执行失败: {e}");
        ctx.status = 500;
        ctx.done = true;
        return true;
    }
    false
}

/// limit_req：命中返回 429（带 Retry-After），未命中返回 None
fn check_limit_req(state: &Arc<AppState>, ctx: &mut RequestCtx, loc: &Location) -> Option<BoxResponse> {
    for rule in &loc.limit_req {
        let retry_after = state
            .limits
            .req_zone(&rule.zone)
            .and_then(|z| z.check(&ctx.remote_addr, rule.burst));
        if let Some(secs) = retry_after {
            log_debug!("limit_req '{}' 命中: {}", rule.zone, ctx.remote_addr);
            ctx.status = state.limits.req_status;
            let mut resp = status_page(state.limits.req_status);
            set_header(&mut resp, "retry-after", &secs.to_string());
            return Some(resp);
        }
    }
    None
}

// ==================== 静态文件（try_files / index / autoindex / alias）====================

async fn serve_static_flow(
    state: &Arc<AppState>,
    ctx: &mut RequestCtx,
    server: &Arc<Server>,
    loc: &Location,
    body: Bytes,
) -> BoxResponse {
    let Some(snap) = static_snapshot(ctx, server, loc) else {
        return error_response(ctx, server, Some(loc), 404).await;
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
                .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
        }
        StaticHit::Redirect(target) => redirect_response(301, &target),
        StaticHit::InternalRedirect(last) => {
            if ctx.exec_depth < MAX_URI_CHANGES as u8 {
                ctx.rewritten_path = Some(last);
                ctx.exec_depth += 1;
                ctx.internal_request = true;
                return Box::pin(process(state, ctx, server, body)).await;
            }
            error_response(ctx, server, Some(loc), 404).await
        }
        StaticHit::NotFound => error_response(ctx, server, Some(loc), 404).await,
        StaticHit::Forbidden => error_response(ctx, server, Some(loc), 403).await,
    }
}

enum StaticHit {
    File { code: u16, mime: String, body: Vec<u8> },
    /// 目录存在但 URI 缺尾斜杠：301
    Redirect(String),
    /// try_files 兜底：内部重定向目标
    InternalRedirect(String),
    NotFound,
    Forbidden,
}

/// 静态解析快照：把 ctx/server/location 的相关数据抽成 owned 结构，整体丢进 spawn_blocking
/// （文件系统调用不能留在 async worker 线程上，否则一个慢盘就能卡住该核全部请求）
struct StaticSnap {
    base: PathBuf,
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
    /// nginx 语义：alias 剥掉 location 前缀，root 追加完整 URI
    fn base_rel(&self, path: &str) -> (PathBuf, String) {
        if self.is_alias {
            let rel = path.strip_prefix(&self.pattern).unwrap_or(path);
            (self.base.clone(), rel.trim_start_matches('/').to_string())
        } else {
            (self.base.clone(), path.trim_start_matches('/').to_string())
        }
    }
}

fn resolve_snap(snap: &StaticSnap) -> StaticHit {
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
        if !path.ends_with('/') {
            let q = if snap.query.is_empty() {
                String::new()
            } else {
                format!("?{}", snap.query)
            };
            return StaticHit::Redirect(format!("{path}/{q}"));
        }
        for name in &snap.index {
            let cand = file_path.join(name);
            if cand.is_file() {
                return file_hit(&cand, 200);
            }
        }
        if snap.autoindex {
            if let Some(html) = autoindex_html(&file_path, path) {
                return StaticHit::File {
                    code: 200,
                    mime: "text/html; charset=utf-8".to_string(),
                    body: html.into_bytes(),
                };
            }
        }
        return StaticHit::Forbidden;
    }
    if file_path.is_file() {
        file_hit(&file_path, 200)
    } else {
        StaticHit::NotFound
    }
}

/// 静态文件内存缓存：小文件整体驻留内存，命中后零磁盘读；以 (mtime, size) 做失效校验
const FILE_CACHE_MAX_FILE: u64 = 1024 * 1024;
const FILE_CACHE_MAX_ENTRIES: usize = 512;

type FileCacheInner = HashMap<PathBuf, (u64, u64, Arc<Vec<u8>>)>;
static FILE_CACHE: std::sync::OnceLock<RwLock<FileCacheInner>> = std::sync::OnceLock::new();
use std::sync::RwLock;

fn file_cache() -> &'static RwLock<FileCacheInner> {
    FILE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
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
        if let Ok(cache) = file_cache().read() {
            if let Some((m, sz, body)) = cache.get(path) {
                if *m == mtime && *sz == size {
                    return StaticHit::File {
                        code,
                        mime: mime_of(path).to_string(),
                        body: (**body).clone(),
                    };
                }
            }
        }
    }

    let body = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return StaticHit::NotFound,
    };
    if size <= FILE_CACHE_MAX_FILE {
        if let Ok(mut cache) = file_cache().write() {
            if cache.len() >= FILE_CACHE_MAX_ENTRIES {
                cache.clear(); // 简单淘汰：满即清空，热文件下一轮自动回填
            }
            cache.insert(path.to_path_buf(), (mtime, size, Arc::new(body.clone())));
        }
    }
    StaticHit::File {
        code,
        mime: mime_of(path).to_string(),
        body,
    }
}

/// autoindex：nginx 风格目录列表页（文件名必须转义，否则恶意文件名可注入脚本）
fn autoindex_html(dir: &std::path::Path, uri: &str) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for e in std::fs::read_dir(dir).ok()? {
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        let slash = if e.path().is_dir() { "/" } else { "" };
        let disp = html_escape(&format!("{name}{slash}"));
        let href = url_encode_path_segment(&name) + slash;
        entries.push(format!("<a href=\"{href}\">{disp}</a>"));
    }
    entries.sort();
    Some(format!(
        "<html>\r\n<head><title>Index of {}</title></head>\r\n<body>\r\n<h1>Index of {}</h1><hr><pre><a href=\"../\">../</a>\r\n{}</pre><hr><center>{}</center>\r\n</body>\r\n</html>\r\n",
        html_escape(uri),
        html_escape(uri),
        entries.join("\r\n"),
        SERVER_HEADER
    ))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// 目录列表里的链接要重新做百分号编码，否则含空格/中文的文件名点不开
fn url_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ==================== 响应构造 ====================

fn convert_upstream_response(
    resp: Response<Incoming>,
    loc: &Location,
    server: &Server,
) -> BoxResponse {
    let (mut parts, body) = resp.into_parts();
    let mut builder = Response::builder().status(parts.status);
    {
        let hm = builder.headers_mut().unwrap();
        if let Ok(v) = HeaderValue::from_str(SERVER_HEADER) {
            hm.insert(SERVER, v);
        }
        for (k, v) in parts.headers.drain() {
            let Some(name) = k else { continue };
            if is_hop_by_hop(name.as_str()) {
                continue;
            }
            hm.insert(name, v);
        }
        for (k, v) in router::effective_add_headers(Some(loc), server) {
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
    }
    builder.body(body.boxed()).unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization"
            | "te" | "trailer" | "transfer-encoding" | "upgrade"
    )
}

/// Lua / Rust 处理器产出的响应：resp_headers + add_header + Server 头
fn finish_response(ctx: &RequestCtx, server: &Server, loc: Option<&Location>) -> BoxResponse {
    let status = StatusCode::from_u16(ctx.status).unwrap_or(StatusCode::OK);
    let body = ctx.body.clone().unwrap_or_default();
    let mut builder = Response::builder().status(status);
    {
        let hm = builder.headers_mut().unwrap();
        for (k, v) in &ctx.resp_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
        for (k, v) in router::effective_add_headers(loc, server) {
            if let (Ok(name), Ok(val)) = (
                HeaderName::try_from(k.as_str()),
                HeaderValue::try_from(v.as_str()),
            ) {
                hm.insert(name, val);
            }
        }
        if !hm.contains_key(hyper::header::CONTENT_TYPE) && !body.is_empty() {
            hm.insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
    }
    builder
        .body(full_body(body))
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

fn redirect_response(code: u16, target: &str) -> BoxResponse {
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND))
        .header("location", target)
        .header("server", SERVER_HEADER)
        .body(full_body(String::new()))
        .unwrap_or_else(|_| error_page(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 按 error_page 指令返回自定义错误页；目标文件不存在则退回内置默认页。
/// 读文件放进 spawn_blocking：错误路径同样不能阻塞 async worker。
async fn error_response(
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
    let base = loc
        .and_then(|l| l.root.as_ref().or(l.alias.as_ref()))
        .or(server.root.as_ref())
        .cloned();
    let file = match (target, base) {
        (Some(t), Some(base)) => {
            let f = base.join(t.trim_start_matches('/'));
            Some(f)
        }
        _ => None,
    };
    if let Some(file) = file {
        let read = tokio::task::spawn_blocking(move || {
            if file.is_file() {
                Some((mime_of(&file).to_string(), std::fs::read(&file).unwrap_or_default()))
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten();
        if let Some((mime, content)) = read {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            return Response::builder()
                .status(status)
                .header("content-type", mime)
                .header("server", SERVER_HEADER)
                .body(full_body(content))
                .unwrap_or_else(|_| error_page(status));
        }
    }
    error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

fn status_page(code: u16) -> BoxResponse {
    error_page(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 显式要求关闭连接：用于请求体没读完就必须回错的场景（413/408）
fn close_now(mut resp: BoxResponse) -> BoxResponse {
    resp.headers_mut().insert(
        hyper::header::CONNECTION,
        HeaderValue::from_static("close"),
    );
    resp
}

fn set_header(resp: &mut BoxResponse, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
        resp.headers_mut().insert(n, v);
    }
}

/// nginx/OpenResty 风格默认错误页
fn error_page(status: StatusCode) -> BoxResponse {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!(
        "<html>\n<head><title>{code} {reason}</title></head>\n<body>\n<center><h1>{code} {reason}</h1></center>\n<hr><center>{SERVER_HEADER}</center>\n</body>\n</html>\n"
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", SERVER_HEADER)
        .body(full_body(body))
        .unwrap_or_else(|_| {
            // 连状态码都不合法时（理论不可达）退回 500 的裸响应
            Response::new(empty_body())
        })
}

fn mime_of(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" | "lua" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

// ==================== 工具 ====================

use hyper::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
const HOST_NAME: HeaderName = HeaderName::from_static("host");

fn proto_name(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

fn header_of(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

fn is_supported_method(m: &Method) -> bool {
    matches!(
        m.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

/// 路径解码 + 归一化（RFC 3986）：
/// - `%XX` 百分号解码（不把 '+' 当空格：那是表单编码的规则，不适用于路径）
/// - `\` 视作 `/`（Windows 文件系统把反斜杠当分隔符，不处理会绕过穿越检测）
/// - 消除 `.` / `..`；`..` 越出根 → 拒绝
/// - 解码后含 NUL 或控制字符 → 拒绝
fn decode_and_normalize(raw: &str) -> Option<String> {
    if raw.contains('\0') {
        return None;
    }
    let mut decoded: Vec<u8> = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                let b = u8::from_str_radix(hex, 16).ok()?;
                // 编码过的分隔符与控制字符同样危险（%2e%2e%2f、%00 之类）
                if b == b'/' || b < 0x20 || b == 0x7f {
                    return None;
                }
                decoded.push(b);
                i += 3;
            }
            b'%' => return None, // 截断的 % 转义
            c => {
                decoded.push(c);
                i += 1;
            }
        }
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    if decoded.chars().any(|c| (c as u32) < 0x20 || c == '\0') {
        return None;
    }
    let unified = decoded.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    for seg in unified.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segs.pop().is_none() {
                    return None;
                }
            }
            _ => segs.push(seg),
        }
    }
    let mut out = String::with_capacity(unified.len() + 1);
    out.push('/');
    out.push_str(&segs.join("/"));
    // 保留尾部斜杠：目录语义（index / 301 补斜杠）依赖它
    if unified.ends_with('/') && !out.ends_with('/') {
        out.push('/');
    }
    Some(out)
}

/// 供 main 使用的连接额度表
pub fn permits_for(settings: &Settings) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(settings.worker_connections.max(1)))
}
