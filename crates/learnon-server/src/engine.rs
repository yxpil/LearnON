//! 引擎：rewrite/return 规则执行 + Rust 原生处理器注册表（对标 OpenResty 的 *_by_lua，但全部 Rust 编译期实现）。
//!
//! 配置指令：
//! ```text
//! rewrite ^/old/(.*)$ /new/$1 last;
//! return 301 http://example.com;
//! content_by_rust hello;          # 调用注册的 Rust 处理器
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::future::BoxFuture;

use learnon_config::Directive;

use crate::AppError;

// ---------- 请求上下文（贯穿 rewrite -> access -> content） ----------

#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    pub method: String,
    /// 解码并归一化后的路径（用于 location 匹配与静态文件解析）
    pub path: String,
    pub query: String,
    /// 客户端发来的原始 URI（含 query，未解码）——日志与 $request_uri 用它
    pub uri: String,
    pub host: Option<String>,
    pub remote_addr: String,
    /// 客户端端口（`$remote_port`）
    pub remote_port: u16,
    /// 本服务监听端口（`$server_port`）
    pub server_port: u16,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    /// 处理过程中可能被 rewrite 修改后的路径
    pub rewritten_path: Option<String>,
    pub status: u16,
    /// 生成式响应体（return / rust handler 产出）
    pub body: Option<Vec<u8>>,
    pub done: bool,
    /// rewrite ... last 触发的内部重定向
    pub internal_redirect: bool,
    /// 请求体（当前缓冲式读取；供 Lua 读取与代理转发）
    pub req_body: Vec<u8>,
    /// ngx.exec 内部重定向深度
    pub exec_depth: u8,
    /// rewrite ... redirect/permanent 触发的外部重定向
    pub redirect: Option<(u16, String)>,
    /// 客户端侧协议（http/https）；由连接的 TLS 状态决定，用于 X-Forwarded-Proto
    pub scheme: String,
    /// 本次请求是否为内部重定向产物（`internal;` location 只放行这类请求）
    pub internal_request: bool,
    /// body_filter_by_lua 参数：ngx.arg[1]=chunk, ngx.arg[2]=eof
    pub filter_chunk: Option<Vec<u8>>,
    pub filter_eof: bool,
}

impl RequestCtx {
    pub fn effective_path(&self) -> &str {
        self.rewritten_path.as_deref().unwrap_or(&self.path)
    }

    /// 定时器/后台任务用的游离上下文：不属于任何请求，ngx.say 等写入落到这里被丢弃
    /// （对标 OpenResty 的 fake request client）
    pub fn detached() -> RequestCtx {
        RequestCtx {
            method: "GET".to_string(),
            path: "@timer".to_string(),
            query: String::new(),
            uri: "@timer".to_string(),
            host: None,
            remote_addr: "0.0.0.0".to_string(),
            remote_port: 0,
            server_port: 0,
            req_headers: Vec::new(),
            resp_headers: Vec::new(),
            rewritten_path: None,
            status: 200,
            body: None,
            done: false,
            internal_redirect: false,
            req_body: Vec::new(),
            exec_depth: 0,
            redirect: None,
            scheme: "http".to_string(),
            internal_request: true,
            filter_chunk: None,
            filter_eof: false,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// 语义上不带请求体的方法（转发时不给它们补 Content-Length）
    pub fn is_bodyless_method(&self) -> bool {
        matches!(self.method.as_str(), "GET" | "HEAD")
    }

    pub fn set_resp_header(&mut self, name: &str, value: &str) {
        let key = name.to_lowercase();
        self.resp_headers.retain(|(k, _)| k.to_lowercase() != key);
        self.resp_headers.push((key, value.to_string()));
    }

    pub fn say(&mut self, text: &str) {
        self.body
            .get_or_insert_with(Vec::new)
            .extend_from_slice(text.as_bytes());
    }
}

// ---------- rewrite / return ----------

#[derive(Debug, Clone)]
pub enum RewriteFlag {
    /// 重新匹配 location
    Last,
    /// 停在本 location，继续后续处理
    Break,
    /// 302 外部重定向
    Redirect,
    /// 301 外部重定向
    Permanent,
}

#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub pattern: regex::Regex,
    pub replacement: String,
    pub flag: RewriteFlag,
}

/// return 指令：状态码 + 可选文本/URL
#[derive(Debug, Clone)]
pub struct ReturnAction {
    pub code: u16,
    pub text: Option<String>,
}

/// 对 ctx 依次应用 rewrite 规则；返回是否需要停止处理
pub fn apply_rewrites(ctx: &mut RequestCtx, rules: &[RewriteRule]) -> bool {
    for rule in rules {
        let path = ctx.effective_path().to_string();
        if let Some(caps) = rule.pattern.captures(&path) {
            let mut replaced = rule.replacement.clone();
            // $1..$9 反向引用
            for i in (1..10).rev() {
                let cap = caps
                    .get(i)
                    .map(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                replaced = replaced.replace(&format!("${i}"), &cap);
            }
            match rule.flag {
                RewriteFlag::Redirect | RewriteFlag::Permanent => {
                    let code = if matches!(rule.flag, RewriteFlag::Permanent) { 301 } else { 302 };
                    let target = if replaced.starts_with("http") {
                        replaced
                    } else {
                        format!("http://{}{}", ctx.host.as_deref().unwrap_or("localhost"), replaced)
                    };
                    ctx.redirect = Some((code, target));
                    ctx.done = true;
                    return true;
                }
                RewriteFlag::Last => {
                    ctx.rewritten_path = Some(replaced);
                    ctx.internal_redirect = true;
                    return true;
                }
                RewriteFlag::Break => {
                    ctx.rewritten_path = Some(replaced);
                    return true;
                }
            }
        }
    }
    false
}

pub fn apply_return(ctx: &mut RequestCtx, ret: &ReturnAction) {
    ctx.status = ret.code;
    // return 301/302 <url>：URL 放入 Location（对标 nginx）
    if matches!(ret.code, 301 | 302 | 303 | 307 | 308) {
        if let Some(url) = &ret.text {
            ctx.set_resp_header("location", url);
            ctx.body = None;
            ctx.done = true;
            return;
        }
    }
    ctx.body = ret.text.clone().map(|t| t.into_bytes());
    ctx.done = true;
}

// ---------- Rust 原生处理器（对标 ngx Lua 模块，编译进二进制） ----------

pub type NativeHandler = Arc<
    dyn for<'a> Fn(&'a mut RequestCtx, &'a [String]) -> BoxFuture<'a, Result<(), String>>
        + Send
        + Sync,
>;

#[derive(Default, Clone)]
pub struct HandlerRegistry {
    map: HashMap<String, NativeHandler>,
}

/// 阶段归属（对应 nginx 的处理阶段）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Rewrite,
    Access,
    Content,
    /// LOG：响应完成后运行（log_by_lua / log_by_rust），其输出被丢弃、不影响已发送的响应
    Log,
}

impl Phase {
    pub fn directive_names() -> &'static [&'static str] {
        &["rewrite_by_rust", "access_by_rust", "content_by_rust", "log_by_rust"]
    }

    pub fn from_directive(name: &str) -> Option<Phase> {
        match name {
            "rewrite_by_rust" => Some(Phase::Rewrite),
            "access_by_rust" => Some(Phase::Access),
            "content_by_rust" => Some(Phase::Content),
            "log_by_rust" => Some(Phase::Log),
            _ => None,
        }
    }
}

/// 处理器规格：来自配置 `content_by_rust name arg1 arg2`
#[derive(Debug, Clone)]
pub struct HandlerSpec {
    pub name: String,
    pub args: Vec<String>,
}

impl HandlerRegistry {
    pub fn with_builtins() -> Self {
        let mut reg = HandlerRegistry::default();

        // echo：输出文本（含变量插值）
        reg.register("echo", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                let text = args.join(" ");
                ctx.say(&crate::proxy::interpolate_vars(&text, ctx));
                Ok(())
            })
        });

        // time：模拟慢接口（sleep 后输出 JSON），演示异步不阻塞
        reg.register("time", |ctx: &mut RequestCtx, _args: &[String]| {
            Box::pin(async move {
                let start = std::time::Instant::now();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                ctx.set_resp_header("content-type", "application/json");
                ctx.say(&format!(
                    "{{\"now\": \"{}\", \"elapsed_ms\": {:.2}}}",
                    now,
                    start.elapsed().as_secs_f64() * 1000.0
                ));
                Ok(())
            })
        });

        // auth：access 阶段 token 鉴权，auth <期望token>
        reg.register("auth", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                let expect = args.first().map(|s| s.as_str()).unwrap_or("");
                match ctx.header("x-token") {
                    Some(t) if t == expect => Ok(()),
                    Some(_) => {
                        ctx.status = 403;
                        ctx.say("forbidden: bad token");
                        ctx.done = true;
                        Ok(())
                    }
                    None => {
                        ctx.status = 401;
                        ctx.say("unauthorized: missing x-token header");
                        ctx.done = true;
                        Ok(())
                    }
                }
            })
        });

        // status：直接返回指定状态码与文本
        reg.register("status", |ctx: &mut RequestCtx, args: &[String]| {
            Box::pin(async move {
                ctx.status = args
                    .first()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200);
                if let Some(text) = args.get(1) {
                    ctx.say(&crate::proxy::interpolate_vars(text, ctx));
                }
                Ok(())
            })
        });

        // info：打印请求画像（调试用）
        reg.register("info", |ctx: &mut RequestCtx, _args: &[String]| {
            Box::pin(async move {
                ctx.set_resp_header("content-type", "text/plain; charset=utf-8");
                ctx.say(&format!(
                    "method={}\npath={}\nquery={}\nremote={}\nhost={:?}\nheaders={:?}",
                    ctx.method, ctx.path, ctx.query, ctx.remote_addr, ctx.host, ctx.req_headers
                ));
                Ok(())
            })
        });

        reg
    }

    pub fn register<F>(&mut self, name: &str, h: F)
    where
        F: for<'a> Fn(&'a mut RequestCtx, &'a [String]) -> BoxFuture<'a, Result<(), String>>
            + Send
            + Sync
            + 'static,
    {
        self.map.insert(name.to_string(), Arc::new(h));
    }

    pub fn get(&self, name: &str) -> Option<&NativeHandler> {
        self.map.get(name)
    }

    /// 执行一个 rust 阶段
    pub async fn run_phase(
        &self,
        phase: Phase,
        spec: &HandlerSpec,
        ctx: &mut RequestCtx,
    ) -> Result<(), AppError> {
        let h = self.get(&spec.name).ok_or_else(|| {
            AppError::Other(format!(
                "{phase:?} 阶段找不到处理器 '{spec_name}'（未注册）",
                spec_name = spec.name
            ))
        })?;
        h(ctx, &spec.args)
            .await
            .map_err(AppError::Other)
    }
}

/// 从配置指令构造 HandlerSpec
pub fn spec_from_directive(d: &Directive) -> Option<HandlerSpec> {
    let name = d.arg(0)?;
    Some(HandlerSpec {
        name: name.to_string(),
        args: d.args[1..].to_vec(),
    })
}
