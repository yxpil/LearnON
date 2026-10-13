//! Lua 引擎：OpenResty 的 LuaJIT + ngx.* 在 Rust 侧的对应物。
//!
//! - VM：mlua (Lua 5.4)，进程级共享，请求阶段串行执行（与 OpenResty 的
//!   "每 worker 一个 VM" 思路一致，简化为每进程一个）
//! - API：ngx.say/print/status/exit/header/req.*/ctx/sleep/time/log/
//!   shared.DICT/redirect/exec/re.*/encode_base64/decode_base64/
//!   escape_uri/unescape_uri/decode_args/encode_args/config —— 语义对齐 ngx_lua
//! - 请求状态放在 `Arc<Mutex<RequestCtx>>`，脚本通过 userdata 句柄读写，
//!   阶段结束后由 Rust 侧继续接管同一个 ctx

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mlua::prelude::*;
use mlua::{AnyUserData, Variadic};

use learnon_config::Config;

use crate::engine::RequestCtx;
use crate::shared_dict::SharedDicts;
use crate::{resolve_path, AppError};

/// 请求句柄 userdata：Lua 里所有 ngx.* 都通过它操作当前请求
#[derive(Clone)]
struct CtxHandle(Arc<Mutex<RequestCtx>>);

impl LuaUserData for CtxHandle {}

/// 阶段脚本来源：内联代码（content_by_lua "code"）或文件（content_by_lua_file "path"）
#[derive(Debug, Clone)]
pub enum LuaSource {
    Inline(String),
    File(PathBuf),
}

impl LuaSource {
    pub fn load(&self) -> Result<String, AppError> {
        match self {
            LuaSource::Inline(s) => Ok(s.clone()),
            LuaSource::File(p) => std::fs::read_to_string(p)
                .map_err(|e| AppError::Other(format!("读取 Lua 文件失败 {}: {e}", p.display()))),
        }
    }

    pub fn from_directive(d: &learnon_config::Directive, base_dir: &PathBuf) -> Option<LuaSource> {
        let arg = d.arg(0)?;
        Some(if d.name.ends_with("_file") {
            LuaSource::File(resolve_path(arg, base_dir))
        } else {
            LuaSource::Inline(arg.to_string())
        })
    }
}

pub struct LuaEngine {
    lua: Lua,
    exec_lock: tokio::sync::Mutex<()>,
}

// ---------- 编解码工具（无第三方依赖的 base64 / percent-encoding） ----------

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(B64_ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && c != b'\r' && c != b'\n').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - i * 6);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn is_uri_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// 对标 ngx.escape_uri：只保留字母数字与 -._~，其余全部 %XX（含 '/'）
pub fn escape_uri(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if is_uri_unreserved(c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// 对标 ngx.unescape_uri：%XX 解码 + '+' 还原为空格
pub fn unescape_uri(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(c) => {
                        out.push(c);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 对标 ngx.decode_args："a=1&b=two&flag" -> {a="1", b="two", flag=true}
fn decode_args(query: &str) -> Vec<(String, LuaArgValue)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => out.push((unescape_uri(k), LuaArgValue::Str(unescape_uri(v)))),
            None => out.push((unescape_uri(pair), LuaArgValue::Flag)),
        }
    }
    out
}

/// 参数值：字符串或布尔标志
pub enum LuaArgValue {
    Str(String),
    Flag,
}

fn push_args_table(lua: &Lua, args: Vec<(String, LuaArgValue)>) -> LuaResult<LuaTable> {
    let t = lua.create_table()?;
    for (k, v) in args {
        match v {
            LuaArgValue::Str(s) => t.raw_set(k, s)?,
            LuaArgValue::Flag => t.raw_set(k, true)?,
        }
    }
    Ok(t)
}

impl LuaEngine {
    pub fn new(config: &Config, base_dir: &PathBuf) -> Result<Self, AppError> {
        let lua = Lua::new();
        let dicts = SharedDicts::parse_all(config);
        Self::install_api(&lua, &dicts)?;
        let engine = LuaEngine {
            lua,
            exec_lock: tokio::sync::Mutex::new(()),
        };

        // init_by_lua / init_by_lua_file：服务器启动时执行一次
        for name in ["init_by_lua", "init_by_lua_file"] {
            if let Some(d) = config.find(name) {
                let Some(arg) = d.arg(0) else { continue };
                let code = if name.ends_with("_file") {
                    std::fs::read_to_string(resolve_path(arg, base_dir))
                        .map_err(|e| AppError::Other(format!("读取 {arg}: {e}")))?
                } else {
                    arg.to_string()
                };
                engine.lua.load(&code).set_name(name).exec()?;
                println!("[learnon] 已执行 {name}");
            }
        }
        Ok(engine)
    }

    fn install_api(lua: &Lua, dicts: &SharedDicts) -> Result<(), AppError> {
        let get_ctx = |lua: &Lua| -> LuaResult<CtxHandle> {
            let ud: AnyUserData = lua.named_registry_value("__ctx")?;
            let h = ud.borrow::<CtxHandle>()?;
            Ok(h.clone())
        };

        let ngx = lua.create_table()?;

        // ngx.say(...) / ngx.print(...) —— 追加响应体（say 换行，print 不换）
        for (fname, newline) in [("say", true), ("print", false)] {
            let f = lua.create_function(move |lua, args: Variadic<LuaValue>| {
                let h = get_ctx(lua)?;
                let mut ctx = h.0.lock().unwrap();
                for (i, v) in args.iter().enumerate() {
                    if i > 0 {
                        ctx.body.get_or_insert_with(Vec::new).push(b' ');
                    }
                    let text: Vec<u8> = match v {
                        LuaValue::String(s) => s.as_bytes().to_vec(),
                        LuaValue::Integer(n) => n.to_string().into_bytes(),
                        LuaValue::Number(n) => n.to_string().into_bytes(),
                        LuaValue::Nil => b"nil".to_vec(),
                        other => format!("{other:?}").into_bytes(),
                    };
                    ctx.body.get_or_insert_with(Vec::new).extend_from_slice(&text);
                }
                if newline {
                    ctx.body.get_or_insert_with(Vec::new).push(b'\n');
                }
                Ok(())
            })?;
            ngx.set(fname, f)?;
        }

        // ngx.log(level, msg...) —— 打到 stdout
        let log = lua.create_function(|_lua, args: Variadic<String>| {
            println!("[lua] {}", args.join(" "));
            Ok(())
        })?;
        ngx.set("log", log)?;

        // ngx.exit(status) —— 结束请求
        let exit = lua.create_function(move |lua, code: Option<u16>| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            if let Some(c) = code {
                ctx.status = c;
            }
            ctx.done = true;
            Ok(())
        })?;
        ngx.set("exit", exit)?;

        // ngx.redirect(uri, status?) —— 外部重定向（默认 302）
        let redirect = lua.create_function(move |lua, (uri, code): (String, Option<u16>)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.redirect = Some((code.unwrap_or(302), uri));
            ctx.done = true;
            Ok(())
        })?;
        ngx.set("redirect", redirect)?;

        // ngx.exec(uri) —— 内部重定向（跳转内部 location，客户端无感）
        let exec = lua.create_function(move |lua, uri: String| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            ctx.rewritten_path = Some(uri);
            ctx.internal_redirect = true;
            Ok(())
        })?;
        ngx.set("exec", exec)?;

        // ngx.sleep(ms) —— 异步睡眠（协程让出，不阻塞 worker）
        let sleep = lua.create_async_function(|_, ms: u64| async move {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            Ok(())
        })?;
        ngx.set("sleep", sleep)?;

        // ngx.time() / ngx.now()
        let time = lua.create_function(|_, ()| Ok(chrono::Utc::now().timestamp()))?;
        ngx.set("time", time)?;
        let now = lua.create_function(|_, ()| Ok(chrono::Utc::now().timestamp_millis() as f64 / 1000.0))?;
        ngx.set("now", now)?;

        // ngx.header —— 响应头（ngx.header["X"] = "v"；读请求头用 ngx.req）
        let header = lua.create_table()?;
        let header_set = lua.create_function(move |lua, (name, value): (String, Option<LuaValue>)| {
            let h = get_ctx(lua)?;
            let mut ctx = h.0.lock().unwrap();
            let key = name.to_lowercase();
            ctx.resp_headers.retain(|(k, _)| k.to_lowercase() != key);
            match value {
                Some(LuaValue::String(s)) => {
                    ctx.resp_headers.push((key, s.to_string_lossy().to_string()));
                }
                Some(LuaValue::Integer(n)) => ctx.resp_headers.push((key, n.to_string())),
                _ => {} // nil = 删除
            }
            Ok(())
        })?;
        header.set("set", header_set)?;
        ngx.set("header", header)?;

        // ngx.req.* —— 请求信息
        let req = lua.create_table()?;
        for (fname, field) in [
            ("get_method", "method"),
            ("get_path", "path"),
            ("get_query", "query"),
        ] {
            let f = lua.create_function(move |lua, ()| {
                let h = get_ctx(lua)?;
                let ctx = h.0.lock().unwrap();
                let v = match field {
                    "method" => ctx.method.clone(),
                    "path" => ctx.effective_path().to_string(),
                    _ => ctx.query.clone(),
                };
                Ok(LuaValue::String(lua.create_string(v)?))
            })?;
            req.set(fname, f)?;
        }
        let get_headers = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            let t = lua.create_table()?;
            for (k, v) in &ctx.req_headers {
                t.raw_set(k.as_str(), v.as_str())?;
            }
            Ok(LuaValue::Table(t))
        })?;
        req.set("get_headers", get_headers)?;

        // ngx.req.get_uri_args() —— 查询串解析为表
        let get_uri_args = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let query = h.0.lock().unwrap().query.clone();
            Ok(LuaValue::Table(push_args_table(lua, decode_args(&query))?))
        })?;
        req.set("get_uri_args", get_uri_args)?;

        // ngx.req.set_uri(path) —— 重写请求路径（不含 query）
        let set_uri = lua.create_function(move |lua, path: String| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().rewritten_path = Some(path);
            Ok(())
        })?;
        req.set("set_uri", set_uri)?;

        // ngx.req.set_uri_args(args) —— 覆盖 query（字符串或表）
        let set_uri_args = lua.create_function(move |lua, args: LuaValue| {
            let h = get_ctx(lua)?;
            let q = match args {
                LuaValue::String(s) => s.to_string_lossy().to_string(),
                LuaValue::Table(t) => {
                    let mut parts = Vec::new();
                    for pair in t.pairs::<LuaValue, LuaValue>() {
                        let (k, v) = pair?;
                        let key: String = match k {
                            LuaValue::String(s) => s.to_string_lossy().to_string(),
                            other => format!("{other:?}"),
                        };
                        match v {
                            LuaValue::Nil => parts.push(escape_uri(&key)),
                            LuaValue::Boolean(true) => parts.push(escape_uri(&key)),
                            other => {
                                let val: String = match other {
                                    LuaValue::String(s) => s.to_string_lossy().to_string(),
                                    LuaValue::Integer(n) => n.to_string(),
                                    LuaValue::Number(n) => n.to_string(),
                                    _ => format!("{other:?}"),
                                };
                                parts.push(format!("{}={}", escape_uri(&key), escape_uri(&val)));
                            }
                        }
                    }
                    parts.join("&")
                }
                _ => return Err(mlua::Error::external("set_uri_args: 参数必须是字符串或表")),
            };
            h.0.lock().unwrap().query = q;
            Ok(())
        })?;
        req.set("set_uri_args", set_uri_args)?;

        // ngx.req.get_body_data() —— 请求体（已由 server 层缓冲）
        let get_body = lua.create_function(move |lua, ()| {
            let h = get_ctx(lua)?;
            let ctx = h.0.lock().unwrap();
            if ctx.req_body.is_empty() {
                Ok(LuaValue::Nil)
            } else {
                Ok(LuaValue::String(lua.create_string(&ctx.req_body)?))
            }
        })?;
        req.set("get_body_data", get_body)?;

        ngx.set("req", req)?;

        // ngx.re.* —— 正则（桥接 Rust regex crate；对标 PCRE 的常用子集）
        let re = lua.create_table()?;

        fn build_regex(pattern: &str, flags: Option<String>) -> LuaResult<regex::Regex> {
            let mut builder = regex::RegexBuilder::new(pattern);
            if let Some(f) = flags {
                if f.contains('i') {
                    builder.case_insensitive(true);
                }
            }
            builder.build().map_err(mlua::Error::external)
        }

        // ngx.re.match(s, pattern, flags?) -> {cap1, cap2, ...} | nil
        let re_match = lua.create_function(move |lua, (s, pattern, flags): (String, String, Option<String>)| {
            let re = build_regex(&pattern, flags)?;
            let Some(caps) = re.captures(&s) else {
                return Ok(LuaValue::Nil);
            };
            let t = lua.create_table()?;
            for i in 1..caps.len() {
                if let Some(m) = caps.get(i) {
                    t.raw_set(i as i64, m.as_str())?;
                }
            }
            Ok(LuaValue::Table(t))
        })?;
        re.set("match", re_match)?;

        // ngx.re.find(s, pattern, flags?) -> from, to（1-based；无匹配返回 nil）
        let re_find = lua.create_function(move |_, (s, pattern, flags): (String, String, Option<String>)| {
            let re = build_regex(&pattern, flags)?;
            match re.find(&s) {
                Some(m) => Ok((Some(m.start() as i64 + 1), Some(m.end() as i64))),
                None => Ok((None, None)),
            }
        })?;
        re.set("find", re_find)?;
        ngx.set("re", re)?;

        // ngx.shared.DICT —— lua_shared_dict 声明的共享区
        let shared = lua.create_table()?;
        for (name, zone) in &dicts.zones {
            shared.raw_set(name.as_str(), zone.clone())?;
        }
        ngx.set("shared", shared)?;

        // ngx.encode_base64 / decode_base64
        let b64e = lua.create_function(|lua, s: LuaString| {
            let bytes = s.as_bytes().to_vec();
            let encoded = b64_encode(&bytes);
            Ok(LuaValue::String(lua.create_string(encoded)?))
        })?;
        ngx.set("encode_base64", b64e)?;
        let b64d = lua.create_function(|lua, s: LuaString| {
            match b64_decode(&s.to_string_lossy()) {
                Some(b) => Ok(LuaValue::String(lua.create_string(&b)?)),
                None => Err(mlua::Error::external("decode_base64: 非法输入")),
            }
        })?;
        ngx.set("decode_base64", b64d)?;

        // ngx.escape_uri / unescape_uri
        let eu = lua.create_function(|_, s: LuaString| Ok(escape_uri(&s.to_string_lossy())))?;
        ngx.set("escape_uri", eu)?;
        let uu = lua.create_function(|_, s: LuaString| Ok(unescape_uri(&s.to_string_lossy())))?;
        ngx.set("unescape_uri", uu)?;

        // ngx.decode_args / encode_args
        let da = lua.create_function(move |lua, s: LuaString| {
            let q = s.to_string_lossy().to_string();
            Ok(LuaValue::Table(push_args_table(lua, decode_args(&q))?))
        })?;
        ngx.set("decode_args", da)?;
        let ea = lua.create_function(|_, t: LuaTable| {
            let mut parts = Vec::new();
            for pair in t.pairs::<LuaValue, LuaValue>() {
                let (k, v) = pair?;
                let key: String = match k {
                    LuaValue::String(s) => s.to_string_lossy().to_string(),
                    other => format!("{other:?}"),
                };
                match v {
                    LuaValue::Nil => parts.push(escape_uri(&key)),
                    LuaValue::Boolean(true) => parts.push(escape_uri(&key)),
                    other => {
                        let val: String = match other {
                            LuaValue::String(s) => s.to_string_lossy().to_string(),
                            LuaValue::Integer(n) => n.to_string(),
                            LuaValue::Number(n) => n.to_string(),
                            _ => continue,
                        };
                        parts.push(format!("{}={}", escape_uri(&key), escape_uri(&val)));
                    }
                }
            }
            Ok(parts.join("&"))
        })?;
        ngx.set("encode_args", ea)?;

        // ngx.config —— 版本信息（服务器品牌：LearnON）
        let config_tbl = lua.create_table()?;
        config_tbl.set("server", "LearnON")?;
        config_tbl.set("server_version", env!("CARGO_PKG_VERSION"))?;
        config_tbl.set("nginx_version", "1.27.0-compatible")?;
        config_tbl.set("ngx_lua_version", "0.10.28-compatible")?;
        config_tbl.set("learnon_version", env!("CARGO_PKG_VERSION"))?;
        ngx.set("config", config_tbl)?;

        // ngx.status —— 通过 metatable 支持读写：ngx.status = 201 / 读取 ngx.status
        let status_get = lua.create_function(move |_lua, ()| {
            let h = get_ctx(_lua)?;
            let v = h.0.lock().unwrap().status as i64;
            Ok(LuaValue::Integer(v))
        })?;
        let status_set = lua.create_function(move |lua, code: u16| {
            let h = get_ctx(lua)?;
            h.0.lock().unwrap().status = code;
            Ok(())
        })?;
        ngx.set("_get_status", status_get)?;
        ngx.set("_set_status", status_set)?;
        let mt = lua.create_table()?;
        let idx = lua.create_function(move |lua, (t, key): (LuaTable, String)| {
            match key.as_str() {
                "status" => {
                    let f: LuaFunction = t.raw_get("_get_status")?;
                    f.call(())
                }
                _ => Ok(LuaValue::Nil),
            }
        })?;
        let newidx = lua.create_function(move |lua, (t, key, value): (LuaTable, String, LuaValue)| {
            if key == "status" {
                let code = value.as_integer().unwrap_or(200) as u16;
                let f: LuaFunction = t.raw_get("_set_status")?;
                f.call::<()>(code)?;
            } else {
                t.raw_set(key, value)?;
            }
            Ok(())
        })?;
        mt.set("__index", idx)?;
        mt.set("__newindex", newidx)?;
        ngx.set_metatable(Some(mt));

        // ngx.ctx —— 每请求共享表
        let ctx_new = lua.create_function(|lua, ()| Ok(LuaValue::Table(lua.create_table()?)))?;
        ngx.set("ctx", ctx_new)?;

        ngx.raw_set("version", env!("CARGO_PKG_VERSION"))?;
        lua.globals().set("ngx", ngx)?;

        Ok(())
    }

    /// 执行一个请求阶段脚本（串行化；ctx 由 Rust 侧传入、改完带回去）
    pub async fn run_phase(
        &self,
        phase_name: &str,
        src: &LuaSource,
        ctx: Arc<Mutex<RequestCtx>>,
    ) -> Result<(), AppError> {
        let _guard = self.exec_lock.lock().await;
        let code = src.load()?;

        self.lua.set_named_registry_value("__ctx", CtxHandle(ctx))?;
        // ngx.ctx：每请求一张真实表（对标 OpenResty 的 ngx.ctx）
        let ngx: LuaTable = self.lua.globals().get("ngx")?;
        let ctx_table: LuaTable = self.lua.create_table()?;
        ngx.raw_set("ctx", ctx_table)?;
        let result = self
            .lua
            .load(&code)
            .set_name(phase_name)
            .exec_async()
            .await;
        let _ = self.lua.unset_named_registry_value("__ctx");

        result.map_err(|e| {
            eprintln!("[learnon] {phase_name} 脚本错误: {e}");
            AppError::Lua(e)
        })
    }
}

// ---------- SharedZone 的 Lua 绑定（ngx.shared.<name>） ----------

impl LuaUserData for crate::shared_dict::SharedZone {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // d:get(key) -> string | nil
        methods.add_method("get", |lua, this, key: String| {
            Ok(this
                .get(&key)
                .map(|b| LuaValue::String(lua.create_string(&b).unwrap())))
        });
        // d:get_stale(key) -> string | nil（含过期项）
        methods.add_method("get_stale", |lua, this, key: String| {
            Ok(this
                .get_stale(&key)
                .map(|b| LuaValue::String(lua.create_string(&b).unwrap())))
        });
        // d:set(key, value, ex?) / safe_set —— value 支持 string/number/boolean
        for m in ["set", "safe_set"] {
            methods.add_method(
                m,
                |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                    let bytes = lua_value_to_bytes(&value)
                        .ok_or_else(|| mlua::Error::external("值类型不支持（仅 string/number/boolean）"))?;
                    this.set(&key, bytes, ex);
                    Ok(())
                },
            );
        }
        // d:add(key, value, ex?) -> bool（已存在则 false）
        methods.add_method(
            "add",
            |lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                Ok(this.add(&key, bytes, ex))
            },
        );
        // d:replace(key, value, ex?) -> bool（不存在则 false）
        methods.add_method(
            "replace",
            |_lua, this, (key, value, ex): (String, LuaValue, Option<f64>)| {
                let bytes = lua_value_to_bytes(&value)
                    .ok_or_else(|| mlua::Error::external("值类型不支持"))?;
                Ok(this.replace(&key, bytes, ex))
            },
        );
        // d:delete(key)
        methods.add_method("delete", |_, this, key: String| {
            this.delete(&key);
            Ok(())
        });
        // d:incr(key, delta, init?) -> new_value（失败抛错，对标返回 nil+err）
        methods.add_method(
            "incr",
            |_, this, (key, delta, init): (String, i64, Option<i64>)| {
                this.incr(&key, delta, init).map_err(mlua::Error::external)
            },
        );
        // d:ttl(key) -> 剩余秒数 | -1（永不过期）| nil（不存在）
        methods.add_method("ttl", |_, this, key: String| Ok(this.ttl(&key)));
        // d:flush_all()
        methods.add_method("flush_all", |_, this, ()| {
            this.flush_all();
            Ok(())
        });
    }
}

fn lua_value_to_bytes(v: &LuaValue) -> Option<Vec<u8>> {
    match v {
        LuaValue::String(s) => Some(s.as_bytes().to_vec()),
        LuaValue::Integer(n) => Some(n.to_string().into_bytes()),
        LuaValue::Number(n) => Some(n.to_string().into_bytes()),
        LuaValue::Boolean(true) => Some(b"true".to_vec()),
        LuaValue::Boolean(false) => Some(b"false".to_vec()),
        _ => None,
    }
}
