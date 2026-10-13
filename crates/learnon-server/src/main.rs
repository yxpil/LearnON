//! LearnON — 用 Rust 从零实现的 OpenResty / Nginx 风格网关服务器。
//!
//! 功能对照（逐项翻译自 Nginx / OpenResty）：
//! | Nginx / OpenResty            | LearnON (Rust)                          |
//! |------------------------------|------------------------------------------|
//! | master/worker 事件循环        | tokio 异步运行时                         |
//! | nginx.conf                   | 自研 Nginx 风格配置解析器                 |
//! | upstream + 负载均衡           | upstream.rs（rr / least_conn / ip_hash） |
//! | proxy_pass 反向代理           | proxy.rs（hyper 连接池，流式转发）        |
//! | rewrite / return             | engine.rs（regex + last/break/redirect） |
//! | location = / ~ / 前缀         | router.rs                                |
//! | ngx_lua 脚本层               | lua_engine.rs（mlua，ngx.* API）          |
//! | access_log                   | access_log.rs（combined 格式）            |
//!
//! 用法：`learnon [path/to/learnon.conf]`

mod access_log;
mod engine;
mod lua_engine;
mod proxy;
mod router;
mod server;
mod shared_dict;
mod upstream;

use learnon_config::Config;
use std::path::PathBuf;
use std::sync::Arc;

use engine::HandlerRegistry;
use lua_engine::LuaEngine;
use proxy::ProxyEngine;
use router::Router;
use upstream::UpstreamPool;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("config error: {0}")]
    Config(#[from] learnon_config::ConfigError),
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("{0}")]
    Other(String),
}

/// 相对路径基于配置文件所在目录解析
pub fn resolve_path(p: &str, base_dir: &PathBuf) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn main() {
    // 网关直连后端，忽略系统代理环境变量（否则 hyper-util 会把 upstream 请求
    // 发给 HTTP_PROXY，后端可达性完全取决于代理工具）
    for k in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::remove_var(k);
    }

    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "conf/learnon.conf".to_string());
    let conf_path = PathBuf::from(&conf_path);
    let base_dir = conf_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let config = match Config::load(&conf_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[learnon] 配置加载失败 {conf_path:?}: {e}");
            std::process::exit(1);
        }
    };
    println!("[learnon] 配置加载成功: {}", conf_path.display());

    let router = match Router::build(&config, &base_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[learnon] 路由构建失败: {e}");
            std::process::exit(1);
        }
    };

    let pool = match UpstreamPool::parse_all(&config) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("[learnon] upstream 解析失败: {e}");
            std::process::exit(1);
        }
    };

    let handlers = Arc::new(HandlerRegistry::with_builtins());
    let lua = match LuaEngine::new(&config, &base_dir) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("[learnon] Lua 引擎初始化失败: {e}");
            std::process::exit(1);
        }
    };

    let proxy = Arc::new(ProxyEngine::new(Arc::clone(&pool)));
    let access_log = Arc::new(access_log::AccessLog::new(&config, &base_dir));

    let listeners = router.listeners.clone();
    if listeners.is_empty() {
        eprintln!("[learnon] 配置中没有任何 listen 指令，退出");
        std::process::exit(1);
    }

    let state = Arc::new(server::AppState {
        router,
        handlers,
        lua,
        proxy,
        access_log,
        base_dir: base_dir.clone(),
    });

    // 多核：worker 线程数 = CPU 逻辑核心数（与 Lua VM 池一一对齐）
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("learnon-worker")
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    println!("[learnon] 启动完成，监听: {:?}", listeners.iter().map(|l| l.addr).collect::<Vec<_>>());

    runtime.block_on(async move {
        let mut handles = Vec::new();
        for listener in listeners {
            let state = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                if let Err(e) = server::serve(state, listener).await {
                    eprintln!("[learnon] 监听异常退出: {e}");
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });
}
