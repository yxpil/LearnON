//! access_log：Nginx combined 格式访问日志。
//!
//! `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//!  "$http_referer" "$http_user_agent"`

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use learnon_config::Config;

use crate::engine::RequestCtx;

pub struct AccessLog {
    file: Mutex<Option<File>>,
}

impl AccessLog {
    pub fn new(config: &Config, base_dir: &PathBuf) -> Self {
        let path = config
            .find("access_log")
            .and_then(|d| d.arg(0))
            .map(|p| crate::resolve_path(p, base_dir));
        let file = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .map_err(|e| eprintln!("[learnon] access_log 打开失败 {}: {e}", p.display()))
                .ok()
        });
        AccessLog {
            file: Mutex::new(file),
        }
    }

    pub fn log_request(&self, ctx: &RequestCtx, status: u16, bytes: usize) {
        let time = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        let ua = ctx
            .header("user-agent")
            .unwrap_or("-")
            .replace('"', "'");
        let referer = ctx.header("referer").unwrap_or("-");
        let line = format!(
            "{} - - [{}] \"{} {}\" {} {} \"{}\" \"{}\"",
            ctx.remote_addr,
            time,
            ctx.method,
            ctx.uri,
            status,
            bytes,
            referer,
            ua
        );
        println!("[access] {line}");
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}
