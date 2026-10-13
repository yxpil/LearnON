//! access_log：Nginx combined 格式访问日志。
//!
//! 多核优化：日志写入走专用后台线程（mpsc 通道），请求热路径只做一次
//! 无锁 send，避免所有 worker 线程争抢同一把文件锁。
//!
//! `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//!  "$http_referer" "$http_user_agent"`

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;

use learnon_config::Config;

use crate::engine::RequestCtx;

pub struct AccessLog {
    tx: Option<Sender<String>>,
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

        // 专用写线程：BufWriter 缓冲，通道关闭或缓冲满时落盘
        let tx = file.map(|f| {
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::Builder::new()
                .name("learnon-access-log".into())
                .spawn(move || {
                    let mut w = BufWriter::new(f);
                    loop {
                        // 阻塞等下一条（通道关闭则退出）
                        let Ok(line) = rx.recv() else { break };
                        if writeln!(w, "{line}").is_err() {
                            break;
                        }
                        // 批量写出当前积压，再统一刷盘（高并发下显著减少 flush 次数）
                        while let Ok(more) = rx.try_recv() {
                            if writeln!(w, "{more}").is_err() {
                                return;
                            }
                        }
                        let _ = w.flush();
                    }
                    let _ = w.flush();
                })
                .ok();
            tx
        });

        AccessLog { tx }
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
        // 仅在交互终端回显；stdout 是管道/重定向时不打印（否则管道写满会阻塞全部 worker）
        if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            println!("[access] {line}");
        }
        // 无锁投递；队列满或线程不存在则丢弃（日志不阻塞请求）
        if let Some(tx) = &self.tx {
            let _ = tx.send(line);
        }
    }
}

// Arc<AccessLog> 跨线程共享
const _: fn(Arc<AccessLog>) = |_| {};
