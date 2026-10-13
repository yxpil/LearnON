//! upstream 模块：对标 Nginx 的 `upstream` 块。
//!
//! ```text
//! upstream backend {
//!     server 127.0.0.1:9001 weight=2 max_fails=3 fail_timeout=10s;
//!     server 127.0.0.1:9002;
//!     least_conn;      # 可选：round-robin(默认) / least_conn / ip_hash
//! }
//! ```
//!
//! - 负载均衡：RoundRobin（默认）/ LeastConn / IpHash
//! - 被动健康检查：max_fails 次失败后在 fail_timeout 秒内摘除该节点（全挂时兜底全量）

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use learnon_config::Directive;

use crate::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalance {
    RoundRobin,
    LeastConn,
    IpHash,
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug)]
pub struct UpstreamServer {
    pub addr: String,
    pub weight: usize,
    /// 被动健康检查：连续失败阈值
    pub max_fails: usize,
    /// 被动健康检查：摘除时长（秒）
    pub fail_timeout: f64,
    /// 当前活跃连接数
    pub conns: AtomicUsize,
    /// 当前失败计数
    fails: AtomicUsize,
    /// 摘除截止时间（epoch 秒）
    down_until: Mutex<Option<f64>>,
}

impl UpstreamServer {
    fn available(&self, now: f64) -> bool {
        match *self.down_until.lock().unwrap() {
            Some(t) if now < t => false,
            _ => true,
        }
    }

    fn note_success(&self) {
        self.fails.store(0, Ordering::Relaxed);
    }

    fn note_failure(&self) {
        let n = self.fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.max_fails.max(1) {
            *self.down_until.lock().unwrap() = Some(now_epoch() + self.fail_timeout);
            self.fails.store(0, Ordering::Relaxed);
            eprintln!(
                "[learnon] upstream 节点 {} 连续失败 {n} 次，摘除 {:.0}s",
                self.addr, self.fail_timeout
            );
        }
    }
}

#[derive(Debug)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub lb: LoadBalance,
    /// 加权轮询游标
    cursor: Mutex<usize>,
}

impl Upstream {
    /// 按负载均衡策略选一个可用后端，并把连接数 +1；guard drop 时 -1。
    /// 所有节点都被摘除时兜底全量参与（避免完全不可用）。
    pub fn acquire(self: &Arc<Self>, client_ip: &str) -> UpstreamGuard {
        let now = now_epoch();
        let mut candidates: Vec<usize> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(_, s)| s.available(now))
            .map(|(i, _)| i)
            .collect();
        if candidates.is_empty() {
            candidates = (0..self.servers.len()).collect();
        }

        let idx = match self.lb {
            LoadBalance::RoundRobin => self.pick_round_robin(&candidates),
            LoadBalance::LeastConn => self.pick_least_conn(&candidates),
            LoadBalance::IpHash => self.pick_ip_hash(client_ip, &candidates),
        };
        self.servers[idx].conns.fetch_add(1, Ordering::Relaxed);
        UpstreamGuard {
            upstream: Arc::clone(self),
            idx,
        }
    }

    fn pick_round_robin(&self, candidates: &[usize]) -> usize {
        // 平滑加权轮询（简化版：按候选集总权重展开游标）
        let total: usize = candidates.iter().map(|&i| self.servers[i].weight).sum();
        let mut c = self.cursor.lock().unwrap();
        *c = (*c + 1) % total.max(1);
        let mut acc = 0;
        for &i in candidates {
            acc += self.servers[i].weight;
            if *c < acc {
                return i;
            }
        }
        candidates[0]
    }

    fn pick_least_conn(&self, candidates: &[usize]) -> usize {
        let mut best = candidates[0];
        let mut best_metric = f64::INFINITY;
        for &i in candidates {
            let s = &self.servers[i];
            let metric = s.conns.load(Ordering::Relaxed) as f64 / s.weight.max(1) as f64;
            if metric < best_metric {
                best_metric = metric;
                best = i;
            }
        }
        best
    }

    fn pick_ip_hash(&self, client_ip: &str, candidates: &[usize]) -> usize {
        let mut h: u64 = 5381;
        for b in client_ip.bytes() {
            h = h.wrapping_mul(33) ^ b as u64;
        }
        let total: usize = candidates.iter().map(|&i| self.servers[i].weight).sum();
        let mut target = (h as usize) % total.max(1);
        for &i in candidates {
            if target < self.servers[i].weight {
                return i;
            }
            target -= self.servers[i].weight;
        }
        candidates[0]
    }
}

/// 连接租约：drop 时把连接计数 -1；代理层可通过 note_success/note_failure 上报健康
pub struct UpstreamGuard {
    upstream: Arc<Upstream>,
    idx: usize,
}

impl UpstreamGuard {
    pub fn note_success(&self) {
        self.upstream.servers[self.idx].note_success();
    }

    pub fn note_failure(&self) {
        self.upstream.servers[self.idx].note_failure();
    }
}

impl std::ops::Deref for UpstreamGuard {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.upstream.servers[self.idx].addr
    }
}

impl Drop for UpstreamGuard {
    fn drop(&mut self) {
        self.upstream.servers[self.idx]
            .conns
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct UpstreamPool {
    pub map: HashMap<String, Arc<Upstream>>,
}

impl UpstreamPool {
    pub fn parse_all(config: &learnon_config::Config) -> Result<Self, AppError> {
        let mut map = HashMap::new();
        for d in config.root.block.iter().filter(|d| d.name == "upstream") {
            let up = Self::parse_upstream(d)?;
            map.insert(up.name.clone(), Arc::new(up));
        }
        Ok(UpstreamPool { map })
    }

    fn parse_upstream(d: &Directive) -> Result<Upstream, AppError> {
        let name = d
            .arg(0)
            .ok_or_else(|| AppError::Other("upstream 缺少名称".into()))?
            .to_string();
        let mut servers = Vec::new();
        let mut lb = LoadBalance::RoundRobin;
        for child in &d.block {
            match child.name.as_str() {
                "server" => {
                    let addr = child
                        .arg(0)
                        .ok_or_else(|| AppError::Other(format!("upstream {name} 的 server 缺少地址")))?;
                    let mut weight = 1usize;
                    let mut max_fails = 1usize;
                    let mut fail_timeout = 10.0f64;
                    for a in &child.args[1..] {
                        if let Some(w) = a.strip_prefix("weight=") {
                            weight = w.parse().unwrap_or(1);
                        } else if let Some(mf) = a.strip_prefix("max_fails=") {
                            max_fails = mf.parse().unwrap_or(1);
                        } else if let Some(ft) = a.strip_prefix("fail_timeout=") {
                            let ft = ft.trim_end_matches('s');
                            fail_timeout = ft.parse().unwrap_or(10.0);
                        }
                    }
                    servers.push(UpstreamServer {
                        addr: addr.to_string(),
                        weight,
                        max_fails,
                        fail_timeout,
                        conns: AtomicUsize::new(0),
                        fails: AtomicUsize::new(0),
                        down_until: Mutex::new(None),
                    });
                }
                "least_conn" => lb = LoadBalance::LeastConn,
                "ip_hash" => lb = LoadBalance::IpHash,
                _ => {} // 未知指令忽略
            }
        }
        if servers.is_empty() {
            return Err(AppError::Other(format!("upstream {name} 没有任何 server")));
        }
        Ok(Upstream {
            name,
            servers,
            lb,
            cursor: Mutex::new(0),
        })
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Upstream>> {
        self.map.get(name)
    }
}
