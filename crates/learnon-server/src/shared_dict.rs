//! ngx.shared.DICT —— 对标 OpenResty 的 `lua_shared_dict` 共享内存字典。
//!
//! ```text
//! lua_shared_dict counters 1m;      # 声明一个共享区（容量暂作声明，不做强制限制）
//! ```
//!
//! Lua 侧：
//! ```lua
//! local d = ngx.shared.counters
//! d:set("k", "v", 10)     -- ttl 可选（秒）
//! d:get("k")              -- 过期返回 nil
//! d:add("k", "1")         -- 已存在则失败
//! d:incr("k", 1)          -- 原子自增
//! d:delete("k"); d:flush_all()
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use learnon_config::Config;

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone)]
struct Entry {
    value: Vec<u8>,
    /// 过期时间（epoch 秒）；None = 永不过期
    expires_at: Option<f64>,
}

impl Entry {
    fn alive(&self, now: f64) -> bool {
        match self.expires_at {
            Some(t) => now < t,
            None => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SharedZone {
    pub name: String,
    inner: Arc<ZoneInner>,
}

#[derive(Debug, Default)]
struct ZoneInner {
    map: Mutex<HashMap<String, Entry>>,
}

impl SharedZone {
    fn new(name: &str) -> Self {
        SharedZone {
            name: name.to_string(),
            inner: Arc::new(ZoneInner::default()),
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let now = now_epoch();
        let map = self.inner.map.lock().unwrap();
        map.get(key).filter(|e| e.alive(now)).map(|e| e.value.clone())
    }

    /// 含过期项的读取（对标 get_stale）
    pub fn get_stale(&self, key: &str) -> Option<Vec<u8>> {
        let map = self.inner.map.lock().unwrap();
        map.get(key).map(|e| e.value.clone())
    }

    pub fn set(&self, key: &str, value: Vec<u8>, ex: Option<f64>) {
        let now = now_epoch();
        let expires_at = ex.map(|t| now + t);
        self.inner
            .map
            .lock()
            .unwrap()
            .insert(key.to_string(), Entry { value, expires_at });
    }

    /// 不存在（或已过期）时才写入；返回是否成功
    pub fn add(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> bool {
        let now = now_epoch();
        let mut map = self.inner.map.lock().unwrap();
        if map.get(key).is_some_and(|e| e.alive(now)) {
            return false;
        }
        let expires_at = ex.map(|t| now + t);
        map.insert(key.to_string(), Entry { value, expires_at });
        true
    }

    /// 已存在（未过期）时才覆盖；返回是否成功
    pub fn replace(&self, key: &str, value: Vec<u8>, ex: Option<f64>) -> bool {
        let now = now_epoch();
        let mut map = self.inner.map.lock().unwrap();
        if !map.get(key).is_some_and(|e| e.alive(now)) {
            return false;
        }
        let expires_at = ex.map(|t| now + t);
        map.insert(key.to_string(), Entry { value, expires_at });
        true
    }

    pub fn delete(&self, key: &str) {
        self.inner.map.lock().unwrap().remove(key);
    }

    /// 原子自增整数值；项不存在时若给了 init 则初始化为 init
    pub fn incr(&self, key: &str, delta: i64, init: Option<i64>) -> Result<i64, String> {
        let now = now_epoch();
        let mut map = self.inner.map.lock().unwrap();
        let entry = map.get_mut(key);
        match entry {
            Some(e) if e.alive(now) => {
                let text = String::from_utf8_lossy(&e.value).trim().to_string();
                let cur: i64 = text
                    .parse()
                    .map_err(|_| format!("incr: '{key}' 的值不是数字 ({text})"))?;
                let new = cur + delta;
                e.value = new.to_string().into_bytes();
                Ok(new)
            }
            _ => {
                let Some(init) = init else {
                    return Err(format!("incr: '{key}' 不存在且未提供 init"));
                };
                let new = init + delta;
                map.insert(
                    key.to_string(),
                    Entry {
                        value: new.to_string().into_bytes(),
                        expires_at: None,
                    },
                );
                Ok(new)
            }
        }
    }

    /// 剩余存活时间：None=不存在，Some(-1.0)=永不过期，Some(x)=剩余秒数
    pub fn ttl(&self, key: &str) -> Option<f64> {
        let now = now_epoch();
        let map = self.inner.map.lock().unwrap();
        map.get(key).map(|e| match e.expires_at {
            None => -1.0,
            Some(t) => (t - now).max(0.0),
        })
    }

    pub fn flush_all(&self) {
        self.inner.map.lock().unwrap().clear();
    }
}

#[derive(Debug, Default)]
pub struct SharedDicts {
    pub zones: HashMap<String, SharedZone>,
}

impl SharedDicts {
    /// 解析顶层 `lua_shared_dict <name> <size>;` 指令
    pub fn parse_all(config: &Config) -> Self {
        let mut zones = HashMap::new();
        for d in &config.root.block {
            if d.name == "lua_shared_dict" {
                if let Some(name) = d.arg(0) {
                    zones.insert(name.to_string(), SharedZone::new(name));
                }
            }
        }
        SharedDicts { zones }
    }

    pub fn get(&self, name: &str) -> Option<SharedZone> {
        self.zones.get(name).cloned()
    }
}
