//! 纯 Lua 的 `resty.*` 模块库：通过 `package.preload` 注册，使请求脚本可以
//! `require "resty.string"` / `require "resty.lock"`，对标 OpenResty 的同名模块语义。
//!
//! 这里的 Lua 源码全部为本项目原创实现（对照公开 API 文档语义手写），未复制任何
//! OpenResty / MIT 上游源码。模块只依赖已在 `lua_engine.rs` 暴露的原生能力：
//!   - `ngx.sha256_bin` / `ngx.md5_bin`（ring 摘要，供 resty.string 复用）；
//!   - `ngx.shared.DICT` 的 `add/get/delete/incr`（供 resty.lock 做分布式互斥）；
//!   - `ngx.now` / `ngx.sleep`（让出式轮询退避）。

use mlua::prelude::*;

/// resty.string —— to_hex / sha256_hex / md5_hex。
const RESTY_STRING: &str = r##"
local _M = {}

local byte  = string.byte
local fmt   = string.format
local concat = table.concat

-- to_hex(str)：把任意字节串编码为小写十六进制（OpenResty 语义）。
function _M.to_hex(s)
    local out = {}
    for i = 1, #s do
        out[i] = fmt("%02x", byte(s, i))
    end
    return concat(out)
end

-- sha256_hex(str)：底层调用原生 ngx.sha256_bin（原始 32 字节）再转十六进制。
function _M.sha256_hex(s)
    return _M.to_hex(ngx.sha256_bin(s))
end

-- md5_hex(str)：底层调用原生 ngx.md5_bin（原始 16 字节）再转十六进制。
function _M.md5_hex(s)
    return _M.to_hex(ngx.md5_bin(s))
end

return _M
"##;

/// resty.lock —— 基于共享字典 add() 原子占位的分布式互斥锁，支持超时与自动过期。
const RESTY_LOCK: &str = r##"
local _M = {}
local mt = { __index = _M }

local COUNTER_KEY = "@resty.lock.monotonic"

-- new(dict, opts)：dict 可为共享字典名（字符串）或 DICT 对象本身。
--   opts.timeout  = 获取锁的最长等待秒数（默认 1）
--   opts.exptime  = 锁的自动过期秒数（默认 = timeout）
function _M.new(self, dict, opts)
    local d
    if type(dict) == "string" then
        d = ngx.shared[dict]
        if not d then
            return nil, "shared dict not found: " .. dict
        end
    else
        d = dict
    end
    opts = opts or {}
    local timeout = opts.timeout or 1
    local exptime = opts.exptime or timeout
    if exptime <= 0 then exptime = 0.001 end
    return setmetatable({
        dict = d,
        timeout = timeout,
        exptime = exptime,
        token = nil,
        key = nil,
    }, mt)
end

-- lock(key) -> elapsed | nil, err
--   成功返回等待耗时（秒，0 表示立即获得）；失败返回 nil 与 "timeout"/其它错误。
--   用单调递增令牌作为锁值，使 unlock() 只释放自己那一把（防止过期后被他人重取再误删）。
function _M.lock(self, key, ...)
    if self.key then
        return nil, "already locked"
    end
    local dict = self.dict
    local exptime = self.exptime

    local token = dict:incr(COUNTER_KEY, 1, 0)
    if not token then
        return nil, "failed to allocate lock token"
    end

    local elapsed = 0
    local step = 0.001

    local ok, err = dict:add(key, token, exptime)
    if ok == nil then return nil, err end
    if ok then
        self.token = token
        self.key = key
        return elapsed
    end

    -- 锁被他人持有：带上限的指数退避轮询（ngx.sleep 为让出点，不阻塞 VM）。
    while true do
        ngx.sleep(step)
        elapsed = elapsed + step
        if elapsed > self.timeout then
            return nil, "timeout"
        end
        ok, err = dict:add(key, token, exptime)
        if ok == nil then return nil, err end
        if ok then
            self.token = token
            self.key = key
            return elapsed
        end
        step = step * 2
        if step > 0.05 then step = 0.05 end
    end
end

-- unlock() -> true | nil, err：仅当锁值仍是本实例令牌时才删除。
function _M.unlock(self)
    local dict = self.dict
    local key = self.key
    if not key then
        return nil, "not locked"
    end
    local cur = dict:get(key)
    if cur ~= nil and tostring(cur) == tostring(self.token) then
        dict:delete(key)
    end
    self.key = nil
    self.token = nil
    return true
end

return _M
"##;

/// 在给定 VM 上注册 resty.* 模块到 `package.preload`，使 `require "resty.xxx"` 可用。
/// mlua 的 `Lua::new()` 已打开标准库（含 `package`），故 `require` 与 preload 搜索器就绪；
/// 这里对 `package`/`preload` 表做存在性兜底，避免个别精简运行时缺表时失败。
pub fn install_modules(lua: &Lua) -> LuaResult<()> {
    let string_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_STRING).set_name("resty.string").eval::<LuaValue>()
    })?;
    let lock_loader = lua.create_function(|lua, _: ()| {
        lua.load(RESTY_LOCK).set_name("resty.lock").eval::<LuaValue>()
    })?;

    let globals = lua.globals();
    let package: LuaTable = match globals.get("package") {
        Ok(p) => p,
        Err(_) => {
            let t = lua.create_table()?;
            globals.set("package", t.clone())?;
            t
        }
    };
    let preload: LuaTable = match package.get("preload") {
        Ok(p) => p,
        Err(_) => {
            let t = lua.create_table()?;
            package.set("preload", t.clone())?;
            t
        }
    };
    preload.set("resty.string", string_loader)?;
    preload.set("resty.lock", lock_loader)?;
    Ok(())
}
