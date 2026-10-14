<p align="center">
  <img src="public/logo.png" alt="LearnON logo" width="180">
</p>

# LearnON (Rust 版)

> **LearnON**（简称 **LON**）—— 用 Rust 从零实现的 OpenResty 替代品。

用 **Rust 从零实现**的 Nginx / OpenResty 风格网关服务器：反向代理、负载均衡（含被动健康检查）、rewrite、
虚拟主机、内嵌 Lua 5.4 脚本层（`ngx.*` API）+ Rust 原生模块。除 tokio/hyper 等基础库外，网关逻辑全部手写。


## 阻塞分析与静态路径优化（spawn_blocking + 文件缓存）

- **Lua 脚本文件缓存**：`LuaSource::File` 每请求同步读盘（`fs::read_to_string`）曾是最大阻塞点之一，
  现改为 `OnceLock<RwLock<HashMap<PathBuf, Arc<str>>>>` 进程级缓存，文件只在首次请求时读取一次。
- **静态 IO 移出 worker**：静态服务的全部文件系统调用（resolve / index / autoindex / 读文件）
  通过 owned 快照整体丢进 `tokio::task::spawn_blocking`，tokio worker 线程不再被磁盘阻塞。
- **error_page 目标文件**同样一次性读出构建响应，错误页热路径不再有额外同步 IO 往返。
- 实测（32 并发 keep-alive）：静态 4880 → 6715 req/s（+38%），Lua 7867 → 9044 req/s（+15%）。
- **静态文件内存缓存**：≤1MB 的文件整体驻留进程内存（上限 512 条），以 (mtime, size) 失效校验，
  缓存命中后零磁盘读、零系统调用（仅一次 stat），文件修改自动感知。

## 安全防护

- **路径穿越防护**：RFC 3986 dot-segment 归一化，`../`/`..%2f`/`%252e`/反斜杠/空字节等全部拦截，越根直接 400
- **请求走私防护**：重复 Content-Length / 非法 CL / CL+TE 并存 → 400；HTTP/1.1 缺 Host → 400
- **未知方法** → 501；URL > 8KB → 414；超大请求头 → 431；超大请求体 → 413（读体前拦截）
- **慢速连接**：不阻塞正常请求（tokio 并发模型天然抗 Slowloris 单连接攻击）
- 安全测试：`sec_test.py`（30 项，覆盖穿越/走私/CRLF 注入/畸形请求/大请求/响应头默认值）

## 多核架构

- **tokio 多线程运行时**：worker 线程数 = CPU 逻辑核心数
- **Lua VM 池**：每个 CPU 核心一个独立 Lua VM（对标 OpenResty 每 worker 一个 VM），多请求完全并行执行脚本，全局无单点锁；`init_by_lua` 在每个 VM 各执行一次（与 nginx 每 worker 初始化一次语义一致）
- **ngx.shared.DICT 16 分片**：按 key 哈希分片，各片独立锁，多核并发读写互不阻塞
- **无锁热路径**：轮询游标 / 节点健康状态 / VM 选择均为原子操作
- **异步访问日志**：专用写线程 + 缓冲批量落盘，请求热路径只做一次无锁投递
- **proxy_next_upstream**：上游连接级失败自动换下一节点重试一次（陈旧连接池命中自愈）
- **TCP_NODELAY**：所有入站连接默认禁用 Nagle


## 功能对照表

| Nginx / OpenResty | LearnON (Rust) | 位置 |
|---|---|---|
| master/worker 事件循环 | tokio 异步运行时 + hyper HTTP/1 | `server.rs` |
| nginx.conf 语法 | 自研词法器 + 递归下降解析器（含单测） | `crates/learnon-config` |
| `upstream` + 负载均衡 | 加权轮询 / `least_conn` / `ip_hash`（带连接数追踪） | `upstream.rs` |
| 被动健康检查 `max_fails` / `fail_timeout` | 失败计数 + 节点摘除 + 过期恢复（全挂兜底全量） | `upstream.rs` |
| `proxy_pass` 反向代理 | hyper 连接池、`proxy_set_header` 变量插值、前缀替换 | `proxy.rs` |
| `rewrite ... last/break/redirect/permanent` | regex 引擎 + `$1..$9` 反向引用 | `engine.rs` |
| `return` / `add_header` / `proxy_read_timeout` | 同语义 | `router.rs` |
| `location =` / 前缀 / `~` 正则 | 精确 > 正则 > 最长前缀 | `router.rs` |
| `listen <port> ssl` + `ssl_certificate` | rustls TLS（HTTPS 端点，可多条 listen 共存） | `server.rs` |
| `ngx_lua` 脚本层 | mlua (Lua 5.4)，见下方 Lua API 列表 | `lua_engine.rs` |
| `init_by_lua` | 启动时执行一次 | `lua_engine.rs` |
| `lua_shared_dict` / `ngx.shared.DICT` | 跨请求共享字典：get/set/add/replace/delete/incr/ttl/flush_all | `shared_dict.rs` |
| `access_log` combined 格式 | 本地文件 + stdout | `access_log.rs` |
| 第三方 C 模块 | `content_by_rust` / `access_by_rust` 编译期注册的 Rust 处理器 | `engine.rs` |
| nginx 语法兼容 | `location =/\^~/~/~*`、server_name 通配符、error_page、try_files、index、autoindex、alias、client_max_body_size、return URL 简写 |

## 目录结构

```
rust/
├── conf/learnon.conf        # 示例网关配置（全功能演示）
├── lua/                     # Lua 业务脚本（auth.lua / time.lua / rewrite_mark.lua）
├── public/                  # 静态文件根目录（含 logo.png）
└── crates/
    ├── learnon-config/      # Nginx 风格配置解析器
    └── learnon-server/      # 服务器主程序
        └── src/
            ├── main.rs      # 启动流程：config -> router -> upstream -> lua -> 监听
            ├── router.rs    # server/location 匹配（= / 前缀 / ~ 正则）、指令模型
            ├── upstream.rs  # upstream 池 + 三种负载均衡 + 被动健康检查
            ├── proxy.rs     # 反向代理引擎（失败上报健康检查）
            ├── engine.rs    # rewrite/return 引擎 + Rust 原生处理器注册表
            ├── shared_dict.rs # ngx.shared.DICT 共享字典
            ├── lua_engine.rs# Lua VM + ngx.* API
            ├── access_log.rs# combined 访问日志
            └── server.rs    # HTTP 管线：rewrite -> access -> content -> 日志
```

## 运行

```bash
cd rust
# 方式一：cargo 直接跑（debug）
cargo run -- conf/learnon.conf
# 方式二：打包后的 exe（release）
cargo build --release
target\release\learnon.exe conf\learnon.conf

# 起两个演示后端（任选）：
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1
```

### HTTPS / 证书

```bash
# 生成自签名证书（SAN: localhost, 127.0.0.1；也可自定义域名）
cargo run --bin lon-gencert -- certs/cert.pem certs/key.pem your.domain.com
```

配置：

```nginx
server {
    listen 8080;              # HTTP
    listen 8443 ssl;          # HTTPS（同一 server 块可多条 listen）
    ssl_certificate     "certs/cert.pem";
    ssl_certificate_key "certs/key.pem";
}
```

示例配置自带 8443 HTTPS 端点（certs/ 下已生成自签名证书），实测通过：TLS 握手、
Lua、反代、共享字典、POST 请求体在 HTTPS 下全部正常。生产环境请换成 CA 签发的证书。

实测通过的路由（28 项冒烟检查，HTTP + HTTPS 全覆盖）：

| 路由 | 功能 |
|---|---|
| `GET /proxy/` | 反代 + upstream 轮询（backend-1/2 交替） |
| `GET /hello` | content_by_lua 内联脚本 |
| `GET /api/time` | rewrite_by_lua_file + content_by_lua_file + ngx.sleep 异步 |
| `GET /api/protected` | access_by_lua 鉴权：无 token 401 / 错 token 403 / 正确 200 |
| `GET /count` | ngx.shared.DICT 原子计数（跨请求累加） |
| `GET /go` | ngx.redirect 302（Location 头） |
| `GET /inner` | ngx.exec 内部重定向 → /hello（客户端无感） |
| `GET /api/tools` | ngx.re 正则捕获 / escape_uri / unescape_uri / 请求体读取 |
| `GET /old/thing` | rewrite last → /new/thing（内部重定向） |
| `GET /health`、`/jump` | return 200 / 301 |
| `GET /user/42` | 正则 location |
| `GET /api/info` | content_by_rust 原生模块 |
| `GET /static/` | 静态文件；未知路径 404 |

## Lua API（对标 ngx.*）

- 响应：`ngx.say / print / status（可读写）/ exit / header.set / send_headers 前的任意响应头`
- 请求：`ngx.req.get_method / get_path / get_query / get_headers / get_uri_args / set_uri / set_uri_args / get_body_data`
- 控制：`ngx.redirect(uri, code?) / ngx.exec(uri) / ngx.exit / ngx.sleep（异步协程）`
- 正则：`ngx.re.match(s, pat, flags?) / ngx.re.find(s, pat, flags?)`（flags 支持 `i`）
- 编解码：`ngx.encode_base64 / decode_base64 / escape_uri / unescape_uri / decode_args / encode_args`
- 共享内存：`ngx.shared.<zone>:get / get_stale / set / safe_set / add / replace / delete / incr / ttl / flush_all`
- 后台定时器：`ngx.timer.at(delay_sec, cb, ...) / ngx.timer.every(interval_sec, cb, ...) / running_count() / pending_count()`
  —— 秒单位、回调首参 `premature`、用户变参原样转发、失败返回 `(nil, err)`、`return false` 停止周期（语义对齐官方 t/106/152/107）
- 响应过滤：`header_filter_by_lua*`（发头前改响应头/清 Content-Length）、`body_filter_by_lua*`（经 `ngx.arg[1]` chunk、`ngx.arg[2]` eof 改写响应体）
- cosocket：`ngx.socket.tcp()` 对象已就位（API 骨架，完整 connect/send/receive 待 v0.4 协程调度）
- 其他：`ngx.ctx（每请求表）/ ngx.time / ngx.now / ngx.log / ngx.config.* / ngx.version`

## E2E 测试（对齐 OpenResty 官方套件）

OpenResty 官方把 E2E 测试发布在 `openresty/lua-nginx-module` 的 `t/` 目录（193 个 `.t` 文件，Perl Test::Nginx 驱动）。
本仓库用「移植断言」策略对标：从官方 `.t` 的 `__DATA__` 段提取 config/request/response/error_log 期望，写成独立可跑的断言脚本。

- `timer_e2e_test.py`：11/11 通过，移植自 `t/106-timer.t`、`t/152-timer-every.t`、`t/107-timer-errors.t`
  （premature 首参、变参转发、every 的 `return false` 停止、四类错误串、无日志串扰）
- 官方套件已 vendored 到 `vendor/lua-nginx-module/t/`（gitignored）作为语义参考；Test::Nginx 直接跑完整 `.t` 需要真实
  OpenResty 二进制作 `TEST_NGINX_BINARY` + `*_by_lua_block` 语法 + Unix 信号，Windows 本机无法运行，故走移植断言路线。
- 兼容性回归：`compat_test.py` 17/17、安全 `sec_test.py` 30 项、静态/场景/上游各套件见目录。

## 设计取舍与路线图

- **Lua 串行执行**：进程级单 VM + 互斥锁（对应 OpenResty 每 worker 一个 VM 的简化）。
- **请求体缓冲转发**：反代先把请求体读入内存再转发（路线图：流式管道）。
- **`lua_shared_dict` 容量为声明式**：不做内存上限强制（OpenResty 会在写满时淘汰/报错）。
- 未实现：WebSocket 升级转发、gzip、Lua 协程多请求并发、主动健康检查、keep-alive 上游连接池调优。
