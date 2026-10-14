<p align="center">
  <img src="public/logo.png" alt="LearnON logo" width="180">
</p>

# LearnON (Rust)

> **LearnON** (short **LON**) — an OpenResty alternative written from scratch in Rust.

A Nginx / OpenResty-style gateway server **implemented from scratch in Rust**: reverse proxy, load
balancing (with passive health checks), rewrite, virtual hosts, an embedded Lua 5.4 scripting layer
(the `ngx.*` API), plus native Rust modules. Apart from foundational libraries such as tokio/hyper,
all gateway logic is hand-written.

## Blocking analysis & static-path optimization (spawn_blocking + file cache)

- **Lua script file cache**: `LuaSource::File` used to read from disk synchronously on every request
  (`fs::read_to_string`), one of the largest blocking points. It is now a process-level cache
  (`OnceLock<RwLock<HashMap<PathBuf, Arc<str>>>>`) — each file is read once, on first request.
- **Static IO moved off workers**: every filesystem call in the static-serving path (resolve / index /
  autoindex / read) is handed wholesale to `tokio::task::spawn_blocking` via an owned snapshot, so
  tokio worker threads are never blocked by disk IO.
- **error_page target files** are likewise read once to build the response, removing extra synchronous
  IO round-trips from the error-page hot path.
- Measured (32 concurrent keep-alive connections): static 4880 → 6715 req/s (+38%), Lua
  7867 → 9044 req/s (+15%).
- **Static file in-memory cache**: files ≤1 MB are held entirely in process memory (up to 512 entries),
  invalidated by (mtime, size). A cache hit costs zero disk reads and zero syscalls beyond a single
  `stat`; file edits are detected automatically.

## Security

- **Path traversal protection**: RFC 3986 dot-segment normalization; `../` / `..%2f` / `%252e` /
  backslash / null-byte payloads are all blocked, and escaping the root returns 400 directly.
- **Request smuggling protection**: duplicate Content-Length / illegal CL / CL+TE together → 400;
  HTTP/1.1 missing Host → 400.
- **Unknown method** → 501; URL > 8 KB → 414; oversized headers → 431; oversized body → 413
  (rejected before the body is read).
- **Slow connections**: do not block normal requests (the tokio concurrency model is inherently
  resistant to single-connection Slowloris attacks).
- Security tests: `sec_test.py` (30 checks, covering traversal / smuggling / CRLF injection /
  malformed requests / oversized requests / default response headers).

## Multi-core architecture

- **tokio multi-threaded runtime**: worker thread count = number of logical CPU cores.
- **Lua VM pool**: one independent Lua VM per CPU core (mirroring OpenResty's one VM per worker).
  Multiple requests execute scripts fully in parallel with no global single-point lock;
  `init_by_lua` runs once per VM (matching nginx's once-per-worker initialization semantics).
- **Within-VM coroutine scheduler**: each VM is driven by a dedicated scheduler task that interleaves
  many in-flight requests as Lua coroutines — a request yields only at `ngx.sleep` and the VM lock is
  released between synchronous resume segments, so `ngx.timer` callbacks and sleep timers progress
  while other requests on the same VM run (OpenResty's single-worker C10K, not one-request-per-VM).
- **16-shard ngx.shared.DICT**: sharded by key hash, each shard with its own lock, so multi-core
  concurrent reads/writes never block each other.
- **Lock-free hot paths**: round-robin cursor / node health state / VM selection are all atomic.
- **Async access log**: a dedicated writer thread + buffered batch flush; the request hot path does
  only one lock-free enqueue.
- **proxy_next_upstream**: connection-level upstream failures automatically retry once against the next
  node (self-heals stale connection-pool hits).
- **TCP_NODELAY**: Nagle disabled by default on all inbound connections.

## Feature map

| Nginx / OpenResty | LearnON (Rust) | Location |
|---|---|---|
| master/worker event loop | tokio async runtime + hyper HTTP/1 | `server.rs` |
| nginx.conf syntax | custom lexer + recursive-descent parser, incl. `include <file \| glob>` (with unit tests) | `crates/learnon-config` |
| `upstream` + load balancing | weighted round-robin / `least_conn` / `ip_hash` (with connection tracking) | `upstream.rs` |
| passive health checks `max_fails` / `fail_timeout` | failure counting + node removal + expiry recovery (falls back to full set when all are down) | `upstream.rs` |
| `proxy_pass` reverse proxy | hyper connection pool, `proxy_set_header` variable interpolation, prefix replacement | `proxy.rs` |
| `resolver` + async DNS | pure-Rust non-blocking UDP stub resolver (A/AAAA, RFC1035 + compression pointers), `valid=` TTL cache | `dns.rs` |
| `proxy_cache` response caching | in-memory named zones, `proxy_cache_valid`/key/methods/min_uses, upstream `Cache-Control`/`Expires` precedence, `X-Cache-Status` | `proxy_cache.rs` |
| `rewrite ... last/break/redirect/permanent` | regex engine + `$1..$9` back-references | `engine.rs` |
| `return` / `add_header` / `proxy_read_timeout` | same semantics | `router.rs` |
| `location =` / prefix / `~` regex | exact > regex > longest prefix | `router.rs` |
| `listen <port> ssl` + `ssl_certificate` | rustls TLS (HTTPS endpoints; multiple `listen` directives coexist) | `server.rs` |
| HTTP/2 serving (`http2 on;` + `listen … http2`) | TLS h2 via ALPN; cleartext h2c prior-knowledge via 24-byte preface sniff (MSG_PEEK, non-consuming) so h1/h2c share one listener; hyper multiplexed streams | `server.rs`, `router.rs` |
| `ngx_lua` scripting layer | mlua (Lua 5.4), see the Lua API list below | `lua_engine.rs` |
| `init_by_lua` | runs once at startup | `lua_engine.rs` |
| `lua_shared_dict` / `ngx.shared.DICT` | cross-request shared dict: get/set/add/replace/delete/incr/ttl/flush_all | `shared_dict.rs` |
| `access_log` combined format | local file + stdout | `access_log.rs` |
| third-party C modules | `content_by_rust` / `access_by_rust` compile-time registered Rust handlers | `engine.rs` |
| `stub_status` / Prometheus scraping | process-global runtime metrics (accepted/active/capacity + requests + 2xx/3xx/4xx/5xx) rendered as Prometheus text via `content_by_rust metrics` | `metrics.rs` |
| `allow` / `deny` | ACCESS-phase IP ACL: IPv4/IPv6/CIDR/`all`, ordered first-match-wins (default allow), location inherits server rules | `access.rs` |
| `auth_basic` / `auth_basic_user_file` | HTTP Basic auth in ACCESS phase; htpasswd supports plaintext, `{SHA}` (SHA-1), `$1$`/`$apr1$` (MD5-crypt), realm tri-state incl. `off`, mtime-cached file reload | `access.rs` |
| nginx syntax compatibility | `location =/\^~/~/~*`, server_name wildcards, error_page, try_files, index, autoindex, alias, client_max_body_size, return URL shorthand | |

## Directory layout

```
rust/
├── conf/learnon.conf        # example gateway config (full-feature demo)
├── lua/                     # Lua business scripts (auth.lua / time.lua / rewrite_mark.lua)
├── public/                  # static file root (includes logo.png)
└── crates/
    ├── learnon-config/      # Nginx-style config parser
    └── learnon-server/      # server main program
        └── src/
            ├── main.rs      # startup: config -> router -> upstream -> lua -> listen
            ├── router.rs    # server/location matching (= / prefix / ~ regex), directive model
            ├── upstream.rs  # upstream pool + 3 load-balancing methods + passive health checks
            ├── proxy.rs     # reverse proxy engine (reports failures to health checks)
            ├── engine.rs    # rewrite/return engine + native Rust handler registry
            ├── shared_dict.rs # ngx.shared.DICT shared dict
            ├── lua_engine.rs# Lua VM + ngx.* API
            ├── access_log.rs# combined access log
            └── server.rs    # HTTP pipeline: rewrite -> access -> content -> log
```

## Running

```bash
cd rust
# Option 1: run directly with cargo (debug)
cargo run -- conf/learnon.conf
# Option 2: packaged exe (release)
cargo build --release
target\release\learnon.exe conf\learnon.conf

# start two demo backends (either way):
python -m http.server 9001 --bind 127.0.0.1
python -m http.server 9002 --bind 127.0.0.1
```

### HTTPS / certificates

```bash
# generate a self-signed cert (SAN: localhost, 127.0.0.1; custom domains also supported)
cargo run --bin lon-gencert -- certs/cert.pem certs/key.pem your.domain.com
```

Config:

```nginx
server {
    listen 8080;              # HTTP
    listen 8443 ssl;          # HTTPS (a single server block may carry multiple listen directives)
    ssl_certificate     "certs/cert.pem";
    ssl_certificate_key "certs/key.pem";
}
```

The example config ships an 8443 HTTPS endpoint (a self-signed cert is already generated under
`certs/`) and is verified end-to-end: TLS handshake, Lua, reverse proxy, shared dict, and POST bodies
all work correctly over HTTPS. Replace with a CA-issued certificate in production.

Verified routes (28 smoke checks, full HTTP + HTTPS coverage):

| Route | Function |
|---|---|
| `GET /proxy/` | reverse proxy + upstream round-robin (backend-1/2 alternating) |
| `GET /hello` | inline `content_by_lua` script |
| `GET /api/time` | `rewrite_by_lua_file` + `content_by_lua_file` + async `ngx.sleep` |
| `GET /api/protected` | `access_by_lua` auth: no token 401 / wrong token 403 / correct 200 |
| `GET /count` | `ngx.shared.DICT` atomic counter (accumulates across requests) |
| `GET /go` | `ngx.redirect` 302 (Location header) |
| `GET /inner` | `ngx.exec` internal redirect → /hello (transparent to the client) |
| `GET /api/tools` | `ngx.re` regex capture / escape_uri / unescape_uri / body read |
| `GET /old/thing` | `rewrite last` → /new/thing (internal redirect) |
| `GET /health`, `/jump` | `return` 200 / 301 |
| `GET /user/42` | regex location |
| `GET /api/info` | `content_by_rust` native module |
| `GET /static/` | static files; unknown path → 404 |

## Lua API (aligned with ngx.*)

- Response: `ngx.say / print / status (read-write) / exit / header.set / any response header before send_headers`
- Request: `ngx.req.get_method / get_path / get_query / get_headers / get_uri_args / set_uri / set_uri_args / get_body_data`
- Control: `ngx.redirect(uri, code?) / ngx.exec(uri) / ngx.exit / ngx.sleep (async coroutine)`
- Cosocket: `ngx.socket.tcp()` → `connect / send / receive(*l | *a | n) / settimeout / close /
  setkeepalive / getstats` — non-blocking TCP, yields to the VM scheduler so concurrent requests
  interleave on one VM (mirrors ngx_lua's cosocket yield-and-resume model)
- Regex: `ngx.re.match(s, pat, flags?) / ngx.re.find(s, pat, flags?)` (flags support `i`)
- Encoding: `ngx.encode_base64 / decode_base64 / escape_uri / unescape_uri / decode_args / encode_args`
- Shared memory: `ngx.shared.<zone>:get / get_stale / set / safe_set / add / replace / delete / incr / ttl / flush_all`
- Background timers: `ngx.timer.at(delay_sec, cb, ...) / ngx.timer.every(interval_sec, cb, ...) / running_count() / pending_count()`
  — seconds unit, `premature` as the callback's first argument, user varargs forwarded verbatim,
  failures return `(nil, err)`, `return false` stops the interval (semantics aligned with official t/106/152/107)
- Response filters: `header_filter_by_lua*` (mutate response headers / clear Content-Length before
  sending), `body_filter_by_lua*` (rewrite the response body via `ngx.arg[1]` chunk, `ngx.arg[2]` eof)
- Log phase: `log_by_lua` / `log_by_lua_file` (runs after the response is formed, reads the final
  `ngx.status` incl. 5xx and request info; its `ngx.say` writes go to a throwaway copy so they can't
  alter the already-built response — verified by `tools/log_by_lua_e2e.py`)
- Constants: `ngx.OK / ngx.ERROR`, log levels `ngx.STDERR/EMERG/ALERT/CRIT/ERR/WARN/NOTICE/INFO/DEBUG`
  (OpenResty's numeric values, recognized by `ngx.log`), and the common `ngx.HTTP_*` status codes
- cosocket: `ngx.socket.tcp()` with `connect/send/receive(*l|*a|n)/settimeout/close` — ops run in
  tokio tasks (no VM lock held) and yield to the scheduler, so many socket-bound requests share one
  VM concurrently; partial-data + timeout semantics mirror ngx_lua (`nil, err, partial`)
- Subrequests: `ngx.location.capture(uri, opts?)` → `{ status, body, header }` (and `opts.method`) —
  runs the *full* pipeline for the captured location (rewrite → access → content: static / `return` /
  `proxy_pass` / nested Lua all work) as an internal subrequest against the same vhost, then yields to
  the VM scheduler (like the cosocket ops) so the parent coroutine and other in-flight requests keep
  progressing; nested captures are supported with a depth guard (`status = 0` on overflow, mirroring
  ngx_lua's error sentinel). Verified by `tools/subrequest_e2e.py`.
- Others: `ngx.ctx (per-request table) / ngx.time / ngx.now / ngx.log / ngx.config.* / ngx.version`

## E2E tests (aligned with the OpenResty official suite)

OpenResty publishes its E2E tests in the `t/` directory of `openresty/lua-nginx-module` (193 `.t`
files driven by Perl Test::Nginx). This repo adopts a "ported-assertions" strategy: extract
config/request/response/error_log expectations from the official `.t` `__DATA__` sections and rewrite
them as standalone runnable assertion scripts.

- `timer_e2e_test.py`: 11/11 passing, ported from `t/106-timer.t`, `t/152-timer-every.t`,
  `t/107-timer-errors.t` (premature first arg, vararg forwarding, `every`'s `return false` stop, four
  error-string classes, no log cross-talk).
- `realworld_e2e_test.py`: 26/26 passing, a full simulation of real-world scenarios (static cache
  negotiation / range resume, API reverse proxy, auth, login rate limit 429, WebSocket 101 tunnel
  round-trip, background timer heartbeat, 5 MB upload with matching sha256, 413, failover, timeout,
  502 on a dead backend, 30-request concurrency burst, malformed request → 400 with the gateway
  staying alive).
- The official suite is vendored under `vendor/lua-nginx-module/t/` (gitignored) as a semantics
  reference. Running a full `.t` directly via Test::Nginx requires a real OpenResty binary as
  `TEST_NGINX_BINARY` plus `*_by_lua_block` syntax and Unix signals, which do not run on this Windows
  host — hence the ported-assertions route.
- nginx syntax-compat shim: LearnON now accepts nginx's `-p <prefix>`, `-g "<directives>"`, `-e <file>`
  flags and writes a pid file, and the config parser flattens the `http{}` wrapper (dropping
  `events{}`), so the official `nginx-tests` Perl harness (Test::Nginx) can spawn LearnON directly.
- Compatibility regression: `compat_test.py` 17/17, security `sec_test.py` 30 checks, plus the
  static / scenario / upstream suites in this directory.

## Design tradeoffs & roadmap

Already done (previously listed as gaps, now implemented):

- **Lua VM pool**: one VM per CPU core, so multiple requests execute scripts truly in parallel across
  VMs (no single process-wide lock).
- **`lua_shared_dict` capacity enforcement**: `set`/`incr` keep total usage within the declared
  capacity via Redis-style approximate LRU eviction; `safe_set` refuses to evict and returns
  `no memory` instead.
- **Active health checks**: `health_check interval=… fails=… rises=… uri=… timeout=…` drives a
  background prober per upstream (in addition to passive `max_fails`/`fail_timeout`).
- **WebSocket / Upgrade tunnel**: `proxy_pass` auto-detects Upgrade requests and, after completing the
  101 handshake with the backend, hands off to hyper's upgrade mechanism for a bidirectional pipe
  (`server.rs::handle_upgrade` + `ProxyEngine::upgrade`); WS-frame bytes that race ahead of the
  backend's 101 are not lost (prefix buffer). `wss` (https backends) is not yet supported.
- **gzip response compression**: `gzip on;` + `gzip_min_length` / `gzip_comp_level` / `gzip_types`
  stream-compress eligible 2xx responses (flate2, pure-Rust). Respects `Accept-Encoding` (including
  `q=0` decline), skips HEAD and non-listed content types, enforces the length threshold via the
  body's exact `size_hint`, sets `Content-Encoding: gzip` + `Vary: Accept-Encoding`, and drops
  `Content-Length` so the access log's `bytes_sent` reflects the real compressed wire bytes.
  (`compress.rs::GzipBody`, `server.rs::finalize`, verified by `tools/gzip_e2e.sh`.)
- **Upstream keep-alive pool tuning**: per-upstream `keepalive N` and `keepalive_timeout <t>` drive
  hyper's client connection pool (`pool_max_idle_per_host` / `pool_idle_timeout`); the proxy caches
  one pooled client per `(connect_timeout, max_idle, idle_timeout)` triple so differently-configured
  upstreams get separate pools. (`upstream.rs::KeepaliveOpts`, `proxy.rs::client`, verified by
  `tools/keepalive_e2e.sh`: `keepalive` reuses one backend connection, a short `keepalive_timeout`
  reaps the idle one between spaced requests.)
- **Streaming request-body forwarding**: `proxy_request_buffering off` (per server/location, default
  `on` as in nginx) pipes the client request body straight to the backend as it arrives instead of
  buffering the whole thing first — the proxy sends a `BoxBody` wrapping the incoming `Incoming` so
  memory stays O(1) and hyper derives `Content-Length`/chunked framing from the body's `size_hint`.
  Because streamed bytes can't be replayed, the streaming path disables `proxy_next_upstream` node
  switching. (`proxy.rs::ProxyBody`, `server.rs::handle_request`, verified by
  `tools/streaming_body_e2e.py`: a body dribbled to the backend over ~1.2s shows a ~1.1s read span
  through `off` but a single burst read through `on`, with matching sha256 both ways.)
- **Within-VM Lua coroutine concurrency**: each VM is run by a scheduler task that holds the `Lua`
  lock only for a synchronous resume segment and releases it between segments, so many requests share
  one VM and interleave at `ngx.sleep` (a Lua wrapper around a `tokio::time::sleep` that yields the
  sleep id; the scheduler re-readies the coroutine when the timer fires). `ngx.ctx` is a per-request
  table re-attached before each resume, so it survives a yield and stays isolated from other coroutines
  on the same VM. (`lua_engine.rs::run_scheduler`/`co_spawn`, verified by `tools/lua_concurrency_e2e.py`:
  48 concurrent 500ms `ngx.sleep` requests finish in ~0.5s wall — not ~1.5s as the old one-request-per-VM
  serialization would give — and 32 concurrent `ngx.ctx` requests each keep their own counter across the yield.
  `ngx.socket.tcp` cosocket ops share the same yield-and-resume path, verified by `tools/cosocket_e2e.py`:
  32 concurrent connect/send/receive round-trips finish in ~1.3s wall, far below the ~9.6s a serialized
  model would take, while per-op timeout returns `(nil, "timeout")` and connect failure returns `(nil, err)`.)
- **Runtime metrics endpoint**: a process-global `Metrics` singleton (std `OnceLock`) is fed by the
  connection layer — accepted-count on each TCP accept, an active-connections gauge via an RAII guard
  scoped to each connection task, requests-handled per HTTP request, and responses bucketed by status
  class (2xx/3xx/4xx/5xx) in `finalize`. `content_by_rust metrics` reads the singleton and renders it
  in the Prometheus text exposition format (`# HELP`/`# TYPE` + `learnon_uptime_seconds`,
  `learnon_connections_{accepted,active,capacity}`, `learnon_http_requests_total`,
  `learnon_http_responses_total{class="…"}`). It uses the singleton because the native handler signature
  has no access to `AppState`. (`metrics.rs`, `server.rs`, `engine.rs`, verified by
  `tools/metrics_e2e.py`: with traffic interleaved between two scrapes, `requests_total`/`2xx`/`4xx`
  deltas track the real request counts, the active gauge stays ≥1 while a connection is in flight, and
  `capacity` equals the `worker_connections` default.)
- **Access control (`allow`/`deny` + `auth_basic`)**: an ACCESS-phase gate runs before
  `access_by_*` (matching nginx's built-in module order). `allow`/`deny` accept IPv4/IPv6/CIDR/`all`,
  evaluated first-match-wins with default-allow, and a location with no own rules inherits the
  server's. `auth_basic`/`auth_basic_user_file` enforce HTTP Basic with the realm as a tri-state
  (`unset` inherits, `off`/`""` disables, else enables); the htpasswd file is loaded through a
  process-wide cache keyed by mtime. Password records may be plaintext, `{SHA}` (SHA-1 base64),
  `$1$` (glibc MD5-crypt) or `$apr1$` (Apache MD5-crypt) — MD5 and SHA-1 are implemented in pure Rust
  (no crypto crates, so cross-compiles stay clean), and the MD5-crypt output is validated against
  `openssl passwd` reference vectors. Comparisons are constant-time. (`access.rs`, `server.rs`,
  `router.rs`, verified by `tools/auth_e2e.py`: missing/wrong credentials → `401` with a
  `WWW-Authenticate: Basic realm=…` challenge, correct `{SHA}`/`$apr1$`/plaintext logins → `200`,
  `deny all` → `403`, `allow 127.0.0.1/32` matches the loopback client.) crypt-DES and bcrypt
  (`$2y$`) htpasswd records are not yet supported.
- **Subrequests (`ngx.location.capture`)**: a captured location runs the entire request pipeline
  (rewrite → access → content: static, `return`, `proxy_pass`, and nested Lua content all work) as an
  internal subrequest resolved against the parent's vhost, returning a `{ status, body, header }`
  table. It is a scheduler yield point (`coroutine.yield(op_id)`) exactly like the cosocket ops — the
  subrequest runs in a tokio task that reaches `AppState` through a late-bound `Weak<AppState>` handle
  (the Lua engine is constructed before `AppState`, so main.rs binds it after startup) — so the parent
  coroutine releases the VM lock and other in-flight requests keep progressing. Nested captures work
  because a subrequest's own Lua re-enters the scheduler without deadlock, and a `capture_depth` guard
  caps runaway recursion (returns `status = 0`, the ngx_lua error sentinel). `internal;` locations are
  reachable only via capture, not from the client. (`server.rs::run_capture`, `lua_engine.rs`,
  verified by `tools/subrequest_e2e.py`: Lua/return/query/404 captures, a two-level nested capture, a
  self-referential capture hitting the depth guard, and an external request to an `internal` location
  still returning 404.) `share_all_vars`/`ctx` option passing is not yet implemented.
- **`resolver` + async DNS**: a pure-Rust, non-blocking UDP DNS stub resolver (`dns.rs`) — it builds
  RFC1035 queries for A/AAAA, follows compression pointers in the answer, and caches results for the
  `valid=` TTL (default 10s), with negative caching for NXDOMAIN. Without it, `proxy_pass` relies on
  the OS `getaddrinfo` (which a busy worker would block on); with it, `proxy.rs` resolves the backend
  hostname to an IP literal before connecting and rewrites the URI authority — hyper then skips
  `getaddrinfo` entirely, and the original name is kept in the `Host` header. Applies to both the
  forward path and the WebSocket/`upgrade` raw-socket path. `resolver <addr…> [valid=…] [timeout=…]
  [ipv6=on|off];` (plus `resolver_timeout`). Resolution failure returns the nginx-mapped `502`.
  (Verified by `tools/resolver_e2e.py`, which points `resolver` at a stub DNS server and proxies to
  `test.invalid` — an RFC6761 reserved name the OS cannot resolve — proving the async path is taken,
  then shows a repeated request does **not** re-query thanks to the TTL cache.) `ngx.socket.tcp`
  `connect` still uses system resolution.
- **`proxy_cache` response caching**: an in-memory, named-zone cache (`proxy_cache.rs`) for the
  `proxy_pass` path. Directives: `proxy_cache <zone>|off`, `proxy_cache_key <template>` (default
  `$scheme$proxy_host$request_uri`), `proxy_cache_valid <codes…|any> <time>` (multi-line),
  `proxy_cache_methods` (default `GET HEAD`), `proxy_cache_min_uses` (default 1). Freshness precedence
  matches nginx: the upstream's own `Cache-Control`/`Expires` wins (and an explicit `no-store`/`no-cache`/
  `private`/`max-age=0` forbids caching outright), falling back to `proxy_cache_valid` only when the
  upstream gives no hint. Responses carrying `Set-Cookie` are never stored (shared-cache safety). Every
  proxied response through a cached location gets an `X-Cache-Status: HIT|MISS|BYPASS` header. A hit
  replays the buffered status/headers/body without contacting the backend.
  (Verified by `tools/proxy_cache_e2e.py`: MISS→backend then HIT→same bytes with the backend counter
  unchanged, distinct `?query` → distinct keys, `Set-Cookie` and `no-store` → `BYPASS`, and a
  non-caching control location with no `X-Cache-Status`.) Not yet implemented: `proxy_cache_use_stale`,
  revalidation (`If-None-Match` to origin), `proxy_cache_purge`, on-disk `keys_zone`, and `Vary`-aware
  keying.
- **HTTP/2 serving**: LearnON serves HTTP/2 over both transports. On TLS endpoints the `h2` protocol is
  negotiated through ALPN (`listen … ssl http2`). On cleartext endpoints `http2 on;` turns on
  prior-knowledge h2c: the connection layer peeks the first 24 bytes with `MSG_PEEK` (`TcpStream::peek`,
  non-consuming) and, only if they match the client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`),
  hands the socket to hyper's `http2` server; otherwise the same listener serves HTTP/1.1 unchanged — so
  h1 and h2c coexist on one port. Requests are handled by the same vhost/location pipeline as HTTP/1, and
  a single h2 connection multiplexes concurrent streams.
  (Verified by `tools/http2_e2e.py` via Node's core `http2` client — the local libcurl has no HTTP/2:
  cleartext h2c and TLS-ALPN h2 both return the configured bodies, HTTP/1.1 still works on the same
  cleartext port, and 3 concurrent streams on one h2 connection all reach `200`.)
  HTTP/2 to *upstreams* (h2 `proxy_pass`) and `server_tokens`/hpack tuning remain open.

Remaining tradeoffs / roadmap:

- **Cosocket coverage**: `ngx.socket.tcp` runs `connect/send/receive(*l|*a|n)/settimeout/close` as
  scheduler yield points (see the API section above), but not yet `receiveany`, the timed `*l` third
  return variant, `connect` over SSL (`ssl:connect`), or `ngx.socket.udp`. `balancer_by_lua` and
  `ngx.location.capture`'s `share_all_vars`/`ctx` option passing remain open.
- **`ngx.sleep` inside `ngx.timer` callbacks**: timer callbacks run synchronously under the VM lock,
  outside a scheduler coroutine, so `ngx.sleep` there is not yet a yield point (request-phase Lua is).
