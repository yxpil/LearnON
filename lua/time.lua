-- time.lua：演示外部 Lua 文件 + 异步 ngx.sleep + ngx.ctx 跨阶段状态
ngx.ctx.entered = ngx.ctx.entered or ngx.now()
ngx.sleep(20)  -- 协程让出，不阻塞 worker
ngx.header["Content-Type"] = "application/json"
local now = os.date("!%Y-%m-%dT%H:%M:%SZ")
ngx.say(string.format('{"now": "%s", "elapsed_ms": %.2f}', now, (ngx.now() - ngx.ctx.entered) * 1000))
