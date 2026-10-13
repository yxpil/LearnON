-- auth.lua：access 阶段鉴权（对标 OpenResty access_by_lua）
local headers = ngx.req.get_headers()
local token = headers["x-token"]
if token == "secret123" then
    return  -- 放行，进入 content 阶段
end
if token == nil then
    ngx.status = 401
    ngx.say("unauthorized: missing x-token header")
else
    ngx.status = 403
    ngx.say("forbidden: bad token")
end
ngx.exit(ngx.status)  -- 结束请求，不再进入 content 阶段
