-- rewrite_mark.lua：rewrite 阶段示例，记录进入时间供 content 阶段读取
ngx.log(1, "rewrite: ", ngx.req.get_method(), " ", ngx.req.get_path())
ngx.ctx.entered = ngx.now()
