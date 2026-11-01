# 内置的 ZJU-Connect v1.3.1（打过补丁）

这是 [Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
**v1.3.1** 的源码拷贝（AGPL-3.0，见 LICENSE），加了两处：

- aTrust 企业微信二维码登录 `auth/qywechat`；
- 从 `clientResource` 里保留应用列表（`Client.Apps()`），供工作台显示。

主模块的 `go.mod` 用：

```go
replace github.com/mythologyli/zju-connect => ./third_party/zju-connect
```

指向它。为了缩小体积，只保留了非 `_test.go` 的 `.go` 源码、`go.mod` 和
LICENSE。

## 为什么需要

上游 v1.3.1 的 aTrust 认证只支持：

- `auth/psw` 密码；
- `auth/cas` CAS；
- `auth/httpsOauth2` 标准 OAuth2。

而实际接入点（例如 `vpn.example.com`、`vpn2.example.com`）返回的是
`auth/qywechat`（企业微信认证），配置在 authConfig 的
`qyWechatQrcodeConf` 里：appid、agentid、redirect_uri、state。上游没有这个
authType，`Session.Login` 找不到匹配项，直接报
`auth type/login domain combination not found`。

## 补丁内容

1. `client/atrust/auth/auth.go`
   - `AuthInfo` 增加 `QyWechatQrcodeConf` 字段和对应类型。
2. `client/atrust/auth/login_method.go`
   - `LoginMethodOptions` 增加 `Callback`；
   - 支持 `auth/qywechat`，返回 `QyWechatLogin`。
3. `client/atrust/auth/qywechat.go`（新增）
   - `QyWechatLogin` 实现 `LoginMethod`；
   - `QyWechatLoginURL` 从 authConfig 构造企业微信二维码页
     `open.work.weixin.qq.com/wwopen/sso/qrConnect`；
   - `login` 用**同一个登录会话**的 AuthConfig 生成二维码 URL，通过 `Open`
     回调让 GUI 显示二维码，拿到回调后 GET `/passport/v1/auth/qywechat`；
   - 从回调 302 的 `ticket` 参数、`/portal/shortcut.html?data=` 的 JSON、
     `/portal/qrcode_middle.html?data=` 的 JSON 里取 portal ticket；取不到时
     再调 `authConfig?needTicket=1` 从响应 `data.ticket` 取，并会跟随几跳重定向；
   - 兼容回调返回 302（portal ticket / qrcode_middle）、200 JSON ticket、
     以及错误跳转；
   - 回调后若会话已登录（`isLogin=1`）但拿不到 ticket，就跳过需要 ticket 的
     `reportEnv`，直接进入 `onlineInfo`，和「已登录」分支一致；
4. `client/atrust/parse.go` / `client.go`
   - `resourceApp` 增加 name、description、accessModel、subModel、group、nodeGroup、
     iconPath、appAddress、accessAddress、accessEntry 等字段；
   - 新增 `App` / `AppAddress` / `ParseApps`，`parseResource` 在解析资源时
     同时保存应用列表；
   - `Client.Apps()` 暴露给 GUI。
5. `main.go` 等未改。

## 升级时

1. 取新版本源码；
2. 用非测试 `.go` 文件覆盖本目录，保留 LICENSE 和本文件；
3. 按上面三点重新打补丁（qywechat 文件可原样拷回）；
4. 改主 `go.mod` 的 `require` 版本（`replace` 不用动），
   `make test && make build`。
