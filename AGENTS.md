# AGENTS.md — 本项目的 AI 协作约定

给在本仓库里干活的 AI agent（以及人）看的规则。凡是本文件与临时指令冲突，
以用户当次的明确要求为准；其余默认按这里来。

## 1. 项目速览

- 纯 Go + [mygo](https://github.com/egoist/mygo) 原生 UI，无 cgo、无前端构建。Go 1.27+。
- 主模块 `github.com/qy/easyconnect`（仓库根）。
- 子模块 `third_party/zju-connect`：打了补丁的 ZJU-Connect，含多点 TUN 辅助程序
  `cmd/multitun`（`zju-connect-multitun`）和 `stack/tun`（TUN 栈、TCP listener、重定向）。
- TUN 辅助程序**不随仓库提交**，由 `make helpers` 编译到 `resources/<os>-<arch>/`，
  再由 `make build` 打进 `.app` 的 `Contents/Resources/`。

## 2. 构建与验证（每次改完代码都要做）

本机 `go env GOROOT` 可能被误设成 `/usr/local/go`，统一用下面的模板：

```sh
export GOROOT=/opt/homebrew/Cellar/go/1.27.3/libexec
export PATH="$GOROOT/bin:$PATH"
export GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" GOTMPDIR=/tmp

make GO=/opt/homebrew/bin/go LOCAL=1 helpers   # 重编 TUN 辅助程序
make GO=/opt/homebrew/bin/go LOCAL=1 build     # 打 .app（build/darwin-arm64/）
```

**改完要让用户真正看到效果，用这一条**（编译 + 覆盖安装到 /Applications + 启动）：

```sh
make GO=/opt/homebrew/bin/go LOCAL=1 install
```

只用 `build` 的话，新代码只落在 `build/darwin-arm64/`；用户平时双击的是
`/Applications/aTrustHub.app`（CI 发版的通用二进制），不覆盖安装就永远是旧界面。
不想动 /Applications 时用 `make ... refresh`（只重启本地 build 那份）。

提交前必须全绿：

```sh
go build ./... && go vet ./... && go test ./...
(cd third_party/zju-connect && go build ./... && go vet ./... && go test ./...)
```

改动涉及 `stack/tun` 或 `cmd/multitun` 等共享代码时，再加一次 Windows 交叉编译
（两个模块都要）：`GOOS=windows GOARCH=amd64 go build ./...`。

新增行为要有单元测试；UI 组件可用 `ui.NewTester` 做渲染/交互断言。

## 3. 绝对禁忌（都是踩过的坑）

1. **不要 `pkill -9` 正在运行的 TUN helper。** 它来不及清理，会留下 `utun` 设备、
   覆盖全网的 `/1 /2 /4 …` 路由、以及指向已死 DNS 的系统设置，**直接导致整机断网**。
   要停就写 `tun.stop` 文件，或走应用的正常关闭路径。
2. **不要在"没有 resolver / 没有 ipPool"的栈上开 `dnsHijack=true` 或 `fakeIP=true`。**
   `shouldHijackUDPDns` 会 nil 解引用 panic；helper 一死，系统 DNS 就指向没人应答的地址。
   映射（mapping-only）模式必须：`dnsHijack=false`、`fakeIP=false`、不 `setSystemDNS`。
3. **接管系统 DNS / 路由后必须有还原。** 正常路径加 `defer restoreSystemDNS()`，
   `Run()` 里 `recover()` 兜 panic。任何"只设不还"的改动都不可接受。
4. **不要提交** `.gocache/`、`.gomodcache/`、`.shots/`、`build/`、`resources/*/zju-connect-multitun`。
5. 不要把签名、密钥、token、用户凭据写进代码或日志。

## 4. 配置与数据

- 运行数据目录：`~/Library/Application Support/aTrust Hub/`
  - `tun.log`（helper 日志）、`tun-launch.log`（启动/崩溃栈）、`tun-access.log`（访问记录）
  - `tun-config.json`（helper 输入）、`config.json`（应用配置）
- 配置模型在 `internal/model`。端口映射：
  - `Settings.LocalMappings`：**生效**的映射（`"目标ip[:port]" -> "本机host:port"`）
  - `Settings.DisabledMappings`：用户**关掉但保留**的映射
- **版本号两处必须同步**：`mygo.json` 的 `version` 与 `app.go` 的 `appBuild`。
  只改一处会导致「关于」和更新检查报的版本不一致。

## 5. 发版流程

1. 把版本号补丁位 +1（例如 0.26.20 → 0.26.21），两处一起改。
2. 功能提交信息用中文，说明背景、改动点、验证方式。
3. release 提交：`release: x.y.z 同步构建号`。
4. 打 tag 并推送（CI 在 `v*` tag 上自动打包 dmg/exe 并创建 GitHub Release）：

```sh
git tag -a vX.Y.Z -m "vX.Y.Z: <一句话>"
git push origin main && git push origin vX.Y.Z
```

## 6. UI 约定

- 顶部按钮区：`全局 TUN` 开关、`系统代理` 开关、齿轮（设置 = 统一入口/分流等）、
  另一个齿轮图标按钮（端口映射弹窗）、`＋ 添加接入点`。
- 端口映射弹窗：标题「端口映射」，**右上角并排**「访问日志」(☰) 与「TUN 日志」(📄)；
  每行 `启用开关 | 目标 IP | 端口 → 映射 IP | 端口 | 删除`，支持多条。
- 主窗口 tab 顺序：`接入点` / `应用 N` / `访问日志` / `分流规则`。第四个 tab **只生成
  Clash Verge 扩展配置格式**（`clash.go` 的 `generateClashMerge`）：`prepend-proxies` /
  `prepend-proxy-groups` / `prepend-rules` 三段，可直接粘贴进「全局扩展覆写配置」。
  每点一个 SOCKS5 代理 + select 组 + 按应用地址生成 `IP-CIDR` / `DOMAIN-SUFFIX` 规则；
  未登录或无独立 SOCKS5 端口的点只报告、不生成。用 `prepend-` 是为了排在订阅自带
  的 `MATCH`/`GEOIP` 兜底规则之前。
- 任何失败都要给用户可见反馈（`a.toast` 或弹窗内 `d.err`），不要静默失败。

## 7. 验证新构建时的注意

- 应用有**单实例锁**：验证新 `.app` 前先彻底退出旧实例，否则 `open` 只会激活旧进程，
  看起来像"改动没生效"。
- **改完没生效**先查这两处，别急着怀疑代码：
  1. `pgrep -fl "MacOS/aTrustHub"` 看跑的是 `build/...` 还是 `/Applications/...`；
  2. 对比时间戳与架构：`/Applications` 里是 CI 的 universal 包，`build/` 里是本地 arm64，
     两者本来就是两次不同的构建，`/Applications` 不会自动更新——用 `make install`。
- 重启 TUN 前确认没有残留 `zju-connect-multitun` 进程，以及没有残留 `utun` 路由。
