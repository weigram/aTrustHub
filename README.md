# aTrust Hub

[![build](https://github.com/weigram/aTrustHub/actions/workflows/build.yml/badge.svg)](https://github.com/weigram/aTrustHub/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/weigram/aTrustHub?display_name=tag)](https://github.com/weigram/aTrustHub/releases)

**同时登录多个 aTrust 接入点**的桌面客户端（macOS / Windows）。一个窗口里管理多个
零信任网关，每个接入点各自保持一条独立隧道，并能按「目标属于谁」自动分流。

支持两种登录方式：**企业微信认证**（扫码 / 电脑端确认）与 **账号密码**（可叠加 TOTP）。

![界面](docs/screenshot.png)

## 它解决什么

官方 aTrust 客户端一次只能连一个网关，而现实中经常要同时用多个：

- 公司 A 的网关（办公网、GitLab、内部系统）；
- 公司 B / 分公司 / 客户的网关（另一套内网、另一批应用）。

来回断开重连很麻烦，而且很多工具（MySQL 客户端、SSH、Git）不会走浏览器代理。
aTrust Hub 的做法是：

1. 每个接入点各建一条隧道，互不影响；
2. 每个接入点开一个本地 SOCKS5 端口；
3. 再提供一个**统一入口** SOCKS5，按策略把连接交给合适的接入点；
4. 需要「不用配代理就能访问」时，打开**全局 TUN**，按接入点分别注入路由。

> 这里的「多接入点」指**多个 aTrust 服务器/网关的同时登录**。

## 功能

| 能力 | 说明 |
| --- | --- |
| 多接入点同时在线 | 每个点独立隧道、独立 SOCKS5 端口、独立状态 |
| 企业微信认证 | 弹窗显示二维码，支持手机扫码与电脑端确认，也可用本地微信认证 |
| 账号密码登录 | 可选登录域、可选 TOTP 动态口令 |
| 单点 / CAS 登录 | 需要网页交互的网关用内置 WebView 完成 |
| 认证方式自动识别 | 填地址后「检测」，自动判断该网关支持哪些登录方式 |
| 统一入口分流 | 故障转移 / 延迟优先 / 轮询 / 哈希，且**优先选覆盖目标资源的接入点** |
| 应用中心 | 按接入点分块、可折叠，展示每个应用地址并测试可达性 |
| 访问日志 | 记录「目标 + 端口 → 接入点 + 应用」，成功绿点、失败红点 |
| 全局 TUN | 每个接入点一套原生 TUN 栈，内网域名与证书正常，无需配代理 |
| 系统代理 | 一键把 macOS 系统代理指向统一入口 |
| 会话复用 | 保存登录会话，开 TUN 时不需要重新扫码 |

## 快速开始

1. 打开应用，点右上角 **+ 添加接入点**；
2. 填名称与**接入地址**（如 `https://vpn.example.com:443`，不写端口默认 443）；
3. 点 **检测** 确认网络与认证方式；
4. 保存后点卡片上的 **登录**：
   - 企业微信：弹窗里扫码，或在手机企业微信里点确认；
   - 账号密码：填用户名 / 密码（可选 TOTP）后登录。
5. 多个接入点都登录后，客户端连统一入口 `socks5://127.0.0.1:10880` 即可。

> 默认**不会**自动登录。需要随应用启动就连接的点，在编辑弹窗里勾选
> 「应用启动时自动登录」。

## 登录方式

### 企业微信认证

网关认证方式为 `auth/qywechat` 时，登录会弹出二维码窗口：

- **手机扫码**：用企业微信扫一扫并确认；
- **电脑端确认**：已在电脑登录企业微信时，手机端会收到确认提示；
- **本地微信认证**：二维码下方按钮，用本机已登录的微信完成认证。

登录成功后会话保存在数据目录，后续开启全局 TUN 不需要再扫码。

### 账号密码

在编辑弹窗填 **用户名 + 密码** 即走账号密码登录，另有两个可选字段：

- **登录域**：RADIUS / 域认证需要时填写；
- **TOTP 密钥**：填 Base32 密钥即自动生成动态口令。

密码存放位置可选「本地文件（推荐，`0600`）」或「系统钥匙串」。

### 单点 / CAS

认证方式为 `auth/cas` 或需要网页交互的网关，会用内置 WebView 打开登录页，
完成（含短信、扫码、IDaaS）后自动回到应用。

## 统一入口

统一入口是本地 SOCKS5，默认 `127.0.0.1:10880`，分流策略在界面上切换：

| 模式 | 行为 |
| --- | --- |
| 故障转移 | 固定用第一个可用接入点，失败后换下一个 |
| 延迟优先 | 选当前延迟最低的接入点 |
| 轮询 | 按连接轮流分配 |
| 哈希 | 同一目标固定走同一接入点 |

此外还有一层**资源优先**：若某接入点发布了覆盖目标主机/域名的应用
（IP、`A-B` 网段、CIDR 或域名），优先走那个接入点，避免「能连上但打不开」。

## 应用中心

登录后自动拉取该接入点的应用列表，按接入点分块展示，可折叠。每个应用可以：

- 查看服务器地址（域名 / IP / 端口）；
- **复制地址**、**复制代理**；
- **测试全部地址**：经统一入口逐个探测，显示延迟或失败原因；
- **用代理浏览器打开**：自动带上代理打开该地址。

## 访问日志

「访问日志」标签记录每次经隧道访问的目标：

```
19:41:17  ● db.internal.example:3306 → 办公网关 ｜ 应用：内部数据库
19:42:36  ● gitlab.example.com:443 → 办公网关 ｜ 应用：GitLab
19:43:02  ● 10.0.0.9:443 ｜ 研发网关 ｜ tcp tunnel connection not allowed
```

- 绿点成功、红点失败；失败会写明原因（拒绝、超时、无资源等）；
- 同一目标重复访问只保留一行，**只更新时间**，不会刷屏；
- 代理模式与 TUN 模式的访问都会记录。

## 全局 TUN

打开 **全局 TUN** 后，不需要给任何客户端配代理即可访问内网：

- 每个在线接入点各启动一套原生 ZJU-Connect TUN 栈（`zju-connect-multitun`），
  各自一个 `utun`，路由只覆盖该点自己的 IP 资源，互不冲突；
- 内网域名由各点的伪装 IP 池（`198.18.0.0/17`、`198.18.128.0/17`…）分配地址，
  数据包进 TUN 后反查回域名再走隧道，**HTTPS 证书正常**；
- 系统 DNS 指向 helper 自己的解析器，非内网域名转发上游，并持续守护该设置；
- **首次开启需要一次管理员授权**，用于安装一条 sudoers 免密规则
  （`/etc/sudoers.d/atrust-hub`，只允许运行这个 helper），之后开启不再弹密码；
- 关闭开关或退出应用时，helper 退出并**自动还原系统 DNS**，不会断网。

应急恢复（若网络异常）：

```sh
sudo pkill -f zju-connect-multitun
for s in "Wi-Fi" "USB 10/100/1000 LAN" "Thunderbolt Bridge"; do
  sudo networksetup -setdnsservers "$s" Empty
  sudo networksetup -setwebproxystate "$s" off
  sudo networksetup -setsocksfirewallproxystate "$s" off
done
```

## 数据目录

```
~/Library/Application Support/aTrust Hub/
├── config.json              # 接入点与设置
├── secrets.json             # 密码（0600，可选钥匙串）
├── app.log                  # 应用日志
├── atrust/<id>.json         # 登录会话（TUN 复用）
├── atrust/<id>.resource.json
├── tun.log                  # TUN helper 日志
├── tun-access.log           # TUN 访问记录
└── tun-config.json          # TUN 启动参数
```

界面右下角 **打开数据目录** 可直接定位。

## 下载

到 [Releases](https://github.com/weigram/aTrustHub/releases) 下载对应架构的压缩包：

| 平台 | 包 | 说明 |
| --- | --- | --- |
| macOS Apple Silicon | `aTrustHub-darwin-arm64.zip` | 解压后把 `aTrustHub.app` 拖进「应用程序」 |
| macOS Intel | `aTrustHub-darwin-amd64.zip` | 同上 |
| Windows x64 | `aTrustHub-windows-amd64.zip` | 解压后运行 `aTrustHub.exe` |

macOS 首次打开若被 Gatekeeper 拦截，右键 →「打开」，或执行
`xattr -dr com.apple.quarantine /Applications/aTrustHub.app`。

Windows 版目前提供**代理模式**（多接入点、统一入口 SOCKS5、应用中心、访问日志）；
全局 TUN 依赖 wintun，启动时会请求管理员权限，仍在验证中；系统代理开关暂不显示。

## 构建

需要 Go 1.27+ 与 macOS（Apple Silicon 或 Intel）。

```sh
make helpers   # 编译 TUN 辅助程序到 resources/
make build     # 打包 .app（产物在 build/darwin-arm64/）
make test      # 单元测试
```

`make helpers` 编译 `third_party/zju-connect/cmd/multitun`。这是打了补丁的
ZJU-Connect 分支（新增企业微信认证、应用列表、会话复用、多点 TUN 等），
编译产物不随仓库提交，需要本地生成。

## 持续集成

`.github/workflows/build.yml` 会在每次 push / PR 时跑测试，并同时打包
`darwin-arm64`、`darwin-amd64`、`windows-amd64` 三个产物；打 `v*` 标签时
自动创建 Release 并附上三个 zip。

```sh
git tag v1.0.0 && git push origin v1.0.0
```

## 架构

```
┌──────────── aTrust Hub（单个进程）────────────┐
│  接入点 A ─ gVisor 栈 ─ resolver ─ SOCKS5 :1081 │
│  接入点 B ─ gVisor 栈 ─ resolver ─ SOCKS5 :1083 │
│  接入点 C ─ gVisor 栈 ─ resolver ─ SOCKS5 :1082 │
│                 └── 统一入口 SOCKS5 :10880 ──┘ │
└───────────────────────────────────────────────┘
                    │ 需要免配代理时
                    ▼
      zju-connect-multitun（root）
      每个接入点一套原生 TUN 栈 + 独立伪装 IP 池
      系统 DNS 127.0.0.1 → 按接入点解析
```

## 平台差异

| 功能 | macOS | Windows |
| --- | --- | --- |
| 多接入点 + 统一入口 SOCKS5 | ✅ | ✅ |
| 企业微信 / 账号密码登录 | ✅ | ✅ |
| 应用中心、访问日志 | ✅ | ✅ |
| 全局 TUN | ✅ | 实验（需 UAC，wintun） |
| 系统代理开关 | ✅ | 暂未提供 |

## 限制

- **服务器可能不允许同一账号多会话**。若 aTrust 策略是「后登录踢掉先登录」，
  同一账号在两个接入点同时在线会被服务器拒绝，客户端无法绕过。
- **扫码登录一次只开一个窗口**：多个扫码接入点同时登录时，后一个会等前一个完成。
- **全局 TUN 需要管理员权限**（创建 utun、改路由与 DNS）。
- **企业微信认证依赖网关支持** `auth/qywechat`；不支持的网关请用账号密码或 CAS。
- 统一入口默认无认证，改成监听 `0.0.0.0` 前请确认所在网络可信。

## 常见问题

**扫码成功但应用没反应？**
手机显示「扫描成功」只代表扫到了码，还需在手机企业微信里点确认；
若仍无反应，看「运行日志」里是否有 `confirm` 或 `ticket` 相关错误。

**域名能解析但打不开？**
确认该域名在对应接入点的应用列表里。若走 TUN，确认全局 TUN 已开启，
且 `tun.log` 中该接入点显示 `ready`。

**开了 TUN 后外网变慢或不通？**
TUN 只接管各接入点的内网网段，外网仍走原路由。若异常，先关掉 TUN，
或按上面「应急恢复」清理 DNS。

**一直显示「处理中」？**
看数据目录 `tun.log` 末尾：常见原因是某个接入点会话过期，重新登录该点即可。

## 致谢

- [ZJU-Connect](https://github.com/mythologyli/zju-connect)：aTrust / EasyConnect 协议实现，
  本项目内置了打过补丁的分支；
- [mygo](https://github.com/egoist/mygo)：原生 macOS UI 框架。

## 许可

MIT
