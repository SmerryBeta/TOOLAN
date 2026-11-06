# TOOLAN 后端安全设计（局域网威胁模型）

> **当前状态（2026-10-02）：鉴权总开关已关闭**（config.yml `Security.AuthEnabled: false`），
> 所有接口免登录直连。恢复：改为 `true` 并重启即可，全部登录链路代码保留未动。
> 关闭期间风险：同局域网内任何人可读/删文件、读剪贴板、上传、伪造 Windows 通知；
> 限流、上传大小限制、CSP sandbox、WS Origin 校验等非鉴权防御仍然生效。

## 1. 威胁模型

服务暴露于局域网，攻击者（"隔壁老王"）可：

- 直接访问所有 HTTP/WS 接口
- 嗅探流量（明文 HTTP）
- 用浏览器打开恶意网页（驱动老王的浏览器向本服务发跨站请求）

## 2. 已修复漏洞与对应防御

| # | 漏洞 | 严重度 | 防御措施 |
|---|------|--------|----------|
| 1 | 全部 API 零认证：可读/清空剪贴板、删文件、上传任意文件、伪造 Windows 通知 | P0 | 共享密码认证（`internal/security`），所有数据接口/上传目录/WS 均需会话 |
| 2 | WS 帧声明长度未校验 → `make([]byte, length)` makeslice panic，远程崩溃进程 | P0 | 帧长度上限 1MB，先校验再分配（`ws/hub.go readFrame`） |
| 3 | 上传无大小限制 → 磨盘 | P0 | `http.MaxBytesReader`（默认 2GB，可配 `MaxUploadMB`），超限 413 |
| 4 | HTTP Server 无超时 → Slowloris | P1 | `ReadHeaderTimeout=10s`、`IdleTimeout=120s`、`MaxHeaderBytes=8KB` |
| 5 | WS 不校验 Origin → 跨站 WebSocket 劫持 | P1 | 同源校验 + `ExtraAllowedHosts` 白名单；无 Origin 的原生客户端放行 |
| 6 | CSRF：Gin `ShouldBindJSON` 可被 text/plain 跨站触发（弹窗轰炸钓鱼） | P1 | 会话 Cookie `SameSite=Strict`，跨站不带 Cookie 即 401 |
| 7 | 上传的 html/svg 同源 inline → 存储型 XSS | P1 | 上传目录响应 `Content-Security-Policy: sandbox` + `nosniff`，脚本无法执行 |
| 8 | Gin debug 模式、无安全头、无限流 | P2 | `gin.ReleaseMode`；全响应 `X-Content-Type-Options/X-Frame-Options/Referrer-Policy`；页面 CSP（`script-src` 含 `'unsafe-eval'`，因 Vue 2 运行时编译模板依赖 `new Function`，缺失时 Vue 静默以空渲染函数挂载导致整页空白）；API `no-store`（剪贴板不落缓存）；每 IP 240 req/min |
| 9 | 登录爆破 | P2 | 5 次失败锁 10 分钟/IP；`SetTrustedProxies(nil)` 防 XFF 伪造绕过限流 |
| 10 | Windows 保留设备名（CON/NUL/COM1…）写入异常 | P2 | 上传与建目录拒绝保留名 |
| 11 | `util/secure.go` MD5 存密码 | P2 | 改为 SHA-256（该包当前未被引用） |
| 12 | 消息/剪贴板无长度限制 | P2 | 统一 100KB 上限 |
| 13 | 上传同名文件静默覆盖 → 误传即损毁仓库旧文件 | P2 | 目标存在且未带 `?overwrite=1` 时返回 409（`code: file_exists`），客户端弹确认；明文路径改为 `.part` 临时文件 + 原子改名，上传中断不再截断旧文件 |

## 3. 认证机制

- **凭据**：config.yml `Security.Password`；为空则首次启动自动生成（10 位无歧义字符），回写文件并打印控制台。
- **令牌**：`base64url(nonce) . expUnix . HMAC-SHA256(secret, nonce|exp)`，无状态可横向扩展校验。
- **密钥**：32 字节随机，持久化于 `static/data/session.key`（0600），重启后会话不失效。密钥一旦丢失/更换（如删除 `static/data`、换目录启动），全部令牌立即作废，所有客户端需重新登录；启动时会打印 `[security] 已生成新的会话密钥` 提示。
- **传输**：
  - 浏览器：`HttpOnly + SameSite=Strict` Cookie（自动携带，覆盖页面/img/fetch/WS）
  - Android/CLI：`Authorization: Bearer <token>`
  - WS 无法带头的客户端：`?token=<token>`
  - 移动端 WebView 下载：下载会被 WebView 转交系统下载器（不携带 Cookie），前端登录时把令牌另存 localStorage，下载 URL 统一拼 `?token=`（与 WS 同通道；旧会话可由 `/api/auth/token` 无感补齐）
- **接口**：
  - `POST /api/auth/login {password}` → Cookie + token
  - `GET /api/auth/status` → 是否已登录
  - `GET /api/auth/token` → 回传当前令牌（需已登录；令牌在 HttpOnly Cookie 里页面读不到）
  - `POST /api/auth/logout` → 清 Cookie
- 登录失败带 IP 审计输出。

## 4. 路由暴露面

| 类别 | 路由 | 认证 |
|------|------|------|
| 页面外壳 | `/`、`/store` | **必须**（未登录由服务端 302 到 `/login?next=`） |
| 登录页 | `/login`、`/gate.js` | 公开 |
| 服务发现 | `/server_info` | 公开（仅端口/协议元数据） |
| 认证 | `/api/auth/*` | 公开 + 限速 + 锁定；例外：`/api/auth/token` 需已登录 |
| 数据 API | `/upload`、`/api/*`（含 `/api/upload/check`）、`/messages*`、`/message*`、`/notify`、`/ws` | **必须** |
| 同步下载 | `/api/sync/file?ftoken=` | **公开** + 限流 + no-store：一次性 ftoken 即凭证（见 §4.1），不要求会话 |
| 上传内容 | `/static/images/*`、`/static/files/*` | **必须** + CSP sandbox |

### 4.1 一次性下载凭证（ftoken）

`POST /upload?sync=1` 上传成功后，服务端向 `?device=android` 的 WS 客户端定向推送
`file.sync_offer`，邀请中的下载地址带 `ftoken`：

- **生成**：32 字节 `crypto/rand` → base64url（约 43 字符），不可预测、不可伪造。
- **绑定**：每条凭证只对应一个分区（image/file）内的一个相对路径，路径存服务端
  内存（`internal/server/sync_token.go`），客户端无法篡改目标。
- **时效/次数**：10 分钟内有效，最多 5 次下载（容忍下载中断重试与多台手机各取
  一份），超限或过期即 404。
- **动机**：移动端接受推送后的下载不需要持有主会话令牌，避免把长期令牌放进下载
  URL（与 §8.6 的 `?token=` 风险同源的问题在这一链路上被消除）。
- **局限**：明文 HTTP 且未启用 A1 加密时，邀请帧与 `?ftoken=` 在局域网可嗅探——但
  凭证能力上限是"10 分钟内读这一个文件"，远小于主会话令牌泄露；`?ftoken=` 同样会
  进 gin 访问日志（与 `?token=` 一致的折衷）。启用 A1 后邀请为密文帧、下载为 A1L
  加密流，嗅探无效。

## 5. 配置参考（config.yml）

```yaml
Server:
  Host: "0.0.0.0"   # 改为内网固定 IP 可缩小暴露面
  Port: 8000
Security:
  AuthEnabled: false      # 鉴权总开关（默认 true；当前用户选择关闭）
  Password: ""          # 留空自动生成
  SessionTTLHours: 168
  MaxUploadMB: 2048
  RatePerMinute: 240
  LoginMaxFails: 5
  LoginLockMinutes: 10
  MaxWSClients: 64
```

## 6. 传输加密（HTTPS）

- **实现**：自签 ECDSA P-256 CA（10 年）+ 服务端证书（825 天，SAN 含主机名与全部网卡 IP），首次启动自动生成于 `static/data/tls/`。
- **IP 变化**：启动时对比 SAN 集合，变化即用同一 CA 重签服务端证书——客户端**无需重装证书**。
- **端口**：HTTPS 为主服务（`Server.TLS.Port`，默认 8443）；HTTP 端口保留 `/ca.crt` 下载与其余请求的 302 跳转（`HTTPRedirect: false` 可关闭）。
- **Cookie**：TLS 启用时自动附加 `Secure` 标志。
- **首次使用（每台客户端一次性）**：
  1. 浏览器访问 `http://<服务器IP>:8000/ca.crt` 下载证书；
  2. 双击安装到「受信任的根证书颁发机构」，重启浏览器；
  3. 之后访问 `https://<服务器IP>:8443` 无告警。Android 同理（设置→安全→加密和凭据→安装证书）。
- **局限（内网固有限制）**：没有公共 CA，信任靠手动安装自签证书；HTTP 端口若保留则该端口仍为明文（仅承载跳转与公开的 CA 证书）。

## 7. 服务器 IP 变化的应对

| 手段 | 说明 | 谁来做 |
|------|------|--------|
| 路由器 DHCP 静态绑定（**根治**） | 管理页里把服务器 MAC 绑定固定 IP，一次配置永久生效 | 需用户在路由器配置 |
| 服务器设静态 IP | 网卡属性手动指定 | 需用户配置 |
| 证书自动重签 | IP 变化后重启服务即更新 SAN，客户端零操作 | 已实现 |
| mDNS（`Server.MDNS: true`） | 广播 `<主机名>.local`，Win10+ 浏览器可解析；Android 支持有限 | 已实现（可选） |
| 启动打印全部 IP | 控制台列出当前所有局域网地址 | 已实现 |
| 页面相对路径 | 连上后 IP 变化不影响已打开的会话 | 已实现 |

## 8. 已知残余风险

1. **HTTP 旁路端口仍为明文**：仅承载 302 跳转与公开的 CA 证书下载，可设 `HTTPRedirect: false` 关闭（关闭后新客户端无法便捷下载 CA）。
2. **自签信任依赖手动安装**：内网无公共 CA，每台客户端首次需手动信任；若服务器主机名/部署名变更导致 CA 重建，需重新安装。
3. **logout 不吊销令牌**：无状态令牌保留至过期；如需立即吊销要引入服务端会话表。
4. `util/auth.go` 仍含硬编码 JWT 密钥（未被引用），启用前必须改为从配置/环境变量读取。
5. `config.yml` 中遗留明文 MySQL 凭据（未被引用），建议删除或迁移到环境变量。
6. **下载/WS 的 `?token=` 会进访问日志**：gin.Logger 会把含令牌的完整 URL 打到控制台。与 WS 既有机制一致的折衷；如需消除需引入一次性签名 URL。
