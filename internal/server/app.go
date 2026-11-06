package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"BackEnd/internal/clipboard"
	"BackEnd/internal/messages"
	"BackEnd/internal/reminders"
	"BackEnd/internal/security"
	"BackEnd/internal/storage"
	"BackEnd/internal/ws"

	"github.com/gin-gonic/gin"
)

// maxTextLength 限制消息/通知/剪贴板/提醒的文本长度，防止内存滥用。
const maxTextLength = 100_000

// App owns the HTTP router and shared services.
type App struct {
	router     *gin.Engine
	files      *storage.FileService
	messages   *messages.Store
	reminders  *reminders.Store
	clipboard  *clipboard.Store
	hub        *ws.Hub
	guard      *security.Guard
	cfg        security.Config
	cipher     security.Cipher  // 应用层加密（A1）；nil 表示未启用，全部流量明文
	syncTokens *syncTokenStore  // 上传同步邀请的一次性下载凭证（ftoken）
	caPEM      []byte           // TLS 启用时非空：供客户端下载安装的 CA 证书
	tlsCert    *tls.Certificate // TLS 启用时非空：服务端证书
}

// wsNotificationPayload is the Android-facing notification payload.
// msg and content intentionally carry the same value: msg is convenient for Android
// notification code, while content keeps the current browser client compatible.
type wsNotificationPayload struct {
	Source     string     `json:"source"`
	Title      string     `json:"title"`
	Msg        string     `json:"msg"`
	Content    string     `json:"content"`
	Time       time.Time  `json:"time"`
	ReminderID string     `json:"reminderId,omitempty"`
	RemindAt   *time.Time `json:"remindAt,omitempty"`
}

// New wires storage, persistence, security and routes for the backend.
func New(staticRoot string, cfg security.Config) (*App, error) {
	gin.SetMode(gin.ReleaseMode)

	sessions, err := security.NewSessionManager(filepath.Join(staticRoot, "data", "session.key"), time.Duration(cfg.SessionTTLHours)*time.Hour)
	if err != nil {
		return nil, err
	}
	if sessions.JustCreated() {
		fmt.Println("[security] 已生成新的会话密钥（static/data/session.key）：此前签发的登录令牌全部失效，所有客户端需重新登录。")
		fmt.Println("[security] 提示：请勿删除 static/data 目录，否则每次重启都会导致全部设备掉线。")
	}

	fileService, err := storage.NewFileService(staticRoot)
	if err != nil {
		return nil, err
	}
	messageStore, err := messages.NewStore(filepath.Join(staticRoot, "data", "messages.json"))
	if err != nil {
		return nil, err
	}
	reminderStore, err := reminders.NewStore(filepath.Join(staticRoot, "data", "reminders.json"))
	if err != nil {
		return nil, err
	}
	clipboardStore, err := clipboard.NewStore(filepath.Join(staticRoot, "data", "clipboard.json"))
	if err != nil {
		return nil, err
	}

	hub := ws.NewHub()
	hub.MaxClients = cfg.MaxWSClients
	hub.AllowedHosts = cfg.ExtraAllowedHosts

	// 应用层加密：CryptoEnabled 时构造 A1 加密器（密钥格式已在 Load 阶段校验）。
	var cipher security.Cipher
	if cfg.CryptoEnabled {
		c, err := security.NewA1Cipher(cfg.CryptoKey)
		if err != nil {
			return nil, fmt.Errorf("初始化应用层加密失败: %w", err)
		}
		cipher = c
		hub.Cipher = c
		fmt.Println("[security] 应用层加密已启用（A1）：客户端经 X-Toolan-Crypto / ?crypto= 协商加密通道")
	}

	router := gin.New()
	router.SetTrustedProxies(nil) // 直接面向局域网客户端，ClientIP 取 RemoteAddr，防止 X-Forwarded-For 伪造绕过限流
	router.Use(gin.Logger(), gin.Recovery())

	app := &App{
		router:     router,
		files:      fileService,
		messages:   messageStore,
		reminders:  reminderStore,
		clipboard:  clipboardStore,
		hub:        hub,
		guard:      security.NewGuard(sessions, cfg.RatePerMinute, cfg.LoginMaxFails, cfg.LoginLockMinutes, cfg.AuthEnabled, cfg.CryptoVerifyPerMinute),
		cfg:        cfg,
		cipher:     cipher,
		syncTokens: newSyncTokenStore(),
	}

	if cfg.TLSEnabled {
		hostname, _ := os.Hostname()
		ips, err := security.LocalAddresses(true)
		if err != nil {
			return nil, fmt.Errorf("枚举本机地址失败: %w", err)
		}
		manager := security.NewTLSManager(filepath.Join(staticRoot, "data", "tls"))
		caPEM, cert, err := manager.Ensure(hostname, ips)
		if err != nil {
			return nil, fmt.Errorf("生成 TLS 证书失败: %w", err)
		}
		app.caPEM = caPEM
		app.tlsCert = &cert
	}

	app.registerRoutes(staticRoot)
	app.startReminderWorker()
	return app, nil
}

// Run 启动服务。TLS 启用时同一端口同时承载 HTTPS 与 HTTP：
// 按连接首字节分流，浏览器（已装 CA）走加密，手机 WebView 等
// 无法信任自签证书的客户端仍可明文访问；页面内 gate.js 会探测
// HTTPS 可达后自动把浏览器升级到加密连接。
func (a *App) Run() error {
	addr := fmt.Sprintf("%s:%d", a.cfg.Host, a.cfg.Port)

	if !a.cfg.TLSEnabled || a.tlsCert == nil {
		srv := &http.Server{
			Addr:              addr,
			Handler:           a.router,
			ReadHeaderTimeout: 10 * time.Second, // Slowloris 防护
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    8 << 10,
			// ReadTimeout/WriteTimeout 不设：允许大文件慢速上传/下载，
			// 上传体积由 MaxBytesReader 限制，请求头阶段由 ReadHeaderTimeout 限时。
		}
		return srv.ListenAndServe()
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*a.tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	return serveDual(addr, a.router, tlsCfg)
}

// serverInfo 处理服务发现请求（HTTP/HTTPS 同端口皆可达）。
func (a *App) serverInfo(c *gin.Context) {
	c.JSON(http.StatusOK, a.serverInfoData(c.Request.Host, c.Request.TLS != nil))
}

// serverInfoData 返回服务发现元数据；scheme 按当前连接的实际协议报告。
func (a *App) serverInfoData(host string, isTLS bool) gin.H {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	return gin.H{
		"app":              "TOOLAN",
		"name":             "TOOLAN Gin BackEnd",
		"serverKind":       "TOOLAN_GIN_BACKEND",
		"protocol":         "toolan-gin-ws-v1",
		"version":          "gin-ws",
		"scheme":           scheme,
		"port":             requestPort(host),
		"tls":              isTLS,
		"wsPath":           "/ws",
		"notifyPath":       "/notify",
		"notificationPush": true,
		"auth":             true,
		"crypto":           gin.H{"enabled": a.cipher != nil, "modes": []string{security.A1Version}},
		"events":           []string{"message", "notification", "reminder.due", "file.sync_offer"},
	}
}

func (a *App) registerRoutes(staticRoot string) {
	r := a.router
	r.Use(security.SecurityHeaders())
	// ---- 公开：登录页与会话探测脚本 ----
	r.GET("/login", security.PageCSP(), func(c *gin.Context) {
		c.File(filepath.Join(staticRoot, "login.html"))
	})
	r.GET("/gate.js", func(c *gin.Context) {
		c.File(filepath.Join(staticRoot, "gate.js"))
	})
	r.GET("/toolan-crypto.js", func(c *gin.Context) {
		c.File(filepath.Join(staticRoot, "toolan-crypto.js"))
	})

	// CA 证书下载（公开）：HTTPS 启用时供客户端安装信任，之后即可免告警访问。
	if a.caPEM != nil {
		r.GET("/ca.crt", func(c *gin.Context) {
			c.Header("Content-Type", "application/x-x509-ca-cert")
			c.Header("Content-Disposition", "inline; filename=toolan-root-ca.crt")
			c.Data(http.StatusOK, "application/x-x509-ca-cert", a.caPEM)
		})
	}

	// ---- 页面外壳同样要求登录：未登录由服务端 302 到 /login，
	// 避免旧的浏览器缓存页面停留在"有壳无数据"的空白状态 ----
	pages := r.Group("/")
	pages.Use(a.guard.RequireAuth(), security.PageCSP())
	pages.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(staticRoot, "index.html"))
	})
	pages.GET("/store", func(c *gin.Context) {
		c.File(filepath.Join(staticRoot, "store.html"))
	})

	// ---- 认证接口本身不限内容，但限速 + 锁定检查；登录请求同样可走加密通道，
	// 密码不再明文传播 ----
	r.POST("/api/auth/login", security.CryptoLayer(a.cipher), a.guard.CheckLoginLocked(), a.guard.RateLimit(), a.login)
	r.GET("/api/auth/status", a.authStatus)
	// 回传当前会话令牌给页面 JS：移动端 WebView 的下载会转交系统下载器（不带 Cookie），
	// 前端需要把令牌拼在下载 URL 上，而令牌存于 HttpOnly Cookie 页面读不到，只能由此取回。
	r.GET("/api/auth/token", a.guard.RequireAuth(), a.authToken)
	r.POST("/api/auth/logout", a.logout)

	// 密钥一致性验证：客户端发送 A1 密文质询，服务端能解开即密钥一致。
	// 独立限流（默认 6 次/分/IP）+ 失败锁定，防密钥爆破。
	r.POST("/api/crypto/verify", a.guard.CheckCryptoLocked(), a.guard.CryptoRateLimit(), a.verifyCrypto)

	// 服务元信息不含敏感数据，公开给客户端发现端口与 ws 路径。
	r.GET("/server_info", a.serverInfo)

	// 凭 ftoken 下载同步邀请的文件：凭证即授权，不要求会话（详见 sync_token.go），
	// 保留加密协商、限流与禁缓存。
	r.GET("/api/sync/file", security.CryptoLayer(a.cipher), a.guard.RateLimit(), security.NoStore(), a.syncFileDownload)

	// ---- 受保护：数据 API（需会话，限速，禁缓存；CryptoLayer 在最外层，
	// 加密客户端的请求体/JSON 响应与流式端点在此统一协商） ----
	api := r.Group("/")
	api.Use(security.CryptoLayer(a.cipher), a.guard.RequireAuth(), a.guard.RateLimit(), security.NoStore())

	// POST /upload saves one multipart file. Images go to static/images; videos and other files go to static/files.
	// 携带 X-Toolan-Crypto 头时走加密分块上传（meta + chunk 信封段）。
	// ?sync=1 上传成功后向安卓端推送同步邀请；同名文件默认 409，?overwrite=1 显式覆盖。
	api.POST("/upload", security.MaxBody(int64(a.cfg.MaxUploadMB)<<20), a.uploadFile)

	// POST /api/upload/check 预检同名冲突（无磁盘副作用），供大文件先确认再上传。
	api.POST("/api/upload/check", a.uploadCheck)

	// GET /api/download streams one stored file; encrypted clients receive an A1L stream.
	api.GET("/api/download", a.downloadFile)

	// GET /api/list returns files for type=image|video|file with sort=name|createdAt|size|type and order=asc|desc.
	api.GET("/api/list", a.listFiles)

	// DELETE /api/items deletes selected items from the matching static folder.
	api.DELETE("/api/items", a.deleteItems)

	// POST /api/zip streams the selected items as a single zip archive for batch download.
	api.POST("/api/zip", a.zipItems)

	// GET /api/zip/entries lists file entries inside a stored zip for in-page browsing.
	api.GET("/api/zip/entries", a.zipEntries)

	// GET /api/zip/file streams one decompressed entry from a stored zip (inline preview).
	api.GET("/api/zip/file", a.zipEntryFile)

	// POST /api/folder creates a (possibly nested) folder inside the given partition.
	api.POST("/api/folder", a.createFolder)

	// DELETE /api/folder removes an empty folder.
	api.DELETE("/api/folder", a.deleteFolder)

	// POST /api/folder/rename renames or relocates a whole folder subtree.
	api.POST("/api/folder/rename", a.renameFolder)

	// POST /api/items/move moves selected files into a target folder.
	api.POST("/api/items/move", a.moveItems)

	// POST /api/item/rename renames a single file, keeping its folder and extension.
	api.POST("/api/item/rename", a.renameItem)

	// GET /messages keeps the legacy browser API and returns persisted messages.
	api.GET("/messages", a.listMessages)

	// POST /message stores a message and broadcasts it to websocket clients.
	api.POST("/message", a.createMessage)

	// DELETE /message/:index removes a legacy message by list index.
	api.DELETE("/message/:index", a.deleteMessage)

	// POST /notify stores a message, optionally raises a Windows toast, and broadcasts it through /ws.
	api.POST("/notify", a.notify)

	// GET /api/reminders returns date reminders. Query includeDone=true also returns completed reminders.
	api.GET("/api/reminders", a.listReminders)

	// POST /api/reminders creates a persisted date reminder.
	api.POST("/api/reminders", a.createReminder)

	// PATCH /api/reminders/:id updates the done flag for one reminder.
	api.PATCH("/api/reminders/:id", a.updateReminder)

	// DELETE /api/reminders/:id removes one reminder.
	api.DELETE("/api/reminders/:id", a.deleteReminder)

	// GET /api/clipboard returns the shared clipboard history (newest last).
	api.GET("/api/clipboard", a.listClipboard)

	// POST /api/clipboard stores a shared clip and broadcasts it to websocket clients.
	api.POST("/api/clipboard", a.createClipboard)

	// DELETE /api/clipboard/:id removes one clip from the shared clipboard.
	api.DELETE("/api/clipboard/:id", a.deleteClipboard)

	// DELETE /api/clipboard clears the whole shared clipboard history.
	api.DELETE("/api/clipboard", a.clearClipboard)

	// GET /ws upgrades to websocket. Android can subscribe here for message/reminder events.
	// 浏览器经 Cookie 认证；原生客户端可用 Authorization 或 ?token=。
	api.GET("/ws", a.hub.Handle)

	// ---- 受保护：用户上传的静态内容（需会话 + CSP sandbox 防存储型 XSS） ----
	media := r.Group("/")
	media.Use(a.guard.RequireAuth(), security.UploadedContent())
	media.Static("/static/images", filepath.Join(staticRoot, "images"))
	media.Static("/static/files", filepath.Join(staticRoot, "files"))
	media.StaticFile("/static/favicon.ico", filepath.Join(staticRoot, "favicon.ico"))
}

// ---- 认证处理 ----

func (a *App) login(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if !a.guard.Sessions.CheckPassword(req.Password, a.cfg.Password) {
		a.guard.RecordLoginResult(c, false)
		fmt.Printf("[security] 登录失败 ip=%s time=%s\n", c.ClientIP(), time.Now().Format(time.RFC3339))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}
	a.guard.RecordLoginResult(c, true)

	token, exp, err := a.guard.Sessions.Issue()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发会话失败"})
		return
	}
	// HttpOnly 防 XSS 读取；SameSite=Strict 阻断跨站请求携带 Cookie（CSRF）。
	// TLS 连接上加 Secure 标志；明文连接（手机等兼容客户端）不加，否则会话无法维持。
	secure := c.Request.TLS != nil
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(a.guard.Sessions.CookieName(), token, int(a.guard.Sessions.TTL().Seconds()), "/", "", secure, true)
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"token":     token,
		"expiresAt": exp.Unix(),
	})
}

func (a *App) authStatus(c *gin.Context) {
	// 鉴权总开关关闭时永远报告已登录，避免前端 gate.js 把用户踢到登录页。
	if !a.cfg.AuthEnabled {
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
		return
	}
	token := security.TokenFromRequest(c, a.guard.Sessions.CookieName())
	c.JSON(http.StatusOK, gin.H{"authenticated": token != "" && a.guard.Sessions.Verify(token)})
}

// authToken 回传当前有效会话令牌（RequireAuth 已完成校验），供前端拼接下载 URL。
func (a *App) authToken(c *gin.Context) {
	token := security.TokenFromRequest(c, a.guard.Sessions.CookieName())
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (a *App) logout(c *gin.Context) {
	// 无状态令牌：清 Cookie 即可，令牌保留至自然过期。
	secure := c.Request.TLS != nil
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(a.guard.Sessions.CookieName(), "", -1, "/", "", secure, true)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) uploadFile(c *gin.Context) {
	overwrite := c.Query("overwrite") == "1"
	syncOffer := c.Query("sync") == "1"

	// 加密客户端（携带 X-Toolan-Crypto 头）：multipart 内是 meta + chunk 信封段。
	if a.cipher != nil && c.GetBool("cryptoRequest") {
		if err := a.uploadEncrypted(c, overwrite, syncOffer); err != nil {
			if errors.Is(err, storage.ErrFileExists) {
				c.JSON(http.StatusConflict, gin.H{"error": storage.ErrFileExists.Error(), "code": "file_exists"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		if isBodyTooLarge(err) {
			c.Header("Retry-After", "0")
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "文件超出大小限制"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到上传文件"})
		return
	}

	folder := c.PostForm("folder")
	savePath, kind, isImage, relPath, err := a.files.ResolveUploadTarget(file.Filename, folder)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !overwrite {
		if _, statErr := os.Stat(savePath); statErr == nil {
			c.JSON(http.StatusConflict, gin.H{"error": storage.ErrFileExists.Error(), "code": "file_exists", "path": relPath})
			return
		}
	}
	if err := a.files.EnsureUploadDir(savePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}
	if err := saveMultipartAtomic(file, savePath); err != nil {
		if isBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "文件超出大小限制"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}

	a.files.RecordUploadMetadata(kind, relPath)
	a.respondUploaded(c, kind, relPath, folder, isImage, file.Size, syncOffer)
}

// saveMultipartAtomic 先写 .part 临时文件再原子改名：上传中途断连不会截断旧文件。
func saveMultipartAtomic(file *multipart.FileHeader, savePath string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(savePath+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(savePath + ".part")
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(savePath + ".part")
		return err
	}
	return os.Rename(savePath+".part", savePath)
}

// respondUploaded 输出上传成功响应；syncOffer 时向安卓端定向推送 file.sync_offer，
// delivered 为送达的客户端数（0=无手机在线，前端据此提示）。
func (a *App) respondUploaded(c *gin.Context, kind, relPath, folder string, isImage bool, size int64, syncOffer bool) {
	delivered := 0
	if syncOffer {
		delivered = a.pushSyncOffer(kind, relPath, size)
	}
	prefix := "/static/files/"
	if isImage {
		prefix = "/static/images/"
	}
	c.JSON(http.StatusOK, gin.H{
		"message":   "上传成功",
		"url":       prefix + relPath,
		"path":      relPath,
		"folder":    folder,
		"type":      isImage,
		"kind":      kind,
		"sync":      syncOffer,
		"delivered": delivered,
	})
}

// maxUploadEnvelope 限制单个 multipart 信封段的读取量：上传分块为 4MB 明文，
// base64 编码后约 5.4MB，8MB 上限留足余量。
const maxUploadEnvelope = 8 << 20

// uploadEncrypted 处理加密分块上传：multipart 依次携带 name="meta"（A1 信封包裹
// StreamMeta：文件名/MIME/大小/目标文件夹）与若干 name="chunk"（A1 信封包裹数据块）。
// 逐段流式解密写入 .part 临时文件，全部完成后原子改名为目标路径。
func (a *App) uploadEncrypted(c *gin.Context, overwrite, syncOffer bool) error {
	mr, err := c.Request.MultipartReader()
	if err != nil {
		if isBodyTooLarge(err) {
			return errors.New("文件超出大小限制")
		}
		return fmt.Errorf("读取上传内容失败: %w", err)
	}

	var (
		meta     *security.StreamMeta
		savePath string
		kind     string
		isImage  bool
		relPath  string
		tmp      *os.File
		written  int64
	)
	success := false
	defer func() {
		if !success {
			if tmp != nil {
				_ = tmp.Close()
			}
			if savePath != "" {
				_ = os.Remove(savePath + ".part")
			}
		}
	}()

	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			if isBodyTooLarge(perr) {
				return errors.New("文件超出大小限制")
			}
			return fmt.Errorf("读取上传段失败: %w", perr)
		}
		body, rerr := io.ReadAll(io.LimitReader(part, maxUploadEnvelope))
		_ = part.Close()
		if rerr != nil {
			return fmt.Errorf("读取上传段内容失败: %w", rerr)
		}

		switch part.FormName() {
		case "meta":
			if meta != nil {
				return errors.New("重复的 meta 段")
			}
			plain, derr := a.cipher.Decrypt(string(body))
			if derr != nil {
				return fmt.Errorf("meta 解密失败：%s", derr.Error())
			}
			var m security.StreamMeta
			if jerr := json.Unmarshal(plain, &m); jerr != nil {
				return errors.New("meta 格式错误")
			}
			if strings.TrimSpace(m.Name) == "" {
				return errors.New("上传文件名为空")
			}
			sp, k, img, rp, terr := a.files.ResolveUploadTarget(m.Name, m.Folder)
			if terr != nil {
				return terr
			}
			if !overwrite {
				if _, serr := os.Stat(sp); serr == nil {
					return storage.ErrFileExists
				}
			}
			if derr := a.files.EnsureUploadDir(sp); derr != nil {
				return derr
			}
			f, ferr := os.Create(sp + ".part")
			if ferr != nil {
				return ferr
			}
			meta, savePath, kind, isImage, relPath, tmp = &m, sp, k, img, rp, f
		case "chunk":
			if tmp == nil {
				return errors.New("数据块先于 meta 段")
			}
			plain, derr := a.cipher.Decrypt(string(body))
			if derr != nil {
				return fmt.Errorf("数据块解密失败：%s", derr.Error())
			}
			if _, werr := tmp.Write(plain); werr != nil {
				return werr
			}
			written += int64(len(plain))
		}
	}

	if tmp == nil || meta == nil {
		return errors.New("缺少 meta 段")
	}
	if meta.Size > 0 && written != meta.Size {
		return fmt.Errorf("上传不完整：期望 %d 字节，实际收到 %d 字节", meta.Size, written)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(savePath+".part", savePath); err != nil {
		return err
	}
	success = true

	a.files.RecordUploadMetadata(kind, relPath)
	size := meta.Size
	if info, serr := os.Stat(savePath); serr == nil {
		size = info.Size()
	}
	a.respondUploaded(c, kind, relPath, meta.Folder, isImage, size, syncOffer)
	return nil
}

// verifyCrypto 验证客户端密钥与服务端一致：客户端发送 A1 信封包裹的
// {"nonce":"随机值"}，服务端能解开并在响应中回传 nonce 即证明一致。
// 失败计数与独立限流由路由中间件（CheckCryptoLocked/CryptoRateLimit）承担。
func (a *App) verifyCrypto(c *gin.Context) {
	if a.cipher == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"enabled": false, "error": "服务端未启用应用层加密"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "读取请求失败"})
		return
	}

	reject := func() {
		a.guard.RecordCryptoResult(c, false)
		fmt.Printf("[security] 密钥验证失败 ip=%s time=%s\n", c.ClientIP(), time.Now().Format(time.RFC3339))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密钥不一致或密文无效"})
	}

	if !security.LooksEncrypted(string(body)) {
		reject()
		return
	}
	plain, derr := a.cipher.Decrypt(string(body))
	if derr != nil {
		reject()
		return
	}
	var req struct {
		Nonce string `json:"nonce"`
	}
	if jerr := json.Unmarshal(plain, &req); jerr != nil || strings.TrimSpace(req.Nonce) == "" {
		reject()
		return
	}

	a.guard.RecordCryptoResult(c, true)
	payload, _ := json.Marshal(gin.H{"success": true, "mode": security.A1Version, "nonce": req.Nonce})
	if env, eerr := a.cipher.Encrypt(payload); eerr == nil {
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(env))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "mode": security.A1Version, "nonce": req.Nonce})
}

// downloadFile 按分区与相对路径流式返回单个文件；加密客户端收到 A1L 流
// （首行 meta 信封 + 逐块数据信封）。GET /api/download?type=file&path=a/b.png
func (a *App) downloadFile(c *gin.Context) {
	kind := c.Query("type")
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未指定文件"})
		return
	}
	f, info, err := a.files.OpenFile(kind, path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a.serveStoredFile(c, f, info)
}

// syncFileDownload 凭 ftoken 下载上传同步邀请中的文件。GET /api/sync/file?ftoken=
// 凭证本身即授权（短时效/限次/仅绑定单文件），路由因此不挂 RequireAuth 而只做限流，
// 移动端无需持有主会话令牌。
func (a *App) syncFileDownload(c *gin.Context) {
	kind, relPath, ok := a.syncTokens.resolve(c.Query("ftoken"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "下载凭证无效或已过期", "code": "ftoken_invalid"})
		return
	}
	f, info, err := a.files.OpenFile(kind, relPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	a.serveStoredFile(c, f, info)
}

// serveStoredFile 按已打开的文件流式输出：加密客户端收 A1L 流，明文走 ServeContent。
func (a *App) serveStoredFile(c *gin.Context, f *os.File, info os.FileInfo) {
	defer f.Close()

	contentType := mime.TypeByExtension(filepath.Ext(info.Name()))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if a.cipher != nil && c.GetBool("cryptoRequest") {
		c.Header("Content-Type", "application/octet-stream")
		c.Header("X-Toolan-Crypto-Stream", "A1L")
		_ = a.cipher.EncryptStream(security.StreamMeta{Name: info.Name(), Mime: contentType, Size: info.Size()}, f, c.Writer)
		return
	}

	c.Header("Content-Type", contentType)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Disposition", "inline; filename="+info.Name())
	http.ServeContent(c.Writer, c.Request, info.Name(), info.ModTime(), f)
}

// uploadCheck 预检上传目标是否已有同名文件：PC 端大文件先问后传，避免整文件传两遍。
// POST {"name":"a.png","folder":"sub"} → {"exists":bool,"kind":..,"path":..,"folder":..}
func (a *App) uploadCheck(c *gin.Context) {
	var req struct {
		Name   string `json:"name"`
		Folder string `json:"folder"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	exists, kind, relPath, err := a.files.UploadTargetExists(req.Name, req.Folder)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exists": exists, "kind": kind, "path": relPath, "folder": req.Folder})
}

func (a *App) listFiles(c *gin.Context) {
	fileType := c.DefaultQuery("type", "image")
	sortBy := c.DefaultQuery("sort", "createdAt")
	order := c.DefaultQuery("order", "desc")
	category := c.DefaultQuery("category", "all")
	folder := c.Query("folder")

	list, folders, err := a.files.List(fileType, sortBy, order, category, folder)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"list": list, "folders": folders, "folder": folder})
}

func (a *App) deleteItems(c *gin.Context) {
	var req struct {
		Type  string   `json:"type"`
		Paths []string `json:"paths"`
		Names []string `json:"names"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	// 兼容旧客户端：优先使用 paths，回退 names。
	targets := req.Paths
	if len(targets) == 0 {
		targets = req.Names
	}
	deleted, failed := a.files.Delete(req.Type, targets)
	c.JSON(http.StatusOK, gin.H{"deleted": deleted, "failed": failed})
}

func (a *App) zipItems(c *gin.Context) {
	kind := ""
	var targets []string

	// 同时支持 JSON（fetch）与表单编码（隐藏 iframe 流式下载，避免大文件缓冲进内存）。
	if strings.HasPrefix(c.GetHeader("Content-Type"), "application/json") {
		var req struct {
			Type  string   `json:"type"`
			Paths []string `json:"paths"`
			Names []string `json:"names"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
			return
		}
		kind = req.Type
		targets = req.Paths
		if len(targets) == 0 {
			targets = req.Names
		}
	} else {
		kind = c.PostForm("type")
		if pathsJSON := c.PostForm("paths"); pathsJSON != "" {
			_ = json.Unmarshal([]byte(pathsJSON), &targets)
		}
		if len(targets) == 0 {
			targets = c.PostFormArray("paths")
		}
	}

	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未选择文件"})
		return
	}

	filename := "TOOLAN_" + time.Now().Format("20060102_150405") + ".zip"

	// 加密客户端：zip 流经 io.Pipe 接 A1L 逐块加密下发（zip 大小事先未知，meta.size=0）。
	if a.cipher != nil && c.GetBool("cryptoRequest") {
		c.Header("Content-Type", "application/octet-stream")
		c.Header("X-Toolan-Crypto-Stream", "A1L")
		pr, pw := io.Pipe()
		go func() {
			_, err := a.files.WriteZip(kind, targets, pw)
			_ = pw.CloseWithError(err)
		}()
		_ = a.cipher.EncryptStream(security.StreamMeta{Name: filename, Mime: "application/zip"}, pr, c.Writer)
		return
	}

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	added, err := a.files.WriteZip(kind, targets, c.Writer)
	if err != nil && added == 0 {
		// Nothing streamed yet, so a JSON error response is still safe to send.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "打包失败"})
		return
	}
}

// zipEntries 列出某个 zip（相对分区路径）内的文件条目，供前端浏览压缩包内容。
// GET /api/zip/entries?type=file&path=xxx.zip
func (a *App) zipEntries(c *gin.Context) {
	kind := c.Query("type")
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未指定压缩包"})
		return
	}
	entries, err := a.files.ZipEntries(kind, path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// zipEntryFile 流式返回 zip 内某个条目的解压内容（inline），前端据此复用现有预览逻辑。
// GET /api/zip/file?type=file&path=xxx.zip&entry=inner/a.png
func (a *App) zipEntryFile(c *gin.Context) {
	kind := c.Query("type")
	path := strings.TrimSpace(c.Query("path"))
	entry := c.Query("entry")
	zr, rc, info, err := a.files.OpenZipEntry(kind, path, entry)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer zr.Close()
	defer rc.Close()

	contentType := mime.TypeByExtension(filepath.Ext(info.Name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// 加密客户端：条目内容走 A1L 流（大小已知，解密侧做完整性校验）。
	if a.cipher != nil && c.GetBool("cryptoRequest") {
		c.Header("Content-Type", "application/octet-stream")
		c.Header("X-Toolan-Crypto-Stream", "A1L")
		_ = a.cipher.EncryptStream(security.StreamMeta{Name: info.Name, Mime: contentType, Size: info.Size}, rc, c.Writer)
		return
	}

	c.Header("Content-Type", contentType)
	c.Header("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(c.Writer, rc)
}

func (a *App) createFolder(c *gin.Context) {
	var req struct {
		Type   string `json:"type"`
		Folder string `json:"folder"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if err := a.files.CreateFolder(req.Type, req.Folder); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) deleteFolder(c *gin.Context) {
	var req struct {
		Type   string `json:"type"`
		Folder string `json:"folder"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if err := a.files.DeleteFolder(req.Type, req.Folder); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) renameFolder(c *gin.Context) {
	var req struct {
		Type string `json:"type"`
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if err := a.files.RenameFolder(req.Type, req.From, req.To); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) moveItems(c *gin.Context) {
	var req struct {
		Type     string   `json:"type"`
		Paths    []string `json:"paths"`
		ToFolder string   `json:"toFolder"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if len(req.Paths) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未选择文件"})
		return
	}
	moved, failed := a.files.MoveItems(req.Type, req.Paths, req.ToFolder)
	c.JSON(http.StatusOK, gin.H{"moved": moved, "failed": failed})
}

func (a *App) renameItem(c *gin.Context) {
	var req struct {
		Type string `json:"type"`
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	if strings.TrimSpace(req.Path) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未选择文件"})
		return
	}
	newRel, err := a.files.RenameItem(req.Type, req.Path, req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "path": newRel, "name": filepath.Base(newRel)})
}

func (a *App) listMessages(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"messages": a.messages.List()})
}

func (a *App) createMessage(c *gin.Context) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容不能为空"})
		return
	}
	if textTooLong(req.Content) || textTooLong(req.Title) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容过长"})
		return
	}

	msg, err := a.messages.Add(req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("message", messagePayload(msg, "message"))
	c.JSON(http.StatusOK, gin.H{"success": true, "message": msg})
}

func (a *App) deleteMessage(c *gin.Context) {
	index, err := strconv.Atoi(c.Param("index"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return
	}
	if err := a.messages.Delete(index); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) notify(c *gin.Context) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容不能为空"})
		return
	}
	if textTooLong(req.Content) || textTooLong(req.Title) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容过长"})
		return
	}
	if runtime.GOOS == "windows" {
		_ = sendWindowsNotification(req.Title, req.Content)
	}
	msg, err := a.messages.Add(req.Title, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("notification", messagePayload(msg, "notification"))
	c.JSON(http.StatusOK, gin.H{"success": true, "message": msg})
}

func (a *App) listReminders(c *gin.Context) {
	includeDone := c.Query("includeDone") == "true"
	c.JSON(http.StatusOK, gin.H{"list": a.reminders.List(includeDone)})
}

func (a *App) createReminder(c *gin.Context) {
	var req struct {
		Title    string `json:"title"`
		Content  string `json:"content"`
		RemindAt string `json:"remindAt"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	remindAt, err := parseClientTime(req.RemindAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "提醒时间格式错误"})
		return
	}
	if strings.TrimSpace(req.Title) == "" && strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "标题或内容不能为空"})
		return
	}
	if textTooLong(req.Content) || textTooLong(req.Title) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容过长"})
		return
	}

	item, err := a.reminders.Add(req.Title, req.Content, remindAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("reminder.created", item)
	c.JSON(http.StatusOK, gin.H{"success": true, "reminder": item})
}

func (a *App) updateReminder(c *gin.Context) {
	var req struct {
		Done bool `json:"done"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	item, err := a.reminders.SetDone(c.Param("id"), req.Done)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("reminder.updated", item)
	c.JSON(http.StatusOK, gin.H{"success": true, "reminder": item})
}

func (a *App) deleteReminder(c *gin.Context) {
	if err := a.reminders.Delete(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("reminder.deleted", gin.H{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) listClipboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"clips": a.clipboard.List()})
}

func (a *App) createClipboard(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容不能为空"})
		return
	}
	if textTooLong(req.Content) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "内容过长"})
		return
	}

	clip, err := a.clipboard.Add(req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("clipboard", clip)
	c.JSON(http.StatusOK, gin.H{"success": true, "clip": clip})
}

func (a *App) deleteClipboard(c *gin.Context) {
	if err := a.clipboard.Delete(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("clipboard.deleted", gin.H{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) clearClipboard(c *gin.Context) {
	if err := a.clipboard.Clear(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	a.hub.Send("clipboard.cleared", gin.H{})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *App) startReminderWorker() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		a.publishDueReminders()
		for range ticker.C {
			a.publishDueReminders()
		}
	}()
}

func (a *App) publishDueReminders() {
	now := time.Now()
	for _, item := range a.reminders.Due(now) {
		payload := reminderDuePayload(item, now)
		a.hub.Send("reminder.due", payload)
		if runtime.GOOS == "windows" {
			_ = sendWindowsNotification(payload.Title, payload.Msg)
		}
		_, _ = a.reminders.MarkNotified(item.ID, now)
	}
}

func messagePayload(msg messages.Message, source string) wsNotificationPayload {
	return wsNotificationPayload{
		Source:  source,
		Title:   defaultString(msg.Title, "消息"),
		Msg:     msg.Content,
		Content: msg.Content,
		Time:    msg.Time,
	}
}

func reminderDuePayload(item reminders.Reminder, eventTime time.Time) wsNotificationPayload {
	msg := strings.TrimSpace(item.Content)
	if msg == "" {
		msg = strings.TrimSpace(item.Title)
	}
	if msg == "" {
		msg = "日期提醒已到期"
	}
	remindAt := item.RemindAt
	return wsNotificationPayload{
		Source:     "reminder",
		Title:      formatReminderDueTitle(item.RemindAt),
		Msg:        msg,
		Content:    msg,
		Time:       eventTime,
		ReminderID: item.ID,
		RemindAt:   &remindAt,
	}
}

func formatReminderDueTitle(value time.Time) string {
	return fmt.Sprintf("%d.%d.%d 到了", value.Year(), value.Month(), value.Day())
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func requestPort(host string) int {
	if idx := strings.LastIndex(host, ":"); idx >= 0 && idx < len(host)-1 {
		if port, err := strconv.Atoi(host[idx+1:]); err == nil {
			return port
		}
	}
	return 8000
}

// isBodyTooLarge 识别 http.MaxBytesReader 触发的超限错误（部分调用链不保留错误类型，需兜底匹配文本）。
func isBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return true
	}
	return strings.Contains(err.Error(), "request body too large")
}

// textTooLong 报告文本是否超过统一上限。
func textTooLong(value string) bool {
	return len(value) > maxTextLength
}

func parseClientTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time")
}

func sendWindowsNotification(title string, message string) error {
	title = escapePowerShellString(title)
	message = escapePowerShellString(message)
	ps := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
$xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode('%s')) > $null
$xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode('%s')) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('BackEnd Store')
$notifier.Show($toast)
`, title, message)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
	return cmd.Run()
}

func escapePowerShellString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
