package security

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Guard 聚合认证与限流组件，供路由中间件使用。
type Guard struct {
	Sessions    *SessionManager
	Limiter     *windowLimiter
	Logins      *loginTracker
	AuthEnabled bool // 鉴权总开关：false 时 RequireAuth 直接放行

	// 加密密钥验证接口（/api/crypto/verify）的独立限流与失败锁定，
	// 与登录限流互不影响：verify 是密钥爆破的入口，配额必须更紧。
	CryptoLimiter *windowLimiter
	CryptoFails   *loginTracker
}

// NewGuard 依赖注入各组件。
func NewGuard(sessions *SessionManager, ratePerMinute int, maxFails int, lockMinutes int, authEnabled bool, cryptoVerifyPerMinute int) *Guard {
	return &Guard{
		Sessions:      sessions,
		Limiter:       NewRateLimiter(ratePerMinute, time.Minute),
		Logins:        NewLoginTracker(maxFails, time.Duration(lockMinutes)*time.Minute),
		AuthEnabled:   authEnabled,
		CryptoLimiter: NewRateLimiter(cryptoVerifyPerMinute, time.Minute),
		CryptoFails:   NewLoginTracker(maxFails, time.Duration(lockMinutes)*time.Minute),
	}
}

// TokenFromRequest 依次从 Authorization: Bearer、Cookie、?token= 提取会话令牌。
// ?token= 主要用于无法携带自定义头的 WebSocket 客户端。
func TokenFromRequest(c *gin.Context, cookieName string) string {
	if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if cookie, err := c.Cookie(cookieName); err == nil && cookie != "" {
		return cookie
	}
	return strings.TrimSpace(c.Query("token"))
}

// RequireAuth 未携带有效会话时返回 401，并在 Accept 为 HTML 时引导到登录页。
// AuthEnabled=false（config.yml Security.AuthEnabled: false）时直接放行。
func (g *Guard) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !g.AuthEnabled {
			c.Next()
			return
		}
		token := TokenFromRequest(c, g.Sessions.CookieName())
		if token != "" && g.Sessions.Verify(token) {
			c.Next()
			return
		}
		if strings.Contains(c.GetHeader("Accept"), "text/html") {
			c.Redirect(http.StatusFound, "/login?next="+url.QueryEscape(c.Request.URL.RequestURI()))
			c.Abort()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录或会话已过期"})
	}
}

// RateLimit 每 IP 窗口限流，超限返回 429。
func (g *Guard) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !g.Limiter.Allow(c.ClientIP()) {
			c.Header("Retry-After", "10")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
			return
		}
		c.Next()
	}
}

// CheckLoginLocked 登录接口前置检查：IP 处于锁定期则直接拒绝。
func (g *Guard) CheckLoginLocked() gin.HandlerFunc {
	return func(c *gin.Context) {
		if locked, remain := g.Logins.Locked(c.ClientIP()); locked {
			c.Header("Retry-After", strconv.Itoa(int(remain.Seconds())+1))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "失败次数过多，请稍后再试",
			})
			return
		}
		c.Next()
	}
}

// RecordLoginResult 登录成功/失败后更新失败计数。
func (g *Guard) RecordLoginResult(c *gin.Context, ok bool) {
	if ok {
		g.Logins.Reset(c.ClientIP())
		return
	}
	g.Logins.Fail(c.ClientIP())
}

// CheckCryptoLocked 密钥验证接口前置检查：IP 处于锁定期则直接拒绝。
func (g *Guard) CheckCryptoLocked() gin.HandlerFunc {
	return func(c *gin.Context) {
		if locked, remain := g.CryptoFails.Locked(c.ClientIP()); locked {
			c.Header("Retry-After", strconv.Itoa(int(remain.Seconds())+1))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "验证失败次数过多，请稍后再试",
			})
			return
		}
		c.Next()
	}
}

// CryptoRateLimit 密钥验证接口的独立每 IP 限流（默认 6 次/分），超限返回 429。
func (g *Guard) CryptoRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !g.CryptoLimiter.Allow(c.ClientIP()) {
			c.Header("Retry-After", "10")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "验证过于频繁"})
			return
		}
		c.Next()
	}
}

// RecordCryptoResult 密钥验证成功/失败后更新失败计数（成功清零）。
func (g *Guard) RecordCryptoResult(c *gin.Context, ok bool) {
	if ok {
		g.CryptoFails.Reset(c.ClientIP())
		return
	}
	g.CryptoFails.Fail(c.ClientIP())
}

// ---- 应用层加密（A1/A1L）----

// CryptoHeader 是客户端声明"本次请求走加密通道"的信号头（GET 等无 body
// 请求也靠它要求加密响应）。WebSocket 与系统下载器等无法带头的场景用
// ?crypto=A1 查询参数代替。
const CryptoHeader = "X-Toolan-Crypto"

// maxCryptoBody 限制非 multipart 请求体的解密读取量；JSON 类接口远小于此值。
const maxCryptoBody = 8 << 20

// CryptoLayer 应用层加解密中间件：
//   - 请求侧：带 CryptoHeader 或 body 本身是 A1 信封（且非 multipart）时解密 body，
//     并在上下文标记 cryptoRequest=true，供 verify/download/zip 等 handler 判断
//   - 响应侧：仅当 cryptoRequest=true 且响应为 application/json 时缓冲并整体加密成
//     单段信封文本；流式/文件响应（octet-stream、zip 等）透传，由各 handler 自行
//     使用 EncryptStream 输出 A1L
//
// cipher 为 nil（未启用加密）时完全透传，行为与不加本中间件一致。
func CryptoLayer(cipher Cipher) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cipher == nil {
			c.Next()
			return
		}

		encrypted := c.GetHeader(CryptoHeader) != "" || c.Query("crypto") != ""
		if c.Request.Body != nil && c.Request.ContentLength != 0 &&
			!strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/") {
			body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxCryptoBody))
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "读取请求体失败"})
				return
			}
			if len(body) > 0 && LooksEncrypted(string(body)) {
				plain, derr := cipher.Decrypt(string(body))
				if derr != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "请求解密失败：密钥不正确或数据已损坏"})
					return
				}
				c.Request.Body = io.NopCloser(bytes.NewReader(plain))
				c.Request.ContentLength = int64(len(plain))
				encrypted = true
			} else {
				c.Request.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
		c.Set("cryptoRequest", encrypted)

		cw := &cryptoWriter{ResponseWriter: c.Writer, cipher: cipher, active: encrypted, status: http.StatusOK}
		c.Writer = cw
		c.Next()
		cw.finish()
	}
}

// cryptoWriter 包装 gin.ResponseWriter，把 JSON 响应缓冲后整体加密。
// 非 JSON 内容（流式下载等）在首次写入时切换为透传，行为不变。
type cryptoWriter struct {
	gin.ResponseWriter
	cipher Cipher
	active bool // 请求来自加密客户端

	status      int
	buf         bytes.Buffer
	passthrough bool
}

func (w *cryptoWriter) pending() bool { return w.active && !w.passthrough }

func (w *cryptoWriter) beginPassthrough() {
	if w.passthrough {
		return
	}
	w.passthrough = true
	if !w.ResponseWriter.Written() {
		w.ResponseWriter.WriteHeader(w.status)
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *cryptoWriter) WriteHeader(code int) {
	if w.pending() {
		w.status = code
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cryptoWriter) WriteHeaderNow() {
	if w.pending() {
		return // 状态码延迟到 finish/透传时再下发
	}
	w.ResponseWriter.WriteHeaderNow()
}

func (w *cryptoWriter) Write(data []byte) (int, error) {
	if !w.pending() {
		return w.ResponseWriter.Write(data)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		w.beginPassthrough()
		return w.ResponseWriter.Write(data)
	}
	return w.buf.Write(data)
}

func (w *cryptoWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *cryptoWriter) Written() bool {
	if w.pending() {
		return false
	}
	return w.ResponseWriter.Written()
}

func (w *cryptoWriter) Status() int {
	if w.pending() {
		return w.status
	}
	return w.ResponseWriter.Status()
}

func (w *cryptoWriter) Size() int {
	if w.pending() {
		return w.buf.Len()
	}
	return w.ResponseWriter.Size()
}

func (w *cryptoWriter) Flush() {
	if w.pending() {
		return // JSON 响应本就该小而快，无需分块下发
	}
	w.ResponseWriter.Flush()
}

// finish 在 handler 链结束后下发加密响应；无 JSON body 时仅补发状态码。
func (w *cryptoWriter) finish() {
	if !w.pending() {
		return
	}
	if w.buf.Len() == 0 {
		w.ResponseWriter.WriteHeader(w.status)
		w.ResponseWriter.WriteHeaderNow()
		return
	}
	env, err := w.cipher.Encrypt(w.buf.Bytes())
	if err != nil {
		w.ResponseWriter.Header().Del("Content-Length")
		w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		_, _ = w.ResponseWriter.WriteString(`{"error":"响应加密失败"}`)
		return
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.ResponseWriter.WriteHeader(w.status)
	w.ResponseWriter.WriteHeaderNow()
	_, _ = w.ResponseWriter.WriteString(env)
}

// MaxBody 用 http.MaxBytesReader 限制请求体大小，超出返回 413。
func MaxBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// SecurityHeaders 为所有响应附加基础安全头。
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Next()
	}
}

// PageCSP 面向 HTML 页面的 CSP。
// script-src 需要 'unsafe-eval'：Vue 2 运行时编译模板依赖 new Function，
// 缺失时 Vue 静默吞掉异常并以空渲染函数挂载，页面表现为导航栏以外的整片空白。
func PageCSP() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; "+
				"media-src 'self' blob:; "+
				"connect-src 'self' ws: wss:; "+
				"font-src 'self' data:; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		c.Next()
	}
}

// NoStore 防止敏感 API 数据（消息、剪贴板）落进缓存。
func NoStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Cache-Control", "no-store, max-age=0")
		c.Next()
	}
}

// UploadedContent 对用户上传的静态内容加 CSP sandbox，
// 使上传的 html/svg 等即使被直接打开也无法执行脚本/发请求（防存储型 XSS）。
func UploadedContent() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src data:; media-src data:; style-src 'unsafe-inline'")
		h.Set("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}
