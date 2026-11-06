package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SessionManager 签发与校验无状态会话令牌：
//
//	token = base64url(nonce) + "." + expUnix + "." + base64url(HMAC-SHA256(secret, nonce|exp))
//
// secret 持久化在数据目录，服务重启后会话不失效。
type SessionManager struct {
	secret  []byte
	ttl     time.Duration
	cookie  string
	storage string
	created bool // 本次启动新生成了密钥：旧令牌将全部失效
}

// ErrSession 无效/过期令牌的统一错误。
var ErrSession = errors.New("invalid session")

// NewSessionManager 加载（或生成）签名密钥。
func NewSessionManager(secretPath string, ttl time.Duration) (*SessionManager, error) {
	secret, created, err := loadOrCreateSecret(secretPath)
	if err != nil {
		return nil, err
	}
	return &SessionManager{
		secret:  secret,
		ttl:     ttl,
		cookie:  "toolan_session",
		storage: secretPath,
		created: created,
	}, nil
}

// JustCreated 报告密钥是否为本次启动新生成（true 意味着旧令牌全部失效，客户端需重新登录）。
func (s *SessionManager) JustCreated() bool { return s.created }

// CookieName 返回会话 Cookie 名。
func (s *SessionManager) CookieName() string { return s.cookie }

// TTL 返回会话有效期。
func (s *SessionManager) TTL() time.Duration { return s.ttl }

// Issue 为一次登录签发令牌，返回令牌文本与过期时间。
func (s *SessionManager) Issue() (token string, exp time.Time, err error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	exp = time.Now().Add(s.ttl).Truncate(time.Second)
	raw := fmt.Sprintf("%s|%d", base64.RawURLEncoding.EncodeToString(nonce), exp.Unix())
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(raw))
	token = base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(exp.Unix(), 10) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token, exp, nil
}

// Verify 校验令牌签名与有效期。
func (s *SessionManager) Verify(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(nonce) != 16 {
		return false
	}
	expUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix() > expUnix {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(parts[0] + "|" + parts[1]))
	return subtle.ConstantTimeCompare(sig, mac.Sum(nil)) == 1
}

// CheckPassword 以恒定时间比较口令，避免时序侧信道。
func (s *SessionManager) CheckPassword(input, real string) bool {
	a := sha256.Sum256([]byte(input))
	b := sha256.Sum256([]byte(real))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func loadOrCreateSecret(path string) ([]byte, bool, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 64 {
		if secret, err := hexOrRaw(data); err == nil {
			return secret, false, nil
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, false, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, false, fmt.Errorf("创建会话密钥目录失败: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(secret))
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return nil, false, fmt.Errorf("写入会话密钥失败: %w", err)
	}
	return secret, true, nil
}

func hexOrRaw(data []byte) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(data) == 32 {
		return data, nil
	}
	return nil, errors.New("bad secret length")
}
