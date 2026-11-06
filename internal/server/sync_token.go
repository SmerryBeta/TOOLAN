package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"mime"
	"path/filepath"
	"sync"
	"time"

	"BackEnd/internal/ws"
)

const (
	// syncTokenTTL 凭证有效期：手机可能锁屏或延迟点"接受"，太短会导致邀请未处理即失效。
	syncTokenTTL = 10 * time.Minute
	// syncTokenMaxUses 单个凭证允许的下载次数：容忍下载中断重试与多台手机各取一份。
	syncTokenMaxUses = 5
	// syncTokenMaxItems 内存凭证条目上限（防御性封顶，达到后按最旧过期时间淘汰）。
	syncTokenMaxItems = 1024
)

// syncTokenEntry 是一条同步下载凭证：仅绑定单一分区相对路径，到期或超次即失效。
type syncTokenEntry struct {
	kind    string
	relPath string
	expires time.Time
	uses    int
}

// syncTokenStore 管理上传同步邀请的下载凭证。纯内存实现：服务重启即全部失效，
// 与凭证本身的短时效属性一致；不落盘也就不存在凭证泄露到备份/日志的持久面。
type syncTokenStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]syncTokenEntry
}

func newSyncTokenStore() *syncTokenStore {
	return &syncTokenStore{ttl: syncTokenTTL, items: map[string]syncTokenEntry{}}
}

// issue 为目标文件签发新凭证；返回空串表示熵源故障，调用方视为推送失败。
func (s *syncTokenStore) issue(kind, relPath string) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	if len(s.items) >= syncTokenMaxItems {
		s.evictOldestLocked()
	}
	s.items[token] = syncTokenEntry{kind: kind, relPath: relPath, expires: time.Now().Add(s.ttl)}
	return token
}

// resolve 校验并核销凭证；未过期且未超次时返回目标文件并计一次使用。
func (s *syncTokenStore) resolve(token string) (kind, relPath string, ok bool) {
	if token == "" {
		return "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.items[token]
	if !exists || time.Now().After(entry.expires) || entry.uses >= syncTokenMaxUses {
		if exists {
			delete(s.items, token)
		}
		return "", "", false
	}
	entry.uses++
	s.items[token] = entry
	return entry.kind, entry.relPath, true
}

// pruneLocked 删除已过期条目（issue/resolve 时顺带清理，无需定时器）。
func (s *syncTokenStore) pruneLocked(now time.Time) {
	for k, v := range s.items {
		if now.After(v.expires) {
			delete(s.items, k)
		}
	}
}

// evictOldestLocked 达到上限时按过期时间最旧淘汰一条。
func (s *syncTokenStore) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	first := true
	for k, v := range s.items {
		if first || v.expires.Before(oldest) {
			oldestKey, oldest, first = k, v.expires, false
		}
	}
	if oldestKey != "" {
		delete(s.items, oldestKey)
	}
}

// wsSyncOfferFile 描述 file.sync_offer 中单个待接收文件。
type wsSyncOfferFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime,omitempty"`
	Kind string `json:"kind"`
	Path string `json:"path"`
	URL  string `json:"url"`
}

// wsSyncOfferPayload 是推送给安卓客户端的同步邀请；URL 为相对路径，
// 客户端用自己配对的服务地址拼接（服务端 IP/协议变化不受影响）。
type wsSyncOfferPayload struct {
	BatchID string          `json:"batchId"`
	Files   []wsSyncOfferFile `json:"files"`
}

// pushSyncOffer 向在线安卓客户端定向推送一次文件同步邀请，返回送达客户端数。
// 无安卓客户端在线时不签发凭证（delivered=0，前端提示手机不在线）。
func (a *App) pushSyncOffer(kind, relPath string, size int64) int {
	if a.hub.CountDevice(ws.DeviceAndroid) == 0 {
		return 0
	}
	token := a.syncTokens.issue(kind, relPath)
	if token == "" {
		return 0
	}

	name := filepath.Base(filepath.FromSlash(relPath))
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0
	}
	payload := wsSyncOfferPayload{
		BatchID: hex.EncodeToString(buf[:]),
		Files: []wsSyncOfferFile{{
			Name: name,
			Size: size,
			Mime: mime.TypeByExtension(filepath.Ext(name)),
			Kind: kind,
			Path: relPath,
			URL:  "/api/sync/file?ftoken=" + token,
		}},
	}
	return a.hub.SendTo(ws.DeviceAndroid, "file.sync_offer", payload)
}
