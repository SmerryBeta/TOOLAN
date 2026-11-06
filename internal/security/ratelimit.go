package security

import (
	"sync"
	"time"
)

// windowLimiter 按 IP 的固定窗口计数限流。
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	hits    map[string]*bucket
	nowFunc func() time.Time
}

type bucket struct {
	count  int
	window time.Time
}

// NewRateLimiter 创建每 IP 限流器：window 内最多 limit 次请求。
func NewRateLimiter(limit int, window time.Duration) *windowLimiter {
	limiter := &windowLimiter{
		limit:   limit,
		window:  window,
		hits:    map[string]*bucket{},
		nowFunc: time.Now,
	}
	go limiter.gcLoop()
	return limiter
}

// Allow 报告该 IP 是否仍在本窗口配额内。
func (l *windowLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFunc()
	b, ok := l.hits[ip]
	if !ok || now.Sub(b.window) >= l.window {
		l.hits[ip] = &bucket{count: 1, window: now}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

func (l *windowLimiter) gcLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := l.nowFunc()
		for ip, b := range l.hits {
			if now.Sub(b.window) >= l.window {
				delete(l.hits, ip)
			}
		}
		l.mu.Unlock()
	}
}

// loginTracker 记录登录失败次数并在超限后锁定 IP 一段时间。
type loginTracker struct {
	mu    sync.Mutex
	max   int
	lock  time.Duration
	fails map[string]*failState
	clean time.Time
}

type failState struct {
	count       int
	lockedUntil time.Time
	lastFail    time.Time
}

// NewLoginTracker 创建登录失败跟踪器：max 次失败后锁定 lock 时长。
func NewLoginTracker(max int, lock time.Duration) *loginTracker {
	return &loginTracker{
		max:   max,
		lock:  lock,
		fails: map[string]*failState{},
		clean: time.Now(),
	}
}

// Locked 报告该 IP 当前是否处于锁定期。
func (t *loginTracker) Locked(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc()
	st, ok := t.fails[ip]
	if !ok {
		return false, 0
	}
	if remain := time.Until(st.lockedUntil); remain > 0 {
		return true, remain
	}
	return false, 0
}

// Fail 记录一次失败，必要时触发锁定；返回是否刚被锁定。
func (t *loginTracker) Fail(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc()
	st, ok := t.fails[ip]
	if !ok {
		st = &failState{}
		t.fails[ip] = st
	}
	st.count++
	st.lastFail = time.Now()
	if st.count >= t.max {
		st.lockedUntil = time.Now().Add(t.lock)
		st.count = 0
		return true
	}
	return false
}

// Reset 登录成功后清除失败记录。
func (t *loginTracker) Reset(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, ip)
}

// gc 延迟清理：仅在持锁时调用。
func (t *loginTracker) gc() {
	now := time.Now()
	if now.Sub(t.clean) < time.Minute {
		return
	}
	t.clean = now
	for ip, st := range t.fails {
		if now.Sub(st.lastFail) > t.lock && now.After(st.lockedUntil) {
			delete(t.fails, ip)
		}
	}
}
