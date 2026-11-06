package ws

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// fakeEncryptor 记录加密调用次数，用于断言"无目标客户端时不加密"。
type fakeEncryptor struct {
	calls int
}

func (f *fakeEncryptor) Encrypt(plaintext []byte) (string, error) {
	f.calls++
	return "A1.fake." + string(plaintext), nil
}

func (f *fakeEncryptor) Decrypt(envelope string) ([]byte, error) {
	return []byte(envelope), nil
}

func addTestClient(h *Hub, device string) *client {
	c1, _ := net.Pipe()
	cl := &client{conn: c1, send: make(chan []byte, 8), device: device}
	h.mu.Lock()
	h.clients[cl] = struct{}{}
	h.mu.Unlock()
	return cl
}

func recvFrame(t *testing.T, cl *client) Event {
	t.Helper()
	select {
	case raw := <-cl.send:
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatalf("帧不是合法 JSON: %v", err)
		}
		return ev
	case <-time.After(time.Second):
		t.Fatal("等待帧超时")
		return Event{}
	}
}

func assertNoFrame(t *testing.T, cl *client) {
	t.Helper()
	select {
	case raw := <-cl.send:
		t.Fatalf("不应收到帧，实际收到: %s", raw)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSendToOnlyDeliversMatchingDevice(t *testing.T) {
	h := NewHub()
	android := addTestClient(h, DeviceAndroid)
	web := addTestClient(h, "")

	if got := h.CountDevice(DeviceAndroid); got != 1 {
		t.Fatalf("CountDevice(android) = %d, want 1", got)
	}
	delivered := h.SendTo(DeviceAndroid, "file.sync_offer", map[string]string{"url": "/x"})
	if delivered != 1 {
		t.Fatalf("SendTo delivered = %d, want 1", delivered)
	}

	ev := recvFrame(t, android)
	if ev.Type != "file.sync_offer" {
		t.Fatalf("安卓端收到 type=%s, want file.sync_offer", ev.Type)
	}
	assertNoFrame(t, web)
}

func TestSendToWithoutTargetSkipsCipher(t *testing.T) {
	h := NewHub()
	fake := &fakeEncryptor{}
	h.Cipher = fake
	addTestClient(h, "") // 仅浏览器客户端

	if delivered := h.SendTo(DeviceAndroid, "file.sync_offer", "x"); delivered != 0 {
		t.Fatalf("SendTo delivered = %d, want 0", delivered)
	}
	if fake.calls != 0 {
		t.Fatalf("无目标客户端时不应加密，实际加密 %d 次", fake.calls)
	}
}

func TestSendStillBroadcastsToAll(t *testing.T) {
	h := NewHub()
	android := addTestClient(h, DeviceAndroid)
	web := addTestClient(h, "")

	h.Send("notification", "hello")

	if ev := recvFrame(t, android); ev.Type != "notification" {
		t.Fatalf("安卓端 type=%s, want notification", ev.Type)
	}
	if ev := recvFrame(t, web); ev.Type != "notification" {
		t.Fatalf("网页端 type=%s, want notification", ev.Type)
	}
}

func TestNormalizeDevice(t *testing.T) {
	for _, in := range []string{"android", "Android", " android "} {
		if got := normalizeDevice(in); got != DeviceAndroid {
			t.Fatalf("normalizeDevice(%q) = %q, want android", in, got)
		}
	}
	for _, in := range []string{"", "web", "ios", "android;drop"} {
		if got := normalizeDevice(in); got != "" {
			t.Fatalf("normalizeDevice(%q) = %q, want \"\"", in, got)
		}
	}
}
