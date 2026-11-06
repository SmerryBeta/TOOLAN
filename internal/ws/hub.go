package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	// maxFrameSize 限制单个入站帧的声明长度，防止恶意超大长度导致
	// make([]byte, length) 触发 makeslice panic（远程崩溃）或内存耗尽。
	maxFrameSize = 1 << 20
	// readIdleTimeout 无入站帧的最长等待时间，超时断开以回收僵尸连接。
	readIdleTimeout = 30 * time.Minute
	// writeTimeout 单帧写超时，避免慢速客户端长期占住发送协程。
	writeTimeout = 15 * time.Second
)

// Event is the message envelope sent to browser and future Android clients.
type Event struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
	Time    time.Time   `json:"time"`
}

// Encryptor 由 security.A1Cipher 实现：广播前把 JSON 事件整体加密为 A1 信封。
// Hub 通过小接口依赖，避免 ws 包反向依赖 security。
type Encryptor interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(envelope string) ([]byte, error)
}

// DeviceAndroid 是 ?device= 握手参数的安卓设备标识；定向事件（如 file.sync_offer）
// 只发给声明了该值的客户端。
const DeviceAndroid = "android"

// Hub tracks active websocket clients and broadcasts JSON events.
type Hub struct {
	mu         sync.Mutex
	clients    map[*client]struct{}
	MaxClients int
	// AllowedHosts 为额外的 Origin 白名单（host[:port]），同源请求始终放行。
	AllowedHosts []string
	// Cipher 非 nil 时支持加密通道：握手带 X-Toolan-Crypto 头或 ?crypto= 参数的
	// 客户端收到的将是加密信封帧，其余客户端仍收明文 JSON（同 Hub 双模广播）。
	Cipher Encryptor
}

type client struct {
	conn      net.Conn
	send      chan []byte
	encrypted bool   // 该客户端是否要求接收加密帧
	device    string // 握手 ?device= 声明的设备类型；空表示未声明（浏览器等）
}

func NewHub() *Hub {
	return &Hub{clients: map[*client]struct{}{}}
}

// Handle upgrades GET /ws to a websocket connection.
func (h *Hub) Handle(c *gin.Context) {
	if !originAllowed(c.Request, h.AllowedHosts) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin not allowed"})
		return
	}

	h.mu.Lock()
	if h.MaxClients > 0 && len(h.clients) >= h.MaxClients {
		h.mu.Unlock()
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "too many connections"})
		return
	}
	h.mu.Unlock()

	conn, err := upgrade(c.Writer, c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cl := &client{
		conn:      conn,
		send:      make(chan []byte, 16),
		encrypted: h.Cipher != nil && (c.GetHeader("X-Toolan-Crypto") != "" || c.Query("crypto") != ""),
		device:    normalizeDevice(c.Query("device")),
	}
	h.add(cl)
	go h.writeLoop(cl)
	go h.readLoop(cl)

	h.Send("connected", gin.H{"message": "websocket connected"})
}

// normalizeDevice 归一化握手声明的设备类型：目前仅识别 android，其余一律视为未声明，
// 避免任意字符串获得定向事件资格。
func normalizeDevice(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), DeviceAndroid) {
		return DeviceAndroid
	}
	return ""
}

// Send serializes an event and broadcasts it to all connected clients.
func (h *Hub) Send(eventType string, payload interface{}) {
	h.dispatch(func(*client) bool { return true }, eventType, payload)
}

// SendTo 仅发送给 device 匹配的客户端，返回实际送达数（写入 send channel 的客户端数）。
func (h *Hub) SendTo(device, eventType string, payload interface{}) int {
	return h.dispatch(func(cl *client) bool { return cl.device == device }, eventType, payload)
}

// CountDevice 返回当前在线的指定设备类型客户端数。
func (h *Hub) CountDevice(device string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for cl := range h.clients {
		if cl.device == device {
			count++
		}
	}
	return count
}

// dispatch 序列化事件并投递给 match 通过的客户端。加密客户端收到的是同一份 A1
// 信封（全局同一密钥，只加密一次）；无目标客户端时不做序列化与加密。
func (h *Hub) dispatch(match func(*client) bool, eventType string, payload interface{}) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	targets := make([]*client, 0, len(h.clients))
	for cl := range h.clients {
		if match(cl) {
			targets = append(targets, cl)
		}
	}
	if len(targets) == 0 {
		return 0
	}

	data, err := json.Marshal(Event{Type: eventType, Payload: payload, Time: time.Now()})
	if err != nil {
		return 0
	}

	var envelope []byte
	if h.Cipher != nil {
		env, eerr := h.Cipher.Encrypt(data)
		if eerr != nil {
			return 0
		}
		envelope = []byte(env)
	}

	delivered := 0
	for _, cl := range targets {
		frame := data
		if cl.encrypted {
			frame = envelope
		}
		select {
		case cl.send <- frame:
			delivered++
		default:
			close(cl.send)
			delete(h.clients, cl)
			_ = cl.conn.Close()
		}
	}
	return delivered
}

func (h *Hub) add(cl *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[cl] = struct{}{}
}

func (h *Hub) remove(cl *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[cl]; ok {
		delete(h.clients, cl)
		close(cl.send)
		_ = cl.conn.Close()
	}
}

func (h *Hub) writeLoop(cl *client) {
	for data := range cl.send {
		_ = cl.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeTextFrame(cl.conn, data); err != nil {
			h.remove(cl)
			return
		}
	}
}

func (h *Hub) readLoop(cl *client) {
	defer h.remove(cl)
	reader := bufio.NewReader(cl.conn)
	for {
		_ = cl.conn.SetReadDeadline(time.Now().Add(readIdleTimeout))
		opcode, payload, err := readFrame(reader)
		if err != nil || opcode == 8 {
			return
		}
		// 上行消息当前无消费者；若为加密信封则尝试解密一次，
		// 失败说明客户端密钥不符——仅记录，不断连（避免重连风暴）。
		if opcode == 1 && h.Cipher != nil && strings.HasPrefix(string(payload), "A1.") {
			if _, derr := h.Cipher.Decrypt(string(payload)); derr != nil {
				log.Printf("[ws] 加密上行解密失败（客户端密钥不符）: %v", derr)
			}
		}
	}
}

// originAllowed 校验浏览器 Origin：同源放行，无 Origin（原生客户端）放行，
// 其余必须在白名单内，阻断跨站 WebSocket 劫持（CSWSH）。
func originAllowed(r *http.Request, extra []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	for _, host := range extra {
		if strings.EqualFold(u.Host, host) {
			return true
		}
	}
	return false
}

func upgrade(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Method != http.MethodGet {
		return nil, errors.New("websocket requires GET")
	}
	if r.Header.Get("Upgrade") != "websocket" {
		return nil, errors.New("missing websocket upgrade header")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing websocket key")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	acceptHash := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptHash[:])
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func writeTextFrame(conn net.Conn, payload []byte) error {
	header := []byte{0x81}
	length := len(payload)
	switch {
	case length <= 125:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126, byte(length>>8), byte(length))
	default:
		header = append(header, 127)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(length))
		header = append(header, buf[:]...)
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	opcode := first & 0x0f
	masked := second&0x80 != 0
	// RFC 6455：客户端帧必须带掩码，未掩码帧视为协议错误直接断开。
	if !masked {
		return 0, nil, errors.New("client frame must be masked")
	}
	length := int64(second & 0x7f)
	if length == 126 {
		var b [2]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(b[:]))
	} else if length == 127 {
		var b [8]byte
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(b[:]))
	}
	// 先校验声明长度再分配内存，阻断超大帧引发的崩溃/内存耗尽。
	if length < 0 || length > maxFrameSize {
		return 0, nil, errors.New("frame too large")
	}

	var mask [4]byte
	if _, err := io.ReadFull(reader, mask[:]); err != nil {
		return 0, nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return opcode, payload, nil
}
