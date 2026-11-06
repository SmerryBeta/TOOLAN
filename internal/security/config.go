package security

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 承载 config.yml 中 Server 与 Security 两个配置块。
type Config struct {
	Host string
	Port int

	TLSEnabled   bool // 启用 HTTPS（自签 CA 自动签发）
	TLSPort      int  // HTTPS 端口
	HTTPRedirect bool // TLS 启用时保留 HTTP 端口用于跳转与 CA 下载
	MDNSEnabled  bool // mDNS 广播 <hostname>.local

	Password          string // 访问口令；为空时首次启动自动生成并回写
	AuthEnabled       bool   // 鉴权总开关：false 时所有接口免登录直连（限流/上传限制等仍生效）
	SessionTTLHours   int
	MaxUploadMB       int
	RatePerMinute     int
	LoginMaxFails     int
	LoginLockMinutes  int
	MaxWSClients      int
	ExtraAllowedHosts []string // WS Origin 额外放行的 host:port（用于反向代理等场景）

	// 应用层加密（A1）：HTTP/WS 全流量加密，替代移动端不可用的自签 TLS。
	CryptoEnabled         bool   // 总开关；false 时所有流量明文（与现状一致）
	CryptoKey             string // 用户密钥：十进制或 0x 十六进制大整数，手动填入，绝不上链路
	CryptoVerifyPerMinute int    // /api/crypto/verify 每 IP 每分钟上限
}

// Defaults 返回内置默认值。
func Defaults() Config {
	return Config{
		Host:             "0.0.0.0",
		Port:             8000,
		TLSPort:          8443,
		HTTPRedirect:     true,
		AuthEnabled:      true,
		SessionTTLHours:  168,
		MaxUploadMB:      2048,
		RatePerMinute:    240,
		LoginMaxFails:    5,
		LoginLockMinutes: 10,
		MaxWSClients:     64,

		CryptoVerifyPerMinute: 6,
	}
}

// Load 从 yaml 文件读取配置；文件或字段缺失时使用默认值。
// 若 Security.Password 为空，则自动生成口令并回写文件，返回 (cfg, generated=true)。
func Load(path string) (Config, bool, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return cfg, false, err
		}
		cfg.Password = generatePassword(10)
		return cfg, true, cfg.saveNew(path)
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return cfg, false, fmt.Errorf("解析 %s 失败: %w", path, err)
	}

	if v := stringAt(doc, "Server", "Host"); v != "" {
		cfg.Host = v
	}
	if v := intAt(doc, "Server", "Port"); v > 0 {
		cfg.Port = v
	}
	cfg.TLSEnabled = boolAt(doc, false, "Server", "TLS", "Enabled")
	if v := intAt(doc, "Server", "TLS", "Port"); v > 0 {
		cfg.TLSPort = v
	}
	cfg.HTTPRedirect = boolAt(doc, cfg.HTTPRedirect, "Server", "TLS", "HTTPRedirect")
	cfg.MDNSEnabled = boolAt(doc, false, "Server", "MDNS")
	if v := stringAt(doc, "Security", "Password"); v != "" {
		cfg.Password = v
	}
	cfg.AuthEnabled = boolAt(doc, cfg.AuthEnabled, "Security", "AuthEnabled")
	if v := intAt(doc, "Security", "SessionTTLHours"); v > 0 {
		cfg.SessionTTLHours = v
	}
	if v := intAt(doc, "Security", "MaxUploadMB"); v > 0 {
		cfg.MaxUploadMB = v
	}
	if v := intAt(doc, "Security", "RatePerMinute"); v > 0 {
		cfg.RatePerMinute = v
	}
	if v := intAt(doc, "Security", "LoginMaxFails"); v > 0 {
		cfg.LoginMaxFails = v
	}
	if v := intAt(doc, "Security", "LoginLockMinutes"); v > 0 {
		cfg.LoginLockMinutes = v
	}
	if v := intAt(doc, "Security", "MaxWSClients"); v > 0 {
		cfg.MaxWSClients = v
	}
	if list := stringListAt(doc, "Security", "ExtraAllowedHosts"); len(list) > 0 {
		cfg.ExtraAllowedHosts = list
	}
	cfg.CryptoEnabled = boolAt(doc, false, "Security", "CryptoEnabled")
	if v := stringAt(doc, "Security", "CryptoKey"); v != "" {
		cfg.CryptoKey = v
	}
	if v := intAt(doc, "Security", "CryptoVerifyPerMinute"); v > 0 {
		cfg.CryptoVerifyPerMinute = v
	}

	if cfg.CryptoEnabled {
		if _, err := ParseNumericKey(cfg.CryptoKey); err != nil {
			return cfg, false, fmt.Errorf("Security.CryptoEnabled 已开启，但 CryptoKey 无效: %w", err)
		}
	}

	if cfg.Password == "" {
		cfg.Password = generatePassword(10)
		if err := writeBack(path, doc, cfg.Password); err != nil {
			return cfg, false, err
		}
		return cfg, true, nil
	}
	return cfg, false, nil
}

// saveNew 在配置文件不存在时创建一份带安全配置的最小文件。
func (c Config) saveNew(path string) error {
	doc := map[string]interface{}{
		"Server": map[string]interface{}{
			"Host": c.Host,
			"Port": c.Port,
		},
		"Security": map[string]interface{}{
			"Password": c.Password,
		},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// writeBack 仅向既有配置文件补写 Security.Password，保留其余键。
func writeBack(path string, doc map[string]interface{}, password string) error {
	sec, ok := doc["Security"].(map[string]interface{})
	if !ok {
		sec = map[string]interface{}{}
		doc["Security"] = sec
	}
	sec["Password"] = password
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func stringAt(doc map[string]interface{}, key ...string) string {
	cur := climb(doc, key...)
	s, _ := cur.(string)
	return s
}

func intAt(doc map[string]interface{}, key ...string) int {
	cur := climb(doc, key...)
	switch v := cur.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		parsed := 0
		_, _ = fmt.Sscanf(v, "%d", &parsed)
		return parsed
	}
	return 0
}

func boolAt(doc map[string]interface{}, elseValue bool, key ...string) bool {
	cur := climb(doc, key...)
	switch v := cur.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	case int:
		return v == 1
	case int64:
		return v == 1
	case float64:
		return v == 1
	}
	return elseValue
}

func stringListAt(doc map[string]interface{}, key ...string) []string {
	cur := climb(doc, key...)
	list, _ := cur.([]interface{})
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func climb(doc map[string]interface{}, key ...string) interface{} {
	var cur interface{} = doc
	for _, k := range key {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = m[k]
		if !ok {
			return nil
		}
	}
	return cur
}

// generatePassword 生成易读、无歧义字符的随机口令。
const passwordAlphabet = "abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ23456789"

func generatePassword(length int) string {
	out := make([]byte, length)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			out[i] = passwordAlphabet[i%len(passwordAlphabet)]
			continue
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out)
}
