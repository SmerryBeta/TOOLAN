package security

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

// 私有加密方案 A1：AES-256-GCM + PBKDF2-HMAC-SHA256。
// 信封格式 A1.<b64url(salt)>.<b64url(iv)>.<b64url(ciphertext+tag)>，
// 与桌面工具 aes256_gcm_encryptor.html 完全互通；流式场景（文件上传/下载）
// 使用 A1L：按行分隔的多个 A1 信封（首行 meta JSON，其后每行一个数据块）。
//
// 扩展预留：信封首段即版本号；新方案（如 R1 非对称混合加密）实现 Cipher
// 接口并在 NewCipherByVersion 注册即可，客户端按版本号嗅探选择。
const (
	A1Version        = "A1"
	a1Iterations     = 310000
	a1SaltSize       = 16
	a1IVSize         = 12
	a1KeySize        = 32
	a1TagSize        = 16
	a1MaxCachedSalts = 8 // 派生密钥缓存上限（不同 salt 的来源：各客户端实例、桌面工具）

	// A1ChunkSize 是 A1L 流式传输时单个数据块的明文上限。
	A1ChunkSize = 512 * 1024
)

// StreamMeta 是 A1L 流首行信封内的元数据（也用于加密上传的 meta part）。
type StreamMeta struct {
	Name   string `json:"name"`
	Mime   string `json:"mime,omitempty"`
	Size   int64  `json:"size"`             // 已知时用于完整性校验；流式打包（zip）可为 0
	Folder string `json:"folder,omitempty"` // 仅上传使用：目标子文件夹
}

// Cipher 是应用层加密方案的统一接口。
type Cipher interface {
	// Version 返回信封版本标识（信封首段），如 "A1"。
	Version() string
	// Encrypt 加密任意字节，返回单段信封文本。
	Encrypt(plaintext []byte) (string, error)
	// Decrypt 解密单段信封；格式错误、密钥不符或被篡改时返回错误。
	Decrypt(envelope string) ([]byte, error)
	// EncryptStream 把 r 的内容分块加密为 A1L 文本流写入 w。
	EncryptStream(meta StreamMeta, r io.Reader, w io.Writer) error
	// DecryptStream 逐行解密 A1L 流并把明文写入 w，返回首行 meta。
	DecryptStream(r io.Reader, w io.Writer) (StreamMeta, error)
}

// ParseNumericKey 按桌面工具的规则解析用户密钥：
// 纯十进制数字或 0x 开头的十六进制，转为最短无符号大端字节序（0 编码为单字节 00）。
func ParseNumericKey(text string) ([]byte, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, errors.New("密钥不能为空")
	}

	var n *big.Int
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		hex := s[2:]
		if hex == "" || !allHexDigits(hex) {
			return nil, errors.New("密钥格式错误：0x 后需要十六进制数字")
		}
		var ok bool
		n, ok = new(big.Int).SetString(hex, 16)
		if !ok {
			return nil, errors.New("密钥格式错误")
		}
	default:
		if !allDigits(s) {
			return nil, errors.New("密钥只能是十进制数字，或 0x 开头的十六进制数字")
		}
		var ok bool
		n, ok = new(big.Int).SetString(s, 10)
		if !ok {
			return nil, errors.New("密钥格式错误")
		}
	}

	if n.Sign() < 0 {
		return nil, errors.New("密钥不能为负数")
	}
	if n.Sign() == 0 {
		return []byte{0}, nil
	}
	return n.Bytes(), nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// LooksEncrypted 嗅探文本是否为 A1 单段信封（前缀 + 恰好 4 段）。
func LooksEncrypted(text string) bool {
	return strings.HasPrefix(text, A1Version+".") && strings.Count(text, ".") == 3
}

// NewCipherByVersion 按信封版本构造加密器；当前仅实现 A1，其余版本预留。
func NewCipherByVersion(version, keyText string) (Cipher, error) {
	if version != A1Version {
		return nil, fmt.Errorf("不支持的加密方案版本: %s", version)
	}
	return NewA1Cipher(keyText)
}

// A1Cipher 实现 AES-256-GCM 对称加密。
//
// 性能说明：加密方向使用构造时随机生成的实例级 salt（信封内仍携带），
// 使 PBKDF2 派生在每个进程内只发生一次；IV 每条随机，GCM 安全性不受影响。
// 解密方向按信封内 salt 派生并缓存（上限 a1MaxCachedSalts 个），因此与
// 每次随机 salt 的桌面工具互通也只需一次派生。
type A1Cipher struct {
	raw  []byte
	salt []byte

	mu    sync.Mutex
	cache map[string][]byte // b64(salt) -> derived key
}

// NewA1Cipher 用用户密钥文本构造加密器。
func NewA1Cipher(keyText string) (*A1Cipher, error) {
	raw, err := ParseNumericKey(keyText)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, a1SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("生成 salt 失败: %w", err)
	}
	return &A1Cipher{raw: raw, salt: salt, cache: map[string][]byte{}}, nil

}

func (c *A1Cipher) Version() string { return A1Version }

// keyFor 对给定 salt 派生 AES 密钥（带缓存）。
func (c *A1Cipher) keyFor(salt []byte) ([]byte, error) {
	cacheKey := base64.RawStdEncoding.EncodeToString(salt)

	c.mu.Lock()
	if key, ok := c.cache[cacheKey]; ok {
		c.mu.Unlock()
		return key, nil
	}
	c.mu.Unlock()

	key, err := pbkdf2.Key(sha256.New, string(c.raw), salt, a1Iterations, a1KeySize)
	if err != nil {
		return nil, fmt.Errorf("密钥派生失败: %w", err)
	}

	c.mu.Lock()
	if len(c.cache) >= a1MaxCachedSalts {
		c.cache = map[string][]byte{}
	}
	c.cache[cacheKey] = key
	c.mu.Unlock()
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt 加密并返回 A1 单段信封。
func (c *A1Cipher) Encrypt(plaintext []byte) (string, error) {
	iv := make([]byte, a1IVSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("生成 IV 失败: %w", err)
	}
	key, err := c.keyFor(c.salt)
	if err != nil {
		return "", err
	}
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, iv, plaintext, nil)

	enc := base64.RawURLEncoding
	return strings.Join([]string{
		A1Version,
		enc.EncodeToString(c.salt),
		enc.EncodeToString(iv),
		enc.EncodeToString(sealed),
	}, "."), nil
}

// Decrypt 解析并解密 A1 单段信封。
func (c *A1Cipher) Decrypt(envelope string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(envelope), ".")
	if len(parts) != 4 || parts[0] != A1Version {
		return nil, errors.New("密文格式不正确")
	}

	enc := base64.RawURLEncoding
	salt, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("密文 salt 编码错误")
	}
	iv, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("密文 nonce 编码错误")
	}
	data, err := enc.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("密文编码错误")
	}

	if len(salt) != a1SaltSize {
		return nil, errors.New("密文 salt 长度错误")
	}
	if len(iv) != a1IVSize {
		return nil, errors.New("密文 nonce 长度错误")
	}
	if len(data) < a1TagSize {
		return nil, errors.New("密文长度过短")
	}

	key, err := c.keyFor(salt)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, data, nil)
	if err != nil {
		return nil, errors.New("解密失败：密钥不正确或密文已被修改")
	}
	return plain, nil
}

// EncryptStream 把 r 分块加密为 A1L 文本流：首行 meta 信封，其后每行一个数据块信封。
// 流自然结束即传输结束；每个数据块独立 GCM 认证，截断/篡改都会在解密侧暴露。
func (c *A1Cipher) EncryptStream(meta StreamMeta, r io.Reader, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 128*1024)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := writeEnvelopeLine(bw, c, metaJSON); err != nil {
		return err
	}

	buf := make([]byte, A1ChunkSize)
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			if err := writeEnvelopeLine(bw, c, buf[:n]); err != nil {
				return err
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return bw.Flush()
}

func writeEnvelopeLine(bw *bufio.Writer, c *A1Cipher, plaintext []byte) error {
	env, err := c.Encrypt(plaintext)
	if err != nil {
		return err
	}
	if _, err := bw.WriteString(env); err != nil {
		return err
	}
	return bw.WriteByte('\n')
}

// DecryptStream 逐行解密 A1L 流并把明文顺序写入 w；meta.Size > 0 时校验总字节数。
func (c *A1Cipher) DecryptStream(r io.Reader, w io.Writer) (StreamMeta, error) {
	br := bufio.NewReaderSize(r, 128*1024)

	metaLine, err := readLine(br)
	if err != nil {
		return StreamMeta{}, fmt.Errorf("读取流元数据失败: %w", err)
	}
	metaPlain, err := c.Decrypt(metaLine)
	if err != nil {
		return StreamMeta{}, fmt.Errorf("解密流元数据失败: %w", err)
	}
	var meta StreamMeta
	if err := json.Unmarshal(metaPlain, &meta); err != nil {
		return StreamMeta{}, fmt.Errorf("流元数据格式错误: %w", err)
	}

	var written int64
	for {
		line, err := readLine(br)
		if line != "" {
			plain, derr := c.Decrypt(line)
			if derr != nil {
				return meta, fmt.Errorf("解密数据块失败: %w", derr)
			}
			if _, werr := w.Write(plain); werr != nil {
				return meta, werr
			}
			written += int64(len(plain))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return meta, err
		}
	}

	if meta.Size > 0 && written != meta.Size {
		return meta, fmt.Errorf("流不完整：期望 %d 字节，实际 %d 字节", meta.Size, written)
	}
	return meta, nil
}

// readLine 读取一行（去掉 \n 与 \r）；空行返回 ""，流结束返回 err=io.EOF。
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadBytes('\n')
	content := strings.TrimRight(string(line), "\r\n")
	if err != nil {
		if len(content) > 0 && err == io.EOF {
			return content, io.EOF
		}
		return content, err
	}
	return content, nil
}

// EncryptBytesToWriter 供需要直接输出单段信封的 handler 使用。
func EncryptBytesToWriter(c Cipher, w io.Writer, plaintext []byte) error {
	env, err := c.Encrypt(plaintext)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader([]byte(env)))
	return err
}
