package security

import (
	"bytes"
	"strings"
	"testing"
)

// 跨端互通向量：由桌面工具同款算法（WebCrypto PBKDF2 310k + AES-256-GCM）生成，
// Go / 安卓 / 浏览器三端必须都能解开同一条信封。
const (
	vectorKeyText   = "1234567890"
	vectorEnvelope  = "A1.EREREREREREREREREREREQ.IiIiIiIiIiIiIiIi.AgU1z0pJfMsFHfDccG9CDzk579QXvy-80HQ-hbFKRZWS39hff_z5QtxPy3S6OR6zMtQ"
	vectorPlaintext = "TOOLAN-A1 cross-tool vector 你好"
)

func TestParseNumericKey(t *testing.T) {
	cases := []struct {
		in      string
		wantHex string // 期望的最短大端字节（hex）
		wantErr bool
	}{
		{"0", "00", false},
		{"1", "01", false},
		{"255", "ff", false},
		{"256", "0100", false},
		{"1234567890", "499602d2", false},
		{"0xff", "ff", false},
		{"0X4F3a", "4f3a", false},
		{"0x00ff", "ff", false},
		{"  42  ", "2a", false},
		{"", "", true},
		{"-5", "", true},
		{"0x", "", true},
		{"12ab", "", true},
		{"0xzz", "", true},
		{"+5", "", true},
		{"1.5", "", true},
	}
	for _, tc := range cases {
		got, err := ParseNumericKey(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseNumericKey(%q) 期望报错，实际得到 %x", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseNumericKey(%q) 意外报错: %v", tc.in, err)
			continue
		}
		if hex := hexOf(got); hex != tc.wantHex {
			t.Errorf("ParseNumericKey(%q) = %s, 期望 %s", tc.in, hex, tc.wantHex)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0xf])
	}
	return string(out)
}

func TestA1RoundTrip(t *testing.T) {
	keys := []string{"0", "1234567890", "0xdeadbeef", strings.Repeat("9", 120)}
	for _, key := range keys {
		c, err := NewA1Cipher(key)
		if err != nil {
			t.Fatalf("NewA1Cipher(%q…) 报错: %v", key[:min(len(key), 8)], err)
		}
		for _, plain := range [][]byte{[]byte(""), []byte("hello"), bytes.Repeat([]byte("x"), 100_000)} {
			env, err := c.Encrypt(plain)
			if err != nil {
				t.Fatalf("Encrypt 报错: %v", err)
			}
			if !LooksEncrypted(env) {
				t.Fatalf("信封未被嗅探识别: %s", env[:20])
			}
			got, err := c.Decrypt(env)
			if err != nil {
				t.Fatalf("Decrypt 报错: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("往返结果不一致（长度 %d vs %d）", len(got), len(plain))
			}
		}
	}
}

func TestA1CrossToolVector(t *testing.T) {
	c, err := NewA1Cipher(vectorKeyText)
	if err != nil {
		t.Fatalf("NewA1Cipher 报错: %v", err)
	}
	got, err := c.Decrypt(vectorEnvelope)
	if err != nil {
		t.Fatalf("跨端向量解密失败: %v", err)
	}
	if string(got) != vectorPlaintext {
		t.Fatalf("跨端向量明文不符: %q", string(got))
	}
}

func TestA1WrongKeyAndTamper(t *testing.T) {
	c1, _ := NewA1Cipher("1111111111")
	c2, _ := NewA1Cipher("2222222222")

	env, err := c1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt 报错: %v", err)
	}

	if _, err := c2.Decrypt(env); err == nil {
		t.Fatal("错误密钥解密应当失败")
	}

	// 篡改密文段末字符（GCM tag 校验必须失败）
	tampered := env[:len(env)-1] + string(flipLastChar(env[len(env)-1]))
	if _, err := c1.Decrypt(tampered); err == nil {
		t.Fatal("篡改后的密文解密应当失败")
	}

	// 格式错误
	for _, bad := range []string{"", "A1", "A1.a", "A1.a.b", "A1.a.b.c.d", "B1.a.b.c", "A1.!!.IiIiIiIiIiIiIiIi.AAAA"} {
		if _, err := c1.Decrypt(bad); err == nil {
			t.Fatalf("非法信封 %q 应当解密失败", bad)
		}
	}
}

func flipLastChar(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}

func TestA1StreamRoundTrip(t *testing.T) {
	c, _ := NewA1Cipher("9876543210")

	// 1.5MB 数据 → 多个 512KB 块
	data := make([]byte, A1ChunkSize*3-7)
	for i := range data {
		data[i] = byte(i % 251)
	}
	meta := StreamMeta{Name: "测试.bin", Mime: "application/octet-stream", Size: int64(len(data))}

	var buf bytes.Buffer
	if err := c.EncryptStream(meta, bytes.NewReader(data), &buf); err != nil {
		t.Fatalf("EncryptStream 报错: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	wantChunks := (len(data) + A1ChunkSize - 1) / A1ChunkSize
	if len(lines) != wantChunks+1 {
		t.Fatalf("A1L 行数 = %d，期望 %d（meta + %d 块）", len(lines), wantChunks+1, wantChunks)
	}
	if !LooksEncrypted(lines[0]) || !LooksEncrypted(lines[1]) {
		t.Fatal("A1L 各行应为独立信封")
	}

	var out bytes.Buffer
	gotMeta, err := c.DecryptStream(&buf, &out)
	if err != nil {
		t.Fatalf("DecryptStream 报错: %v", err)
	}
	if gotMeta.Name != meta.Name || gotMeta.Size != meta.Size || gotMeta.Mime != meta.Mime {
		t.Fatalf("meta 往返不符: %+v vs %+v", gotMeta, meta)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("流数据往返不一致（%d vs %d 字节）", out.Len(), len(data))
	}
}

func TestA1StreamTruncation(t *testing.T) {
	c, _ := NewA1Cipher("555555")
	data := bytes.Repeat([]byte("z"), A1ChunkSize+100)
	meta := StreamMeta{Name: "t.bin", Size: int64(len(data))}

	var buf bytes.Buffer
	if err := c.EncryptStream(meta, bytes.NewReader(data), &buf); err != nil {
		t.Fatalf("EncryptStream 报错: %v", err)
	}

	// 截掉最后一个数据行，size 校验必须失败
	content := buf.String()
	idx := strings.LastIndex(content[:len(content)-1], "\n")
	var cut bytes.Buffer
	cut.WriteString(content[:idx+1])

	var out bytes.Buffer
	if _, err := c.DecryptStream(&cut, &out); err == nil {
		t.Fatal("截断的流应当校验失败")
	}
}

func TestA1StreamWrongKey(t *testing.T) {
	c1, _ := NewA1Cipher("1111111111")
	c2, _ := NewA1Cipher("2222222222")

	var buf bytes.Buffer
	if err := c1.EncryptStream(StreamMeta{Name: "a"}, bytes.NewReader([]byte("data")), &buf); err != nil {
		t.Fatalf("EncryptStream 报错: %v", err)
	}
	var out bytes.Buffer
	if _, err := c2.DecryptStream(&buf, &out); err == nil {
		t.Fatal("错误密钥解密流应当失败")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
