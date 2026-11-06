package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// TLSManager 管理自签 CA 与服务端证书：
//   - CA 证书只生成一次并长期不变，客户端安装一次即永久信任；
//   - 服务端证书内置当前主机名与全部网卡 IP（SAN），IP 变化后下次启动自动重签，
//     因 CA 不变，客户端无需重新安装。
type TLSManager struct {
	dir string
}

// NewTLSManager 创建 TLS 材料管理器，证书文件存放于 dir。
func NewTLSManager(dir string) *TLSManager {
	return &TLSManager{dir: dir}
}

const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
	sansMetaFile   = "sans.json"
)

// Ensure 返回 CA 证书 PEM（供下载安装）与可直接使用的服务端证书。
func (m *TLSManager) Ensure(hostname string, ips []net.IP) ([]byte, tls.Certificate, error) {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return nil, tls.Certificate{}, err
	}

	caKey, caCertDER, err := m.loadOrCreateCA(hostname)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, tls.Certificate{}, errors.New("解析 CA 证书失败: " + err.Error())
	}

	want := sanFingerprint(hostname, ips)
	if !m.serverCertMatches(want) {
		if err := m.issueServerCert(caKey, caCert, hostname, ips); err != nil {
			return nil, tls.Certificate{}, err
		}
		_ = os.WriteFile(filepath.Join(m.dir, sansMetaFile), []byte(want), 0600)
	}

	cert, err := m.loadServerCert()
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	return caPEM, cert, nil
}

// loadOrCreateCA 返回 CA 私钥与 DER 证书；不存在则生成（有效期 10 年）。
func (m *TLSManager) loadOrCreateCA(hostname string) (*ecdsa.PrivateKey, []byte, error) {
	certPEM, certErr := os.ReadFile(filepath.Join(m.dir, caCertFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(m.dir, caKeyFile))
	if certErr == nil && keyErr == nil {
		block, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if block != nil && keyBlock != nil {
			if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
				if _, err := x509.ParseCertificate(block.Bytes); err == nil {
					return key, block.Bytes, nil
				}
			}
		}
		// 文件损坏则重建
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cn := hostname
	if cn == "" {
		cn = "TOOLAN"
	}
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "TOOLAN Root CA (" + cn + ")"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(filepath.Join(m.dir, caCertFile), "CERTIFICATE", der, 0644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(filepath.Join(m.dir, caKeyFile), "EC PRIVATE KEY", keyDER, 0600); err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// issueServerCert 用 CA 签发服务端证书（有效期 825 天，SAN 覆盖主机名与全部当前 IP）。
func (m *TLSManager) issueServerCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, hostname string, ips []net.IP) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsNames := []string{"localhost"}
	if hostname != "" && !strings.EqualFold(hostname, "localhost") {
		dnsNames = append(dnsNames, hostname)
	}
	ipSANs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ipSANs = append(ipSANs, ips...)

	cn := hostname
	if cn == "" {
		cn = "TOOLAN"
	}
	tpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 825),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(m.dir, serverCertFile), "CERTIFICATE", der, 0644); err != nil {
		return err
	}
	return writePEM(filepath.Join(m.dir, serverKeyFile), "EC PRIVATE KEY", keyDER, 0600)
}

func (m *TLSManager) loadServerCert() (tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(m.dir, serverCertFile))
	if err != nil {
		return tls.Certificate{}, errors.New("服务端证书不存在")
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.dir, serverKeyFile))
	if err != nil {
		return tls.Certificate{}, errors.New("服务端私钥不存在")
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return tls.Certificate{}, errors.New("证书文件损坏")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, errors.New("解析服务端私钥失败: " + err.Error())
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, errors.New("解析服务端证书失败: " + err.Error())
	}
	return tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// serverCertMatches 判断已签发证书的 SAN 是否与当前主机名/IP 集合一致。
func (m *TLSManager) serverCertMatches(want string) bool {
	if _, err := os.Stat(filepath.Join(m.dir, serverCertFile)); err != nil {
		return false
	}
	got, err := os.ReadFile(filepath.Join(m.dir, sansMetaFile))
	return err == nil && strings.TrimSpace(string(got)) == want
}

func sanFingerprint(hostname string, ips []net.IP) string {
	sort.Slice(ips, func(i, j int) bool {
		return bytesLess(ips[i], ips[j])
	})
	parts := []string{"host=" + strings.ToLower(hostname)}
	for _, ip := range ips {
		parts = append(parts, "ip="+ip.String())
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return string(sum[:])
}

func bytesLess(a, b net.IP) bool {
	return string(a) < string(b)
}

func writePEM(path string, blockType string, der []byte, mode os.FileMode) error {
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, data, mode)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

// LocalAddresses 返回本机所有非环回 IPv4 地址（用于提示与证书 SAN）。
// includeLoopback 同时返回环回与 IPv6 地址（用于 SAN）。
func LocalAddresses(includeLoopback bool) ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil || seen[string(ip.To16())] {
			return
		}
		isLoop := ip.IsLoopback()
		if !includeLoopback && isLoop {
			return
		}
		seen[string(ip.To16())] = true
		out = append(out, ip)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				add(ipnet.IP)
			}
		}
	}
	return out, nil
}
