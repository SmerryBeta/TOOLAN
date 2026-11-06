package security

import (
	"fmt"
	"net"

	"github.com/hashicorp/mdns"
)

// AnnounceService 通过 mDNS 广播服务，局域网内可通过 http://<instance>.local.:port 访问。
// Windows 10 1903+ 的 Edge/Chrome 可直接解析 .local 域名；部分 Android 版本支持有限，
// 因此这只作为「服务器 IP 变化」的辅助手段，根治仍建议路由器 DHCP 静态绑定。
func AnnounceService(instance string, hostName string, port int, ips []net.IP) (shutdown func(), err error) {
	if hostName == "" {
		hostName = instance
	}
	service, err := mdns.NewMDNSService(
		instance,                           // 服务实例名
		"_http._tcp",                       // 服务类型
		"local.",                           // 域
		fmt.Sprintf("%s.local.", hostName), // 主机名（客户端解析 hostname.local）
		port,
		ips,
		[]string{"toolan"},
	)
	if err != nil {
		return nil, fmt.Errorf("创建 mDNS 服务失败: %w", err)
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return nil, fmt.Errorf("启动 mDNS 失败: %w", err)
	}
	return func() { _ = server.Shutdown() }, nil
}
