package main

import (
	"fmt"
	"os"
	"strings"

	"BackEnd/internal/cli"
	"BackEnd/internal/security"
	"BackEnd/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cli" {
		if err := cli.Run("static"); err != nil {
			fmt.Println("CLI 启动失败:", err)
			os.Exit(1)
		}
		return
	}

	cfg, generated, err := security.Load("config.yml")
	if err != nil {
		fmt.Println("读取安全配置失败:", err)
		os.Exit(1)
	}
	if generated {
		fmt.Println("========================================================")
		fmt.Println("  检测到未设置访问密码，已自动生成并写入 config.yml：")
		fmt.Printf("  访问密码: %s\n", cfg.Password)
		fmt.Println("  请妥善保存！局域网内访问均需输入该密码。")
		fmt.Println("========================================================")
	}

	app, err := server.New("static", cfg)
	if err != nil {
		fmt.Println("服务初始化失败:", err)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	ips, _ := security.LocalAddresses(false)
	fmt.Printf("服务监听 %s:%d（主机名 %s）\n", cfg.Host, cfg.Port, hostname)
	fmt.Printf("  本机访问: http://localhost:%d\n", cfg.Port)
	for _, ip := range ips {
		fmt.Printf("  局域网访问: http://%s:%d\n", ip, cfg.Port)
		if cfg.MDNSEnabled {
			fmt.Printf("              http://%s.local.:%d (mDNS，部分设备可用)\n", strings.ToLower(hostname), cfg.Port)
			break
		}
	}

	if cfg.TLSEnabled {
		fmt.Println("  ------------------------------------------------")
		fmt.Println("  加密已启用（同端口双协议）：")
		fmt.Printf("    加密访问 https://<IP>:%d —— 首次使用需安装证书：\n", cfg.Port)
		fmt.Printf("      浏览器访问 http://<本机IP>:%d/ca.crt 下载，\n", cfg.Port)
		fmt.Println("      双击安装到「受信任的根证书颁发机构」后重启浏览器；")
		fmt.Println("      装好后浏览器访问 http 地址会自动升级到 https。")
		fmt.Println("    未装证书的客户端（手机 WebView 等）仍可用 http 访问。")
		fmt.Println("    IP 变化无需重装证书（服务端自动重签，CA 不变）。")
	}

	if cfg.MDNSEnabled {
		if shutdown, err := security.AnnounceService("TOOLAN", hostname, cfg.Port, ips); err == nil {
			fmt.Printf("  mDNS 已广播: %s.local.:%d\n", strings.ToLower(hostname), cfg.Port)
			defer shutdown()
		} else {
			fmt.Println("  mDNS 启动失败（不影响正常使用）:", err)
		}
	}
	fmt.Println("  提示: 若服务器 IP 经常变化，可在路由器中为本机做 DHCP 静态绑定（MAC -> 固定 IP），一次配置永久生效。")

	if err := app.Run(); err != nil {
		fmt.Println("服务启动失败:", err)
		os.Exit(1)
	}
}
