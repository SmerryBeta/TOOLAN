package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// dualListener 把同一端口上的连接按首字节分流：
//   - 0x16（TLS ClientHello）→ HTTPS 服务
//   - 其余（明文 HTTP）→ HTTP 服务
//
// 兼容无法处理自签证书的客户端（如手机 WebView 直接走明文），
// 同时允许已安装 CA 的浏览器在同一端口使用加密。
type dualListener struct {
	httpCh chan net.Conn
	tlsCh  chan net.Conn
	closed chan struct{}
}

func newDualListener() *dualListener {
	return &dualListener{
		httpCh: make(chan net.Conn),
		tlsCh:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *dualListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.httpCh:
		return c, nil
	case c := <-l.tlsCh:
		return c, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *dualListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *dualListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

// peekConn 回放已预读字节的连接包装。
type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

// serveDual 在同一端口同时提供 HTTP 与 HTTPS。
func serveDual(addr string, handler http.Handler, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return errors.New("tls config required")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	httpLn := newDualListener()
	tlsLn := newDualListener()

	srvDefaults := func(s *http.Server) {
		s.Handler = handler
		s.ReadHeaderTimeout = 10 * time.Second
		s.IdleTimeout = 120 * time.Second
		s.MaxHeaderBytes = 8 << 10
	}

	httpSrv := &http.Server{}
	srvDefaults(httpSrv)
	tlsSrv := &http.Server{}
	srvDefaults(tlsSrv)
	tlsSrv.TLSConfig = tlsConfig

	go func() { _ = httpSrv.Serve(httpLn) }()
	// Serve 不会自动包 TLS 层，必须用 tls.NewListener 包装后再交给 HTTP Server
	go func() { _ = tlsSrv.Serve(tls.NewListener(tlsLn, tlsConfig)) }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			_ = httpLn.Close()
			_ = tlsLn.Close()
			return err
		}
		go classify(conn, httpLn, tlsLn)
	}
}

// classify 读取首字节判断协议并分发；超时按明文处理。
// 用 Peek 而非 ReadByte：Peek 不消费缓冲，回放时首字节保留。
func classify(conn net.Conn, httpLn, tlsLn *dualListener) {
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	head, err := br.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	pc := &peekConn{Conn: conn, reader: br}
	if head[0] == 0x16 { // TLS ClientHello
		tlsLn.tlsCh <- pc
	} else {
		httpLn.httpCh <- pc
	}
}
