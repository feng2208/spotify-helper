package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"spotify-helper/ca"
	"spotify-helper/config"
	"spotify-helper/dns"
	"spotify-helper/spotify"
)

// Server represents the SNI proxy server
type Server struct {
	listenAddr     string
	httpListenAddr string
	caManager      *ca.Manager
	config         *config.Manager
	resolver       *dns.Resolver
}

// NewServer creates a new proxy server
func NewServer(listenAddr string, httpListenAddr string, caManager *ca.Manager, cfg *config.Manager, resolver *dns.Resolver) *Server {
	return &Server{
		listenAddr:     listenAddr,
		httpListenAddr: httpListenAddr,
		caManager:      caManager,
		config:         cfg,
		resolver:       resolver,
	}
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Start HTTP server if address is provided
	if s.httpListenAddr != "" {
		go func() {
			log.Printf("HTTP Server listening on %s", s.httpListenAddr)
			listener, err := net.Listen("tcp", s.httpListenAddr)
			if err != nil {
				log.Printf("Failed to listen on HTTP %s: %v", s.httpListenAddr, err)
				return
			}
			defer listener.Close()

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("HTTP Accept error: %v", err)
					continue
				}
				go s.handleHTTPConnection(conn)
			}
		}()
	}

	// Start SNI Proxy (HTTPS)
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	defer listener.Close()

	log.Printf("SNI Proxy listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// peekHTTPRequest peeks the request to extract Host header and raw bytes
func peekHTTPRequest(reader *bufio.Reader) (string, []byte, error) {
	var accumulated []byte
	var host string

	// Read until we find the end of headers (\r\n\r\n) or limit
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return "", nil, err
		}
		accumulated = append(accumulated, line...)

		lineStr := string(line)

		// Check for Host header
		if strings.HasPrefix(strings.ToLower(lineStr), "host:") {
			host = strings.TrimSpace(strings.TrimPrefix(lineStr[5:], " "))
			// Remove port if present, as config usually matches domain
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}

		// Check for end of headers
		if lineStr == "\r\n" || lineStr == "\n" {
			break
		}

		// Safety limit (e.g., 64KB headers)
		if len(accumulated) > 65536 {
			return "", nil, fmt.Errorf("headers too large")
		}
	}

	return host, accumulated, nil
}

// handleHTTPConnection handles a single plain HTTP connection
func (s *Server) handleHTTPConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	// Peek the request to get Host
	host, headerBytes, err := peekHTTPRequest(reader)
	if err != nil {
		log.Printf("[HTTP] Failed to peek request: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	// Check for CA Download Page (sp-mitm.it)
	if host == "sp-mitm.it" {
		log.Printf("[HTTP] Intercepting CA Download Page request")
		s.handleCADownload(conn, headerBytes)
		return
	}

	// Check if this host is matched in config
	// Is it mapped?
	// Note: config only has GetMapping for SNI usually, but we check hosts
	mapping := s.config.GetMapping(host)

	if mapping != nil {
		// Rule 1: Matched -> Redirect to HTTPS
		log.Printf("[HTTP] Matched host %s -> Redirecting to HTTPS", host)

		// We need to parse the request line to get the URI
		// Simpler to just read the first line from headerBytes
		requestLine := ""
		if idx := bytes.IndexByte(headerBytes, '\n'); idx != -1 {
			requestLine = string(headerBytes[:idx])
		}

		parts := strings.Fields(requestLine)
		uri := "/"
		if len(parts) >= 2 {
			uri = parts[1]
			// Ensure URI starts with / if it's not a full URL
			if !strings.HasPrefix(uri, "http") && !strings.HasPrefix(uri, "/") {
				uri = "/" + uri
			}
			// If it is a full URL (proxy request), parse it
			if strings.HasPrefix(uri, "http://") {
				if u, err := url.Parse(uri); err == nil {
					uri = u.Path
					if u.RawQuery != "" {
						uri += "?" + u.RawQuery
					}
				}
			}
		}

		redirectUrl := fmt.Sprintf("https://%s%s", host, uri)
		resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", redirectUrl)
		conn.Write([]byte(resp))
		return
	}

	// Rule 2: Unmatched -> Transparent Proxy
	log.Printf("[HTTP] Unmatched host %s -> Transparent Proxy", host)

	// Resolve upstream
	ip, err := s.resolver.Resolve(host)
	if err != nil {
		log.Printf("[HTTP] DNS resolution failed for %s: %v", host, err)
		return
	}

	targetAddr := net.JoinHostPort(ip, "80") // Assume HTTP is on port 80

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[HTTP] Failed to connect to upstream %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Reconstruct the stream: headerBytes + rest of body
	// We use prefixConn mechanism logic
	// We need to write headerBytes to target first
	if _, err := targetConn.Write(headerBytes); err != nil {
		log.Printf("[HTTP] Failed to write headers to upstream: %v", err)
		return
	}

	// Bidirectional copy
	// From client (rest of body/requests) to target
	go func() {
		io.Copy(targetConn, reader) // reader has buffered data consumed from conn, plus directly reads from conn
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	// From target to client
	io.Copy(conn, targetConn)
}

// handleCADownload serves the CA download page and certificate file
func (s *Server) handleCADownload(conn net.Conn, headerBytes []byte) {
	// Parse request line to determine path
	requestLine := ""
	if idx := bytes.IndexByte(headerBytes, '\n'); idx != -1 {
		requestLine = string(headerBytes[:idx])
	}
	parts := strings.Fields(requestLine)
	path := "/"
	if len(parts) >= 2 {
		path = parts[1]
		if strings.HasPrefix(path, "http://") {
			if u, err := url.Parse(path); err == nil {
				path = u.Path
			}
		}
	}

	if path == "/cert" {
		// Serve CA certificate
		certPEM := s.caManager.GetCACert()

		headers := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/x-x509-ca-cert\r\n"+
			"Content-Disposition: attachment; filename=\"sp-helper-ca.crt\"\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n", len(certPEM))

		conn.Write([]byte(headers))
		conn.Write(certPEM)
		return
	}

	// Serve HTML page
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SP Helper CA 证书安装</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        h1 { color: #333; }
        .download-btn { display: inline-block; background-color: #1DB954; color: white; padding: 12px 24px; text-decoration: none; border-radius: 25px; font-weight: bold; margin: 20px 0; }
        .step { margin-bottom: 20px; }
        .os-section { margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px; }
        code { background-color: #f5f5f5; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>SP Helper CA 证书</h1>
    <p>为了正常使用此代理服务，您必须在设备上安装并信任 CA 证书。</p>
    
    <a href="/cert" class="download-btn">下载证书 (sp-helper-ca.crt)</a>

    <div class="os-section">
        <h2>iOS</h2>
        <ol>
            <li>使用 <strong>Safari</strong> 打开此页面并点击"下载证书"。</li>
            <li>允许下载配置描述文件。</li>
            <li>前往 <strong>设置</strong> > <strong>已下载描述文件</strong> 并安装该描述文件。</li>
            <li>前往 <strong>设置</strong> > <strong>通用</strong> > <strong>关于本机</strong> > <strong>证书信任设置</strong>。</li>
            <li>针对 "<strong>SP Helper Root CA</strong>" 开启完全信任。</li>
        </ol>
    </div>

    <div class="os-section">
        <h2>Android</h2>
        <ol>
            <li>点击"下载证书"保存文件。</li>
            <li>前往 <strong>设置</strong> > <strong>安全</strong> > <strong>加密与凭据</strong> > <strong>安装证书</strong> > <strong>CA 证书</strong>。</li>
            <li>选择"仍然安装"并选择下载的文件。</li>
        </ol>
    </div>

    <div class="os-section">
        <h2>Windows</h2>
        <ol>
            <li>下载证书文件。</li>
            <li>双击 <code>sp-helper-ca.crt</code> 并点击"安装证书..."。</li>
            <li>选择"本地计算机" (需要管理员权限) 或 "当前用户"。</li>
            <li>选择"将所有的证书都放入下列存储"并浏览选择 "<strong>受信任的根证书颁发机构</strong>"。</li>
            <li>完成安装向导。</li>
        </ol>
    </div>

    <div class="os-section">
        <h2>macOS</h2>
        <ol>
            <li>下载证书文件。</li>
            <li>双击打开钥匙串访问 (Keychain Access)。</li>
            <li>将证书拖入 "<strong>系统</strong>" (System) 钥匙串中。</li>
            <li>双击该证书，展开"信任" (Trust)，并将"使用此证书时"设置为 "<strong>始终信任</strong>" (Always Trust)。</li>
        </ol>
    </div>

    <div class="os-section">
        <h2>Linux</h2>
        <p>将文件复制到 <code>/usr/local/share/ca-certificates/</code> 并运行 <code>sudo update-ca-certificates</code>。</p>
    </div>
</body>
</html>`

	headers := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n", len(html))

	conn.Write([]byte(headers))
	conn.Write([]byte(html))
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Set read deadline for ClientHello
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Peek at the TLS ClientHello to extract SNI
	clientReader := bufio.NewReader(clientConn)
	hello, clientHelloBytes, err := peekClientHello(clientReader)
	if err != nil {
		log.Printf("Failed to peek ClientHello: %v", err)
		return
	}

	sni := hello.ServerName
	if sni == "" {
		log.Printf("No SNI in ClientHello")
		return
	}

	// log.Printf("[SNI] %s", sni)

	// Clear read deadline
	clientConn.SetReadDeadline(time.Time{})

	// Check if we have a mapping for this host
	mapping := s.config.GetMapping(sni)

	// Determine target address
	var targetAddr string
	if mapping != nil && mapping.Address != "" {
		targetAddr = mapping.Address
		log.Printf("[Target] %s %s", sni, targetAddr)
	} else {
		// Resolve via upstream DNS (don't use config.yaml dns overrides for SNI proxy)
		ip, err := s.resolver.Resolve(sni)
		if err != nil {
			log.Printf("DNS resolution failed for %s: %v", sni, err)
			return
		}
		targetAddr = net.JoinHostPort(ip, "443")
		// log.Printf("[Target] Resolved via DNS: %s", targetAddr)
	}

	// Check if we should MITM this connection
	if mapping != nil && mapping.SNI != "" {
		log.Printf("[MITM] %s (sni: %s)", sni, mapping.SNI)
		s.handleMITM(clientConn, clientReader, clientHelloBytes, sni, targetAddr, mapping.SNI)
	} else {
		// log.Printf("[Passthrough] Forwarding connection to %s", sni)
		s.handlePassthrough(clientConn, clientReader, clientHelloBytes, targetAddr)
	}
}

// handlePassthrough forwards the connection without MITM
func (s *Server) handlePassthrough(clientConn net.Conn, clientReader *bufio.Reader, clientHelloBytes []byte, targetAddr string) {
	// Connect to target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Forward the ClientHello we already read
	if _, err := targetConn.Write(clientHelloBytes); err != nil {
		log.Printf("Failed to forward ClientHello: %v", err)
		return
	}

	// Bidirectional copy
	go func() {
		io.Copy(targetConn, clientReader)
		targetConn.(*net.TCPConn).CloseWrite()
	}()
	io.Copy(clientConn, targetConn)
}

// handleMITM performs MITM on the TLS connection
func (s *Server) handleMITM(clientConn net.Conn, clientReader *bufio.Reader, clientHelloBytes []byte, sni string, targetAddr string, targetSNI string) {
	// Get certificate for this host
	cert, err := s.caManager.GetCertificate(sni)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", sni, err)
		return
	}

	// Create a connection that includes the already-read ClientHello bytes
	prefixConn := &prefixConn{
		Conn:   clientConn,
		reader: io.MultiReader(bytes.NewReader(clientHelloBytes), clientReader),
	}

	// Wrap client connection with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	clientTLS := tls.Server(prefixConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("Client TLS handshake failed: %v", err)
		return
	}
	defer clientTLS.Close()

	// Connect to target with TLS
	targetConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		targetAddr,
		&tls.Config{
			ServerName: targetSNI,
		},
	)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	//log.Printf("[MITM] TLS established with client and server")

	// Handle HTTP traffic
	s.handleHTTPTraffic(clientTLS, targetConn, sni)
}

// handleHTTPTraffic handles HTTP requests/responses between client and server
func (s *Server) handleHTTPTraffic(clientConn *tls.Conn, serverConn *tls.Conn, sni string) {
	clientReader := bufio.NewReader(clientConn)
	serverReader := bufio.NewReader(serverConn)
	isSpotify := spotify.IsSpotifyClient(sni)

	for {
		// Read request from client
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to read request: %v", err)
			}
			return
		}

		reqPath := req.URL.Path
		// log.Printf("[HTTP] %s %s%s", req.Method, sni, reqPath)

		// Spotify-specific request handling
		if isSpotify {
			// Block ads and trackers
			if spotify.ShouldBlockPath(reqPath) {
				//log.Printf("[Spotify] Blocking: %s", reqPath)
				// Drain request body to keep connection alive for next request
				if req.Body != nil {
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
				}
				resp := &http.Response{
					StatusCode: 503,
					Status:     "503 Service Unavailable",
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}
				resp.Write(clientConn)
				continue
			}

			// Modify artist view path
			req.URL.Path = spotify.ModifyArtistViewPath(reqPath)

			// Remove if-none-match and accept-encoding for protobuf endpoints
			if spotify.IsSpotifyPath(reqPath) {
				req.Header.Del("If-None-Match")
				req.Header.Del("Accept-Encoding")
			}
		}

		// Forward request to server
		if err := req.Write(serverConn); err != nil {
			log.Printf("Failed to forward request: %v", err)
			return
		}

		// Read response from server
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			return
		}

		// Spotify-specific response handling
		if isSpotify && spotify.IsSpotifyPath(reqPath) && resp.StatusCode == 200 {
			// Read the response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Printf("Failed to read response body: %v", err)
				return
			}

			// Try to modify the protobuf response
			isBootstrap := strings.Contains(reqPath, "v1/bootstrap")
			// log.Printf("[Spotify-MITM] Checking Host=%s Path=%s for Protobuf modification", req.Host, reqPath)

			if modifiedBody, err := spotify.ModifyProtobufResponse(body, isBootstrap); err == nil && modifiedBody != nil {
				log.Printf("[Spotify-MITM] Protobuf Modified: YES (Host=%s Path=%s)", req.Host, reqPath)
				body = modifiedBody
			} else {
				// log.Printf("[Spotify-MITM] Protobuf Modified: NO (Host=%s Path=%s)", req.Host, reqPath)
			}

			// Update content length and body
			resp.ContentLength = int64(len(body))
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Forward response to client
		if err := resp.Write(clientConn); err != nil {
			log.Printf("Failed to forward response: %v", err)
			return
		}

		if resp.Body != nil {
			resp.Body.Close()
		}
	}
}

// prefixConn wraps a net.Conn to prepend already-read data
type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
