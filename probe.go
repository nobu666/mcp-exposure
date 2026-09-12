package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Network checks for MCP servers on a loopback host. Same approach as
// localai-audit: connect on every local address to see whether the socket
// is bound to all interfaces, then compare a plain request with one that
// carries a foreign Host/Origin (DNS rebinding). The MCP spec (2026-07-28,
// Streamable HTTP) says servers MUST validate Origin, SHOULD bind to
// 127.0.0.1 only, and SHOULD authenticate.

const (
	connectTimeout = 400 * time.Millisecond
	httpTimeout    = 3 * time.Second
	spoofHost      = "evil.example"
	initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"mcp-exposure","version":"0"}}}`
)

// probeLocal returns findings for a server whose URL points at this host.
func probeLocal(s Server, addrs []string) []Finding {
	u, err := url.Parse(s.URL)
	if err != nil {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" || u.Scheme == "wss" {
			port = "443"
		}
	}
	open := openAddrs(port, addrs)
	if len(open) == 0 {
		return []Finding{{Code: "DOWN", Level: "info", Note: "nothing listening on port " + port}}
	}
	var f []Finding
	allIfaces := false
	for _, a := range open {
		if !net.ParseIP(a).IsLoopback() {
			allIfaces = true
		}
	}
	if allIfaces {
		f = append(f, Finding{Code: "LISTEN_ALL", Level: "red", Note: "port " + port + " is bound to all interfaces (spec: SHOULD bind to 127.0.0.1)"})
	}
	if s.Transport == "ws" {
		return f
	}
	// Legacy HTTP+SSE servers answer GET on /sse with an event stream;
	// Streamable HTTP servers take a JSON-RPC initialize by POST.
	method := "POST"
	if s.Transport == "sse" || strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/sse") {
		method = "GET"
	}
	target := *u
	target.Host = net.JoinHostPort(open[0], port)
	plain, err := send(method, target.String(), "")
	if err != nil {
		return append(f, Finding{Code: "NO_HTTP", Level: "info", Note: err.Error()})
	}
	spoofed, _ := send(method, target.String(), spoofHost)
	// Probe the non-loopback side too when bound to all interfaces; some
	// servers only enforce Host on loopback (Ollama does). Keep the worse.
	if allIfaces {
		target.Host = net.JoinHostPort(open[len(open)-1], port)
		if p2, err := send(method, target.String(), ""); err == nil {
			s2, _ := send(method, target.String(), spoofHost)
			rb1, au1 := judge(plain, spoofed)
			rb2, au2 := judge(p2, s2)
			if rb2 == "open" && rb1 != "open" || au2 == "none" && au1 != "none" {
				plain, spoofed = p2, s2
			}
		}
	}
	rebind, auth := judge(plain, spoofed)
	switch rebind {
	case "open":
		f = append(f, Finding{Code: "REBIND_OPEN", Level: "red", Note: "accepts Host/Origin " + spoofHost + " (spec: MUST validate Origin)"})
	case "?":
		f = append(f, Finding{Code: "REBIND_UNKNOWN", Level: "info", Note: "plain " + strconv.Itoa(plain) + ", spoofed " + strconv.Itoa(spoofed)})
	}
	if auth == "none" {
		f = append(f, Finding{Code: "AUTH_NONE", Level: "warn", Note: "accepted with no credentials (spec: SHOULD authenticate)"})
	}
	return f
}

func openAddrs(port string, addrs []string) []string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var open []string
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, port), connectTimeout)
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, addr)
			mu.Unlock()
		}(addr)
	}
	wg.Wait()
	// loopback first
	var lo, ext []string
	for _, a := range open {
		if net.ParseIP(a).IsLoopback() {
			lo = append(lo, a)
		} else {
			ext = append(ext, a)
		}
	}
	return append(lo, ext...)
}

// localAddrs returns loopback first, then every unicast address on the host.
func localAddrs() []string {
	addrs := []string{"127.0.0.1", "::1"}
	ifAddrs, _ := net.InterfaceAddrs()
	for _, a := range ifAddrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		addrs = append(addrs, ipn.IP.String())
	}
	return addrs
}

// judge: rebind is open when the spoofed request gets through, blocked
// when it is rejected with 4xx; auth is none when plain is 2xx.
func judge(plain, spoofed int) (rebind, auth string) {
	switch {
	case plain/100 == 2:
		auth = "none"
	case plain == http.StatusUnauthorized || plain == http.StatusForbidden:
		return "n/a", "required"
	default:
		return "?", "?"
	}
	switch {
	case spoofed/100 == 2 || spoofed/100 == 3:
		return "open", auth
	case spoofed/100 == 4:
		return "blocked", auth
	}
	return "?", auth
}

var client = &http.Client{
	Timeout:       httpTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// send makes one request and returns only the status code. The body is
// never read: it may be an event stream. The plain request carries a
// same-origin Origin header, since spec-compliant servers may reject a
// missing one; the spoofed request carries a foreign Host and Origin.
func send(method, u, host string) (int, error) {
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader(initializeBody)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	origin := "http://" + req.URL.Host
	if host != "" {
		req.Host = host
		origin = "http://" + host
	}
	req.Header.Set("Origin", origin)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
