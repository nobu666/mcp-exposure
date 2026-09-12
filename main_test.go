package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpinned(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want bool
	}{
		{"npx", []string{"-y", "@xdevplatform/xurl", "mcp"}, true},
		{"npx", []string{"-y", "@xdevplatform/xurl@1.2.0", "mcp"}, false},
		{"npx", []string{"-y", "some-server@latest"}, true}, // a tag moves; not a pin
		{"npx", []string{"-y", "some-server@^1.2.0"}, true},
		{"npx", []string{"--package=foo", "foo-cli"}, true},
		{"npx", []string{"--package=@scope/foo@2.0.0", "foo-cli"}, false},
		{"npx", []string{"-y", "-p", "foo@1.0.0", "foo-cli"}, false},
		{"/opt/homebrew/bin/npx", []string{"-y", "foo"}, true},
		{"uvx", []string{"mcp-server-fetch"}, true},
		{"uvx", []string{"mcp-server-fetch==0.6.2"}, false},
		{"uvx", []string{"--from", "pkg==1.0.0", "cmd"}, false},
		{"uvx", []string{"--from", "pkg", "cmd"}, true},
		{"uvx", []string{"--python", "3.12", "mcp-server-git==1.0.4"}, false},
		{"uvx", []string{"-p", "3.12", "mcp-server-git"}, true},
		{"npx", []string{"-y", "foo@1.2.3-beta.1"}, false},
		{"npx", []string{"--loglevel=silent", "-y", "foo"}, true},
		{"pnpm", []string{"dlx", "foo"}, true},
		{"node", []string{"/abs/server.js"}, false},
		{"npx", []string{"./local-dir"}, false},
		{"bun", []string{"run", "start"}, false},
	}
	for _, c := range cases {
		_, got := unpinned(c.cmd, c.args)
		if got != c.want {
			t.Errorf("unpinned(%s %v) = %v want %v", c.cmd, c.args, got, c.want)
		}
	}
}

func TestSecretInline(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json") // not git-tracked
	f := secretInline(map[string]string{
		"API_KEY":                        "abc123",
		"CLIENT_ID":                      "not-secret-by-name",
		"TOKEN":                          "${MY_TOKEN}",
		"AUTH_HEADER":                    "$AUTH",
		"Authorization":                  "Bearer ${env:TOKEN}",
		"apiKey":                         "${input:api-key}",
		"SECRET":                         "",
		"KEYBOARD_LAYOUT":                "us",
		"OAUTH_MODE":                     "browser",
		"GOOGLE_APPLICATION_CREDENTIALS": "/Users/x/sa.json",
		"API_KEY_FILE":                   "keys/x",
	}, file, "env")
	if len(f) != 1 || f[0].Code != "SECRET_INLINE" || f[0].Level != "warn" || !strings.Contains(f[0].Note, "API_KEY") {
		t.Errorf("unexpected: %+v", f)
	}
	if w := splitWords("apiKeyValue"); len(w) != 3 || w[1] != "Key" {
		t.Errorf("splitWords: %v", w)
	}
	if w := splitWords("APIKey"); len(w) != 2 || w[0] != "API" || w[1] != "Key" {
		t.Errorf("splitWords(APIKey): %v", w)
	}
	for k, want := range map[string]bool{"Authorization": true, "APIKey": true, "XAuthToken": true, "DBPassword": true,
		"KEYBOARD": false, "OAUTH_MODE": false, "AUTHOR": false, "CLIENT_ID": false} {
		if secretKeyName(k) != want {
			t.Errorf("secretKeyName(%s) want %v", k, want)
		}
	}
}

func TestProbeLocalKeepsWorseAuth(t *testing.T) {
	// Loopback side demands auth; the all-interfaces side answers without it.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	ts := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		local := r.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr)
		if local.IP.IsLoopback() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.Header.Get("Origin"), local.IP.String()) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{}`))
	})}}
	ts.Start()
	defer ts.Close()
	addrs := localAddrs()
	if len(addrs) <= 2 {
		t.Skip("no non-loopback address")
	}
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	f := probeLocal(Server{Transport: "http", URL: "http://127.0.0.1:" + itoa(port) + "/mcp"}, addrs)
	if codesOf(f) != "LISTEN_ALL,AUTH_NONE" {
		t.Errorf("want AUTH_NONE from the non-loopback probe: %+v", f)
	}
}

func TestProbeLocalLegacySSE(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
	}))
	defer ts.Close()
	f := probeLocal(Server{Transport: "sse", URL: ts.URL + "/sse"}, localAddrs())
	if codesOf(f) != "REBIND_OPEN,AUTH_NONE" {
		t.Errorf("legacy SSE should be probed with GET: %+v", f)
	}
}

func TestProbeLocalRejectsMissingOrigin(t *testing.T) {
	// A server that requires a same-origin Origin header on every request.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := r.Header.Get("Origin")
		if o == "" || !strings.Contains(o, "127.0.0.1") { // compares against its own bind address
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	f := probeLocal(Server{Transport: "http", URL: ts.URL + "/mcp"}, localAddrs())
	if codesOf(f) != "AUTH_NONE" {
		t.Errorf("plain request must carry a same-origin Origin: %+v", f)
	}
}

func TestLoadAndTransport(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write(".mcp.json", `{"mcpServers":{"a":{"command":"npx","args":["-y","x"]},"b":{"type":"http","url":"http://127.0.0.1:9/mcp"}}}`)
	write(".vscode/mcp.json", `{"servers":{"c":{"type":"sse","url":"http://localhost:9/sse"}}}`)
	write(".gemini/settings.json", `{"mcpServers":{"d":{"httpUrl":"http://localhost:9/mcp"},"e":{"url":"http://localhost:9/sse"}}}`)
	write("home/.claude.json", `{"mcpServers":{"u":{"command":"uvx","args":["p"]}},"projects":{"/x":{"mcpServers":{"l":{"command":"node","args":["s.js"]}}}}}`)

	servers, err := load(sources(dir, filepath.Join(dir, "home")))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range servers {
		got[s.Client+"/"+s.Scope+"/"+s.Name] = s.Transport
	}
	want := map[string]string{
		"claude-code/project/a": "stdio", "claude-code/project/b": "http",
		"vscode/project/c": "sse", "gemini/project/d": "http", "gemini/project/e": "sse",
		"claude-code/user/u": "stdio", "claude-code/local/l": "stdio",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "[::1]": true,
		"0.0.0.0": true, "foo.localhost": true, "host.docker.internal": false, "192.168.1.5": false, "example.com": false} {
		if isLoopbackHost(h) != want {
			t.Errorf("isLoopbackHost(%s) want %v", h, want)
		}
	}
	if f := check(Server{Transport: "http", URL: "http://host.docker.internal:8000/mcp"}); codesOf(f) != "CONTAINER_ALIAS" {
		t.Errorf("host.docker.internal should be info only: %+v", f)
	}
}

func TestIgnoredFindingsDoNotCount(t *testing.T) {
	fs := []Finding{{Code: "PLAINTEXT_REMOTE", Level: "red", Ignored: true}, {Code: "UNPINNED", Level: "warn"}}
	if v := verdict(fs); v != "WARN" {
		t.Errorf("ignored red should not count, got %s", v)
	}
	fs[1].Ignored = true
	if v := verdict(fs); v != "ok" {
		t.Errorf("all ignored should be ok, got %s", v)
	}
}

func TestSuggestAppendsPin(t *testing.T) {
	old := lookup
	defer func() { lookup = old }()
	var asked []string
	lookup = func(eco, name string) (release, error) {
		asked = append(asked, eco+":"+name)
		return release{"1.3.1", "2026-07-21"}, nil
	}
	s := Server{Transport: "stdio", Command: "npx", Args: []string{"-y", "@xdevplatform/xurl@latest", "mcp"}}
	fs := check(s)
	suggest(s, fs)
	if len(asked) != 1 || asked[0] != "npm:@xdevplatform/xurl" {
		t.Errorf("lookup called with %v", asked)
	}
	if len(fs) != 1 || !strings.HasSuffix(fs[0].Note, "pin as @xdevplatform/xurl@1.3.1") {
		t.Errorf("unexpected: %+v", fs)
	}
	s = Server{Transport: "stdio", Command: "uvx", Args: []string{"mcp-server-git>=1.0"}}
	fs = check(s)
	suggest(s, fs)
	if asked[1] != "pypi:mcp-server-git" || !strings.HasSuffix(fs[0].Note, "pin as mcp-server-git==1.3.1") {
		t.Errorf("unexpected: %v %+v", asked, fs)
	}
	if n := bareName("npm", "@scope/name@^2"); n != "@scope/name" {
		t.Errorf("bareName: %s", n)
	}
}

func TestCheckPlaintextRemote(t *testing.T) {
	f := check(Server{Transport: "http", URL: "http://mcp.example.com/mcp"})
	if len(f) != 1 || f[0].Code != "PLAINTEXT_REMOTE" || f[0].Level != "red" {
		t.Errorf("unexpected: %+v", f)
	}
	if f := check(Server{Transport: "http", URL: "https://mcp.example.com/mcp"}); len(f) != 0 {
		t.Errorf("https should be clean: %+v", f)
	}
}

// originChecking mimics a spec-compliant local MCP server: foreign Origin is rejected.
func originChecking(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	if o != "" && !strings.Contains(o, "127.0.0.1") && !strings.Contains(o, "localhost") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
}

func codesOf(fs []Finding) string {
	var c []string
	for _, f := range fs {
		c = append(c, f.Code)
	}
	return strings.Join(c, ",")
}

func TestProbeLocalCompliant(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(originChecking)) // 127.0.0.1
	defer ts.Close()
	f := probeLocal(Server{Transport: "http", URL: ts.URL + "/mcp"}, localAddrs())
	if codesOf(f) != "AUTH_NONE" {
		t.Errorf("want only AUTH_NONE, got %+v", f)
	}
}

func TestProbeLocalAllIfacesNoOriginCheck(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	ts := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})}}
	ts.Start()
	defer ts.Close()
	addrs := localAddrs()
	if len(addrs) <= 2 {
		t.Skip("no non-loopback address")
	}
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	f := probeLocal(Server{Transport: "http", URL: "http://localhost:" + itoa(port) + "/mcp"}, addrs)
	if codesOf(f) != "LISTEN_ALL,REBIND_OPEN,AUTH_NONE" {
		t.Errorf("unexpected: %+v", f)
	}
}

func TestProbeLocalAuthRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()
	if f := probeLocal(Server{Transport: "http", URL: ts.URL}, localAddrs()); len(f) != 0 {
		t.Errorf("auth-required server should be clean: %+v", f)
	}
}

func itoa(n int) string { return strings.TrimSpace(strings.Replace(fmtInt(n), " ", "", -1)) }
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
