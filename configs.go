package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Server is one MCP server entry found in a client config file.
type Server struct {
	Client    string            `json:"client"`
	Scope     string            `json:"scope"` // project | user | local
	Name      string            `json:"name"`
	File      string            `json:"file"`
	Transport string            `json:"transport"` // stdio | http | sse | ws
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// rawServer is the common shape used by every client we read. Gemini CLI
// uses httpUrl for Streamable HTTP and url for SSE; everyone else uses url.
type rawServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	HTTPURL string            `json:"httpUrl"`
	Headers map[string]string `json:"headers"`
}

func (r rawServer) toServer(client, scope, name, file string) Server {
	s := Server{Client: client, Scope: scope, Name: name, File: file,
		Command: r.Command, Args: r.Args, Env: r.Env, Headers: r.Headers}
	s.URL = r.URL
	if r.HTTPURL != "" {
		s.URL = r.HTTPURL
	}
	s.Transport = strings.ToLower(r.Type)
	if s.Transport == "" {
		switch {
		case s.URL == "":
			s.Transport = "stdio"
		case strings.HasPrefix(s.URL, "ws"):
			s.Transport = "ws"
		case strings.HasSuffix(strings.TrimRight(s.URL, "/"), "/sse") || r.URL != "" && r.HTTPURL == "" && client == "gemini":
			s.Transport = "sse"
		default:
			s.Transport = "http"
		}
	}
	return s
}

type source struct {
	client, scope, file, key string
}

// sources lists every config file we know how to read. Paths that do not
// exist are skipped silently. Documented locations as of 2026-09-11:
// Claude Code (.mcp.json, ~/.claude.json), Claude Desktop, Cursor, VS Code
// (.vscode/mcp.json; user-level path is the conventional one, unverified),
// Gemini CLI (~/.gemini/settings.json, .gemini/settings.json).
func sources(cwd, home string) []source {
	desktop := filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	vscodeUser := filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	switch runtime.GOOS {
	case "windows":
		desktop = filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
		vscodeUser = filepath.Join(os.Getenv("APPDATA"), "Code", "User", "mcp.json")
	case "linux":
		desktop = filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
		vscodeUser = filepath.Join(home, ".config", "Code", "User", "mcp.json")
	}
	return []source{
		{"claude-code", "project", filepath.Join(cwd, ".mcp.json"), "mcpServers"},
		{"claude-code", "user", filepath.Join(home, ".claude.json"), "mcpServers"},
		{"claude-desktop", "user", desktop, "mcpServers"},
		{"cursor", "project", filepath.Join(cwd, ".cursor", "mcp.json"), "mcpServers"},
		{"cursor", "user", filepath.Join(home, ".cursor", "mcp.json"), "mcpServers"},
		{"vscode", "project", filepath.Join(cwd, ".vscode", "mcp.json"), "servers"},
		{"vscode", "user", vscodeUser, "servers"},
		{"gemini", "project", filepath.Join(cwd, ".gemini", "settings.json"), "mcpServers"},
		{"gemini", "user", filepath.Join(home, ".gemini", "settings.json"), "mcpServers"},
	}
}

// load reads every source and returns the servers found. ~/.claude.json
// also carries per-project ("local" scope) servers under projects.<path>.
func load(srcs []source) ([]Server, error) {
	var out []Server
	for _, src := range srcs {
		data, err := os.ReadFile(src.file)
		if err != nil {
			continue
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, &parseError{src.file, err}
		}
		out = append(out, parseServers(doc[src.key], src.client, src.scope, src.file)...)

		if src.client == "claude-code" && src.scope == "user" {
			var projects map[string]struct {
				MCPServers json.RawMessage `json:"mcpServers"`
			}
			if json.Unmarshal(doc["projects"], &projects) == nil {
				for _, p := range projects {
					out = append(out, parseServers(p.MCPServers, src.client, "local", src.file)...)
				}
			}
		}
	}
	return out, nil
}

func parseServers(raw json.RawMessage, client, scope, file string) []Server {
	var m map[string]rawServer
	if raw == nil || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var out []Server
	for name, r := range m {
		out = append(out, r.toServer(client, scope, name, file))
	}
	return out
}

type parseError struct {
	file string
	err  error
}

func (e *parseError) Error() string { return e.file + ": " + e.err.Error() }
