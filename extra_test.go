package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadCodex(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.toml")
	os.WriteFile(file, []byte(`
model = "gpt-5" # unrelated

[mcp_servers.fetch]
command = "uvx"
args = ["mcp-server-fetch"] # trailing comment
env = { API_KEY = "abc", OTHER = "x" }

[mcp_servers."my http"]
url = "http://127.0.0.1:8000/mcp"

[mcp_servers.git]
command = "npx"
args = [
  "-y", # yes
  "@scope/git@1.0.0",
]

[mcp_servers.git.env]
GIT_TOKEN = "t0k"

[mcp_servers.quoted]
command = 'echo #not-a-comment'

[other_table]
command = "not-an-mcp"
`), 0o644)
	servers := loadCodex(file, "user")
	got := map[string]Server{}
	for _, s := range servers {
		got[s.Name] = s
	}
	if len(got) != 4 {
		t.Fatalf("want 4 servers, got %v", got)
	}
	if s := got["quoted"]; s.Command != "echo #not-a-comment" {
		t.Errorf("single-quoted # kept: %q", s.Command)
	}
	if s := got["fetch"]; s.Transport != "stdio" || s.Command != "uvx" || len(s.Args) != 1 || s.Args[0] != "mcp-server-fetch" || s.Env["API_KEY"] != "abc" || s.Env["OTHER"] != "x" {
		t.Errorf("fetch: %+v", s)
	}
	if s := got["my http"]; s.Transport != "http" || s.URL != "http://127.0.0.1:8000/mcp" {
		t.Errorf("my http: %+v", s)
	}
	if s := got["git"]; s.Env["GIT_TOKEN"] != "t0k" || len(s.Args) != 2 || s.Args[1] != "@scope/git@1.0.0" {
		t.Errorf("git (multi-line args): %+v", s)
	}
}

func TestLoadPlugins(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "cache", "acme", "tool", "1.0.0")
	os.MkdirAll(filepath.Join(root, ".claude-plugin"), 0o755)
	os.MkdirAll(filepath.Join(home, ".claude", "plugins"), 0o755)
	os.WriteFile(filepath.Join(root, ".claude-plugin", "plugin.json"), []byte(`{"name":"tool","mcpServers":{"tool":{"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/start.mjs"]}}}`), 0o644)
	os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"tool-http":{"type":"http","url":"https://example.com/mcp"}}}`), 0o644)
	os.WriteFile(filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), []byte(`{"version":2,"plugins":{"tool@acme":[{"installPath":"`+root+`"}],"off@acme":[{"installPath":"`+root+`"}]}}`), 0o644)
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"enabledPlugins":{"tool@acme":true,"off@acme":false}}`), 0o644)

	servers := loadPlugins(home, t.TempDir())
	if len(servers) != 2 {
		t.Fatalf("want 2 servers from the enabled plugin only, got %+v", servers)
	}
	for _, s := range servers {
		if s.Scope != "plugin:tool" || s.Client != "claude-code" {
			t.Errorf("scope/client: %+v", s)
		}
		if s.Name == "tool" && s.Args[0] != filepath.Join(root, "start.mjs") {
			t.Errorf("CLAUDE_PLUGIN_ROOT not expanded: %+v", s.Args)
		}
	}
	// A project can enable a plugin the user settings have off.
	cwd := t.TempDir()
	os.MkdirAll(filepath.Join(cwd, ".claude"), 0o755)
	os.WriteFile(filepath.Join(cwd, ".claude", "settings.local.json"), []byte(`{"enabledPlugins":{"off@acme":true,"tool@acme":false}}`), 0o644)
	servers = loadPlugins(home, cwd)
	if len(servers) != 2 || servers[0].Scope != "plugin:off" {
		t.Fatalf("project settings.local.json should override: %+v", servers)
	}
}

func TestGitState(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.json\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "tracked.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "untracked.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "ignored.json"), []byte("{}"), 0o644)
	run("add", ".gitignore", "tracked.json")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "x")
	for name, want := range map[string]string{"tracked.json": "tracked", "untracked.json": "untracked", "ignored.json": "ignored"} {
		if got := gitState(filepath.Join(dir, name)); got != want {
			t.Errorf("%s: got %s want %s", name, got, want)
		}
	}
	if got := gitState(filepath.Join(t.TempDir(), "x.json")); got != "none" {
		t.Errorf("outside repo: got %s", got)
	}
}
