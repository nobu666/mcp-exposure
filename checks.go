package main

import (
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	Code    string `json:"code"`
	Level   string `json:"level"` // red | warn | info
	Note    string `json:"note"`
	Ignored bool   `json:"ignored,omitempty"` // accepted via --ignore: shown, not counted
}

// check runs the static checks that need no network.
func check(s Server) []Finding {
	var f []Finding
	switch s.Transport {
	case "stdio":
		if pkg, ok := unpinned(s.Command, s.Args); ok {
			f = append(f, Finding{Code: "UNPINNED", Level: "warn", Note: pkg + " is fetched at every start with no exact version"})
		}
		f = append(f, secretInline(s.Env, s.File, "env")...)
	default:
		u, err := url.Parse(s.URL)
		if err != nil {
			return append(f, Finding{Code: "BAD_URL", Level: "info", Note: s.URL})
		}
		host := u.Hostname()
		if host == "host.docker.internal" {
			f = append(f, Finding{Code: "CONTAINER_ALIAS", Level: "info", Note: "host.docker.internal resolves differently outside a container; not probed"})
		} else if (u.Scheme == "http" || u.Scheme == "ws") && !isLoopbackHost(host) {
			f = append(f, Finding{Code: "PLAINTEXT_REMOTE", Level: "red", Note: u.Scheme + ":// to " + host + " sends headers and data in the clear"})
		}
		f = append(f, secretInline(s.Headers, s.File, "headers")...)
	}
	return f
}

// runner describes a tool that fetches and executes a package by name.
// pkgFlags name the package explicitly; valueFlags take a value that is
// not the package; otherwise the first positional argument is the package.
type runner struct {
	pkgFlags, valueFlags, subcommands map[string]bool
}

func set(s ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}

var runners = map[string]runner{
	"npx":  {set("-p", "--package"), set("-c", "--call", "--shell", "--loglevel"), nil},
	"bunx": {nil, set("--bun"), nil},
	"uvx":  {set("--from"), set("-p", "--python", "-w", "--with", "--index", "--index-url", "--cache-dir"), nil},
	"pnpm": {set("--package"), nil, set("dlx")},
	"pipx": {set("--spec"), set("--python"), set("run")},
}

var exactVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)

// unpinned reports the package when a runner is used without an exact
// version. name@1.2.3, @scope/name@1.2.3, name==1.2.3 count as pinned;
// @latest, @next, ^1, 1.x and no version at all do not.
func unpinned(cmd string, args []string) (string, bool) {
	r, ok := runners[filepath.Base(cmd)]
	if !ok {
		return "", false
	}
	pkg := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if eq := strings.IndexByte(a, '='); eq > 0 && strings.HasPrefix(a, "-") {
			if r.pkgFlags[a[:eq]] {
				pkg = a[eq+1:]
				break
			}
			continue
		}
		if r.pkgFlags[a] && i+1 < len(args) {
			pkg = args[i+1]
			break
		}
		if r.valueFlags[a] {
			i++
			continue
		}
		if a == "" || strings.HasPrefix(a, "-") || r.subcommands[a] {
			continue
		}
		pkg = a
		break
	}
	if pkg == "" || strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "/") || strings.HasPrefix(pkg, "~") {
		return "", false // local path, not a registry fetch
	}
	version := ""
	if i := strings.Index(pkg, "=="); i > 0 {
		version = pkg[i+2:]
	} else if i := strings.LastIndex(pkg, "@"); i > 0 {
		version = pkg[i+1:]
	}
	if exactVersion.MatchString(version) {
		return "", false
	}
	return pkg, true
}

var secretWords = set("key", "secret", "token", "password", "passwd", "pwd", "credential", "credentials", "bearer", "auth", "authorization")
var expansion = regexp.MustCompile(`\$\{|\$[A-Za-z_]`)

// secretInline flags plaintext values under secret-looking keys. Keys are
// matched word by word (API_KEY yes, KEYBOARD no). Values that reference
// an environment variable in any client's syntax (${VAR}, ${VAR:-x},
// ${env:VAR}, ${input:x}, $VAR) are fine, as are empty values and paths
// (a key like GOOGLE_APPLICATION_CREDENTIALS points at a file). The
// finding is red when the file is tracked by git.
func secretInline(m map[string]string, file, where string) []Finding {
	var f []Finding
	for k, v := range m {
		if v == "" || expansion.MatchString(v) || !secretKeyName(k) || looksLikePath(v) {
			continue
		}
		level := "warn"
		note := where + "." + k + " is stored in plaintext"
		if gitTracked(file) {
			level, note = "red", note+" in a git-tracked file"
		}
		f = append(f, Finding{Code: "SECRET_INLINE", Level: level, Note: note})
	}
	return f
}

func secretKeyName(k string) bool {
	if strings.HasSuffix(strings.ToUpper(k), "_FILE") || strings.HasSuffix(strings.ToUpper(k), "_PATH") {
		return false
	}
	for _, w := range splitWords(k) {
		if secretWords[strings.ToLower(w)] {
			return true
		}
	}
	return false
}

// splitWords splits API_KEY, api-key, apiKey and APIKey into words.
func splitWords(k string) []string {
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	isLower := func(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
	var out []string
	start := 0
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c == '_' || c == '-' || c == '.' {
			if i > start {
				out = append(out, k[start:i])
			}
			start = i + 1
			continue
		}
		if i > start && isUpper(c) && (isLower(k[i-1]) || i+1 < len(k) && isLower(k[i+1]) && isUpper(k[i-1])) {
			out = append(out, k[start:i])
			start = i
		}
	}
	if start < len(k) {
		out = append(out, k[start:])
	}
	return out
}

func looksLikePath(v string) bool {
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../")
}

func gitTracked(file string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	cmd := exec.Command("git", "-C", filepath.Dir(file), "ls-files", "--error-unmatch", filepath.Base(file))
	return cmd.Run() == nil
}

func isLoopbackHost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}
