package main

import (
	"os"
	"strings"
)

// Codex CLI keeps MCP servers in TOML (~/.codex/config.toml, or a
// project's .codex/config.toml) as [mcp_servers.<id>] tables with
// command, args, env and url (config reference, developers.openai.com,
// 2026-09-12). ponytail: a line parser for just that shape; strings,
// string arrays and inline/sub tables. Not a TOML parser.
func loadCodex(file, scope string) []Server {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	type entry struct {
		raw rawServer
		env map[string]string
	}
	entries := map[string]*entry{}
	var order []string
	cur, sub := "", "" // current server id, and "env" when inside [mcp_servers.x.env]
	get := func(id string) *entry {
		if entries[id] == nil {
			entries[id] = &entry{env: map[string]string{}}
			order = append(order, id)
		}
		return entries[id]
	}
	lines := strings.Split(string(data), "\n")
	for n := 0; n < len(lines); n++ {
		line := strings.TrimSpace(stripComment(lines[n]))
		if line == "" {
			continue
		}
		// A value whose array opens on this line may close on a later one.
		for strings.Count(line, "[") > strings.Count(line, "]") && !strings.HasPrefix(line, "[") && n+1 < len(lines) {
			n++
			line += " " + strings.TrimSpace(stripComment(lines[n]))
		}
		if strings.HasPrefix(line, "[") {
			cur, sub = "", ""
			name := strings.Trim(line, "[]")
			if !strings.HasPrefix(name, "mcp_servers.") {
				continue
			}
			rest := strings.TrimPrefix(name, "mcp_servers.")
			id, tail := splitTomlKey(rest)
			cur = id
			if tail == "env" {
				sub = "env"
			}
			get(cur)
			continue
		}
		if cur == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		e := get(cur)
		if sub == "env" {
			e.env[unquote(k)] = unquote(v)
			continue
		}
		switch k {
		case "command":
			e.raw.Command = unquote(v)
		case "url":
			e.raw.URL = unquote(v)
		case "args":
			e.raw.Args = tomlStrings(v)
		case "env":
			for _, kv := range splitTop(strings.Trim(v, "{}"), ',') {
				ek, ev, ok := strings.Cut(kv, "=")
				if ok {
					e.env[unquote(strings.TrimSpace(ek))] = unquote(strings.TrimSpace(ev))
				}
			}
		}
	}
	var out []Server
	for _, id := range order {
		e := entries[id]
		if len(e.env) > 0 {
			e.raw.Env = e.env
		}
		out = append(out, e.raw.toServer("codex", scope, id, file))
	}
	return out
}

// splitTomlKey splits `foo.env` / `"my server".env` into (id, tail).
func splitTomlKey(s string) (string, string) {
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			id := s[1 : end+1]
			return id, strings.TrimPrefix(s[end+2:], ".")
		}
	}
	id, tail, _ := strings.Cut(s, ".")
	return id, tail
}

// stripComment drops a trailing # comment, ignoring # inside "..." or '...'.
func stripComment(line string) string {
	var quote rune
	for i, c := range line {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func tomlStrings(v string) []string {
	var out []string
	for _, x := range splitTop(strings.Trim(strings.TrimSpace(v), "[]"), ',') {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, unquote(x))
		}
	}
	return out
}

// splitTop splits on sep outside double quotes.
func splitTop(s string, sep rune) []string {
	var out []string
	cur, inStr := "", false
	for _, c := range s {
		switch {
		case c == '"':
			inStr = !inStr
			cur += string(c)
		case c == sep && !inStr:
			out = append(out, cur)
			cur = ""
		default:
			cur += string(c)
		}
	}
	if strings.TrimSpace(cur) != "" {
		out = append(out, cur)
	}
	return out
}
