package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Claude Code plugins can bring their own MCP servers, declared in
// <installPath>/.claude-plugin/plugin.json (mcpServers) or
// <installPath>/.mcp.json. Installed plugins and their paths are in
// ~/.claude/plugins/installed_plugins.json. Which ones are enabled comes
// from enabledPlugins in the settings files, user level first and the
// project's own last, so a project can turn a plugin on or off.
// ${CLAUDE_PLUGIN_ROOT} means the install path.
func loadPlugins(home, cwd string) []Server {
	var installed struct {
		Plugins map[string][]struct {
			Scope       string `json:"scope"`
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if data, err := os.ReadFile(filepath.Join(home, ".claude", "plugins", "installed_plugins.json")); err != nil || json.Unmarshal(data, &installed) != nil {
		return nil
	}
	enabled := map[string]bool{}
	for _, f := range []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(cwd, ".claude", "settings.json"),
		filepath.Join(cwd, ".claude", "settings.local.json"),
	} {
		var settings struct {
			Enabled map[string]bool `json:"enabledPlugins"`
		}
		if data, err := os.ReadFile(f); err == nil && json.Unmarshal(data, &settings) == nil {
			for k, v := range settings.Enabled {
				enabled[k] = v
			}
		}
	}
	var out []Server
	for name, installs := range installed.Plugins {
		if !enabled[name] || len(installs) == 0 {
			continue
		}
		// ponytail: with both a project and a user install, prefer the
		// project one; the file does not say which project it belongs to.
		root := installs[0].InstallPath
		for _, in := range installs {
			if in.Scope == "project" {
				root = in.InstallPath
			}
		}
		for _, file := range []string{filepath.Join(root, ".claude-plugin", "plugin.json"), filepath.Join(root, ".mcp.json")} {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			var doc map[string]json.RawMessage
			if json.Unmarshal(data, &doc) != nil {
				continue
			}
			for _, s := range parseServers(doc["mcpServers"], "claude-code", "plugin:"+strings.SplitN(name, "@", 2)[0], file) {
				s.Command = strings.ReplaceAll(s.Command, "${CLAUDE_PLUGIN_ROOT}", root)
				for i := range s.Args {
					s.Args[i] = strings.ReplaceAll(s.Args[i], "${CLAUDE_PLUGIN_ROOT}", root)
				}
				out = append(out, s)
			}
		}
	}
	return out
}
