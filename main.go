// mcp-exposure lists the MCP servers registered in the AI clients on this
// machine (Claude Code, Claude Desktop, Cursor, VS Code, Gemini CLI) and
// reports how each one is exposed: unpinned packages fetched at every
// start, plaintext secrets in config files, plaintext remote transports,
// and local HTTP servers bound to all interfaces or accepting a foreign
// Host header.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

type Result struct {
	Server
	Findings []Finding `json:"findings"`
	Verdict  string    `json:"verdict"` // ok | WARN | RED
}

func main() {
	asJSON := flag.Bool("json", false, "output JSON")
	extra := flag.String("config", "", "extra mcpServers JSON file to read")
	flag.Parse()

	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	srcs := sources(cwd, home)
	if *extra != "" {
		srcs = append(srcs, source{"extra", "file", *extra, "mcpServers"})
	}
	servers, err := load(srcs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	addrs := localAddrs()
	var results []Result
	for _, s := range servers {
		r := Result{Server: s, Findings: check(s)}
		if s.Transport != "stdio" {
			if u, err := url.Parse(s.URL); err == nil && isLoopbackHost(u.Hostname()) {
				r.Findings = append(r.Findings, probeLocal(s, addrs)...)
			}
		}
		r.Verdict = verdict(r.Findings)
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		return a.Name < b.Name
	})

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(results)
	} else {
		printTable(results)
	}
	for _, r := range results {
		if r.Verdict == "RED" {
			os.Exit(1)
		}
	}
}

func verdict(fs []Finding) string {
	v := "ok"
	for _, f := range fs {
		switch f.Level {
		case "red":
			return "RED"
		case "warn":
			v = "WARN"
		}
	}
	return v
}

func target(s Server) string {
	if s.Transport == "stdio" {
		return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
	}
	return s.URL
}

func printTable(results []Result) {
	if len(results) == 0 {
		fmt.Println("no MCP servers found in known config files")
		return
	}
	fmt.Printf("%-14s %-8s %-18s %-6s %-40s %-32s %s\n", "CLIENT", "SCOPE", "NAME", "TYPE", "TARGET", "FINDINGS", "VERDICT")
	for _, r := range results {
		var codes []string
		for _, f := range r.Findings {
			codes = append(codes, f.Code)
		}
		fs := strings.Join(codes, ",")
		if fs == "" {
			fs = "-"
		}
		fmt.Printf("%-14s %-8s %-18s %-6s %-40s %-32s %s\n",
			r.Client, r.Scope, trunc(r.Name, 18), r.Transport, trunc(target(r.Server), 40), trunc(fs, 32), r.Verdict)
	}
	fmt.Println()
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Level != "info" {
				fmt.Printf("%s/%s: %s: %s\n", r.Client, r.Name, f.Code, f.Note)
			}
		}
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
