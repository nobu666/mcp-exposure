package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// --suggest: for each UNPINNED finding, ask the package registry for the
// latest version and print the pinned form. Off by default because it
// sends the package name to npm or PyPI.

type release struct {
	Version string
	Date    string // YYYY-MM-DD
}

// lookup is a variable so tests can replace it.
var lookup = registryLookup

var registryClient = &http.Client{Timeout: 5 * time.Second}

func ecosystemOf(cmd string) string {
	switch filepath.Base(cmd) {
	case "npx", "bunx", "pnpm":
		return "npm"
	case "uvx", "pipx":
		return "pypi"
	}
	return ""
}

// bareName strips any version spec: name@1.x, name==1.0, name>=1.
func bareName(eco, pkg string) string {
	if eco == "npm" {
		if i := strings.LastIndex(pkg, "@"); i > 0 {
			return pkg[:i]
		}
		return pkg
	}
	if i := strings.IndexAny(pkg, "=<>!~@["); i > 0 {
		return pkg[:i]
	}
	return pkg
}

func registryLookup(eco, name string) (release, error) {
	switch eco {
	case "npm":
		var doc struct {
			Tags map[string]string `json:"dist-tags"`
			Time map[string]string `json:"time"`
		}
		if err := getJSON("https://registry.npmjs.org/"+url.PathEscape(name), &doc); err != nil {
			return release{}, err
		}
		v := doc.Tags["latest"]
		if v == "" {
			return release{}, errors.New("no latest tag")
		}
		return release{v, day(doc.Time[v])}, nil
	case "pypi":
		var doc struct {
			Info     struct{ Version string }
			Releases map[string][]struct {
				Upload string `json:"upload_time_iso_8601"`
			}
		}
		if err := getJSON("https://pypi.org/pypi/"+url.PathEscape(name)+"/json", &doc); err != nil {
			return release{}, err
		}
		v := doc.Info.Version
		d := ""
		if files := doc.Releases[v]; len(files) > 0 {
			d = day(files[0].Upload)
		}
		return release{v, d}, nil
	}
	return release{}, errors.New("unknown ecosystem")
}

func getJSON(u string, v any) error {
	resp, err := registryClient.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(u + ": " + resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// suggest appends the pinned form to every UNPINNED finding of s.
func suggest(s Server, fs []Finding) {
	pkg, ok := unpinned(s.Command, s.Args)
	if !ok {
		return
	}
	eco := ecosystemOf(s.Command)
	name := bareName(eco, pkg)
	rel, err := lookup(eco, name)
	for i := range fs {
		if fs[i].Code != "UNPINNED" {
			continue
		}
		if err != nil {
			fs[i].Note += "; registry lookup failed: " + err.Error()
			continue
		}
		sep := "@"
		if eco == "pypi" {
			sep = "=="
		}
		fs[i].Note += "; latest is " + rel.Version + " (" + rel.Date + "), pin as " + name + sep + rel.Version
	}
}
