package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicationArguments(t *testing.T) {
	dir := t.TempDir()
	base := Application{AgentSocket: filepath.Join(dir, "agent"), Endpoint: filepath.Join(dir, "application"), ResourceID: "59d73719-4dc0-4d8c-898e-aa2f9466a89e", Revision: 1, Argv: []string{filepath.Join(dir, "program"), "{socket}", "literal $() ; whitespace", ""}}
	args, err := base.arguments()
	if err != nil || args[1] != base.Endpoint || args[2] != base.Argv[2] || args[3] != "" || base.Argv[1] != "{socket}" {
		t.Fatal("literal argument handling changed")
	}
	for name, change := range map[string]func(*Application){
		"relative_agent":      func(a *Application) { a.AgentSocket = "relative" },
		"abstract_endpoint":   func(a *Application) { a.Endpoint = "\x00abstract" },
		"same_endpoint":       func(a *Application) { a.Endpoint = a.AgentSocket },
		"bad_identity":        func(a *Application) { a.ResourceID = "192.0.2.10:443" },
		"zero_revision":       func(a *Application) { a.Revision = 0 },
		"missing_command":     func(a *Application) { a.Argv = nil },
		"path_lookup":         func(a *Application) { a.Argv[0] = "curl" },
		"missing_placeholder": func(a *Application) { a.Argv[1] = "--socket={socket}" },
		"nul_argument":        func(a *Application) { a.Argv[2] = "bad\x00argument" },
		"too_many_arguments":  func(a *Application) { a.Argv = append(a.Argv, make([]string, 64)...) },
		"oversized_argument":  func(a *Application) { a.Argv[2] = strings.Repeat("x", 32*1024) },
	} {
		t.Run(name, func(t *testing.T) {
			a := base
			a.Argv = append([]string(nil), base.Argv...)
			change(&a)
			if _, err := a.arguments(); err == nil {
				t.Fatal("unsafe or ambiguous command accepted")
			}
		})
	}
}
