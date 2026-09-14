//go:build linux

package controller

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

// Read-only observations of the disposable guest. Do not infer host-wide
// invariance merely from successful forwarding or a source-code search.
func applicationNetworkSnapshot(t *testing.T) map[string]string {
	t.Helper()
	requireArchApplicationGuest(t)
	snapshot := make(map[string]string)
	for _, path := range []string{"/etc/resolv.conf", "/etc/hosts", "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/forwarding"} {
		data, err := os.ReadFile(path)
		must(t, err)
		snapshot[path] = string(data)
	}
	for _, family := range []string{"-4", "-6"} {
		for _, kind := range []string{"route", "rule"} {
			args := []string{"-j", family, kind, "show"}
			if kind == "route" {
				args = append(args, "table", "all")
			}
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			data, err := exec.CommandContext(call, "/usr/bin/ip", args...).Output()
			cancel()
			must(t, err)
			var rows []json.RawMessage
			must(t, json.Unmarshal(data, &rows))
			canonical := make([]string, len(rows))
			for i, row := range rows {
				var fields map[string]any
				must(t, json.Unmarshal(row, &fields))
				encoded, err := json.Marshal(fields)
				must(t, err)
				canonical[i] = string(encoded)
			}
			sort.Strings(canonical)
			snapshot[family+" "+kind] = strings.Join(canonical, "\n")
		}
	}
	return snapshot
}
