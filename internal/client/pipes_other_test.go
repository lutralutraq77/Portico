//go:build !linux

package client

import "testing"

func TestApplicationPipesFailOnUnqualifiedPlatforms(t *testing.T) {
	if in, out, e := OpenPipes(nil, nil); e != ErrConfiguration || in != nil || out != nil {
		t.Fatal("unqualified platform accepted application pipes")
	}
}
