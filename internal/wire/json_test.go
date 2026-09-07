package wire

import (
	"strings"
	"testing"
)

type message struct {
	Version int
	Nested  *message
}

func TestStrictControlJSON(t *testing.T) {
	for _, body := range []string{``, `null`, `[]`, `1`, `{} {}`, `{"Unknown":1}`, `{"Version":1,"Version":2}`, `{"Version":1,"version":2}`, `{"Version":1,"\u0056ersion":2}`, `{"Nested":{"Version":1,"version":2}}`, `{"Version":"1"}`, `{"Version":1e1000}`, strings.Repeat(`{"Nested":`, 26) + `{}` + strings.Repeat(`}`, 26), `{"Version":1}` + strings.Repeat(" ", MaxBody)} {
		var m message
		if Decode([]byte(body), &m) == nil {
			t.Fatalf("accepted ambiguous/invalid message %.80q", body)
		}
	}
	var m message
	if Decode([]byte(`{"Version":1,"Nested":{"Version":2}}`), &m) != nil || m.Version != 1 || m.Nested == nil || m.Nested.Version != 2 {
		t.Fatal("valid control message rejected")
	}
}
func FuzzControlJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"Version":1}`, `{"Version":1,"version":2}`, `{"Nested":{"Version":2}}`, `null`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { var m message; _ = Decode([]byte(s), &m) })
}
