package adminbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"portico.local/portico/internal/testfixture"
)

type pipeFixture struct {
	peer   net.Conn
	done   chan struct{}
	result error
	cancel context.CancelFunc
}

func pipeSeed(t *testing.T, c *Client) *pipeFixture {
	t.Helper()
	local, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	f := &pipeFixture{peer: peer, done: make(chan struct{}), cancel: cancel}
	state := t.TempDir()
	go func() { f.result = Serve(ctx, c, local, local, state); close(f.done) }()
	t.Cleanup(func() { cancel(); _ = peer.Close(); _ = f.join(t) })
	return f
}

func (f *pipeFixture) join(t *testing.T) error {
	t.Helper()
	select {
	case <-f.done:
		return f.result
	case <-time.After(3 * time.Second):
		t.Fatal("pipe worker did not terminate")
		return nil
	}
}

func (f *pipeFixture) hello(t *testing.T, origin string) {
	t.Helper()
	var hello Hello
	testfixture.Must(t, readHeader(f.peer, &hello))
	if hello.Version != 1 || hello.Origin != origin || hello.StateDirectory == "" {
		t.Fatal("invalid public greeting")
	}
}

func pipeResponse(t *testing.T, in io.Reader) (PipeResponse, []byte) {
	t.Helper()
	var h PipeResponse
	testfixture.Must(t, readHeader(in, &h))
	if h.Length < 0 || h.Length > MaxResponse {
		t.Fatal("unbounded response")
	}
	body := make([]byte, h.Length)
	_, err := io.ReadFull(in, body)
	testfixture.Must(t, err)
	return h, body
}

func TestPrivatePipeRoundTripAndExplicitClose(t *testing.T) {
	body := bytes.Repeat([]byte("asset"), 16000)
	f := bridgeSeed(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	c := f.client(t)
	p := pipeSeed(t, c)
	p.hello(t, c.Origin())
	testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 1, Method: "GET", Path: "/admin"}, nil))
	h, got := pipeResponse(t, p.peer)
	if h.Failed || h.Status != 200 || h.ID != 1 || !bytes.Equal(got, body) {
		t.Fatal("large asset corrupted by framing")
	}
	testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 2, Method: "POST", Path: "/unavailable", Length: 2}, []byte("{}")))
	h, got = pipeResponse(t, p.peer)
	if !h.Failed || h.Status != 0 || len(got) != 0 || h.Headers != nil {
		t.Fatal("rejected request disclosed a response")
	}
	testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 3, Close: true}, nil))
	h, got = pipeResponse(t, p.peer)
	if h.Status != 204 || h.Failed || len(got) != 0 {
		t.Fatal("invalid close acknowledgment")
	}
	testfixture.Must(t, p.join(t))
	if f.hits.Load() != 1 {
		t.Fatal("invalid request or close reached network")
	}
}

func TestPrivatePipeRejectsMalformedFrames(t *testing.T) {
	c := bridgeSeed(t, nil).client(t)
	for name, raw := range map[string]string{
		"duplicate_id":       `{"Version":1,"ID":1,"id":2}`,
		"unknown_field":      `{"Version":1,"ID":1,"URL":"https://foreign.test"}`,
		"wrong_version":      `{"Version":2,"ID":1}`,
		"wrong_id":           `{"Version":1,"ID":2}`,
		"negative_body":      `{"Version":1,"ID":1,"Length":-1}`,
		"oversized_body":     `{"Version":1,"ID":1,"Length":65537}`,
		"close_with_request": `{"Version":1,"ID":1,"Close":true,"Method":"GET"}`,
		"close_with_body":    `{"Version":1,"ID":1,"Close":true,"Length":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := pipeSeed(t, c)
			p.hello(t, c.Origin())
			packet := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
			packet = append(packet, raw...)
			_, err := p.peer.Write(packet)
			testfixture.Must(t, err)
			if p.join(t) == nil {
				t.Fatal("malformed packet accepted")
			}
		})
	}
	for _, n := range []uint32{0, maxHeader + 1, ^uint32(0)} {
		p := pipeSeed(t, c)
		p.hello(t, c.Origin())
		_, err := p.peer.Write(binary.BigEndian.AppendUint32(nil, n))
		testfixture.Must(t, err)
		if p.join(t) == nil {
			t.Fatal("unbounded header accepted")
		}
	}
}

func TestPrivatePipeCancellationInterruptsBlockedIO(t *testing.T) {
	c := bridgeSeed(t, nil).client(t)
	for _, scenario := range []string{"greeting_write", "header_read", "body_read", "response_write"} {
		t.Run(scenario, func(t *testing.T) {
			p := pipeSeed(t, c)
			if scenario != "greeting_write" {
				p.hello(t, c.Origin())
			}
			if scenario == "body_read" {
				testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 1, Method: "POST", Path: "/api/v1/admin/policy/confirm", Length: 8}, []byte("{")))
			}
			if scenario == "response_write" {
				testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 1, Method: "GET", Path: "/admin"}, nil))
			}
			p.cancel()
			if p.join(t) == nil {
				t.Fatal("cancelled pipe reported clean shutdown")
			}
		})
	}
}

func TestWindowsShellPreambleIsOnlyAcceptedOnce(t *testing.T) {
	var packet bytes.Buffer
	testfixture.Must(t, writePacket(&packet, PipeRequest{Version: 1, ID: 1}, nil))
	for _, prefix := range []string{"", "\r\n", "\n", "\r\n\r\n", "garbage"} {
		r := &shellOutput{Reader: bufio.NewReader(io.MultiReader(bytes.NewBufferString(prefix), bytes.NewReader(packet.Bytes()))), Closer: io.NopCloser(bytes.NewReader(nil))}
		var h PipeRequest
		err := readHeader(r, &h)
		if (err == nil) != (prefix == "" || prefix == "\r\n") {
			t.Errorf("unexpected preamble result: %q", prefix)
		}
	}
	stream := append(bytes.Clone(packet.Bytes()), '\r', '\n')
	stream = append(stream, packet.Bytes()...)
	r := &shellOutput{Reader: bufio.NewReader(bytes.NewReader(stream)), Closer: io.NopCloser(bytes.NewReader(nil))}
	var h PipeRequest
	testfixture.Must(t, readHeader(r, &h))
	if readHeader(r, &h) == nil {
		t.Fatal("resynchronized after malformed later frame")
	}
}
