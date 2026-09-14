package controller

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
	"portico.local/portico/internal/carrier"
	pb "portico.local/portico/internal/carrierpb"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

const hostileCanary = "protocol-fixture-private-canary-91"

// This component entry runs on both hosted platforms. The guest acceptance
// entry also composes these boundaries with an independent live TCP workload.
func TestProtocolHostileControlInputs(t *testing.T) {
	t.Run("csr_enrollment", hostileCSREnrollment)
	t.Run("https_bodies", hostilePolicyBodies)
	t.Run("http2_carrier", func(t *testing.T) {
		f := newCarrierFixture(t, hostileCarrierLimits)
		hostileHTTP2Carrier(t, f, func(t *testing.T) {})
	})
}

func hostileCarrierLimits(c *carrier.Config) {
	c.MaxLifetime = 2 * time.Minute
	c.HelloTimeout = 5 * time.Second
	c.PairTimeout = 30 * time.Second
}

func hostileCSREnrollment(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.invite(t)
	s, actor := f.f.s, f.f.actor
	before := summary(t, s)
	bad := [][]byte{nil, bytes.Repeat([]byte{0xff}, pki.MaxCSR+1), append(bytes.Clone(v.csr), v.csr...)}
	for end := 1; end < len(v.csr); end += 7 {
		bad = append(bad, bytes.Clone(v.csr[:end]))
	}
	for bit := uint(0); bit < 8; bit++ {
		b := bytes.Clone(v.csr)
		b[len(b)-1] ^= 1 << bit
		bad = append(bad, b)
	}
	for _, claim := range []*x509.CertificateRequest{
		{Subject: pkix.Name{CommonName: hostileCanary}},
		{DNSNames: []string{hostileCanary + ".test"}},
		{ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: []byte(hostileCanary)}}},
	} {
		b, e := x509.CreateCertificateRequest(rand.Reader, claim, v.key)
		must(t, e)
		bad = append(bad, b)
	}
	for i, b := range bad {
		t.Run(fmt.Sprintf("mutation_%02d", i), func(t *testing.T) {
			if e := s.ReserveEnrollment(ctx, actor, v.id, v.secret, v.attempt, b); e != ErrInvalid {
				t.Fatal("hostile CSR did not return the fixed invalid-input error")
			}
			if e := s.IssueEnrollment(ctx, actor, v.id, f.trust, f.provider(t)); e != ErrDenied {
				t.Fatal("rejected CSR became issuable")
			}
			if der, e := s.EnrollmentCertificate(ctx, actor, v.id, v.secret, v.attempt, b); e == nil || len(der) != 0 {
				t.Fatal("rejected CSR yielded a certificate")
			}
			if f.calls.Load() != 0 || summary(t, s) != before {
				t.Fatal("rejected CSR called the signer or committed enrollment authority")
			}
		})
	}
	// Reuse the same invitation: denial must not consume it or reserve a key.
	must(t, s.ReserveEnrollment(ctx, actor, v.id, v.secret, v.attempt, v.csr))
	must(t, s.IssueEnrollment(ctx, actor, v.id, f.trust, f.provider(t)))
	der, e := s.EnrollmentCertificate(ctx, actor, v.id, v.secret, v.attempt, v.csr)
	must(t, e)
	if f.calls.Load() != 1 || len(der) == 0 {
		t.Fatal("valid CSR did not reach the real fixture CA exactly once")
	}
	t.Logf("%d hostile CSRs: unchanged enrollment/certificate state, zero signing calls; same invitation then issued once", len(bad))
}

func hostilePolicyBodies(t *testing.T) {
	v := newPolicyFixture(t)
	f := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Connector}, v.connectorIdentity)
	valid, e := json.Marshal(v.request())
	must(t, e)
	positive := func() {
		var permit Authorization
		f.post(t, "/api/v1/connector/authorize", v.request(), &permit)
		f.post(t, "/api/v1/connector/close", SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: permit.Sequence}, nil)
	}
	positive()
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	// A small compressed input expands beyond the 64 KiB policy body limit.
	_, e = z.Write(bytes.Repeat([]byte(hostileCanary), 65536))
	must(t, e)
	must(t, z.Close())
	if compressed.Len() >= wire.MaxBody {
		t.Fatal("compressed-body fixture does not fit under the wire limit")
	}
	cases := []struct {
		name, encoding string
		body           []byte
	}{
		{"gzip_expansion", "gzip", compressed.Bytes()},
		{"compressed_without_header", "", compressed.Bytes()},
		{"unsupported_encoding", "br", []byte(hostileCanary)},
		{"giant_json", "", append(bytes.Repeat([]byte(" "), wire.MaxBody+1), valid...)},
		{"nested_arrays", "", []byte(strings.Repeat("[", 1024) + `"` + hostileCanary + `"` + strings.Repeat("]", 1024))},
		{"trailing_document", "", append(bytes.Clone(valid), []byte(`{"private":"`+hostileCanary+`"}`)...)},
	}
	var fields map[string]json.RawMessage
	must(t, json.Unmarshal(valid, &fields))
	for name, value := range fields {
		for _, alias := range []string{name, strings.ToLower(name), fmt.Sprintf(`\u%04x%s`, name[0], name[1:])} {
			body := strings.TrimSuffix(string(valid), "}") + `,"` + alias + `":` + string(value) + `}`
			cases = append(cases, struct {
				name, encoding string
				body           []byte
			}{"duplicate_" + alias, "", []byte(body)})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := summary(t, v.device.f.s)
			r, e := http.NewRequest(http.MethodPost, "https://"+f.host+"/api/v1/connector/authorize", bytes.NewReader(c.body))
			must(t, e)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Private-Fixture", hostileCanary)
			if c.encoding != "" {
				r.Header.Set("Content-Encoding", c.encoding)
			}
			response, e := f.client.Do(r)
			must(t, e)
			data, e := io.ReadAll(io.LimitReader(response.Body, 1025))
			must(t, e)
			must(t, response.Body.Close())
			if response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("hostile body did not receive a bounded, uniform denial")
			}
			if strings.Contains(fmt.Sprint(response.Header), hostileCanary) || summary(t, v.device.f.s) != before {
				t.Fatal("hostile body leaked its canary or committed authority")
			}
		})
	}
	positive()
	t.Logf("%d real HTTPS body mutations denied; valid authorization and close before and after", len(cases))
}

// A deliberately small, synchronous HTTP/2 peer: bounded frame/header reads,
// no background goroutines, TLS authentication, no proxy/DNS or OS trust. It
// writes actual RST_STREAM frames, rather than inferring them from cancellation.
type hostileH2 struct {
	conn     *tls.Conn
	frames   *http2.Framer
	next     uint32
	settings bool
}

func newHostileH2(t *testing.T, c carrier.ClientConfig) *hostileH2 {
	t.Helper()
	u, e := url.Parse(c.Endpoint)
	must(t, e)
	root, e := x509.ParseCertificate(c.ServerRootDER)
	must(t, e)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	// The fixture is always IPv4 loopback. Never resolve the endpoint hostname.
	if u.Hostname() != "localhost" || u.Port() == "" {
		t.Fatal("nonlocal hostile peer fixture")
	}
	raw, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", u.Port()), 3*time.Second)
	must(t, e)
	t.Cleanup(func() { _ = raw.Close() })
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: pool, Certificates: []tls.Certificate{c.Identity}, NextProtos: []string{"h2"}})
	must(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	must(t, conn.HandshakeContext(ctx))
	if state := conn.ConnectionState(); state.NegotiatedProtocol != "h2" || pki.Hash(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != c.ServerSPKI {
		t.Fatal("wrong carrier TLS/ALPN identity")
	}
	h := &hostileH2{conn: conn, next: 1}
	h.frames = http2.NewFramer(conn, conn)
	h.frames.SetMaxReadFrameSize(16384)
	h.frames.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	h.frames.MaxHeaderListSize = 8192
	_, e = io.WriteString(conn, http2.ClientPreface)
	must(t, e)
	must(t, h.frames.WriteSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 0}))
	return h
}

func (h *hostileH2) begin(t *testing.T, encoding string) uint32 {
	t.Helper()
	must(t, h.conn.SetDeadline(time.Now().Add(5*time.Second)))
	id := h.next
	h.next += 2
	var b bytes.Buffer
	e := hpack.NewEncoder(&b)
	fields := []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: pb.Carrier_Bind_FullMethodName}, {Name: ":authority", Value: "localhost"}, {Name: "te", Value: "trailers"}, {Name: "content-type", Value: "application/grpc"}, {Name: "grpc-timeout", Value: "5S"}, {Name: "x-private-fixture", Value: hostileCanary}}
	if encoding != "" {
		fields = append(fields, hpack.HeaderField{Name: "grpc-encoding", Value: encoding})
	}
	for _, f := range fields {
		must(t, e.WriteField(f))
	}
	must(t, h.frames.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: b.Bytes(), EndHeaders: true}))
	return id
}

func grpcEnvelope(flag byte, size uint32, body []byte) []byte {
	b := make([]byte, 5+len(body))
	b[0] = flag
	binary.BigEndian.PutUint32(b[1:5], size)
	copy(b[5:], body)
	return b
}

func (h *hostileH2) readUntil(t *testing.T, accept func(http2.Frame) bool) {
	t.Helper()
	var total uint32
	for i := 0; i < 64; i++ {
		frame, e := h.frames.ReadFrame()
		must(t, e)
		total += frame.Header().Length + 9
		if total > 32768 {
			t.Fatal("hostile request produced excessive response frames")
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				h.settings = true
				must(t, h.frames.WriteSettingsAck())
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				must(t, h.frames.WritePing(true, f.Data))
			}
		case *http2.MetaHeadersFrame:
			if f.Truncated {
				t.Fatal("oversized response headers")
			}
			for _, field := range f.Fields {
				if strings.Contains(field.Value, hostileCanary) {
					t.Fatal("carrier reflected private input")
				}
			}
		case *http2.DataFrame:
			if len(f.Data()) != 0 {
				t.Fatal("hostile carrier request received protocol payload")
			}
		case *http2.GoAwayFrame:
			t.Fatalf("carrier closed the HTTP/2 connection: %v", f.ErrCode)
		}
		if accept(frame) {
			return
		}
	}
	t.Fatal("carrier did not complete within the response frame budget")
}

func (h *hostileH2) denied(t *testing.T, id uint32, expected string) {
	t.Helper()
	h.readUntil(t, func(frame http2.Frame) bool {
		f, ok := frame.(*http2.MetaHeadersFrame)
		if !ok || f.StreamID != id || !f.StreamEnded() {
			return false
		}
		if f.PseudoValue("status") != "200" || f.RegularFields() == nil {
			t.Fatal("missing gRPC rejection headers")
		}
		for _, field := range f.Fields {
			if field.Name == "grpc-status" && field.Value == expected {
				return true
			}
		}
		t.Fatalf("carrier did not explicitly reject the malformed message with status %s: %v", expected, f.Fields)
		return false
	})
}

func (h *hostileH2) reset(t *testing.T, id uint32) {
	t.Helper()
	must(t, h.frames.WriteRSTStream(id, http2.ErrCodeCancel))
	// SETTINGS acknowledgment is an ordered protocol barrier after the RST;
	// also drain the initial handshake acknowledgment before using this barrier.
	must(t, h.frames.WriteSettings())
	h.readUntil(t, func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && s.IsAck() })
}

func hostileHTTP2Carrier(t *testing.T, f *carrierFixture, healthy func(*testing.T)) {
	h := newHostileH2(t, f.connectorConfig)
	defer func() { _ = h.conn.Close() }()
	h.readUntil(t, func(frame http2.Frame) bool {
		s, ok := frame.(*http2.SettingsFrame)
		return h.settings && ok && s.IsAck()
	})
	baseline := f.relay.Stats()
	settled := func(t *testing.T) {
		// Earlier than either configured hello/pair timeout: ordinary expiry
		// must not mask failure to handle the actual reset.
		deadline := time.Now().Add(2 * time.Second)
		for {
			s := f.relay.Stats()
			if s.Streams == baseline.Streams && s.Waiting == baseline.Waiting && s.Endpoints == baseline.Endpoints && s.Watches == baseline.Watches && s.Workers == baseline.Workers {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("carrier failed to release input/reset handlers before its fallback timeouts")
			}
			time.Sleep(5 * time.Millisecond)
		}
		healthy(t)
	}
	hello, e := proto.Marshal(carrierHello(t, f.policy.device.f.connector.ID))
	must(t, e)
	// Positive control before and after: exact valid HELLO must enter the
	// actual authenticated binding queue, then actual RST must release it.
	validBind := func(t *testing.T) {
		id := h.begin(t, "")
		must(t, h.frames.WriteData(id, false, grpcEnvelope(0, uint32(len(hello)), hello)))
		carrierEventually(t, func() bool { return f.relay.Stats().Waiting == baseline.Waiting+1 })
		h.reset(t, id)
		settled(t)
	}
	validBind(t)
	cases := []struct {
		name, encoding string
		data           []byte
		status         string
	}{
		{"zero_message", "", grpcEnvelope(0, 0, nil), "7"},
		{"bad_protobuf", "", grpcEnvelope(0, 3, []byte{0xff, 0xff, 0xff}), "13"},
		{"unknown_field", "", grpcEnvelope(0, uint32(len(hello)+2), append(bytes.Clone(hello), 0x30, 1)), "7"},
		{"oversized_length", "", grpcEnvelope(0, carrier.MaxMessage+1, nil), "8"},
		{"maximum_length", "", grpcEnvelope(0, ^uint32(0), nil), "8"},
		{"truncated_message", "", grpcEnvelope(0, uint32(len(hello)), hello[:len(hello)-1]), "13"},
		{"compressed_without_encoding", "", grpcEnvelope(1, uint32(len(hello)), hello), "13"},
		{"unsupported_compression", "gzip", grpcEnvelope(1, uint32(len(hello)), hello), "12"},
		{"invalid_compression_flag", "", grpcEnvelope(2, uint32(len(hello)), hello), "13"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := f.admitted.Load()
			id := h.begin(t, c.encoding)
			must(t, h.frames.WriteData(id, true, c.data))
			h.denied(t, id, c.status)
			admissions := int64(1)
			if c.encoding != "" {
				admissions = 0
			} // gRPC rejects uninstalled compressors before invoking Bind.
			if f.admitted.Load() != before+admissions {
				t.Fatal("malformed input did not reach the authenticated carrier handler")
			}
			settled(t)
		})
	}
	for wave := 0; wave < 8; wave++ {
		for _, mode := range []string{"headers", "partial_prefix", "waiting_bind"} {
			t.Run(fmt.Sprintf("reset_%d_%s", wave, mode), func(t *testing.T) {
				before := f.admitted.Load()
				id := h.begin(t, "")
				switch mode {
				case "partial_prefix":
					must(t, h.frames.WriteData(id, false, []byte{0, 0, 0}))
				case "waiting_bind":
					must(t, h.frames.WriteData(id, false, grpcEnvelope(0, uint32(len(hello)), hello)))
				}
				carrierEventually(t, func() bool {
					s := f.relay.Stats()
					return f.admitted.Load() == before+1 && s.Streams == baseline.Streams+1 && (mode != "waiting_bind" || s.Waiting == baseline.Waiting+1)
				})
				h.reset(t, id)
				settled(t)
			})
		}
	}
	validBind(t)
	t.Log("HTTP/2 TLS positive binding controls, 9 malformed messages and 24 authenticated RST_STREAMs; bounded responses and joined handlers on the same connection")
}
