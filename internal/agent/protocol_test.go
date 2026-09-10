package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/control"
)

func resource() control.ResourceAccess {
	return control.ResourceAccess{ID: "fd320721-e047-4f32-9f4b-2a7686156b87", Revision: 3, Name: "fixture", ConnectorID: "a4401050-48ef-4d65-a693-194770e247ab", ConnectorName: "connector", Address: "192.0.2.10", Protocol: "tcp", Port: 443, Until: time.Date(2026, 9, 11, 12, 0, 0, 123, time.UTC)}
}

func TestCatalogProtocolRejectsMalformedInventory(t *testing.T) {
	good, err := encodeCatalog([]control.ResourceAccess{resource()})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCatalog(good)
	if err != nil || len(decoded) != 1 || decoded[0] != resource() {
		t.Fatal("catalog changed exact inventory")
	}
	for _, name := range []string{"nil", "version", "future_response", "nil_resource", "future_resource", "duplicate", "too_many", "id", "revision", "name", "connector", "address", "mapped_address", "protocol", "port_zero", "port_overflow", "until", "until_offset", "until_oversized"} {
		t.Run(name, func(t *testing.T) {
			r := proto.Clone(good).(*pb.CatalogResponse)
			switch name {
			case "nil":
				r = nil
			case "version":
				r.Version++
			case "future_response":
				r.ProtoReflect().SetUnknown([]byte{0x18, 1})
			case "nil_resource":
				r.Resources[0] = nil
			case "future_resource":
				r.Resources[0].ProtoReflect().SetUnknown([]byte{0x50, 1})
			case "duplicate":
				r.Resources = append(r.Resources, r.Resources[0])
			case "too_many":
				for len(r.Resources) <= control.MaxCatalogResources {
					r.Resources = append(r.Resources, r.Resources[0])
				}
			case "id":
				r.Resources[0].Id = "192.0.2.10:443"
			case "revision":
				r.Resources[0].Revision = 0
			case "name":
				r.Resources[0].Name = strings.Repeat("s", 129)
			case "connector":
				r.Resources[0].ConnectorId = "invalid"
			case "address":
				r.Resources[0].Address = "localhost"
			case "mapped_address":
				r.Resources[0].Address = "::ffff:192.0.2.10"
			case "protocol":
				r.Resources[0].Protocol = "udp"
			case "port_zero":
				r.Resources[0].Port = 0
			case "port_overflow":
				r.Resources[0].Port = 1 << 31
			case "until":
				r.Resources[0].Until = "not a time"
			case "until_offset":
				r.Resources[0].Until = "2026-09-11T12:00:00+00:00"
			case "until_oversized":
				r.Resources[0].Until = strings.Repeat("s", 41)
			}
			if v, err := decodeCatalog(r); v != nil || !errors.Is(err, ErrRejected) {
				t.Fatal("malformed response accepted")
			}
		})
	}
	for _, rows := range [][]control.ResourceAccess{nil, {resource(), resource()}, {{ID: "bad"}}, make([]control.ResourceAccess, control.MaxCatalogResources+1)} {
		if r, err := encodeCatalog(rows); r != nil || !errors.Is(err, ErrRejected) {
			t.Fatal("malformed backend inventory encoded")
		}
	}
	empty, err := encodeCatalog([]control.ResourceAccess{})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := decodeCatalog(empty); err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty inventory is not an explicit empty list")
	}
}

func TestCatalogRequestVersionAndUnknownFields(t *testing.T) {
	if !validRequest(&pb.CatalogRequest{Version: Version}) {
		t.Fatal("valid request rejected")
	}
	unknown := &pb.CatalogRequest{Version: Version}
	unknown.ProtoReflect().SetUnknown([]byte{0x10, 1})
	for _, r := range []*pb.CatalogRequest{nil, {}, {Version: 2}, unknown} {
		if validRequest(r) {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestUnlockWindowIncludesElapsedSuspendAndNeverReopens(t *testing.T) {
	for _, mode := range []string{"expiry", "backward", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Hour
			var clockErr error
			w, err := makeWindow(func() (time.Duration, error) { return now, clockErr })
			if err != nil {
				t.Fatal(err)
			}
			now += time.Second
			if !w.valid() {
				t.Fatal("healthy clock rejected")
			}
			switch mode {
			case "expiry":
				now += unlockLifetime
			case "backward":
				now -= time.Nanosecond
			case "unavailable":
				clockErr = errors.New("unavailable")
			}
			if w.valid() {
				t.Fatal("unsafe window remained open")
			}
			now = time.Hour + 2*time.Second
			clockErr = nil
			if w.valid() {
				t.Fatal("closed window reopened")
			}
		})
	}
	if w, err := makeWindow(func() (time.Duration, error) { return -1, nil }); w != nil || err == nil {
		t.Fatal("negative initial clock accepted")
	}
}

func TestAgentInvalidContextNeverOpensTransport(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if rows, err := Catalog(ctx, "/unused"); rows != nil || !errors.Is(err, ErrRejected) {
			t.Fatal("invalid context accepted")
		}
		if err := run(ctx, "/unused", backendFunc(func(context.Context) ([]control.ResourceAccess, error) { t.Fatal("backend called"); return nil, nil })); !errors.Is(err, ErrRejected) {
			t.Fatal("invalid agent context accepted")
		}
	}
	if err := Run(context.Background(), "/unused", nil); !errors.Is(err, ErrRejected) {
		t.Fatal("nil configuration accepted")
	}
}

type backendFunc func(context.Context) ([]control.ResourceAccess, error)

func (b backendFunc) Catalog(ctx context.Context) ([]control.ResourceAccess, error) { return b(ctx) }

func FuzzAgentCatalog(f *testing.F) {
	r, err := encodeCatalog([]control.ResourceAccess{resource()})
	if err != nil {
		f.Fatal(err)
	}
	b, err := proto.Marshal(r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{8, 1})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxMessage {
			return
		}
		var r pb.CatalogResponse
		if proto.Unmarshal(b, &r) != nil {
			return
		}
		rows, err := decodeCatalog(&r)
		if err != nil {
			return
		}
		encoded, err := encodeCatalog(rows)
		if err != nil || !proto.Equal(&r, encoded) {
			t.Fatal("accepted inventory changed across decode/encode")
		}
	})
}
