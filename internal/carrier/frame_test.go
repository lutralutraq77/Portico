package carrier

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "portico.local/portico/internal/carrierpb"
)

// Fuzz the actual protobuf decoder and the trust boundary together. Unknown
// fields must survive decoding so the validator can reject them, rather than
// silently interpreting future protocol messages as this version.
func FuzzCarrierFrames(f *testing.F) {
	id := "c0534d16-7689-4a93-a44a-e716e8586a15"
	for _, frame := range []*pb.Frame{
		{},
		{Version: Version, Kind: pb.Kind_KIND_HELLO, ConnectorId: id, StreamId: bytes.Repeat([]byte{1}, 32)},
		{Version: Version, Kind: pb.Kind_KIND_READY, ConnectorId: id, StreamId: bytes.Repeat([]byte{2}, 32)},
		{Version: Version, Kind: pb.Kind_KIND_DATA, Data: []byte("ciphertext fixture")},
		{Version: Version, Kind: pb.Kind_KIND_DATA, Data: make([]byte, MaxData)},
		{Version: Version, Kind: pb.Kind_KIND_DATA, Data: make([]byte, MaxData+1)},
	} {
		b, e := proto.Marshal(frame)
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b)
	}
	f.Add([]byte{8, 1, 16, 3, 34, 1, 1, 48, 1}) // DATA with a future field.
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxMessage {
			return
		}
		var frame pb.Frame
		if proto.Unmarshal(b, &frame) != nil {
			return
		}
		connector := ""
		if frame.Kind == pb.Kind_KIND_HELLO || frame.Kind == pb.Kind_KIND_READY {
			connector = frame.ConnectorId
		}
		if !valid(&frame, frame.Kind, connector) {
			return
		}
		if frame.Kind != pb.Kind_KIND_HELLO && frame.Kind != pb.Kind_KIND_READY && frame.Kind != pb.Kind_KIND_DATA {
			t.Fatal("unknown message kind accepted")
		}
		encoded, e := proto.Marshal(&frame)
		if e != nil {
			t.Fatal(e)
		}
		var again pb.Frame
		if proto.Unmarshal(encoded, &again) != nil || !valid(&again, frame.Kind, connector) || !proto.Equal(&frame, &again) {
			t.Fatal("accepted message changed meaning during transport")
		}
		again.ProtoReflect().SetUnknown([]byte{0x30, 1})
		encoded, e = proto.Marshal(&again)
		if e != nil {
			t.Fatal(e)
		}
		var future pb.Frame
		if proto.Unmarshal(encoded, &future) != nil {
			t.Fatal("invalid future-field fixture")
		}
		if valid(&future, frame.Kind, connector) {
			t.Fatal("future field was silently discarded")
		}
	})
}
