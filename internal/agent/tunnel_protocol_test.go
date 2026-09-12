package agent

import (
	"testing"

	"google.golang.org/protobuf/proto"
	pb "portico.local/portico/internal/agentpb"
)

func FuzzAgentTunnel(f *testing.F) {
	for _, kind := range []pb.TunnelFrame_Kind{pb.TunnelFrame_OPEN, pb.TunnelFrame_READY, pb.TunnelFrame_DATA, pb.TunnelFrame_FIN} {
		r := frame(kind)
		if kind == pb.TunnelFrame_OPEN {
			r.ResourceId, r.Revision = resource().ID, resource().Revision
		}
		if kind == pb.TunnelFrame_DATA {
			r.Data = []byte{0, 0xff, '\n'}
		}
		data, err := proto.Marshal(r)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMessage {
			return
		}
		var r pb.TunnelFrame
		if proto.Unmarshal(data, &r) != nil {
			return
		}
		accepted := 0
		for _, kind := range []pb.TunnelFrame_Kind{pb.TunnelFrame_OPEN, pb.TunnelFrame_READY, pb.TunnelFrame_DATA, pb.TunnelFrame_FIN} {
			if !validFrame(&r, kind) {
				continue
			}
			accepted++
			if len(r.Data) > maxChunk || proto.Size(&r) > MaxMessage || len(r.ProtoReflect().GetUnknown()) != 0 {
				t.Fatal("unbounded/future frame accepted")
			}
			copy := proto.Clone(&r).(*pb.TunnelFrame)
			copy.ProtoReflect().SetUnknown([]byte{0x30, 1})
			if validFrame(copy, kind) {
				t.Fatal("unknown field accepted")
			}
			copy = proto.Clone(&r).(*pb.TunnelFrame)
			copy.Version++
			if validFrame(copy, kind) {
				t.Fatal("future version accepted")
			}
		}
		if accepted > 1 {
			t.Fatal("ambiguous frame type")
		}
	})
}
