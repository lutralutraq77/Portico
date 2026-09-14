package agent

import (
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/pki"
)

const maxChunk = 32 * 1024

func frame(kind pb.TunnelFrame_Kind) *pb.TunnelFrame {
	return &pb.TunnelFrame{Version: Version, Kind: kind}
}

func validFrame(r *pb.TunnelFrame, kind pb.TunnelFrame_Kind) bool {
	if r == nil || r.Version != Version || r.Kind != kind || len(r.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	if kind == pb.TunnelFrame_OPEN {
		return pki.ValidID(r.ResourceId) && r.Revision > 0 && len(r.Data) == 0
	}
	if r.ResourceId != "" || r.Revision != 0 {
		return false
	}
	switch kind {
	case pb.TunnelFrame_DATA:
		return len(r.Data) > 0 && len(r.Data) <= maxChunk
	case pb.TunnelFrame_READY, pb.TunnelFrame_FIN:
		return len(r.Data) == 0
	default:
		return false
	}
}
