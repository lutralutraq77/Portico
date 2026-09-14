// Package agent serves bounded local client operations over OS-protected IPC.
// It owns no authority beyond the selected device's existing client identity.
package agent

import (
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/control"
)

const Version = 1
const MaxMessage = 64 * 1024
const maxConnections = 8
const operationTimeout = 5 * time.Second
const clientTimeout = 10 * time.Second
const unlockLifetime = 15 * time.Minute

var ErrRejected = errors.New("local agent operation rejected")

func validRequest(r *pb.CatalogRequest) bool {
	return r != nil && r.Version == Version && len(r.ProtoReflect().GetUnknown()) == 0
}

func encodeCatalog(resources []control.ResourceAccess) (*pb.CatalogResponse, error) {
	if resources == nil || len(resources) > control.MaxCatalogResources {
		return nil, ErrRejected
	}
	r := &pb.CatalogResponse{Version: Version}
	seen := make(map[string]bool, len(resources))
	for _, v := range resources {
		if !v.Valid() || seen[v.ID] {
			return nil, ErrRejected
		}
		seen[v.ID] = true
		r.Resources = append(r.Resources, &pb.Resource{Id: v.ID, Revision: v.Revision, Name: v.Name, ConnectorId: v.ConnectorID, ConnectorName: v.ConnectorName, Address: v.Address, Protocol: v.Protocol, Port: uint32(v.Port), Until: v.Until.UTC().Format(time.RFC3339Nano)})
	}
	if proto.Size(r) > MaxMessage {
		return nil, ErrRejected
	}
	return r, nil
}

func decodeCatalog(r *pb.CatalogResponse) ([]control.ResourceAccess, error) {
	if r == nil || r.Version != Version || len(r.ProtoReflect().GetUnknown()) != 0 || len(r.Resources) > control.MaxCatalogResources || proto.Size(r) > MaxMessage {
		return nil, ErrRejected
	}
	resources := make([]control.ResourceAccess, 0, len(r.Resources))
	seen := make(map[string]bool, len(r.Resources))
	for _, v := range r.Resources {
		if v == nil || len(v.ProtoReflect().GetUnknown()) != 0 || v.Port > 65535 || len(v.Until) > 40 {
			return nil, ErrRejected
		}
		until, err := time.Parse(time.RFC3339Nano, v.Until)
		if err != nil || until.UTC().Format(time.RFC3339Nano) != v.Until {
			return nil, ErrRejected
		}
		entry := control.ResourceAccess{ID: v.Id, Revision: v.Revision, Name: v.Name, ConnectorID: v.ConnectorId, ConnectorName: v.ConnectorName, Address: v.Address, Protocol: v.Protocol, Port: int(v.Port), Until: until}
		if !entry.Valid() || seen[entry.ID] {
			return nil, ErrRejected
		}
		seen[entry.ID] = true
		resources = append(resources, entry)
	}
	return resources, nil
}
