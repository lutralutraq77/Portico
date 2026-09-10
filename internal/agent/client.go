package agent

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/localipc"
)

// Catalog uses an explicit protected socket and never resolves a hostname or
// consults proxy settings. The server's actual UID is checked by localipc.Dial.
func Catalog(ctx context.Context, path string) ([]control.ResourceAccess, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	c, err := newClient(path)
	if err != nil {
		return nil, ErrRejected
	}
	defer c.Close()
	r, err := pb.NewAgentClient(c).Catalog(ctx, &pb.CatalogRequest{Version: Version})
	if err != nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	return decodeCatalog(r)
}

func newClient(path string) (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///portico-local-agent", grpc.WithTransportCredentials(local.NewCredentials()), grpc.WithNoProxy(), grpc.WithDisableServiceConfig(), grpc.WithDisableRetry(), grpc.WithMaxHeaderListSize(8192), grpc.WithStaticStreamWindowSize(64*1024), grpc.WithStaticConnWindowSize(64*1024), grpc.WithReadBufferSize(4096), grpc.WithWriteBufferSize(4096), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessage), grpc.MaxCallSendMsgSize(MaxMessage)), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return localipc.Dial(ctx, path) }))
}
