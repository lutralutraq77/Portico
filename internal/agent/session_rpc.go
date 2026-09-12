package agent

import (
	"context"
	"unicode/utf8"

	pb "portico.local/portico/internal/agentpb"
)

func validPassphrase(passphrase []byte) bool {
	return len(passphrase) >= 16 && len(passphrase) <= 1024 && utf8.Valid(passphrase)
}
func validStateRequest(r *pb.StateRequest) bool {
	return r != nil && r.Version == Version && len(r.ProtoReflect().GetUnknown()) == 0
}
func validStateResponse(r *pb.StateResponse) bool {
	return r != nil && r.Version == Version && len(r.ProtoReflect().GetUnknown()) == 0 && r.State >= pb.StateResponse_LOCKED && r.State <= pb.StateResponse_DRAINING
}
func stateResponse(state pb.StateResponse_State) *pb.StateResponse {
	return &pb.StateResponse{Version: Version, State: state}
}

func (m *manager) state() (*pb.StateResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.observeLocked(); !ok {
		return nil, ErrRejected
	}
	switch {
	case m.retiring != nil:
		return stateResponse(pb.StateResponse_DRAINING), nil
	case m.pending != nil:
		return stateResponse(pb.StateResponse_UNLOCKING), nil
	case m.active != nil:
		return stateResponse(pb.StateResponse_UNLOCKED), nil
	default:
		return stateResponse(pb.StateResponse_LOCKED), nil
	}
}

func (s *server) controlAdmission(ctx context.Context) (func(), error) {
	if s.manager == nil || ctx == nil || ctx.Err() != nil {
		return nil, rejected()
	}
	if s.requests.Add(1) > maxConnections {
		s.requests.Add(-1)
		return nil, rejected()
	}
	return func() { s.requests.Add(-1) }, nil
}
func (s *server) Status(ctx context.Context, r *pb.StateRequest) (*pb.StateResponse, error) {
	if !validStateRequest(r) {
		return nil, rejected()
	}
	release, err := s.controlAdmission(ctx)
	if err != nil {
		return nil, rejected()
	}
	defer release()
	response, err := s.manager.state()
	if err != nil {
		return nil, rejected()
	}
	return response, nil
}
func (s *server) Unlock(ctx context.Context, r *pb.UnlockRequest) (*pb.StateResponse, error) {
	if r != nil {
		defer clear(r.Passphrase)
	}
	if r == nil || r.Version != Version || len(r.ProtoReflect().GetUnknown()) != 0 || !validPassphrase(r.Passphrase) {
		return nil, rejected()
	}
	release, err := s.controlAdmission(ctx)
	if err != nil {
		return nil, rejected()
	}
	defer release()
	if s.manager.unlock(ctx, r.Passphrase) != nil {
		return nil, rejected()
	}
	return stateResponse(pb.StateResponse_UNLOCKED), nil
}
func (s *server) Lock(ctx context.Context, r *pb.StateRequest) (*pb.StateResponse, error) {
	if !validStateRequest(r) {
		return nil, rejected()
	}
	release, err := s.controlAdmission(ctx)
	if err != nil {
		return nil, rejected()
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if s.manager.lock(ctx) != nil {
		return nil, rejected()
	}
	return stateResponse(pb.StateResponse_LOCKED), nil
}

// Status reveals only the bounded local lock state, never identity/key data.
func Status(ctx context.Context, path string) (string, error) {
	r, err := sessionCall(ctx, path, "status", nil)
	if err != nil {
		return "", err
	}
	switch r.State {
	case pb.StateResponse_LOCKED:
		return "locked", nil
	case pb.StateResponse_UNLOCKING:
		return "unlocking", nil
	case pb.StateResponse_UNLOCKED:
		return "unlocked", nil
	case pb.StateResponse_DRAINING:
		return "draining", nil
	default:
		return "", ErrRejected
	}
}

// Unlock makes a bounded private-socket call. The caller retains ownership of
// passphrase; the temporary request copy is cleared after the call is joined.
func Unlock(ctx context.Context, path string, passphrase []byte) error {
	if !validPassphrase(passphrase) {
		return ErrRejected
	}
	r, err := sessionCall(ctx, path, "unlock", passphrase)
	if err != nil || r.State != pb.StateResponse_UNLOCKED {
		return ErrRejected
	}
	return nil
}
func Lock(ctx context.Context, path string) error {
	r, err := sessionCall(ctx, path, "lock", nil)
	if err != nil || r.State != pb.StateResponse_LOCKED {
		return ErrRejected
	}
	return nil
}
func sessionCall(ctx context.Context, path, operation string, passphrase []byte) (*pb.StateResponse, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	limit := clientTimeout
	if operation == "unlock" {
		limit = unlockTimeout + operationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	c, err := newClient(path)
	if err != nil {
		return nil, ErrRejected
	}
	defer c.Close()
	api := pb.NewAgentClient(c)
	var r *pb.StateResponse
	switch operation {
	case "status":
		r, err = api.Status(ctx, &pb.StateRequest{Version: Version})
	case "lock":
		r, err = api.Lock(ctx, &pb.StateRequest{Version: Version})
	case "unlock":
		owned := append([]byte(nil), passphrase...)
		defer clear(owned)
		r, err = api.Unlock(ctx, &pb.UnlockRequest{Version: Version, Passphrase: owned})
	default:
		return nil, ErrRejected
	}
	if err != nil || ctx.Err() != nil || !validStateResponse(r) {
		return nil, ErrRejected
	}
	return r, nil
}
