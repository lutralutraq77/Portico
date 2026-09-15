package adminapp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/wire"
)

type renewalKey interface {
	deviceKey
	CSR() ([]byte, error)
}

type nativeRenewal struct {
	mu        sync.Mutex
	journal   *credentialJournal
	key       renewalKey
	completed bool
}

func newNativeRenewal(c *Configuration, key renewalKey, storage credentialStorage) (*nativeRenewal, error) {
	if key == nil {
		return nil, ErrRejected
	}
	j, err := openCredentialJournal(c, storage)
	if err != nil {
		return nil, ErrRejected
	}
	return &nativeRenewal{journal: j, key: key}, nil
}

// Handle is reachable only through the fixed-origin native pipe. It serializes
// state-changing operations without a queue. The renderer can request a lifetime
// and supply WebAuthn proof; it cannot choose keys, CSRs, destinations or files.
func (n *nativeRenewal) Handle(ctx context.Context, request adminbridge.Request, send adminbridge.RenewalExchange) (adminbridge.Response, error) {
	if ctx == nil || ctx.Err() != nil || !n.mu.TryLock() {
		return adminbridge.Response{}, ErrRejected
	}
	defer n.mu.Unlock()
	if n.journal.failed || send == nil || request.Method != http.MethodPost || request.Origin != n.journal.config.bridge.Origin || (request.Site != "" && request.Site != "same-origin" && request.Site != "none") {
		return adminbridge.Response{}, ErrRejected
	}
	var err error
	switch request.Path {
	case adminrenewal.StartPath:
		var body adminrenewal.StartRequest
		if wire.Decode(request.Body, &body) != nil || body.Version != 1 || n.completed || n.journal.record.Pending != nil {
			return adminbridge.Response{}, ErrRejected
		}
		id, idErr := uuid.NewRandom()
		csr, csrErr := n.key.CSR()
		if idErr != nil || csrErr != nil || ctx.Err() != nil {
			return adminbridge.Response{}, ErrRejected
		}
		next := n.journal.next()
		next.Pending = &pendingRenewal{Phase: "preparing", CreatedAt: time.Now().UTC(), Request: adminrenewal.PrepareRequest{Version: 1, RenewalID: id.String(), CSR: csr, NotAfter: body.NotAfter, PolicyRevision: body.PolicyRevision}}
		if n.journal.commit(next) != nil {
			return adminbridge.Response{}, ErrRejected
		}
		err = n.prepare(send)
	case adminrenewal.ApprovePath:
		var body adminrenewal.ConfirmRequest
		p := n.journal.record.Pending
		if wire.Decode(request.Body, &body) != nil || body.Version != 1 || p == nil || p.Phase != "prepared" || len(body.Response) == 0 || n.completed {
			return adminbridge.Response{}, ErrRejected
		}
		prepared, challenge, verifyErr := n.journal.prepared(n.journal.record.Certificate, p)
		if verifyErr != nil || body.ChallengeID != challenge.ID || !time.Now().Add(n.journal.config.bridge.Timeout).Before(prepared.ExpiresAt) {
			return adminbridge.Response{}, ErrRejected
		}
		next := n.journal.next()
		next.Pending.Phase = "confirming"
		// An uncertain confirmation is never resent, including after a restart.
		if n.journal.commit(next) != nil {
			return adminbridge.Response{}, ErrRejected
		}
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return adminbridge.Response{}, ErrRejected
		}
		result, sendErr := send(adminrenewal.ConfirmPath, encoded)
		if sendErr != nil || n.retain(result) != nil {
			return adminbridge.Response{}, ErrRejected
		}
		err = n.activate(ctx)
	case adminrenewal.StatusPath, adminrenewal.ResumePath, adminrenewal.CancelPath:
		var body adminrenewal.NativeRequest
		if wire.Decode(request.Body, &body) != nil || body.Version != 1 {
			return adminbridge.Response{}, ErrRejected
		}
		p := n.journal.record.Pending
		if request.Path == adminrenewal.CancelPath {
			// Before proof submission, forgetting a local challenge creates no
			// signing authority. Confirming/issued records must be reconciled.
			if p == nil || (p.Phase != "preparing" && p.Phase != "prepared") || n.completed {
				return adminbridge.Response{}, ErrRejected
			}
			next := n.journal.next()
			next.Pending = nil
			err = n.journal.commit(next)
		} else if request.Path == adminrenewal.ResumePath && p != nil {
			switch p.Phase {
			case "preparing":
				err = n.prepare(send)
			case "confirming":
				var body []byte
				body, err = json.Marshal(adminrenewal.CertificateRequest{Version: 1, RenewalID: p.Request.RenewalID})
				if err == nil {
					var response adminbridge.Response
					response, err = send(adminrenewal.CertificatePath, body)
					if err == nil {
						err = n.retain(response)
					}
				}
				if err == nil {
					err = n.activate(ctx)
				}
			case "issued":
				err = n.activate(ctx)
			}
		}
	default:
		return adminbridge.Response{}, ErrRejected
	}
	if err != nil || ctx.Err() != nil || n.journal.failed {
		return adminbridge.Response{}, ErrRejected
	}
	return n.status()
}

func (n *nativeRenewal) prepare(send adminbridge.RenewalExchange) error {
	p := n.journal.record.Pending
	if p == nil || p.Phase != "preparing" {
		return ErrRejected
	}
	body, err := json.Marshal(p.Request)
	if err != nil {
		return ErrRejected
	}
	response, err := send(adminrenewal.PreparePath, body)
	if err != nil || response.Status != http.StatusOK {
		return ErrRejected
	}
	next := n.journal.next()
	next.Pending.Phase, next.Pending.Prepared = "prepared", bytes.Clone(response.Body)
	return n.journal.commit(next)
}

func (n *nativeRenewal) retain(response adminbridge.Response) error {
	p := n.journal.record.Pending
	var result adminrenewal.Certificate
	if p == nil || p.Phase != "confirming" || response.Status != http.StatusOK || wire.Decode(response.Body, &result) != nil || result.Version != 1 || result.RenewalID != p.Request.RenewalID {
		return ErrRejected
	}
	if _, err := n.key.Identity(result.CertificateDER); err != nil {
		return ErrRejected
	}
	next := n.journal.next()
	next.Pending.Phase, next.Pending.Certificate = "issued", bytes.Clone(result.CertificateDER)
	return n.journal.commit(next)
}

func (n *nativeRenewal) activate(ctx context.Context) error {
	j := n.journal
	p := j.record.Pending
	if p == nil || p.Phase != "issued" || j.failed || ctx.Err() != nil {
		return ErrRejected
	}
	identity, err := n.key.Identity(p.Certificate)
	if err != nil {
		return ErrRejected
	}
	// First reconcile an activation whose response or final local commit was
	// lost. Normal administrator TLS admits only the currently active leaf;
	// this read-only proof also works after the activation retry window expires.
	management := j.config.bridge
	management.Identity, management.RenewalHandler = identity, nil
	current := false
	probe, err := adminbridge.New(ctx, management)
	if err != nil {
		return ErrRejected
	}
	response, probeErr := probe.Exchange(ctx, adminbridge.Request{Method: http.MethodGet, Path: "/admin"})
	current = probeErr == nil && response.Status == http.StatusOK
	faulted := false
	select {
	case <-probe.Done():
		faulted = true
	default:
	}
	probe.Close()
	if faulted || ctx.Err() != nil {
		return ErrRejected
	}
	if !current {
		activation := *j.config.renewal
		activation.Identity = identity
		if adminbridge.Activate(ctx, activation, p.Request.RenewalID) != nil {
			return ErrRejected
		}
	}
	next := j.next()
	next.Certificate, next.Pending = bytes.Clone(p.Certificate), nil
	if j.commit(next) != nil {
		return ErrRejected
	}
	n.completed = true
	return nil
}

func (n *nativeRenewal) status() (adminbridge.Response, error) {
	j := n.journal
	current, err := historicalCredential(j.config.bridge.AdministratorTrust, j.config.principal, j.record.Certificate)
	if err != nil {
		return adminbridge.Response{}, ErrRejected
	}
	result := adminrenewal.Status{Version: 1, State: "ready", CurrentCertificateHash: current.LeafSHA256, CurrentNotAfter: current.NotAfter}
	if n.completed {
		result.State = "complete"
	}
	if p := j.record.Pending; p != nil {
		result.State, result.RenewalID, result.RequestedNotAfter = p.Phase, p.Request.RenewalID, p.Request.NotAfter
		if p.Phase == "prepared" {
			prepared, _, err := j.prepared(j.record.Certificate, p)
			if err != nil {
				return adminbridge.Response{}, ErrRejected
			}
			result.Prepared = &prepared
		}
	}
	body, err := json.Marshal(result)
	if err != nil || len(body) > wire.MaxBody {
		return adminbridge.Response{}, ErrRejected
	}
	return adminbridge.Response{Status: http.StatusOK, Body: body, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"}}, nil
}
