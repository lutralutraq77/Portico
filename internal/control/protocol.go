// Package control defines the bounded device/connector control API. It has no
// controller database, issuer private-key, or administrator dependencies.
package control

import "time"

const Version = 1
const MaxHostingResources = 64
const MaxCancellationBatch = 64

type AuthorizeRequest struct {
	Version       int
	ClientLeafDER []byte
	ResourceID    string
	Revision      int64
}
type SessionRequest struct {
	Version   int
	SessionID string
	Sequence  int64
}
type ResourceAccess struct {
	ID                                                  string
	Revision                                            int64
	Name, ConnectorID, ConnectorName, Address, Protocol string
	Port                                                int
	Until                                               time.Time
}
type Authorization struct {
	Version                                                                 int
	SessionID, DeviceID, ConnectorID, CertificateID, ConnectorCertificateID string
	Resource                                                                ResourceAccess
	Sequence, PolicyRevision                                                int64
	IssuedAt, LeaseUntil, ActivateUntil, SessionUntil                       time.Time
}
type ConnectorCheck struct {
	Version          int
	ResourceID       string
	Revision         int64
	ConnectorLeafDER []byte
}
type ConnectorStatus struct {
	Version                int
	Resource               ResourceAccess
	ConnectorCertificateID string
	PolicyRevision         int64
	CheckedAt              time.Time
}
type HostingResource struct {
	Resource      ResourceAccess
	HostBindingID string
	From, Until   time.Time
}
type HostingSnapshot struct {
	Version                             int
	ConnectorID, ConnectorCertificateID string
	PolicyRevision                      int64
	CheckedAt, Until                    time.Time
	Resources                           []HostingResource
}
type CancellationRequest struct{ Version, Limit, WaitMillis int }
type Cancellation struct{ SessionID, Reason string }
type CancellationBatch struct {
	Version                int
	ConnectorCertificateID string
	PolicyRevision         int64
	ObservedAt             time.Time
	Items                  []Cancellation
}
type CancellationAck struct {
	Version   int
	SessionID string
}
