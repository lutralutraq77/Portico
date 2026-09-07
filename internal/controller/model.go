// Package controller implements trusted, local controller domain storage.
// Its methods are not an authentication boundary and never authorize network access.
package controller

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalid    = errors.New("invalid domain value")
	ErrConflict   = errors.New("stale revision or duplicate record")
	ErrDenied     = errors.New("domain state denies operation")
	ErrStorage    = errors.New("authoritative storage unavailable")
	ErrIntegrity  = errors.New("authoritative state integrity failure")
	ErrQuarantine = errors.New("restored state is quarantined")
)

func NewID() string { return uuid.NewString() }
func validID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func interval(from, until time.Time) bool {
	return !from.IsZero() && until.After(from) && from.Year() >= 2000 && until.Year() < 2262
}
func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func literal(s string) (string, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || a.Zone() != "" {
		return "", ErrInvalid
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.String() == "255.255.255.255" || a == netip.MustParseAddr("169.254.169.254") {
		return "", ErrInvalid
	}
	return a.String(), nil
}

type User struct {
	ID, Name string
	Enabled  bool
}
type Device struct {
	ID, UserID, Name, Platform string
	Enabled                    bool
	NotAfter                   time.Time
}
type Connector struct {
	ID, Name, Version string
	Enabled           bool
}
type Issuer struct {
	ID       string
	Enabled  bool
	NotAfter time.Time
}
type Certificate struct {
	ID, IssuerID, Serial, PrincipalID, Profile, LeafSHA256, SPKISHA256 string
	NotBefore, NotAfter                                                time.Time
	Revoked                                                            bool
}
type Resource struct {
	ID                                         string
	Revision                                   int64
	Name, ConnectorID, Kind, Address, Protocol string
	Port                                       int
	Enabled                                    bool
}
type Grant struct {
	ID, UserID, DeviceID, ResourceID, ApprovalID string
	Revision                                     int64
	Enabled                                      bool
	From, Until                                  time.Time
}
type HostBinding struct {
	ID, ConnectorID, ResourceID string
	Revision                    int64
	Enabled                     bool
	From, Until                 time.Time
}
type Session struct {
	ID, DeviceID, CertificateID, ConnectorCertificateID, ResourceID, GrantID, HostBindingID string
	Revision                                                                                int64
	Until                                                                                   time.Time
}
type Summary struct {
	Users, Devices, Connectors, Resources, Grants, Certificates, Sessions, OpenSessions int
	Generation, AuditSequence                                                           int64
	Quarantined                                                                         bool
}
