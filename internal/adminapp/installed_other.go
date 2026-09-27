//go:build !linux

package adminapp

import "portico.local/portico/internal/adminbridge"

func prepareInstalled(string) (adminbridge.Launch, func(), error) {
	return adminbridge.Launch{}, nil, ErrRejected
}
