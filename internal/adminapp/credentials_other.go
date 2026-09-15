//go:build !linux

package adminapp

const maxCredentialState = 64 * 1024

func openCredentialDisk(string) (credentialStorage, error) { return nil, ErrRejected }
