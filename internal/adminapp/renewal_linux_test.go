//go:build linux

package adminapp

import (
	"bytes"
	"testing"

	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestLinuxNativeRenewalReopensDurableStateAfterUncertainNetworkResult(t *testing.T) {
	for _, scenario := range []string{"confirmation", "activation"} {
		t.Run(scenario, func(t *testing.T) {
			_, state := installedFixture(t)
			f := nativeRenewalSeed(t)
			disk, err := openCredentialDisk(state)
			testfixture.Must(t, err)
			t.Cleanup(disk.Close)
			f.disk = disk
			f.native, err = newNativeRenewal(f.config, f.key, disk)
			testfixture.Must(t, err)
			f.lostConfirm = scenario == "confirmation"
			f.lostActive.Store(scenario == "activation")
			f.start(t)
			if _, err := f.request(t, adminrenewal.ApprovePath, f.confirmation(t)); err == nil {
				t.Fatal("uncertain network result reported success")
			}
			before := f.stored(t)
			if before.Pending == nil || (scenario == "confirmation" && before.Pending.Phase != "confirming") || (scenario == "activation" && before.Pending.Phase != "issued") {
				t.Fatal("native process lost its durable continuation state")
			}
			disk.Close()
			disk, err = openCredentialDisk(state)
			testfixture.Must(t, err)
			t.Cleanup(disk.Close)
			f.disk = disk
			f.native, err = newNativeRenewal(f.config, f.key, disk)
			testfixture.Must(t, err)
			status, err := f.request(t, adminrenewal.ResumePath, adminrenewal.NativeRequest{Version: 1})
			testfixture.Must(t, err)
			after := f.stored(t)
			if status.State != "complete" || status.CurrentCertificateHash != pki.Hash(f.candidate) || after.Pending != nil || !bytes.Equal(after.Certificate, f.candidate) || f.confirms.Load() != 1 || f.activations.Load() != 1 || f.key.csrs.Load() != 1 {
				t.Fatal("Linux durable resumption repeated signing or lost the activated identity")
			}
		})
	}
}
