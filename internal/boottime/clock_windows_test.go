package boottime

import "testing"

func TestNativeInterruptTimeSymbol(t *testing.T) {
	if e := interruptTime.Find(); e != nil {
		t.Fatalf("Windows interrupt clock lookup: %v", e)
	}
}
