package controller

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/connector"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/workload"
)

func startConnectorRuntime(t *testing.T, v *workloadFixture, workers int) (context.CancelFunc, <-chan error) {
	t.Helper()
	root, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- connector.Run(root, v.carrier.connector, v.server, connector.Options{Workers: workers, RetryMin: 250 * time.Millisecond, RetryMax: time.Second})
	}()
	t.Cleanup(cancel)
	carrierEventually(t, func() bool { return v.carrier.relay.Stats().Waiting == workers })
	return cancel, done
}

func openThroughRuntime(t *testing.T, v *workloadFixture) *workload.Conn {
	t.Helper()
	c, err := tryOpenThroughRuntime(v)
	must(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func tryOpenThroughRuntime(v *workloadFixture) (*workload.Conn, error) {
	r := v.resource
	raw, err := v.carrier.device.Dial(ctx, r.ConnectorID)
	if err != nil {
		return nil, err
	}
	return v.client.Open(ctx, raw, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
}

func runtimeEcho(t *testing.T, c *workload.Conn) {
	t.Helper()
	must(t, c.SetDeadline(time.Now().Add(3*time.Second)))
	_, err := c.Write([]byte("runtime"))
	must(t, err)
	var response [7]byte
	_, err = io.ReadFull(c, response[:])
	must(t, err)
	if string(response[:]) != "runtime" {
		t.Fatal("changed application data")
	}
	must(t, c.SetDeadline(time.Time{}))
}

func TestWorkloadGuestConnectorRuntimeRebindsAndJoinsShutdown(t *testing.T) {
	v := newWorkloadFixture(t)
	cancel, done := startConnectorRuntime(t, v, 1)
	// A pending Bind expires at the relay's pair deadline even while idle.
	// The runtime must back off and open a fresh authenticated binding.
	admissions := v.carrier.admitted.Load()
	carrierEventually(t, func() bool { return v.carrier.admitted.Load() > admissions && v.carrier.relay.Stats().Waiting == 1 })
	c := openThroughRuntime(t, v)
	runtimeEcho(t, c)
	must(t, c.Close())
	carrierEventually(t, func() bool { return v.closed.Load() == 1 && v.carrier.relay.Stats().Waiting == 1 })
	c = openThroughRuntime(t, v)
	runtimeEcho(t, c)
	cancel()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("runtime shutdown did not join")
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client retained terminated runtime")
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 2 && v.carrier.connector.ActiveStreams() == 0 })
	if v.server.Stats().Connections != 0 {
		t.Fatal("shutdown retained destination workers")
	}
	if err := v.server.CheckHealth(); err == nil {
		t.Fatal("closed server accepted restart")
	}
}

func TestWorkloadGuestConnectorRuntimeClockFailureStopsAllStreams(t *testing.T) {
	var unhealthy atomic.Bool
	v := newWorkloadFixture(t, func(s *workload.ServerConfig, _ *workload.ClientConfig) {
		s.ClockHealth = func() (time.Duration, error) {
			if unhealthy.Load() {
				return 0, workload.ErrDenied
			}
			return 20 * time.Millisecond, nil // Explicit fixture bound; no host/kernel clock change.
		}
	})
	_, done := startConnectorRuntime(t, v, 2)
	// Claim both pending slots concurrently. Performing a whole TLS/control
	// authorization before the second Dial can outlast its idle pair deadline.
	type opened struct {
		c   *workload.Conn
		err error
	}
	results := make(chan opened, 2)
	for i := 0; i < 2; i++ {
		go func() { c, err := tryOpenThroughRuntime(v); results <- opened{c, err} }()
	}
	var connections []*workload.Conn
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.c != nil {
				t.Cleanup(func() { _ = result.c.Close() })
			}
			if result.err != nil {
				t.Errorf("concurrent runtime open: %v", result.err)
			}
			connections = append(connections, result.c)
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent runtime open stalled")
		}
	}
	if t.Failed() {
		return
	}
	a, b := connections[0], connections[1]
	runtimeEcho(t, a)
	runtimeEcho(t, b)
	unhealthy.Store(true)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("health loss returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("clock failure did not join runtime")
	}
	for _, c := range []*workload.Conn{a, b} {
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("clock failure retained client")
		}
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 2 && v.carrier.connector.ActiveStreams() == 0 })
	unhealthy.Store(false)
	if err := v.server.CheckHealth(); err == nil {
		t.Fatal("clock recovery revived old authority")
	}
	if v.server.Stats().Connections != 0 {
		t.Fatal("unhealthy runtime retained destination workers")
	}
}
