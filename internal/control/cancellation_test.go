package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClientRejectsCancellationOutsideRequestedSelection(t *testing.T) {
	id := uuid.NewString()
	for _, name := range []string{"valid", "outside_selection", "duplicate", "too_many", "bad_reason", "bad_id", "nil_items", "wrong_version", "wrong_certificate"} {
		t.Run(name, func(t *testing.T) {
			batch := CancellationBatch{Version: 1, ConnectorCertificateID: uuid.NewString(), PolicyRevision: 1, ObservedAt: time.Now().UTC(), Items: []Cancellation{{SessionID: id, Reason: "closed"}}}
			switch name {
			case "outside_selection":
				batch.Items[0].SessionID = uuid.NewString()
			case "duplicate":
				batch.Items = append(batch.Items, batch.Items[0])
			case "too_many":
				batch.Items = append(batch.Items, Cancellation{SessionID: uuid.NewString(), Reason: "expired"})
			case "bad_reason":
				batch.Items[0].Reason = "active"
			case "bad_id":
				batch.Items[0].SessionID = "invalid"
			case "nil_items":
				batch.Items = nil
			case "wrong_version":
				batch.Version = 2
			case "wrong_certificate":
				batch.ConnectorCertificateID = ""
			}
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(batch)
			}), time.Second)
			limit := 2
			if name == "too_many" {
				limit = 1
			}
			got, e := client.Cancellations(context.Background(), CancellationRequest{Version: 1, Limit: limit, SessionIDs: []string{id}})
			if name == "valid" {
				if e != nil || len(got.Items) != 1 || got.Items[0].SessionID != id {
					t.Fatal("valid selected cancellation rejected")
				}
			} else if e == nil || got.ConnectorCertificateID != "" {
				t.Fatal("untrusted cancellation response escaped validation")
			}
		})
	}
}
