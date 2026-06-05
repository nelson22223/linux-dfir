package session

import (
	"testing"
	"time"
)

func TestNewSessionIDFormat(t *testing.T) {
	sess, err := New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(sess.SessionID) {
		t.Fatalf("invalid session id: %s", sess.SessionID)
	}
	if sess.CaseID != "case-1" {
		t.Fatalf("case id mismatch: %s", sess.CaseID)
	}
	if sess.HostID == "" {
		t.Fatal("host id is empty")
	}
}
