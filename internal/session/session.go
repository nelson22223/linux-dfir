package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"time"

	"linux-dfir/internal/evidence"
)

var idPattern = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{8}$`)

func New(caseID string, now time.Time) (evidence.Session, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	suffix, err := randomHex(4)
	if err != nil {
		return evidence.Session{}, err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}
	if caseID == "" {
		caseID = "unspecified"
	}
	sum := sha256.Sum256([]byte(hostname))

	return evidence.Session{
		CaseID:    caseID,
		HostID:    hex.EncodeToString(sum[:8]),
		SessionID: fmt.Sprintf("%s-%s", now.Format("20060102T150405Z"), suffix),
		CreatedAt: now,
	}, nil
}

func ValidID(id string) bool {
	return idPattern.MatchString(id)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session entropy: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
