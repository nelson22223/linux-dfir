package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsCredentialPatterns(t *testing.T) {
	input := `curl https://user:pass@example.test/path?token=secret TOKEN=secret QUOTED_TOKEN="secret" PASSWORD="correct horse" --api-key secret --auth-key "secret value" BEGIN OPENSSH PRIVATE KEY`
	got := Text(input)
	for _, fragment := range []string{"user:pass", "token=secret", "TOKEN=secret", `QUOTED_TOKEN="secret"`, `PASSWORD="correct horse"`, "--api-key secret", `--auth-key "secret value"`, "BEGIN OPENSSH PRIVATE KEY"} {
		if strings.Contains(got, fragment) {
			t.Fatalf("redacted text still contains %q: %s", fragment, got)
		}
	}
	for _, fragment := range []string{"https://[redacted]@example.test/path?token=[redacted]", "TOKEN=[redacted]", `QUOTED_TOKEN="[redacted]"`, `PASSWORD="[redacted]"`, "--api-key [redacted]", `--auth-key "[redacted]"`} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("redacted text missing %q: %s", fragment, got)
		}
	}
}

func TestTextRedactsPrivateKeyBlockBody(t *testing.T) {
	input := "prefix -----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-body\n-----END OPENSSH PRIVATE KEY----- suffix"
	got := Text(input)
	for _, fragment := range []string{"BEGIN OPENSSH PRIVATE KEY", "secret-key-body", "END OPENSSH PRIVATE KEY"} {
		if strings.Contains(got, fragment) {
			t.Fatalf("redacted private key block still contains %q: %s", fragment, got)
		}
	}
	if !strings.Contains(got, "prefix [redacted] suffix") {
		t.Fatalf("redacted private key block missing placeholder context: %s", got)
	}
}

func TestArgsRedactsOptionValues(t *testing.T) {
	got := Args([]string{"curl", "https://user:pass@example.test/path?token=secret", "--api-key", "secret", "--mode", "prod"})
	want := []string{"curl", "https://[redacted]@example.test/path?token=[redacted]", "--api-key", "[redacted]", "--mode", "prod"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("Args()=%q want %q", got, want)
	}
}

func TestValueRedactsSensitiveKeys(t *testing.T) {
	if got := Value("TAILSCALE_AUTHKEY", "tskey-secret"); got != Placeholder() {
		t.Fatalf("Value sensitive key=%q want %q", got, Placeholder())
	}
	if got := Value("MODE", "prod"); got != "prod" {
		t.Fatalf("Value non-sensitive key=%q want prod", got)
	}
}
