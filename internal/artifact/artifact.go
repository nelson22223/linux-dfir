package artifact

import (
	"crypto/sha256"
	"encoding/hex"
)

func ID(sessionID, relPath string) string {
	sum := sha256.Sum256([]byte(sessionID + "\x00" + relPath))
	return hex.EncodeToString(sum[:12])
}
