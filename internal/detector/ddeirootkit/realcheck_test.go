package ddeirootkit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRealSamples validates the behavioural discriminator against the actual
// incident samples (stored in testdata/, not committed to the branch).
func TestRealSamples(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "libnet.so.1")); err != nil {
		t.Skip("testdata samples not present")
	}
	lib := realInspectELF(filepath.Join("testdata", "libnet.so.1"))
	if !lib.IsELF || !looksLikeHookLib(lib) {
		t.Fatalf("real libnet.so.1 must look like a hook lib: %+v", lib)
	}
	t.Logf("libnet.so.1: defined=%d hooks=%d interp=%v", lib.DefinedTotal, lib.DefinedHooks, lib.HasInterpreter)

	drop := realInspectELF(filepath.Join("testdata", "xinetd.1"))
	if drop.HasInterpreter {
		t.Fatalf("real xinetd.1 dropper must have no PT_INTERP: %+v", drop)
	}
	t.Logf("xinetd.1: defined=%d interp=%v", drop.DefinedTotal, drop.HasInterpreter)
}
