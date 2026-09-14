package ddeirootkit

import "testing"

func TestSharedMemoryDoesNotSuppressInfection(t *testing.T) {
	o := behavior()
	o.Processes[0].Mappings = []MappingObservation{{Kind: "shared_anonymous", Address: "1000-2000", Permissions: "rwxs", Device: "00:04", Inode: "123"}, {Kind: "shared_anonymous", Address: "2000-3000", Permissions: "rwxs", Device: "00:04", Inode: "456"}}
	r := Evaluate(o)
	if r.Verdict != VerdictInfected || len(r.SharedMemory) != 1 || len(r.SharedMemory[0].Mappings) != 2 {
		t.Fatalf("%+v", r)
	}
	count := 0
	for _, f := range r.Findings {
		if f.ID == "shared_anonymous" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one summary, got %d", count)
	}
}

func TestZeroMappingShape(t *testing.T) {
	for _, tc := range []struct {
		perms, path, dev, ino, probe string
		want                         bool
	}{
		{"rwxs", "/dev/zero (deleted)", "00:04", "123", "00:04", true},
		{"rwxp", "/dev/zero (deleted)", "00:04", "123", "00:04", false},
		{"rwxs", "/dev/zero", "00:04", "123", "00:04", false},
		{"rwxs", "/dev/zero (deleted)", "08:01", "123", "00:04", false},
		{"rwxs", "/dev/zero (deleted)", "00:04", "0", "00:04", false},
		{"rwxs", "/dev/zero (deleted)", "00:04", "123", "", false},
	} {
		if got := zeroMappingShape(tc.perms, tc.path, tc.dev, tc.ino, tc.probe); got != tc.want {
			t.Fatalf("%+v: %t", tc, got)
		}
	}
}
