package ddei_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"linux-dfir/internal/detector/ddeirootkit"
)

type evidenceRecord struct {
	Line   int             `json:"line"`
	Stream string          `json:"stream"`
	Source string          `json:"source_path"`
	Data   json.RawMessage `json:"data"`
}

// Replay maps a minimal, verified projection of the historical collector's
// fields to the same evaluator used by live detection. It cannot test live IO
// or pretend the archive contains the original ELF bytes.
func caseObservations(t *testing.T, omit map[string]bool) ddeirootkit.Observations {
	t.Helper()
	raw, err := os.ReadFile("testdata/case-20260825.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Records []evidenceRecord `json:"records"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	obs := ddeirootkit.Observations{Gaps: []string{"historical projection: full live coverage not asserted"}}
	for _, row := range input.Records {
		if omit[row.Stream] {
			continue
		}
		switch row.Stream {
		case "facts/persistence_items":
			var d struct {
				Path   string `json:"target_path"`
				SHA256 string `json:"target_sha256"`
				Exists bool   `json:"target_exists"`
			}
			if err := json.Unmarshal(row.Data, &d); err != nil || !d.Exists {
				t.Fatalf("invalid preload evidence at line %d: %v", row.Line, err)
			}
			obs.Objects = append(obs.Objects, ddeirootkit.ObjectObservation{ID: d.Path, Path: d.Path, SHA256: d.SHA256, Role: "preload"})
			obs.PreloadObjects = append(obs.PreloadObjects, d.Path)
		case "facts/pam_persistence":
			var d struct {
				Path    string `json:"module_path_resolved"`
				SHA256  string `json:"module_file_sha256"`
				Exists  bool   `json:"module_file_exists"`
				Type    string `json:"pam_type"`
				Control string `json:"control"`
			}
			if err := json.Unmarshal(row.Data, &d); err != nil || !d.Exists || d.Type != "auth" {
				t.Fatalf("invalid PAM evidence at line %d: %v", row.Line, err)
			}
			obs.Objects = append(obs.Objects, ddeirootkit.ObjectObservation{ID: d.Path, Path: d.Path, SHA256: d.SHA256, Role: "pam"})
			obs.AuthPAMObjects = append(obs.AuthPAMObjects, d.Path)
			obs.PAMAuth = append(obs.PAMAuth, ddeirootkit.PAMObservation{Config: row.Source, Control: d.Control, Module: d.Path, ObjectID: d.Path})
		case "facts/process_lineage":
			var d struct {
				PID    int    `json:"pid"`
				Exe    string `json:"exe"`
				SHA256 string `json:"exe_sha256"`
				Size   int64  `json:"exe_size"`
			}
			if err := json.Unmarshal(row.Data, &d); err != nil {
				t.Fatal(err)
			}
			obs.Objects = append(obs.Objects, ddeirootkit.ObjectObservation{ID: d.Exe, Path: d.Exe, SHA256: d.SHA256, Size: d.Size, Role: "xinetd"})
			obs.Processes = append(obs.Processes, ddeirootkit.ProcessObservation{PID: d.PID, Exe: d.Exe, ExeObject: d.Exe})
		case "entities/process":
			var d struct {
				PID  int    `json:"pid"`
				UID  int    `json:"uid"`
				PPID int    `json:"ppid"`
				Exe  string `json:"exe"`
				FDs  []struct {
					Target string `json:"target"`
				} `json:"fds"`
				Maps struct {
					Paths []string `json:"sample_paths"`
					RWX   int      `json:"writable_executable_count"`
				} `json:"maps"`
			}
			if err := json.Unmarshal(row.Data, &d); err != nil {
				t.Fatal(err)
			}
			p := ddeirootkit.ProcessObservation{PID: d.PID, UID: d.UID, PPID: d.PPID, Exe: d.Exe, RWX: d.Maps.RWX > 0, MappedObjects: d.Maps.Paths}
			for _, fd := range d.FDs {
				if fd.Target == "/dev/ptmx" || strings.HasPrefix(fd.Target, "/dev/pts/") {
					p.HasPTY = true
				}
			}
			obs.Processes = append(obs.Processes, p)
		case "facts/network_flows":
			// Kept in the fixture for the isolated IOC test; correlation tests
			// deliberately do not depend on this peer being present.
		}
	}
	return obs
}

func TestVerifiedArchiveCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name string
		omit map[string]bool
		want ddeirootkit.Verdict
	}{
		{"complete selected case", nil, ddeirootkit.VerdictInfected},
		{"preload and PAM remain without running dropper", map[string]bool{"facts/process_lineage": true}, ddeirootkit.VerdictInfected},
		{"preload and running dropper without PAM", map[string]bool{"facts/pam_persistence": true}, ddeirootkit.VerdictInfected},
		{"PAM and dropper without loader not sufficient", map[string]bool{"facts/persistence_items": true}, ddeirootkit.VerdictInconclusive},
		{"loader alone not sufficient", map[string]bool{"facts/pam_persistence": true, "facts/process_lineage": true}, ddeirootkit.VerdictInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := ddeirootkit.Evaluate(caseObservations(t, tc.omit))
			if rep.Verdict != tc.want {
				t.Fatalf("got %s want %s: %+v", rep.Verdict, tc.want, rep.Findings)
			}
			if rep.Complete {
				t.Fatal("partial historical replay must not claim complete live inspection")
			}
		})
	}
}

func TestHistoricalBehaviorWithoutOriginalELFIsNotCleared(t *testing.T) {
	obs := caseObservations(t, nil)
	for i := range obs.Objects {
		obs.Objects[i].SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	if rep := ddeirootkit.Evaluate(obs); rep.Verdict != ddeirootkit.VerdictInconclusive {
		t.Fatalf("historical replay without original ELF must remain unresolved: %+v", rep)
	}
}

func TestBehaviorNeedsAllIndependentStages(t *testing.T) {
	for _, stage := range []string{"preload", "PAM", "RWX", "PTY", "mapped"} {
		t.Run(stage, func(t *testing.T) {
			obs := caseObservations(t, nil)
			for i := range obs.Objects {
				obs.Objects[i].SHA256 = "changed"
			}
			switch stage {
			case "preload":
				obs.PreloadObjects = nil
			case "PAM":
				obs.PAMAuth = nil
			case "RWX":
				for i := range obs.Processes {
					obs.Processes[i].RWX = false
				}
			case "PTY":
				for i := range obs.Processes {
					obs.Processes[i].HasPTY = false
				}
			case "mapped":
				for i := range obs.Processes {
					obs.Processes[i].MappedObjects = nil
				}
			}
			if rep := ddeirootkit.Evaluate(obs); rep.Verdict == ddeirootkit.VerdictInfected {
				t.Fatalf("missing %s still convicted: %+v", stage, rep)
			}
		})
	}
}

func TestVerifiedCaseNetworkPeer(t *testing.T) {
	data, err := os.ReadFile("testdata/case-20260825.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Records []evidenceRecord `json:"records"`
	}
	if err = json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	var obs ddeirootkit.Observations
	for _, row := range input.Records {
		if row.Stream != "facts/network_flows" {
			continue
		}
		var d struct {
			Socket struct {
				Remote   string `json:"remote_address"`
				Port     int    `json:"remote_port"`
				State    string `json:"state"`
				Protocol string `json:"protocol"`
				Inode    string `json:"inode"`
			} `json:"socket"`
			Owners []struct {
				PID int `json:"pid"`
			} `json:"process_owners"`
		}
		if err = json.Unmarshal(row.Data, &d); err != nil {
			t.Fatal(err)
		}
		peer := ddeirootkit.NetworkObservation{RemoteIP: d.Socket.Remote, Port: d.Socket.Port, Protocol: d.Socket.Protocol, State: d.Socket.State, Inode: d.Socket.Inode, Source: row.Source}
		for _, owner := range d.Owners {
			peer.PIDs = append(peer.PIDs, owner.PID)
		}
		obs.NetworkPeers = append(obs.NetworkPeers, peer)
	}
	if rep := ddeirootkit.Evaluate(obs); rep.Verdict != ddeirootkit.VerdictInfected {
		t.Fatalf("verified actual peer not detected: %+v", rep)
	}
}

func TestCompleteNormalObservationIsClean(t *testing.T) {
	rep := ddeirootkit.Evaluate(ddeirootkit.Observations{Coverage: ddeirootkit.Coverage{Root: true, Proc: true}})
	if rep.Verdict != ddeirootkit.VerdictClean || !rep.Complete {
		t.Fatalf("normal complete observations should be CLEAN: %+v", rep)
	}
}
