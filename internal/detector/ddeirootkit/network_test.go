package ddeirootkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func networkNamespaceFixture(t *testing.T) *collector {
	t.Helper()
	root := t.TempDir()
	put := func(path, data string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(path, target string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	const header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	link("proc/self/ns/net", "net:[1]")
	link("proc/100/ns/net", "net:[2]")
	link("proc/100/fd/3", "socket:[12345]")
	put("proc/100/stat", "100 (fixture) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 100 0\n")
	put("proc/net/tcp", header)
	put("proc/net/udp", header)
	put("proc/100/net/tcp", header+"0: 0100007F:D000 05A85B65:0019 02 00000000:00000000 00:00000000 00000000 0 0 12345\n")
	put("proc/100/net/udp", header)
	return &collector{ctx: context.Background(), root: root}
}

func TestNetworkNamespaceChangeDiscardsEvidence(t *testing.T) {
	for _, tc := range []struct {
		stage    string
		changeAt int
	}{
		{"before socket tables", 2},
		{"after socket tables", 3},
		{"before socket owner observation", 4},
		{"after socket owner observation", 5},
		{"after socket owner snapshot", 6},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			c := networkNamespaceFixture(t)
			dir := c.path("/proc/100")
			before, err := c.networkIdentity(dir)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			c.networkWithReadlink(func(path string) (string, error) {
				if path == dir+"/ns/net" {
					calls++
					if calls >= tc.changeAt {
						return "net:[3]", nil
					}
				}
				return os.Readlink(path)
			})
			after, err := c.networkIdentity(dir)
			if err != nil || before != after {
				t.Fatalf("starttime changed: %s %s %v", before, after, err)
			}
			if calls < tc.changeAt || len(c.o.NetworkPeers) != 0 || len(networkFindings(c.o)) != 0 {
				t.Fatalf("unstable namespace evidence retained: calls=%d observations=%+v", calls, c.o)
			}
			if !strings.Contains(strings.Join(c.o.Gaps, "\n"), tc.stage) {
				t.Fatalf("missing namespace coverage gap at %s: %+v", tc.stage, c.o.Gaps)
			}
		})
	}
}

func TestNetworkStableRepresentativeNamespace(t *testing.T) {
	c := networkNamespaceFixture(t)
	c.network()
	if len(c.o.Gaps) != 0 || len(c.o.NetworkPeers) != 1 {
		t.Fatalf("stable namespace observations: %+v", c.o)
	}
	p := c.o.NetworkPeers[0]
	if p.Namespace != "net:[2]" || len(p.PIDs) != 1 || p.PIDs[0] != 100 {
		t.Fatalf("wrong namespace ownership: %+v", p)
	}
}

func TestNetworkIOCRequiresActualOwnedPeer(t *testing.T) {
	for _, tc := range []struct {
		name, ip, state string
		pids            []int
		want            Level
	}{
		{"confirmed first", "101.91.168.5", "ESTABLISHED", []int{100}, LevelCompromised},
		{"confirmed second", "14.116.197.139", "SYN_SENT", []int{100}, LevelCompromised},
		{"mapped IPv6", "::ffff:101.91.168.5", "ESTABLISHED", []int{100}, LevelCompromised},
		{"stale connection", "101.91.168.5", "TIME_WAIT", nil, LevelReview},
		{"unowned peer", "101.91.168.5", "ESTABLISHED", nil, LevelReview},
		{"business remote", "192.0.2.1", "ESTABLISHED", []int{100}, ""},
		{"text not address", "log mentions 101.91.168.5", "ESTABLISHED", []int{100}, ""},
		{"listener", "101.91.168.5", "LISTEN", []int{100}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Observations{NetworkPeers: []NetworkObservation{{RemoteIP: tc.ip, Port: 25, Protocol: "tcp", State: tc.state, PIDs: tc.pids}}}
			findings := networkFindings(o)
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatal(findings)
				}
			} else if len(findings) != 1 || findings[0].Level != tc.want {
				t.Fatalf("got %+v want %s", findings, tc.want)
			}
		})
	}
}

func TestNetworkReadsRemoteAndSocketOwner(t *testing.T) {
	root := t.TempDir()
	put := func(path, data string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(path, target string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	const header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	link("proc/self/ns/net", "net:[1]")
	link("proc/100/ns/net", "net:[1]")
	link("proc/100/fd/3", "socket:[12345]")
	put("proc/100/stat", "100 (fixture) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 100 0\n")
	put("proc/net/tcp", header+"0: 0100007F:D000 05A85B65:0019 02 00000000:00000000 00:00000000 00000000 0 0 12345\n")
	put("proc/net/udp", header)
	c := collector{ctx: context.Background(), root: root, o: Observations{Processes: []ProcessObservation{{PID: 100}}}}
	c.network()
	if len(c.o.Gaps) != 0 || len(c.o.NetworkPeers) != 1 {
		t.Fatalf("observations %+v", c.o)
	}
	peer := c.o.NetworkPeers[0]
	if peer.RemoteIP != "101.91.168.5" || len(peer.PIDs) != 1 || peer.PIDs[0] != 100 {
		t.Fatal(peer)
	}
	if found := networkFindings(c.o); len(found) != 1 || found[0].Level != LevelCompromised {
		t.Fatal(found)
	}
	// The same address bound locally is not a remote IOC hit.
	put("proc/net/tcp", header+"0: 05A85B65:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345\n")
	c.o.NetworkPeers = nil
	c.network()
	if len(c.o.NetworkPeers) != 0 {
		t.Fatalf("local binding was treated as a remote connection: %+v", c.o.NetworkPeers)
	}
	put("proc/net/tcp", header+"malformed\n")
	c.network()
	if len(c.o.Gaps) == 0 {
		t.Fatal("malformed socket table must not silently clear the check")
	}
}
