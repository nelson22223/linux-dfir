package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestNetworkRetryBoundAndGaps(t *testing.T) {
	for _, stableAt := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprint(stableAt), func(t *testing.T) {
			c := networkNamespaceFixture(t)
			c.gap("existing", fmt.Errorf("unrelated failure"))
			calls := 0
			c.networkWithRetry(func() []string {
				calls++
				if calls == 1 {
					c.gap("socket table", fmt.Errorf("I/O failure"))
				}
				if calls < stableAt {
					return []string{"network snapshot: churn"}
				}
				return nil
			})
			wantCalls := stableAt
			if wantCalls > 3 {
				wantCalls = 3
			}
			wantGaps := 2
			if stableAt > 3 {
				wantGaps++
			}
			if calls != wantCalls || len(c.o.Gaps) != wantGaps || !strings.Contains(c.o.Gaps[0], "existing") || !strings.Contains(c.o.Gaps[1], "I/O failure") {
				t.Fatalf("calls=%d gaps=%v", calls, c.o.Gaps)
			}
		})
	}
}

func TestNetworkRetryPreservesFullPeerIdentity(t *testing.T) {
	c := networkNamespaceFixture(t)
	base := NetworkObservation{RemoteIP: "101.91.168.5", Port: 25, Protocol: "tcp", State: "ESTABLISHED", Inode: "123", Source: "/proc/net/tcp", Namespace: "net:[1]", PIDs: []int{100, 200}}
	variants := []NetworkObservation{base}
	for i := 0; i < 8; i++ {
		p := base
		switch i {
		case 0:
			p.RemoteIP = "14.116.197.139"
		case 1:
			p.Port++
		case 2:
			p.Protocol = "udp"
		case 3:
			p.State = "TIME_WAIT"
		case 4:
			p.Inode = "456"
		case 5:
			p.Source = "/proc/100/net/tcp"
		case 6:
			p.Namespace = "net:[2]"
		case 7:
			p.PIDs = nil
		}
		variants = append(variants, p)
	}
	calls := 0
	c.networkWithRetry(func() []string {
		calls++
		if calls == 1 {
			c.o.NetworkPeers = append(c.o.NetworkPeers, variants...)
			return []string{"network snapshot: churn"}
		}
		duplicate := base
		duplicate.PIDs = []int{200, 100, 100}
		c.o.NetworkPeers = append(c.o.NetworkPeers, duplicate)
		return nil
	})
	if len(c.o.NetworkPeers) != len(variants) || len(c.o.Gaps) != 0 {
		t.Fatalf("lost or duplicated evidence: %+v", c.o)
	}
	for i, p := range c.o.NetworkPeers {
		if i == len(variants)-1 && len(p.PIDs) != 0 {
			t.Fatalf("fabricated ownership: %+v", p)
		}
	}
	if networkFindings(c.o)[0].Level != LevelCompromised {
		t.Fatal("earlier confirmed infection was lost")
	}
}

func TestNetworkRetryContext(t *testing.T) {
	for _, cancelBefore := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelBefore), func(t *testing.T) {
			c := networkNamespaceFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.ctx = ctx
			if cancelBefore {
				cancel()
			}
			calls := 0
			c.networkWithRetry(func() []string {
				calls++
				c.o.NetworkPeers = append(c.o.NetworkPeers, NetworkObservation{RemoteIP: "101.91.168.5", Port: 25})
				cancel()
				return []string{"network snapshot: churn"}
			})
			if calls > 1 || cancelBefore && calls != 0 || !strings.Contains(strings.Join(c.o.Gaps, "\n"), "context canceled") {
				t.Fatalf("calls=%d gaps=%v", calls, c.o.Gaps)
			}
			if !cancelBefore && (len(c.o.NetworkPeers) != 1 || !strings.Contains(strings.Join(c.o.Gaps, "\n"), "churn")) {
				t.Fatalf("cancellation lost evidence: %+v", c.o)
			}
		})
	}
}

func TestNetworkRetryRealSnapshotChurn(t *testing.T) {
	for _, sustained := range []bool{false, true} {
		t.Run(fmt.Sprint(sustained), func(t *testing.T) {
			c := networkNamespaceFixture(t)
			calls := 0
			c.networkWithRetry(func() []string {
				calls++
				changed := false
				return c.networkAttempt(func(path string) (string, error) {
					if !changed && (sustained || calls == 1) && path == c.path("/proc/self/ns/net") {
						changed = true
						// A new process appears after the initial process snapshot.
						dir := c.path(fmt.Sprintf("/proc/%d", 200+calls))
						if err := os.MkdirAll(dir+"/ns", 0755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(dir+"/stat", []byte("200 (fixture) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 100 0\n"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("net:[1]", dir+"/ns/net"); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(dir+"/fd", 0755); err != nil {
							t.Fatal(err)
						}
					}
					return os.Readlink(path)
				})
			})
			if sustained && (calls != 3 || len(c.o.Gaps) == 0) || !sustained && (calls != 2 || len(c.o.Gaps) != 0) {
				t.Fatalf("calls=%d gaps=%v", calls, c.o.Gaps)
			}
			if len(c.o.NetworkPeers) != 1 || len(c.o.NetworkPeers[0].PIDs) != 1 || c.o.NetworkPeers[0].PIDs[0] != 100 {
				t.Fatalf("wrong peer evidence: %+v", c.o.NetworkPeers)
			}
		})
	}
}

func TestNetworkRetryKeepsEarlierPeerAndIOGap(t *testing.T) {
	c := networkNamespaceFixture(t)
	udp := c.path("/proc/net/udp")
	data, err := os.ReadFile(udp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(udp); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.networkWithRetry(func() []string {
		calls++
		churn := c.networkAttempt(os.Readlink)
		if calls == 1 {
			if err := os.WriteFile(udp, data, 0600); err != nil {
				t.Fatal(err)
			}
			// The next scan has no IOC socket at all.
			if err := os.WriteFile(c.path("/proc/100/net/tcp"), data, 0600); err != nil {
				t.Fatal(err)
			}
			return append(churn, "network snapshot: churn")
		}
		return churn
	})
	if calls != 2 || len(c.o.Gaps) != 1 || !strings.Contains(c.o.Gaps[0], udp) {
		t.Fatalf("I/O gap lost: calls=%d gaps=%v", calls, c.o.Gaps)
	}
	if len(c.o.NetworkPeers) != 1 || len(networkFindings(c.o)) != 1 || networkFindings(c.o)[0].Level != LevelCompromised {
		t.Fatalf("earlier infection lost: %+v", c.o.NetworkPeers)
	}
}

func TestNetworkSnapshotDetectsExitAndIdentityChange(t *testing.T) {
	for _, exited := range []bool{false, true} {
		t.Run(fmt.Sprint(exited), func(t *testing.T) {
			c := networkNamespaceFixture(t)
			before := c.networkProcesses()
			if exited {
				if err := os.RemoveAll(c.path("/proc/100")); err != nil {
					t.Fatal(err)
				}
			} else {
				before[100] = "99"
			}
			if churn := c.checkNetworkSnapshot(before); len(churn) != 1 || len(c.o.Gaps) != 0 {
				t.Fatalf("churn=%v gaps=%v", churn, c.o.Gaps)
			}
		})
	}
}

func TestNetworkCancellationRetainsValidatedSockets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		at         int
		invalidate bool
	}{
		{"between namespace tables", "/proc/self/ns/net", 3, false},
		{"before owner observation", "/proc/100/ns/net", 4, false},
		{"after owner observation", "/proc/100/ns/net", 5, false},
		{"during final snapshot", "/proc/self/ns/net", 4, false},
		{"during final representative check", "/proc/100/ns/net", 6, false},
		{"invalidated owner namespace", "/proc/100/ns/net", 5, true},
		{"invalidated final namespace", "/proc/100/ns/net", 6, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := networkNamespaceFixture(t)
			// Both namespaces contain a real parsed IOC socket. The self namespace
			// sorts first, allowing cancellation between table scans.
			data, err := os.ReadFile(c.path("/proc/100/net/tcp"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.path("/proc/net/tcp"), data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.ctx = ctx
			calls, reads := 0, 0
			c.networkWithRetry(func() []string {
				calls++
				return c.networkAttempt(func(path string) (string, error) {
					if path == c.path(tc.path) {
						reads++
						if reads == tc.at {
							cancel()
							if tc.invalidate {
								return "net:[3]", nil
							}
						}
					}
					return os.Readlink(path)
				})
			})
			want := 2
			if tc.at == 3 || tc.invalidate {
				want = 1
			}
			if calls != 1 || reads < tc.at || len(c.o.NetworkPeers) != want || !strings.Contains(strings.Join(c.o.Gaps, "\n"), "context canceled") {
				t.Fatalf("calls=%d reads=%d observations=%+v", calls, reads, c.o)
			}
			for _, peer := range c.o.NetworkPeers {
				if len(peer.PIDs) != 0 || !confirmedPeer(peer.RemoteIP) || peer.Inode != "12345" || tc.invalidate && peer.Namespace == "net:[2]" {
					t.Fatalf("invalid partial evidence: %+v", peer)
				}
			}
		})
	}
}

func TestNetworkRetryChurnThenIOAbort(t *testing.T) {
	c := networkNamespaceFixture(t)
	calls := 0
	c.networkWithRetry(func() []string {
		calls++
		reads := 0
		return c.networkAttempt(func(path string) (string, error) {
			if path == c.path("/proc/self/ns/net") {
				reads++
				if calls == 2 {
					return "", fmt.Errorf("injected namespace I/O failure")
				}
				// Remove a snapshotted PID before namespace discovery. This is
				// genuine churn, not a synthetic attempt return value.
				if reads == 1 {
					if err := os.RemoveAll(c.path("/proc/100")); err != nil {
						t.Fatal(err)
					}
				}
			}
			return os.Readlink(path)
		})
	})
	gaps := strings.Join(c.o.Gaps, "\n")
	if calls != 2 || !strings.Contains(gaps, "PID 100 disappeared") || !strings.Contains(gaps, "injected namespace I/O failure") {
		t.Fatalf("aborted retry lost pending churn: calls=%d gaps=%v", calls, c.o.Gaps)
	}
}
