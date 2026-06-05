package network

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestCollectWithFixtureProcNet(t *testing.T) {
	root := t.TempDir()
	procNet := filepath.Join(root, "proc", "net")
	proc := filepath.Join(root, "proc")
	sysNet := filepath.Join(root, "sys", "class", "net")
	hosts := filepath.Join(root, "etc", "hosts")
	resolv := filepath.Join(root, "etc", "resolv.conf")
	dpkgStatus := filepath.Join(root, "var", "lib", "dpkg", "status")
	dpkgInfo := filepath.Join(root, "var", "lib", "dpkg", "info")
	networkConfig := filepath.Join(root, "etc", "environment")
	restore := SetRootsForTest(procNet, proc, sysNet, hosts, resolv, dpkgStatus, dpkgInfo, []string{networkConfig})
	defer restore()

	writeFile(t, filepath.Join(procNet, "tcp"), "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n")
	writeFile(t, filepath.Join(procNet, "tcp6"), "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	writeFile(t, filepath.Join(procNet, "udp"), "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 333 1 0000000000000000 100 0 0 10 0\n")
	writeFile(t, filepath.Join(procNet, "udp6"), "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	writeFile(t, filepath.Join(procNet, "unix"), "Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 77 /run/test.sock\n0000000000000000: 00000002 00000000 00000000 0001 03 78 /run/connected.sock\n")
	writeFile(t, filepath.Join(procNet, "route"), "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0\n")
	writeFile(t, filepath.Join(procNet, "arp"), "IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n")
	writeFile(t, filepath.Join(procNet, "dev"), "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 3 0 0 0 0 0 0 200 4 0 0 0 0 0 0\n")
	writeFile(t, filepath.Join(procNet, "if_inet6"), "")
	writeFile(t, filepath.Join(procNet, "snmp"), "Ip: Forwarding DefaultTTL\nIp: 2 64\n")
	writeFile(t, filepath.Join(procNet, "netstat"), "TcpExt: SyncookiesSent\nTcpExt: 0\n")
	writeFile(t, filepath.Join(procNet, "snmp6"), "Ip6InReceives 1\n")
	writeFile(t, filepath.Join(procNet, "nf_conntrack"), "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=8.8.8.8 sport=51515 dport=443 src=8.8.8.8 dst=10.0.0.5 sport=443 dport=51515 [ASSURED] mark=0 use=1\n")
	writeFile(t, hosts, "127.0.0.1 localhost\n10.0.0.5 app app.local\n")
	writeFile(t, resolv, "nameserver 1.1.1.1\nsearch corp.local\noptions timeout:2 rotate\n")
	writeFile(t, networkConfig, "HTTPS_PROXY=https://user:pass@proxy.local:8443\nAPI_TOKEN=super-secret-token\nPrivateKey = super-secret-private-key\nTAILSCALE_AUTHKEY=tskey-super-secret-tail\nfrpc token = super-secret-frp\ncloudflared_token=super-secret-cloud\n")
	writeFile(t, filepath.Join(sysNet, "eth0", "ifindex"), "2\n")
	writeFile(t, filepath.Join(sysNet, "eth0", "address"), "aa:bb:cc:dd:ee:ff\n")
	writeFile(t, filepath.Join(sysNet, "eth0", "mtu"), "1500\n")
	writeFile(t, filepath.Join(sysNet, "eth0", "operstate"), "up\n")
	writeFile(t, filepath.Join(sysNet, "eth0", "flags"), "0x1003\n")

	base := filepath.Join(proc, "123")
	writeFile(t, filepath.Join(base, "status"), "Name:\ttestproc\nUid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(base, "cmdline"), "testproc\x00--listen\x00")
	exePath := filepath.Join(root, "usr", "bin", "testproc")
	writeFile(t, exePath, "fixture-binary")
	if err := os.Symlink(exePath, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(base, "root")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(base, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(base, "fd", "4")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dpkgStatus, "Package: testpkg\nVersion: 1.2.3\n")
	writeFile(t, filepath.Join(dpkgInfo, "testpkg.list"), exePath+"\n")
	runtimeInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{
			Index:        2,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		}}, nil
	}

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"local_port\":8080")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"pid\":123")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"state\":\"LISTEN\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"is_listener\":true")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/run/test.sock")
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "parsed/listeners", 0)
	assertStreamCount(t, filepath.Join(outDir, "ai/evidence.jsonl"), "parsed/network_connections", 0)
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"entities/socket"`, `"inode":"12345"`}, []string{`"is_listener":true`, `"owners":[`, `"sources":[`})
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"gateway\":\"192.168.2.1\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "aa:bb:cc:dd:ee:ff")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"name\":\"eth0\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"mac\":\"aa:bb:cc:dd:ee:ff\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"mtu\":1500")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/dns_config\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"nameservers\":[\"1.1.1.1\"]")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/network_flows\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"cmdline\":[\"testproc\",\"--listen\"]")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"package_name\":\"testpkg\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/conntrack_entries\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"src\":\"10.0.0.5\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"dst\":\"8.8.8.8\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"sport\":51515")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"dport\":443")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"reply_src\":\"8.8.8.8\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"reply_dst\":\"10.0.0.5\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"destination_address\":\"8.8.8.8\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/firewall_rules\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/network_persistence\"")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "https://[redacted]@proxy.local:8443")
	assertEvidenceLineNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/network_persistence\"", "user:pass")
	assertEvidenceLineNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/network_persistence\"", "super-secret")
	assertEvidenceLineNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"stream\":\"facts/network_persistence\"", "tskey-")
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"facts/network_persistence"`, `"key":"token"`}, []string{`"value":"[redacted]"`, `"line":"API_TOKEN= [redacted]"`})
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"facts/network_persistence"`, `"key":"privatekey"`}, []string{`"value":"[redacted]"`, `"line":"PrivateKey = [redacted]"`})
	assertEvidenceLineContainsAll(t, filepath.Join(outDir, "ai/evidence.jsonl"), []string{`"stream":"facts/network_persistence"`, `"key":"authkey"`}, []string{`"value":"[redacted]"`, `"line":"TAILSCALE_AUTHKEY= [redacted]"`})
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_sockets.out"), "123/testproc")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_route.out"), "192.168.2.1")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_arp.out"), "aa:bb:cc:dd:ee:ff")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_interfaces.out"), "eth0")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_snmp.out"), "Forwarding")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_netstat.out"), "SyncookiesSent")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_snmp6.out"), "Ip6InReceives")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/hosts"), "localhost")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/resolv.conf"), "1.1.1.1")
}

func TestCollectWithMissingProcNetWritesAbsent(t *testing.T) {
	root := t.TempDir()
	procNet := filepath.Join(root, "missing-proc-net")
	proc := filepath.Join(root, "missing-proc")
	sysNet := filepath.Join(root, "missing-sys-net")
	hosts := filepath.Join(root, "missing-hosts")
	resolv := filepath.Join(root, "missing-resolv")
	restore := SetRootsForTest(procNet, proc, sysNet, hosts, resolv, filepath.Join(root, "missing-dpkg-status"), filepath.Join(root, "missing-dpkg-info"), nil)
	defer restore()

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "\"exists\":false")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "missing-proc-net")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_sockets.out"), "Proto")
	assertFileContains(t, filepath.Join(outDir, "legacy/network/proc_net_route.out"), "Kernel IP routing table")
}

func newOutput(t *testing.T) (*output.Manager, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	out, err := output.New(outDir, "dual", evidence.Session{
		CaseID:    "case-test",
		HostID:    "host-test",
		SessionID: "session-test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, outDir
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func SetRootsForTest(procNet, proc, sysNet, hosts, resolv, dpkgStatus, dpkgInfo string, persistencePaths []string) func() {
	oldProcNet := procNetRoot
	oldProc := procRoot
	oldSysNet := sysClassNetRoot
	oldHosts := hostsPath
	oldResolv := resolvConfPath
	oldDPKGStatus := dpkgStatusPath
	oldDPKGInfo := dpkgInfoDir
	oldRuntimeInterfaces := runtimeInterfaces
	oldPersistencePaths := networkPersistencePaths
	procNetRoot = procNet
	procRoot = proc
	sysClassNetRoot = sysNet
	hostsPath = hosts
	resolvConfPath = resolv
	dpkgStatusPath = dpkgStatus
	dpkgInfoDir = dpkgInfo
	networkPersistencePaths = persistencePaths
	runtimeInterfaces = func() ([]net.Interface, error) { return nil, nil }
	return func() {
		procNetRoot = oldProcNet
		procRoot = oldProc
		sysClassNetRoot = oldSysNet
		hostsPath = oldHosts
		resolvConfPath = oldResolv
		dpkgStatusPath = oldDPKGStatus
		dpkgInfoDir = oldDPKGInfo
		runtimeInterfaces = oldRuntimeInterfaces
		networkPersistencePaths = oldPersistencePaths
	}
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fragment) {
		t.Fatalf("%s does not contain %q: %s", path, fragment, string(data))
	}
}

func assertFileNotContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func assertEvidenceLineNotContains(t *testing.T, path, requiredFragment, forbiddenFragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, requiredFragment) && strings.Contains(line, forbiddenFragment) {
			t.Fatalf("%s has forbidden fragment %q in evidence line: %s", path, forbiddenFragment, line)
		}
	}
}

func assertStreamCount(t *testing.T, path, stream string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			Stream string `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("invalid evidence line: %v: %s", err, line)
		}
		if record.Stream == stream {
			got++
		}
	}
	if got != want {
		t.Fatalf("stream %s count=%d want=%d", stream, got, want)
	}
}

func assertEvidenceLineContainsAll(t *testing.T, path string, requiredLineFragments []string, expectedFragments []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		matched := true
		for _, fragment := range requiredLineFragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		for _, fragment := range expectedFragments {
			if !strings.Contains(line, fragment) {
				t.Fatalf("matched evidence line missing %q: %s", fragment, line)
			}
		}
		return
	}
	t.Fatalf("no evidence line matched required fragments: %v", requiredLineFragments)
}
