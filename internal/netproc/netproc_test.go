package netproc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTCPUDP(t *testing.T) {
	text := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n"
	conns := ParseTCPUDP(text, "tcp", false)
	if len(conns) != 1 {
		t.Fatalf("connection count mismatch: %+v", conns)
	}
	conn := conns[0]
	if conn.LocalAddress != "127.0.0.1" || conn.LocalPort != 8080 || conn.State != "LISTEN" || conn.UID != 1000 || conn.Inode != "12345" {
		t.Fatalf("unexpected connection: %+v", conn)
	}
}

func TestParseUnix(t *testing.T) {
	text := "Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 22334 /tmp/dfir.sock\n"
	conns := ParseUnix(text)
	if len(conns) != 1 || conns[0].Protocol != "unix" || conns[0].State != "LISTENING" || conns[0].Inode != "22334" || conns[0].SocketPath != "/tmp/dfir.sock" {
		t.Fatalf("unexpected unix connection: %+v", conns)
	}
}

func TestParseRoutes(t *testing.T) {
	text := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0\n"
	routes := ParseRoutes(text)
	if len(routes) != 1 || routes[0].Gateway != "192.168.2.1" || routes[0].Interface != "eth0" {
		t.Fatalf("unexpected routes: %+v", routes)
	}
}

func TestParseARP(t *testing.T) {
	text := "IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n"
	entries := ParseARP(text)
	if len(entries) != 1 || entries[0].MAC != "aa:bb:cc:dd:ee:ff" || entries[0].Device != "eth0" {
		t.Fatalf("unexpected arp entries: %+v", entries)
	}
}

func TestParseInterfaces(t *testing.T) {
	dev := "Inter-| Receive | Transmit\neth0: 10 2 0 0 0 0 0 0 30 4 0 0 0 0 0 0\n"
	inet6 := "00000000000000000000000000000001 01 80 10 80 eth0\n"
	interfaces := ParseInterfaces(dev, inet6)
	if len(interfaces) != 1 || interfaces[0].Name != "eth0" || interfaces[0].RXBytes != 10 || interfaces[0].TXPackets != 4 || interfaces[0].IPv6[0] != "::1" {
		t.Fatalf("unexpected interfaces: %+v", interfaces)
	}
}

func TestEnrichInterfacesFromSysfsAndRuntime(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "eth0")
	writeFile(t, filepath.Join(base, "ifindex"), "2\n")
	writeFile(t, filepath.Join(base, "address"), "aa:bb:cc:dd:ee:ff\n")
	writeFile(t, filepath.Join(base, "mtu"), "1500\n")
	writeFile(t, filepath.Join(base, "operstate"), "up\n")
	writeFile(t, filepath.Join(base, "flags"), "0x1003\n")
	if err := os.Symlink("../br0", filepath.Join(base, "master")); err != nil {
		t.Fatal(err)
	}
	ifaces := EnrichInterfacesFromSysfs([]Interface{{Exists: true, Name: "eth0"}}, root)
	if len(ifaces) != 1 || ifaces[0].MAC != "aa:bb:cc:dd:ee:ff" || ifaces[0].MTU != 1500 || ifaces[0].OperState != "up" || ifaces[0].Master != "br0" {
		t.Fatalf("unexpected sysfs enrichment: %+v", ifaces)
	}
	if len(ifaces[0].Flags) == 0 || ifaces[0].Flags[0] != "up" {
		t.Fatalf("expected flags: %+v", ifaces[0].Flags)
	}

	ifaces = ApplyRuntimeInterfaceAddrs(ifaces, []net.Interface{{
		Index:        2,
		MTU:          1500,
		Name:         "eth0",
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Flags:        net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
	}})
	if ifaces[0].IfIndex != 2 {
		t.Fatalf("expected ifindex: %+v", ifaces[0])
	}
}

func TestParseHostsAndResolver(t *testing.T) {
	hosts := ParseHosts("127.0.0.1 localhost\n10.0.0.5 app app.local # comment\n")
	if len(hosts) != 2 || hosts[1].Canonical != "app" || hosts[1].Aliases[0] != "app.local" {
		t.Fatalf("unexpected hosts: %+v", hosts)
	}
	resolv := ParseResolvConf("nameserver 1.1.1.1\nsearch corp.local example.com\noptions timeout:2 rotate\n")
	if len(resolv.Nameservers) != 1 || resolv.Nameservers[0] != "1.1.1.1" || len(resolv.Search) != 2 || resolv.Options[0].Key != "timeout" || resolv.Options[0].Value != "2" {
		t.Fatalf("unexpected resolver: %+v", resolv)
	}
}

func TestParseConntrack(t *testing.T) {
	text := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=8.8.8.8 sport=51515 dport=443 src=8.8.8.8 dst=10.0.0.5 sport=443 dport=51515 [ASSURED] mark=0 use=1\n"
	entries := ParseConntrack(text)
	if len(entries) != 1 || entries[0].Protocol != "tcp" || entries[0].State != "ESTABLISHED" || entries[0].Original.DestinationAddress != "8.8.8.8" || entries[0].Reply.SourcePort != 443 {
		t.Fatalf("unexpected conntrack: %+v", entries)
	}
	if entries[0].SourceAddress != "10.0.0.5" || entries[0].DestinationAddress != "8.8.8.8" || entries[0].SourcePort != 51515 || entries[0].DestinationPort != 443 || entries[0].ReplySourceAddress != "8.8.8.8" || entries[0].ReplyDestinationAddress != "10.0.0.5" || entries[0].ReplySourcePort != 443 || entries[0].ReplyDestinationPort != 51515 {
		t.Fatalf("unexpected conntrack: %+v", entries)
	}
}

func TestParseFirewallRules(t *testing.T) {
	ipt := ParseIPTablesSave("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n", "iptables-save")
	if len(ipt) != 3 || ipt[2].Chain != "INPUT" || ipt[2].Action != "accept" || ipt[2].Target != "ACCEPT" {
		t.Fatalf("unexpected iptables rules: %+v", ipt)
	}
	nft := ParseNFTRuleset("table inet filter {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 22 accept\n }\n}\n")
	if len(nft) != 4 || nft[2].RuleType != "chain_policy" || nft[2].Policy != "accept" || nft[3].Action != "accept" {
		t.Fatalf("unexpected nft rules: %+v", nft)
	}
}

func TestScanSocketOwners(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "777/status"), "Name:\tfakeproc\nUid:\t1000\t1000\t1000\t1000\n")
	writeFile(t, filepath.Join(root, "777/cmdline"), "fakeproc\x00--listen\x00--api-key\x00super-secret-owner\x00")
	if err := os.MkdirAll(filepath.Join(root, "777/fd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(root, "777/fd/3")); err != nil {
		t.Fatal(err)
	}
	owners, issues := ScanSocketOwners(root)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if len(owners["12345"]) != 1 || owners["12345"][0].PID != 777 || owners["12345"][0].ProcessName != "fakeproc" {
		t.Fatalf("unexpected owners: %+v", owners)
	}
	if len(owners["12345"][0].Cmdline) != 4 {
		t.Fatalf("expected cmdline enrichment: %+v", owners)
	}
	if owners["12345"][0].Cmdline[3] != "[redacted]" {
		t.Fatalf("expected redacted cmdline owner: %+v", owners["12345"][0].Cmdline)
	}
}

func TestParseIPv6Hex(t *testing.T) {
	got := parseIPv6Hex("00000000000000000000000001000000")
	if got != "::1" {
		t.Fatalf("unexpected ipv6: %s", got)
	}
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
