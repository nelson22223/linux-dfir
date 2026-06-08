package netproc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"linux-dfir/internal/procfs"
	"linux-dfir/internal/redact"
)

type Connection struct {
	Exists        bool          `json:"exists"`
	AbsentReason  string        `json:"absent_reason,omitempty"`
	Protocol      string        `json:"protocol"`
	Family        string        `json:"family,omitempty"`
	LocalAddress  string        `json:"local_address,omitempty"`
	LocalPort     int           `json:"local_port,omitempty"`
	RemoteAddress string        `json:"remote_address,omitempty"`
	RemotePort    int           `json:"remote_port,omitempty"`
	State         string        `json:"state,omitempty"`
	UID           int           `json:"uid,omitempty"`
	Inode         string        `json:"inode,omitempty"`
	SocketPath    string        `json:"socket_path,omitempty"`
	SocketType    string        `json:"socket_type,omitempty"`
	SocketFlags   string        `json:"socket_flags,omitempty"`
	Owners        []SocketOwner `json:"owners,omitempty"`
}

type SocketOwner struct {
	PID              int      `json:"pid"`
	PPID             int      `json:"ppid,omitempty"`
	FD               string   `json:"fd"`
	ProcessName      string   `json:"process_name,omitempty"`
	UID              int      `json:"uid,omitempty"`
	Cmdline          []string `json:"cmdline,omitempty"`
	Exe              string   `json:"exe,omitempty"`
	Cwd              string   `json:"cwd,omitempty"`
	Root             string   `json:"root,omitempty"`
	ExeSHA256        string   `json:"exe_sha256,omitempty"`
	ExeHashError     string   `json:"exe_hash_error,omitempty"`
	PackageManager   string   `json:"package_manager,omitempty"`
	PackageName      string   `json:"package_name,omitempty"`
	PackageVersion   string   `json:"package_version,omitempty"`
	LineageKey       string   `json:"lineage_key,omitempty"`
	ProcessSessionID int      `json:"process_session_id,omitempty"`
	CgroupPath       string   `json:"cgroup_path,omitempty"`
	ContainerID      string   `json:"container_id,omitempty"`
}

type Route struct {
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Interface    string `json:"interface,omitempty"`
	Destination  string `json:"destination,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	Flags        string `json:"flags,omitempty"`
	Mask         string `json:"mask,omitempty"`
	Metric       int    `json:"metric,omitempty"`
}

type ARPEntry struct {
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	IP           string `json:"ip,omitempty"`
	HWType       string `json:"hw_type,omitempty"`
	Flags        string `json:"flags,omitempty"`
	MAC          string `json:"mac,omitempty"`
	Device       string `json:"device,omitempty"`
}

type Interface struct {
	Exists       bool        `json:"exists"`
	AbsentReason string      `json:"absent_reason,omitempty"`
	Name         string      `json:"name,omitempty"`
	IfIndex      int         `json:"ifindex,omitempty"`
	MAC          string      `json:"mac,omitempty"`
	MTU          int         `json:"mtu,omitempty"`
	Flags        []string    `json:"flags,omitempty"`
	OperState    string      `json:"operstate,omitempty"`
	Master       string      `json:"master,omitempty"`
	KindHints    []string    `json:"kind_hints,omitempty"`
	RXBytes      uint64      `json:"rx_bytes,omitempty"`
	RXPackets    uint64      `json:"rx_packets,omitempty"`
	TXBytes      uint64      `json:"tx_bytes,omitempty"`
	TXPackets    uint64      `json:"tx_packets,omitempty"`
	IPv4         []IPAddress `json:"ipv4,omitempty"`
	IPv6         []string    `json:"ipv6,omitempty"`
}

type Issue struct {
	Path   string
	Kind   string
	Error  string
	IsRace bool
}

type IPAddress struct {
	Address      string `json:"address"`
	CIDR         string `json:"cidr,omitempty"`
	PrefixLength int    `json:"prefix_length,omitempty"`
}

type HostsEntry struct {
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	LineNumber   int      `json:"line_number,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Names        []string `json:"names,omitempty"`
	Canonical    string   `json:"canonical,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`
}

type ResolverConfig struct {
	Exists        bool             `json:"exists"`
	AbsentReason  string           `json:"absent_reason,omitempty"`
	Source        string           `json:"source,omitempty"`
	Scope         string           `json:"scope,omitempty"`
	Manager       string           `json:"manager,omitempty"`
	Runtime       bool             `json:"runtime,omitempty"`
	Static        bool             `json:"static,omitempty"`
	StubResolver  bool             `json:"stub_resolver,omitempty"`
	SymlinkTarget string           `json:"symlink_target,omitempty"`
	Nameservers   []string         `json:"nameservers,omitempty"`
	Search        []string         `json:"search,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	Options       []ResolverOption `json:"options,omitempty"`
	Directives    []ResolverLine   `json:"directives,omitempty"`
}

type DHCPLease struct {
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	SourceFormat string   `json:"source_format,omitempty"`
	Interface    string   `json:"interface,omitempty"`
	Address      string   `json:"address,omitempty"`
	Router       []string `json:"router,omitempty"`
	DNS          []string `json:"dns,omitempty"`
	Server       string   `json:"server,omitempty"`
	LeaseStart   string   `json:"lease_start,omitempty"`
	LeaseEnd     string   `json:"lease_end,omitempty"`
	Renew        string   `json:"renew,omitempty"`
	Rebind       string   `json:"rebind,omitempty"`
	LineNumber   int      `json:"line_number,omitempty"`
	SourcePath   string   `json:"source_path,omitempty"`
}

type IPv6Route struct {
	Exists               bool   `json:"exists"`
	AbsentReason         string `json:"absent_reason,omitempty"`
	Interface            string `json:"interface,omitempty"`
	Destination          string `json:"destination,omitempty"`
	DestinationPrefixLen int    `json:"destination_prefix_len"`
	Source               string `json:"source,omitempty"`
	SourcePrefixLen      int    `json:"source_prefix_len"`
	NextHop              string `json:"next_hop,omitempty"`
	Metric               string `json:"metric,omitempty"`
	Flags                string `json:"flags,omitempty"`
}

type NeighborEntry struct {
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Family       string `json:"family,omitempty"`
	Interface    string `json:"interface,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	MAC          string `json:"mac,omitempty"`
	State        string `json:"state,omitempty"`
	RawLine      string `json:"raw_line,omitempty"`
}

type NetworkCounter struct {
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Source       string `json:"source,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Name         string `json:"name,omitempty"`
	Value        uint64 `json:"value"`
}

type ResolverOption struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type ResolverLine struct {
	LineNumber int      `json:"line_number"`
	Directive  string   `json:"directive"`
	Values     []string `json:"values,omitempty"`
}

type Endpoint struct {
	SourceAddress      string `json:"source_address,omitempty"`
	DestinationAddress string `json:"destination_address,omitempty"`
	SourcePort         int    `json:"source_port,omitempty"`
	DestinationPort    int    `json:"destination_port,omitempty"`
}

type ConntrackEntry struct {
	Exists                  bool     `json:"exists"`
	AbsentReason            string   `json:"absent_reason,omitempty"`
	Family                  string   `json:"family,omitempty"`
	Layer3Protocol          string   `json:"layer3_protocol,omitempty"`
	Protocol                string   `json:"protocol,omitempty"`
	Timeout                 int      `json:"timeout,omitempty"`
	State                   string   `json:"state,omitempty"`
	SourceAddress           string   `json:"src,omitempty"`
	DestinationAddress      string   `json:"dst,omitempty"`
	SourcePort              int      `json:"sport,omitempty"`
	DestinationPort         int      `json:"dport,omitempty"`
	ReplySourceAddress      string   `json:"reply_src,omitempty"`
	ReplyDestinationAddress string   `json:"reply_dst,omitempty"`
	ReplySourcePort         int      `json:"reply_sport,omitempty"`
	ReplyDestinationPort    int      `json:"reply_dport,omitempty"`
	Original                Endpoint `json:"original,omitempty"`
	Reply                   Endpoint `json:"reply,omitempty"`
	StatusFlags             []string `json:"status_flags,omitempty"`
	Mark                    string   `json:"mark,omitempty"`
	Use                     string   `json:"use,omitempty"`
	RawLine                 string   `json:"raw_line,omitempty"`
}

type FirewallRule struct {
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	Tool         string   `json:"tool,omitempty"`
	Family       string   `json:"family,omitempty"`
	Table        string   `json:"table,omitempty"`
	Chain        string   `json:"chain,omitempty"`
	RuleType     string   `json:"rule_type,omitempty"`
	Hook         string   `json:"hook,omitempty"`
	Priority     string   `json:"priority,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	Expression   string   `json:"expression,omitempty"`
	Action       string   `json:"action,omitempty"`
	Target       string   `json:"target,omitempty"`
	LineNumber   int      `json:"line_number,omitempty"`
	Tokens       []string `json:"tokens,omitempty"`
}

func ParseTCPUDP(text, protocol string, ipv6 bool) []Connection {
	var result []Connection
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, errLocal := parseAddrPort(fields[1], ipv6)
		remoteAddr, remotePort, errRemote := parseAddrPort(fields[2], ipv6)
		if errLocal != nil || errRemote != nil {
			continue
		}
		uid, _ := strconv.Atoi(fields[7])
		inode := fields[9]
		family := "ipv4"
		if ipv6 {
			family = "ipv6"
		}
		result = append(result, Connection{
			Exists:        true,
			Protocol:      protocol,
			Family:        family,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         socketState(fields[3], protocol),
			UID:           uid,
			Inode:         inode,
		})
	}
	return result
}

func ParseUnix(text string) []Connection {
	var result []Connection
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		path := ""
		if len(fields) >= 8 {
			path = strings.Join(fields[7:], " ")
		}
		result = append(result, Connection{
			Exists:      true,
			Protocol:    "unix",
			Family:      "unix",
			State:       unixState(fields[5]),
			Inode:       fields[6],
			SocketPath:  path,
			SocketType:  unixType(fields[4]),
			SocketFlags: fields[3],
		})
	}
	return result
}

func ParseRoutes(text string) []Route {
	var routes []Route
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		metric := 0
		if len(fields) > 6 {
			metric, _ = strconv.Atoi(fields[6])
		}
		routes = append(routes, Route{
			Exists:      true,
			Interface:   fields[0],
			Destination: parseIPv4Hex(fields[1]),
			Gateway:     parseIPv4Hex(fields[2]),
			Flags:       fields[3],
			Mask:        parseIPv4Hex(fields[7]),
			Metric:      metric,
		})
	}
	return routes
}

func ParseIPv6Routes(text string) []IPv6Route {
	var routes []IPv6Route
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 10 {
			continue
		}
		routes = append(routes, IPv6Route{
			Exists:               true,
			Destination:          parseIPv6Plain(fields[0]),
			DestinationPrefixLen: parseHexInt(fields[1]),
			Source:               parseIPv6Plain(fields[2]),
			SourcePrefixLen:      parseHexInt(fields[3]),
			NextHop:              parseIPv6Plain(fields[4]),
			Metric:               fields[5],
			Flags:                fields[8],
			Interface:            fields[9],
		})
	}
	return routes
}

func ParseNeighborCache(text, family string) []NeighborEntry {
	var entries []NeighborEntry
	for _, line := range strings.Split(text, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "IPv6") || strings.HasPrefix(clean, "IP ") {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 3 {
			continue
		}
		entry := NeighborEntry{Exists: true, Family: family, RawLine: clean}
		if family == "ipv6" {
			entry.IPAddress = parseMaybeIPv6(fields[0])
			entry.Interface = fields[len(fields)-1]
			for _, field := range fields {
				if strings.Count(field, ":") == 5 {
					entry.MAC = field
				}
			}
			if len(fields) >= 2 {
				entry.State = fields[len(fields)-2]
			}
		} else if len(fields) >= 6 {
			entry.IPAddress = fields[0]
			entry.MAC = fields[3]
			entry.Interface = fields[5]
			entry.State = fields[2]
		}
		entries = append(entries, entry)
	}
	return entries
}

func ParseDHCPLeases(text, sourcePath string) []DHCPLease {
	if strings.Contains(text, "lease {") || strings.Contains(text, "lease{") {
		return parseISCLeases(text, sourcePath)
	}
	return parseKeyValueLease(text, sourcePath)
}

func ParseNetworkCounters(text, source string) []NetworkCounter {
	if source == "snmp6" {
		return parseSNMP6Counters(text, source)
	}
	return parsePairedProcNetCounters(text, source)
}

func ParseARP(text string) []ARPEntry {
	var entries []ARPEntry
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		entries = append(entries, ARPEntry{
			Exists: true,
			IP:     fields[0],
			HWType: fields[1],
			Flags:  fields[2],
			MAC:    fields[3],
			Device: fields[5],
		})
	}
	return entries
}

func ParseInterfaces(devText, inet6Text string) []Interface {
	interfaces := map[string]Interface{}
	for _, line := range strings.Split(devText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") || strings.HasPrefix(line, "Inter-|") || strings.HasPrefix(line, "face |") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		iface := Interface{
			Exists:    true,
			Name:      name,
			RXBytes:   parseUint(fields[0]),
			RXPackets: parseUint(fields[1]),
			TXBytes:   parseUint(fields[8]),
			TXPackets: parseUint(fields[9]),
		}
		interfaces[name] = iface
	}
	for _, line := range strings.Split(inet6Text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 6 {
			continue
		}
		name := fields[5]
		iface := interfaces[name]
		iface.Exists = true
		iface.Name = name
		iface.IPv6 = append(iface.IPv6, parseIPv6Plain(fields[0]))
		interfaces[name] = iface
	}
	result := make([]Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		sort.Strings(iface.IPv6)
		result = append(result, iface)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func EnrichInterfacesFromSysfs(interfaces []Interface, sysClassNetRoot string) []Interface {
	index := map[string]int{}
	for i := range interfaces {
		index[interfaces[i].Name] = i
	}
	entries, err := os.ReadDir(sysClassNetRoot)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if _, ok := index[name]; !ok {
				interfaces = append(interfaces, Interface{Exists: true, Name: name})
				index[name] = len(interfaces) - 1
			}
		}
	}
	for i := range interfaces {
		if interfaces[i].Name == "" {
			continue
		}
		base := filepath.Join(sysClassNetRoot, interfaces[i].Name)
		interfaces[i].IfIndex = readInt(filepath.Join(base, "ifindex"))
		interfaces[i].MAC = readTrimmed(filepath.Join(base, "address"))
		interfaces[i].MTU = readInt(filepath.Join(base, "mtu"))
		interfaces[i].OperState = readTrimmed(filepath.Join(base, "operstate"))
		interfaces[i].Flags = parseInterfaceFlags(readTrimmed(filepath.Join(base, "flags")))
		interfaces[i].Master = readInterfaceMaster(base)
		interfaces[i].KindHints = inferInterfaceKinds(base, interfaces[i])
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	return interfaces
}

func ApplyRuntimeInterfaceAddrs(interfaces []Interface, runtime []net.Interface) []Interface {
	index := map[string]int{}
	for i := range interfaces {
		index[interfaces[i].Name] = i
	}
	for _, runtimeIface := range runtime {
		i, ok := index[runtimeIface.Name]
		if !ok {
			interfaces = append(interfaces, Interface{Exists: true, Name: runtimeIface.Name})
			i = len(interfaces) - 1
			index[runtimeIface.Name] = i
		}
		if interfaces[i].IfIndex == 0 {
			interfaces[i].IfIndex = runtimeIface.Index
		}
		if interfaces[i].MTU == 0 {
			interfaces[i].MTU = runtimeIface.MTU
		}
		if interfaces[i].MAC == "" {
			interfaces[i].MAC = runtimeIface.HardwareAddr.String()
		}
		if len(interfaces[i].Flags) == 0 {
			interfaces[i].Flags = runtimeFlags(runtimeIface.Flags)
		}
		addrs, err := runtimeIface.Addrs()
		if err == nil {
			interfaces[i].IPv4 = append(interfaces[i].IPv4, parseRuntimeIPv4(addrs)...)
			interfaces[i].IPv4 = uniqueIPAddresses(interfaces[i].IPv4)
		}
		interfaces[i].KindHints = uniqueStrings(append(interfaces[i].KindHints, inferInterfaceKinds("", interfaces[i])...))
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	return interfaces
}

func ParseHosts(text string) []HostsEntry {
	var entries []HostsEntry
	for i, line := range strings.Split(text, "\n") {
		clean := stripInlineComment(line)
		fields := strings.Fields(clean)
		if len(fields) < 2 {
			continue
		}
		entry := HostsEntry{
			Exists:     true,
			LineNumber: i + 1,
			IP:         fields[0],
			Names:      append([]string{}, fields[1:]...),
			Canonical:  fields[1],
		}
		if len(fields) > 2 {
			entry.Aliases = append([]string{}, fields[2:]...)
		}
		entries = append(entries, entry)
	}
	return entries
}

func ParseResolvConf(text string) ResolverConfig {
	config := ResolverConfig{Exists: true}
	for i, line := range strings.Split(text, "\n") {
		clean := stripInlineComment(line)
		fields := strings.Fields(clean)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		values := append([]string{}, fields[1:]...)
		config.Directives = append(config.Directives, ResolverLine{LineNumber: i + 1, Directive: directive, Values: values})
		switch directive {
		case "nameserver":
			config.Nameservers = append(config.Nameservers, values...)
		case "search":
			config.Search = append(config.Search, values...)
		case "domain":
			if len(values) > 0 {
				config.Domain = values[0]
			}
		case "options":
			for _, value := range values {
				parts := strings.SplitN(value, ":", 2)
				option := ResolverOption{Key: parts[0]}
				if len(parts) == 2 {
					option.Value = parts[1]
				}
				config.Options = append(config.Options, option)
			}
		}
	}
	config.Nameservers = uniqueStrings(config.Nameservers)
	config.Search = uniqueStrings(config.Search)
	return config
}

func ParseResolvedConf(text string) ResolverConfig {
	config := ResolverConfig{Exists: true, Manager: "systemd-resolved", Static: true}
	for i, line := range strings.Split(text, "\n") {
		clean := stripInlineComment(line)
		if strings.TrimSpace(clean) == "" || strings.HasPrefix(strings.TrimSpace(clean), "[") || !strings.Contains(clean, "=") {
			continue
		}
		parts := strings.SplitN(clean, "=", 2)
		key := strings.TrimSpace(parts[0])
		values := strings.Fields(strings.TrimSpace(parts[1]))
		config.Directives = append(config.Directives, ResolverLine{LineNumber: i + 1, Directive: strings.ToLower(key), Values: values})
		switch strings.ToLower(key) {
		case "dns", "fallbackdns":
			config.Nameservers = append(config.Nameservers, values...)
		case "domains":
			config.Search = append(config.Search, values...)
		}
	}
	config.Nameservers = uniqueStrings(config.Nameservers)
	config.Search = uniqueStrings(config.Search)
	return config
}

func ParseNetworkManagerConfig(text string) ResolverConfig {
	config := ResolverConfig{Exists: true, Manager: "NetworkManager", Static: true}
	for i, line := range strings.Split(text, "\n") {
		clean := stripInlineComment(line)
		if strings.TrimSpace(clean) == "" || strings.HasPrefix(strings.TrimSpace(clean), "[") || !strings.Contains(clean, "=") {
			continue
		}
		parts := strings.SplitN(clean, "=", 2)
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		values := splitAddressList(parts[1])
		config.Directives = append(config.Directives, ResolverLine{LineNumber: i + 1, Directive: key, Values: values})
		switch key {
		case "ipv4.dns", "ipv6.dns", "dns-data", "servers", "nameserver", "nameservers":
			config.Nameservers = append(config.Nameservers, ipValues(values)...)
		case "dns-search", "ipv4.dns-search", "ipv6.dns-search", "domains":
			config.Search = append(config.Search, values...)
		}
	}
	config.Nameservers = uniqueStrings(config.Nameservers)
	config.Search = uniqueStrings(config.Search)
	return config
}

func ParseDNSMasqConfig(text string) ResolverConfig {
	config := ResolverConfig{Exists: true, Manager: "dnsmasq", Static: true}
	for i, line := range strings.Split(text, "\n") {
		clean := stripInlineComment(line)
		if strings.TrimSpace(clean) == "" {
			continue
		}
		key := clean
		values := []string{}
		if strings.Contains(clean, "=") {
			parts := strings.SplitN(clean, "=", 2)
			key = strings.TrimSpace(parts[0])
			values = splitDNSMasqValues(parts[1])
		}
		config.Directives = append(config.Directives, ResolverLine{LineNumber: i + 1, Directive: strings.ToLower(key), Values: values})
		if strings.EqualFold(key, "server") {
			config.Nameservers = append(config.Nameservers, dnsmasqServerValues(values)...)
		}
	}
	config.Nameservers = uniqueStrings(config.Nameservers)
	return config
}

func ParseConntrack(text string) []ConntrackEntry {
	var entries []ConntrackEntry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		entry := ConntrackEntry{Exists: true, RawLine: line}
		entry.Family = fields[0]
		if len(fields) > 1 {
			entry.Layer3Protocol = fields[1]
		}
		if len(fields) > 2 {
			entry.Protocol = fields[2]
		}
		if len(fields) > 4 {
			entry.Timeout, _ = strconv.Atoi(fields[4])
		}
		nextEndpoint := "original"
		for i, field := range fields[3:] {
			if !strings.Contains(field, "=") {
				if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
					entry.StatusFlags = append(entry.StatusFlags, strings.Trim(field, "[]"))
				} else if i == 2 && !strings.Contains(field, "=") {
					entry.State = field
				}
				continue
			}
			parts := strings.SplitN(field, "=", 2)
			key, value := parts[0], parts[1]
			switch key {
			case "src", "dst", "sport", "dport":
				if nextEndpoint == "original" && endpointHasKey(entry.Original, key) {
					nextEndpoint = "reply"
				}
				if nextEndpoint == "original" {
					fillEndpoint(&entry.Original, key, value)
					if key == "dport" {
						nextEndpoint = "reply"
					}
				} else {
					fillEndpoint(&entry.Reply, key, value)
				}
			case "mark":
				entry.Mark = value
			case "use":
				entry.Use = value
			}
		}
		entry.SourceAddress = entry.Original.SourceAddress
		entry.DestinationAddress = entry.Original.DestinationAddress
		entry.SourcePort = entry.Original.SourcePort
		entry.DestinationPort = entry.Original.DestinationPort
		entry.ReplySourceAddress = entry.Reply.SourceAddress
		entry.ReplyDestinationAddress = entry.Reply.DestinationAddress
		entry.ReplySourcePort = entry.Reply.SourcePort
		entry.ReplyDestinationPort = entry.Reply.DestinationPort
		entries = append(entries, entry)
	}
	return entries
}

func ParseIPTablesSave(text, tool string) []FirewallRule {
	var rules []FirewallRule
	table := ""
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
			rules = append(rules, FirewallRule{Exists: true, Tool: tool, Table: table, RuleType: "table", LineNumber: i + 1, Expression: line})
		case strings.HasPrefix(line, ":"):
			fields := strings.Fields(strings.TrimPrefix(line, ":"))
			rule := FirewallRule{Exists: true, Tool: tool, Table: table, RuleType: "chain", LineNumber: i + 1, Expression: line}
			if len(fields) > 0 {
				rule.Chain = fields[0]
			}
			if len(fields) > 1 && fields[1] != "-" {
				rule.Policy = fields[1]
			}
			rules = append(rules, rule)
		case strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-I "):
			tokens := strings.Fields(line)
			rule := FirewallRule{Exists: true, Tool: tool, Table: table, RuleType: "rule", LineNumber: i + 1, Expression: line, Tokens: tokens}
			if len(tokens) > 1 {
				rule.Chain = tokens[1]
			}
			rule.Action, rule.Target = parseIPTablesTarget(tokens)
			rules = append(rules, rule)
		}
	}
	return rules
}

func ParseNFTRuleset(text string) []FirewallRule {
	var rules []FirewallRule
	table := ""
	chain := ""
	family := ""
	for i, line := range strings.Split(text, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" || clean == "}" {
			continue
		}
		tokens := strings.Fields(clean)
		if len(tokens) == 0 {
			continue
		}
		if len(tokens) >= 3 && tokens[0] == "table" {
			family = tokens[1]
			table = strings.TrimSuffix(tokens[2], "{")
			rules = append(rules, FirewallRule{Exists: true, Tool: "nft", Family: family, Table: table, RuleType: "table", LineNumber: i + 1, Expression: clean, Tokens: tokens})
			continue
		}
		if len(tokens) >= 2 && tokens[0] == "chain" {
			chain = strings.TrimSuffix(tokens[1], "{")
			rules = append(rules, FirewallRule{Exists: true, Tool: "nft", Family: family, Table: table, Chain: chain, RuleType: "chain", LineNumber: i + 1, Expression: clean, Tokens: tokens})
			continue
		}
		rule := FirewallRule{Exists: true, Tool: "nft", Family: family, Table: table, Chain: chain, RuleType: "rule", LineNumber: i + 1, Expression: clean, Tokens: tokens}
		if strings.HasPrefix(clean, "type ") {
			rule.RuleType = "chain_policy"
			rule.Hook = tokenAfter(tokens, "hook")
			rule.Priority = tokenAfter(tokens, "priority")
			rule.Policy = strings.TrimSuffix(tokenAfter(tokens, "policy"), ";")
		} else {
			rule.Action, rule.Target = parseNFTAction(tokens)
		}
		rules = append(rules, rule)
	}
	return rules
}

func ScanSocketOwners(procRoot string) (map[string][]SocketOwner, []Issue) {
	pids, err := procfs.ListPIDs(procRoot)
	if err != nil {
		return map[string][]SocketOwner{}, []Issue{{Path: procRoot, Kind: "proc", Error: err.Error()}}
	}
	owners := map[string][]SocketOwner{}
	var issues []Issue
	for _, pid := range pids {
		base := filepath.Join(procRoot, strconv.Itoa(pid))
		status, err := procfs.ParseStatusFile(filepath.Join(base, "status"))
		if err != nil {
			if isRaceError(err) {
				continue
			}
			issues = append(issues, issue(filepath.Join(base, "status"), "process_status", err))
			continue
		}
		entries, err := os.ReadDir(filepath.Join(base, "fd"))
		if err != nil {
			if isRaceError(err) {
				continue
			}
			issues = append(issues, issue(filepath.Join(base, "fd"), "process_fd", err))
			continue
		}
		cmdline, cmdlineErr := procfs.ReadNullSeparated(filepath.Join(base, "cmdline"))
		if cmdlineErr != nil && !isRaceError(cmdlineErr) {
			issues = append(issues, issue(filepath.Join(base, "cmdline"), "process_cmdline", cmdlineErr))
		}
		exe, exeErr := os.Readlink(filepath.Join(base, "exe"))
		if exeErr != nil && !isRaceError(exeErr) {
			issues = append(issues, issue(filepath.Join(base, "exe"), "process_exe", exeErr))
		}
		cwd, cwdErr := os.Readlink(filepath.Join(base, "cwd"))
		if cwdErr != nil && !isRaceError(cwdErr) {
			issues = append(issues, issue(filepath.Join(base, "cwd"), "process_cwd", cwdErr))
		}
		root, rootErr := os.Readlink(filepath.Join(base, "root"))
		if rootErr != nil && !isRaceError(rootErr) {
			issues = append(issues, issue(filepath.Join(base, "root"), "process_root", rootErr))
		}
		stat, statErr := procfs.ReadProcessStat(filepath.Join(base, "stat"))
		if statErr != nil && !isRaceError(statErr) {
			issues = append(issues, issue(filepath.Join(base, "stat"), "process_stat", statErr))
		}
		cgroups, cgroupErr := procfs.ReadCgroupLines(filepath.Join(base, "cgroup"))
		if cgroupErr != nil && !isRaceError(cgroupErr) {
			issues = append(issues, issue(filepath.Join(base, "cgroup"), "process_cgroup", cgroupErr))
		}
		cgroupPath := primaryCgroupPath(cgroups)
		for _, entry := range entries {
			fdPath := filepath.Join(base, "fd", entry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				if isRaceError(err) {
					continue
				}
				issues = append(issues, issue(fdPath, "process_fd_entry", err))
				continue
			}
			inode := socketInode(target)
			if inode == "" {
				continue
			}
			owners[inode] = append(owners[inode], SocketOwner{
				PID:              pid,
				PPID:             firstNumber(status["PPid"]),
				FD:               entry.Name(),
				ProcessName:      status["Name"],
				UID:              firstNumber(status["Uid"]),
				Cmdline:          redact.Args(cmdline),
				Exe:              exe,
				Cwd:              cwd,
				Root:             root,
				LineageKey:       ownerLineageKey(pid, stat.StartTimeTicks),
				ProcessSessionID: stat.SessionID,
				CgroupPath:       cgroupPath,
				ContainerID:      ContainerIDFromCgroups(cgroups),
			})
		}
	}
	for inode := range owners {
		sort.Slice(owners[inode], func(i, j int) bool {
			if owners[inode][i].PID == owners[inode][j].PID {
				return owners[inode][i].FD < owners[inode][j].FD
			}
			return owners[inode][i].PID < owners[inode][j].PID
		})
	}
	return owners, issues
}

func ContainerIDFromCgroups(cgroups []procfs.CgroupLine) string {
	for _, cgroup := range cgroups {
		for _, part := range strings.FieldsFunc(cgroup.Path, func(r rune) bool {
			return r == '/' || r == ':' || r == '-' || r == '.'
		}) {
			part = strings.TrimSpace(part)
			if len(part) >= 12 && isLowerHex(part) {
				if len(part) > 64 {
					part = part[:64]
				}
				return part
			}
		}
	}
	return ""
}

func issue(path, kind string, err error) Issue {
	return Issue{Path: path, Kind: kind, Error: err.Error(), IsRace: isRaceError(err)}
}

func isRaceError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func AttachOwners(connections []Connection, owners map[string][]SocketOwner) []Connection {
	for index := range connections {
		if connections[index].Inode == "" {
			continue
		}
		connections[index].Owners = owners[connections[index].Inode]
	}
	return connections
}

func Listeners(connections []Connection) []Connection {
	var listeners []Connection
	for _, conn := range connections {
		switch conn.Protocol {
		case "tcp", "tcp6":
			if conn.State == "LISTEN" {
				listeners = append(listeners, conn)
			}
		case "udp", "udp6":
			if conn.RemoteAddress == "" || conn.RemoteAddress == "0.0.0.0" || conn.RemoteAddress == "::" {
				listeners = append(listeners, conn)
			}
		case "unix":
			if conn.State == "LISTENING" || strings.EqualFold(conn.SocketFlags, "00010000") {
				listeners = append(listeners, conn)
			}
		}
	}
	return listeners
}

func parseAddrPort(value string, ipv6 bool) (string, int, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", value)
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}
	if ipv6 {
		return parseIPv6Hex(parts[0]), int(port), nil
	}
	return parseIPv4Hex(parts[0]), int(port), nil
}

func parseIPv4Hex(value string) string {
	if len(value) != 8 {
		return ""
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return ""
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(parsed))
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func parseIPv6Hex(value string) string {
	if len(value) != 32 {
		return ""
	}
	bytes := make([]byte, 16)
	for i := 0; i < 16; i += 4 {
		chunk, err := strconv.ParseUint(value[i*2:i*2+8], 16, 32)
		if err != nil {
			return ""
		}
		binary.LittleEndian.PutUint32(bytes[i:i+4], uint32(chunk))
	}
	return net.IP(bytes).String()
}

func parseIPv6Plain(value string) string {
	if len(value) != 32 {
		return ""
	}
	bytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		chunk, err := strconv.ParseUint(value[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		bytes[i] = byte(chunk)
	}
	return net.IP(bytes).String()
}

func parseMaybeIPv6(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, ":") {
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
		return value
	}
	if len(value) == 32 {
		return parseIPv6Plain(value)
	}
	return value
}

func parseHexInt(value string) int {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	n, _ := strconv.ParseInt(value, 16, 64)
	return int(n)
}

func socketState(value, protocol string) string {
	if strings.HasPrefix(protocol, "udp") {
		if value == "07" {
			return "UNCONN"
		}
	}
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if state, ok := states[strings.ToUpper(value)]; ok {
		return state
	}
	return value
}

func unixState(value string) string {
	states := map[string]string{
		"01": "LISTENING",
		"02": "CONNECTING",
		"03": "CONNECTED",
		"04": "DISCONNECTING",
	}
	if state, ok := states[strings.ToUpper(value)]; ok {
		return state
	}
	return value
}

func unixType(value string) string {
	types := map[string]string{
		"0001": "STREAM",
		"0002": "DGRAM",
		"0003": "RAW",
		"0005": "SEQPACKET",
	}
	if typ, ok := types[strings.ToUpper(value)]; ok {
		return typ
	}
	return value
}

func socketInode(target string) string {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
}

func firstNumber(value string) int {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}

func ownerLineageKey(pid int, startTimeTicks uint64) string {
	if startTimeTicks > 0 {
		return fmt.Sprintf("pid:%d:start_ticks:%d", pid, startTimeTicks)
	}
	return fmt.Sprintf("pid:%d", pid)
}

func primaryCgroupPath(cgroups []procfs.CgroupLine) string {
	for _, cgroup := range cgroups {
		if cgroup.Path != "" && cgroup.Path != "/" {
			return cgroup.Path
		}
	}
	if len(cgroups) > 0 {
		return cgroups[0].Path
	}
	return ""
}

func parseISCLeases(text, sourcePath string) []DHCPLease {
	var leases []DHCPLease
	var current *DHCPLease
	startLine := 0
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripInlineComment(raw))
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "lease") && strings.Contains(line, "{"):
			current = &DHCPLease{Exists: true, SourceFormat: "isc_dhclient", SourcePath: sourcePath, LineNumber: i + 1}
			startLine = i + 1
		case line == "}" || strings.HasPrefix(line, "}") || strings.HasSuffix(line, "}"):
			if current != nil {
				if current.LineNumber == 0 {
					current.LineNumber = startLine
				}
				leases = append(leases, *current)
				current = nil
			}
		default:
			if current != nil {
				fillISCLease(current, line)
			}
		}
	}
	if current != nil {
		leases = append(leases, *current)
	}
	return leases
}

func fillISCLease(lease *DHCPLease, line string) {
	line = strings.TrimSuffix(line, ";")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "interface":
		lease.Interface = strings.Trim(strings.Join(fields[1:], " "), `"`)
	case "fixed-address":
		if len(fields) > 1 {
			lease.Address = strings.Trim(fields[1], `";`)
		}
	case "option":
		if len(fields) < 3 {
			return
		}
		values := commaFields(strings.Join(fields[2:], " "))
		switch fields[1] {
		case "routers":
			lease.Router = uniqueStrings(append(lease.Router, values...))
		case "domain-name-servers":
			lease.DNS = uniqueStrings(append(lease.DNS, values...))
		case "dhcp-server-identifier":
			if len(values) > 0 {
				lease.Server = values[0]
			}
		}
	case "renew":
		lease.Renew = leaseTime(fields[1:])
	case "rebind":
		lease.Rebind = leaseTime(fields[1:])
	case "expire", "ends":
		lease.LeaseEnd = leaseTime(fields[1:])
	case "starts":
		lease.LeaseStart = leaseTime(fields[1:])
	}
}

func parseKeyValueLease(text, sourcePath string) []DHCPLease {
	lease := DHCPLease{Exists: true, SourceFormat: "key_value", SourcePath: sourcePath, LineNumber: 1}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripInlineComment(raw))
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch key {
		case "interface", "interface_name":
			lease.Interface = value
		case "address", "ip_address", "ip4_address_0":
			lease.Address = strings.Split(value, "/")[0]
		case "routers", "router", "gateway", "dhcp4_routers":
			lease.Router = uniqueStrings(append(lease.Router, splitAddressList(value)...))
		case "dns", "domain_name_servers", "dhcp4_domain_name_servers", "nameservers":
			lease.DNS = uniqueStrings(append(lease.DNS, splitAddressList(value)...))
		case "server_address", "dhcp_server_identifier", "server_identifier":
			lease.Server = value
		case "lease_start", "starts":
			lease.LeaseStart = value
		case "expiry", "lease_end", "ends", "expire":
			lease.LeaseEnd = value
		case "renew":
			lease.Renew = value
		case "rebind":
			lease.Rebind = value
		}
	}
	if lease.Interface == "" && lease.Address == "" && len(lease.Router) == 0 && len(lease.DNS) == 0 && lease.Server == "" {
		return nil
	}
	return []DHCPLease{lease}
}

func leaseTime(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	if len(fields) >= 3 && len(fields[0]) == 1 {
		return strings.Trim(strings.Join(fields[1:], " "), `";`)
	}
	return strings.Trim(strings.Join(fields, " "), `";`)
}

func commaFields(value string) []string {
	return splitAddressList(strings.Trim(value, `";`))
}

func splitAddressList(value string) []string {
	var result []string
	for _, item := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		item = strings.Trim(item, `"'`)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parsePairedProcNetCounters(text, source string) []NetworkCounter {
	var counters []NetworkCounter
	var headers map[string][]string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
			continue
		}
		protocol := strings.TrimSuffix(fields[0], ":")
		if headers == nil {
			headers = map[string][]string{}
		}
		if _, ok := headers[protocol]; !ok {
			headers[protocol] = append([]string{}, fields[1:]...)
			continue
		}
		names := headers[protocol]
		for i, value := range fields[1:] {
			if i >= len(names) {
				break
			}
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			counters = append(counters, NetworkCounter{Exists: true, Source: source, Protocol: protocol, Name: names[i], Value: n})
		}
		delete(headers, protocol)
	}
	return counters
}

func parseSNMP6Counters(text, source string) []NetworkCounter {
	var counters []NetworkCounter
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		proto := "Ip6"
		for i, r := range fields[0] {
			if i > 0 && r >= 'A' && r <= 'Z' {
				proto = fields[0][:i]
				break
			}
		}
		counters = append(counters, NetworkCounter{Exists: true, Source: source, Protocol: proto, Name: fields[0], Value: n})
	}
	return counters
}

func splitDNSMasqValues(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return splitAddressList(value)
}

func dnsmasqServerValues(values []string) []string {
	var servers []string
	for _, value := range values {
		value = strings.Trim(value, "/")
		if ip := net.ParseIP(value); ip != nil {
			servers = append(servers, ip.String())
		}
	}
	return servers
}

func ipValues(values []string) []string {
	var result []string
	for _, value := range values {
		value = strings.Trim(value, "[]")
		host, _, err := net.SplitHostPort(value)
		if err == nil {
			value = host
		}
		if ip := net.ParseIP(value); ip != nil {
			result = append(result, ip.String())
		}
	}
	return result
}

func isLowerHex(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func parseUint(value string) uint64 {
	n, _ := strconv.ParseUint(value, 10, 64)
	return n
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readInt(path string) int {
	value, _ := strconv.Atoi(readTrimmed(path))
	return value
}

func readInterfaceMaster(base string) string {
	target, err := os.Readlink(filepath.Join(base, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func parseInterfaceFlags(value string) []string {
	if value == "" {
		return nil
	}
	raw := strings.TrimPrefix(strings.ToLower(value), "0x")
	n, err := strconv.ParseUint(raw, 16, 32)
	if err != nil {
		return []string{value}
	}
	flags := []struct {
		bit  uint64
		name string
	}{
		{0x1, "up"},
		{0x2, "broadcast"},
		{0x8, "loopback"},
		{0x10, "point_to_point"},
		{0x40, "running"},
		{0x80, "noarp"},
		{0x100, "promisc"},
		{0x1000, "multicast"},
		{0x20000, "lower_up"},
		{0x40000, "dormant"},
	}
	var result []string
	for _, flag := range flags {
		if n&flag.bit != 0 {
			result = append(result, flag.name)
		}
	}
	return result
}

func runtimeFlags(flags net.Flags) []string {
	var result []string
	if flags&net.FlagUp != 0 {
		result = append(result, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		result = append(result, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		result = append(result, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		result = append(result, "point_to_point")
	}
	if flags&net.FlagMulticast != 0 {
		result = append(result, "multicast")
	}
	return result
}

func inferInterfaceKinds(base string, iface Interface) []string {
	var hints []string
	name := strings.ToLower(iface.Name)
	switch {
	case name == "lo":
		hints = append(hints, "loopback")
	case strings.HasPrefix(name, "veth"):
		hints = append(hints, "veth")
	case strings.HasPrefix(name, "docker"):
		hints = append(hints, "docker")
	case strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "bridge"):
		hints = append(hints, "bridge")
	case strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "utun"):
		hints = append(hints, "tun")
	case strings.HasPrefix(name, "tap"):
		hints = append(hints, "tap")
	case strings.HasPrefix(name, "wg"):
		hints = append(hints, "wireguard")
	}
	if base != "" {
		if _, err := os.Stat(filepath.Join(base, "bridge")); err == nil {
			hints = append(hints, "bridge")
		}
		if _, err := os.Stat(filepath.Join(base, "tun_flags")); err == nil {
			hints = append(hints, "tun_tap")
		}
		if _, err := os.Stat(filepath.Join(base, "wireguard")); err == nil {
			hints = append(hints, "wireguard")
		}
		if target, err := os.Readlink(filepath.Join(base, "device", "driver")); err == nil {
			driver := strings.ToLower(filepath.Base(target))
			if strings.Contains(driver, "veth") {
				hints = append(hints, "veth")
			}
			if strings.Contains(driver, "wireguard") {
				hints = append(hints, "wireguard")
			}
		}
	}
	return uniqueStrings(hints)
}

func parseRuntimeIPv4(addrs []net.Addr) []IPAddress {
	var result []IPAddress
	for _, addr := range addrs {
		ip, ipnet, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		result = append(result, IPAddress{Address: ip4.String(), CIDR: fmt.Sprintf("%s/%d", ip4.String(), ones), PrefixLength: ones})
	}
	return result
}

func stripInlineComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func fillEndpoint(endpoint *Endpoint, key, value string) {
	switch key {
	case "src":
		endpoint.SourceAddress = value
	case "dst":
		endpoint.DestinationAddress = value
	case "sport":
		endpoint.SourcePort, _ = strconv.Atoi(value)
	case "dport":
		endpoint.DestinationPort, _ = strconv.Atoi(value)
	}
}

func endpointHasKey(endpoint Endpoint, key string) bool {
	switch key {
	case "src":
		return endpoint.SourceAddress != ""
	case "dst":
		return endpoint.DestinationAddress != ""
	case "sport":
		return endpoint.SourcePort != 0
	case "dport":
		return endpoint.DestinationPort != 0
	default:
		return false
	}
}

func parseIPTablesTarget(tokens []string) (string, string) {
	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i] == "-j" || tokens[i] == "-g" {
			return strings.ToLower(tokens[i+1]), tokens[i+1]
		}
	}
	return "", ""
}

func parseNFTAction(tokens []string) (string, string) {
	actions := map[string]bool{
		"accept": true, "drop": true, "reject": true, "queue": true, "return": true,
		"jump": true, "goto": true, "masquerade": true, "redirect": true, "dnat": true, "snat": true,
	}
	for i, token := range tokens {
		clean := strings.Trim(token, ";")
		if actions[clean] {
			target := ""
			if (clean == "jump" || clean == "goto" || clean == "dnat" || clean == "snat" || clean == "redirect") && i+1 < len(tokens) {
				target = strings.Trim(tokens[i+1], ";")
			}
			return clean, target
		}
	}
	return "", ""
}

func tokenAfter(tokens []string, key string) string {
	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i] == key {
			return tokens[i+1]
		}
	}
	return ""
}

func uniqueIPAddresses(items []IPAddress) []IPAddress {
	seen := map[string]bool{}
	var result []IPAddress
	for _, item := range items {
		key := item.Address + "/" + strconv.Itoa(item.PrefixLength)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Address == result[j].Address {
			return result[i].PrefixLength < result[j].PrefixLength
		}
		return result[i].Address < result[j].Address
	})
	return result
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
