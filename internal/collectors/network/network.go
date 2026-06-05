package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
	"linux-dfir/internal/netproc"
	"linux-dfir/internal/output"
	"linux-dfir/internal/redact"
)

var (
	procNetRoot             = "/proc/net"
	procRoot                = "/proc"
	sysClassNetRoot         = "/sys/class/net"
	hostsPath               = "/etc/hosts"
	resolvConfPath          = "/etc/resolv.conf"
	dpkgStatusPath          = "/var/lib/dpkg/status"
	dpkgInfoDir             = "/var/lib/dpkg/info"
	runtimeInterfaces       = net.Interfaces
	networkPersistencePaths = []string{
		"/etc/environment",
		"/etc/wgetrc",
		"/etc/curlrc",
		"/etc/ssh/ssh_config",
		"/etc/netplan",
		"/etc/NetworkManager/system-connections",
		"/etc/wireguard",
		"/etc/tailscale",
		"/etc/cloudflared",
		"/etc/frp",
		"/etc/openvpn",
	}
)

type ConnectionRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	IsListener bool                 `json:"is_listener,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.Connection
}

type RouteRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.Route
}

type ARPRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.ARPEntry
}

type InterfaceRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.Interface
}

type DNSConfigRecord struct {
	evidence.RecordMeta
	EntityType     string                  `json:"entity_type,omitempty"`
	EntityID       string                  `json:"entity_id,omitempty"`
	ConfigType     string                  `json:"config_type,omitempty"`
	Sources        []evidence.SourceRef    `json:"sources,omitempty"`
	HostsEntry     *netproc.HostsEntry     `json:"hosts_entry,omitempty"`
	ResolverConfig *netproc.ResolverConfig `json:"resolver_config,omitempty"`
}

type ConntrackRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.ConntrackEntry
}

type FirewallRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.FirewallRule
}

type NetworkFlowRecord struct {
	evidence.RecordMeta
	EntityType    string                `json:"entity_type,omitempty"`
	EntityID      string                `json:"entity_id,omitempty"`
	Sources       []evidence.SourceRef  `json:"sources,omitempty"`
	FlowKind      string                `json:"flow_kind,omitempty"`
	RemoteScope   string                `json:"remote_scope,omitempty"`
	Socket        netproc.Connection    `json:"socket"`
	ProcessOwners []netproc.SocketOwner `json:"process_owners,omitempty"`
}

type NetworkPersistenceRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	Exists     bool                 `json:"exists"`
	Path       string               `json:"path,omitempty"`
	LineNumber int                  `json:"line_number,omitempty"`
	ItemType   string               `json:"item_type,omitempty"`
	Key        string               `json:"key,omitempty"`
	Value      string               `json:"value,omitempty"`
	Line       string               `json:"line,omitempty"`
}

type packageOwner struct {
	Manager string
	Name    string
	Version string
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeNativeCommandOutputs(ctx, out); err != nil {
		return err
	}

	owners, ownerIssues := netproc.ScanSocketOwners(procRoot)
	for _, issue := range ownerIssues {
		if issue.IsRace {
			continue
		}
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: issue.Error, SourcePath: issue.Path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	enrichSocketOwners(owners)

	connections, connSources, err := collectConnections(out, owners)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	routes, err := collectRoutes(out)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	arpEntries, err := collectARP(out)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	interfaces, err := collectInterfaces(out)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectDNSConfig(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectNetworkFlows(out, connections); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectConntrack(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectFirewall(ctx, out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectNetworkPersistence(out); err != nil {
		return err
	}
	if err := writeLegacy(out, connections, routes, arpEntries, interfaces, connSources); err != nil {
		return err
	}
	if err := copyText(out, hostsPath, "network/hosts", "legacy/network/hosts"); err != nil {
		return err
	}
	if err := copyText(out, resolvConfPath, "network/resolv.conf", "legacy/network/resolv.conf"); err != nil {
		return err
	}
	if err := copyDHCPLeases(out); err != nil {
		return err
	}
	if err := copyProcNetStats(out); err != nil {
		return err
	}
	return nil
}

func collectConnections(out *output.Manager, owners map[string][]netproc.SocketOwner) ([]netproc.Connection, []string, error) {
	specs := []struct {
		file     string
		protocol string
		ipv6     bool
		unix     bool
	}{
		{"tcp", "tcp", false, false},
		{"tcp6", "tcp6", true, false},
		{"udp", "udp", false, false},
		{"udp6", "udp6", true, false},
		{"unix", "unix", false, true},
	}
	var all []netproc.Connection
	var sources []string
	records := map[string]ConnectionRecord{}
	for _, spec := range specs {
		sourcePath := filepath.Join(procNetRoot, spec.file)
		text, err := os.ReadFile(sourcePath)
		if err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			if err := writeAbsentConnection(out, sourcePath, err.Error()); err != nil {
				return nil, sources, err
			}
			continue
		}
		sources = append(sources, sourcePath)
		var parsed []netproc.Connection
		if spec.unix {
			parsed = netproc.ParseUnix(string(text))
		} else {
			parsed = netproc.ParseTCPUDP(string(text), spec.protocol, spec.ipv6)
		}
		parsed = netproc.AttachOwners(parsed, owners)
		for _, conn := range parsed {
			entityID := socketEntityID(conn)
			record := ConnectionRecord{
				RecordMeta: out.Meta("network", "entities/socket.jsonl", sourcePath, "procfs", "high"),
				EntityType: "socket",
				EntityID:   entityID,
				IsListener: isListener(conn),
				Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
				Connection: conn,
			}
			records[entityID] = mergeSocketRecord(records[entityID], record)
		}
		all = append(all, parsed...)
	}
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		record := records[id]
		sourcePath := sourcePathFromSources(record.Sources, procNetRoot)
		if len(record.Sources) > 1 {
			parts := make([]string, 0, len(record.Sources))
			for _, source := range record.Sources {
				parts = append(parts, source.SourcePath)
			}
			sourcePath = strings.Join(parts, ",")
		}
		if err := out.AppendAIJSONL("entities/socket.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
			return nil, sources, err
		}
	}
	return all, sources, nil
}

func collectRoutes(out *output.Manager) ([]netproc.Route, error) {
	sourcePath := filepath.Join(procNetRoot, "route")
	text, err := os.ReadFile(sourcePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		record := RouteRecord{
			RecordMeta: out.Meta("network", "facts/routes.jsonl", sourcePath, "procfs", "high"),
			EntityType: "route",
			EntityID:   "route:absent:" + sourcePath,
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			Route:      netproc.Route{Exists: false, AbsentReason: err.Error()},
		}
		return nil, out.AppendAIJSONL("facts/routes.jsonl", record, "network", sourcePath, "procfs", "high")
	}
	routes := netproc.ParseRoutes(string(text))
	for _, route := range routes {
		record := RouteRecord{
			RecordMeta: out.Meta("network", "facts/routes.jsonl", sourcePath, "procfs", "high"),
			EntityType: "route",
			EntityID:   routeEntityID(route),
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			Route:      route,
		}
		if err := out.AppendAIJSONL("facts/routes.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
			return nil, err
		}
	}
	return routes, nil
}

func collectARP(out *output.Manager) ([]netproc.ARPEntry, error) {
	sourcePath := filepath.Join(procNetRoot, "arp")
	text, err := os.ReadFile(sourcePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		record := ARPRecord{
			RecordMeta: out.Meta("network", "facts/arp.jsonl", sourcePath, "procfs", "high"),
			EntityType: "arp_entry",
			EntityID:   "arp:absent:" + sourcePath,
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			ARPEntry:   netproc.ARPEntry{Exists: false, AbsentReason: err.Error()},
		}
		return nil, out.AppendAIJSONL("facts/arp.jsonl", record, "network", sourcePath, "procfs", "high")
	}
	entries := netproc.ParseARP(string(text))
	for _, entry := range entries {
		record := ARPRecord{
			RecordMeta: out.Meta("network", "facts/arp.jsonl", sourcePath, "procfs", "high"),
			EntityType: "arp_entry",
			EntityID:   arpEntityID(entry),
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			ARPEntry:   entry,
		}
		if err := out.AppendAIJSONL("facts/arp.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

func collectInterfaces(out *output.Manager) ([]netproc.Interface, error) {
	devPath := filepath.Join(procNetRoot, "dev")
	dev, err := os.ReadFile(devPath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: devPath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		record := InterfaceRecord{
			RecordMeta: out.Meta("network", "entities/interface.jsonl", devPath, "procfs", "high"),
			EntityType: "interface",
			EntityID:   "interface:absent:" + devPath,
			Sources:    []evidence.SourceRef{{SourcePath: devPath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			Interface:  netproc.Interface{Exists: false, AbsentReason: err.Error()},
		}
		return nil, out.AppendAIJSONL("entities/interface.jsonl", record, "network", devPath, "procfs", "high")
	}
	inet6Path := filepath.Join(procNetRoot, "if_inet6")
	inet6, inet6Err := os.ReadFile(inet6Path)
	if inet6Err != nil && !os.IsNotExist(inet6Err) {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: inet6Err.Error(), SourcePath: inet6Path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	interfaces := netproc.ParseInterfaces(string(dev), string(inet6))
	interfaces = netproc.EnrichInterfacesFromSysfs(interfaces, sysClassNetRoot)
	if runtime, runtimeErr := runtimeInterfaces(); runtimeErr == nil {
		interfaces = netproc.ApplyRuntimeInterfaceAddrs(interfaces, runtime)
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: runtimeErr.Error(), SourcePath: "net.Interfaces", SourceType: "go_runtime", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	for _, iface := range interfaces {
		record := InterfaceRecord{
			RecordMeta: out.Meta("network", "entities/interface.jsonl", devPath, "procfs", "high"),
			EntityType: "interface",
			EntityID:   "interface:" + iface.Name,
			Sources:    interfaceSources(devPath, inet6Path, inet6Err, sysClassNetRoot),
			Interface:  iface,
		}
		if err := out.AppendAIJSONL("entities/interface.jsonl", record, "network", devPath, "procfs", "high"); err != nil {
			return nil, err
		}
	}
	return interfaces, nil
}

func collectDNSConfig(out *output.Manager) error {
	if err := collectHostsConfig(out); err != nil {
		return err
	}
	return collectResolverConfig(out)
}

func collectHostsConfig(out *output.Manager) error {
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		record := DNSConfigRecord{
			RecordMeta: out.Meta("network", "facts/dns_config.jsonl", hostsPath, "file", "high"),
			EntityType: "dns_config",
			EntityID:   "dns_config:hosts:absent",
			ConfigType: "hosts",
			Sources:    []evidence.SourceRef{{SourcePath: hostsPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/hosts"}},
			HostsEntry: &netproc.HostsEntry{Exists: false, AbsentReason: err.Error()},
		}
		if !os.IsNotExist(err) {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: hostsPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/hosts"})
		}
		return out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", hostsPath, "file", "high")
	}
	for _, entry := range netproc.ParseHosts(string(data)) {
		entryCopy := entry
		record := DNSConfigRecord{
			RecordMeta: out.Meta("network", "facts/dns_config.jsonl", hostsPath, "file", "high"),
			EntityType: "dns_config",
			EntityID:   fmt.Sprintf("dns_config:hosts:%s:%d", entry.IP, entry.LineNumber),
			ConfigType: "hosts",
			Sources:    []evidence.SourceRef{{SourcePath: hostsPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/hosts"}},
			HostsEntry: &entryCopy,
		}
		if err := out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", hostsPath, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func collectResolverConfig(out *output.Manager) error {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		config := netproc.ResolverConfig{Exists: false, AbsentReason: err.Error()}
		record := DNSConfigRecord{
			RecordMeta:     out.Meta("network", "facts/dns_config.jsonl", resolvConfPath, "file", "high"),
			EntityType:     "dns_config",
			EntityID:       "dns_config:resolv_conf",
			ConfigType:     "resolv_conf",
			Sources:        []evidence.SourceRef{{SourcePath: resolvConfPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/resolv.conf"}},
			ResolverConfig: &config,
		}
		if !os.IsNotExist(err) {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: resolvConfPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/resolv.conf"})
		}
		return out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", resolvConfPath, "file", "high")
	}
	config := netproc.ParseResolvConf(string(data))
	record := DNSConfigRecord{
		RecordMeta:     out.Meta("network", "facts/dns_config.jsonl", resolvConfPath, "file", "high"),
		EntityType:     "dns_config",
		EntityID:       "dns_config:resolv_conf",
		ConfigType:     "resolv_conf",
		Sources:        []evidence.SourceRef{{SourcePath: resolvConfPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/resolv.conf"}},
		ResolverConfig: &config,
	}
	return out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", resolvConfPath, "file", "high")
}

func collectNetworkFlows(out *output.Manager, connections []netproc.Connection) error {
	for _, conn := range connections {
		if !conn.Exists {
			continue
		}
		sourcePath := procNetRoot
		record := NetworkFlowRecord{
			RecordMeta:    out.Meta("network", "facts/network_flows.jsonl", sourcePath, "procfs", "high"),
			EntityType:    "network_flow",
			EntityID:      "network_flow:" + strings.TrimPrefix(socketEntityID(conn), "socket:"),
			Sources:       []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			FlowKind:      flowKind(conn),
			RemoteScope:   remoteScope(conn.RemoteAddress),
			Socket:        conn,
			ProcessOwners: conn.Owners,
		}
		if err := out.AppendAIJSONL("facts/network_flows.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
			return err
		}
	}
	return nil
}

func collectConntrack(out *output.Manager) error {
	paths := []string{filepath.Join(procNetRoot, "nf_conntrack"), filepath.Join(procNetRoot, "ip_conntrack")}
	wrote := false
	for _, sourcePath := range paths {
		data, err := os.ReadFile(sourcePath)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			}
			record := ConntrackRecord{
				RecordMeta:     out.Meta("network", "facts/conntrack_entries.jsonl", sourcePath, "procfs", "high"),
				EntityType:     "conntrack_entry",
				EntityID:       "conntrack:absent:" + sourcePath,
				Sources:        []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
				ConntrackEntry: netproc.ConntrackEntry{Exists: false, AbsentReason: err.Error()},
			}
			if err := out.AppendAIJSONL("facts/conntrack_entries.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
				return err
			}
			continue
		}
		for _, entry := range netproc.ParseConntrack(string(data)) {
			record := ConntrackRecord{
				RecordMeta:     out.Meta("network", "facts/conntrack_entries.jsonl", sourcePath, "procfs", "high"),
				EntityType:     "conntrack_entry",
				EntityID:       conntrackEntityID(entry),
				Sources:        []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
				ConntrackEntry: entry,
			}
			if err := out.AppendAIJSONL("facts/conntrack_entries.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
				return err
			}
			wrote = true
		}
	}
	_ = wrote
	return nil
}

func collectFirewall(ctx context.Context, out *output.Manager) error {
	specs := []struct {
		tool   string
		args   []string
		legacy string
		parse  func(string) []netproc.FirewallRule
	}{
		{tool: "nft", args: []string{"list", "ruleset"}, legacy: "network/firewall/nft_list_ruleset.out", parse: netproc.ParseNFTRuleset},
		{tool: "iptables-save", legacy: "network/firewall/iptables-save.out", parse: func(text string) []netproc.FirewallRule { return netproc.ParseIPTablesSave(text, "iptables-save") }},
		{tool: "ip6tables-save", legacy: "network/firewall/ip6tables-save.out", parse: func(text string) []netproc.FirewallRule { return netproc.ParseIPTablesSave(text, "ip6tables-save") }},
	}
	for _, spec := range specs {
		result := common.RunCommand(ctx, spec.tool, spec.args...)
		sourcePath := strings.TrimSpace(strings.Join(append([]string{spec.tool}, spec.args...), " "))
		if result.Missing() {
			record := FirewallRecord{
				RecordMeta:   out.Meta("network", "facts/firewall_rules.jsonl", sourcePath, "native_command", "medium"),
				EntityType:   "firewall_rule",
				EntityID:     "firewall:absent:" + spec.tool,
				Sources:      []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)}},
				FirewallRule: netproc.FirewallRule{Exists: false, AbsentReason: result.Err.Error(), Tool: spec.tool},
			}
			if err := out.AppendAIJSONL("facts/firewall_rules.jsonl", record, "network", sourcePath, "native_command", "medium"); err != nil {
				return err
			}
			continue
		}
		if result.Err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: result.Err.Error(), SourcePath: sourcePath, SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)})
		}
		if len(result.Output) > 0 {
			if err := out.WriteLegacyFromSource(spec.legacy, result.Output, "network", sourcePath, "native_command", "medium"); err != nil {
				return err
			}
		}
		rules := spec.parse(string(result.Output))
		if len(rules) == 0 {
			status := "no_rules"
			if result.Err != nil {
				status = result.Err.Error()
			}
			record := FirewallRecord{
				RecordMeta:   out.Meta("network", "facts/firewall_rules.jsonl", sourcePath, "native_command", "medium"),
				EntityType:   "firewall_rule",
				EntityID:     "firewall:status:" + spec.tool,
				Sources:      []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)}},
				FirewallRule: netproc.FirewallRule{Exists: true, Tool: spec.tool, RuleType: "status", Expression: status},
			}
			if err := out.AppendAIJSONL("facts/firewall_rules.jsonl", record, "network", sourcePath, "native_command", "medium"); err != nil {
				return err
			}
			continue
		}
		for _, rule := range rules {
			record := FirewallRecord{
				RecordMeta:   out.Meta("network", "facts/firewall_rules.jsonl", sourcePath, "native_command", "medium"),
				EntityType:   "firewall_rule",
				EntityID:     firewallEntityID(rule),
				Sources:      []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)}},
				FirewallRule: rule,
			}
			if err := out.AppendAIJSONL("facts/firewall_rules.jsonl", record, "network", sourcePath, "native_command", "medium"); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectNetworkPersistence(out *output.Manager) error {
	paths := discoverNetworkPersistenceFiles()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: path, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			}
			continue
		}
		for _, record := range parseNetworkPersistenceFile(out, path, string(data)) {
			if err := out.AppendAIJSONL("facts/network_persistence.jsonl", record, "network", path, "file", "high"); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeLegacy(out *output.Manager, connections []netproc.Connection, routes []netproc.Route, arpEntries []netproc.ARPEntry, interfaces []netproc.Interface, connSources []string) error {
	connSource := procNetRoot
	if len(connSources) > 0 {
		connSource = strings.Join(connSources, ",")
	}
	if err := out.WriteLegacyFromSource("network/proc_net_sockets.out", []byte(renderNetstat(connections)), "network", connSource, "procfs", "high"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource("network/proc_net_route.out", []byte(renderRoutes(routes)), "network", filepath.Join(procNetRoot, "route"), "procfs", "high"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource("network/proc_net_arp.out", []byte(renderARP(arpEntries)), "network", filepath.Join(procNetRoot, "arp"), "procfs", "high"); err != nil {
		return err
	}
	return out.WriteLegacyFromSource("network/proc_net_interfaces.out", []byte(renderInterfaces(interfaces)), "network", filepath.Join(procNetRoot, "dev"), "procfs", "high")
}

func writeNativeCommandOutputs(ctx context.Context, out *output.Manager) error {
	specs := []struct {
		command string
		args    []string
		legacy  string
	}{
		{command: "ifconfig", args: []string{"-a"}, legacy: "network/ifconfig_-a.out"},
		{command: "route", args: []string{"-nv"}, legacy: "network/route_-nv.out"},
		{command: "netstat", args: []string{"-avpeW"}, legacy: "network/netstat_-avpeW.out"},
		{command: "netstat", args: []string{"-rn"}, legacy: "network/netstat_-rn.out"},
		{command: "netstat", args: []string{"-s"}, legacy: "network/netstat_-s.out"},
		{command: "arp", args: []string{"-a"}, legacy: "network/arp_-a.out"},
		{command: "ip", args: []string{"addr"}, legacy: "network/ip_addr.out"},
		{command: "ip", args: []string{"route"}, legacy: "network/ip_route.out"},
		{command: "ip", args: []string{"link"}, legacy: "network/ip_link.out"},
		{command: "ip", args: []string{"rule"}, legacy: "network/ip_rule.out"},
	}
	for _, spec := range specs {
		result := common.RunCommand(ctx, spec.command, spec.args...)
		if result.Missing() {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: result.Err.Error(), SourcePath: result.CommandLine(), SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)})
			continue
		}
		if result.Err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: result.Err.Error(), SourcePath: result.CommandLine(), SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)})
		}
		if len(result.Output) == 0 {
			continue
		}
		if err := out.WriteLegacyFromSource(spec.legacy, result.Output, "network", result.CommandLine(), "native_command", "medium"); err != nil {
			return err
		}
	}
	return nil
}

func copyText(out *output.Manager, sourcePath, legacyRel, rawRef string) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: rawRef})
		return nil
	}
	return out.WriteLegacyFromSource(legacyRel, data, "network", sourcePath, "file", "high")
}

func copyDHCPLeases(out *output.Manager) error {
	for _, sourceDir := range []string{"/var/lib/dhcp", "/var/lib/dhclient"} {
		entries, err := os.ReadDir(sourceDir)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourceDir, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/dhcp/"})
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			sourcePath := filepath.Join(sourceDir, entry.Name())
			data, err := os.ReadFile(sourcePath)
			if err != nil {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/dhcp/" + entry.Name()})
				continue
			}
			if err := out.WriteLegacyFromSource(filepath.Join("network/dhcp", entry.Name()), data, "network", sourcePath, "file", "high"); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyProcNetStats(out *output.Manager) error {
	specs := []struct {
		source string
		legacy string
	}{
		{source: filepath.Join(procNetRoot, "snmp"), legacy: "network/proc_net_snmp.out"},
		{source: filepath.Join(procNetRoot, "netstat"), legacy: "network/proc_net_netstat.out"},
		{source: filepath.Join(procNetRoot, "snmp6"), legacy: "network/proc_net_snmp6.out"},
	}
	for _, spec := range specs {
		data, err := os.ReadFile(spec.source)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: spec.source, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/" + spec.legacy})
			}
			continue
		}
		if err := out.WriteLegacyFromSource(spec.legacy, data, "network", spec.source, "procfs", "high"); err != nil {
			return err
		}
	}
	return nil
}

func writeAbsentConnection(out *output.Manager, sourcePath, reason string) error {
	record := ConnectionRecord{
		RecordMeta: out.Meta("network", "entities/socket.jsonl", sourcePath, "procfs", "high"),
		EntityType: "socket_table",
		EntityID:   "socket:absent:" + sourcePath,
		Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
		Connection: netproc.Connection{Exists: false, AbsentReason: reason},
	}
	return out.AppendAIJSONL("entities/socket.jsonl", record, "network", sourcePath, "procfs", "high")
}

func isListener(conn netproc.Connection) bool {
	return len(netproc.Listeners([]netproc.Connection{conn})) == 1
}

func socketEntityID(conn netproc.Connection) string {
	if conn.Inode != "" {
		return "socket:" + conn.Inode
	}
	if conn.Protocol == "unix" && conn.SocketPath != "" {
		return "socket:unix:" + conn.SocketPath
	}
	return fmt.Sprintf("socket:%s:%s:%d:%s:%d", conn.Protocol, conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort)
}

func routeEntityID(route netproc.Route) string {
	return fmt.Sprintf("route:%s:%s:%s:%s:%d", route.Interface, route.Destination, route.Gateway, route.Mask, route.Metric)
}

func arpEntityID(entry netproc.ARPEntry) string {
	return fmt.Sprintf("arp:%s:%s", entry.Device, entry.IP)
}

func conntrackEntityID(entry netproc.ConntrackEntry) string {
	return fmt.Sprintf("conntrack:%s:%s:%s:%d:%s:%d", entry.Protocol, entry.Original.SourceAddress, entry.Original.DestinationAddress, entry.Original.DestinationPort, entry.Reply.SourceAddress, entry.Reply.DestinationPort)
}

func firewallEntityID(rule netproc.FirewallRule) string {
	return fmt.Sprintf("firewall:%s:%s:%s:%s:%d", rule.Tool, rule.Table, rule.Chain, rule.RuleType, rule.LineNumber)
}

func interfaceSources(devPath, inet6Path string, inet6Err error, sysfsRoot string) []evidence.SourceRef {
	sources := []evidence.SourceRef{{SourcePath: devPath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}}
	if inet6Err == nil {
		sources = append(sources, evidence.SourceRef{SourcePath: inet6Path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	if sysfsRoot != "" {
		sources = append(sources, evidence.SourceRef{SourcePath: sysfsRoot, SourceType: "sysfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	return sources
}

func enrichSocketOwners(owners map[string][]netproc.SocketOwner) {
	packages := loadPackageOwners()
	for inode, inodeOwners := range owners {
		for i := range inodeOwners {
			exe := cleanDeletedSuffix(inodeOwners[i].Exe)
			if exe != "" && filepath.IsAbs(exe) {
				if hash, err := integrity.HashFile(exe); err == nil {
					inodeOwners[i].ExeSHA256 = hash.SHA256
				} else {
					inodeOwners[i].ExeHashError = err.Error()
				}
				if owner, ok := packages[exe]; ok {
					inodeOwners[i].PackageManager = owner.Manager
					inodeOwners[i].PackageName = owner.Name
					inodeOwners[i].PackageVersion = owner.Version
				}
			}
		}
		owners[inode] = inodeOwners
	}
}

func loadPackageOwners() map[string]packageOwner {
	owners := map[string]packageOwner{}
	versions := loadDPKGVersions()
	entries, err := os.ReadDir(dpkgInfoDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
				continue
			}
			pkgKey := strings.TrimSuffix(entry.Name(), ".list")
			data, err := os.ReadFile(filepath.Join(dpkgInfoDir, entry.Name()))
			if err != nil {
				continue
			}
			pkgName := strings.Split(pkgKey, ":")[0]
			for _, line := range strings.Split(string(data), "\n") {
				path := strings.TrimSpace(line)
				if path == "" {
					continue
				}
				owners[path] = packageOwner{Manager: "dpkg", Name: pkgName, Version: versions[pkgName]}
			}
		}
	}
	if len(owners) == 0 {
		for _, command := range []string{"sh", "bash", "sshd", "systemd"} {
			if path, err := exec.LookPath(command); err == nil {
				owners[path] = packageOwner{Manager: "path_lookup", Name: command}
			}
		}
	}
	return owners
}

func loadDPKGVersions() map[string]string {
	data, err := os.ReadFile(dpkgStatusPath)
	if err != nil {
		return map[string]string{}
	}
	versions := map[string]string{}
	for _, stanza := range strings.Split(string(data), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			if !strings.Contains(line, ":") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
		if fields["Package"] != "" {
			versions[fields["Package"]] = fields["Version"]
		}
	}
	return versions
}

func cleanDeletedSuffix(path string) string {
	path = strings.TrimSuffix(path, " (deleted)")
	return strings.TrimSpace(path)
}

func flowKind(conn netproc.Connection) string {
	if isListener(conn) {
		return "listener"
	}
	if strings.HasPrefix(conn.Protocol, "tcp") || strings.HasPrefix(conn.Protocol, "udp") {
		if conn.RemoteAddress != "" && conn.RemoteAddress != "0.0.0.0" && conn.RemoteAddress != "::" {
			return "connected"
		}
	}
	if conn.Protocol == "unix" {
		return "unix_socket"
	}
	return "socket"
}

func remoteScope(address string) string {
	if address == "" {
		return ""
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return "name_or_path"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsPrivate() {
		return "private"
	}
	if ip.IsUnspecified() {
		return "unspecified"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link_local"
	}
	return "public"
}

func discoverNetworkPersistenceFiles() []string {
	var files []string
	for _, path := range networkPersistencePaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		_ = filepath.WalkDir(path, func(item string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			files = append(files, item)
			return nil
		})
	}
	sort.Strings(files)
	return files
}

func parseNetworkPersistenceFile(out *output.Manager, path, text string) []NetworkPersistenceRecord {
	var records []NetworkPersistenceRecord
	for i, line := range strings.Split(text, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, ";") {
			continue
		}
		itemType, key, value := networkPersistenceLine(clean)
		if itemType == "" {
			continue
		}
		record := NetworkPersistenceRecord{
			RecordMeta: out.Meta("network", "facts/network_persistence.jsonl", path, "file", "high"),
			EntityType: "network_persistence_item",
			EntityID:   fmt.Sprintf("network_persistence:%s:%d", path, i+1),
			Sources:    []evidence.SourceRef{{SourcePath: path, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			Exists:     true,
			Path:       path,
			LineNumber: i + 1,
			ItemType:   itemType,
			Key:        key,
			Value:      redact.Value(key, value),
			Line:       redactNetworkPersistenceLine(clean, key),
		}
		records = append(records, record)
	}
	return records
}

func networkPersistenceLine(line string) (string, string, string) {
	lower := strings.ToLower(line)
	for _, key := range []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy"} {
		if strings.Contains(lower, key) {
			return "proxy_config", key, valueAfterSeparator(line)
		}
	}
	for _, key := range []string{"proxycommand", "proxyjump"} {
		if strings.Contains(lower, key) {
			return "ssh_proxy_config", key, valueAfterSeparator(line)
		}
	}
	for _, key := range []string{"password", "passwd", "token", "credential", "privatekey", "private_key", "presharedkey", "pre_shared_key", "psk", "api_key", "apikey", "authkey", "auth_key", "secret"} {
		if strings.Contains(lower, key) {
			return "network_credential_reference", key, valueAfterSeparator(line)
		}
	}
	for _, key := range []string{"wireguard", "tailscale", "cloudflared", "frpc", "frps", "ngrok", "openvpn"} {
		if strings.Contains(lower, key) {
			return "tunnel_config_line", key, valueAfterSeparator(line)
		}
	}
	return "", "", ""
}

func valueAfterSeparator(line string) string {
	for _, sep := range []string{"=", " "} {
		if idx := strings.Index(line, sep); idx >= 0 && idx+1 < len(line) {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return line
}

func redactNetworkPersistenceLine(line, key string) string {
	line = redact.Text(line)
	if !redact.SensitiveKey(key) {
		return line
	}
	for _, sep := range []string{"=", " "} {
		idx := strings.Index(line, sep)
		if idx >= 0 && idx+1 < len(line) {
			return strings.TrimRight(line[:idx+1], " ") + " [redacted]"
		}
	}
	return "[redacted]"
}

func mergeSocketRecord(existing, next ConnectionRecord) ConnectionRecord {
	if existing.EntityID == "" {
		next.Sources = uniqueNetworkSources(next.Sources)
		next.Connection.Owners = uniqueOwners(next.Connection.Owners)
		return next
	}
	existing.IsListener = existing.IsListener || next.IsListener
	existing.Sources = uniqueNetworkSources(append(existing.Sources, next.Sources...))
	existing.Connection.Owners = uniqueOwners(append(existing.Connection.Owners, next.Connection.Owners...))
	if !existing.Connection.Exists && next.Connection.Exists {
		existing.Connection = next.Connection
		existing.Connection.Owners = uniqueOwners(append(existing.Connection.Owners, next.Connection.Owners...))
	}
	return existing
}

func uniqueNetworkSources(sources []evidence.SourceRef) []evidence.SourceRef {
	seen := map[string]bool{}
	result := []evidence.SourceRef{}
	for _, source := range sources {
		key := source.SourcePath + "\x00" + source.SourceType + "\x00" + source.SourceTrust + "\x00" + source.RawArtifactRef
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, source)
	}
	return result
}

func uniqueOwners(owners []netproc.SocketOwner) []netproc.SocketOwner {
	seen := map[string]bool{}
	result := []netproc.SocketOwner{}
	for _, owner := range owners {
		key := fmt.Sprintf("%d:%s:%s:%d", owner.PID, owner.FD, owner.ProcessName, owner.UID)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, owner)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PID == result[j].PID {
			return result[i].FD < result[j].FD
		}
		return result[i].PID < result[j].PID
	})
	return result
}

func sourcePathFromSources(sources []evidence.SourceRef, fallback string) string {
	if len(sources) == 0 || sources[0].SourcePath == "" {
		return fallback
	}
	return sources[0].SourcePath
}

func renderNetstat(connections []netproc.Connection) string {
	sort.Slice(connections, func(i, j int) bool {
		if connections[i].Protocol == connections[j].Protocol {
			return connections[i].Inode < connections[j].Inode
		}
		return connections[i].Protocol < connections[j].Protocol
	})
	var b strings.Builder
	b.WriteString("Proto Local Address           Foreign Address         State       User       Inode      PID/Program name\n")
	for _, conn := range connections {
		if !conn.Exists {
			continue
		}
		local := endpoint(conn.LocalAddress, conn.LocalPort, conn.SocketPath)
		remote := endpoint(conn.RemoteAddress, conn.RemotePort, "")
		owner := "-"
		if len(conn.Owners) > 0 {
			owner = fmt.Sprintf("%d/%s", conn.Owners[0].PID, conn.Owners[0].ProcessName)
		}
		b.WriteString(fmt.Sprintf("%-5s %-23s %-23s %-11s %-10d %-10s %s\n", conn.Protocol, local, remote, conn.State, conn.UID, conn.Inode, owner))
	}
	return b.String()
}

func renderRoutes(routes []netproc.Route) string {
	var b strings.Builder
	b.WriteString("Kernel IP routing table\n")
	b.WriteString("Destination     Gateway         Genmask         Flags Metric Iface\n")
	for _, route := range routes {
		if !route.Exists {
			continue
		}
		b.WriteString(fmt.Sprintf("%-15s %-15s %-15s %-5s %-6d %s\n", route.Destination, route.Gateway, route.Mask, route.Flags, route.Metric, route.Interface))
	}
	return b.String()
}

func renderARP(entries []netproc.ARPEntry) string {
	var b strings.Builder
	b.WriteString("Address                  HWtype  HWaddress           Flags Mask            Iface\n")
	for _, entry := range entries {
		if !entry.Exists {
			continue
		}
		b.WriteString(fmt.Sprintf("%-24s %-7s %-19s %-5s %-15s %s\n", entry.IP, entry.HWType, entry.MAC, entry.Flags, "*", entry.Device))
	}
	return b.String()
}

func renderInterfaces(interfaces []netproc.Interface) string {
	var b strings.Builder
	b.WriteString("Interface RX-Bytes RX-Packets TX-Bytes TX-Packets IPv6\n")
	for _, iface := range interfaces {
		if !iface.Exists {
			continue
		}
		b.WriteString(fmt.Sprintf("%-9s %8d %10d %8d %10d %s\n", iface.Name, iface.RXBytes, iface.RXPackets, iface.TXBytes, iface.TXPackets, strings.Join(iface.IPv6, ",")))
	}
	return b.String()
}

func endpoint(address string, port int, socketPath string) string {
	if socketPath != "" {
		return socketPath
	}
	if address == "" && port == 0 {
		return "*"
	}
	return fmt.Sprintf("%s:%d", address, port)
}
