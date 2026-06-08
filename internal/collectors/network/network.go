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
	procNetRoot                = "/proc/net"
	procRoot                   = "/proc"
	sysClassNetRoot            = "/sys/class/net"
	hostsPath                  = "/etc/hosts"
	resolvConfPath             = "/etc/resolv.conf"
	systemdResolveRuntimePaths = []string{"/run/systemd/resolve/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"}
	systemdResolvedConfigPaths = []string{"/etc/systemd/resolved.conf", "/etc/systemd/resolved.conf.d"}
	networkManagerDNSPaths     = []string{"/run/NetworkManager/resolv.conf", "/run/NetworkManager/no-stub-resolv.conf", "/etc/NetworkManager/NetworkManager.conf", "/etc/NetworkManager/conf.d"}
	dnsmasqConfigPaths         = []string{"/etc/dnsmasq.conf", "/etc/dnsmasq.d", "/run/dnsmasq", "/var/lib/misc/dnsmasq.leases"}
	dhcpLeaseDirs              = []string{"/var/lib/dhcp", "/var/lib/dhclient", "/var/lib/NetworkManager"}
	dpkgStatusPath             = "/var/lib/dpkg/status"
	dpkgInfoDir                = "/var/lib/dpkg/info"
	runtimeInterfaces          = net.Interfaces
	networkCommandRunner       = common.RunCommand
	networkPersistencePaths    = []string{
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

type IPv6RouteRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.IPv6Route
}

type ARPRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.ARPEntry
}

type NeighborRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.NeighborEntry
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

type DHCPLeaseRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.DHCPLease
}

type DNSSourceHint struct {
	Source  string `json:"source,omitempty"`
	Manager string `json:"manager,omitempty"`
	Runtime bool   `json:"runtime,omitempty"`
	Static  bool   `json:"static,omitempty"`
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
	EntityType         string                `json:"entity_type,omitempty"`
	EntityID           string                `json:"entity_id,omitempty"`
	Sources            []evidence.SourceRef  `json:"sources,omitempty"`
	FlowKind           string                `json:"flow_kind,omitempty"`
	RemoteScope        string                `json:"remote_scope,omitempty"`
	Socket             netproc.Connection    `json:"socket"`
	ProcessOwners      []netproc.SocketOwner `json:"process_owners,omitempty"`
	OwnerLineageKeys   []string              `json:"owner_lineage_keys,omitempty"`
	ProcessSessionIDs  []int                 `json:"process_session_ids,omitempty"`
	ContainerIDs       []string              `json:"container_ids,omitempty"`
	CgroupPaths        []string              `json:"cgroup_paths,omitempty"`
	RouteInterfaceHint string                `json:"route_interface_hint,omitempty"`
	DNSSourceHint      []DNSSourceHint       `json:"dns_source_hint,omitempty"`
}

type CommandObservationRecord struct {
	evidence.RecordMeta
	EntityType     string               `json:"entity_type,omitempty"`
	EntityID       string               `json:"entity_id,omitempty"`
	Sources        []evidence.SourceRef `json:"sources,omitempty"`
	Command        string               `json:"command"`
	Args           []string             `json:"args,omitempty"`
	CommandLine    string               `json:"command_line"`
	Path           string               `json:"path,omitempty"`
	SHA256         string               `json:"sha256,omitempty"`
	HashError      string               `json:"hash_error,omitempty"`
	PackageManager string               `json:"package_manager,omitempty"`
	PackageName    string               `json:"package_name,omitempty"`
	PackageVersion string               `json:"package_version,omitempty"`
	Missing        bool                 `json:"missing,omitempty"`
	ExitStatus     string               `json:"exit_status,omitempty"`
	LineCount      int                  `json:"line_count,omitempty"`
	ParsedSummary  map[string]string    `json:"parsed_summary,omitempty"`
}

type NetworkCounterRecord struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type,omitempty"`
	EntityID   string               `json:"entity_id,omitempty"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
	netproc.NetworkCounter
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
	packages := loadPackageOwners()
	if err := writeNativeCommandOutputs(ctx, out, packages); err != nil {
		return err
	}

	owners, ownerIssues := netproc.ScanSocketOwners(procRoot)
	for _, issue := range ownerIssues {
		if issue.IsRace {
			continue
		}
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: issue.Error, SourcePath: issue.Path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	enrichSocketOwners(owners, packages)

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
	ipv6Routes, err := collectIPv6Routes(out)
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
	if err := collectNeighbors(out); err != nil {
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
	dnsHints, err := collectDNSConfig(out)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectNetworkFlows(out, connections, routes, ipv6Routes, dnsHints); err != nil {
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
	if err := collectDHCPLeases(out); err != nil {
		return err
	}
	if err := collectNetworkCounters(out); err != nil {
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

func collectIPv6Routes(out *output.Manager) ([]netproc.IPv6Route, error) {
	sourcePath := filepath.Join(procNetRoot, "ipv6_route")
	text, err := os.ReadFile(sourcePath)
	if err != nil {
		if !os.IsNotExist(err) {
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		}
		record := IPv6RouteRecord{
			RecordMeta: out.Meta("network", "facts/ipv6_routes.jsonl", sourcePath, "procfs", "high"),
			EntityType: "route",
			EntityID:   "ipv6_route:absent:" + sourcePath,
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			IPv6Route:  netproc.IPv6Route{Exists: false, AbsentReason: err.Error()},
		}
		return nil, out.AppendAIJSONL("facts/ipv6_routes.jsonl", record, "network", sourcePath, "procfs", "high")
	}
	routes := netproc.ParseIPv6Routes(string(text))
	for _, route := range routes {
		record := IPv6RouteRecord{
			RecordMeta: out.Meta("network", "facts/ipv6_routes.jsonl", sourcePath, "procfs", "high"),
			EntityType: "route",
			EntityID:   ipv6RouteEntityID(route),
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			IPv6Route:  route,
		}
		if err := out.AppendAIJSONL("facts/ipv6_routes.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
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

func collectNeighbors(out *output.Manager) error {
	specs := []struct {
		path   string
		family string
	}{
		{path: filepath.Join(procNetRoot, "ndisc_cache"), family: "ipv6"},
	}
	for _, spec := range specs {
		data, err := os.ReadFile(spec.path)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: spec.path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			}
			record := NeighborRecord{
				RecordMeta:    out.Meta("network", "facts/neighbors.jsonl", spec.path, "procfs", "high"),
				EntityType:    "neighbor_entry",
				EntityID:      "neighbor:absent:" + spec.path,
				Sources:       []evidence.SourceRef{{SourcePath: spec.path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
				NeighborEntry: netproc.NeighborEntry{Exists: false, Family: spec.family, AbsentReason: err.Error()},
			}
			if err := out.AppendAIJSONL("facts/neighbors.jsonl", record, "network", spec.path, "procfs", "high"); err != nil {
				return err
			}
			continue
		}
		for _, neighbor := range netproc.ParseNeighborCache(string(data), spec.family) {
			record := NeighborRecord{
				RecordMeta:    out.Meta("network", "facts/neighbors.jsonl", spec.path, "procfs", "high"),
				EntityType:    "neighbor_entry",
				EntityID:      neighborEntityID(neighbor),
				Sources:       []evidence.SourceRef{{SourcePath: spec.path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
				NeighborEntry: neighbor,
			}
			if err := out.AppendAIJSONL("facts/neighbors.jsonl", record, "network", spec.path, "procfs", "high"); err != nil {
				return err
			}
		}
	}
	return nil
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

func collectDNSConfig(out *output.Manager) ([]DNSSourceHint, error) {
	var hints []DNSSourceHint
	if err := collectHostsConfig(out); err != nil {
		return hints, err
	}
	resolverHints, err := collectResolverConfig(out)
	if err != nil {
		return hints, err
	}
	hints = append(hints, resolverHints...)
	runtimeHints, err := collectDNSRuntimeConfig(out)
	if err != nil {
		return hints, err
	}
	hints = append(hints, runtimeHints...)
	return uniqueDNSSourceHints(hints), nil
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

func collectResolverConfig(out *output.Manager) ([]DNSSourceHint, error) {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		config := netproc.ResolverConfig{Exists: false, AbsentReason: err.Error(), Source: resolvConfPath, Scope: "static", Static: true, Manager: "libc"}
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
		return nil, out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", resolvConfPath, "file", "high")
	}
	config := netproc.ParseResolvConf(string(data))
	config.Source = resolvConfPath
	config.Scope = "static"
	config.Static = true
	config.Manager = "libc"
	if target, linkErr := os.Readlink(resolvConfPath); linkErr == nil {
		config.SymlinkTarget = target
		if strings.Contains(target, "systemd/resolve") {
			config.Manager = "systemd-resolved"
			config.Runtime = true
			config.Scope = "runtime_link"
		} else if strings.Contains(target, "NetworkManager") {
			config.Manager = "NetworkManager"
			config.Runtime = true
			config.Scope = "runtime_link"
		}
	}
	config.StubResolver = hasStubResolver(config.Nameservers)
	record := DNSConfigRecord{
		RecordMeta:     out.Meta("network", "facts/dns_config.jsonl", resolvConfPath, "file", "high"),
		EntityType:     "dns_config",
		EntityID:       "dns_config:resolv_conf",
		ConfigType:     "resolv_conf",
		Sources:        []evidence.SourceRef{{SourcePath: resolvConfPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/network/resolv.conf"}},
		ResolverConfig: &config,
	}
	return []DNSSourceHint{{Source: resolvConfPath, Manager: config.Manager, Runtime: config.Runtime, Static: config.Static}}, out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", resolvConfPath, "file", "high")
}

func collectDNSRuntimeConfig(out *output.Manager) ([]DNSSourceHint, error) {
	var hints []DNSSourceHint
	collectFile := func(path, manager, scope string, parser func(string) netproc.ResolverConfig) error {
		if !regularFileForRead(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: path, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			return nil
		}
		config := parser(string(data))
		config.Source = path
		config.Manager = manager
		config.Scope = scope
		config.Runtime = strings.HasPrefix(path, "/run/") || strings.Contains(path, "/run/")
		config.Static = !config.Runtime
		config.StubResolver = hasStubResolver(config.Nameservers) || strings.Contains(filepath.Base(path), "stub")
		record := DNSConfigRecord{
			RecordMeta:     out.Meta("network", "facts/dns_config.jsonl", path, "file", "high"),
			EntityType:     "dns_config",
			EntityID:       fmt.Sprintf("dns_config:%s:%s", manager, path),
			ConfigType:     "dns_runtime",
			Sources:        []evidence.SourceRef{{SourcePath: path, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			ResolverConfig: &config,
		}
		if err := out.AppendAIJSONL("facts/dns_config.jsonl", record, "network", path, "file", "high"); err != nil {
			return err
		}
		hints = append(hints, DNSSourceHint{Source: path, Manager: manager, Runtime: config.Runtime, Static: config.Static})
		return nil
	}
	for _, path := range systemdResolveRuntimePaths {
		if err := collectFile(path, "systemd-resolved", "runtime", netproc.ParseResolvConf); err != nil {
			return hints, err
		}
	}
	for _, path := range expandFiles(systemdResolvedConfigPaths) {
		if err := collectFile(path, "systemd-resolved", "static", netproc.ParseResolvedConf); err != nil {
			return hints, err
		}
	}
	for _, path := range expandFiles(networkManagerDNSPaths) {
		parser := netproc.ParseResolvConf
		if strings.HasSuffix(path, ".conf") {
			parser = netproc.ParseNetworkManagerConfig
		}
		if err := collectFile(path, "NetworkManager", "runtime_or_static", parser); err != nil {
			return hints, err
		}
	}
	for _, path := range expandFiles(dnsmasqConfigPaths) {
		if strings.Contains(filepath.Base(path), "lease") {
			continue
		}
		if err := collectFile(path, "dnsmasq", "runtime_or_static", netproc.ParseDNSMasqConfig); err != nil {
			return hints, err
		}
	}
	return hints, nil
}

func collectNetworkFlows(out *output.Manager, connections []netproc.Connection, routes []netproc.Route, ipv6Routes []netproc.IPv6Route, dnsHints []DNSSourceHint) error {
	wrote := false
	for _, conn := range connections {
		if !conn.Exists {
			continue
		}
		sourcePath := procNetRoot
		ownerLineageKeys, sessionIDs, containerIDs, cgroupPaths := flowOwnerHints(conn.Owners)
		record := NetworkFlowRecord{
			RecordMeta:         out.Meta("network", "facts/network_flows.jsonl", sourcePath, "procfs", "high"),
			EntityType:         "network_flow",
			EntityID:           "network_flow:" + strings.TrimPrefix(socketEntityID(conn), "socket:"),
			Sources:            []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			FlowKind:           flowKind(conn),
			RemoteScope:        remoteScope(conn.RemoteAddress),
			Socket:             conn,
			ProcessOwners:      conn.Owners,
			OwnerLineageKeys:   ownerLineageKeys,
			ProcessSessionIDs:  sessionIDs,
			ContainerIDs:       containerIDs,
			CgroupPaths:        cgroupPaths,
			RouteInterfaceHint: routeInterfaceHint(conn.RemoteAddress, conn.Family, routes, ipv6Routes),
			DNSSourceHint:      dnsHints,
		}
		if err := out.AppendAIJSONL("facts/network_flows.jsonl", record, "network", sourcePath, "procfs", "high"); err != nil {
			return err
		}
		wrote = true
	}
	if !wrote {
		sourcePath := procNetRoot
		record := NetworkFlowRecord{
			RecordMeta: out.Meta("network", "facts/network_flows.jsonl", sourcePath, "procfs", "high"),
			EntityType: "network_flow",
			EntityID:   "network_flow:absent",
			Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			Socket:     netproc.Connection{Exists: false, AbsentReason: "no network flows discovered"},
		}
		return out.AppendAIJSONL("facts/network_flows.jsonl", record, "network", sourcePath, "procfs", "high")
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

func writeNativeCommandOutputs(ctx context.Context, out *output.Manager, packages map[string]packageOwner) error {
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
		{command: "ip", args: []string{"-6", "route"}, legacy: "network/ip_-6_route.out"},
		{command: "ip", args: []string{"neigh"}, legacy: "network/ip_neigh.out"},
		{command: "ss", args: []string{"-tunap"}, legacy: "network/ss_-tunap.out"},
		{command: "lsof", args: []string{"-nP", "-i"}, legacy: "network/lsof_-nP_-i.out"},
	}
	for _, spec := range specs {
		result := networkCommandRunner(ctx, spec.command, spec.args...)
		if err := writeCommandObservation(out, result, spec.legacy, packages); err != nil {
			return err
		}
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

func writeCommandObservation(out *output.Manager, result common.CommandResult, legacy string, packages map[string]packageOwner) error {
	sourcePath := result.CommandLine()
	record := CommandObservationRecord{
		RecordMeta:    out.Meta("network", "facts/command_observations.jsonl", sourcePath, "native_command", "medium"),
		EntityType:    "command_observation",
		EntityID:      "command_observation:" + sourcePath,
		Sources:       []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", legacy)}},
		Command:       result.Command,
		Args:          append([]string{}, result.Args...),
		CommandLine:   sourcePath,
		Path:          result.Path,
		Missing:       result.Missing(),
		LineCount:     countLines(result.Output),
		ParsedSummary: commandSummary(result.Command, result.Args, string(result.Output)),
	}
	if result.Err != nil {
		record.ExitStatus = result.Err.Error()
	} else {
		record.ExitStatus = "success"
	}
	if result.Path != "" {
		if hash, err := integrity.HashFile(result.Path); err == nil {
			record.SHA256 = hash.SHA256
		} else {
			record.HashError = err.Error()
		}
		if owner, ok := packages[result.Path]; ok {
			record.PackageManager = owner.Manager
			record.PackageName = owner.Name
			record.PackageVersion = owner.Version
		}
	}
	return out.AppendAIJSONL("facts/command_observations.jsonl", record, "network", sourcePath, "native_command", "medium")
}

func copyText(out *output.Manager, sourcePath, legacyRel, rawRef string) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: rawRef})
		return nil
	}
	return out.WriteLegacyFromSource(legacyRel, data, "network", sourcePath, "file", "high")
}

func collectDHCPLeases(out *output.Manager) error {
	wrote := false
	for _, sourceDir := range dhcpLeaseDirs {
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
			for _, lease := range netproc.ParseDHCPLeases(string(data), sourcePath) {
				record := DHCPLeaseRecord{
					RecordMeta: out.Meta("network", "facts/dhcp_leases.jsonl", sourcePath, "file", "high"),
					EntityType: "dhcp_lease",
					EntityID:   dhcpLeaseEntityID(lease),
					Sources:    []evidence.SourceRef{{SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: filepath.Join("legacy/network/dhcp", entry.Name())}},
					DHCPLease:  lease,
				}
				if err := out.AppendAIJSONL("facts/dhcp_leases.jsonl", record, "network", sourcePath, "file", "high"); err != nil {
					return err
				}
				wrote = true
			}
		}
	}
	if !wrote {
		record := DHCPLeaseRecord{
			RecordMeta: out.Meta("network", "facts/dhcp_leases.jsonl", strings.Join(dhcpLeaseDirs, ","), "file", "high"),
			EntityType: "dhcp_lease",
			EntityID:   "dhcp_lease:absent",
			Sources:    []evidence.SourceRef{{SourcePath: strings.Join(dhcpLeaseDirs, ","), SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
			DHCPLease:  netproc.DHCPLease{Exists: false, AbsentReason: "no readable dhcp lease records found"},
		}
		return out.AppendAIJSONL("facts/dhcp_leases.jsonl", record, "network", strings.Join(dhcpLeaseDirs, ","), "file", "high")
	}
	return nil
}

func collectNetworkCounters(out *output.Manager) error {
	specs := []struct {
		source string
		legacy string
		name   string
	}{
		{source: filepath.Join(procNetRoot, "snmp"), legacy: "network/proc_net_snmp.out", name: "snmp"},
		{source: filepath.Join(procNetRoot, "netstat"), legacy: "network/proc_net_netstat.out", name: "netstat"},
		{source: filepath.Join(procNetRoot, "snmp6"), legacy: "network/proc_net_snmp6.out", name: "snmp6"},
	}
	for _, spec := range specs {
		data, err := os.ReadFile(spec.source)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: "network", Error: err.Error(), SourcePath: spec.source, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/" + spec.legacy})
			}
			record := NetworkCounterRecord{
				RecordMeta:     out.Meta("network", "facts/network_counters.jsonl", spec.source, "procfs", "high"),
				EntityType:     "network_counter",
				EntityID:       "network_counter:absent:" + spec.name,
				Sources:        []evidence.SourceRef{{SourcePath: spec.source, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/" + spec.legacy}},
				NetworkCounter: netproc.NetworkCounter{Exists: false, Source: spec.name, AbsentReason: err.Error()},
			}
			if err := out.AppendAIJSONL("facts/network_counters.jsonl", record, "network", spec.source, "procfs", "high"); err != nil {
				return err
			}
			continue
		}
		if err := out.WriteLegacyFromSource(spec.legacy, data, "network", spec.source, "procfs", "high"); err != nil {
			return err
		}
		for _, counter := range netproc.ParseNetworkCounters(string(data), spec.name) {
			record := NetworkCounterRecord{
				RecordMeta:     out.Meta("network", "facts/network_counters.jsonl", spec.source, "procfs", "high"),
				EntityType:     "network_counter",
				EntityID:       networkCounterEntityID(counter),
				Sources:        []evidence.SourceRef{{SourcePath: spec.source, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/" + spec.legacy}},
				NetworkCounter: counter,
			}
			if err := out.AppendAIJSONL("facts/network_counters.jsonl", record, "network", spec.source, "procfs", "high"); err != nil {
				return err
			}
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

func ipv6RouteEntityID(route netproc.IPv6Route) string {
	return fmt.Sprintf("ipv6_route:%s:%s/%d:%s", route.Interface, route.Destination, route.DestinationPrefixLen, route.NextHop)
}

func arpEntityID(entry netproc.ARPEntry) string {
	return fmt.Sprintf("arp:%s:%s", entry.Device, entry.IP)
}

func neighborEntityID(entry netproc.NeighborEntry) string {
	return fmt.Sprintf("neighbor:%s:%s:%s", entry.Family, entry.Interface, entry.IPAddress)
}

func dhcpLeaseEntityID(lease netproc.DHCPLease) string {
	return fmt.Sprintf("dhcp_lease:%s:%s:%s:%d", lease.Interface, lease.Address, lease.SourcePath, lease.LineNumber)
}

func networkCounterEntityID(counter netproc.NetworkCounter) string {
	return fmt.Sprintf("network_counter:%s:%s:%s", counter.Source, counter.Protocol, counter.Name)
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

func enrichSocketOwners(owners map[string][]netproc.SocketOwner, packages map[string]packageOwner) {
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

func flowOwnerHints(owners []netproc.SocketOwner) ([]string, []int, []string, []string) {
	var lineageKeys []string
	var sessionIDs []int
	var containerIDs []string
	var cgroupPaths []string
	seenString := map[string]bool{}
	seenInt := map[int]bool{}
	for _, owner := range owners {
		if owner.LineageKey != "" && !seenString["lineage:"+owner.LineageKey] {
			lineageKeys = append(lineageKeys, owner.LineageKey)
			seenString["lineage:"+owner.LineageKey] = true
		}
		if owner.ProcessSessionID != 0 && !seenInt[owner.ProcessSessionID] {
			sessionIDs = append(sessionIDs, owner.ProcessSessionID)
			seenInt[owner.ProcessSessionID] = true
		}
		if owner.ContainerID != "" && !seenString["container:"+owner.ContainerID] {
			containerIDs = append(containerIDs, owner.ContainerID)
			seenString["container:"+owner.ContainerID] = true
		}
		if owner.CgroupPath != "" && !seenString["cgroup:"+owner.CgroupPath] {
			cgroupPaths = append(cgroupPaths, owner.CgroupPath)
			seenString["cgroup:"+owner.CgroupPath] = true
		}
	}
	sort.Strings(lineageKeys)
	sort.Ints(sessionIDs)
	sort.Strings(containerIDs)
	sort.Strings(cgroupPaths)
	return lineageKeys, sessionIDs, containerIDs, cgroupPaths
}

func routeInterfaceHint(address, family string, routes []netproc.Route, ipv6Routes []netproc.IPv6Route) string {
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	if family == "ipv6" || strings.Contains(address, ":") {
		bestIface := ""
		bestPrefix := -1
		for _, route := range ipv6Routes {
			if !route.Exists || route.Interface == "" {
				continue
			}
			if route.Destination == "::" && bestPrefix < route.DestinationPrefixLen {
				bestIface = route.Interface
				bestPrefix = route.DestinationPrefixLen
				continue
			}
			if route.DestinationPrefixLen > bestPrefix && ipv6InPrefix(ip, route.Destination, route.DestinationPrefixLen) {
				bestIface = route.Interface
				bestPrefix = route.DestinationPrefixLen
			}
		}
		return bestIface
	}
	bestIface := ""
	bestOnes := -1
	for _, route := range routes {
		if !route.Exists || route.Interface == "" {
			continue
		}
		_, bits := ipv4MaskSize(route.Mask)
		if bits > bestOnes && ipv4InRoute(ip, route.Destination, route.Mask) {
			bestIface = route.Interface
			bestOnes = bits
		}
	}
	return bestIface
}

func ipv4MaskSize(mask string) (int, int) {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0, 0
	}
	ones, bits := net.IPMask(ip).Size()
	if bits == 0 {
		return 0, 0
	}
	return ones, bits
}

func ipv4InRoute(ip net.IP, destination, mask string) bool {
	v4 := ip.To4()
	dest := net.ParseIP(destination).To4()
	m := net.ParseIP(mask).To4()
	if v4 == nil || dest == nil || m == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if v4[i]&m[i] != dest[i]&m[i] {
			return false
		}
	}
	return true
}

func ipv6InPrefix(ip net.IP, destination string, prefixLen int) bool {
	ip16 := ip.To16()
	dest := net.ParseIP(destination).To16()
	if ip16 == nil || dest == nil || prefixLen < 0 || prefixLen > 128 {
		return false
	}
	mask := net.CIDRMask(prefixLen, 128)
	return ip16.Mask(mask).Equal(dest.Mask(mask))
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
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !regularFileForRead(path) {
				continue
			}
			files = append(files, path)
			continue
		}
		_ = filepath.WalkDir(path, func(item string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !regularFileForRead(item) {
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

func expandFiles(paths []string) []string {
	var files []string
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !regularFileForRead(path) {
				continue
			}
			files = append(files, path)
			continue
		}
		_ = filepath.WalkDir(path, func(item string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !regularFileForRead(item) {
				return nil
			}
			files = append(files, item)
			return nil
		})
	}
	sort.Strings(files)
	return files
}

func regularFileForRead(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Stat(path)
		return err == nil && target.Mode().IsRegular()
	}
	return info.Mode().IsRegular()
}

func hasStubResolver(nameservers []string) bool {
	for _, ns := range nameservers {
		if ns == "127.0.0.53" || ns == "127.0.0.54" || ns == "::1" {
			return true
		}
	}
	return false
}

func uniqueDNSSourceHints(hints []DNSSourceHint) []DNSSourceHint {
	seen := map[string]bool{}
	var result []DNSSourceHint
	for _, hint := range hints {
		key := fmt.Sprintf("%s\x00%s\x00%t\x00%t", hint.Source, hint.Manager, hint.Runtime, hint.Static)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, hint)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Manager == result[j].Manager {
			return result[i].Source < result[j].Source
		}
		return result[i].Manager < result[j].Manager
	})
	return result
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	lines := strings.Count(string(data), "\n")
	if data[len(data)-1] != '\n' {
		lines++
	}
	return lines
}

func commandSummary(command string, args []string, output string) map[string]string {
	lines := nonEmptyLines(output)
	summary := map[string]string{
		"non_empty_lines": fmt.Sprint(len(lines)),
	}
	key := strings.TrimSpace(command + " " + strings.Join(args, " "))
	switch {
	case strings.HasPrefix(key, "ip rule"):
		summary["policy_rule_count"] = fmt.Sprint(len(lines))
	case strings.HasPrefix(key, "ip route"):
		summary["route_count"] = fmt.Sprint(len(lines))
		summary["default_route_count"] = fmt.Sprint(countLinesWithPrefix(lines, "default "))
	case strings.HasPrefix(key, "ip -6 route"):
		summary["ipv6_route_count"] = fmt.Sprint(len(lines))
	case strings.HasPrefix(key, "ip neigh"):
		summary["neighbor_count"] = fmt.Sprint(len(lines))
	case strings.HasPrefix(key, "ss "):
		summary["socket_line_count"] = fmt.Sprint(maxInt(0, len(lines)-1))
	case strings.HasPrefix(key, "netstat -s"):
		summary["counter_line_count"] = fmt.Sprint(len(lines))
	}
	return summary
}

func nonEmptyLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func countLinesWithPrefix(lines []string, prefix string) int {
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
