package ddeirootkit

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"linux-dfir/internal/netproc"
)

// These peers were explicitly selected for this DDEI investigation. A text
// occurrence or a local listening address is not a connection observation.
var confirmedPeers = map[string]bool{"101.91.168.5": true, "14.116.197.139": true}

type NetworkObservation struct {
	RemoteIP  string `json:"remote_ip"`
	Port      int    `json:"remote_port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Inode     string `json:"inode"`
	Source    string `json:"source"`
	Namespace string `json:"namespace"`
	PIDs      []int  `json:"pids"`
}

func confirmedPeer(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && confirmedPeers[addr.Unmap().String()]
}

func networkFindings(o Observations) []Finding {
	var findings []Finding
	for _, peer := range o.NetworkPeers {
		if !confirmedPeer(peer.RemoteIP) || peer.Port <= 0 || peer.Port > 65535 || peer.State == "LISTEN" {
			continue
		}
		level := LevelReview
		active := peer.Protocol == "tcp" && (peer.State == "ESTABLISHED" || peer.State == "SYN_SENT") || peer.Protocol == "udp" && peer.State == "ESTABLISHED"
		if active && len(peer.PIDs) > 0 {
			level = LevelCompromised
		}
		findings = append(findings, Finding{ID: "confirmed_network_peer", Title: "Confirmed case network IOC", Level: level,
			Detail: fmt.Sprintf("remote=%s:%d protocol=%s state=%s pids=%v inode=%s namespace=%s source=%s; based on an observed socket, not a text occurrence", peer.RemoteIP, peer.Port, peer.Protocol, peer.State, peer.PIDs, peer.Inode, peer.Namespace, peer.Source)})
	}
	return findings
}

func (c *collector) network() {
	c.networkWithRetry(func() []string { return c.networkAttempt(os.Readlink) })
}

// Only snapshot churn is recoverable by a later complete scan. All other gaps
// and all peer evidence stay attached to the collector across attempts.
func (c *collector) networkWithRetry(attempt func() []string) {
	var pending []string
	defer func() {
		c.o.Gaps = append(c.o.Gaps, pending...)
		seen := make(map[string]bool)
		var peers []NetworkObservation
		for _, peer := range c.o.NetworkPeers {
			peer.PIDs = append([]int(nil), peer.PIDs...)
			sort.Ints(peer.PIDs)
			ids := peer.PIDs[:0]
			for _, pid := range peer.PIDs {
				if len(ids) == 0 || ids[len(ids)-1] != pid {
					ids = append(ids, pid)
				}
			}
			peer.PIDs = ids
			// This fixed, JSON-safe struct includes source, namespace and owners;
			// never union ownership from independent observations.
			key, _ := json.Marshal(peer)
			if !seen[string(key)] {
				seen[string(key)] = true
				peers = append(peers, peer)
			}
		}
		c.o.NetworkPeers = peers
	}()
	for i := 0; i < 3; i++ {
		if err := c.ctx.Err(); err != nil {
			c.gap("network scan", err)
			return
		}
		gapCount := len(c.o.Gaps)
		churn := attempt()
		if err := c.ctx.Err(); err != nil {
			pending = append(pending, churn...)
			c.gap("network scan", err)
			return
		}
		// A scan reporting a coverage failure cannot supersede an earlier
		// snapshot, even when it returned no churn (for example an early abort).
		if len(c.o.Gaps) != gapCount {
			pending = append(pending, churn...)
		} else {
			pending = churn
		}
		if len(churn) == 0 {
			return
		}
	}
}

// The readlink seam permits deterministic namespace-transition tests.
func (c *collector) networkWithReadlink(readlink func(string) (string, error)) {
	churn := c.networkAttempt(readlink)
	c.o.Gaps = append(c.o.Gaps, churn...)
}

func (c *collector) networkAttempt(readlink func(string) (string, error)) []string {
	pids := c.networkProcesses()
	selfNS, err := readlink(c.path("/proc/self/ns/net"))
	if err != nil {
		c.gap("/proc/self/ns/net", err)
		return nil
	}
	namespaces := map[string]string{selfNS: c.path("/proc/net")}
	namespaceLinks := map[string]string{selfNS: c.path("/proc/self/ns/net")}
	pidNamespaces := map[int]string{}
	representatives := map[string]int{}
	for pid := range pids {
		if err := c.ctx.Err(); err != nil {
			c.gap("network namespace scan", err)
			return nil
		}
		dir := c.path(fmt.Sprintf("/proc/%d", pid))
		ns, err := readlink(dir + "/ns/net")
		if err != nil {
			if !c.gone(dir) {
				c.gap(dir+"/ns/net", err)
			}
			continue
		}
		pidNamespaces[pid] = ns
		if _, exists := namespaces[ns]; !exists {
			namespaces[ns] = dir + "/net"
			namespaceLinks[ns] = dir + "/ns/net"
			representatives[ns] = pid
		}
	}
	invalid := map[string]bool{}
	checkNamespace := func(ns, path, stage string) bool {
		current, err := readlink(path)
		if err != nil || current != ns {
			if err == nil {
				err = fmt.Errorf("network namespace changed from %s to %s", ns, current)
			}
			c.gap(path, fmt.Errorf("%s: %w", stage, err))
			invalid[ns] = true
			return false
		}
		return true
	}
	checkRepresentative := func(ns, stage string) bool {
		if !checkNamespace(ns, namespaceLinks[ns], stage) {
			return false
		}
		if pid, ok := representatives[ns]; ok {
			dir := c.path(fmt.Sprintf("/proc/%d", pid))
			if current, err := c.networkIdentity(dir); err != nil || current != pids[pid] {
				if err != nil && c.ctx.Err() != nil {
					c.gap(dir, err)
					return false
				}
				c.gap(dir, fmt.Errorf("process changed %s", stage))
				invalid[ns] = true
				return false
			}
		}
		return true
	}
	var peers []NetworkObservation
	validated := map[string]bool{}
	published := false
	defer func() {
		if published {
			return
		}
		// Early exits retain only table-validated sockets. Ownership is not
		// attached until the complete owner snapshot has been validated.
		for _, peer := range peers {
			if validated[peer.Namespace] && !invalid[peer.Namespace] {
				c.o.NetworkPeers = append(c.o.NetworkPeers, peer)
			}
		}
	}()
	keys := make([]string, 0, len(namespaces))
	for ns := range namespaces {
		keys = append(keys, ns)
	}
	sort.Strings(keys)
	for _, ns := range keys {
		if err := c.ctx.Err(); err != nil {
			c.gap("network socket table scan", err)
			return nil
		}
		if !checkRepresentative(ns, "before socket tables") {
			continue
		}
		for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
			path := filepath.Join(namespaces[ns], table)
			data, ok := c.text(path, strings.HasSuffix(table, "6"))
			if !ok {
				continue
			}
			protocol := strings.TrimSuffix(table, "6")
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) == 0 || !strings.Contains(lines[0], "local_address") || (!strings.Contains(lines[0], "rem_address") && !strings.Contains(lines[0], "remote_address")) {
				c.gap(path, fmt.Errorf("invalid socket table header"))
				continue
			}
			for _, line := range lines[1:] {
				if strings.TrimSpace(line) == "" {
					continue
				}
				rows := netproc.ParseTCPUDP(lines[0]+"\n"+line, protocol, strings.HasSuffix(table, "6"))
				if len(rows) != 1 {
					c.gap(path, fmt.Errorf("malformed socket row"))
					continue
				}
				r := rows[0]
				if confirmedPeer(r.RemoteAddress) && r.RemotePort > 0 && r.State != "LISTEN" {
					peers = append(peers, NetworkObservation{RemoteIP: r.RemoteAddress, Port: r.RemotePort, Protocol: protocol, State: r.State, Inode: r.Inode, Namespace: ns, Source: path})
				}
			}
		}
		validated[ns] = checkRepresentative(ns, "after socket tables")
	}
	if len(peers) == 0 {
		return c.checkNetworkSnapshot(pids)
	}
	owners := map[string][]int{}
	for pid, identity := range pids {
		if err := c.ctx.Err(); err != nil {
			c.gap("socket owner scan", err)
			return nil
		}
		dir := c.path(fmt.Sprintf("/proc/%d", pid))
		ns, known := pidNamespaces[pid]
		if !known || invalid[ns] || !checkNamespace(ns, dir+"/ns/net", "before socket owner observation") {
			continue
		}
		if current, err := c.networkIdentity(dir); err != nil || current != identity {
			if !c.gone(dir) {
				c.gap(dir, fmt.Errorf("process changed before socket owner observation"))
			}
			continue
		}
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			if !c.gone(dir) {
				c.gap(dir+"/fd", err)
			}
			continue
		}
		seen := map[string]bool{}
		var observed []string
		for _, fd := range fds {
			target, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil {
				if !os.IsNotExist(err) {
					c.gap(dir+"/fd/"+fd.Name(), err)
				}
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") && !seen[target] {
				seen[target] = true
				inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				observed = append(observed, inode)
			}
		}
		if current, err := c.networkIdentity(dir); err != nil || current != identity {
			if !c.gone(dir) {
				c.gap(dir, fmt.Errorf("process changed during socket owner observation"))
			}
			continue
		}
		if !checkNamespace(ns, dir+"/ns/net", "after socket owner observation") {
			continue
		}
		for _, inode := range observed {
			owners[inode] = append(owners[inode], pid)
		}
	}
	if err := c.ctx.Err(); err != nil {
		c.gap("socket owner scan", err)
		return nil
	}
	for _, ns := range keys {
		if err := c.ctx.Err(); err != nil {
			c.gap("socket owner snapshot", err)
			return nil
		}
		if !invalid[ns] {
			checkRepresentative(ns, "after socket owner snapshot")
		}
	}
	if err := c.ctx.Err(); err != nil {
		c.gap("socket owner snapshot", err)
		return nil
	}
	for _, peer := range peers {
		if !validated[peer.Namespace] || invalid[peer.Namespace] {
			continue
		}
		for _, pid := range owners[peer.Inode] {
			if !invalid[pidNamespaces[pid]] {
				peer.PIDs = append(peer.PIDs, pid)
			}
		}
		sort.Ints(peer.PIDs)
		c.o.NetworkPeers = append(c.o.NetworkPeers, peer)
	}
	published = true
	return c.checkNetworkSnapshot(pids)
}

func (c *collector) networkIdentity(dir string) (string, error) {
	b, err := readBounded(c.ctx, dir+"/stat", 65536)
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", fmt.Errorf("truncated process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}

func (c *collector) networkProcesses() map[int]string {
	result := map[int]string{}
	entries, err := os.ReadDir(c.path("/proc"))
	if err != nil {
		c.gap("network /proc enumeration", err)
		return result
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if err := c.ctx.Err(); err != nil {
			c.gap("network process enumeration", err)
			break
		}
		if len(result) >= 65536 {
			c.gap("network process enumeration", fmt.Errorf("process limit exceeded"))
			break
		}
		dir := c.path("/proc/" + entry.Name())
		identity, err := c.networkIdentity(dir)
		if err != nil {
			if !c.gone(dir) {
				c.gap(dir+"/stat", err)
			}
			continue
		}
		result[pid] = identity
	}
	return result
}

func (c *collector) checkNetworkSnapshot(before map[int]string) []string {
	var churn []string
	after := c.networkProcesses()
	for pid, identity := range after {
		if previous, ok := before[pid]; !ok || previous != identity {
			churn = append(churn, fmt.Sprintf("network snapshot: PID %d appeared or changed during scan; repeat observation required", pid))
		}
	}
	for pid := range before {
		if _, ok := after[pid]; !ok {
			churn = append(churn, fmt.Sprintf("network snapshot: PID %d disappeared during scan; repeat observation required", pid))
		}
	}
	sort.Strings(churn)
	return churn
}
