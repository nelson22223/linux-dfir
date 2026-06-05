package system

import "testing"

func TestParseMemInfo(t *testing.T) {
	items := ParseMemInfo("MemTotal:       16384 kB\nSwapTotal: 0 kB\n")
	if len(items) != 2 || items[0].Key != "MemTotal" || items[0].Value != 16384 || items[0].Unit != "kB" {
		t.Fatalf("unexpected meminfo parse: %+v", items)
	}
}

func TestParseCPUInfo(t *testing.T) {
	items := ParseCPUInfo("processor : 0\nmodel name : Test CPU\n\nprocessor : 1\nmodel name : Test CPU\n")
	if len(items) != 2 || items[0].Fields["model name"] != "Test CPU" {
		t.Fatalf("unexpected cpuinfo parse: %+v", items)
	}
}
