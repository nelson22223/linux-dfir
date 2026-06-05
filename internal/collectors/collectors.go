package collectors

import (
	"context"

	"linux-dfir/internal/collectors/browser"
	"linux-dfir/internal/collectors/container"
	"linux-dfir/internal/collectors/disk"
	"linux-dfir/internal/collectors/files"
	"linux-dfir/internal/collectors/host"
	"linux-dfir/internal/collectors/kernel"
	"linux-dfir/internal/collectors/logs"
	"linux-dfir/internal/collectors/network"
	"linux-dfir/internal/collectors/packages"
	"linux-dfir/internal/collectors/persistence"
	"linux-dfir/internal/collectors/process"
	"linux-dfir/internal/collectors/system"
	"linux-dfir/internal/collectors/timeinfo"
	"linux-dfir/internal/collectors/users"
	"linux-dfir/internal/output"
)

type Collector func(context.Context, *output.Manager) error

func Registry() map[string]Collector {
	return map[string]Collector{
		"host":        host.Collect,
		"browser":     browser.Collect,
		"container":   container.Collect,
		"files":       files.Collect,
		"kernel":      kernel.Collect,
		"logs":        logs.Collect,
		"network":     network.Collect,
		"packages":    packages.Collect,
		"persistence": persistence.Collect,
		"process":     process.Collect,
		"system":      system.Collect,
		"users":       users.Collect,
		"disk":        disk.Collect,
		"time":        timeinfo.Collect,
	}
}
