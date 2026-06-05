package common

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

type CommandResult struct {
	Command string
	Args    []string
	Output  []byte
	Path    string
	Err     error
}

func RunCommand(ctx context.Context, command string, args ...string) CommandResult {
	path, err := exec.LookPath(command)
	if err != nil {
		return CommandResult{Command: command, Args: args, Err: err}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	output, runErr := cmd.CombinedOutput()
	return CommandResult{
		Command: command,
		Args:    args,
		Output:  output,
		Path:    path,
		Err:     runErr,
	}
}

func (r CommandResult) CommandLine() string {
	parts := append([]string{r.Command}, r.Args...)
	return strings.Join(parts, " ")
}

func (r CommandResult) Missing() bool {
	return errors.Is(r.Err, exec.ErrNotFound)
}
