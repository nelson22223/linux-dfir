package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"linux-dfir/internal/app"
)

func main() {
	if err := app.Run(context.Background(), os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if !app.ErrorReported() {
			fmt.Fprintf(os.Stderr, "Execution failed: %v\n", err)
		}
		os.Exit(app.ErrorExitCode())
	}
	// Propagate the DDEI rootkit detector verdict as the process exit code
	// (0 clean, 2 inconclusive/execution failure, 3 infected).
	if code := app.ExitCode(); code != 0 {
		os.Exit(code)
	}
}
