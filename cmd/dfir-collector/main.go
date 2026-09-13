package main

import (
	"context"
	"os"

	"linux-dfir/internal/app"
)

func main() {
	if err := app.Run(context.Background(), os.Args[1:]); err != nil {
		os.Exit(1)
	}
	// Propagate the DDEI rootkit detector verdict as the process exit code
	// (0 clean, 1 suspicious, 2 likely infected, 3 infected).
	if code := app.ExitCode(); code != 0 {
		os.Exit(code)
	}
}
