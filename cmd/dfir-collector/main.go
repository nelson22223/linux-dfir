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
}
