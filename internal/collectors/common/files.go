package common

import (
	"errors"
	"os"
	"strings"
)

func ReadText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ReadFirstExisting(paths ...string) (string, string, error) {
	for _, path := range paths {
		data, err := ReadText(path)
		if err == nil {
			return path, data, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return path, "", err
		}
	}
	return "", "", os.ErrNotExist
}

func Lines(text string) []string {
	raw := strings.Split(text, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
