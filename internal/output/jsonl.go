package output

import (
	"encoding/json"
	"fmt"
	"os"
)

func appendJSONL(path string, value any) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write jsonl %s: %w", path, err)
	}
	return nil
}
