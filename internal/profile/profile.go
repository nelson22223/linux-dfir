package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Definition struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Collectors  []string `yaml:"collectors"`
	Limits      Limits   `yaml:"limits"`
}

type Limits struct {
	MaxFileSize     int64  `yaml:"max_file_size"`
	Timeout         string `yaml:"timeout"`
	JournalMaxLines int    `yaml:"journal_max_lines"`
}

func Load(profileDir, name string) (Definition, error) {
	path := filepath.Join(profileDir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return Definition{}, fmt.Errorf("load profile %q: %w", name, err)
	}

	var def Definition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return Definition{}, fmt.Errorf("parse profile %q: %w", name, err)
	}
	if def.Name == "" {
		def.Name = name
	}
	if len(def.Collectors) == 0 {
		return Definition{}, fmt.Errorf("profile %q has no collectors", name)
	}
	return def, nil
}
