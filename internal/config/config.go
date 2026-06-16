package config

import (
	"os"
	"path/filepath"
)

const Version = "1.1.0"

type Config struct {
	OutputDir  string
	MaxFileMB  int64
	JSONOutput bool
	Verbose    bool
}

func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		OutputDir:  filepath.Join(home, ".kitinspect", "reports"),
		MaxFileMB:  500,
		JSONOutput: false,
		Verbose:    false,
	}
}

func (c *Config) EnsureDirs() error {
	return os.MkdirAll(c.OutputDir, 0755)
}
