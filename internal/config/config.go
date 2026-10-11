// Package config reads the agent configuration file written by the installer.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config is the content of /etc/alertly/agent.yml.
type Config struct {
	Endpoint    string
	Token       string
	Docker      bool
	Logs        bool
	DownloadURL string
}

// Load reads a flat "key: value" file. Only the keys the installer writes are supported.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	cfg := Config{Logs: true}
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		key, value, ok := strings.Cut(text, ":")
		if !ok {
			return Config{}, fmt.Errorf("%s:%d: expected \"key: value\"", path, line)
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		switch strings.TrimSpace(key) {
		case "endpoint":
			cfg.Endpoint = strings.TrimRight(value, "/")
		case "token":
			cfg.Token = value
		case "docker":
			cfg.Docker = value == "true"
		case "logs":
			cfg.Logs = value == "true"
		case "download_url":
			cfg.DownloadURL = strings.TrimRight(value, "/")
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}

	if cfg.Endpoint == "" || cfg.Token == "" {
		return Config{}, fmt.Errorf("%s: endpoint and token are required", path)
	}

	return cfg, nil
}
