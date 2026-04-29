package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server     ServerConfig
	Credential CredentialConfig
	Session    SessionConfig
	Lingma     LingmaConfig
}

type ServerConfig struct {
	Host       string
	Port       int
	AdminToken string
}

type CredentialConfig struct {
	AuthFile string
}

type SessionConfig struct {
	TTLMinutes  int
	MaxSessions int
}

type LingmaConfig struct {
	BaseURL         string
	CosyVersion     string
	Transport       string
	ClientID        string
	OAuthListenAddr string
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
		Credential: CredentialConfig{
			AuthFile: "./auth/credentials.json",
		},
		Session: SessionConfig{
			TTLMinutes:  30,
			MaxSessions: 100,
		},
		Lingma: LingmaConfig{
			BaseURL:         "https://lingma.alibabacloud.com",
			CosyVersion:     "2.11.2",
			Transport:       "curl",
			OAuthListenAddr: "127.0.0.1:37510",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := applyYAML(&cfg, string(data)); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyYAML(cfg *Config, raw string) error {
	section := ""
	for index, rawLine := range strings.Split(raw, "\n") {
		line := stripComment(strings.TrimRight(rawLine, "\r"))
		if strings.TrimSpace(line) == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			if !strings.HasSuffix(trimmed, ":") {
				return fmt.Errorf("line %d: invalid section header", index+1)
			}
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}

		if section == "" || indent < 2 {
			return fmt.Errorf("line %d: nested value without section", index+1)
		}

		key, value, err := splitKeyValue(trimmed)
		if err != nil {
			return fmt.Errorf("line %d: %w", index+1, err)
		}
		if err := assignValue(cfg, section, key, value); err != nil {
			return fmt.Errorf("line %d: %w", index+1, err)
		}
	}

	return nil
}

func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func splitKeyValue(line string) (string, string, error) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid key/value pair")
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, `"'`)
	return key, value, nil
}

func assignValue(cfg *Config, section, key, value string) error {
	switch section {
	case "server":
		return assignServerValue(&cfg.Server, key, value)
	case "credential":
		return assignCredentialValue(&cfg.Credential, key, value)
	case "session":
		return assignSessionValue(&cfg.Session, key, value)
	case "lingma":
		return assignLingmaValue(&cfg.Lingma, key, value)
	default:
		return fmt.Errorf("unknown section %q", section)
	}
}

func assignServerValue(cfg *ServerConfig, key, value string) error {
	switch key {
	case "host":
		cfg.Host = value
	case "port":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.Port = parsed
	case "admin_token":
		cfg.AdminToken = value
	default:
		return fmt.Errorf("unknown server key %q", key)
	}
	return nil
}

func assignCredentialValue(cfg *CredentialConfig, key, value string) error {
	switch key {
	case "auth_file":
		cfg.AuthFile = value
	default:
		return fmt.Errorf("unknown credential key %q", key)
	}
	return nil
}

func assignSessionValue(cfg *SessionConfig, key, value string) error {
	switch key {
	case "ttl_minutes":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.TTLMinutes = parsed
	case "max_sessions":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		cfg.MaxSessions = parsed
	default:
		return fmt.Errorf("unknown session key %q", key)
	}
	return nil
}

func assignLingmaValue(cfg *LingmaConfig, key, value string) error {
	switch key {
	case "base_url":
		cfg.BaseURL = value
	case "cosy_version":
		cfg.CosyVersion = value
	case "transport":
		cfg.Transport = value
	case "client_id":
		cfg.ClientID = value
	case "oauth_listen_addr":
		cfg.OAuthListenAddr = value
	default:
		return fmt.Errorf("unknown lingma key %q", key)
	}
	return nil
}
