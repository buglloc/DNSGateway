package config

import (
	"fmt"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Listener Listener `koanf:"listener"`
	Adguard  Adguard  `koanf:"adguard"`
}

func (c *Config) Validate() error {
	//if len(c.Clients.Names) != len(c.Clients.Secrets) {
	//	return fmt.Errorf(
	//		"clients name <-> secrets mismatch: %d (names) != %d (secrets)",
	//		len(c.Clients.Names), len(c.Clients.Secrets),
	//	)
	//}
	//
	//if len(c.Clients.Names) != len(c.Clients.Zones) {
	//	return fmt.Errorf(
	//		"clients name <-> zones mismatch: %d (names) != %d (zones)",
	//		len(c.Clients.Names), len(c.Clients.Zones),
	//	)
	//}
	//
	//names := make(map[string]struct{})
	//for i, name := range c.Clients.Names {
	//	_, exists := names[name]
	//	if exists {
	//		return fmt.Errorf("duplicate client name: %s", name)
	//	}
	//	names[name] = struct{}{}
	//
	//	if len(c.Clients.Secrets[i]) < 32 {
	//		return fmt.Errorf("invalid client %q secret: too short: 32 chars min", name)
	//	}
	//}
	return nil
}

type Runtime struct {
	cfg *Config
}

func LoadConfig(files ...string) (*Config, error) {
	out := Config{
		Listener: Listener{
			Kind: ListenerKindRFC2136,
		},
	}

	k := koanf.New(".")
	if err := k.Load(env.Provider("DG", "_", nil), nil); err != nil {
		return nil, fmt.Errorf("load env config: %w", err)
	}

	yamlParser := yaml.Parser()
	for _, fpath := range files {
		if err := k.Load(file.Provider(fpath), yamlParser); err != nil {
			return nil, fmt.Errorf("load %q config: %w", fpath, err)
		}
	}

	return &out, k.Unmarshal("", &out)
}

func (c *Config) NewRuntime() (*Runtime, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &Runtime{
		cfg: c,
	}, nil
}
