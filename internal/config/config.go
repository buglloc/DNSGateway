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
	Upstream Upstream `koanf:"upstream"`
}

func (c *Config) Validate() error {
	return nil
}

type Runtime struct {
	cfg *Config
}

func LoadConfig(files ...string) (*Config, error) {
	out := Config{
		Listener: Listener{
			Kind: ListenerKindRFC2136,
			RFC2136: RFC2136Listener{
				Addr: ":53",
				Nets: []string{
					"udp",
					"tcp",
				},
			},
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
