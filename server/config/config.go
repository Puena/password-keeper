package config

import (
	"flag"
	"fmt"

	"github.com/caarlos0/env/v6"
)

var errConfigRequired = "%s is required"

type Config struct {
	JWTSecretKey             string `env:"JWT_SECRET" envDefault:"some"`
	PostgresConnectionString string `env:"POSTGRES_URI" envDefault:"host=localhost user=postgres password=test port=54320 dbname=postgres"`
	Release                  bool   `env:"RELEASE" envDefault:"false"`
	MigrationFolder          string `env:"MIGRATION_FOLDER" envDefault:"migration"`
	Address                  string `env:"ADDRESS" envDefault:"localhost:3030"`
	TLSCert                  string `env:"TLS_CERT" envDefault:""`
	TLSKey                   string `env:"TLS_KEY" envDefault:""`
}

// Create new config, first read env, then flags.
func Parse() (*Config, error) {
	cfg := &Config{}
	err := cfg.readEnv()
	if err != nil {
		return nil, err
	}

	err = cfg.readFlags()
	if err != nil {
		return nil, err
	}

	err = cfg.validate()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// ReadEnv read to config.
func (c *Config) readEnv() error {
	err := env.Parse(c)
	return err
}

// ReadFlags read to config.
func (c *Config) readFlags() error {
	flag.StringVar(&c.JWTSecretKey, "jwt", c.JWTSecretKey, "jwt secret")
	flag.StringVar(&c.PostgresConnectionString, "pg", c.PostgresConnectionString, "postgres connection string")
	flag.BoolVar(&c.Release, "release", c.Release, "release flag")
	flag.StringVar(&c.MigrationFolder, "migration", c.MigrationFolder, "migration folder")
	flag.StringVar(&c.Address, "address", c.Address, "address for server, for example 127.0.0.1:20531")

	flag.Parse()

	return nil
}

// Validate check that required fields are not empty.
func (c *Config) validate() error {
	if c.JWTSecretKey == "" {
		return fmt.Errorf(errConfigRequired, "jwt secret")
	}

	if c.PostgresConnectionString == "" {
		return fmt.Errorf(errConfigRequired, "postgres connection string")
	}

	return nil
}
