package config

import (
	"fmt"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

const (
	// Flag for devault database path.
	backgroundWorkersFlag = "BackgroundWorkers"
	databasePathFlag      = "DatabasePath"
	databaseDefaultPath   = "%s/.keeper/storage"
	logPathFlag           = "LogPath"
	logDefaultPath        = "%s/.keeper"
)

// Config represent app configuration.
type Config struct {
	// Viper config
	viperConfig viperConfig
	// BuildInfo contains build information.
	buildInfo BuildInfo
}

// BuildInfo represent build information.
type BuildInfo struct {
	// Version of build.
	Version string
	// Time of build.
	Time string
	// Realese flag.
	Release bool
	// Host address.
	Host string
	// Hostname of server.
	Hostname string
	// Sert file path.
	CertFile string
}

type viperConfig struct {
	LogPath           string
	BackgroundWorkers int
	Login             string
	DatabasePath      string
}

// ReadViperConfig read vipers config.
func (c *Config) ReadViperConfig() (*viperConfig, error) {
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	err = viper.Unmarshal(&c.viperConfig)
	if err != nil {
		return nil, err
	}

	return &c.viperConfig, nil
}

// GetBuildInfo return build info.
func (c *Config) GetBuildInfo() BuildInfo {
	return c.buildInfo
}

func (c *Config) loadConfig() error {
	home, err := homedir.Dir()
	if err != nil {
		return fmt.Errorf("failed while trying to get home dir %w", err)
	}

	// set defaults
	databasePath := fmt.Sprintf(databaseDefaultPath, home)
	logPath := fmt.Sprintf(logDefaultPath, home)
	err = createFolders(databasePath)
	if err != nil {
		return fmt.Errorf("failed while create database path folders %w", err)
	}
	err = createFolders(logPath)
	if err != nil {
		return fmt.Errorf("failed while create log patht folders %w", err)
	}
	viper.SetDefault(databasePathFlag, databasePath)
	viper.SetDefault(backgroundWorkersFlag, 10)
	viper.SetDefault(logPathFlag, logPath)

	viper.AddConfigPath(home)
	viper.SetConfigName(".keeper")
	viper.SetConfigType("yaml")

	viper.SetEnvPrefix("keeper")
	viper.AutomaticEnv()

	_ = viper.SafeWriteConfig()

	_, err = c.ReadViperConfig()
	if err != nil {
		return fmt.Errorf("failed while reading viper config %w", err)
	}

	return nil
}

func createFolders(path string) error {
	return os.MkdirAll(path, 0744)
}

// New load config from default path or create new one.
func New() (*Config, error) {
	cfg := &Config{}
	err := cfg.loadConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// AddBuildInfo add build info to config.
func (c *Config) AddBuildInfo(info *BuildInfo) *Config {
	c.buildInfo = *info
	return c
}
