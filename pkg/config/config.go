package config

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/notification"
	"github.com/fernet/fernet-go"
)

// ErrDatasourceNotLoaded is returned when the datasource variable in the
// configuration file is not loaded properly
var ErrDatasourceNotLoaded = errors.New("could not load configuration: no database source specified")

// File represents a YAML configuration file that namespaces all Clair
// configuration under the top-level "clair" key.
type File struct {
	Clair Config `yaml:"clair"`
}

// UpdaterConfig configures the regularly updater by cron
type UpdaterConfig struct {
	// Cron defines when to update, refer to https://godoc.org/github.com/robfig/cron
	Cron string
	// Disabled indicates whether the regular updater is disabled
	Disabled bool
}

// Config is the configuration for the API service.
type APIConfig struct {
	Port                      int
	HealthPort                int
	Timeout                   time.Duration
	PaginationKey             string
	CertFile, KeyFile, CAFile string
}

// Config is the global configuration for an instance of Clair.
type Config struct {
	Database database.RegistrableComponentConfig
	Updater  *UpdaterConfig
	Notifier *notification.Config
	API      *APIConfig
}

// AppConfig is config loaded
var AppConfig *Config

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		Database: database.RegistrableComponentConfig{
			Type: "pgsql",
		},
		Updater: &UpdaterConfig{
			Cron:     "@midnight",
			Disabled: false,
		},
		API: &APIConfig{
			Port:       6060,
			HealthPort: 6061,
			Timeout:    900 * time.Second,
		},
		Notifier: &notification.Config{
			Attempts:         5,
			RenotifyInterval: 2 * time.Hour,
		},
	}
}

// LoadConfig is a shortcut to open a file, read it, and generate a Config.
//
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func LoadConfig(path string) (config *Config, err error) {
	var cfgFile File
	cfgFile.Clair = DefaultConfig()
	if path == "" {
		return &cfgFile.Clair, nil
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.Clair

	// Generate a pagination key if none is provided.
	if config.API.PaginationKey == "" {
		var key fernet.Key
		if err = key.Generate(); err != nil {
			return
		}
		config.API.PaginationKey = key.Encode()
	} else {
		_, err = fernet.DecodeKey(config.API.PaginationKey)
		if err != nil {
			err = errors.New("invalid Pagination key; must be 32-bit URL-safe base64")
			return
		}
	}

	return
}
