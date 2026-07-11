// Package config provides configuration loading and defaults for the traceroute exporter.
package config

import (
	"context"
	"time"

	"github.com/fmotalleb/go-tools/config"
	"github.com/fmotalleb/go-tools/decoder"
	"github.com/fmotalleb/go-tools/defaulter"
	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
)

// Config holds all application configuration.
type Config struct {
	// Listen address for HTTP server
	ListenAddress string `mapstructure:"listen_address" default:":9805" env:"LISTEN_ADDRESS"`

	// Traceroute settings (native Go implementation, no external binary needed)
	DefaultMethod         string        `mapstructure:"default_method" default:"auto" env:"TRACEROUTE_METHOD"`
	DefaultMaxHops        int           `mapstructure:"default_max_hops" default:"30" env:"TRACEROUTE_MAX_HOPS"`
	DefaultQueries        int           `mapstructure:"default_queries" default:"1" env:"TRACEROUTE_QUERIES"`
	DefaultWait           time.Duration `mapstructure:"default_wait" default:"1s" env:"TRACEROUTE_WAIT"`
	DefaultTimeout        time.Duration `mapstructure:"default_timeout" default:"55s" env:"PROBE_TIMEOUT"`
	DefaultIPFamily       string        `mapstructure:"default_ip_family" default:"" env:"TRACEROUTE_IP_FAMILY"`
	DefaultLoopMaxRepeats int           `mapstructure:"default_loop_max_repeats" default:"4" env:"TRACEROUTE_LOOP_MAX_REPEATS"`

	// Source identification for tree graph metrics
	SourceID       string `mapstructure:"source_id" default:"exporter" env:"SOURCE_ID"`
	SourceHostname string `mapstructure:"source_hostname" default:"" env:"SOURCE_HOSTNAME"`
	SourceAddress  string `mapstructure:"source_address" default:"" env:"SOURCE_ADDRESS"`

	// Web configuration
	WebConfigFile string `mapstructure:"web_config_file" default:"" env:"WEB_CONFIG_FILE"`
}

// LoadConfig loads configuration from file and applies defaults.
func LoadConfig(ctx context.Context, configPath string) (*Config, error) {
	logger := log.FromContext(ctx)
	cfg := &Config{}

	// Read and merge config file
	if configPath != "" {
		logger.Info("loading config file", zap.String("path", configPath))
		rawConfig, err := config.ReadAndMergeConfig(ctx, configPath)
		if err != nil {
			logger.Error("failed to read config file", zap.Error(err))
			return nil, err
		}

		// Decode raw config into struct
		if err := decoder.Decode(cfg, rawConfig); err != nil {
			logger.Error("failed to decode config", zap.Error(err))
			return nil, err
		}
	}

	// Apply defaults for zero-value fields
	if err := defaulter.ApplyDefaults(cfg, nil); err != nil {
		logger.Warn("failed to apply some defaults", zap.Error(err))
	}

	// Post-processing
	cfg.DefaultMethod = normalizeMethod(cfg.DefaultMethod)
	cfg.DefaultLoopMaxRepeats = clampInt(cfg.DefaultLoopMaxRepeats, 0, 100)
	if cfg.SourceHostname == "" {
		cfg.SourceHostname = cfg.SourceID
	}

	logger.Debug("config loaded",
		zap.String("listen_address", cfg.ListenAddress),
		zap.String("default_method", cfg.DefaultMethod),
	)

	return cfg, nil
}

const (
	methodAuto = "auto"
	methodTCP  = "tcp"
	methodICMP = "icmp"
	methodUDP  = "udp"
)

func normalizeMethod(method string) string {
	switch method {
	case "", methodAuto:
		return methodAuto
	case methodTCP, "t":
		return methodTCP
	case methodICMP, "i":
		return methodICMP
	case methodUDP, "u":
		return methodUDP
	default:
		return method
	}
}

func clampInt(v, minVal, maxVal int) int {
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}
