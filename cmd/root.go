/*
Copyright © 2026 Motalleb Fallahnehzad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/fmotalleb/go-tools/log"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/fmotalleb/traceroute-exporter/internal/config"
	"github.com/fmotalleb/traceroute-exporter/internal/handler"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "traceroute-exporter",
	Short: "A Prometheus exporter for traceroute metrics",
	Long: `A Prometheus exporter that performs traceroute probes and exposes
the results as metrics. It supports TCP, ICMP, and UDP traceroute methods,
loop detection, and a web dashboard for visualization.`,
	RunE: run,
}

var (
	configFile    string
	listenAddress string
	webConfigFile string
)

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "path to config file (yaml/json/toml)")
	rootCmd.Flags().StringVarP(&listenAddress, "listen-address", "l", "", "HTTP listen address (overrides config)")
	rootCmd.Flags().StringVarP(&webConfigFile, "web.config.file", "w", "", "path to web config file for TLS/auth")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Create root context with logger
	ctx := context.Background()
	ctx = log.WithNewLoggerForced(ctx, func(b *log.Builder) *log.Builder {
		return b.Level("info").ServiceName("traceroute-exporter")
	})
	logger := log.FromContext(ctx)

	// Load configuration
	cfg, err := config.LoadConfig(ctx, configFile)
	if err != nil {
		logger.Error("failed to load config", zap.Error(err))
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply flag overrides
	if listenAddress != "" {
		cfg.ListenAddress = listenAddress
	}
	if webConfigFile != "" {
		cfg.WebConfigFile = webConfigFile
	}

	logger.Info("starting traceroute exporter",
		zap.String("listen_address", cfg.ListenAddress),
		zap.String("default_method", cfg.DefaultMethod),
		zap.Int("default_max_hops", cfg.DefaultMaxHops),
		zap.Int("default_queries", cfg.DefaultQueries),
		zap.Int("loop_max_repeats", cfg.DefaultLoopMaxRepeats),
	)

	// Create exporter and HTTP server
	exporter := handler.NewExporter(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/", exporter.Index)
	mux.HandleFunc("/healthz", exporter.Healthz)
	mux.HandleFunc("/trace", exporter.Trace)
	mux.HandleFunc("/metrics", exporter.Metrics)
	mux.HandleFunc("/dashboard", exporter.Dashboard)

	server := &http.Server{Addr: cfg.ListenAddress}
	useTLS, err := handler.ConfigureWebServer(ctx, server, mux, cfg.WebConfigFile)
	if err != nil {
		logger.Error("failed to configure web server", zap.Error(err))
		return fmt.Errorf("failed to configure web server: %w", err)
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	if cfg.WebConfigFile != "" {
		logger.Info("loaded web config file", zap.String("path", cfg.WebConfigFile))
	}
	logger.Info("server starting",
		zap.String("address", cfg.ListenAddress),
		zap.String("scheme", scheme),
	)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if useTLS {
			errCh <- server.ListenAndServeTLS("", "")
		} else {
			errCh <- server.ListenAndServe()
		}
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", zap.Error(err))
			return err
		}
	}

	// Graceful shutdown
	logger.Info("shutting down server")
	if err := server.Shutdown(context.Background()); err != nil {
		logger.Error("failed to shutdown server", zap.Error(err))
		return err
	}

	logger.Info("server stopped")
	return nil
}
