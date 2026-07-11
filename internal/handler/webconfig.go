package handler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// WebConfig represents the web server configuration.
type WebConfig struct {
	TLSServerConfig  TLSServerConfig   `yaml:"tls_server_config"`
	HTTPServerConfig HTTPServerConfig  `yaml:"http_server_config"`
	BasicAuthUsers   map[string]string `yaml:"basic_auth_users"`
}

// TLSServerConfig holds TLS configuration.
type TLSServerConfig struct {
	CertFile                 string   `yaml:"cert_file"`
	KeyFile                  string   `yaml:"key_file"`
	ClientCAFile             string   `yaml:"client_ca_file"`
	ClientAuthType           string   `yaml:"client_auth_type"`
	MinVersion               string   `yaml:"min_version"`
	MaxVersion               string   `yaml:"max_version"`
	CipherSuites             []string `yaml:"cipher_suites"`
	PreferServerCipherSuites *bool    `yaml:"prefer_server_cipher_suites"`
	CurvePreferences         []string `yaml:"curve_preferences"`
}

// HTTPServerConfig holds HTTP configuration.
type HTTPServerConfig struct {
	HTTP2   *bool             `yaml:"http2"`
	Headers map[string]string `yaml:"headers"`
}

// ConfigureWebServer sets up the HTTP server with TLS and middleware.
func ConfigureWebServer(ctx context.Context, server *http.Server, handler http.Handler, webConfigFile string) (bool, error) {
	logger := log.FromContext(ctx)
	server.Handler = handler
	if strings.TrimSpace(webConfigFile) == "" {
		return false, nil
	}

	cfg, err := loadWebConfig(ctx, webConfigFile)
	if err != nil {
		return false, err
	}
	server.Handler = cfg.wrapHandler(handler)

	tlsConfig, useTLS, err := cfg.tlsConfig(ctx)
	if err != nil {
		return false, err
	}
	if tlsConfig != nil {
		server.TLSConfig = tlsConfig
	}

	if cfg.HTTPServerConfig.HTTP2 != nil && !*cfg.HTTPServerConfig.HTTP2 {
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		if server.TLSConfig != nil {
			server.TLSConfig.NextProtos = []string{"http/1.1"}
		}
	}

	logger.Info("web server configured",
		zap.Bool("tls", useTLS),
		zap.String("config_file", webConfigFile),
	)

	return useTLS, nil
}

// DefaultWebConfigFile returns the default web config file path.
func DefaultWebConfigFile() string {
	for _, path := range []string{"web.yml", "web.yaml"} {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

func loadWebConfig(ctx context.Context, path string) (WebConfig, error) {
	logger := log.FromContext(ctx)
	file, err := os.Open(path)
	if err != nil {
		logger.Error("failed to open web config", zap.String("path", path), zap.Error(err))
		return WebConfig{}, fmt.Errorf("open web config %q: %w", path, err)
	}
	defer file.Close()

	var cfg WebConfig
	dec := yaml.NewDecoder(file)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		logger.Error("failed to parse web config", zap.String("path", path), zap.Error(err))
		return WebConfig{}, fmt.Errorf("parse web config %q: %w", path, err)
	}
	if cfg.BasicAuthUsers == nil {
		cfg.BasicAuthUsers = map[string]string{}
	}
	return cfg, nil
}

func (c WebConfig) wrapHandler(next http.Handler) http.Handler {
	wrapped := next
	if len(c.BasicAuthUsers) > 0 {
		wrapped = c.basicAuthMiddleware(wrapped)
	}
	if len(c.HTTPServerConfig.Headers) > 0 {
		wrapped = c.headersMiddleware(wrapped)
	}
	return wrapped
}

func (c WebConfig) headersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range c.HTTPServerConfig.Headers {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

func (c WebConfig) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !c.checkBasicAuth(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="traceroute-exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c WebConfig) checkBasicAuth(username, password string) bool {
	hash, ok := c.BasicAuthUsers[username]
	if !ok || hash == "" {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
		return true
	}
	if strings.HasPrefix(hash, "$2y$") {
		alternate := "$2a$" + strings.TrimPrefix(hash, "$2y$")
		return bcrypt.CompareHashAndPassword([]byte(alternate), []byte(password)) == nil
	}
	return false
}

func (c WebConfig) tlsConfig(ctx context.Context) (*tls.Config, bool, error) {
	logger := log.FromContext(ctx)
	tlsCfg := c.TLSServerConfig
	hasTLSConfig := tlsCfg.CertFile != "" || tlsCfg.KeyFile != "" || tlsCfg.ClientCAFile != "" || tlsCfg.ClientAuthType != "" || tlsCfg.MinVersion != "" || tlsCfg.MaxVersion != "" || len(tlsCfg.CipherSuites) > 0 || len(tlsCfg.CurvePreferences) > 0
	if !hasTLSConfig {
		return nil, false, nil
	}
	if tlsCfg.CertFile == "" || tlsCfg.KeyFile == "" {
		return nil, false, errors.New("tls_server_config requires both cert_file and key_file")
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		logger.Error("failed to load TLS certificate", zap.Error(err))
		return nil, false, fmt.Errorf("load TLS certificate/key: %w", err)
	}
	minVersion, err := parseTLSVersion(tlsCfg.MinVersion, tls.VersionTLS12)
	if err != nil {
		return nil, false, err
	}
	maxVersion, err := parseTLSVersion(tlsCfg.MaxVersion, tls.VersionTLS13)
	if err != nil {
		return nil, false, err
	}
	if minVersion > maxVersion {
		return nil, false, fmt.Errorf("tls_server_config min_version %q is greater than max_version %q", tlsCfg.MinVersion, tlsCfg.MaxVersion)
	}
	clientAuth, err := parseClientAuthType(tlsCfg.ClientAuthType)
	if err != nil {
		return nil, false, err
	}
	cipherSuites, err := parseCipherSuites(tlsCfg.CipherSuites)
	if err != nil {
		return nil, false, err
	}
	curves, err := parseCurvePreferences(tlsCfg.CurvePreferences)
	if err != nil {
		return nil, false, err
	}

	preferServerCipherSuites := true
	if tlsCfg.PreferServerCipherSuites != nil {
		preferServerCipherSuites = *tlsCfg.PreferServerCipherSuites
	}

	config := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		ClientAuth:               clientAuth,
		MinVersion:               minVersion,
		MaxVersion:               maxVersion,
		CipherSuites:             cipherSuites,
		CurvePreferences:         curves,
		PreferServerCipherSuites: preferServerCipherSuites,
	}

	if tlsCfg.ClientCAFile != "" {
		caPEM, err := os.ReadFile(tlsCfg.ClientCAFile)
		if err != nil {
			return nil, false, fmt.Errorf("read client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, false, fmt.Errorf("client_ca_file %q did not contain any PEM certificates", tlsCfg.ClientCAFile)
		}
		config.ClientCAs = pool
	}

	return config, true, nil
}

func parseTLSVersion(value string, def uint16) (uint16, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(".", "", "_", "-", " ", "").Replace(strings.TrimSpace(value)))
	switch cleaned {
	case "":
		return def, nil
	case "TLS10", "TLS1", "VERSIONTLS10":
		return tls.VersionTLS10, nil
	case "TLS11", "VERSIONTLS11":
		return tls.VersionTLS11, nil
	case "TLS12", "VERSIONTLS12":
		return tls.VersionTLS12, nil
	case "TLS13", "VERSIONTLS13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q", value)
	}
}

func parseClientAuthType(value string) (tls.ClientAuthType, error) {
	cleaned := strings.ToLower(strings.NewReplacer("_", "-", " ", "").Replace(strings.TrimSpace(value)))
	switch cleaned {
	case "", "noclientcert":
		return tls.NoClientCert, nil
	case "requestclientcert":
		return tls.RequestClientCert, nil
	case "requireanyclientcert":
		return tls.RequireAnyClientCert, nil
	case "verifyclientcertifgiven":
		return tls.VerifyClientCertIfGiven, nil
	case "requireandverifyclientcert":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, fmt.Errorf("unsupported client_auth_type %q", value)
	}
}

func parseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	available := map[string]uint16{}
	for _, suite := range tls.CipherSuites() {
		available[suite.Name] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		available[suite.Name] = suite.ID
	}

	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		id, ok := available[trimmed]
		if !ok {
			return nil, fmt.Errorf("unsupported TLS cipher suite %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func parseCurvePreferences(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return nil, nil
	}
	curves := map[string]tls.CurveID{
		"CURVEP256":   tls.CurveP256,
		"P256":        tls.CurveP256,
		"SECP256R1":   tls.CurveP256,
		"CURVEP384":   tls.CurveP384,
		"P384":        tls.CurveP384,
		"SECP384R1":   tls.CurveP384,
		"CURVEP521":   tls.CurveP521,
		"P521":        tls.CurveP521,
		"SECP521R1":   tls.CurveP521,
		"X25519":      tls.X25519,
		"CURVEX25519": tls.X25519,
	}

	out := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		key := strings.ToUpper(strings.NewReplacer("_", "-", " ", "").Replace(strings.TrimSpace(name)))
		curve, ok := curves[key]
		if !ok {
			return nil, fmt.Errorf("unsupported TLS curve %q", name)
		}
		out = append(out, curve)
	}
	return out, nil
}
