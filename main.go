package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// constants settable at build time
var (
	Version = "0.1.0"
)

var (
	registry = prometheus.NewRegistry()

	deviceExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tailscale_devices_expiry_time",
			Help: "The expiry time of devices authentication",
		},
		[]string{"name", "address", "owner"},
	)

	deviceLastSeen = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tailscale_devices_last_seen",
			Help: "The last time the device was active",
		},
		[]string{"name", "address", "owner"},
	)

	deviceUpdateAvailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tailscale_devices_update_available",
			Help: "If the Tailscale device has a client update available",
		},
		[]string{"name", "address", "owner"},
	)
)

func init() {
	registry.MustRegister(deviceExpiry)
	registry.MustRegister(deviceLastSeen)
	registry.MustRegister(deviceUpdateAvailable)
}

func main() {
	if len(os.Args) == 1 || strings.HasPrefix(os.Args[1], "-") {
		if mode := detectModeFromEnv(); mode != "" {
			os.Args = append([]string{os.Args[0], mode}, os.Args[1:]...)
		}
	}

	var args mainCommand
	p := arg.MustParse(&args)

	if args.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	ctx := context.Background()

	if args.TailscaleAPIKey == "" {
		args.TailscaleAPIKey = getTailscaleAPIKeyToken()
	}
	if args.TailscaleAuthKey == "" {
		args.TailscaleAuthKey = getTailscaleAuthKeyToken()
	}
	if args.TailscaleOAuthID == "" {
		args.TailscaleOAuthID = getTailscaleOAuthIDToken()
	}
	if args.TailscaleOAuthSecret == "" {
		args.TailscaleOAuthSecret = getTailscaleOAuthSecretToken()
	}

	var tsClient *tailscale.Client
	if args.TailscaleAPIKey != "" {
		tsClient = &tailscale.Client{
			Tailnet: args.TailscaleTailnet,
			APIKey:  args.TailscaleAPIKey,
		}
	} else if args.TailscaleOAuthID != "" && args.TailscaleOAuthSecret != "" {
		tsClient = &tailscale.Client{
			Tailnet: args.TailscaleTailnet,
			HTTP: tailscale.OAuthConfig{
				ClientID:     args.TailscaleOAuthID,
				ClientSecret: args.TailscaleOAuthSecret,
				Scopes:       []string{"devices:core:read"},
			}.HTTPClient(),
		}
	}

	var tsServer *tsnet.Server
	if args.TailscaleAuthKey != "" && args.TailscaleHostname != "" {
		tsServer = new(tsnet.Server)
		tsServer.Hostname = args.TailscaleHostname
		tsServer.Ephemeral = args.Generate != nil
		tsServer.AuthKey = args.TailscaleAuthKey
		if args.Verbose {
			tsServer.Logf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", tsServer.Hostname), log.LstdFlags).Printf
			tsServer.UserLogf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", tsServer.Hostname), log.LstdFlags).Printf
		}
	}

	switch subargs := p.Subcommand().(type) {
	case *generateCommand:
		runGenerate(ctx, tsClient, tsServer, subargs)
	case *serveCommand:
		runServe(ctx, tsClient, tsServer, subargs)
	default:
		p.WriteHelp(os.Stdout)
		os.Exit(1)
	}
}

type generateCommand struct {
	Output             string  `arg:"-o,--output,env:TS_EXPORTER_OUTPUT" placeholder:"FILE"`
	PushgatewayURL     url.URL `arg:"-p,--pushgateway-url,env:TS_EXPORTER_PUSHGATEWAY_URL" placeholder:"URL"`
	PushgatewayRetries int     `arg:"-r,--pushgateway-retries,env:TS_EXPORTER_PUSHGATEWAY_RETRIES" default:"1" placeholder:"RETRIES"`
}

type serveCommand struct {
	Addr     string        `arg:"-l,--listen,env:TS_EXPORTER_LISTEN" default:":9824" placeholder:"ADDRESS:PORT"`
	Interval time.Duration `arg:"-i,--interval,env:TS_EXPORTER_INTERVAL" default:"15m" placeholder:"INTERVAL"`
}

type mainCommand struct {
	TailscaleAPIKey      string           `arg:"--ts-apikey,env:TS_API_KEY" placeholder:"KEY"`
	TailscaleAuthKey     string           `arg:"--ts-authkey,env:TS_AUTHKEY" placeholder:"KEY"`
	TailscaleOAuthID     string           `arg:"--ts-oauth-id,env:TS_OAUTH_ID" placeholder:"ID"`
	TailscaleOAuthSecret string           `arg:"--ts-oauth-secret,env:TS_OAUTH_SECRET" placeholder:"SECRET"`
	TailscaleTailnet     string           `arg:"--ts-tailnet,env:TS_TAILNET" default:"-" placeholder:"TAILNET"`
	TailscaleHostname    string           `arg:"--ts-hostname,env:TS_HOSTNAME" default:"tailscale_exporter" placeholder:"HOSTNAME"`
	Verbose              bool             `arg:"-v,--verbose,env:TS_EXPORTER_VERBOSE" help:"Enable verbose logging"`
	Version              bool             `arg:"-V,--version" help:"Print version information"`
	Generate             *generateCommand `arg:"subcommand:generate"`
	Serve                *serveCommand    `arg:"subcommand:serve"`
}

func detectModeFromEnv() string {
	if os.Getenv("TS_EXPORTER_MODE") != "" {
		return os.Getenv("TS_EXPORTER_MODE")
	}

	if os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_PID") != "" {
		log.Println("Detected systemd socket activation")
		return "serve"
	}

	if os.Getenv("TRIGGER_UNIT") != "" || os.Getenv("TRIGGER_PATH") != "" {
		log.Println("Detected systemd timer activation")
		return "generate"
	}

	return ""
}

func readSystemdCredential(names ...string) string {
	credsDir := os.Getenv("CREDENTIALS_DIRECTORY")
	if credsDir == "" {
		return ""
	}

	for _, name := range names {
		filepath := credsDir + "/" + name
		if data, err := os.ReadFile(filepath); err == nil {
			credential := strings.TrimSpace(string(data))
			if credential != "" {
				return credential
			}
		}
	}

	return ""
}

func getTailscaleAPIKeyToken() string {
	if apiKey := os.Getenv("TS_API_KEY"); apiKey != "" {
		return apiKey
	} else if apiKey := os.Getenv("TS_APIKEY"); apiKey != "" {
		return apiKey
	}

	return readSystemdCredential("TS_API_KEY", "TS_APIKEY", "ts-api-key", "ts-apikey")
}

func getTailscaleAuthKeyToken() string {
	if authKey := os.Getenv("TS_AUTH_KEY"); authKey != "" {
		return authKey
	} else if authKey := os.Getenv("TS_AUTHKEY"); authKey != "" {
		return authKey
	}

	return readSystemdCredential("TS_AUTH_KEY", "TS_AUTHKEY", "ts-auth-key", "ts-authkey")
}

func getTailscaleOAuthIDToken() string {
	if oauthID := os.Getenv("TS_OAUTH_ID"); oauthID != "" {
		return oauthID
	}

	return readSystemdCredential("TS_OAUTH_ID", "ts-oauth-id")
}

func getTailscaleOAuthSecretToken() string {
	if oauthSecret := os.Getenv("TS_OAUTH_SECRET"); oauthSecret != "" {
		return oauthSecret
	}

	return readSystemdCredential("TS_OAUTH_SECRET", "ts-oauth-secret")
}

func runGenerate(ctx context.Context, tsClient *tailscale.Client, tsServer *tsnet.Server, generateArgs *generateCommand) {
	if tsClient == nil {
		log.Fatalf("tailscale api not configured")
	}

	if err := gatherMetrics(ctx, tsClient); err != nil {
		log.Fatalf("Error fetching metrics: %v", err)
	}

	// If no output or pushgateway is specified, write to stdout
	if generateArgs.Output == "" && generateArgs.PushgatewayURL.String() == "" {
		generateArgs.Output = "-"
	}

	if generateArgs.Output == "-" {
		if err := writeToStdout(registry); err != nil {
			log.Fatalf("Error writing metrics: %v", err)
		}
	} else if generateArgs.Output != "" {
		if err := prometheus.WriteToTextfile(generateArgs.Output, registry); err != nil {
			log.Fatalf("Error writing metrics: %v", err)
		}
	}

	if generateArgs.PushgatewayURL.String() != "" {
		pushHTTPClient := http.DefaultClient

		if tsServer != nil {
			log.Printf("Starting Tailscale server")
			if err := tsServer.Start(); err != nil {
				log.Fatalf("Error starting Tailscale server: %v", err)
			}
			defer func() {
				if err := tsServer.Close(); err != nil {
					log.Printf("Error closing Tailscale server: %v", err)
				}
			}()
			pushHTTPClient = tsServer.HTTPClient()
		}

		pusher := push.New(generateArgs.PushgatewayURL.String(), "tailscale").Client(pushHTTPClient).Gatherer(registry)
		var err error
		for i := 1; i < generateArgs.PushgatewayRetries; i++ {
			if err = pusher.Push(); err == nil {
				break
			}
			log.Printf("Error pushing metrics, retrying (%d/%d): %v", i, generateArgs.PushgatewayRetries, err)
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			log.Fatalf("Error pushing metrics after %d retries: %v", generateArgs.PushgatewayRetries, err)
		}
	}
}

func runServe(ctx context.Context, tsClient *tailscale.Client, tsServer *tsnet.Server, serveArgs *serveCommand) {
	if tsClient == nil {
		log.Fatalf("tailscale api not configured")
	}

	go func() {
		log.Printf("[%s] Updating Tailscale metrics", time.Now().Format(time.RFC3339))
		if err := gatherMetrics(ctx, tsClient); err != nil {
			log.Printf("[%s] Error fetching metrics: %v", time.Now().Format(time.RFC3339), err)
		}

		for range time.Tick(serveArgs.Interval) {
			log.Printf("[%s] Updating Tailscale metrics", time.Now().Format(time.RFC3339))
			if err := gatherMetrics(ctx, tsClient); err != nil {
				log.Printf("[%s] Error fetching metrics: %v", time.Now().Format(time.RFC3339), err)
			}
		}
	}()

	if tsServer != nil {
		log.Printf("Starting Tailscale server")
		if err := tsServer.Start(); err != nil {
			log.Fatalf("Error starting Tailscale server: %v", err)
		}
		defer func() {
			if err := tsServer.Close(); err != nil {
				log.Printf("Error closing Tailscale server: %v", err)
			}
		}()
	}

	var ln net.Listener
	var err error
	if os.Getenv("LISTEN_FDS") == "1" {
		ln, err = activationListener()
	} else if tsServer != nil {
		ln, err = tsServer.Listen("tcp", serveArgs.Addr)
	} else {
		ln, err = net.Listen("tcp", serveArgs.Addr)
	}
	if err != nil {
		log.Fatalf("Error listening on %s: %v", serveArgs.Addr, err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}()

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	log.Fatal(http.Serve(ln, nil))
}

func writeToStdout(reg *prometheus.Registry) error {
	enc := expfmt.NewEncoder(os.Stdout, expfmt.NewFormat(expfmt.TypeTextPlain))
	mfs, err := reg.Gather()
	if err != nil {
		return err
	}
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return err
		}
	}
	return nil
}

func gatherMetrics(ctx context.Context, client *tailscale.Client) error {
	if client == nil {
		return fmt.Errorf("missing tailscale client")
	}

	devices, err := client.Devices().List(ctx)
	if err != nil {
		return err
	}

	for _, device := range devices {
		name, err := deviceShortDomain(device)
		if err != nil {
			log.Printf("Error getting device short domain: %v", err)
			continue
		}
		address := device.Addresses[0]

		var owner string
		if len(device.Tags) == 0 {
			owner = fmt.Sprintf("user:%s", device.User)
		} else {
			owner = strings.Join(device.Tags, ",")
		}

		if !device.KeyExpiryDisabled {
			deviceExpiry.With(prometheus.Labels{"name": name, "address": address, "owner": owner}).Set(float64(device.Expires.Unix()))
		}
		deviceLastSeen.With(prometheus.Labels{"name": name, "address": address, "owner": owner}).Set(float64(device.LastSeen.Unix()))

		updateAvailable := 0.0
		if device.UpdateAvailable {
			updateAvailable = 1.0
		}
		deviceUpdateAvailable.With(prometheus.Labels{"name": name, "address": address, "owner": owner}).Set(updateAvailable)
	}

	return nil
}

func activationListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != fmt.Sprintf("%d", os.Getpid()) {
		return nil, fmt.Errorf("expected LISTEN_PID=%d, but was %s", os.Getpid(), os.Getenv("LISTEN_PID"))
	}

	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, fmt.Errorf("expected LISTEN_FDS=1, but was %s", os.Getenv("LISTEN_FDS"))
	}

	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != 1 {
		return nil, fmt.Errorf("expected LISTEN_FDNAMES to set 1 name, but was '%s'", os.Getenv("LISTEN_FDNAMES"))
	}

	fd := 3
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), names[0])

	ln, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close file: %w", err)
	}

	return ln, nil
}

func deviceShortDomain(device tailscale.Device) (string, error) {
	parts := strings.Split(device.Name, ".")
	if len(parts) == 4 && parts[2] == "ts" && parts[3] == "net" {
		return parts[0], nil
	}
	return "", fmt.Errorf("bad device name: %s", device.Name)
}
