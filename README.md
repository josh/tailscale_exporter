# Tailscale Prometheus Exporter

A Prometheus exporter that collects device metrics from your Tailscale network (tailnet). This exporter provides visibility into device status, authentication expiry, and update availability across your Tailscale infrastructure.

## Metrics

The exporter collects the following metrics:

- **`tailscale_devices_expiry_time`** - The expiry time of device authentication (Unix timestamp)
- **`tailscale_devices_last_seen`** - The last time the device was active (Unix timestamp)
- **`tailscale_devices_update_available`** - Whether the Tailscale device has a client update available (0 or 1)

All metrics include labels:

- `name` - Device hostname (short domain)
- `address` - Device IP address
- `owner` - Device owner (user:username or tag list)

## Authentication

The exporter supports multiple authentication methods with Tailscale:

### API Key

```sh
--ts-apikey=tskey-api-xxxxx
# or
export TS_API_KEY=tskey-api-xxxxx
```

### OAuth

```sh
--ts-oauth-id=your-oauth-id --ts-oauth-secret=your-oauth-secret
# or
export TS_OAUTH_ID=your-oauth-id
export TS_OAUTH_SECRET=your-oauth-secret
```

### Auth Key

```bash
--ts-authkey=tskey-auth-xxxxx
# or
export TS_AUTHKEY=tskey-auth-xxxxx
```

## Usage

### Serve Mode

Run as a persistent HTTP server exposing Prometheus metrics:

```bash
tailscale_exporter serve [options]
```

**Options:**

- `-l, --listen` - Address to listen on (default: `:9824`)
- `-i, --interval` - Metrics collection interval (default: `15m`)
- `--ts-tailnet` - Tailnet to query (default: `-` for your default tailnet)
- `--ts-hostname` - Hostname for the exporter's Tailscale node (default: `tailscale_exporter`)
- `-v, --verbose` - Enable verbose logging

Metrics will be available at `http://localhost:9824/metrics`

**Example:**

```sh
# Run with API key authentication
$ export TS_API_KEY=tskey-api-xxxxx
$ tailscale_exporter serve --listen=:9824 --interval=5m

# Run on custom port with verbose logging
$ tailscale_exporter serve -l :8080 -v --ts-apikey=tskey-api-xxxxx
```

### Generate Mode

Generate metrics once and exit (useful for batch jobs or cron):

```sh
$ tailscale_exporter generate [options]
```

**Options:**

- `-o, --output` - Output file path (defaults to stdout)
- `-p, --pushgateway-url` - Pushgateway URL to send metrics to
- `-r, --pushgateway-retries` - Number of retries for Pushgateway requests (default: `1`)

**Examples:**

```sh
# Output to stdout
$ tailscale_exporter generate --ts-apikey=tskey-api-xxxxx

# Save to file
$ tailscale_exporter generate -o metrics.txt --ts-apikey=tskey-api-xxxxx

# Push to Pushgateway
$ tailscale_exporter generate -p http://pushgateway:9091 --ts-apikey=tskey-api-xxxxx
```

## Environment Variables

All CLI options can be configured via environment variables:

**Authentication:**

- `TS_API_KEY` - Tailscale API key
- `TS_AUTHKEY` - Tailscale auth key
- `TS_OAUTH_ID` - OAuth client ID
- `TS_OAUTH_SECRET` - OAuth client secret
- `TS_TAILNET` - Tailnet to query
- `TS_HOSTNAME` - Hostname for exporter's Tailscale node

**Serve Mode:**

- `TS_EXPORTER_LISTEN` - Listen address
- `TS_EXPORTER_INTERVAL` - Collection interval
- `TS_EXPORTER_VERBOSE` - Enable verbose logging

**Generate Mode:**

- `TS_EXPORTER_OUTPUT` - Output file path
- `TS_EXPORTER_PUSHGATEWAY_URL` - Pushgateway URL
- `TS_EXPORTER_PUSHGATEWAY_RETRIES` - Pushgateway retry count
- `TS_EXPORTER_MODE` - Default subcommand (`serve` or `generate`)

## Credential Loading

The exporter supports loading credentials from files or a credentials directory:

```sh
# Load from file
--ts-apikey=file:/path/to/api-key.txt

# Load from credentials directory (requires CREDENTIALS_DIRECTORY env var)
export CREDENTIALS_DIRECTORY=/etc/tailscale_exporter/credentials
--ts-apikey=cred:tskey-api  # loads from $CREDENTIALS_DIRECTORY/tskey-api
```

## Installation & Deployment

### Binary

```sh
$ go install github.com/josh/tailscale_exporter@latest
```

### Systemd

Systemd service files are included in the `systemd/` directory:

```sh
# Copy service files
$ sudo cp systemd/* /etc/systemd/system/

# Enable and start
$ sudo systemctl enable --now tailscale_exporter.service
```

The service supports socket activation and includes a timer for periodic execution.

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "tailscale"
    static_configs:
      - targets: ["localhost:9824"]
    scrape_interval: 60s
```

## Example Queries

```promql
# Devices with expired authentication
tailscale_devices_expiry_time < time()

# Devices not seen in the last 24 hours
tailscale_devices_last_seen < (time() - 86400)

# Devices with updates available
tailscale_devices_update_available == 1

# Count devices by owner
count by (owner) (tailscale_devices_last_seen)
```

## License

See [LICENSE](LICENSE) file.
