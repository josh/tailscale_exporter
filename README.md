# Tailscale Prometheus Exporter

A Prometheus exporter that collects metrics from Tailscale, including:

- Node counts

## Usage

TK

### Serve Mode

Run as a Prometheus metrics endpoint:

```bash
github_exporter serve [options]

Options:
  -h, --host      Host address to listen on (default: ":9100")
  -i, --interval  Metrics collection interval (default: 15m)
```

Metrics will be available at `http://localhost:9100/metrics`

### Generate Mode

Generate metrics once and exit:

```bash
tailscale_exporter generate [options]

Options:
  -o, --output      Output file path (defaults to stdout if not specified)
  -p, --pushgateway Pushgateway URL to send metrics to
  -r, --pushgateway-retries Number of retries for Pushgateway requests (default: 1)
```

### Environment Variables

All CLI options can be configured via environment variables:

- `FOO`: TK
