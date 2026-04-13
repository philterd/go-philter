# Metrics

Philter provides a `/metrics` endpoint that exposes internal application metrics in a format compatible with [Prometheus](https://prometheus.io/). These metrics can be used for monitoring, alerting, and performance analysis.

Note that metrics are not persisted and will be reset on restart.

## Metrics Endpoint

The metrics endpoint is available at:

```
GET /metrics
```

This endpoint is unauthenticated by default, allowing it to be easily scraped by a Prometheus server.

## Available Metrics

The following metrics are currently exposed by Philter:

- `philter_healthy`: A gauge indicating if the Philter service is healthy. A value of `1` indicates healthy, while `0` indicates unhealthy.
- `philter_tokens_received_total`: A counter for the total number of tokens (words) processed by the `/filter` and `/explain` endpoints.
- `philter_redactions_total`: A counter for the total number of redactions performed by the `/filter` and `/explain` endpoints.
- `philter_contexts_total`: A gauge representing the total number of active contexts stored in the system.

## Prometheus Integration

To integrate Philter with Prometheus, add a new scrape job to your `prometheus.yml` configuration:

```yaml
scrape_configs:
  - job_name: 'philter'
    static_configs:
      - targets: ['philter:8080']
```

Replace `philter:8080` with the appropriate hostname and port where Philter is running.

## Example Request

You can manually inspect the metrics using `curl`:

```bash
curl "https://localhost:8443/metrics"
```
