# Health

Philter provides a `GET /api/health` endpoint for liveness probes. It matches the health contract shared across Philterd products.

The endpoint is unauthenticated so a container runtime or load balancer can probe it without an API token.

## Response

A healthy service returns `200` with the application version:

```json
{"status": "UP", "applicationVersion": "1.0.0"}
```

The version is `unknown` when the binary was built without a version being set at build time.

## Example Request

```bash
curl "https://localhost:8443/api/health"
```
