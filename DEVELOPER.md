# Philter Developer Guide (v0.1.0)

This document provides technical details for developers working on the Philter Go project.

## Architecture

Philter is built using the [Gin Web Framework](https://github.com/gin-gonic/gin) and integrates with the [go-phileas](https://github.com/philterd/go-phileas) library for core redaction logic.

## Dependencies

This project builds upon several of our other open-source projects:

* [Phileas](https://github.com/philterd/go-phileas) for text redaction.
* [Philolog](https://github.com/philterd/philolog) for immutable redaction logging.

## Environment Variables

Philter is configured using environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `PHILTER_AUTH_ENABLED` | Set to `true` to enable Bearer token authentication. | `true` |
| `PHILTER_API_TOKEN` | The token required for Bearer authentication. | None |
| `MONGO_URI` | MongoDB connection URI. If not set, In-Memory storage is used. | None |
| `MONGO_DATABASE` | MongoDB database name. | `philter` |
| `MONGO_COLLECTION` | MongoDB collection name for contexts. | `contexts` |
| `MONGO_POLICY_COLLECTION` | MongoDB collection name for policies. | `policies` |
| `PHILTER_CERT_FILE` | Path to the SSL certificate for HTTPS. | None |
| `PHILTER_KEY_FILE` | Path to the SSL private key for HTTPS. | None |

## API Endpoints

All API endpoints are under the `/api` prefix and require Bearer token authentication when enabled.

### Redaction

- `POST /api/filter`: Filter text based on a named policy.
- `POST /api/explain`: Explain redactions in text based on a named policy.

### Context Management

- `GET /api/contexts`: List all existing context names.
- `GET /api/contexts/:name`: Get the count of items in a specific context.
- `DELETE /api/contexts/:name`: Delete all entries for a specific context.

### Policy Management

- `GET /api/policies`: List all policy names.
- `GET /api/policies/:name`: Retrieve a specific policy.
- `POST /api/policies`: Save a new or update an existing policy.
- `DELETE /api/policies/:name`: Delete a specific policy.

### Observability

- `GET /metrics`: Prometheus-compatible metrics endpoint (public).

## Development

### Prerequisites

- Go 1.26
- MongoDB (optional, for persistent storage)
- Docker (optional)

### Common Tasks

- **Build**: `make build`
- **Run Tests**: `make test`
- **Build Docker Image**: `make docker-build`
- **Clean Artifacts**: `make clean`

### Adding New Metrics

New metrics should be added to `metrics.go` and documented in this guide.

### Security

Tokens are hashed using SHA-256 before being stored in the `ContextService` to protect sensitive information from being stored in plain text.
