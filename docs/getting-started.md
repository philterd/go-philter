# Getting Started with Philter

Philter is a service for identifying and redacting sensitive information (PII/PHI) from text.

## Running Philter

### Using Docker Compose (Recommended)

The easiest way to run Philter along with its MongoDB dependency (used for policies, contexts, and the ledger) is using Docker Compose.

1. Ensure you have Docker and Docker Compose installed.
2. Run the following command:
   ```bash
   docker compose up -d
   ```
This will start Philter on port `8443` (HTTPS) and MongoDB on its default port `27017`.

### Running Locally with Go

If you have Go installed, you can run Philter directly:

1. Clone the repository and navigate to the root directory.
2. Build the application:
   ```bash
   go build -o philterd main.go
   ```
3. Run the application:
   ```bash
   ./philterd
   ```
By default, the application will listen on port `8080`.

**Note:** When running locally without Docker, Philter defaults to using in-memory storage for policies and contexts, and an in-memory ledger. This data will be lost when the service stops.

## Configuration

Philter can be configured using environment variables:

- `MONGO_URI`: The MongoDB connection string (e.g., `mongodb://localhost:27017`).
- `MONGO_DATABASE`: The MongoDB database name (default: `philter`).
- `PHILTER_AUTH_ENABLED`: Set to `true` to enable API token authentication (default: `false`).
- `PHILTER_API_TOKEN`: The token required for authentication if enabled.
- `LEDGER_ENCRYPTION_KEY`: A 16, 24, or 32-byte key for encrypting ledger entries.
- `PHILTER_CERT_FILE` and `PHILTER_KEY_FILE`: Paths to TLS certificate and key files to enable HTTPS.

## Authentication

If `PHILTER_AUTH_ENABLED` is set to `true`, you must include an `Authorization` header in your API requests:

```
Authorization: Bearer <your-api-token>
```
