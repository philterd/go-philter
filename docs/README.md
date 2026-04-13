# Philter Documentation

Welcome to the documentation for Philter, a service for redacting sensitive information.

## Contents

- [Getting Started](getting-started.md)
  - Installation and running Philter using Docker or locally.
  - Configuration environment variables and authentication.

- [Managing Policies](policies.md)
  - Creating, updating, listing, and deleting policies (includes PhEye).

- [Redacting and Explaining Text](redaction.md)
  - Using the `/filter` and `/explain` endpoints.
  - Request and response examples.

- [Using Contexts](contexts.md)
  - How contexts provide consistent redactions across requests.
  - API endpoints for managing contexts.

- [Immutable Ledger](ledgers.md)
  - Cryptographically verifiable record of redactions.
  - Retrieving and verifying the redaction chain.
