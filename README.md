# Philter

> [!NOTE]
> This project is currently in active development. We welcome issue reports and pull requests.

Philter is an application for PII/PHI redaction and anonymization. It provides endpoints to filter sensitive information from text, explain identified spans, and manage redaction policies and contexts.

Contexts support referential integrity and can be used to store and retrieve redactions across multiple requests.

This project builds upon several of our other open-source projects:

* [Phileas](https://github.com/philterd/go-phileas) for text redaction.
* [Philolog](https://github.com/philterd/philolog) for immutable redaction logging.

For the Java version of Philter, see [philter-java](https://github.com/philterd/philter).

## Features

- PII/PHI Redaction: Identify and redact sensitive information such as SSNs from text.
- Explainable Redaction: Get detailed information about why specific spans were identified.
- Policy Management: Create, list, and delete redaction policies.
- Context Storage: Store and retrieve redactions based on context names, supporting both In-Memory and MongoDB backends.
- Prometheus Metrics: Built-in metrics for health, token counts, redaction counts, and context counts.
- Secure API: Optional Bearer token authentication and HTTPS support with self-signed certificates. (Recommended to use your own certificates in production.)

## Quick Start

### Using Docker Compose

The easiest way to run Philter with its MongoDB backend is using `docker-compose`:

```bash
docker-compose up --build
```

This will start the Philter API on `https://localhost:8443`.

### Using Makefile

You can also build and run the binary directly:

```bash
make build
./go-philter
```

## API Usage Examples

Refer to the `examples.sh` script for common API operations using `curl`.

For more detailed technical information, see [DEVELOPER.md](DEVELOPER.md).

## License

Copyright 2026 Philterd, LLC. "Philter" is a registered trademark of Philterd, LLC.

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.