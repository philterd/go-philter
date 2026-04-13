# Redaction Ledger

Philter includes an immutable ledger that can record every redaction performed. The ledger provides a cryptographically verifiable chain of redaction events, ensuring the integrity of the redaction history.

## How the Ledger Works

When the `ledger=true` query parameter is included in a `/api/filter` or `/api/explain` request, each identified redaction span is recorded in the ledger.

- **Immutable Chain:** Each entry in the ledger includes a cryptographic hash of the previous entry, creating a per-document chain.
- **Encryption:** Sensitive original text can be encrypted before being stored in the ledger (see `LEDGER_ENCRYPTION_KEY` in [Getting Started](getting-started.md)).
- **Indexing:** Each entry has an `index` that denotes its position in the document's chain, starting at 0.

## Retrieving Ledger Entries

Use the `GET /api/ledger/:documentId` endpoint to retrieve all ledger entries for a specific document.

### Example Request

```bash
curl "https://localhost:8443/api/ledger/621c91da-948c-4451-9447-5e427d555816"
```

## Verifying the Ledger

Use the `GET /api/ledger/:documentId/verify` endpoint to verify the integrity of the ledger chain for a specific document.

### Example Request

```bash
curl "https://localhost:8443/api/ledger/621c91da-948c-4451-9447-5e427d555816/verify"
```

### Response

The response indicates whether the chain is valid:

```json
{
  "verified": true
}
```

If any entry in the document's chain has been tampered with, `verified` will be `false`.
