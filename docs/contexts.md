# Using Contexts

Contexts allow you to track redactions across multiple requests and ensure consistent replacement values for the same sensitive information within the same context. This is also known as referential integrity.

## How Contexts Work

When you provide a `context` name in a `/api/filter` or `/api/explain` request, Philter stores the original text (encrypted) and its replacement value. If the same original text is encountered again in a subsequent request using the *same context*, Philter will automatically apply the *same replacement value*, even if the redaction filter for that type is currently disabled.

## Listing Contexts

Use the `GET /api/contexts` endpoint to retrieve a list of all active context names.

### Example Request

```bash
curl "https://localhost:8443/api/contexts"
```

## Getting Context Summary

Use the `GET /api/contexts/:name` endpoint to get a summary of a specific context, including the number of items it contains.

### Example Request

```bash
curl "https://localhost:8443/api/contexts/my-context"
```

## Deleting a Context

Use the `DELETE /api/contexts/:name` endpoint to remove a context and all its associated redaction mappings.

### Example Request

```bash
curl -X DELETE "https://localhost:8443/api/contexts/my-context"
```
