# Redacting Text

Philter provides two primary endpoints for processing sensitive information in text: `/api/filter` for redaction and `/api/explain` for identifying the types of sensitive information found.

## Redacting Text

Use the `POST /api/filter` endpoint to redact sensitive information from text based on a specific policy. Use the `POST /api/explain` endpoint to learn more about how the redaction was performed. This endpoint is useful for refining policies and for testing them.

### Request Body

- `text` (string, required): The text to be redacted.
- `policy` (string, required): The name of the policy to use.
- `context` (string, optional): A context name for tracking redactions.
- `documentId` (string, optional): A unique identifier for the document. If not provided, one will be generated.
- `fileName` (string, optional): The name of the file being processed.

### Example Request

```bash
curl -X POST "https://localhost:8443/api/filter" \
     -H 'Content-Type: application/json' \
     -d '{
           "text": "His SSN is 123-45-6789.",
           "policy": "my-policy",
           "context": "medical-records"
         }'
```

### Example Response

```json
{
  "filteredText": "His SSN is {{{REDACTED-ssn}}}.",
  "context": "medical-records",
  "documentId": "621c91da-948c-4451-9447-5e427d555816",
  "spans": [
    {
      "characterStart": 11,
      "characterEnd": 22,
      "filterType": "SSN",
      "text": "123-45-6789",
      "replacement": "{{{REDACTED-ssn}}}",
      "confidence": 1.0,
      "applied": true
    }
  ]
}
```

## Explaining Redactions

Use the `POST /api/explain` endpoint to identify sensitive information in text without actually redacting it.

### Request Body

Same as `/api/filter`.

### Example Request

```bash
curl -X POST "https://localhost:8443/api/explain" \
     -H 'Content-Type: application/json' \
     -d '{
           "text": "My SSN is 987-65-4321.",
           "policy": "my-policy"
         }'
```

### Example Response

```json
{
  "documentId": "621c91da-948c-4451-9447-5e427d555816",
  "spans": [
    {
      "characterStart": 10,
      "characterEnd": 21,
      "filterType": "SSN",
      "text": "987-65-4321",
      "replacement": "{{{REDACTED-ssn}}}",
      "confidence": 1.0,
      "applied": false
    }
  ]
}
```

## Recording to Ledger

To record redaction entries to the immutable ledger, append the `ledger=true` query parameter to your request:

```bash
curl -X POST "https://localhost:8443/api/filter?ledger=true" ...
```
