# Policies

Policies define the types of sensitive information to be identified and how they should be redacted.

## Creating or Updating a Policy

Use the `POST /api/policies` endpoint to save a new policy or update an existing one.

### Request Body

- `name` (string, required): The name of the policy.
- `policy` (object, required): The policy definition.

### Example Request

```bash
curl -X POST "https://localhost:8443/api/policies" \
     -H 'Content-Type: application/json' \
     -d '{
           "name": "my-policy",
           "policy": {
             "identifiers": {
               "ssn": {
                 "enabled": true
               },
               "age": {
                 "enabled": true
               }
             }
           }
         }'
```

## Listing Policies

Use the `GET /api/policies` endpoint to retrieve a list of all saved policy names.

### Example Request

```bash
curl "https://localhost:8443/api/policies"
```

## Getting a Specific Policy

Use the `GET /api/policies/:name` endpoint to retrieve a specific policy definition.

### Example Request

```bash
curl "https://localhost:8443/api/policies/my-policy"
```

## Deleting a Policy

Use the `DELETE /api/policies/:name` endpoint to remove a policy.

### Example Request

```bash
curl -X DELETE "https://localhost:8443/api/policies/my-policy"
```
