# Policies

Policies define the types of sensitive information to be identified and how they should be redacted.

## Creating a Policy

Use the `POST /api/policies` endpoint to save a new policy. If the policy already exists, a 409 Conflict will be returned.

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
               }
             }
           }
         }'
```

## Updating a Policy

Use the `PUT /api/policies/:name` endpoint to update an existing policy.

### Request Body

The request body should be the policy definition (the object inside the `policy` field in the POST request).

### Example Request

```bash
curl -X PUT "https://localhost:8443/api/policies/my-policy" \
     -H 'Content-Type: application/json' \
     -d '{
           "identifiers": {
             "ssn": {
               "enabled": true
             },
             "age": {
               "enabled": true
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

## PhEye Filter

The `pheye` filter allows you to use GLiNER models directly for entity detection (e.g., Person, Organization, Location).

### Configuration

```json
{
  "identifiers": {
    "pheye": [
      {
        "pheyeConfiguration": {
          "modelPath": "/path/to/gliner/model",
          "labels": "Person,Organization"
        }
      }
    ]
  }
}
```

### Enabling PhEye Support

By default, the project builds with a mock PhEye client to avoid external dependencies. To enable real model support using `GLiNER.cpp`, you must:

1. Install the `libgliner` shared library on your system.
2. Build the project with the `pheye` build tag:

```bash
go build -tags pheye .
```
