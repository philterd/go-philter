#!/bin/bash

# Port 8443 if running in docker-compose.
# Port 8080 if running just the executable.
API_URL="https://localhost:8443/api"
API_TOKEN="secret-token"
HEADERS="-H 'Content-Type: application/json' -H \"Authorization: Bearer $API_TOKEN\""

# Note: Using -k because of the self-signed certificate

echo "1. Creating a policy"
curl -k -X POST "$API_URL/policies" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN" \
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
echo -e "\n"

echo "2. Filtering text using the policy"
curl -k -X POST "$API_URL/filter" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN" \
     -d '{
           "text": "His SSN is 123-45-6789.",
           "context": "my-context",
           "policy": "my-policy"
         }'
echo -e "\n"

echo "3. Explaining redactions using the policy"
curl -k -X POST "$API_URL/explain" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN" \
     -d '{
           "text": "My SSN is 987-65-4321.",
           "context": "my-context",
           "policy": "my-policy"
         }'
echo -e "\n"

echo "4. Listing all policy names"
curl -k -X GET "$API_URL/policies" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "5. Getting a specific policy"
curl -k -X GET "$API_URL/policies/my-policy" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "6. Listing all context names"
curl -k -X GET "$API_URL/contexts" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "7. Getting context item count"
curl -k -X GET "$API_URL/contexts/my-context" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "8. Deleting a context"
curl -k -X DELETE "$API_URL/contexts/my-context" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "9. Deleting a policy"
curl -k -X DELETE "$API_URL/policies/my-policy" \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN"
echo -e "\n"

echo "10. Metrics (unauthenticated)"
curl -k -X GET "https://localhost:8443/metrics"
echo -e "\n"
