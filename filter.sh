#!/bin/bash -e

#curl -v -k -X POST "https://localhost:8443/api/policies" \
#     -H 'Content-Type: application/json' -H "Authorization: Bearer $API_TOKEN" \
#     -d '{
#           "name": "my-policy",
#           "policy": {
#             "identifiers": {
#               "ssn": {
#                 "enabled": true
#               }
#             }
#           }
#         }'

curl -s -k -X POST "https://localhost:8443/api/filter" \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer $API_TOKEN" \
          -d '{
           "text": "His SSN is 123-45-6789 and 123-45-6789.",
           "context": "my-context",
           "policy": "my-policy"
         }' \
         --http1.1 | jq

curl -s -k -X GET "https://localhost:8443/api/contexts" \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer $API_TOKEN" \
         --http1.1

curl -s -k -X GET "https://localhost:8443/api/ledger/9bc2e74e-2c28-4db8-ab06-98ddb96b7db4" \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer $API_TOKEN" \
         --http1.1 | jq


curl -s -k -X GET "https://localhost:8443/api/ledger/915d94ee-96a2-4e98-8018-7b94d1da0e33/verify" \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer $API_TOKEN" \
         --http1.1 | jq

curl -s -k -X GET "https://localhost:8443/api/metrics"