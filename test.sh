#!/bin/bash

echo "==================================="
echo "Testing Secure MCP Demo"
echo "==================================="

echo -e "\n1. Testing OAuth metadata endpoint..."
curl -s http://localhost:3000/.well-known/oauth-protected-resource/google-drive-mcp | jq

echo -e "\n2. Testing Dynamic Client Registration (DCR - RFC 7591)..."
DCR_RESPONSE=$(curl -s -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"Test MCP Client","redirect_uris":["http://localhost:8080/callback"],"grant_types":["authorization_code","client_credentials"]}')
echo "$DCR_RESPONSE" | jq
CLIENT_ID=$(echo "$DCR_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$DCR_RESPONSE" | jq -r '.client_secret')
echo "✅ Registered with Client ID: ${CLIENT_ID:0:20}..."

echo -e "\n3. Requesting token with CORRECT audience (full URI with path)..."
echo "   Using client_id: ${CLIENT_ID:0:20}..."
CORRECT_TOKEN=$(curl -s -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&audience=http://localhost:3000/google-drive-mcp" | jq -r '.access_token')
echo "Token received (first 50 chars): ${CORRECT_TOKEN:0:50}..."

echo -e "\n4. Testing MCP endpoint with CORRECT token..."
curl -s -X POST http://localhost:3000/google-drive-mcp/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${CORRECT_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq

echo -e "\n5. Requesting token with BROKEN audience (path stripped)..."
echo "   Using client_id: ${CLIENT_ID:0:20}..."
BROKEN_TOKEN=$(curl -s -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&audience=http://localhost:3000" | jq -r '.access_token')
echo "Token received (first 50 chars): ${BROKEN_TOKEN:0:50}..."

echo -e "\n6. Testing MCP endpoint with BROKEN token..."
curl -s -X POST http://localhost:3000/google-drive-mcp/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${BROKEN_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq

echo -e "\n==================================="
echo "Test complete! Check server logs for validation details."
echo "==================================="
