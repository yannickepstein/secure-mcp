# Secure MCP Demo - OAuth Audience Validation

A minimal reproducible example demonstrating proper OAuth audience validation in MCP (Model Context Protocol) servers per RFC 8707.

## The Problem

Some MCP clients fail to send the `resource` or `audience` parameter when requesting OAuth tokens, violating RFC 8707 and the MCP specification, breaking audience-restricted access tokens.

### What Should Happen (RFC 8707 Compliant)

1. MCP server advertises: `"resource": "https://example.com/google-drive-mcp"`
2. Client includes resource in authorization request: `resource=https://example.com/google-drive-mcp`
3. Client includes resource in token request: `resource=https://example.com/google-drive-mcp`
4. Token is issued with matching `aud` claim
5. Token validation succeeds ✅

### What's Happening (Windsurf Bug)

1. MCP server advertises: `"resource": "https://example.com/google-drive-mcp"`
2. Client **omits resource** in authorization request ❌
3. Client **omits resource and audience** in token request ❌
4. Token is issued with generic audience (just the origin)
5. Token validation fails because `aud` claim doesn't match the MCP server's resource URI

## Why This Matters

Per [RFC 9728 Section 7.4](https://www.rfc-editor.org/rfc/rfc9728.html#section-7.4), audience-restricted access tokens prevent a token issued for one resource server from being used on another. Without proper audience validation, a token for one MCP server could be reused on a different MCP server at the same host.

## Real-World Test Results

This demo has been tested with multiple MCP clients. Here are the actual results:

### ✅ Cursor - RFC 8707 Compliant

```
[OAuth Server] Authorization request received:
  Resource: http://localhost:3000/google-drive-mcp  ✅

[OAuth Server] Token request received:
  Requested Resource: http://localhost:3000/google-drive-mcp  ✅

[MCP Server] Token validation:
  Expected audience: http://localhost:3000/google-drive-mcp
  Actual audience: http://localhost:3000/google-drive-mcp
  ✅ VALIDATION SUCCESSFUL
```

**Result**: Cursor successfully connects and can use all MCP features.

### ❌ Windsurf - RFC 8707 Violations

```
[OAuth Server] Authorization request received:
  Resource: undefined  ❌ NOT SENT

[OAuth Server] Token request received:
  Requested Audience: NOT PROVIDED  ❌
  Requested Resource: NOT PROVIDED  ❌

[MCP Server] Token validation:
  Expected audience: http://localhost:3000/google-drive-mcp
  Actual audience: http://localhost:3000
  ❌ VALIDATION FAILED: Audience mismatch!
```

**Result**: Windsurf fails to connect. Token validation fails because no resource parameter was sent.

### Specification Violations (Windsurf)

1. **Missing resource in authorization request** - Violates MCP spec section 2.5.1
2. **Missing resource/audience in token request** - Violates RFC 8707 section 2
3. **Wrong discovery endpoint** - Requests `/.well-known/oauth-protected-resource` instead of `/.well-known/oauth-protected-resource/google-drive-mcp`

## Installation

```bash
npm install
```

## Usage

### Start the Demo Server

```bash
npm install
npm run dev
```

This starts a combined server containing:
- **Mock OAuth Authorization Server** - Issues JWT tokens with requested audience
- **Mock MCP Server** - Implements MCP JSON-RPC protocol with OAuth validation

### Quick Test with Automated Script

```bash
./test.sh
```

This script demonstrates:
- ✅ Token with correct audience (`http://localhost:3000/google-drive-mcp`) → Request succeeds
- ❌ Token with path stripped (`http://localhost:3000`) → Request fails with audience mismatch

### Test with a Real MCP Client

The server implements a proper MCP server that can be tested with real MCP clients (Claude Code, Cursor, Windsurf, etc.).

Add this configuration to your MCP client settings:

```json
{
  "mcpServers": {
    "secure-mcp-demo": {
      "url": "http://localhost:3000/google-drive-mcp",
      "transport": "http"
    }
  }
}
```

When the MCP client connects, it will:
1. Attempt to call the MCP server without a token
2. Receive a 401 response with `WWW-Authenticate` header containing the resource URI
3. Discover OAuth metadata from `.well-known/oauth-protected-resource`
4. Request a token from the OAuth server with the `audience` parameter
5. Retry the MCP request with the token

**Watch the server logs** to see what each client does. The server logs every request with detailed information about OAuth parameters, making it easy to identify specification compliance issues.

## Relevant Specifications

### MCP Specification

[MCP Authorization - Section 2.5.1](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#resource-parameter-implementation):

> MCP clients MUST implement Resource Indicators for OAuth 2.0 as defined in RFC 8707... The resource parameter MUST use the canonical URI of the MCP server as defined in RFC 8707 Section 2.

### RFC 8707 - Resource Indicators for OAuth 2.0

[RFC 8707 Section 2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2):

> The value of the "resource" parameter MUST be an absolute URI.

The specification requires using the **full canonical URI** as the resource identifier.

### RFC 9728 - OAuth 2.0 Security Best Practices

[RFC 9728 Section 7.4](https://www.rfc-editor.org/rfc/rfc9728.html#section-7.4):

> If a client expects to interact with multiple resource servers, the client SHOULD request audience-restricted access tokens using [RFC8707].

## Project Structure

```
secure-mcp/
├── src/
│   └── server.ts         # Combined OAuth + MCP server
├── package.json
├── tsconfig.json
└── README.md
```

## How It Works

1. **MCP Client makes initial request** without authentication to `/google-drive-mcp`
2. **Server responds with 401** including `WWW-Authenticate: Bearer resource="http://localhost:3000/google-drive-mcp"`
3. **Client discovers OAuth metadata** from `/.well-known/oauth-protected-resource/google-drive-mcp`
4. **Client discovers OAuth server** from `/.well-known/oauth-authorization-server`
5. **Client registers dynamically** (optional, RFC 7591) via `/register` endpoint
6. **Client initiates authorization** with `resource` parameter in the authorization request
7. **Client requests token** from OAuth server with `resource` or `audience` parameter
   - ✅ Compliant client (Cursor): Sends `resource=http://localhost:3000/google-drive-mcp`
   - ❌ Non-compliant client (Windsurf): Omits both `resource` and `audience` parameters
8. **OAuth server issues token** with the requested audience in the `aud` claim
9. **Client retries MCP request** with `Authorization: Bearer <token>`
10. **Server validates token** and checks if `aud` claim matches the resource URI exactly
    - ✅ If match: Request succeeds
    - ❌ If mismatch: Returns 403 with detailed error message

## Implemented OAuth Features

- ✅ **Dynamic Client Registration (RFC 7591)** - Automatic client registration
- ✅ **Resource Indicators (RFC 8707)** - Audience-restricted tokens
- ✅ **PKCE (RFC 7636)** - Proof Key for Code Exchange support
- ✅ **Authorization Code Flow** - Full OAuth 2.1 flow
- ✅ **JWT Access Tokens (RFC 9068)** - Structured access tokens with `at+jwt` type
- ✅ **OAuth Discovery (RFC 8414)** - `.well-known/oauth-authorization-server`
- ✅ **Protected Resource Metadata** - `.well-known/oauth-protected-resource` per MCP spec

## License

Apache-2.0

## References

- [MCP Specification - Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 9728 - OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9728.html)
