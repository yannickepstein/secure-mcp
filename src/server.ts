import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log all incoming requests for debugging
app.use((req, res, next) => {
  console.log(`\n[DEBUG] ${req.method} ${req.path}`);
  if (Object.keys(req.query).length > 0) {
    console.log(`  Query: ${JSON.stringify(req.query)}`);
  }
  if (Object.keys(req.body).length > 0) {
    console.log(`  Body: ${JSON.stringify(req.body)}`);
  }
  if (req.headers.authorization) {
    console.log(`  Auth: ${req.headers.authorization.substring(0, 30)}...`);
  }
  next();
});

// Generate RSA key pair for JWT signing
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const OAUTH_ISSUER = 'http://localhost:3000';
const MCP_SERVER_PATH = '/google-drive-mcp';
const MCP_RESOURCE_URI = `${OAUTH_ISSUER}${MCP_SERVER_PATH}`;

// =============================================================================
// MOCK OAUTH AUTHORIZATION SERVER
// =============================================================================

// OAuth token endpoint - issues JWT tokens with requested audience
const handleToken = (req: express.Request, res: express.Response) => {
  const { audience, grant_type, code, resource } = req.body;

  console.log('\n[OAuth Server] Token request received:');
  console.log(`  Grant Type: ${grant_type}`);
  console.log(`  Requested Audience: ${audience || 'NOT PROVIDED'}`);
  console.log(`  Requested Resource: ${resource || 'NOT PROVIDED'}`);

  // Use resource parameter if audience is not provided (some clients may use resource instead)
  const effectiveAudience = audience || resource;

  if (!effectiveAudience) {
    console.log('  ❌ CRITICAL BUG: Client did not send audience or resource parameter!');
    console.log('  ❌ This violates RFC 8707 and MCP spec section 2.5.1');
    console.log('  ❌ Issuing token anyway (for demo purposes) with default audience');

    // Issue a token with a generic audience to demonstrate the problem
    const token = jwt.sign(
      {
        sub: 'user@example.com',
        aud: OAUTH_ISSUER, // Generic issuer URL (no path)
        iss: OAUTH_ISSUER,
        scope: 'mcp.read mcp.write profile email openid',
        typ: 'at+jwt'
      },
      privateKey,
      {
        algorithm: 'RS256',
        expiresIn: '1h',
        header: { typ: 'at+jwt' }
      }
    );

    console.log(`  Issued token with GENERIC audience (no path): ${OAUTH_ISSUER}`);
    console.log(`  This token will FAIL validation at the MCP server!`);

    return res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'mcp.read mcp.write profile email openid'
    });
  }

  // Issue token with the requested audience (whatever it is)
  const token = jwt.sign(
    {
      sub: 'user@example.com',
      aud: effectiveAudience,
      iss: OAUTH_ISSUER,
      scope: 'mcp.read mcp.write profile email openid',
      typ: 'at+jwt'
    },
    privateKey,
    {
      algorithm: 'RS256',
      expiresIn: '1h',
      header: { typ: 'at+jwt' }
    }
  );

  console.log(`  ✅ Issued token with audience: ${effectiveAudience}`);

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'mcp.read mcp.write profile email openid'
  });
};

app.post('/token', handleToken);
app.post('/oauth/token', handleToken);

// OAuth authorization endpoint (support both /authorize and /oauth/authorize)
const handleAuthorize = (req: express.Request, res: express.Response) => {
  const { resource, redirect_uri, state, code_challenge, scope } = req.query;

  console.log('\n[OAuth Server] Authorization request received:');
  console.log(`  Resource: ${resource}`);
  console.log(`  Redirect URI: ${redirect_uri}`);
  console.log(`  Scope: ${scope}`);
  console.log(`  PKCE Code Challenge: ${code_challenge ? 'Present' : 'Missing'}`);

  // Auto-approve and redirect with code (simplified for demo)
  const code = crypto.randomBytes(32).toString('hex');
  console.log(`  Issued authorization code: ${code.substring(0, 20)}...`);
  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
};

app.get('/authorize', handleAuthorize);
app.get('/oauth/authorize', handleAuthorize);

// Dynamic Client Registration (RFC 7591)
app.post('/register', (req, res) => {
  const { client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method } = req.body;

  console.log('\n[OAuth Server] Dynamic Client Registration request received:');
  console.log(`  Client Name: ${client_name}`);
  console.log(`  Redirect URIs: ${JSON.stringify(redirect_uris)}`);

  // Generate client credentials
  const clientId = crypto.randomBytes(16).toString('hex');
  const clientSecret = crypto.randomBytes(32).toString('hex');

  const registration = {
    client_id: clientId,
    client_secret: clientSecret,
    client_name: client_name || 'MCP Client',
    redirect_uris: redirect_uris || [],
    grant_types: grant_types || ['authorization_code'],
    response_types: response_types || ['code'],
    token_endpoint_auth_method: token_endpoint_auth_method || 'none',
    client_id_issued_at: Math.floor(Date.now() / 1000),
    // Don't set client_secret_expires_at (it never expires in this demo)
  };

  console.log(`  Issued Client ID: ${clientId}`);
  console.log(`  Response: ${JSON.stringify(registration, null, 2)}`);

  res.status(201).json(registration);
});

// OAuth authorization server metadata (for discovery)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: OAUTH_ISSUER,
    authorization_endpoint: `${OAUTH_ISSUER}/authorize`,
    token_endpoint: `${OAUTH_ISSUER}/token`,
    registration_endpoint: `${OAUTH_ISSUER}/register`,
    jwks_uri: `${OAUTH_ISSUER}/oauth/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp.read', 'mcp.write', 'profile', 'email', 'openid'],
    resource_parameter_supported: true
  });
});

// JWKS endpoint (public keys for token verification)
app.get('/oauth/jwks', (req, res) => {
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  res.json({
    keys: [
      {
        ...jwk,
        use: 'sig',
        alg: 'RS256',
        kid: 'default'
      }
    ]
  });
});

// =============================================================================
// MCP SERVER - OAuth Protected Resource Metadata
// =============================================================================

// OAuth Protected Resource metadata endpoint (MCP spec section 2.5.1)
app.get('/.well-known/oauth-protected-resource' + MCP_SERVER_PATH, (req, res) => {
  console.log('\n[MCP Server] Protected resource metadata requested');

  const metadata = {
    resource: MCP_RESOURCE_URI,
    authorization_servers: [OAUTH_ISSUER],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://github.com/yannickepstein/secure-mcp',
    scopes_supported: ['profile', 'email', 'openid']
  };

  console.log(`  Resource URI: ${metadata.resource}`);
  res.json(metadata);
});

// Token validation middleware
function validateToken(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('\n[MCP Server] Authentication required - sending 401 with WWW-Authenticate');
    return res
      .status(401)
      .header('WWW-Authenticate', `Bearer realm="${MCP_RESOURCE_URI}", resource="${MCP_RESOURCE_URI}"`)
      .json({
        error: 'invalid_token',
        error_description: 'Missing or invalid Authorization header'
      });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: OAUTH_ISSUER
    }) as jwt.JwtPayload;

    console.log('\n[MCP Server] Token validation:');
    console.log(`  Expected audience: ${MCP_RESOURCE_URI}`);
    console.log(`  Actual audience: ${decoded.aud}`);

    // RFC 8707: The audience MUST match the resource URI
    if (decoded.aud !== MCP_RESOURCE_URI) {
      console.log('  ❌ VALIDATION FAILED: Audience mismatch!');
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'Token audience does not match resource URI',
        expected_audience: MCP_RESOURCE_URI,
        actual_audience: decoded.aud
      });
    }

    console.log('  ✅ VALIDATION SUCCESSFUL');
    req.user = decoded;
    next();
  } catch (err) {
    console.log('\n[MCP Server] Token validation failed:', (err as Error).message);
    return res
      .status(401)
      .header('WWW-Authenticate', `Bearer realm="${MCP_RESOURCE_URI}", resource="${MCP_RESOURCE_URI}", error="invalid_token"`)
      .json({
        error: 'invalid_token',
        error_description: (err as Error).message
      });
  }
}

// =============================================================================
// MCP SERVER - JSON-RPC over HTTP
// =============================================================================

// Handle MCP JSON-RPC requests with authentication
app.post(MCP_SERVER_PATH, validateToken, async (req, res) => {
  console.log('\n[MCP Server] JSON-RPC request received:', JSON.stringify(req.body, null, 2));

  const { jsonrpc, id, method, params } = req.body;

  // Handle initialize
  if (method === 'initialize') {
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {}
        },
        serverInfo: {
          name: 'secure-mcp-demo',
          version: '1.0.0'
        }
      }
    });
  }

  // Handle initialized notification
  if (method === 'notifications/initialized') {
    return res.status(204).send();
  }

  // Handle tools/list
  if (method === 'tools/list') {
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        tools: [
          {
            name: 'list_files',
            description: 'List files from Google Drive',
            inputSchema: {
              type: 'object',
              properties: {},
              required: []
            }
          }
        ]
      }
    });
  }

  // Handle tools/call
  if (method === 'tools/call') {
    if (params.name === 'list_files') {
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                files: [
                  { name: 'document1.txt', size: 1234 },
                  { name: 'document2.pdf', size: 5678 }
                ]
              }, null, 2)
            }
          ]
        }
      });
    }
  }

  // Method not found
  return res.json({
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: 'Method not found'
    }
  });
});

// Catch-all 404 handler for unmatched routes
app.use((req, res) => {
  console.log(`\n⚠️  [404] No route matched: ${req.method} ${req.path}`);
  console.log(`  This might indicate a client implementation issue`);
  res.status(404).json({
    error: 'not_found',
    message: `No handler for ${req.method} ${req.path}`,
    available_endpoints: {
      oauth: ['/register', '/authorize', '/token', '/.well-known/oauth-authorization-server'],
      mcp: [MCP_SERVER_PATH, `/.well-known/oauth-protected-resource${MCP_SERVER_PATH}`]
    }
  });
});

// =============================================================================
// START SERVER
// =============================================================================

const PORT = 3000;
app.listen(PORT, () => {
  console.log('\n='.repeat(80));
  console.log('Secure MCP Demo Server Running');
  console.log('='.repeat(80));
  console.log(`\nOAuth Authorization Server: ${OAUTH_ISSUER}`);
  console.log(`MCP Resource URI: ${MCP_RESOURCE_URI}`);
  console.log(`\nEndpoints:`);
  console.log(`  - OAuth DCR: ${OAUTH_ISSUER}/register`);
  console.log(`  - OAuth Authorize: ${OAUTH_ISSUER}/oauth/authorize`);
  console.log(`  - OAuth Token: ${OAUTH_ISSUER}/oauth/token`);
  console.log(`  - OAuth Metadata: ${OAUTH_ISSUER}/.well-known/oauth-authorization-server`);
  console.log(`  - MCP Metadata: ${OAUTH_ISSUER}/.well-known/oauth-protected-resource${MCP_SERVER_PATH}`);
  console.log(`  - MCP JSON-RPC: ${OAUTH_ISSUER}${MCP_SERVER_PATH} (POST)`);
  console.log(`\nTo test with a real MCP client, configure:`);
  console.log(`  URL: ${MCP_RESOURCE_URI}`);
  console.log(`  Transport: HTTP with SSE`);
  console.log('='.repeat(80) + '\n');
});

// Make user property available on Request type
declare global {
  namespace Express {
    interface Request {
      user?: jwt.JwtPayload;
    }
  }
}
