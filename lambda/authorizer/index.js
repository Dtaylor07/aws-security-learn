'use strict';

/**
 * Lambda Authorizer (TOKEN type)
 * ─────────────────────────────
 * Validates a Cognito-issued JWT Access Token passed as a Bearer token.
 * Returns an IAM policy (Allow or Deny) consumed by API Gateway.
 *
 * Exam relevance: Domain 4 (IAM) — authorisation strategies.
 * CloudWatch Logs: all decisions logged for Domain 1 (Detection).
 */

const https = require('https');
const { createLogger, format, transports } = require('winston');

const logger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [new transports.Console()]
});

// ── Config from environment variables set in Lambda console / CDK ───────────
const COGNITO_REGION   = process.env.COGNITO_REGION    || 'us-east-1';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const COGNITO_APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID;

// JWKS endpoint for the Cognito user pool
const JWKS_URL = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}/.well-known/jwks.json`;

// In-memory JWKS cache (warmed after cold start)
let jwksCache = null;
let jwksCacheTime = 0;
const JWKS_TTL_MS = 3600_000; // 1 hour

// ── Helpers ──────────────────────────────────────────────────────────────────

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function getJwks() {
  const now = Date.now();
  if (jwksCache && (now - jwksCacheTime) < JWKS_TTL_MS) {
    return jwksCache;
  }
  logger.info('jwks_cache_refresh', { url: JWKS_URL });
  jwksCache = await httpsGet(JWKS_URL);
  jwksCacheTime = now;
  return jwksCache;
}

/**
 * Decode and parse JWT without verification (verification is done via JWKS).
 * Returns { header, payload } or throws.
 */
function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT structure');
  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  return { header, payload, parts };
}

/**
 * Verify JWT signature against JWKS.
 * NOTE: In production use aws-jwt-verify or jsonwebtoken + jwk-to-pem.
 * This implementation performs all the CLAIMS checks the exam tests you on.
 */
async function verifyCognitoToken(token) {
  const { header, payload } = decodeJwt(token);

  // ── Claim validation (exam-critical checks) ──────────────────────────────

  // 1. token_use must be 'access' (not 'id')
  if (payload.token_use !== 'access') {
    throw new Error(`Invalid token_use: ${payload.token_use}. Expected 'access'`);
  }

  // 2. issuer must match the user pool
  const expectedIss = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
  if (payload.iss !== expectedIss) {
    throw new Error(`Invalid issuer: ${payload.iss}`);
  }

  // 3. client_id must match the app client
  if (COGNITO_APP_CLIENT_ID && payload.client_id !== COGNITO_APP_CLIENT_ID) {
    throw new Error(`Invalid client_id: ${payload.client_id}`);
  }

  // 4. Expiry check
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new Error(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
  }

  // 5. JWKS kid match (signature verification scaffold)
  const jwks = await getJwks();
  const key = jwks.keys.find(k => k.kid === header.kid);
  if (!key) {
    throw new Error(`No matching JWKS key for kid: ${header.kid}`);
  }

  // Production: use aws-jwt-verify to verify RS256 signature against the JWK.
  // For this reference implementation the claim checks above are shown.
  // In real deployments add: const verifier = CognitoJwtVerifier.create(...)

  return payload;
}

// ── IAM policy builder ───────────────────────────────────────────────────────

function buildPolicy(principalId, effect, resource, context = {}) {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: resource
      }]
    },
    // Context is passed to integration (Lambda / HTTP) as $context.authorizer.*
    context: {
      userId: context.sub || principalId,
      email:  context.email || '',
      scope:  context.scope || '',
      ...context
    }
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const requestId = event.requestContext?.requestId || 'unknown';

  logger.info('authorizer_invoked', {
    requestId,
    methodArn: event.methodArn,
    tokenPresent: !!event.authorizationToken
  });

  // Extract Bearer token
  const authHeader = event.authorizationToken || '';
  if (!authHeader.startsWith('Bearer ')) {
    logger.warn('authorizer_denied', { reason: 'missing_bearer', requestId });
    // Throwing 'Unauthorized' returns a 401 to the caller
    throw new Error('Unauthorized');
  }

  const token = authHeader.slice(7).trim();

  try {
    const payload = await verifyCognitoToken(token);

    logger.info('authorizer_allowed', {
      requestId,
      sub: payload.sub,
      username: payload.username || payload['cognito:username'],
      tokenExp: payload.exp
    });

    // Allow — wildcard the resource so one authorizer policy covers all methods
    const wildcardArn = event.methodArn.replace(/\/[^\/]+\/[^\/]+$/, '/*/*');
    return buildPolicy(payload.sub, 'Allow', wildcardArn, payload);

  } catch (err) {
    logger.warn('authorizer_denied', {
      requestId,
      reason: err.message
    });

    // Deny (returns 403 to the caller)
    return buildPolicy('unauthorized', 'Deny', event.methodArn);
  }
};
