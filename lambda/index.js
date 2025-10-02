'use strict';

const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand } = require('@aws-sdk/lib-dynamodb');
const { KMSClient, GetPublicKeyCommand, SignCommand } = require('@aws-sdk/client-kms');

/* UTILITY FUNCTIONS */

// base64url encode for JWT parts
function base64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64url');
}

// parse x-www-form-urlencoded body into an object
function parseForm(body) {
  const out = {};
  const params = new URLSearchParams(body || '');
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

// parse "Authorization: Basic base64(id:secret)"
function parseBasicAuth(header) {
  if (!header || !header.startsWith('Basic ')) return null;
  const raw = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const idx = raw.indexOf(':');
  if (idx < 0) return null;
  return { client_id: raw.slice(0, idx), client_secret: raw.slice(idx + 1) };
}

// case-insensitive header getter
function headerGet(headers, name) {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === target) return v;
  }
  return undefined;
}

// get AWS Endpoint
function awsEndpoint() {
  if (process.env.AWS_ENDPOINT_URL) return process.env.AWS_ENDPOINT_URL;
  return undefined;
}

/* AWS VARIABLES */

const REGION = process.env.AWS_REGION || 'eu-west-1';
const DDB = DynamoDBDocumentClient.from(new DynamoDBClient({ endpoint: awsEndpoint(), region: REGION }));
const KMS = new KMSClient({ endpoint: awsEndpoint(), region: REGION });

const USERS_TABLE = process.env.USERS_TABLE || 'Users';
const KMS_KEY_ALIAS = process.env.KMS_KEY_ALIAS || 'alias/signing-key';

/* DYNAMODB */

// fetch row using both keys; wrong password => no item
async function getClientByUsername(username, password) {
  const res = await DDB.send(new GetCommand({
    TableName: USERS_TABLE,
    Key: { Username: username, Password: password }
  }));
  const item = res.Item;
  if (!item) return null;
  return {
    client_id: item.Username,
    client_secret: item.Password,
    token_ttl_seconds: item.token_ttl_seconds || 3600
  };
}

/* AWS KMS */
// sign payload with RS256 using KMS key
async function signJwtRS256(payload) {
  const pub = await KMS.send(new GetPublicKeyCommand({ KeyId: KMS_KEY_ALIAS })); // resolve kid
  const kid = pub.KeyId;
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const { Signature } = await KMS.send(new SignCommand({
    KeyId: KMS_KEY_ALIAS,
    Message: Buffer.from(signingInput),
    MessageType: 'RAW',
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256'
  }));
  if (!Signature) throw new Error('KMS returned empty signature');
  return `${signingInput}.${base64url(Signature)}`;
}

/* OAuth logic */

function badRequest(error, error_description) { return { statusCode: 400, body: { error, error_description } }; }
function unauthorized() { return { statusCode: 401, body: { error: 'invalid_client' } }; }


async function handleTokenRequest(req) {
  // must be application/x-www-form-urlencoded
  const contentType = headerGet(req.headers, 'content-type') || '';
  if (!/application\/x-www-form-urlencoded/i.test(contentType)) {
    return badRequest('invalid_request', 'content-type must be application/x-www-form-urlencoded');
  }

  const auth = parseBasicAuth(headerGet(req.headers, 'authorization')); // prefer Basic auth
  const form = parseForm(req.body); // parse body

  // must be client_credentials
  const grantType = form['grant_type'];
  if (grantType !== 'client_credentials') {
    return { statusCode: 400, body: { error: 'unsupported_grant_type' } };
  }

  // pull creds from Basic auth only (fits your schema)
  const presentedId = auth && auth.client_id;
  const presentedSecret = auth && auth.client_secret;
  if (!presentedId || !presentedSecret) {
    return badRequest('invalid_request', 'missing client credentials');
  }

  // lookup with composite key
  const client = await getClientByUsername(presentedId, presentedSecret);
  if (!client) return unauthorized();

  // build minimal claims
  const now = Math.floor(Date.now() / 1000);
  const ttl = client.token_ttl_seconds || 3600;
  const payload = { sub: client.client_id, iat: now, exp: now + ttl };

  // sign + respond
  const jwt = await signJwtRS256(payload);
  return { statusCode: 200, body: { access_token: jwt, token_type: 'Bearer', expires_in: ttl } };
}

/* Lambda handler */

exports.handler = async (event) => {
  try {
    const bodyStr = event && event.isBase64Encoded
      ? Buffer.from(event.body || '', 'base64').toString('utf8')
      : ((event && event.body) || '');
      
    const res = await handleTokenRequest({ headers: (event && event.headers) || {}, body: bodyStr });

    return { isBase64Encoded: false, statusCode: res.statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(res.body) };
  } catch (err) {
    console.error('Unhandled error in handler:', err); // quick visibility in logs
    return { isBase64Encoded: false, statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'server_error' }) };
  }
};

