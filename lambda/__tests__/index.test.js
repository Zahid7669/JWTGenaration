/* Mocks for AWS SDK clients */
const mockDdbSend = jest.fn();
const mockKmsSend = jest.fn();

jest.mock('@aws-sdk/client-dynamodb', () => {
  class DynamoDBClient {}
  return { DynamoDBClient };
}, { virtual: true });

jest.mock('@aws-sdk/lib-dynamodb', () => {
  // Simple command class capturing input like the real one
  class GetCommand {
    constructor(input) { this.input = input; }
  }
  const DynamoDBDocumentClient = {
    from: () => ({ send: mockDdbSend }),
  };
  return { DynamoDBDocumentClient, GetCommand };
}, { virtual: true });

jest.mock('@aws-sdk/client-kms', () => {
  class GetPublicKeyCommand { constructor(input) { this.input = input; } }
  class SignCommand { constructor(input) { this.input = input; } }
  class KMSClient {
    constructor() {}
    send(cmd) { return mockKmsSend(cmd); }
  }
  return { KMSClient, GetPublicKeyCommand, SignCommand };
}, { virtual: true });

/* Helper to build events */
function eventWith({ authPair, body, contentType = 'application/x-www-form-urlencoded' } = {}) {
  const headers = {};
  if (contentType) headers['content-type'] = contentType;
  if (authPair) headers['authorization'] = 'Basic ' + Buffer.from(authPair).toString('base64');
  return {
    headers,
    body,
    isBase64Encoded: false,
  };
}

describe('token endpoint (client_credentials)', () => {
  let handler;

  beforeEach(() => {
    jest.resetModules();
    mockDdbSend.mockReset();
    mockKmsSend.mockReset();

    // Default mocks: valid DDB row when username/password match, valid KMS signing
    mockDdbSend.mockImplementation(async (cmd) => {
      if (cmd.input?.Key?.Username === 'admin' && cmd.input?.Key?.Password === 'admin') {
        return { Item: { Username: 'admin', Password: 'admin', token_ttl_seconds: 3600 } };
      }
      return {}; // Item undefined -> not found
    });

    mockKmsSend.mockImplementation(async (cmd) => {
      const cname = cmd.constructor?.name;
      if (cname === 'GetPublicKeyCommand') {
        return { KeyId: 'kid-123' };
      }
      if (cname === 'SignCommand') {
        return { Signature: Buffer.from('sig') };
      }
      return {};
    });

    // Load handler after mocks
    ({ handler } = require('../index.js'));
  });

  test('400 when content-type is not x-www-form-urlencoded', async () => {
    const res = await handler(eventWith({
      authPair: 'admin:admin',
      body: 'grant_type=client_credentials',
      contentType: 'application/json',
    }));
    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('invalid_request');
  });

  test('400 when grant_type is unsupported', async () => {
    const res = await handler(eventWith({
      authPair: 'admin:admin',
      body: 'grant_type=refresh_token',
    }));
    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('unsupported_grant_type');
  });

  test('400 when credentials missing (no Basic auth)', async () => {
    const res = await handler(eventWith({
      body: 'grant_type=client_credentials',
    }));
    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('invalid_request');
  });

  test('401 when invalid client (wrong password)', async () => {
    const res = await handler(eventWith({
      authPair: 'admin:wrong',
      body: 'grant_type=client_credentials',
    }));
    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('invalid_client');
  });

  test('200 issues JWT for valid client', async () => {
    const res = await handler(eventWith({
      authPair: 'admin:admin',
      body: 'grant_type=client_credentials',
    }));
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.token_type).toBe('Bearer');
    expect(typeof body.expires_in).toBe('number');

    // access_token should look like JWT (3 parts separated by '.')
    expect(typeof body.access_token).toBe('string');
    expect(body.access_token.split('.')).toHaveLength(3);
  });

  test('500 when KMS returns empty signature', async () => {
    mockKmsSend.mockImplementation(async (cmd) => {
      const cname = cmd.constructor?.name;
      if (cname === 'GetPublicKeyCommand') return { KeyId: 'kid-123' };
      if (cname === 'SignCommand') return { Signature: undefined }; // force error
      return {};
    });

    const res = await handler(eventWith({
      authPair: 'admin:admin',
      body: 'grant_type=client_credentials',
    }));

    expect(res.statusCode).toBe(500);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('server_error');
  });
});
