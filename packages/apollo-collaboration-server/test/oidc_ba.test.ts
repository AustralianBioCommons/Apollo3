// Provider mocks intentionally expose asynchronous APIs without performing I/O.
/* eslint-disable @typescript-eslint/require-await */
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import fs from 'node:fs'
import { afterEach, test, mock } from 'node:test'

import type { ExecutionContext } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as oidc from 'openid-client'

import type { AuthenticationService } from '../src/authentication/authentication.service.js'
import {
  oidcBaConfigFactory,
  oidcBaValidationSchema,
  type OidcBaConfiguration,
} from '../src/utils/oidc_ba.config.js'
import { OidcBaAuthGuard } from '../src/utils/oidc_ba.guard.js'
import {
  OidcBaStrategy,
  type OidcBaRequest,
} from '../src/utils/strategies/oidc_ba.strategy.js'

const issuer = 'https://issuer.example.org'
const values = {
  URL: 'https://apollo.example.org/apollo/',
  OIDC_BA_ISSUER: issuer,
  OIDC_BA_CLIENT_ID: 'apollo-client',
  OIDC_BA_CLIENT_SECRET: 'client-secret',
}
const metadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
  userinfo_endpoint: `${issuer}/userinfo`,
  response_types_supported: ['code'],
  id_token_signing_alg_values_supported: ['RS256'],
  code_challenge_methods_supported: ['S256'],
}
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
})
const key = {
  ...publicKey.export({ format: 'jwk' }),
  kid: 'test-key',
  alg: 'RS256',
  use: 'sig',
}

// Sign real test tokens so callback tests exercise the OIDC library's validation.
function idToken(claims: Record<string, unknown>, badSignature = false) {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', kid: key.kid }),
  ).toString('base64url')
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
  const input = `${header}.${payload}`
  const signature = sign('RSA-SHA256', Buffer.from(input), privateKey)
  if (badSignature) {
    signature[0] = (signature[0] ?? 0) ^ 255
  }
  return `${input}.${signature.toString('base64url')}`
}

function configuration(userinfo = true): OidcBaConfiguration {
  const client = new oidc.Configuration(
    {
      ...metadata,
      userinfo_endpoint: userinfo ? metadata.userinfo_endpoint : undefined,
    },
    values.OIDC_BA_CLIENT_ID,
    values.OIDC_BA_CLIENT_SECRET,
  )
  oidc.enableNonRepudiationChecks(client)
  return { client, callbackURL: new URL(`${values.URL}auth/oidc_ba`) }
}

// Supply only the HTTP context used by Nest's authentication guard.
function context(req: OidcBaRequest, response: object = {}) {
  return {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => response,
    }),
  } as unknown as ExecutionContext
}

function request(url: string, session: object = {}): OidcBaRequest {
  return {
    method: 'GET',
    originalUrl: url,
    session,
    query: {},
  } as OidcBaRequest
}

afterEach(() => {
  mock.restoreAll()
})

await test('configuration is optional and requires a complete, unambiguous provider', () => {
  assert.equal(oidcBaValidationSchema.validate({}).error, undefined)
  const complete = { ...values }
  const validate = (input: object) =>
    oidcBaValidationSchema.unknown().validate(input).error
  assert.equal(validate(complete), undefined)
  assert.equal(
    validate({
      URL: values.URL,
      OIDC_BA_ISSUER: issuer,
      OIDC_BA_CLIENT_ID_FILE: 'id',
      OIDC_BA_CLIENT_SECRET_FILE: 'secret',
    }),
    undefined,
  )
  for (const field of [
    'OIDC_BA_ISSUER',
    'OIDC_BA_CLIENT_ID',
    'OIDC_BA_CLIENT_SECRET',
  ]) {
    const partial = Object.fromEntries(
      Object.entries(complete).filter(([key]) => key !== field),
    )
    assert.ok(validate(partial))
  }
  for (const invalid of [
    { ...complete, OIDC_BA_CLIENT_ID_FILE: 'id' },
    { ...complete, OIDC_BA_CLIENT_SECRET_FILE: 'secret' },
    { ...complete, OIDC_BA_CLIENT_SECRET: '  ' },
    ...[
      'http://issuer.example.org',
      `${issuer}?query=1`,
      `${issuer}#hash`,
      `${issuer}/.well-known/openid-configuration`,
    ].map((OIDC_BA_ISSUER) => ({ ...complete, OIDC_BA_ISSUER })),
  ]) {
    assert.ok(validate(invalid))
  }
})

await test('disabled configuration does not fetch discovery', async () => {
  const fetch = mock.method(globalThis, 'fetch', () => {
    throw new Error('Unexpected network access')
  })
  assert.equal(await oidcBaConfigFactory(new ConfigService({})), null)
  assert.equal(fetch.mock.callCount(), 0)
})

await test('discovery supports file credentials and retains the Apollo path prefix', async () => {
  mock.method(fs, 'readFileSync', (file: unknown) =>
    file === 'id-file' ? ' apollo-client\n' : ' client-secret\n',
  )
  mock.method(globalThis, 'fetch', async () => Response.json(metadata))
  const configured = await oidcBaConfigFactory(
    new ConfigService({
      URL: values.URL,
      OIDC_BA_ISSUER: issuer,
      OIDC_BA_CLIENT_ID_FILE: 'id-file',
      OIDC_BA_CLIENT_SECRET_FILE: 'secret-file',
    }),
  )
  assert.equal(configured?.callbackURL.href, `${values.URL}auth/oidc_ba`)
  assert.equal(configured.client.clientMetadata().client_id, 'apollo-client')
  mock.restoreAll()
  mock.method(fs, 'readFileSync', () => '  ')
  await assert.rejects(
    oidcBaConfigFactory(
      new ConfigService({
        ...values,
        OIDC_BA_CLIENT_ID: undefined,
        OIDC_BA_CLIENT_ID_FILE: 'empty-file',
      }),
    ),
    /must not be empty/,
  )
})

await test('discovery rejects a mismatched issuer', async () => {
  mock.method(globalThis, 'fetch', async () =>
    Response.json({ ...metadata, issuer: 'https://wrong.example.org' }),
  )
  await assert.rejects(oidcBaConfigFactory(new ConfigService(values)))
})

await test('guard rejects disabled, expired, missing, and malformed login state', async () => {
  await assert.rejects(
    new OidcBaAuthGuard(null).canActivate(context(request('/auth/oidc_ba'))),
    /not configured/,
  )
  const guard = new OidcBaAuthGuard(configuration())
  for (const session of [
    {},
    { oidcBaReturn: { redirectUri: 'https://app.example.org', createdAt: 0 } },
  ]) {
    await assert.rejects(
      guard.canActivate(
        context(request('/auth/oidc_ba?code=code&state=state', session)),
      ),
      /expired/,
    )
  }
  const session = {
    oidcBaReturn: {
      redirectUri: 'https://app.example.org',
      createdAt: Date.now(),
    },
  }
  await assert.rejects(
    guard.canActivate(context(request('/auth/oidc_ba?state=state', session))),
    /Malformed/,
  )
  assert.equal(session.oidcBaReturn, undefined)
  for (const destination of [
    '',
    'javascript:alert(1)',
    '/relative',
    'https://user:pass@example.org',
  ]) {
    await assert.rejects(
      guard.canActivate(
        context(
          request(
            `/auth/oidc_ba?redirect_uri=${encodeURIComponent(destination)}`,
          ),
        ),
      ),
      /redirect_uri/,
    )
  }
})

// Run the actual Passport guard/strategy with a simulated provider and signed tokens.
async function login(
  overrides: {
    claims?: Record<string, unknown>
    profile?: Record<string, unknown>
    state?: string
    badSignature?: boolean
    userinfo?: boolean
    error?: boolean
  } = {},
) {
  const logIn = mock.fn(async () => ({ token: 'apollo-jwt' }))
  const auth = { logIn } as unknown as AuthenticationService
  const config = configuration(overrides.userinfo ?? true)
  new OidcBaStrategy(auth, config)
  const guard = new OidcBaAuthGuard(config)
  const session: Record<string, unknown> = {}
  let destination = ''
  const start = request(
    `/apollo/auth/oidc_ba?redirect_uri=${encodeURIComponent('https://app.example.org/login')}`,
    session,
  )
  // Passport ends the response when redirecting to the authorization endpoint.
  await new Promise<void>((resolve, reject) => {
    void guard
      .canActivate(
        context(start, {
          setHeader: (name: string, value: string) => {
            if (name === 'Location') {
              destination = value
            }
          },
          end: resolve,
        }),
      )
      .catch(reject)
  })
  const authorization = new URL(destination)
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(authorization.searchParams.get('scope'), 'openid profile email')
  assert.equal(
    authorization.searchParams.get('redirect_uri'),
    `${values.URL}auth/oidc_ba`,
  )
  assert.ok(authorization.searchParams.get('nonce'))
  assert.ok(authorization.searchParams.get('state'))
  const transaction = session.oidc_ba as { code_verifier: string }
  assert.equal(
    await oidc.calculatePKCECodeChallenge(transaction.code_verifier),
    authorization.searchParams.get('code_challenge'),
  )
  const now = Math.floor(Date.now() / 1000)
  const claims = {
    iss: issuer,
    aud: 'apollo-client',
    sub: 'person-1',
    iat: now,
    exp: now + 300,
    nonce: authorization.searchParams.get('nonce'),
    email: 'user@example.org',
    email_verified: true,
    ...overrides.claims,
  }
  mock.method(
    globalThis,
    'fetch',
    async (input: unknown, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/token')) {
        assert.ok(init?.body instanceof URLSearchParams)
        const { body } = init
        assert.equal(body.get('code_verifier'), transaction.code_verifier)
        assert.equal(body.get('client_secret'), 'client-secret')
        return Response.json({
          access_token: 'provider-token',
          token_type: 'Bearer',
          id_token: idToken(claims, overrides.badSignature),
        })
      }
      if (url.endsWith('/jwks')) {
        return Response.json({ keys: [key] })
      }
      if (url.endsWith('/userinfo')) {
        return Response.json({
          sub: 'person-1',
          email: 'user@example.org',
          email_verified: true,
          name: 'Test User',
          ...overrides.profile,
        })
      }
      throw new Error(`Unexpected network request: ${url}`)
    },
  )
  const state = overrides.state ?? authorization.searchParams.get('state') ?? ''
  const callback = request(
    `/apollo/auth/oidc_ba?${overrides.error ? 'error=access_denied' : 'code=authorization-code'}&state=${state}&redirect_uri=https://attacker.example.org`,
    session,
  )
  const result = guard.canActivate(context(callback))
  return { result, callback, logIn, guard, session }
}

await test('OIDC login issues an Apollo token and preserves the session destination', async () => {
  const { result, callback, logIn, guard, session } = await login()
  assert.equal(await result, true)
  assert.deepEqual(logIn.mock.calls[0]?.arguments, [
    'Test User',
    'user@example.org',
  ])
  assert.deepEqual(callback.user, {
    token: 'apollo-jwt',
    redirectUri: 'https://app.example.org/login',
  })
  assert.equal(session.oidc_ba, undefined)
  assert.equal(session.oidcBaReturn, undefined)
  await assert.rejects(guard.canActivate(context(callback)), /expired/)
})

await test('OIDC login accepts verified ID-token claims when UserInfo is unavailable', async () => {
  const { result, logIn } = await login({ userinfo: false })
  assert.equal(await result, true)
  assert.deepEqual(logIn.mock.calls[0]?.arguments, [
    'user@example.org',
    'user@example.org',
  ])
})

for (const [name, overrides] of Object.entries({
  'wrong state': { state: 'wrong-state' },
  'wrong nonce': { claims: { nonce: 'wrong-nonce' } },
  'wrong issuer': { claims: { iss: 'https://wrong.example.org' } },
  'wrong audience': { claims: { aud: 'another-client' } },
  'expired token': { claims: { exp: 1 } },
  'invalid signature': { badSignature: true },
  'wrong UserInfo subject': { profile: { sub: 'another-person' } },
  'unverified email': { profile: { email_verified: false } },
  'missing verification': { profile: { email_verified: undefined } },
  'string verification': { profile: { email_verified: 'true' } },
  'missing email': { profile: { email: undefined } },
  'reserved root identity': { profile: { email: 'root_user', name: 'root' } },
  'provider denial': { error: true },
})) {
  await test(`OIDC login rejects ${name}`, async () => {
    const { result, logIn } = await login(overrides)
    await assert.rejects(result)
    assert.equal(logIn.mock.callCount(), 0)
  })
}
