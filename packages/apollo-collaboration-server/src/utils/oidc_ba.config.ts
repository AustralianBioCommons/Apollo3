import fs from 'node:fs'

import type { ConfigService } from '@nestjs/config'
import Joi from 'joi'
import * as client from 'openid-client'
import {
  fetch,
  ProxyAgent,
  type RequestInit as UndiciRequestInit,
} from 'undici'

export const OIDC_BA_CONFIGURATION = Symbol('OIDC_BA_CONFIGURATION')
export const OIDC_BA_LOGIN = Symbol('OIDC_BA_LOGIN')

// Require a complete optional provider and exactly one source per credential.
export const oidcBaValidationSchema = Joi.object({
  OIDC_BA_ISSUER: Joi.string()
    .uri({ scheme: ['https'] })
    .custom((value: string, helpers) => {
      const url = new URL(value)
      if (
        url.search ||
        url.hash ||
        url.username ||
        url.password ||
        url.pathname.includes('/.well-known/')
      ) {
        return helpers.error('any.invalid')
      }
      return value
    }),
  OIDC_BA_CLIENT_ID: Joi.string().trim(),
  OIDC_BA_CLIENT_ID_FILE: Joi.string(),
  OIDC_BA_CLIENT_SECRET: Joi.string().trim(),
  OIDC_BA_CLIENT_SECRET_FILE: Joi.string(),
  OIDC_BA_DISPLAY_NAME: Joi.string().trim().default('BioCommons Access'),
})
  .oxor('OIDC_BA_CLIENT_ID', 'OIDC_BA_CLIENT_ID_FILE')
  .oxor('OIDC_BA_CLIENT_SECRET', 'OIDC_BA_CLIENT_SECRET_FILE')
  .with('OIDC_BA_CLIENT_ID', 'OIDC_BA_ISSUER')
  .with('OIDC_BA_CLIENT_ID_FILE', 'OIDC_BA_ISSUER')
  .with('OIDC_BA_CLIENT_SECRET', 'OIDC_BA_ISSUER')
  .with('OIDC_BA_CLIENT_SECRET_FILE', 'OIDC_BA_ISSUER')
  .when(Joi.object({ OIDC_BA_ISSUER: Joi.exist() }).unknown(), {
    // Joi uses then to define conditional validation rules.
    // eslint-disable-next-line unicorn/no-thenable
    then: Joi.object()
      .or('OIDC_BA_CLIENT_ID', 'OIDC_BA_CLIENT_ID_FILE')
      .or('OIDC_BA_CLIENT_SECRET', 'OIDC_BA_CLIENT_SECRET_FILE'),
  })

export interface OidcBaConfiguration {
  client: client.Configuration
  callbackURL: URL
}

// Resolve file credentials once at startup and reject empty secret files.
function credential(config: ConfigService, key: string): string {
  const inline = config.get<string>(key)
  const file = config.get<string>(`${key}_FILE`)
  const value = (inline ?? (file ? fs.readFileSync(file, 'utf8') : '')).trim()
  if (!value) {
    throw new Error(`${key} must not be empty`)
  }
  return value
}

export async function oidcBaConfigFactory(
  config: ConfigService,
): Promise<OidcBaConfiguration | null> {
  // Leave OIDC disabled without contacting an identity provider.
  const issuer = config.get<string>('OIDC_BA_ISSUER')
  if (!issuer) {
    return null
  }
  const clientId = credential(config, 'OIDC_BA_CLIENT_ID')
  const clientSecret = credential(config, 'OIDC_BA_CLIENT_SECRET')
  const proxy = config.get<string>('OAUTH_HTTP_PROXY')
  const dispatcher = proxy ? new ProxyAgent(proxy) : undefined

  // Apply the same proxy to discovery, token, userinfo, and signing-key requests.
  const customFetch: typeof globalThis.fetch = async (input, init) => {
    if (!dispatcher) {
      return await globalThis.fetch(input, init)
    }
    // Bridge Node's bundled fetch types to the installed Undici implementation.
    const options = { ...init, dispatcher } as unknown as UndiciRequestInit
    const url =
      typeof input === 'string' || input instanceof URL ? input : input.url
    return await fetch(url, options)
  }
  const discovered = await client.discovery(
    new URL(issuer),
    clientId,
    clientSecret,
    undefined,
    { [client.customFetch]: customFetch, timeout: 10 },
  )
  // Verify ID-token signatures with the provider's discovered signing keys.
  client.enableNonRepudiationChecks(discovered)
  const callbackURL = new URL(config.getOrThrow<string>('URL'))
  callbackURL.pathname = `${callbackURL.pathname.replace(/\/$/, '')}/auth/oidc_ba`
  callbackURL.search = ''
  callbackURL.hash = ''
  return { client: discovered, callbackURL }
}
