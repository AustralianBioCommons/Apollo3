import { Inject, Injectable, UnauthorizedException } from '@nestjs/common'
import { PassportStrategy } from '@nestjs/passport'
import type { Request } from 'express'
import Joi from 'joi'
import * as client from 'openid-client'
import { Strategy, type AuthenticateOptions } from 'openid-client/passport'

import type { AuthenticationService } from '../../authentication/authentication.service.js'
import {
  OIDC_BA_CONFIGURATION,
  OIDC_BA_LOGIN,
  type OidcBaConfiguration,
} from '../oidc_ba.config.js'

export interface OidcBaRequest extends Request {
  oidcBaRedirectUri?: string
}

@Injectable()
export class OidcBaStrategy extends PassportStrategy(Strategy, 'oidc_ba', 3) {
  constructor(
    @Inject(OIDC_BA_LOGIN)
    private readonly authService: Pick<AuthenticationService, 'logIn'>,
    @Inject(OIDC_BA_CONFIGURATION)
    private readonly configuration: OidcBaConfiguration | null,
  ) {
    // Register a dormant strategy when disabled; the guard rejects login attempts.
    super({
      config:
        configuration?.client ??
        new client.Configuration(
          { issuer: 'https://disabled.invalid' },
          'disabled',
        ),
      callbackURL: configuration?.callbackURL,
      scope: 'openid profile email',
      sessionKey: 'oidc_ba',
      passReqToCallback: true,
    })
  }

  authorizationRequestParams(req: Request, options: AuthenticateOptions) {
    // Bind every authorization request to both random state and an ID-token nonce.
    const params = new URLSearchParams(
      super.authorizationRequestParams(req, options),
    )
    params.set('state', client.randomState())
    params.set('nonce', client.randomNonce())
    return params
  }

  currentUrl(req: Request) {
    // Use the public callback origin even when Apollo sits behind a reverse proxy.
    const url = new URL(
      this.configuration?.callbackURL ?? 'https://disabled.invalid',
    )
    url.search = new URL(req.originalUrl, url).search
    return url
  }

  async validate(
    req: OidcBaRequest,
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
  ) {
    const claims = tokens.claims()
    if (!claims || !this.configuration || !req.oidcBaRedirectUri) {
      throw new UnauthorizedException('Invalid BioCommons Access login')
    }
    // Userinfo must belong to the same subject as the validated ID token.
    const profile = this.configuration.client.serverMetadata().userinfo_endpoint
      ? await client.fetchUserInfo(
          this.configuration.client,
          tokens.access_token,
          claims.sub,
        )
      : claims
    if (
      typeof profile.email !== 'string' ||
      Joi.string()
        .email({ tlds: { allow: false } })
        .validate(profile.email).error ||
      profile.email_verified !== true
    ) {
      throw new UnauthorizedException(
        'BioCommons Access must provide a verified email',
      )
    }
    const name =
      typeof profile.name === 'string' && profile.name.trim()
        ? profile.name
        : profile.email
    const user = await this.authService.logIn(name, profile.email)
    return { ...user, redirectUri: req.oidcBaRedirectUri }
  }
}
