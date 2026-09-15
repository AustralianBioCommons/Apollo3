import {
  type ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common'
import { AuthGuard } from '@nestjs/passport'
import type { SessionData } from 'express-session'

import {
  OIDC_BA_CONFIGURATION,
  type OidcBaConfiguration,
} from './oidc_ba.config.js'
import type { OidcBaRequest } from './strategies/oidc_ba.strategy.js'

declare module 'express-session' {
  interface SessionData {
    oidcBaReturn?: { redirectUri: string; createdAt: number }
  }
}

@Injectable()
export class OidcBaAuthGuard extends AuthGuard('oidc_ba') {
  constructor(
    @Inject(OIDC_BA_CONFIGURATION)
    private readonly configuration: OidcBaConfiguration | null,
  ) {
    super()
  }

  async canActivate(context: ExecutionContext) {
    if (!this.configuration) {
      throw new UnauthorizedException(
        'BioCommons Access login is not configured',
      )
    }
    const req = context.switchToHttp().getRequest<OidcBaRequest>()
    const query = new URL(req.originalUrl, this.configuration.callbackURL)
      .searchParams
    const callback = ['code', 'error', 'response', 'state'].some((key) =>
      query.has(key),
    )
    if (callback) {
      // Consume the saved destination before processing a callback, including failures.
      const saved: SessionData['oidcBaReturn'] = req.session.oidcBaReturn
      delete req.session.oidcBaReturn
      if (!saved || Date.now() - saved.createdAt > 10 * 60 * 1000) {
        throw new UnauthorizedException(
          'BioCommons Access login has expired; please try again',
        )
      }
      if (!query.has('code') && !query.has('error')) {
        throw new UnauthorizedException('Malformed BioCommons Access callback')
      }
      req.oidcBaRedirectUri = saved.redirectUri
    } else {
      // Keep Apollo's popup destination in the session rather than OAuth state.
      const redirectUri = query.get('redirect_uri')
      let destination: URL
      try {
        destination = new URL(redirectUri ?? '')
      } catch {
        throw new BadRequestException('A valid redirect_uri is required')
      }
      if (
        !['https:', 'http:'].includes(destination.protocol) ||
        destination.username ||
        destination.password
      ) {
        throw new BadRequestException(
          'redirect_uri must be an HTTP or HTTPS URL',
        )
      }
      req.session.oidcBaReturn = {
        redirectUri: destination.href,
        createdAt: Date.now(),
      }
    }
    return (await super.canActivate(context)) as boolean
  }
}
