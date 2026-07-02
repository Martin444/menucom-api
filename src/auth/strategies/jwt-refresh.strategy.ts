import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';

import config from '../../config';
import { ConfigType } from '@nestjs/config';
import { JwtPayload, AuthenticatedUser } from '../types/auth.types';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  private readonly logger = new Logger(JwtRefreshStrategy.name);

  constructor(
    @Inject(config.KEY)
    private readonly configService: ConfigType<typeof config>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: true,
      secretOrKey: configService.jwtsecret,
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    if (!payload || !payload.sub) {
      this.logger.warn('Token inválido: sin payload o sub');
      throw new UnauthorizedException('Token inválido');
    }

    this.logger.log(`Refresh token válido para usuario ${payload.sub}`);
    return {
      userId: payload.sub,
      username: payload.username,
      role: payload.role,
      commerceId: payload.commerceId,
    };
  }
}
