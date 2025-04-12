import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { TokenService } from '../token.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private tokenService: TokenService,
    private jwtService: JwtService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([(req: Request) => {
        let data = req?.cookies["tokens"];

        const res = req.res;

        if (!res)
          throw new UnauthorizedException('Response object not available');

        if (!data)
          throw new UnauthorizedException({ message: 'Refresh token not found', tokensHasValid: false });

        try {
          const verifyRefreshToken = this.jwtService.verify(
            data.refreshToken,
            { secret: process.env.JWT_REFRESH_SECRET }
          );

          if (verifyRefreshToken)
            return data.refreshToken;

        } catch (refreshTokenError) {
          this.tokenService.invalidateTokens(res);

          throw new UnauthorizedException({
            message: 'Refresh token expired',
            tokensHasValid: false
          });
        }

        return data.refreshToken;
      }]),
      secretOrKey: process.env.JWT_REFRESH_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    try {
      const res = req.res;

      if (!res)
        throw new UnauthorizedException('Response object not available');

      const validationResult = await this.tokenService.validateToken(req, res);

      if (!validationResult.tokensHasValid)
        throw new UnauthorizedException({ message: 'Invalid or expired tokens', tokensHasValid: false });

      return validationResult.userPayload;
    } catch (error) {
      console.error('Error when validate refreshToken: ', error);
      throw new UnauthorizedException({ message: error.message || 'Authentication failed', tokensHasValid: false });
    }
  }
}