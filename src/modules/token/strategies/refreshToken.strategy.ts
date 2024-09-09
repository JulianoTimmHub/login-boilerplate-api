import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { TokenService } from '../token.service';
import { PrismaService } from 'src/modules/prisma/prisma.service';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private tokenService: TokenService,
    private prismaService: PrismaService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([(request: Request) => {
        let data = request?.cookies["auth-tokens"];

        if (!data) {
          console.log("tokens inválidos!")
          return null;
        }

        return data.refreshToken
      }]),
      secretOrKey: process.env.JWT_REFRESH_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    console.log({payload})

    if (!payload) {
      console.log("refreshToken inválido")
      throw new BadRequestException('refreshToken inválido!');
    }

    let data = req?.cookies["auth-tokens"];

    console.log({data})

    if (!data?.refreshToken) {
      console.log("refreshToken inválido ou inexistente!")
      throw new BadRequestException('refreshToken inválido ou inexistente!');
    }

    let payloadUser = await this.tokenService.validateRefreshToken(data.refreshToken);

    const user = await this.prismaService.user.findUnique({
      where: {
        email: payloadUser.email
      },
    });

    if (!user)
      throw new NotFoundException("Usuário não encontrado!");

    return payloadUser;
    
  }
}