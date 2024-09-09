import { ConflictException, ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTokenDto, RefreshTokenDto } from './dto/token.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { hash, compare } from 'bcrypt';
import { UserService } from '../user/user.service';
import { TokenResponse, UpdateRefreshToken } from 'src/types/token.type';
import { Request, Response } from 'express';

@Injectable()
export class TokenService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) { }

  async generateTokens(createTokenDto: CreateTokenDto) {
    const { email, username } = createTokenDto;

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          email,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: '30s',
        },
      ),
      this.jwtService.signAsync(
        {
          email,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: '1m',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(
    req: Request,
    res: Response
  ): Promise<TokenResponse> {
    const user = req.user;

    // const refreshTokenMatches = await compare(
    //   refreshToken,
    //   user.refreshToken
    // );

    // if (!refreshTokenMatches)
    //   throw new ForbiddenException('Acesso negado!');

    const createTokenDto: CreateTokenDto = {
      email: user['email'],
      username: user['username']
    }

    const tokens = await this.generateTokens(createTokenDto);

    await this.updateRefreshToken(user['email'], tokens.refreshToken);

    console.log("accessToken refreshed: ", { accessToken: tokens.accessToken });
    console.log("refreshToken refreshed: ", { refreshToken: tokens.refreshToken });

    return tokens;
  }

  async updateRefreshToken(
    email: string,
    refreshToken: string
  ) {
    const hashedRefreshToken = await hash(refreshToken, 10);

    const newRefreshToken: UpdateRefreshToken = {
      email: email,
      refreshToken: hashedRefreshToken
    }

    await this.userService.updateUser(newRefreshToken);
  }

  async validateRefreshToken(
    refreshToken: string
  ) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      return payload;
    } catch (error) {
      if (error.name === 'TokenExpiredError')
        throw new UnauthorizedException('Refresh token expired');

      else if (error.name === 'JsonWebTokenError')
        throw new UnauthorizedException('Invalid refresh token');

      else
        throw new UnauthorizedException('error to read refreshToken');
    }
  }

}