import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTokenDto } from './dto/token.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { hash } from 'bcrypt';
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
    const { email, username, application } = createTokenDto;

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          email,
          username,
          application
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
          application
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

  async generateAccessToken(createTokenDto: CreateTokenDto) {
    const { email, username, application } = createTokenDto;

    const [accessToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          email,
          username,
          application
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: '30s',
        },
      )
    ]);

    return {
      accessToken
    };
  }

  async refreshToken(
    req: Request,
    res: Response
  ): Promise<void> {
    const cookieTokens = req.cookies['tokens'];
    const decodedRefreshToken = this.jwtService.decode(cookieTokens.refreshToken);
    const { email, username, application } = decodedRefreshToken;

    const createTokenDto: CreateTokenDto = {
      email: email,
      username: username
    }

    const tokens = await this.generateTokens(createTokenDto);

    await this.saveTokensInCookies(res, tokens);

    const updateRefreshToken: UpdateRefreshToken = {
      email: email,
      application: application,
      refreshToken: tokens.refreshToken
    }

    await this.updateRefreshToken(updateRefreshToken);
  }

  async updateRefreshToken(
    updateRefreshToken: UpdateRefreshToken
  ) {
    const { email, application, refreshToken } = updateRefreshToken;

    const hashedRefreshToken = refreshToken != null ? await hash(refreshToken, 10) : null;

    const newRefreshToken: UpdateRefreshToken = {
      email: email,
      application: application,
      refreshToken: hashedRefreshToken
    }

    await this.userService.updateUser(newRefreshToken);
  }

  async validateToken(
    req: Request,
    res: Response
  ): Promise<TokenResponse> {
    try {
      const cookieTokens = req.cookies['tokens'];

      if (!cookieTokens || !cookieTokens.refreshToken) {
        res.clearCookie('tokens');
        return { tokensHasValid: false };
      }

      if (cookieTokens.accessToken) {
        try {
          const verifyAccessToken = this.jwtService.verify(
            cookieTokens.accessToken,
            { secret: process.env.JWT_ACCESS_SECRET }
          );

          const user = await this.prismaService.user.findFirst({
            where: { email: verifyAccessToken.email }
          });

          if (!user) {
            await this.invalidateTokens(res);
            return { tokensHasValid: false };
          }

          return { userPayload: user, tokensHasValid: true };
        } catch (accessTokenError) {
          return await this.validateRefreshToken(res, cookieTokens.refreshToken);
        }
      } else {
        return await this.validateRefreshToken(res, cookieTokens.refreshToken);
      }
    } catch (error) {
      console.error('General token validation error: ', error);
      res.clearCookie('tokens');
      return { tokensHasValid: false };
    }
  }

  async validateRefreshToken(
    res: Response,
    refreshToken: any
  ): Promise<TokenResponse> {
    try {
      const verifyRefreshToken = this.jwtService.verify(
        refreshToken,
        { secret: process.env.JWT_REFRESH_SECRET }
      );

      console.log({ verifyRefreshToken })

      if (verifyRefreshToken) {
        const user = await this.prismaService.user.findUnique({
          where: {
            email_application_id: {
              email: verifyRefreshToken.email,
              application_id: verifyRefreshToken.application.id
            }
          }
        });

        if (!user) {
          await this.invalidateTokens(res);
          return { userPayload: null, tokensHasValid: false };
        }

        const createTokenDto: CreateTokenDto = {
          email: user.email,
          username: user.username,
        };

        const newAccessToken = await this.generateAccessToken(createTokenDto);

        const tokens = {
          accessToken: newAccessToken,
          refreshToken: refreshToken
        };

        await this.saveTokensInCookies(res, tokens);

        return { userPayload: user, tokensHasValid: true };
      } else {
        await this.invalidateTokens(res);
        return { userPayload: null, tokensHasValid: false };
      }
    } catch (refreshTokenError) {
      await this.invalidateTokens(res);

      if (refreshTokenError.name === 'TokenExpiredError') {
        throw new UnauthorizedException({ message: 'Refresh token expired', tokensHasValid: false });
      } else if (refreshTokenError.name === 'JsonWebTokenError') {
        throw new UnauthorizedException({ message: 'Invalid refresh token', tokensHasValid: false });
      } else {
        throw new UnauthorizedException({ message: 'error to read refreshToken', tokensHasValid: false });
      }
    }
  }

  async invalidateTokens(
    res: Response
  ): Promise<void> {
    res.clearCookie('tokens');
  }

  async saveTokensInCookies(
    res: Response,
    tokens: {
      accessToken: any;
      refreshToken: any;
    }
  ): Promise<void> {
    let expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day by default

    try {
      const verifyRefreshToken = this.jwtService.verify(
        tokens?.refreshToken,
        { secret: process.env.JWT_REFRESH_SECRET }
      );

      if (verifyRefreshToken)
        expires = new Date(verifyRefreshToken?.exp * 1000);
    } catch (refreshTokenError) {
      console.error("Refresh token is invalid: ", { refreshTokenError })
    }

    res.cookie('tokens', tokens, {
      secure: process.env.NODE_ENV === 'production', // For send the cookie only in HTTPS requests
      httpOnly: true,
      sameSite: 'strict', // 'strict' for CSRF protection, 'lax' is less restricted than 'strict', is adequed for development enviroment
      domain: 'localhost',
      expires: expires
    });
  }
}