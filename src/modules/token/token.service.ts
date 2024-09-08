import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTokenDto, RefreshTokenDto } from './dto/token.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { hash, verify } from 'argon2';
import { UserService } from '../user/user.service';
import { TokenResponse, UpdateRefreshToken } from 'src/types/token.type';

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
          sub: email,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: '1m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: email,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: '3m',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto
  ): Promise<TokenResponse> {
    const { email, username, refreshToken } = refreshTokenDto;

    const user = await this.prismaService.user.findUnique({
      where: {
        email
      }
    });

    if (!user) {
      throw new ConflictException("Usuário não encontrado!");
    }

    const refreshTokenMatches = await verify(
      user.refreshToken,
      refreshToken,
    );

    if (!refreshTokenMatches) 
      throw new ForbiddenException('Acesso negado!');

    const createTokenDto: CreateTokenDto = {
      email: email,
      username: username
    }

    const tokens = await this.generateTokens(createTokenDto);

    await this.updateRefreshToken(email, tokens.refreshToken);

    console.log("Tokens refreshed: ", tokens.accessToken, " | ", tokens.refreshToken);

    return tokens;
  }

  async updateRefreshToken(
    email: string, 
    refreshToken: string
  ) {
    const hashedRefreshToken = await hash(refreshToken);

    const newRefreshToken: UpdateRefreshToken = {
      email: email,
      refreshToken: hashedRefreshToken
    }

    await this.userService.updateUser(newRefreshToken);
  }

}