import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { TokenService } from './token.service';
import { TokenController } from './token.controller';
import { AccessTokenStrategy } from './strategies/accessToken.strategy';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

@Module({
  imports: [PrismaModule],
  controllers: [TokenController],
  providers: [TokenService, UserService, JwtService, ConfigService, AccessTokenStrategy, RefreshTokenStrategy]
})

export class TokenModule {}