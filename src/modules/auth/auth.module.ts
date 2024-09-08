import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from '../prisma/prisma.module';
import { TokenService } from '../token/token.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

@Module({
  imports: [PrismaModule],
  controllers: [AuthController],
  providers: [AuthService, TokenService, JwtService, ConfigService, UserService]
})

export class AuthModule {}