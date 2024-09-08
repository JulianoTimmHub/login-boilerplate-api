import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { verify, hash } from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { SignInDto } from './dto/sign-in.dto';
import { SignInResponse } from 'src/types/auth.type';
import { RecoverPasswordDto } from './dto/recover-password.dto';
import { TokenService } from '../token/token.service';
import { CreateTokenDto } from '../token/dto/token.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly tokenService: TokenService,
  ) {}

  async signIn (
    signInDto: SignInDto
  ): Promise<SignInResponse> {
    const { email, password } = signInDto;

    const user: User = await this.prismaService.user.findUnique({
      where: {
        email: email
      }
    })

    if (!user) {
      throw new NotFoundException("Usuário não encontrado!");
    }

    const hasUser = await verify(password, user.hashedPassword);

    if (!hasUser) {
      throw new UnauthorizedException('Credenciais incorretas!');
    }

    const createTokenDto: CreateTokenDto = {
      email: user.email,
      username: user.username,
    }; 

    const tokens = await this.tokenService.generateTokens(createTokenDto);

    console.log("Tokens generated: ", tokens.accessToken, " | ", tokens.refreshToken)

    console.log("User logged: ", user)

    return {
      username: user.username,
      tokens
    }
  }

  async recoverPassword (
    recoverPasswordDto: RecoverPasswordDto
  ): Promise<Boolean> {
    const { email, newPassword, confirmNewPassword } = recoverPasswordDto;

    if (newPassword !== confirmNewPassword) {
      throw new BadRequestException("As senhas devem ser iguais!");
    }

    const user: User = await this.prismaService.user.findUnique({
      where: {
        email,
      }
    });

    if (!user) {
      throw new NotFoundException("Usuário não encontrado!")
    }

    const hashNewPassword = await hash(confirmNewPassword);

    const newUserPassword: User = await this.prismaService.user.update({
      where: {
        email
      },
      data: {
        hashedPassword: hashNewPassword
      },
    });

    console.log("User changed: ", newUserPassword)

    return !!newUserPassword;
  }

}