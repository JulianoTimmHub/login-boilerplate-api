import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { compare, hash } from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { SignInDto } from './dto/sign-in.dto';
import { SignInResponse } from 'src/types/auth.type';
import { RecoverPasswordDto } from './dto/recover-password.dto';
import { TokenService } from '../token/token.service';
import { CreateTokenDto } from '../token/dto/token.dto';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly tokenService: TokenService,
  ) {}

  async signIn (
    signInDto: SignInDto,
    res: Response
  ): Promise<SignInResponse> {
    const { email, password } = signInDto;

    const user: User = await this.prismaService.user.findUnique({
      where: {
        email: email
      }
    })

    if (!user) {
      console.log("Usuário não encontrado ao realizar login!")
      throw new NotFoundException("Usuário não encontrado!");
    }

    const correctPassword = await compare(password, user.hashedPassword);

    if (!correctPassword) {
      console.log("Senha do usuario incorreta!")
      throw new UnauthorizedException('Credenciais incorretas!');
    }

    const createTokenDto: CreateTokenDto = {
      email: user.email,
      username: user.username,
    }; 

    const tokens = await this.tokenService.generateTokens(createTokenDto);

    await this.tokenService.updateRefreshToken(email, tokens.refreshToken);

    const cookiesTokens = {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    }

    res.cookie('auth-tokens', cookiesTokens, {
      secure: true, // Para enviar o cookie apenas em requisição HTTPS
      httpOnly: true,
      sameSite: 'strict' // Proteção CSRF
    });

    console.log("accessToken generated: ", {accessToken: tokens.accessToken});
    console.log("refreshToken generated: ", {refreshToken: tokens.refreshToken});
    console.log("User logged: ", user)

    return {
      username: user.username
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

    const hashNewPassword = await hash(confirmNewPassword, 10);

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