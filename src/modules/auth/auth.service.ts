import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { compare, hash } from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { SignInDto } from './dto/sign-in.dto';
import { SignInResponse } from 'src/types/auth.type';
import { RecoverPasswordDto } from './dto/recover-password.dto';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

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

    const hasUser = await compare(password, user.hashedPassword);

    if (!hasUser) {
      throw new UnauthorizedException('Credenciais incorretas!');
    }

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