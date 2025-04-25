import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { compare, hash } from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { SignInDto } from './dto/sign-in.dto';
import { SignInResponse } from 'src/types/auth.type';
import { RecoverPasswordDto } from './dto/recover-password.dto';
import { TokenService } from '../token/token.service';
import { CreateTokenDto } from '../token/dto/token.dto';
import { Response, Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { UpdateRefreshToken } from 'src/types/token.type';
import { LogoutDto } from './dto/logout.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
  ) { }

  async signIn(
    signInDto: SignInDto,
    req: Request,
    res: Response
  ): Promise<SignInResponse> {
    const { email, password, application } = signInDto;

    const existingApplication = await this.prismaService.application.findUnique({
      where: {
        name: application.name
      }
    });

    const user: User = await this.prismaService.user.findFirst({
      where: {
        email,
        application_id: existingApplication ? existingApplication.id : null
      }
    })

    if (!user) {
      console.error("User not found when loggin in!")
      throw new NotFoundException("User not found!");
    }

    const correctPassword = await compare(password, user.hashedPassword);

    if (!correctPassword) {
      console.error("User password incorrect!")
      throw new UnauthorizedException('Incorrect credentials!');
    }

    const createTokenDto: CreateTokenDto = {
      email: user.email,
      username: user.username,
      application: existingApplication
    };

    const tokens = await this.tokenService.generateTokens(createTokenDto);

    const updateRefreshToken: UpdateRefreshToken = {
      email: email,
      application: existingApplication,
      refreshToken: tokens.refreshToken
    }

    await this.tokenService.updateRefreshToken(updateRefreshToken);

    const cookiesTokens = {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    }

    await this.tokenService.saveTokensInCookies(res, cookiesTokens);

    console.info("User logged: ", user)

    return {
      username: user.username
    }
  }

  async logout(
    req: Request,
    res: Response,
    logoutDto: LogoutDto
  ): Promise<void> {
    let dataUserTokens = req?.cookies["tokens"];
    const decodedRefreshToken = this.jwtService.decode(dataUserTokens?.refreshToken);

    const updateRefreshToken: UpdateRefreshToken = {
      email: decodedRefreshToken?.email ?? logoutDto?.email,
      application: decodedRefreshToken?.application ?? logoutDto?.application,
      refreshToken: null
    }

    await this.tokenService.invalidateTokens(res);

    await this.userService.updateUser(updateRefreshToken);
  }

  async recoverPassword(
    recoverPasswordDto: RecoverPasswordDto
  ): Promise<Boolean> {
    const { email, newPassword, confirmNewPassword, application } = recoverPasswordDto;

    if (newPassword !== confirmNewPassword)
      throw new BadRequestException("The passwords must be equals!");

    const existingApplication = await this.prismaService.application.findUnique({
      where: {
        name: application.name
      }
    });

    const user: User = await this.prismaService.user.findFirst({
      where: {
        email,
        application_id: existingApplication ? existingApplication.id : null
      }
    });

    if (!user)
      throw new NotFoundException("User not found!")

    const hashNewPassword = await hash(confirmNewPassword, 10);

    const newUserPassword: User = await this.prismaService.user.update({
      where: {
        email_application_id: {
          email,
          application_id: existingApplication.id
        }
      },
      data: {
        hashedPassword: hashNewPassword
      },
    });

    console.info("User changed: ", newUserPassword)

    return !!newUserPassword;
  }

}