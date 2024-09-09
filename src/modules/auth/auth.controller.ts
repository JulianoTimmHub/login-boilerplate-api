import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { RecoverPasswordDto } from './dto/recover-password.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signin')
  async signIn (
    @Body() signInDto: SignInDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return await this.authService.signIn(signInDto, res);
  };

  @Post('/recoverPassword')
  async recoverPassword (
    @Body() recoverPasswordDto: RecoverPasswordDto
  ) {
    return await this.authService.recoverPassword(recoverPasswordDto);
  }
  
}
