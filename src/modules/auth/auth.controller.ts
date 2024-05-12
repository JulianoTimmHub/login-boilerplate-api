import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { RecoverPasswordDto } from './dto/recover-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signin')
  async signIn (
    @Body() signInDto: SignInDto
  ) {
    return await this.authService.signIn(signInDto);
  };

  @Post('/recoverPassword')
  async recoverPassword (
    @Body() recoverPasswordDto: RecoverPasswordDto
  ) {
    return await this.authService.recoverPassword(recoverPasswordDto);
  }
  
}
