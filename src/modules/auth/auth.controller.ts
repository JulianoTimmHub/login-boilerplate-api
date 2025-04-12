import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { RecoverPasswordDto } from './dto/recover-password.dto';
import { Response, Request } from 'express';
import { LogoutDto } from './dto/logout.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('/signin')
  async signIn(
    @Body() signInDto: SignInDto,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request
  ) {
    return await this.authService.signIn(signInDto, req, res);
  };

  @Post('/recoverPassword')
  async recoverPassword(
    @Body() recoverPasswordDto: RecoverPasswordDto
  ) {
    return await this.authService.recoverPassword(recoverPasswordDto);
  }

  @Post('/logout')
  async logout(
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
    @Body() logoutDto: LogoutDto
  ) {
    return await this.authService.logout(req, res, logoutDto);
  }

}
