import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { TokenService } from './token.service';
import { TokenResponse } from 'src/types/token.type';
import { RefreshTokenGuard } from './guards/refreshToken.guard';
import { Response } from 'express';

@Controller('token')
export class TokenController {
  constructor(private readonly tokenService: TokenService) { }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshToken(
    @Req() req,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    this.tokenService.refreshToken(req, res);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('validateToken')
  async validateToken(
    @Req() req,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponse> {
    return this.tokenService.validateToken(req, res);
  }

}