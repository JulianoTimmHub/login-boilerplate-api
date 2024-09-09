import { Body, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { TokenService } from './token.service';
import { RefreshTokenDto } from './dto/token.dto';
import { TokenResponse } from 'src/types/token.type';
import { RefreshTokenGuard } from './guards/refreshToken.guard';
import { Request, Response } from 'express';

@Controller('token')
export class TokenController {
  constructor( private readonly tokenService: TokenService) { }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshToken (
    @Req() req,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponse> {
    return this.tokenService.refreshToken(req, res);
  }

}