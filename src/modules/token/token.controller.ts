import { Body, Controller, Post } from '@nestjs/common';
import { TokenService } from './token.service';
import { RefreshTokenDto } from './dto/token.dto';
import { TokenResponse } from 'src/types/token.type';

@Controller('token')
export class TokenController {
  constructor( private readonly tokenService: TokenService) { }

  @Post('/refresh')
  async refreshToken (
    @Body() refreshTokenDto: RefreshTokenDto
  ): Promise<TokenResponse> {
    return this.tokenService.refreshToken(refreshTokenDto);
  }

}