import { IsString, IsNotEmpty, ValidateNested } from "class-validator";
import { ApplicationDto } from "src/modules/user/dto/application.dto";

export class CreateTokenDto {
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  readonly username: string;

  @ValidateNested()
  readonly application?: ApplicationDto
}

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  readonly username: string;

  @IsString()
  @IsNotEmpty()
  readonly refreshToken: string;
}