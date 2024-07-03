import { IsNotEmpty, IsString } from "class-validator";

export class RecoverPasswordDto {
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  readonly newPassword: string;

  @IsString()
  @IsNotEmpty()
  readonly confirmNewPassword: string;
}