import { IsNotEmpty, IsString, ValidateNested } from "class-validator";
import { ApplicationDto } from "src/modules/user/dto/application.dto";

export class SignInDto {
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  readonly password: string;

  @ValidateNested()
  readonly application?: ApplicationDto
}