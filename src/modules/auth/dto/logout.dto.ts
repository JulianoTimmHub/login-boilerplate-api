import { IsNotEmpty, IsString, ValidateNested } from "class-validator";
import { ApplicationDto } from "src/modules/user/dto/application.dto";

export class LogoutDto {
  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @ValidateNested()
  readonly application: ApplicationDto;
}