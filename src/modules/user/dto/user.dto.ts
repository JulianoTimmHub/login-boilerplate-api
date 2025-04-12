import { IsString, IsNotEmpty, ValidateNested, } from "class-validator";
import { ApplicationDto } from "./application.dto";

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  readonly username: string;

  @IsString()
  @IsNotEmpty()
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @ValidateNested()
  readonly application?: ApplicationDto;
}

export class UpdateUserDto {
  @IsString()
  @IsNotEmpty()
  readonly username?: string;

  @IsString()
  @IsNotEmpty()
  readonly password?: string;

  @IsString()
  @IsNotEmpty()
  readonly refreshToken?: string;

  @IsString()
  @IsNotEmpty()
  readonly email: string;

  @ValidateNested()
  readonly application?: ApplicationDto;
}