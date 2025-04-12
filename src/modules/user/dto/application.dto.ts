import { IsString, IsOptional, IsNotEmpty } from 'class-validator';

export class ApplicationDto {
  @IsString()
  @IsNotEmpty()
  readonly name: string;

  @IsString()
  @IsOptional()
  readonly description?: string;
}
