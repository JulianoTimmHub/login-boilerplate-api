import { Body, Controller, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/user.dto';

@Controller('user')
export class UserController {
  constructor( private readonly userService: UserService) { }

  @Post('/registerUser')
  async createUser (
    @Body() createUserDto: CreateUserDto
  ): Promise<Boolean> {
    return this.userService.createUser(createUserDto);
  }

}