import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { hash } from 'bcrypt';
import { User } from '@prisma/client';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(
    createUserDto: CreateUserDto
  ): Promise<Boolean> {
    const { username, email, password } = createUserDto;

    const user = await this.prismaService.user.findUnique({
      where: {
        email
      }
    });

    if (user) {
      throw new ConflictException("Usuário já está registrado!");
    }

    const hashPassword = await hash(password, 10);
    const createdUser = await this.prismaService.user.create({
      data: {
        email,
        username,
        hashedPassword: hashPassword
      }      
    });

    console.log("User created: ", {createdUser})

    return !!createdUser;
  }

  async updateUser(
    updateUserDto: UpdateUserDto,
  ): Promise<User> {
    const { email, refreshToken } = updateUserDto;

    return this.prismaService.user.update({
      where: {
        email
      },
      data: {
        refreshToken: refreshToken
      }
    });
  }

}