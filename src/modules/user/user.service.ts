import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { hash } from 'bcryptjs';
import { User } from '@prisma/client';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) { }

  async createUser(createUserDto: CreateUserDto): Promise<Boolean> {
    const { username, email, password, application } = createUserDto;

    console.info({ application });

    let existingApplication = null;
    if (application) {
      existingApplication = await this.prismaService.application.findUnique({
        where: {
          name: application.name
        }
      });

      if (!existingApplication && application.name) {
        existingApplication = await this.prismaService.application.create({
          data: {
            name: application.name,
            description: application.description ?? null
          }
        });
      }
    }

    const existingUser = await this.prismaService.user.findFirst({
      where: {
        email,
        application_id: existingApplication ? existingApplication.id : null
      }
    });

    if (existingUser)
      throw new ConflictException("User is already registered!");

    let applicationData = undefined;
    if (existingApplication)
      applicationData = { connect: { id: existingApplication.id } };

    const hashPassword = await hash(password, 10);
    const createdUser = await this.prismaService.user.create({
      data: {
        email,
        username,
        hashedPassword: hashPassword,
        application: applicationData
      }
    });

    console.info("User created: ", { createdUser });

    return !!createdUser;
  }

  async updateUser(
    updateUserDto: UpdateUserDto
  ): Promise<User> {
    const { email, refreshToken, application } = updateUserDto;

    const existingApplication = await this.prismaService.application.findUnique({
      where: {
        name: application.name
      }
    });

    return this.prismaService.user.update({
      where: {
        email_application_id: {
          email,
          application_id: existingApplication.id
        }
      },
      data: {
        refreshToken: refreshToken
      }
    });
  }

}