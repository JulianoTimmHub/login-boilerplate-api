import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './modules/user/user.module';
import { PrismaModule } from './modules/prisma/prisma.module';
import { AuthModule } from './modules/auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { appConfig } from './config/app.config';
import { TokenModule } from './modules/token/token.module';

@Module({
  imports: [
    ConfigModule.forRoot(appConfig),
    PrismaModule, 
    UserModule, 
    AuthModule, 
    TokenModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
