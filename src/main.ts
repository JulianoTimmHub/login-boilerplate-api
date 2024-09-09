import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ApiConfig } from './config/api.config';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });

  const configService = app.get<ConfigService>(ConfigService);
 
  const { port, basePath } = configService.get<ApiConfig>('api');

  app.setGlobalPrefix(basePath);

  app.use(cookieParser());
  
  app.use(helmet());
  await app.listen(port);
}

bootstrap();