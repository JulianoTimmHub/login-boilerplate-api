import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ApiConfig } from './config/api.config';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get<ConfigService>(ConfigService);

  const {
    port,
    basePath,
    externalUrl,
    methods,
    allowedHeaders
  } = configService.get<ApiConfig>('api');

  app.enableCors({
    origin: externalUrl,
    credentials: true,
    methods: methods,
    allowedHeaders: allowedHeaders,
    exposedHeaders: ['Set-Cookie']
  });

  app.setGlobalPrefix(basePath);
  app.use(cookieParser());
  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production'
  }));
  await app.listen(port);
}

bootstrap();