import { ConfigModuleOptions } from "@nestjs/config";
import { apiConfig } from './api.config';

export const appConfig: ConfigModuleOptions = {
  load: [
    apiConfig
  ]
}