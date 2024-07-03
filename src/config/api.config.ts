export type ApiConfig = {
  port: number;
  basePath: string;
}

const {
  API_PORT: port,
  API_BASE_PATH: basePath
} = process.env;

export const apiConfig = (): { api: ApiConfig } => ({
  api: {
    port: parseInt(port, 10),
    basePath: basePath,
  }
});