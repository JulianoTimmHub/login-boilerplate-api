export type ApiConfig = {
  port: number;
  basePath: string;
  externalUrl: string;
  methods: string | string[];
  allowedHeaders: string | string[];
}

const {
  API_PORT: port,
  API_BASE_PATH: basePath,
  API_EXTERNAL_URL: externalUrl,
  API_METHODS: methods,
  API_ALLOWED_HEADERS: allowedHeaders
} = process.env;

export const apiConfig = (): { api: ApiConfig } => ({
  api: {
    port: parseInt(port, 10),
    basePath: basePath,
    externalUrl: externalUrl,
    methods: methods.split(','),
    allowedHeaders: allowedHeaders.split(',')
  }
});