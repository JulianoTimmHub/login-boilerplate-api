export type TokenResponse = {
  accessToken: string;
  refreshToken: string;
}

export type UpdateRefreshToken = {
  email: string;
  refreshToken: string;
}