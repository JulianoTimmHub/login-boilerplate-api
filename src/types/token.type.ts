export type TokenResponse = {
  tokensHasValid: boolean;
  userPayload?: any;
}

export type UpdateRefreshToken = {
  email: string;
  application: any;
  refreshToken: string | null;
}

export type RefreshTokenDecoded = {
  email: string;
  application: any;
  refreshToken: string | null;
}