type ErrorCode = "email_taken" | "invalid_token" | "email_unchanged";

type ResponseCode = "password_verified";

export const errorCodes = {
  email_taken: "An account with this email already exists.",
  invalid_token: "Token is invalid or expired.",
  email_unchanged: "Email is unchanged.",
};

export const responseCodes = {
  password_verified: "Password verified.",
};

export function getErrorMessage(code: ErrorCode): string {
  return errorCodes[code];
}

export function getResponseMessage(code: ResponseCode): string {
  return responseCodes[code];
}
