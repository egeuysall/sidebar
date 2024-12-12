type ErrorCode = "email_taken" | "invalid_token" | "email_unchanged";
type ResponseCode = "password_verified";

const DEFAULT_ERROR_MESSAGE =
  "Something went wrong. Please try again or contact support if the issue persists.";
const DEFAULT_RESPONSE_MESSAGE = "Completed successfully.";

export const errorCodes = {
  email_taken: "An account with this email already exists.",
  invalid_token: "Token is invalid or expired.",
  email_unchanged: "Email is unchanged.",
};

export const responseCodes = {
  password_verified: "Password verified.",
};

export function getErrorMessage(code: ErrorCode): string {
  return errorCodes[code] || DEFAULT_ERROR_MESSAGE;
}

export function getResponseMessage(code: ResponseCode): string {
  return responseCodes[code] || DEFAULT_RESPONSE_MESSAGE;
}
