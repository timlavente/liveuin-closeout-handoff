/** Server rule for LiveUIN passwords: 12-128 characters, at least one letter and one digit. */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;
export const PASSWORD_RULES_MESSAGE =
  "Choose a password with 12 to 128 characters, including at least one letter and one number.";

export function passwordMeetsRules(password: string) {
  const value = String(password || "");
  return (
    value.length >= PASSWORD_MIN_LENGTH &&
    value.length <= PASSWORD_MAX_LENGTH &&
    /\p{L}/u.test(value) &&
    /\d/.test(value)
  );
}
