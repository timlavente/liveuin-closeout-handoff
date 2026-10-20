let residentLogoutInProgress = false;
let residentSessionLifecycleVersion = 0;

export function beginResidentLogout() {
  residentLogoutInProgress = true;
  residentSessionLifecycleVersion += 1;
  return residentSessionLifecycleVersion;
}

export function finishResidentLogout() {
  residentLogoutInProgress = false;
  residentSessionLifecycleVersion += 1;
  return residentSessionLifecycleVersion;
}

export function isResidentLogoutInProgress() {
  return residentLogoutInProgress;
}

export function getResidentSessionLifecycleVersion() {
  return residentSessionLifecycleVersion;
}

export function isResidentLogoutTokenCurrent(token: number) {
  return residentLogoutInProgress && residentSessionLifecycleVersion === token;
}
