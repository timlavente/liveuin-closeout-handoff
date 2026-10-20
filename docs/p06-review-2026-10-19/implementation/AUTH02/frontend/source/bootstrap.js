async function qx() {
  if (!auth02IsApp() || auth02LoggingOut || auth02LoginFlow || auth02HasLogoutLock()) return auth02Closed("identity_session_required");
  const epoch = auth02Epoch;
  try {
    const payload = await auth02Request("/api/core/identity/session/resolve", {}, true);
    if (auth02LoggingOut || epoch !== auth02Epoch) return auth02Closed("identity_session_changed");
    return auth02Project(payload);
  } catch {
    return auth02Closed("identity_session_required");
  }
}
