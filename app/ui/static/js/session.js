/* Token helpers (localStorage key: token). */
(function (global) {
  "use strict";

  const VERIFIED_AT_KEY = "vmp:session:verifiedAt";
  /** Skip /auth/verify on rapid MPA tab switches; real 401s still hit api.onUnauthorized. */
  const VERIFY_TTL_MS = 60_000;

  function getToken() {
    return localStorage.getItem("token");
  }

  function markVerified() {
    try {
      sessionStorage.setItem(VERIFIED_AT_KEY, String(Date.now()));
    } catch {
      /* ignore */
    }
  }

  function clearVerified() {
    try {
      sessionStorage.removeItem(VERIFIED_AT_KEY);
    } catch {
      /* ignore */
    }
  }

  function recentlyVerified() {
    try {
      const at = Number(sessionStorage.getItem(VERIFIED_AT_KEY) || 0);
      return at > 0 && Date.now() - at < VERIFY_TTL_MS;
    } catch {
      return false;
    }
  }

  function logout() {
    localStorage.removeItem("token");
    clearVerified();
    if (global.pageCache) global.pageCache.clear();
  }

  function isAuthenticated() {
    const token = getToken();
    if (!token) return false;
    try {
      const payloadBase64 = token.split(".")[1];
      if (!payloadBase64) return false;
      const payloadJson = atob(payloadBase64.replace(/-/g, "+").replace(/_/g, "/"));
      const payload = JSON.parse(payloadJson);
      if (payload.exp) {
        return payload.exp > Date.now() / 1000;
      }
    } catch {
      return false;
    }
    return true;
  }

  async function login(username, password) {
    const body = new URLSearchParams();
    body.append("grant_type", "password");
    body.append("username", username);
    body.append("password", password);

    const data = await api.request("/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      defaultErrorMessage: "Authentication failed",
    });
    localStorage.setItem("token", data.access_token);
    markVerified();
    return data;
  }

  async function verifyToken() {
    return api.get("/auth/verify", {
      defaultErrorMessage: "Token verification failed",
    });
  }

  async function ensureSession() {
    if (!isAuthenticated()) {
      logout();
      return false;
    }
    // Full page nav aborts in-flight verify; don't re-hit the API on every tab click.
    if (recentlyVerified()) return true;
    try {
      await verifyToken();
      markVerified();
      return true;
    } catch (err) {
      // Navigating away mid-verify must not wipe the session (MPA-only race).
      if (api.isAbortError(err)) return true;
      // Only a rejected token ends the session; network blips keep a still-valid JWT.
      if (err?.status === 401) {
        logout();
        return false;
      }
      return true;
    }
  }

  function requireSession() {
    return ensureSession().then((ok) => {
      if (!ok) location.replace("/");
      return ok;
    });
  }

  api.onUnauthorized(() => {
    logout();
    if (location.pathname !== "/") location.replace("/");
  });

  global.session = {
    getToken,
    logout,
    isAuthenticated,
    login,
    verifyToken,
    ensureSession,
    requireSession,
  };
})(window);
