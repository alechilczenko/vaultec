/* Same-origin fetch wrapper (no build). */
(function (global) {
  "use strict";

  const API_URL = "";

  let unauthorizedHandler = null;
  /** Set before unload so cancelled fetches are not shown as UI errors. */
  let navigatingAway = false;

  function onUnauthorized(handler) {
    unauthorizedHandler = handler;
  }

  function markNavigatingAway() {
    navigatingAway = true;
  }

  function bindNavGuards() {
    window.addEventListener("pagehide", markNavigatingAway);
    window.addEventListener("beforeunload", markNavigatingAway);
    // Capture same-origin link clicks *before* the browser aborts in-flight fetch
    // (Chromium often rejects with TypeError "Failed to fetch", not AbortError).
    document.addEventListener(
      "click",
      (event) => {
        if (event.defaultPrevented) return;
        if (event.button !== 0) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
          return;
        }
        const anchor = event.target?.closest?.("a[href]");
        if (!anchor) return;
        if (anchor.target && anchor.target !== "_self") return;
        if (anchor.hasAttribute("download")) return;
        let url;
        try {
          url = new URL(anchor.href, location.href);
        } catch {
          return;
        }
        if (url.origin !== location.origin) return;
        if (url.pathname === location.pathname && url.search === location.search) {
          return;
        }
        markNavigatingAway();
      },
      true
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindNavGuards);
  } else {
    bindNavGuards();
  }

  // location.assign/replace skip the <a> click guard (shell redirects, logout).
  try {
    const assign = location.assign.bind(location);
    const replace = location.replace.bind(location);
    location.assign = (url) => {
      markNavigatingAway();
      return assign(url);
    };
    location.replace = (url) => {
      markNavigatingAway();
      return replace(url);
    };
  } catch {
    /* Location methods may be non-configurable */
  }

  class ApiError extends Error {
    constructor(message, { status, detail, cause } = {}) {
      super(message, { cause });
      this.name = "ApiError";
      this.status = status;
      this.detail = detail;
    }
  }

  /**
   * True when fetch was cancelled by navigation (MPA tab switch) or AbortController.
   * Callers must skip banners/toasts when this is true.
   */
  function isAbortError(err) {
    if (navigatingAway) return true;
    if (!err) return false;
    if (err.name === "AbortError") return true;
    const cause = err.cause;
    return !!(cause && cause.name === "AbortError");
  }

  function asAbortError(cause) {
    if (cause?.name === "AbortError") return cause;
    try {
      return new DOMException("The operation was aborted.", "AbortError");
    } catch {
      const err = new Error("The operation was aborted.");
      err.name = "AbortError";
      err.cause = cause;
      return err;
    }
  }

  async function parseError(response, defaultMessage) {
    let detail;
    try {
      detail = (await response.json())?.detail;
    } catch {
      detail = undefined;
    }

    if (typeof detail === "string" && detail) return { message: detail, detail };
    if (Array.isArray(detail) && detail.length) {
      const first = detail[0];
      const field = Array.isArray(first?.loc)
        ? first.loc.filter((part) => part !== "body").join(".")
        : "";
      const msg = first?.msg || "Validation error";
      return { message: field ? `${field}: ${msg}` : msg, detail };
    }
    if (detail && typeof detail === "object") {
      const message = String(detail.message || "").trim();
      if (message) return { message, detail };
    }

    if (response.status === 401) return { message: "Invalid credentials", detail };
    if (response.status === 422) return { message: "Invalid data provided", detail };
    if (response.status === 400) return { message: "Bad request", detail };
    return { message: defaultMessage, detail };
  }

  async function request(endpoint, options = {}) {
    const {
      body,
      headers = {},
      defaultErrorMessage = "Request failed",
      query,
      responseType,
      ...restOptions
    } = options;
    const defaultHeaders = {
      Accept: "application/json",
    };

    const token = localStorage.getItem("token");
    if (token) {
      defaultHeaders.Authorization = `Bearer ${token}`;
    }

    let finalBody = body;
    if (body && typeof body === "object" && !(body instanceof URLSearchParams)) {
      defaultHeaders["Content-Type"] = "application/json";
      finalBody = JSON.stringify(body);
    }

    let url = `${API_URL}${endpoint}`;
    if (query) {
      const params = new URLSearchParams(
        Object.entries(query).filter(([, value]) => value != null && value !== "")
      );
      const search = params.toString();
      if (search) url += `?${search}`;
    }

    let response;
    try {
      response = await fetch(url, {
        ...restOptions,
        headers: {
          ...defaultHeaders,
          ...headers,
        },
        body: finalBody,
      });
    } catch (networkError) {
      // Don't wrap as "Request failed" — callers skip UI errors on nav cancel.
      if (isAbortError(networkError)) throw asAbortError(networkError);
      throw new ApiError(defaultErrorMessage, { cause: networkError });
    }

    if (navigatingAway) throw asAbortError();

    if (!response.ok) {
      const { message, detail } = await parseError(response, defaultErrorMessage);
      // Login also answers 401 for bad credentials; only a rejected token ends the session
      if (response.status === 401 && token) {
        localStorage.removeItem("token");
        unauthorizedHandler?.();
      }
      throw new ApiError(message, { status: response.status, detail });
    }

    if (response.status === 204) {
      return null;
    }

    if (responseType === "blob") {
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = /filename="([^"]+)"/i.exec(disposition);
      return { blob, filename: match ? match[1] : null };
    }

    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  function get(endpoint, options = {}) {
    return request(endpoint, { ...options, method: "GET" });
  }

  function getBlob(endpoint, options = {}) {
    return request(endpoint, {
      ...options,
      method: "GET",
      responseType: "blob",
      headers: {
        Accept: "application/pdf, application/octet-stream, */*",
        ...(options.headers || {}),
      },
    });
  }

  function post(endpoint, body, options = {}) {
    return request(endpoint, { ...options, method: "POST", body });
  }

  function patch(endpoint, body, options = {}) {
    return request(endpoint, { ...options, method: "PATCH", body });
  }

  function del(endpoint, options = {}) {
    return request(endpoint, { ...options, method: "DELETE" });
  }

  global.api = {
    ApiError,
    isAbortError,
    markNavigatingAway,
    onUnauthorized,
    parseError,
    request,
    get,
    getBlob,
    post,
    patch,
    delete: del,
  };
})(window);
