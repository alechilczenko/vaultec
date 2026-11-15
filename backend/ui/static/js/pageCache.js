/* Tiny sessionStorage cache so MPA view switches skip the Loading… flash. */
(function (global) {
  "use strict";

  const PREFIX = "vmp:cache:";

  /** Drop Alpine proxies and non-JSON values before persisting. */
  function plain(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function read(key) {
    try {
      const raw = sessionStorage.getItem(PREFIX + key);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function write(key, value) {
    try {
      sessionStorage.setItem(PREFIX + key, JSON.stringify(plain(value)));
    } catch {
      /* ignore quota / private mode / circular */
    }
  }

  function clear() {
    try {
      const keys = [];
      for (let i = 0; i < sessionStorage.length; i += 1) {
        const key = sessionStorage.key(i);
        if (key && key.startsWith(PREFIX)) keys.push(key);
      }
      keys.forEach((key) => sessionStorage.removeItem(key));
    } catch {
      /* ignore */
    }
  }

  global.pageCache = { read, write, clear, plain };
})(window);
