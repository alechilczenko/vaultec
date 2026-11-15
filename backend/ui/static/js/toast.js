/* Global toast store (Alpine $store.toast). */
(function (global) {
  "use strict";

  const PENDING_KEY = "vmp:toast:pending";
  const TOAST_MAX_CHARS = 140;
  const TONE_ICONS = {
    success: "success",
    warning: "warning",
    danger: "warning",
    info: "info",
  };

  const timers = new Map();
  let nextId = 1;
  let storeRef = null;

  function clipMessage(message) {
    const text = String(message ?? "").trim();
    if (!text) return "";
    if (text.length <= TOAST_MAX_CHARS) return text;
    return `${text.slice(0, TOAST_MAX_CHARS - 1).trimEnd()}…`;
  }

  function show(message, { tone = "success", duration = 4000 } = {}) {
    if (!storeRef) {
      queue(message, { tone, duration });
      return null;
    }
    const text = clipMessage(message);
    if (!text) return null;
    const id = nextId++;
    storeRef.items.push({ id, message: text, tone: tone || "success" });
    if (duration > 0) {
      timers.set(
        id,
        setTimeout(() => dismiss(id), duration)
      );
    }
    return id;
  }

  /** Survive full-page navigations (setup / workspace reset). */
  function queue(message, { tone = "success", duration = 4000 } = {}) {
    const text = clipMessage(message);
    if (!text) return;
    try {
      sessionStorage.setItem(
        PENDING_KEY,
        JSON.stringify({ message: text, tone, duration })
      );
    } catch {
      /* ignore */
    }
  }

  function flushPending() {
    let raw;
    try {
      raw = sessionStorage.getItem(PENDING_KEY);
      if (!raw) return;
      sessionStorage.removeItem(PENDING_KEY);
    } catch {
      return;
    }
    try {
      const data = JSON.parse(raw);
      show(data.message, {
        tone: data.tone || "success",
        duration: Number.isFinite(data.duration) ? data.duration : 4000,
      });
    } catch {
      /* ignore */
    }
  }

  function dismiss(id) {
    if (!storeRef) return;
    const timer = timers.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.delete(id);
    }
    const index = storeRef.items.findIndex((toast) => toast.id === id);
    if (index !== -1) storeRef.items.splice(index, 1);
  }

  function iconFor(tone) {
    return TONE_ICONS[tone] || "info";
  }

  document.addEventListener("alpine:init", () => {
    Alpine.store("toast", {
      items: [],
      show,
      queue,
      dismiss,
      iconFor,
    });
    storeRef = Alpine.store("toast");
    flushPending();
  });

  global.toast = { show, queue, dismiss, iconFor };
})(window);
