/* Confirm dialog store (Alpine $store.confirm). */
(function (global) {
  "use strict";

  let storeRef = null;

  function defaults(options = {}) {
    return {
      title: String(options.title || "Confirm"),
      message: String(options.message || ""),
      confirmLabel: String(options.confirmLabel || "Confirm"),
      tone: options.tone === "default" ? "default" : "danger",
      action: typeof options.action === "function" ? options.action : null,
    };
  }

  /**
   * Open the confirm dialog.
   * Without `action`: resolves true/false when the user confirms/cancels.
   * With `action`: on confirm runs it with loading; resolves true on success;
   * keeps the dialog open on failure (resolves false only on cancel).
   */
  function ask(options = {}) {
    if (!storeRef) {
      return Promise.resolve(false);
    }
    return storeRef.ask(defaults(options));
  }

  document.addEventListener("alpine:init", () => {
    Alpine.store("confirm", {
      open: false,
      title: "Confirm",
      message: "",
      confirmLabel: "Confirm",
      tone: "danger",
      loading: false,
      _action: null,
      _resolver: null,

      get isDanger() {
        return this.tone !== "default";
      },

      get confirmVariant() {
        return this.isDanger ? "danger" : "primary";
      },

      get confirmIcon() {
        return this.isDanger ? "delete" : "check";
      },

      ask(opts) {
        if (this.open) {
          this.cancel();
        }
        return new Promise((resolve) => {
          this.title = opts.title;
          this.message = opts.message;
          this.confirmLabel = opts.confirmLabel;
          this.tone = opts.tone;
          this._action = opts.action;
          this.loading = false;
          this.open = true;
          this._resolver = resolve;
          queueMicrotask(() => {
            document.getElementById("confirm-cancel-btn")?.focus();
          });
        });
      },

      settle(value) {
        const resolve = this._resolver;
        this._resolver = null;
        this._action = null;
        this.loading = false;
        this.open = false;
        resolve?.(value);
      },

      cancel() {
        if (this.loading) return;
        this.settle(false);
      },

      async confirm() {
        if (this.loading) return;
        const action = this._action;
        if (!action) {
          this.settle(true);
          return;
        }
        this.loading = true;
        try {
          await action();
          this.settle(true);
        } catch {
          this.loading = false;
        }
      },
    });
    storeRef = Alpine.store("confirm");
  });

  global.confirmDialog = { ask };
})(window);
