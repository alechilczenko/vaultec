/* Pre-import modal: dropzone + expected JSON sample. */
(function (global) {
  "use strict";

  let storeRef = null;

  function show(options = {}) {
    if (!storeRef) return;
    storeRef.show(options);
  }

  function close() {
    storeRef?.close();
  }

  document.addEventListener("alpine:init", () => {
    Alpine.store("importPicker", {
      open: false,
      title: "Import",
      schemaSample: "",
      fileName: "",
      isDragging: false,
      busy: false,
      _onFile: null,

      show(opts = {}) {
        if (this.open) this.close();
        this.title = String(opts.title || "Import").trim() || "Import";
        this.schemaSample = String(opts.schemaSample || "").trim();
        this.fileName = "";
        this.isDragging = false;
        this.busy = false;
        this._onFile =
          typeof opts.onFile === "function" ? opts.onFile : null;
        this.open = true;
        queueMicrotask(() => {
          document.getElementById("import-picker-close-btn")?.focus();
        });
      },

      close() {
        this.open = false;
        this.fileName = "";
        this.isDragging = false;
        this.busy = false;
        this._onFile = null;
      },

      onDragEnter() {
        if (!this.busy) this.isDragging = true;
      },

      onDragLeave() {
        this.isDragging = false;
      },

      async onDrop(event) {
        this.isDragging = false;
        await this.handleFile(event.dataTransfer?.files?.[0]);
      },

      async onFileChange(event) {
        const file = event.target.files?.[0];
        event.target.value = "";
        await this.handleFile(file);
      },

      async handleFile(file) {
        if (this.busy || !file || !this._onFile) return;
        this.busy = true;
        this.fileName = String(file.name || "").trim();
        try {
          const result = await this._onFile(file);
          if (result !== false) this.close();
        } catch {
          /* caller toasts; keep modal open for retry */
        } finally {
          this.busy = false;
        }
      },
    });
    storeRef = Alpine.store("importPicker");
  });

  global.importPicker = { show, close };
})(window);
