/* Global import-result dialog — toast summary + scannable detail list. */
(function (global) {
  "use strict";

  let storeRef = null;

  function show(options = {}) {
    if (!storeRef) return;
    storeRef.show(options);
  }

  document.addEventListener("alpine:init", () => {
    Alpine.store("importResult", {
      open: false,
      title: "Import result",
      summary: "",
      tone: "info",
      sections: [],

      get hasSections() {
        return Array.isArray(this.sections) && this.sections.some((s) => s.items?.length);
      },

      show(opts = {}) {
        const sections = Array.isArray(opts.sections)
          ? opts.sections
              .map((section) => ({
                label: String(section?.label || "").trim() || "Items",
                items: (Array.isArray(section?.items) ? section.items : [])
                  .map((item) => String(item ?? "").trim())
                  .filter(Boolean),
              }))
              .filter((section) => section.items.length)
          : [];

        this.title = String(opts.title || "Import result").trim() || "Import result";
        this.summary = String(opts.summary || "").trim();
        this.tone = opts.tone || "info";
        this.sections = sections;
        this.open = true;
        queueMicrotask(() => {
          document.getElementById("import-result-close-btn")?.focus();
        });
      },

      close() {
        this.open = false;
      },
    });
    storeRef = Alpine.store("importResult");
  });

  global.importResult = { show };
})(window);
