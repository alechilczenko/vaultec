document.addEventListener("alpine:init", () => {
  const LIMIT = 500;
  const IMPORT_BATCH = 100;
  const ASSET_NAME_MAX = 255;
  const NOTES_MAX = 2000;

  const TYPE_OPTIONS = [
    {
      id: "URL",
      label: "WebApp",
      icon: "asset-url",
      description: "Web endpoints and application paths under test.",
      example: "https://api.corp.internal/v1/auth",
    },
    {
      id: "Host",
      label: "Hostname",
      icon: "asset-host",
      description: "Hostnames or host:port pairs for services.",
      example: "admin-panel.corp.internal:8443",
    },
    {
      id: "IP",
      label: "IP address",
      icon: "asset-ip",
      description: "IPv4 addresses for infrastructure targets.",
      example: "10.0.4.50",
    },
  ];

  const IMPORT_SCHEMA_SAMPLE = `[
  {
    "name": "https://api.corp.internal/v1/auth",
    "type": "URL",
    "notes": "Primary auth endpoint"
  }
]`;

  const TYPE_LABELS = {
    URL: "WebApp",
    Host: "Hostname",
    IP: "IP address",
  };

  const SEVERITY_RANK = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  function severityRank(value) {
    return SEVERITY_RANK[String(value || "").toLowerCase()] || 0;
  }

  function assetTypeLabel(type) {
    const key = String(type || "").trim();
    return TYPE_LABELS[key] || key || "";
  }

  function parseDate(value) {
    if (!value) return null;
    if (value instanceof Date) return value;
    const date = new Date(String(value).trim().replace(" ", "T"));
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    const date = parseDate(value);
    if (!date) return value || "";
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  }

  function formatDateTime(value) {
    const date = parseDate(value);
    if (!date) return value || "";
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  }

  function slugify(text) {
    return String(text || "")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function formatRawRecord(item) {
    if (!item) return "";
    try {
      return JSON.stringify(item, null, 2);
    } catch {
      return "";
    }
  }

  function emptyForm() {
    return {
      type: "",
      name: "",
      notes: "",
    };
  }

  function itemToForm(item) {
    return {
      type: item.type || "",
      name: item.name || "",
      notes: item.notes || "",
    };
  }

  function formToBody(form) {
    const notes = String(form.notes || "").trim();
    return {
      name: String(form.name || "").trim(),
      type: form.type,
      notes: notes || null,
    };
  }

  function findingCount(item) {
    return Number(item?.findings_count) || 0;
  }

  const SORT_ACCESSORS = {
    identifier: (a) => String(a.name || a.identifier || "").toLowerCase(),
    type: (a) => String(a.type || "").toLowerCase(),
    registeredAt: (a) => listPagination.toTimestamp(a.created_at),
    // Count first, worst severity as tiebreaker
    findings: (a) => findingCount(a) * 10 + severityRank(a.max_severity),
  };
  const SORT_DESC_FIRST = ["registeredAt", "findings"];

  function detailAccent(item) {
    if (!item) return "var(--border-chrome)";
    if (findingCount(item) === 0) return "var(--sev-info)";
    if (item.max_severity) return `var(--sev-${item.max_severity})`;
    return "var(--border-strong)";
  }

  function pillTone(item) {
    if (findingCount(item) === 0) return "var(--sev-info)";
    if (item?.max_severity) return `var(--sev-${item.max_severity})`;
    return "var(--sev-info)";
  }

  function inferType(identifier, explicit) {
    const raw = String(explicit || "").trim();
    if (raw) {
      const match = TYPE_OPTIONS.find(
        (opt) => opt.id.toLowerCase() === raw.toLowerCase()
      );
      if (match) return match.id;
    }
    const value = String(identifier || "").toLowerCase();
    if (value.startsWith("http://") || value.startsWith("https://")) return "URL";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return "IP";
    return "Host";
  }

  function normalizeImportEntry(raw, index) {
    const row = `Row ${index + 1}`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return { error: `${row}: expected an object` };
    }
    const name = String(
      raw.name || raw.identifier || raw.host || raw.url || raw.ip || ""
    ).trim();
    if (!name) return { error: `${row}: missing name` };
    if (name.length > ASSET_NAME_MAX) {
      return { error: `${row}: name exceeds ${ASSET_NAME_MAX} characters` };
    }
    const notes = String(raw.notes || "").trim();
    if (notes.length > NOTES_MAX) {
      return { error: `${row}: notes exceed ${NOTES_MAX} characters` };
    }
    return {
      item: {
        name,
        type: inferType(name, raw.type),
        notes: notes || null,
      },
    };
  }

  function matchesQuery(query, item) {
    const q = String(query || "").trim().toLowerCase();
    if (!q) return true;
    const haystack = [
      item.name,
      item.type,
      assetTypeLabel(item.type),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  }

  Alpine.data("assetsPage", () => {
    const cached = pageCache.read("assets");
    const hydrated = Boolean(cached?.loaded);
    return {
    items: hydrated ? cached.items || [] : [],
    total: hydrated ? Number(cached.total) || 0 : 0,
    query: "",
    filters: { type: "all" },
    currentPage: 1,
    pageSize: listPagination.PAGE_SIZE,
    sortKey: "findings",
    sortDir: "desc",
    entityLabel: "assets",
    loading: !hydrated,
    saving: false,
    error: "",
    selected: null,
    mode: "list", // list | detail | create | edit
    form: emptyForm(),
    typePreview: "",
    rawCopied: false,
    _rawCopyTimer: null,
    identifierCopied: false,
    _identifierCopyTimer: null,
    assetTypeLabel,
    formatDate,
    formatDateTime,
    findingCount,
    detailAccent,
    pillTone,
    formatRawRecord,

    get typeOptions() {
      const selected = this.form.type;
      return TYPE_OPTIONS.map((opt) => ({
        ...opt,
        selected: opt.id === selected,
      }));
    },

    get typeDescription() {
      const id = this.typePreview || this.form.type;
      return TYPE_OPTIONS.find((opt) => opt.id === id)?.description || "";
    },

    get identifierPlaceholder() {
      const opt = TYPE_OPTIONS.find((item) => item.id === this.form.type);
      return opt?.example || "Target identifier";
    },

    get canSubmit() {
      const name = this.form.name.trim();
      return (
        Boolean(this.form.type) &&
        name.length > 0 &&
        name.length <= ASSET_NAME_MAX &&
        String(this.form.notes || "").length <= NOTES_MAX
      );
    },

    get presentTypes() {
      const present = new Set(this.items.map((item) => item.type).filter(Boolean));
      return TYPE_OPTIONS.map((opt) => opt.id).filter((id) => present.has(id));
    },

    get filtersActive() {
      return this.filters.type !== "all";
    },

    get filteredItems() {
      return this.items.filter((item) => {
        if (this.filters.type !== "all" && item.type !== this.filters.type) {
          return false;
        }
        return matchesQuery(this.query, item);
      });
    },

    get filteredCount() {
      return this.filteredItems.length;
    },

    get sortedItems() {
      return listPagination.sortItems(
        this.filteredItems,
        this.sortKey,
        this.sortDir,
        SORT_ACCESSORS
      );
    },

    get totalPages() {
      return listPagination.totalPages(this.filteredCount, this.pageSize);
    },

    get displayedItems() {
      return listPagination.pageSlice(
        this.sortedItems,
        this.currentPage,
        this.pageSize
      );
    },

    get paginationPageItems() {
      return listPagination.pageItems(this.currentPage, this.totalPages);
    },

    get paginationMetaLabel() {
      if (!this.filteredCount) return `0 ${this.entityLabel}`;
      const { start, end } = listPagination.rangeMeta(
        this.currentPage,
        this.filteredCount,
        this.pageSize
      );
      return `Showing ${start} to ${end} of ${this.filteredCount}`;
    },

    get rawRecordContent() {
      return formatRawRecord(this.selected);
    },

    get rawRecordLineCount() {
      const content = this.rawRecordContent;
      if (!content) return 0;
      return content.replace(/\r\n/g, "\n").split("\n").length;
    },

    get rawRecordLineLabel() {
      const n = this.rawRecordLineCount;
      return `${n} ${n === 1 ? "line" : "lines"}`;
    },

    async copyRawRecord() {
      const content = this.rawRecordContent;
      if (!content) return;
      try {
        await navigator.clipboard.writeText(content);
        this.rawCopied = true;
        clearTimeout(this._rawCopyTimer);
        this._rawCopyTimer = setTimeout(() => {
          this.rawCopied = false;
        }, 2000);
      } catch {
        this.rawCopied = false;
      }
    },

    async copyIdentifier() {
      const value = String(this.selected?.name || "").trim();
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        this.identifierCopied = true;
        clearTimeout(this._identifierCopyTimer);
        this._identifierCopyTimer = setTimeout(() => {
          this.identifierCopied = false;
        }, 2000);
      } catch {
        this.identifierCopied = false;
        toast.show("Could not copy identifier", { tone: "danger" });
      }
    },

    setFilter(key, value) {
      this.filters = { ...this.filters, [key]: value || "all" };
      this.currentPage = 1;
    },

    clearFilters() {
      this.filters = { type: "all" };
      this.query = "";
      this.currentPage = 1;
    },

    goToPage(page) {
      this.currentPage = listPagination.clampPage(page, this.totalPages);
    },

    handleSort(key) {
      const next = listPagination.nextSortState(
        this.sortKey,
        this.sortDir,
        key,
        SORT_ACCESSORS,
        SORT_DESC_FIRST
      );
      this.sortKey = next.sortKey;
      this.sortDir = next.sortDir;
      this.currentPage = 1;
    },

    headerSortIconHtml(key) {
      return listPagination.sortIconHtml(this.sortKey, this.sortDir, key);
    },

    headerSortAria(key) {
      return listPagination.sortAria(this.sortKey, this.sortDir, key);
    },

    selectType(type) {
      this.form = { ...this.form, type };
      this.typePreview = type;
    },

    async init() {
      this.$watch("query", () => {
        this.currentPage = 1;
      });
      this.$watch("filteredCount", () => {
        if (this.currentPage > this.totalPages) {
          this.currentPage = this.totalPages;
        }
      });
      await this.load();
      this.applyOpenFromRoute();
    },

    /** Deep-link `?open=<id>` from Findings. */
    applyOpenFromRoute() {
      const params = new URLSearchParams(location.search);
      const rawId = params.get("open");
      if (rawId == null || String(rawId).trim() === "") return;
      const item = this.items.find(
        (entry) => String(entry.id) === String(rawId)
      );
      if (item) this.openDetail(item);
      params.delete("open");
      const qs = params.toString();
      history.replaceState({}, "", location.pathname + (qs ? `?${qs}` : ""));
    },

    async load({ quiet } = {}) {
      if (!(quiet ?? !this.loading)) this.loading = true;
      this.error = "";
      try {
        const assets = [];
        for (let skip = 0; ; skip += LIMIT) {
          const data = await api.get("/assets", {
            query: { skip, limit: LIMIT },
            defaultErrorMessage: "Could not load assets",
          });
          const page = Array.isArray(data?.assets) ? data.assets : [];
          assets.push(...page);
          const total = Number(data?.total);
          if (
            page.length < LIMIT ||
            (Number.isFinite(total) && assets.length >= total)
          ) {
            this.total = Number.isFinite(total) ? total : assets.length;
            break;
          }
        }
        this.items = assets;
        pageCache.write("assets", {
          loaded: true,
          items: this.items,
          total: this.total,
        });
      } catch (err) {
        if (api.isAbortError(err)) return;
        this.error = err.message || "Could not load assets";
        this.items = [];
        this.total = 0;
      } finally {
        this.loading = false;
      }
    },

    toggleSelect(item) {
      this.selected = this.selected?.id === item.id ? null : item;
    },

    openDetail(item) {
      if (!item) return;
      this.selected = item;
      this.mode = "detail";
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
      this.identifierCopied = false;
      clearTimeout(this._identifierCopyTimer);
    },

    closePanel() {
      if (this.mode === "detail") {
        this.mode = "list";
        this.identifierCopied = false;
        clearTimeout(this._identifierCopyTimer);
        return;
      }
      this.selected = null;
      this.mode = "list";
      this.form = emptyForm();
      this.typePreview = "";
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
      this.identifierCopied = false;
      clearTimeout(this._identifierCopyTimer);
    },

    startCreate() {
      this.selected = null;
      this.form = emptyForm();
      this.typePreview = "";
      this.mode = "create";
    },

    startEdit() {
      if (!this.selected) return;
      this.form = itemToForm(this.selected);
      this.typePreview = "";
      this.mode = "edit";
    },

    viewFindings() {
      if (!this.selected) return;
      const params = new URLSearchParams({
        asset: String(this.selected.id),
        target: this.selected.name || "",
      });
      location.assign(`/workspace/findings?${params.toString()}`);
    },

    async saveCreate() {
      if (!this.canSubmit) return;
      this.saving = true;
      try {
        const created = await api.post("/assets/create", formToBody(this.form), {
          defaultErrorMessage: "Could not create asset",
        });
        await this.load();
        this.openDetail(created);
        toast.show(`Created asset #${created.id}`);
      } catch (err) {
        const message = err.message || "Could not create asset";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },

    async saveEdit() {
      if (!this.selected || !this.canSubmit) return;
      this.saving = true;
      try {
        const updated = await api.patch(
          `/assets/${this.selected.id}`,
          formToBody(this.form),
          { defaultErrorMessage: "Could not update asset" }
        );
        await this.load();
        this.openDetail(updated);
        toast.show(`Updated asset #${updated.id}`);
      } catch (err) {
        const message = err.message || "Could not update asset";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },

    async remove() {
      if (!this.selected) return;
      const selected = this.selected;
      const label =
        selected.name || selected.identifier || `#${selected.id}`;
      const ok = await confirmDialog.ask({
        title: "Delete this asset?",
        message: `${selected.identifier || selected.name} will be removed from this engagement. Assets with findings can’t be deleted until those findings are removed. This can’t be undone.`,
        confirmLabel: "Delete asset",
        action: async () => {
          this.saving = true;
          try {
            await api.delete(`/assets/${selected.id}`, {
              defaultErrorMessage: "Could not delete asset",
            });
            this.closePanel();
            await this.load();
            toast.show(`Deleted asset ${label}`);
          } catch (err) {
            const message = err.message || "Could not delete asset";
            toast.show(message, { tone: "danger" });
            throw err;
          } finally {
            this.saving = false;
          }
        },
      });
      if (!ok) return;
    },

    pickImport() {
      importPicker.show({
        title: "Import assets",
        schemaSample: IMPORT_SCHEMA_SAMPLE,
        onFile: (file) => this.importFromFile(file),
      });
    },

    /** @returns {Promise<boolean>} false keeps the import picker open for retry */
    async importFromFile(file) {
      if (!file) return false;
      this.saving = true;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const rawList = Array.isArray(parsed)
          ? parsed
          : Array.isArray(parsed?.assets)
            ? parsed.assets
            : null;
        if (!rawList) {
          throw new Error("Import JSON has the wrong shape");
        }
        if (!rawList.length) {
          throw new Error("Import file has no assets");
        }

        const entries = [];
        for (let i = 0; i < rawList.length; i += 1) {
          const result = normalizeImportEntry(rawList[i], i);
          if (result.error) throw new Error(result.error);
          entries.push(result.item);
        }

        let added = 0;
        let skipped = 0;
        const addedNames = [];
        const skippedNames = [];
        for (let i = 0; i < entries.length; i += IMPORT_BATCH) {
          const batch = entries.slice(i, i + IMPORT_BATCH);
          const data = await api.post(
            "/assets/import",
            { assets: batch },
            { defaultErrorMessage: "Could not import assets" }
          );
          added += data?.summary?.added_count || 0;
          skipped += data?.summary?.skipped_count || 0;
          if (Array.isArray(data?.details?.added_assets)) {
            addedNames.push(...data.details.added_assets);
          }
          if (Array.isArray(data?.details?.ignored_duplicates)) {
            skippedNames.push(...data.details.ignored_duplicates);
          }
        }
        const feedback = importFeedback.formatAssetImportFeedback({
          added,
          skipped,
          addedNames,
          skippedNames,
        });
        importFeedback.presentImportFeedback(feedback);
        if (!feedback.failureMessage) {
          await this.load();
        }
        return true;
      } catch (err) {
        const message =
          err instanceof SyntaxError
            ? "Import file is not valid JSON"
            : importFeedback.formatImportCatchMessage(
                err,
                "Could not import assets"
              );
        toast.show(message, { tone: "danger" });
        return false;
      } finally {
        this.saving = false;
      }
    },

    async exportInventory() {
      this.saving = true;
      try {
        const data = await api.get("/assets/export", {
          defaultErrorMessage: "Could not export assets",
        });
        const client =
          slugify(data?.workspace?.client_name) || "assessment";
        const day =
          typeof data?.exported_at === "string" && data.exported_at.length >= 10
            ? data.exported_at.slice(0, 10)
            : new Date().toISOString().slice(0, 10);
        const blob = new Blob([JSON.stringify(data, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${client}-assets-${day}.json`;
        link.click();
        URL.revokeObjectURL(url);
        toast.show("Assets exported");
      } catch (err) {
        const message = err.message || "Could not export assets";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },
  };
  });
});
