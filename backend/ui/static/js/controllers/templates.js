document.addEventListener("alpine:init", () => {
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_RANK = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  const SORT_ACCESSORS = {
    severity: (d) => SEVERITY_RANK[String(d.severity || "").toLowerCase()] || 0,
    title: (d) => String(d.title || "").toLowerCase(),
    category: (d) => String(d.category || "General").toLowerCase(),
    lastUpdated: (d) => listPagination.toTimestamp(d.created_at),
  };
  const SORT_DESC_FIRST = ["severity", "lastUpdated"];
  const LIMIT = 100;
  const IMPORT_BATCH = 100;
  const SEVERITY_LABELS = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
  };
  const SEVERITY_ABBREV = {
    critical: "CRIT",
    high: "HIGH",
    medium: "MED",
    low: "LOW",
    info: "INFO",
  };
  const SEVERITY_DESC = {
    critical: "Immediate risk of full compromise, data breach, or remote code execution.",
    high: "Serious impact with a realistic path to privilege escalation or sensitive access.",
    medium: "Meaningful risk that usually needs chaining or limited attacker conditions.",
    low: "Limited impact; useful hardening signal but unlikely to be exploited alone.",
    info: "No direct exploit path. Observation for awareness, hygiene, or future context.",
  };

  const IMPORT_SCHEMA_SAMPLE = `[
  {
    "id": 7,
    "title": "SQL Injection in Authentication Endpoint",
    "category": "Injection",
    "severity": "critical",
    "description": "…",
    "recommendation": "…",
    "tags": ["cwe-89", "owasp-a03"]
  }
]`;

  function severityLabel(value) {
    return SEVERITY_LABELS[value] || value || "";
  }

  function severityAbbrev(value) {
    return SEVERITY_ABBREV[value] || String(value || "").toUpperCase();
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

  const PROSE_COLLAPSE_CHARS = 480;

  function proseParagraphs(text) {
    const raw = String(text || "").trim();
    if (!raw) return [];
    const blocks = raw
      .split(/\n\s*\n/)
      .map((part) => part.trim())
      .filter(Boolean);
    return blocks.length ? blocks : [raw];
  }

  function proseCollapsible(text) {
    return String(text || "").trim().length > PROSE_COLLAPSE_CHARS;
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
      title: "",
      severity: "",
      category: "",
      description: "",
      recommendation: "",
      tagsText: "",
    };
  }

  function tagsFromText(text) {
    return String(text || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .slice(0, 10);
  }

  function formToBody(form) {
    return {
      title: String(form.title || "").trim(),
      severity: form.severity,
      category: String(form.category || "").trim() || "General",
      description: String(form.description || "").trim(),
      recommendation: String(form.recommendation || "").trim(),
      tags: tagsFromText(form.tagsText),
    };
  }

  function itemToForm(item) {
    return {
      title: item.title || "",
      severity: item.severity || "medium",
      category: item.category || "General",
      description: item.description || "",
      recommendation: item.recommendation || "",
      tagsText: Array.isArray(item.tags) ? item.tags.join(", ") : "",
    };
  }

  function normalizeImportEntry(raw) {
    const entry = {
      title: String(raw.title || "").trim(),
      severity: String(raw.severity || "medium").toLowerCase(),
      category: String(raw.category || "").trim() || "General",
      description: String(raw.description || "").trim(),
      recommendation: String(
        raw.recommendation || raw.remediation || ""
      ).trim(),
      tags: Array.isArray(raw.tags) ? raw.tags : tagsFromText(raw.tags),
    };
    const id = Number(raw.id);
    if (Number.isInteger(id) && id >= 1) entry.id = id;
    return entry;
  }

  function normalizeTitleKey(title) {
    return String(title || "").trim().toLowerCase();
  }

  /** Case-insensitive title match; excludeId skips the row being edited. */
  function findTemplateByTitle(templates, title, excludeId = null) {
    const key = normalizeTitleKey(title);
    if (!key) return null;
    return (
      (templates || []).find((item) => {
        if (excludeId != null && item.id === excludeId) return false;
        return normalizeTitleKey(item.title) === key;
      }) || null
    );
  }

  /** Client-side search on title/category/tags. */
  function matchesQuery(query, item) {
    const q = String(query || "").trim().toLowerCase();
    if (!q) return true;
    const fields = [item.title, item.category, ...(item.tags || [])];
    return fields.some((field) => String(field || "").toLowerCase().includes(q));
  }

  Alpine.data("templatesPage", () => {
    const cached = pageCache.read("templates");
    const hydrated = Boolean(cached?.loaded);
    return {
    items: hydrated ? cached.items || [] : [],
    total: hydrated ? Number(cached.total) || 0 : 0,
    query: "",
    filters: { severity: "all", category: "all" },
    currentPage: 1,
    pageSize: listPagination.PAGE_SIZE,
    sortKey: "severity",
    sortDir: "desc",
    entityLabel: "templates",
    loading: !hydrated,
    saving: false,
    error: "",
    selected: null,
    mode: "list", // list | detail | create | edit
    form: emptyForm(),
    severityPreview: "",
    descriptionExpanded: false,
    remediationExpanded: false,
    rawCopied: false,
    _rawCopyTimer: null,
    severityLabel,
    severityAbbrev,
    formatDate,
    formatDateTime,
    proseParagraphs,
    proseCollapsible,
    formatRawRecord,

    get severityDescription() {
      const id = this.severityPreview || this.form.severity;
      return SEVERITY_DESC[id] || "";
    },

    /** Fresh objects each time so x-for re-renders selected / aria state. */
    get severityOptions() {
      const selected = this.form.severity;
      return SEVERITIES.map((id) => ({
        id,
        selected: id === selected,
        label: severityLabel(id),
        abbrev: severityAbbrev(id),
      }));
    },

    get canSubmit() {
      return (
        Boolean(this.form.severity) &&
        this.form.title.trim().length > 0 &&
        this.form.description.trim().length > 0 &&
        this.form.recommendation.trim().length > 0
      );
    },

    get categories() {
      const set = new Set();
      for (const item of this.items) {
        if (item?.category) set.add(item.category);
      }
      return [...set].sort((a, b) => a.localeCompare(b));
    },

    /** Severities present in the current result set (for filter options). */
    get presentSeverities() {
      const present = new Set(this.items.map((item) => item.severity));
      return SEVERITIES.filter((level) => present.has(level));
    },

    /** Categories present in the current result set (for filter options). */
    get categoryOptions() {
      const set = new Set(
        this.items.map((item) => item.category || "General")
      );
      return [...set].sort((a, b) => a.localeCompare(b));
    },

    get filtersActive() {
      return this.filters.severity !== "all" || this.filters.category !== "all";
    },

    /** Client-side query + severity/category filter. */
    get filteredItems() {
      return this.items.filter((item) => {
        if (
          this.filters.severity !== "all" &&
          item.severity !== this.filters.severity
        ) {
          return false;
        }
        if (
          this.filters.category !== "all" &&
          (item.category || "General") !== this.filters.category
        ) {
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

    setFilter(key, value) {
      this.filters = { ...this.filters, [key]: value || "all" };
      this.currentPage = 1;
    },

    clearFilters() {
      this.filters = { severity: "all", category: "all" };
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

    /** Replace form so x-for bindings (class / aria-checked) re-evaluate. */
    selectSeverity(sev) {
      this.form = { ...this.form, severity: sev };
      this.severityPreview = sev;
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
        const data = await api.get("/templates", {
          query: { skip: 0, limit: LIMIT },
          defaultErrorMessage: "Could not load templates",
        });
        this.items = Array.isArray(data?.templates) ? data.templates : [];
        this.total = Number(data?.total) || this.items.length;
        pageCache.write("templates", {
          loaded: true,
          items: this.items,
          total: this.total,
        });
      } catch (err) {
        if (api.isAbortError(err)) return;
        this.error = err.message || "Could not load templates";
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
      this.descriptionExpanded = false;
      this.remediationExpanded = false;
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
    },

    closePanel() {
      if (this.mode === "detail") {
        this.mode = "list";
        return;
      }
      this.selected = null;
      this.mode = "list";
      this.form = emptyForm();
      this.severityPreview = "";
      this.descriptionExpanded = false;
      this.remediationExpanded = false;
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
    },

    startCreate() {
      this.selected = null;
      this.form = emptyForm();
      this.severityPreview = "";
      this.mode = "create";
    },

    startEdit() {
      if (!this.selected) return;
      this.form = itemToForm(this.selected);
      this.severityPreview = "";
      this.mode = "edit";
    },

    async confirmDuplicateTitle() {
      if (this.mode !== "create" && this.mode !== "edit") return true;
      const excludeId = this.mode === "edit" ? this.selected?.id : null;
      const match = findTemplateByTitle(this.items, this.form.title, excludeId);
      if (!match) return true;
      const title = String(this.form.title || "").trim();
      if (this.mode === "edit") {
        return confirmDialog.ask({
          title: "Rename to an existing title?",
          message: `“${title}” is already used by template #${match.id}. Save this rename anyway?`,
          confirmLabel: "Save anyway",
          tone: "default",
        });
      }
      return confirmDialog.ask({
        title: "Create another template?",
        message: `“${title}” already exists as template #${match.id}. Create a second definition with the same title?`,
        confirmLabel: "Create anyway",
        tone: "default",
      });
    },

    async saveCreate() {
      if (!this.canSubmit) return;
      if (!(await this.confirmDuplicateTitle())) return;
      this.saving = true;
      try {
        const created = await api.post(
          "/templates/create",
          formToBody(this.form),
          { defaultErrorMessage: "Could not create template" }
        );
        await this.load();
        this.openDetail(created);
        toast.show(`Created template #${created.id}`);
      } catch (err) {
        const message = err.message || "Could not create template";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },

    async saveEdit() {
      if (!this.selected || !this.canSubmit) return;
      if (!(await this.confirmDuplicateTitle())) return;
      this.saving = true;
      try {
        const updated = await api.patch(
          `/templates/${this.selected.id}`,
          formToBody(this.form),
          { defaultErrorMessage: "Could not update template" }
        );
        await this.load();
        this.openDetail(updated);
        toast.show(`Updated template #${updated.id}`);
      } catch (err) {
        const message = err.message || "Could not update template";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },

    async remove() {
      if (!this.selected) return;
      const selected = this.selected;
      const label = `“${selected.title}”`;
      const ok = await confirmDialog.ask({
        title: "Delete this template?",
        message: `${label} will be removed from the template library. Templates used by findings can’t be deleted until those findings are removed. This can’t be undone.`,
        confirmLabel: "Delete template",
        action: async () => {
          this.saving = true;
          try {
            await api.delete(`/templates/${selected.id}`, {
              defaultErrorMessage: "Could not delete template",
            });
            this.closePanel();
            await this.load();
            toast.show(`Deleted template ${label}`);
          } catch (err) {
            const message = err.message || "Could not delete template";
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
        title: "Import templates",
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
          : Array.isArray(parsed?.templates)
            ? parsed.templates
            : null;
        if (!rawList) {
          throw new Error("Import JSON has the wrong shape");
        }
        if (!rawList.length) {
          throw new Error("Import file has no templates");
        }

        const entries = rawList.map(normalizeImportEntry);
        let created = 0;
        let updated = 0;
        const createdItems = [];
        const updatedItems = [];
        for (let i = 0; i < entries.length; i += IMPORT_BATCH) {
          const batch = entries.slice(i, i + IMPORT_BATCH);
          const data = await api.post(
            "/templates/import",
            { templates: batch },
            { defaultErrorMessage: "Could not import templates" }
          );
          created += data?.summary?.created || 0;
          updated += data?.summary?.updated || 0;
          if (Array.isArray(data?.details?.created)) {
            createdItems.push(...data.details.created);
          }
          if (Array.isArray(data?.details?.updated)) {
            updatedItems.push(...data.details.updated);
          }
        }
        const feedback = importFeedback.formatTemplatesImportFeedback({
          created,
          updated,
          createdItems,
          updatedItems,
        });
        importFeedback.presentImportFeedback(feedback);
        if (!feedback.failureMessage) {
          this.mode = "list";
          this.selected = null;
          await this.load();
        }
        return true;
      } catch (err) {
        const message =
          err instanceof SyntaxError
            ? "Import file is not valid JSON"
            : importFeedback.formatImportCatchMessage(
                err,
                "Could not import templates"
              );
        toast.show(message, { tone: "danger" });
        return false;
      } finally {
        this.saving = false;
      }
    },

    async exportLibrary() {
      this.saving = true;
      try {
        const data = await api.get("/templates/export", {
          defaultErrorMessage: "Could not export templates",
        });
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
        link.download = `templates-${day}.json`;
        link.click();
        URL.revokeObjectURL(url);
        toast.show("Templates exported");
      } catch (err) {
        const message = err.message || "Could not export templates";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },
  };
  });
});
